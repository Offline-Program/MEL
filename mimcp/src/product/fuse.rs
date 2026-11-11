// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! A faithful, offline port of the subset of [Fuse.js](https://fusejs.io)
//! v7.4.2 that the online product `search_products` tool depends on.
//!
//! The online Red Hat product MCP server resolves `products_search.relevanceScore`
//! from a Fuse.js index built by the subgraph gateway
//! (`rhg-subgraph-gateway-commons/src/datasources/products-search-index.ts`) over
//! each product's `name` (weight 2) and `alternateNames` (weight 1), with
//! `threshold: 0.4`, `minMatchCharLength: 2`, `includeScore: true`. To reproduce
//! the same ranking offline, this module ports Fuse's Bitap scorer, field-norm,
//! and the per-item score combine (`computeScoreSingle`) exactly.
//!
//! Fidelity is pinned by golden tests in [`tests`] generated from the real
//! `fuse.js@7.4.2` (see `testdata/fuse_goldens.json`). The `fuse-rust` crate was
//! evaluated and rejected: it tracks an older Fuse with a different multi-key
//! score combine, so it does not reproduce these scores.
//!
//! Only the features the gateway actually uses are ported: plain (non-extended,
//! non-token) object-list search over string and string-array keys, with the
//! default `location: 0`, `distance: 100`, `ignoreLocation: false`,
//! `ignoreFieldNorm: false`, `fieldNormWeight: 1`. Patterns longer than 32 code
//! points are chunked exactly as upstream.

use std::collections::HashMap;

/// Fuse's default search location (bias toward matches near the start).
const LOCATION: f64 = 0.0;
/// Fuse's default distance: how far from `LOCATION` a match may drift before it
/// is scored as a non-match.
const DISTANCE: f64 = 100.0;
/// Maximum pattern length a single Bitap chunk can score (bitmask width).
const MAX_PATTERN_LEN: usize = 32;

/// A key in the Fuse index: a field to search with its (raw, un-normalized)
/// weight. The gateway uses `name` (weight 2) and `alternateNames` (weight 1).
#[derive(Debug, Clone, Copy)]
pub struct FuseKey {
    /// Raw weight, used directly as `weight * fieldNorm` in the score exponent.
    /// Upstream passes `options.keys` straight to `createIndex`, so weights are
    /// NOT normalized to sum 1 in the object-list scoring path.
    pub weight: f64,
}

/// One indexed value: its lowercased characters and its field norm.
#[derive(Debug, Clone)]
struct IndexedValue {
    /// Lowercased characters of the value (Fuse indexes by code unit; we use
    /// Unicode scalar values).
    chars: Vec<char>,
    /// Precomputed field norm for this value.
    norm: f64,
}

/// One corpus record: the per-key indexed values. `name` is a single value;
/// `alternate_names` is a list (each element scored independently).
#[derive(Debug, Clone)]
pub struct FuseRecord {
    /// Single-valued `name` key, if present and non-blank.
    name: Option<IndexedValue>,
    /// Multi-valued `alternateNames` key; blanks are dropped at build time.
    alternate_names: Vec<IndexedValue>,
}

/// A built Fuse index over a fixed corpus, ready to score queries.
#[derive(Debug, Clone)]
pub struct FuseIndex {
    /// Indexed corpus records.
    records: Vec<FuseRecord>,
    /// Key metadata for the `name` field.
    name_key: FuseKey,
    /// Key metadata for the `alternateNames` field.
    alt_key: FuseKey,
    /// Per-field match threshold (Fuse `threshold`, 0.4 here).
    threshold: f64,
    /// Minimum contiguous match length (Fuse `minMatchCharLength`, 2 here).
    min_match_char_length: usize,
}

/// One scored hit: the corpus index and the combined item score (lower = better).
#[derive(Debug, Clone, Copy)]
pub struct FuseHit {
    /// Index into the corpus the record came from.
    pub index: usize,
    /// Combined item score in `[0, 1]` (0 = perfect). Matches Fuse's `result.score`.
    pub score: f64,
}

impl FuseIndex {
    /// Builds an index over `(name, alternate_names)` records using the gateway's
    /// configuration: `name` weight 2, `alternateNames` weight 1, threshold 0.4,
    /// `minMatchCharLength` 2.
    pub fn build(records: &[(String, Vec<String>)]) -> Self {
        let name_key = FuseKey { weight: 2.0 };
        let alt_key = FuseKey { weight: 1.0 };
        let records = records
            .iter()
            .map(|(name, alts)| FuseRecord {
                name: make_value(name),
                alternate_names: alts.iter().filter_map(|a| make_value(a)).collect(),
            })
            .collect();
        Self {
            records,
            name_key,
            alt_key,
            threshold: 0.4,
            min_match_char_length: 2,
        }
    }

    /// Scores `query` against every record, returning the hits that match at the
    /// item level (at least one field matched), sorted by Fuse's default order
    /// (score ascending, then original index). Mirrors `_searchObjectList` +
    /// `computeScore` + the default `sortFn`.
    pub fn search(&self, query: &str) -> Vec<FuseHit> {
        let searcher = BitapSearcher::new(query);
        let mut hits: Vec<FuseHit> = Vec::new();

        for (index, record) in self.records.iter().enumerate() {
            let mut matches: Vec<(f64, FuseKey, f64)> = Vec::new();

            // `name` key: single value, 0 or 1 match.
            if let Some(value) = &record.name {
                if let Some(score) =
                    searcher.search_in(&value.chars, self.threshold, self.min_match_char_length)
                {
                    matches.push((score, self.name_key, value.norm));
                }
            }

            // `alternateNames` key: one match per matching array element.
            for value in &record.alternate_names {
                if let Some(score) =
                    searcher.search_in(&value.chars, self.threshold, self.min_match_char_length)
                {
                    matches.push((score, self.alt_key, value.norm));
                }
            }

            if matches.is_empty() {
                continue;
            }
            hits.push(FuseHit {
                index,
                score: compute_score_single(&matches),
            });
        }

        // Default sortFn: ascending score, ties broken by original index.
        hits.sort_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.index.cmp(&b.index))
        });
        hits
    }
}

/// Builds an [`IndexedValue`] from a raw string, returning `None` for blank
/// values (mirrors Fuse's `isBlank` filtering in `_createObjectRecord`). Values
/// are lowercased (Fuse default `isCaseSensitive: false`).
fn make_value(raw: &str) -> Option<IndexedValue> {
    if raw.trim().is_empty() {
        return None;
    }
    let chars: Vec<char> = raw.to_lowercase().chars().collect();
    let norm = field_norm(&chars);
    Some(IndexedValue { chars, norm })
}

/// Fuse's `norm(fieldNormWeight = 1).get(value)`: `round(1000 / sqrt(numTokens)) / 1000`,
/// where `numTokens = 1 + (number of whitespace-delimited gaps)`, counting a run
/// of spaces as a single gap (spaces are U+0020 only, per Fuse).
fn field_norm(chars: &[char]) -> f64 {
    let mut num_tokens: u32 = 1;
    let mut in_space = false;
    for &c in chars {
        if c == ' ' {
            if !in_space {
                num_tokens += 1;
                in_space = true;
            }
        } else {
            in_space = false;
        }
    }
    let m = 1000.0_f64;
    (m / (num_tokens as f64).powf(0.5)).round() / m
}

/// Fuse's `computeScoreSingle`: product over all matches of
/// `pow(score == 0 ? EPSILON : score, weight * norm)` (with `ignoreFieldNorm`
/// false, so the exponent includes the field norm).
fn compute_score_single(matches: &[(f64, FuseKey, f64)]) -> f64 {
    let mut total = 1.0_f64;
    for &(score, key, norm) in matches {
        let base = if score == 0.0 { f64::EPSILON } else { score };
        total *= base.powf(key.weight * norm);
    }
    total
}

/// A compiled Bitap searcher for a single query pattern, split into <=32-char
/// chunks exactly as Fuse's `BitapSearch`.
struct BitapSearcher {
    /// Full lowercased pattern (for the exact-equality fast path).
    pattern: Vec<char>,
    /// `(chunk_pattern, alphabet, start_index)` tuples.
    chunks: Vec<(Vec<char>, HashMap<char, u64>, usize)>,
}

impl BitapSearcher {
    /// Compiles `query` (lowercased) into Bitap chunks.
    fn new(query: &str) -> Self {
        let pattern: Vec<char> = query.to_lowercase().chars().collect();
        let mut chunks = Vec::new();
        let len = pattern.len();
        if len == 0 {
            return Self { pattern, chunks };
        }
        let mut add_chunk = |p: &[char], start: usize| {
            chunks.push((p.to_vec(), create_pattern_alphabet(p), start));
        };
        if len > MAX_PATTERN_LEN {
            let remainder = len % MAX_PATTERN_LEN;
            let end = len - remainder;
            let mut i = 0;
            while i < end {
                add_chunk(&pattern[i..i + MAX_PATTERN_LEN], i);
                i += MAX_PATTERN_LEN;
            }
            if remainder != 0 {
                let start = len - MAX_PATTERN_LEN;
                add_chunk(&pattern[start..], start);
            }
        } else {
            add_chunk(&pattern, 0);
        }
        Self { pattern, chunks }
    }

    /// Scores this pattern against `text` (already lowercased characters).
    /// Returns `Some(score)` when it matches at the field level, mirroring
    /// `BitapSearch.searchIn`; `None` when it does not match.
    fn search_in(
        &self,
        text: &[char],
        threshold: f64,
        min_match_char_length: usize,
    ) -> Option<f64> {
        if self.chunks.is_empty() {
            return None;
        }
        // Exact-equality fast path (score exactly 0, bypassing the 0.001 floor).
        if self.pattern == text {
            return Some(0.0);
        }
        let mut total_score = 0.0;
        let mut has_matches = false;
        for (pattern, alphabet, start_index) in &self.chunks {
            let (is_match, score) = bitap_search(
                text,
                pattern,
                alphabet,
                LOCATION + *start_index as f64,
                threshold,
                min_match_char_length,
            );
            if is_match {
                has_matches = true;
            }
            total_score += score;
        }
        if has_matches {
            Some(total_score / self.chunks.len() as f64)
        } else {
            None
        }
    }
}

/// Fuse's `createPatternAlphabet`: maps each pattern char to its bitmask.
fn create_pattern_alphabet(pattern: &[char]) -> HashMap<char, u64> {
    let len = pattern.len();
    let mut mask: HashMap<char, u64> = HashMap::new();
    for (i, &ch) in pattern.iter().enumerate() {
        let bit = 1u64 << (len - i - 1);
        *mask.entry(ch).or_insert(0) |= bit;
    }
    mask
}

/// Finds the first index at or after `from` where `pattern` occurs in `text`,
/// mirroring JS `String.prototype.indexOf(pattern, from)` over code points.
fn index_of(text: &[char], pattern: &[char], from: usize) -> Option<usize> {
    if pattern.is_empty() {
        return Some(from.min(text.len()));
    }
    if pattern.len() > text.len() {
        return None;
    }
    let last = text.len() - pattern.len();
    let mut i = from;
    while i <= last {
        if text[i..i + pattern.len()] == *pattern {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Fuse's Bitap `search`: scores a single chunk pattern against `text`.
/// Returns `(is_match, score)`; `score` is floored at `0.001` as upstream. The
/// gateway uses `location: 0`, `distance: 100`, `ignoreLocation: false`,
/// `findAllMatches: false`, and `includeMatches` false (but a
/// `minMatchCharLength` above 1 still forces mask computation, which can turn a
/// numeric match into a
/// non-match when no run is long enough).
fn bitap_search(
    text: &[char],
    pattern: &[char],
    alphabet: &HashMap<char, u64>,
    location: f64,
    threshold: f64,
    min_match_char_length: usize,
) -> (bool, f64) {
    let pattern_len = pattern.len();
    let text_len = text.len();
    let expected_location = location.max(0.0).min(text_len as f64);

    let calc_score = |errors: usize, current_location: f64| -> f64 {
        let accuracy = errors as f64 / pattern_len as f64;
        // ignore_location is always false for our config.
        let proximity = (expected_location - current_location).abs();
        if DISTANCE == 0.0 {
            return if proximity != 0.0 { 1.0 } else { accuracy };
        }
        accuracy + proximity / DISTANCE
    };

    let mut current_threshold = threshold;
    // `computeMatches` is true because min_match_char_length > 1.
    let compute_matches = min_match_char_length > 1;
    let mut match_mask = vec![false; text_len];

    // First pass: exact substring occurrences tighten the threshold / set mask.
    let mut best_location = index_of(text, pattern, expected_location as usize);
    while let Some(index) = best_location {
        let score = calc_score(0, index as f64);
        current_threshold = current_threshold.min(score);
        let next = index + pattern_len;
        if compute_matches {
            for i in 0..pattern_len {
                if index + i < text_len {
                    match_mask[index + i] = true;
                }
            }
        }
        best_location = index_of(text, pattern, next);
    }

    // Second pass: the Bitap bit-parallel fuzzy match.
    let mut found_location: i64 = -1;
    let mut last_bit_arr: Vec<u64> = Vec::new();
    let mut final_score = 1.0_f64;
    let mut best_errors = 0usize;
    let mut bin_max = pattern_len + text_len;
    let bit_mask = 1u64 << (pattern_len - 1);

    for i in 0..pattern_len {
        let mut bin_min = 0usize;
        let mut bin_mid = bin_max;
        while bin_min < bin_mid {
            if calc_score(i, expected_location + bin_mid as f64) <= current_threshold {
                bin_min = bin_mid;
            } else {
                bin_max = bin_mid;
            }
            bin_mid = (bin_max - bin_min) / 2 + bin_min;
        }
        bin_max = bin_mid;

        let mut start = 1.0_f64.max(expected_location - bin_mid as f64 + 1.0) as usize;
        // findAllMatches is false.
        let finish =
            ((expected_location + bin_mid as f64).min(text_len as f64) as usize) + pattern_len;

        let mut bit_arr = vec![0u64; finish + 2];
        bit_arr[finish + 1] = (1u64 << i) - 1;

        let mut j = finish;
        while j >= start {
            let current_location = j - 1;
            let char_match = text
                .get(current_location)
                .and_then(|c| alphabet.get(c).copied())
                .unwrap_or(0);
            bit_arr[j] = ((bit_arr[j + 1] << 1) | 1) & char_match;
            if i != 0 {
                bit_arr[j] |=
                    ((last_bit_arr[j + 1] | last_bit_arr[j]) << 1) | 1 | last_bit_arr[j + 1];
            }
            if bit_arr[j] & bit_mask != 0 {
                final_score = calc_score(i, current_location as f64);
                if final_score <= current_threshold {
                    current_threshold = final_score;
                    found_location = current_location as i64;
                    best_errors = i;
                    if found_location <= expected_location as i64 {
                        break;
                    }
                    let candidate = 2.0 * expected_location - found_location as f64;
                    start = 1.0_f64.max(candidate) as usize;
                }
            }
            if j == start {
                break;
            }
            j -= 1;
        }

        if calc_score(i + 1, expected_location) > current_threshold {
            break;
        }
        last_bit_arr = bit_arr;
    }

    // Mask refinement for the best fuzzy location.
    if compute_matches && found_location >= 0 {
        let bl = found_location as usize;
        let match_end = (text_len.saturating_sub(1)).min(bl + pattern_len - 1 + best_errors);
        for (k, slot) in match_mask
            .iter_mut()
            .enumerate()
            .take(match_end + 1)
            .skip(bl)
        {
            if text
                .get(k)
                .map(|c| alphabet.contains_key(c))
                .unwrap_or(false)
            {
                *slot = true;
            }
        }
    }

    let mut is_match = found_location >= 0;
    let score = final_score.max(0.001);

    if compute_matches {
        let indices = convert_mask_to_indices(&match_mask, min_match_char_length);
        if indices.is_empty() {
            is_match = false;
        }
    }

    (is_match, score)
}

/// Fuse's `convertMaskToIndices`: returns the `[start, end]` runs of set bits at
/// least `min_match_char_length` long. We only need whether any run qualifies.
fn convert_mask_to_indices(
    match_mask: &[bool],
    min_match_char_length: usize,
) -> Vec<(usize, usize)> {
    let mut indices = Vec::new();
    let mut start: i64 = -1;
    let len = match_mask.len();
    let mut i = 0usize;
    while i < len {
        if match_mask[i] {
            if start == -1 {
                start = i as i64;
            }
        } else if start != -1 {
            let end = i - 1;
            if end as i64 - start + 1 >= min_match_char_length as i64 {
                indices.push((start as usize, end));
            }
            start = -1;
        }
        i += 1;
    }
    if len > 0 && match_mask[len - 1] && (i as i64 - start) >= min_match_char_length as i64 {
        indices.push((start as usize, len - 1));
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const GOLDENS: &str = include_str!("testdata/fuse_goldens.json");

    #[derive(Deserialize)]
    struct Goldens {
        corpus: Vec<CorpusItem>,
        queries: std::collections::HashMap<String, Vec<ItemHit>>,
        fields: Vec<FieldCase>,
    }

    #[derive(Deserialize, Clone)]
    struct CorpusItem {
        uuid: String,
        name: String,
        #[serde(rename = "alternateNames")]
        alternate_names: Vec<String>,
    }

    #[derive(Deserialize)]
    struct ItemHit {
        uuid: String,
        score: f64,
        relevance: f64,
    }

    #[derive(Deserialize)]
    struct FieldCase {
        pattern: String,
        text: String,
        #[serde(rename = "isMatch")]
        is_match: bool,
        score: f64,
    }

    fn goldens() -> Goldens {
        serde_json::from_str(GOLDENS).expect("golden fixture parses")
    }

    /// Field-level Bitap scores must match real fuse.js `Fuse.match` exactly.
    #[test]
    fn bitap_field_scores_match_fuse() {
        for case in goldens().fields {
            let searcher = BitapSearcher::new(&case.pattern);
            let text: Vec<char> = case.text.to_lowercase().chars().collect();
            let result = searcher.search_in(&text, 0.4, 2);
            match result {
                Some(score) => {
                    assert!(
                        case.is_match,
                        "{:?} should not match {:?}",
                        case.pattern, case.text
                    );
                    assert!(
                        (score - case.score).abs() < 1e-9,
                        "field score for {:?} in {:?}: got {score}, want {}",
                        case.pattern,
                        case.text,
                        case.score
                    );
                }
                None => assert!(
                    !case.is_match,
                    "{:?} should match {:?} (want score {})",
                    case.pattern, case.text, case.score
                ),
            }
        }
    }

    /// Item-level ranking (post `computeScoreSingle`) must match real fuse.js,
    /// after applying the gateway's LOW (<=0.2) filter and relevance rounding.
    #[test]
    fn item_search_matches_fuse() {
        let g = goldens();
        let corpus: Vec<(String, Vec<String>)> = g
            .corpus
            .iter()
            .map(|c| (c.name.clone(), c.alternate_names.clone()))
            .collect();
        let index = FuseIndex::build(&corpus);

        for (query, expected) in &g.queries {
            let hits: Vec<_> = index
                .search(query)
                .into_iter()
                .filter(|h| h.score <= 0.2)
                .collect();
            assert_eq!(
                hits.len(),
                expected.len(),
                "hit count for query {query:?}: got {}, want {}",
                hits.len(),
                expected.len()
            );
            for (got, want) in hits.iter().zip(expected.iter()) {
                assert_eq!(
                    g.corpus[got.index].uuid, want.uuid,
                    "query {query:?}: ranked uuid mismatch"
                );
                assert!(
                    (got.score - want.score).abs() < 1e-9,
                    "query {query:?}: item score got {}, want {}",
                    got.score,
                    want.score
                );
                let relevance = ((1.0 - got.score) * 100.0).round() / 100.0;
                assert!(
                    (relevance - want.relevance).abs() < 1e-9,
                    "query {query:?}: relevance got {relevance}, want {}",
                    want.relevance
                );
            }
        }
    }

    #[test]
    fn field_norm_matches_fuse_formula() {
        // 1 token -> 1.0; 2 tokens -> round(1000/sqrt2)/1000 = 0.707; collapses space runs.
        assert_eq!(field_norm(&"rhel".chars().collect::<Vec<_>>()), 1.0);
        assert_eq!(field_norm(&"red hat".chars().collect::<Vec<_>>()), 0.707);
        assert_eq!(field_norm(&"red  hat".chars().collect::<Vec<_>>()), 0.707);
    }
}
