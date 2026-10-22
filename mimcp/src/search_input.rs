// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Input handling for the security tools.
//!
//! Mirrors the upstream Red Hat security MCP server's input contract so clients
//! written against it work unchanged: identifier validation, the `input`
//! object-or-JSON-string duality, the legacy `q` alias, hoisting of top-level
//! `rows` / `start` / `filterQueries` / `sortField`, and the documented sort
//! allowlists.

use std::time::{SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::Deserialize;

/// Default number of rows a search returns.
pub const DEFAULT_ROWS: u32 = 10;

/// Upper bound on rows a single search may return.
pub const MAX_ROWS: u32 = 100;

/// Query that matches every document, used when only filters apply.
pub const MATCH_ALL: &str = "*:*";

/// Severity values recognized in a `cve_threatSeverity` filter clause, in the
/// capitalization the index stores.
const CVE_SEVERITIES: [&str; 5] = ["Critical", "Important", "Moderate", "Low", "None"];

/// Sort fields the CVE search accepts, per the upstream tool description.
const CVE_SORT_FIELDS: [&str; 3] = ["cve_publicDate", "lastModifiedDate", "cve_threatSeverity"];

/// Sort fields the advisory search accepts, per the upstream tool description.
const ERRATA_SORT_FIELDS: [&str; 5] = [
    "id",
    "portal_advisory_type",
    "portal_severity_level",
    "portal_publication_date",
    "portal_update_date",
];

/// Returns the current year (UTC).
fn current_year() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    year_from_unix_days(secs.div_euclid(86_400))
}

/// Converts a count of days since the Unix epoch to a calendar year, using the
/// standard civil-from-days algorithm so the check is exact at year boundaries.
fn year_from_unix_days(days: i64) -> i64 {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    yoe + era * 400 + i64::from(month <= 2)
}

/// Rejects an identifier whose year is in the future.
fn check_year(year: &str, field: &str) -> Result<(), String> {
    let parsed: i64 = year
        .parse()
        .map_err(|_| format!("{field} must contain a four-digit year"))?;
    let current = current_year();
    if parsed > current {
        return Err(format!(
            "{field} year cannot be greater than the current year ({current})"
        ));
    }
    Ok(())
}

/// Validates and normalizes a CVE identifier to `CVE-YYYY-NNNN` form.
///
/// Returns `Err` with a client-facing message when the shape is wrong or the
/// year is in the future.
pub fn normalize_cve_id(raw: &str) -> Result<String, String> {
    const SHAPE: &str = "cve_id must match CVE-YYYY-NNNN (e.g. CVE-2024-1234)";
    let normalized = raw.trim().to_uppercase();
    let mut parts = normalized.split('-');
    let (Some("CVE"), Some(year), Some(sequence), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(SHAPE.to_owned());
    };
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if year.len() != 4 || !digits(year) || sequence.len() < 4 || !digits(sequence) {
        return Err(SHAPE.to_owned());
    }
    check_year(year, "cve_id")?;
    Ok(normalized)
}

/// Validates and normalizes an advisory identifier to `RHSA-YYYY:NNNN` form.
///
/// Both `RHSA-2024:1234` and `RHSA-2024-1234` are accepted, as upstream does;
/// the separator is normalized to `:` because that is how the index stores the
/// advisory `id`.
pub fn normalize_advisory_id(raw: &str) -> Result<String, String> {
    const SHAPE: &str = "advisory_id must match RHSA/RHEA/RHBA-YYYY:NNNN (e.g. RHSA-2024:1234)";
    let normalized = raw.trim().to_uppercase();
    let Some((prefix, rest)) = normalized.split_once('-') else {
        return Err(SHAPE.to_owned());
    };
    if !matches!(prefix, "RHSA" | "RHEA" | "RHBA") {
        return Err(SHAPE.to_owned());
    }
    let Some((year, sequence)) = rest.split_once([':', '-']) else {
        return Err(SHAPE.to_owned());
    };
    let digits = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
    if year.len() != 4 || !digits(year) || !digits(sequence) {
        return Err(SHAPE.to_owned());
    }
    check_year(year, "advisory_id")?;
    Ok(format!("{prefix}-{year}:{sequence}"))
}

/// Page window for a search.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Pagination {
    /// Rows to return (default 10, max 100).
    pub rows: Option<u32>,
    /// Zero-based offset of the first row (default 0).
    pub start: Option<u32>,
}

/// Sort selection for a search.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Sort {
    /// Full sort clause, `<field> asc|desc`.
    #[serde(rename = "sortOrder")]
    pub sort_order: Option<String>,
    /// Field alone, paired with [`Self::sort_order`] as a direction.
    #[serde(rename = "sortField")]
    pub sort_field: Option<String>,
}

/// Structured filter clauses for a search.
///
/// The CVE tool documents a single `filterQuery` and the advisory tool a
/// `filterQueries` list; both spellings are accepted for either so a client
/// cannot fail on the wrong one.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Filter {
    /// A single filter clause.
    #[serde(rename = "filterQuery")]
    pub filter_query: Option<String>,
    /// Several filter clauses, AND-combined.
    #[serde(rename = "filterQueries")]
    pub filter_queries: Option<Vec<String>>,
}

/// The `input` object accepted by `search_cves` and `search_advisories`.
///
/// Top-level `rows` / `start` / `filterQuery` / `filterQueries` / `sortField` /
/// `sortOrder` are accepted and hoisted into their nested homes, matching the
/// upstream normalization handlers.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SearchInput {
    /// Free-text query; use `*:*` when only filters apply.
    pub query: Option<String>,
    /// Legacy alias for [`Self::query`].
    pub q: Option<String>,
    /// Page window.
    pub pagination: Option<Pagination>,
    /// Structured filters.
    pub filter: Option<Filter>,
    /// Sort selection.
    pub sort: Option<Sort>,
    /// Hoisted alias for `pagination.rows`.
    pub rows: Option<u32>,
    /// Hoisted alias for `pagination.start`.
    pub start: Option<u32>,
    /// Hoisted alias for `filter.filterQuery`.
    #[serde(rename = "filterQuery")]
    pub filter_query: Option<String>,
    /// Hoisted alias for `filter.filterQueries`.
    #[serde(rename = "filterQueries")]
    pub filter_queries: Option<Vec<String>>,
    /// Hoisted alias for `sort.sortField`.
    #[serde(rename = "sortField")]
    pub sort_field: Option<String>,
    /// Hoisted alias for `sort.sortOrder`.
    #[serde(rename = "sortOrder")]
    pub sort_order: Option<String>,
}

/// A search request's `input`, accepted either as an object or as a JSON string.
///
/// MCP clients vary in whether they send structured arguments or a serialized
/// blob; upstream accepts both, so this does too.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RawSearchInput {
    /// A JSON-encoded object.
    Text(String),
    /// A structured object.
    Object(Box<SearchInput>),
}

impl RawSearchInput {
    /// Resolves to a [`SearchInput`], parsing the JSON-string form if needed.
    ///
    /// Returns `Err` when the string is not valid JSON, or decodes to something
    /// other than an object.
    pub fn resolve(self) -> Result<SearchInput, String> {
        match self {
            Self::Object(input) => Ok(*input),
            Self::Text(raw) => {
                let value: serde_json::Value = serde_json::from_str(&raw)
                    .map_err(|e| format!("input must be valid JSON: {e}"))?;
                if !value.is_object() {
                    return Err("input JSON must decode to an object".to_owned());
                }
                serde_json::from_value(value)
                    .map_err(|e| format!("input is not a valid search input: {e}"))
            }
        }
    }
}

/// Which tool a search is being normalized for; selects the sort allowlist.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SearchKind {
    /// `search_cves`.
    Cve,
    /// `search_advisories`.
    Errata,
}

/// A search reduced to the parameters a Solr query needs.
#[derive(Debug, PartialEq, Eq)]
pub struct NormalizedSearch {
    /// Main query string.
    pub query: String,
    /// Client-supplied filter clauses.
    pub filters: Vec<String>,
    /// Rows to return, clamped to [`MAX_ROWS`].
    pub rows: u32,
    /// Zero-based offset of the first row.
    pub start: u32,
    /// Rendered `sort` clause, if any.
    pub sort: Option<String>,
}

/// Normalizes a client `input` into Solr query parameters.
///
/// Returns `Err` with a client-facing message for an unsupported sort field or
/// a filter clause that tries to use Solr local-param syntax.
pub fn normalize(input: SearchInput, kind: SearchKind) -> Result<NormalizedSearch, String> {
    let query = [input.query.as_deref(), input.q.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or(MATCH_ALL)
        .to_owned();

    let pagination = input.pagination.unwrap_or_default();
    let rows = pagination
        .rows
        .or(input.rows)
        .unwrap_or(DEFAULT_ROWS)
        .clamp(1, MAX_ROWS);
    let start = pagination.start.or(input.start).unwrap_or(0);

    let filter = input.filter.unwrap_or_default();
    let mut clauses: Vec<String> = Vec::new();
    for clause in [filter.filter_query, input.filter_query]
        .into_iter()
        .flatten()
        .chain(
            [filter.filter_queries, input.filter_queries]
                .into_iter()
                .flatten()
                .flatten(),
        )
    {
        let clause = clause.trim();
        if clause.is_empty() {
            continue;
        }
        clauses.push(prepare_filter_clause(clause, kind)?);
    }

    let sort_input = input.sort.unwrap_or_default();
    let sort = render_sort(
        sort_input.sort_field.or(input.sort_field),
        sort_input.sort_order.or(input.sort_order),
        kind,
    )?;

    Ok(NormalizedSearch {
        query,
        filters: clauses,
        rows,
        start,
        sort,
    })
}

/// Validates and rewrites a single client filter clause.
fn prepare_filter_clause(clause: &str, kind: SearchKind) -> Result<String, String> {
    // Local params would let a clause switch query parsers or change caching
    // behaviour, which is well outside the documented "field:value" contract.
    if clause.contains("{!") {
        return Err(format!(
            "filter clause may not use Solr local parameters: {clause}"
        ));
    }
    Ok(match kind {
        SearchKind::Cve => fix_cve_severity_casing(clause),
        SearchKind::Errata => widen_errata_severity(clause),
    })
}

/// Capitalizes severity values in a `cve_threatSeverity` clause.
///
/// Clients commonly send `cve_threatSeverity:critical`; the index stores
/// `Critical`, and the field is a `string` type, so the lowercase form matches
/// nothing. Upstream applies the same fixup.
fn fix_cve_severity_casing(clause: &str) -> String {
    const FIELD: &str = "cve_threatSeverity:";
    let mut out = String::with_capacity(clause.len());
    let mut rest = clause;

    while let Some(at) = rest.find(FIELD) {
        let (before, after) = rest.split_at(at + FIELD.len());
        out.push_str(before);
        let value_len = after
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(after.len());
        let (value, tail) = after.split_at(value_len);
        match CVE_SEVERITIES
            .iter()
            .find(|known| known.eq_ignore_ascii_case(value))
        {
            Some(known) => out.push_str(known),
            None => out.push_str(value),
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Accepts the upstream `portal_severity:"None"` spelling against an index that
/// currently stores the literal `(none)`.
///
/// The clause is widened to match either spelling, so it keeps working after
/// the index is normalized (RHOKP-1760 gap list) rather than needing a matching
/// code change at that moment.
fn widen_errata_severity(clause: &str) -> String {
    const PATTERNS: [&str; 2] = ["portal_severity:\"None\"", "portal_severity:None"];
    let mut out = clause.to_owned();
    for pattern in PATTERNS {
        if out.contains(pattern) {
            out = out.replace(pattern, "portal_severity:(\"None\" OR \"(none)\")");
        }
    }
    out
}

/// Renders a `sort` clause, validating the field against the tool's allowlist.
fn render_sort(
    field: Option<String>,
    order: Option<String>,
    kind: SearchKind,
) -> Result<Option<String>, String> {
    // `sortOrder` carries the whole clause unless a bare `sortField` is given.
    let (field, direction) = match (field, order) {
        (Some(f), order) if !f.trim().is_empty() => (
            f.trim().to_owned(),
            order
                .map(|o| o.trim().to_owned())
                .filter(|o| !o.is_empty())
                .unwrap_or_else(|| "desc".to_owned()),
        ),
        (_, Some(order)) if !order.trim().is_empty() => {
            let order = order.trim();
            match order.split_once(char::is_whitespace) {
                Some((f, d)) => (f.trim().to_owned(), d.trim().to_owned()),
                None => (order.to_owned(), "desc".to_owned()),
            }
        }
        _ => return Ok(None),
    };

    let direction = match direction.to_ascii_lowercase().as_str() {
        "asc" => "asc",
        "desc" => "desc",
        other => return Err(format!("sort direction must be asc or desc, got {other:?}")),
    };

    let allowed: &[&str] = match kind {
        SearchKind::Cve => &CVE_SORT_FIELDS,
        SearchKind::Errata => &ERRATA_SORT_FIELDS,
    };
    if !allowed.contains(&field.as_str()) {
        return Err(format!(
            "sort field {field:?} is not supported; use one of: {}",
            allowed.join(", ")
        ));
    }

    Ok(Some(format!("{} {direction}", solr_sort_field(&field)?)))
}

/// Maps a documented sort field to the field name this index actually carries.
///
/// Two of the advisory sort fields in the upstream contract have no direct
/// equivalent yet (RHOKP-1760 gap list): the update date is stored as
/// `errata_updated_date`, and there is no severity-level field at all. The
/// rename is bridged here; the missing field reports a clear error rather than
/// letting Solr fail with an opaque one.
fn solr_sort_field(field: &str) -> Result<&str, String> {
    Ok(match field {
        // TODO(RHOKP-1760): drop this mapping once the index field is renamed.
        "portal_update_date" => "errata_updated_date",
        "portal_severity_level" => {
            return Err(
                "sort field \"portal_severity_level\" is not available in this index yet; \
                 sort by portal_publication_date or portal_advisory_type instead"
                    .to_owned(),
            )
        }
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(json: serde_json::Value) -> SearchInput {
        serde_json::from_value(json).expect("SearchInput should deserialize")
    }

    fn normalized(json: serde_json::Value, kind: SearchKind) -> NormalizedSearch {
        normalize(input(json), kind).expect("input should normalize")
    }

    #[test]
    fn cve_ids_are_validated_and_upcased() {
        assert_eq!(normalize_cve_id("cve-2024-1234").unwrap(), "CVE-2024-1234");
        assert_eq!(
            normalize_cve_id("  CVE-2021-44228 ").unwrap(),
            "CVE-2021-44228"
        );
        assert!(
            normalize_cve_id("CVE-2024-123").is_err(),
            "sequence too short"
        );
        assert!(normalize_cve_id("RHSA-2024:1234").is_err());
        assert!(normalize_cve_id("CVE-2024-1234-extra").is_err());
        assert!(normalize_cve_id("").is_err());
    }

    #[test]
    fn cve_ids_in_the_future_are_rejected() {
        let next_year = current_year() + 1;
        let err = normalize_cve_id(&format!("CVE-{next_year}-1234")).unwrap_err();
        assert!(
            err.contains("cannot be greater than the current year"),
            "{err}"
        );
    }

    #[test]
    fn advisory_ids_normalize_to_the_indexed_separator() {
        assert_eq!(
            normalize_advisory_id("rhsa-2024-1234").unwrap(),
            "RHSA-2024:1234"
        );
        assert_eq!(
            normalize_advisory_id("RHBA-2016:0144").unwrap(),
            "RHBA-2016:0144"
        );
        assert!(normalize_advisory_id("RHXX-2024:1234").is_err());
        assert!(normalize_advisory_id("CVE-2024-1234").is_err());
    }

    /// Upstream's own tests assert on substrings of these rejection messages,
    /// so clients and test suites written against that server match on them.
    /// Changing the wording here is a compatibility break, not a copy edit.
    #[test]
    fn rejection_messages_keep_the_substrings_clients_match_on() {
        assert!(
            normalize_cve_id("not-a-cve")
                .unwrap_err()
                .contains("CVE-YYYY-NNNN"),
            "upstream matches on \"CVE-YYYY-NNNN\""
        );
        assert!(
            normalize_advisory_id("RHSA-2024")
                .unwrap_err()
                .contains("RHSA/RHEA/RHBA"),
            "upstream matches on \"RHSA/RHEA/RHBA\""
        );

        let raw: RawSearchInput = serde_json::from_value(serde_json::json!("{\"query\":\"rhel}"))
            .expect("a string input should deserialize");
        assert!(
            raw.resolve().unwrap_err().contains("valid JSON"),
            "upstream matches on \"valid JSON\""
        );
    }

    #[test]
    fn year_conversion_is_exact_at_boundaries() {
        // 2024-01-01 and 2023-12-31 are adjacent days either side of a year end.
        assert_eq!(year_from_unix_days(19_723), 2024);
        assert_eq!(year_from_unix_days(19_722), 2023);
    }

    #[test]
    fn empty_input_defaults_to_match_all() {
        let n = normalized(serde_json::json!({}), SearchKind::Cve);
        assert_eq!(n.query, MATCH_ALL);
        assert_eq!(n.rows, DEFAULT_ROWS);
        assert_eq!(n.start, 0);
        assert!(n.filters.is_empty());
        assert_eq!(n.sort, None);
    }

    #[test]
    fn legacy_q_alias_is_accepted() {
        let n = normalized(serde_json::json!({ "q": "log4j" }), SearchKind::Cve);
        assert_eq!(n.query, "log4j");
        // An explicit query wins over the alias.
        let n = normalized(
            serde_json::json!({ "q": "log4j", "query": "openssl" }),
            SearchKind::Cve,
        );
        assert_eq!(n.query, "openssl");
    }

    #[test]
    fn blank_query_falls_back_to_match_all() {
        let n = normalized(serde_json::json!({ "query": "   " }), SearchKind::Cve);
        assert_eq!(n.query, MATCH_ALL);
    }

    #[test]
    fn pagination_is_read_from_either_position_and_clamped() {
        let n = normalized(
            serde_json::json!({ "pagination": { "rows": 25, "start": 50 } }),
            SearchKind::Errata,
        );
        assert_eq!((n.rows, n.start), (25, 50));

        let n = normalized(
            serde_json::json!({ "rows": 7, "start": 3 }),
            SearchKind::Errata,
        );
        assert_eq!((n.rows, n.start), (7, 3));

        let n = normalized(serde_json::json!({ "rows": 5000 }), SearchKind::Errata);
        assert_eq!(n.rows, MAX_ROWS);
        let n = normalized(serde_json::json!({ "rows": 0 }), SearchKind::Errata);
        assert_eq!(n.rows, 1);
    }

    #[test]
    fn filter_clauses_are_collected_from_both_spellings() {
        let n = normalized(
            serde_json::json!({
                "filter": { "filterQuery": "documentKind:Cve" },
                "filterQueries": ["cve_threatSeverity:Critical", "  "],
            }),
            SearchKind::Cve,
        );
        assert_eq!(
            n.filters,
            vec!["documentKind:Cve", "cve_threatSeverity:Critical"]
        );
    }

    #[test]
    fn cve_severity_casing_is_corrected() {
        let n = normalized(
            serde_json::json!({
                "filter": { "filterQuery": "cve_threatSeverity:critical AND cve_threatSeverity:LOW" },
            }),
            SearchKind::Cve,
        );
        assert_eq!(
            n.filters,
            vec!["cve_threatSeverity:Critical AND cve_threatSeverity:Low"]
        );
    }

    #[test]
    fn unknown_severity_values_are_left_alone() {
        let n = normalized(
            serde_json::json!({ "filterQuery": "cve_threatSeverity:bogus" }),
            SearchKind::Cve,
        );
        assert_eq!(n.filters, vec!["cve_threatSeverity:bogus"]);
    }

    #[test]
    fn errata_severity_none_matches_either_index_spelling() {
        let n = normalized(
            serde_json::json!({ "filterQueries": ["portal_severity:\"None\""] }),
            SearchKind::Errata,
        );
        assert_eq!(n.filters, vec!["portal_severity:(\"None\" OR \"(none)\")"]);
    }

    #[test]
    fn local_params_in_a_filter_are_rejected() {
        let err = normalize(
            input(serde_json::json!({ "filterQuery": "{!func}sum(1,1)" })),
            SearchKind::Cve,
        )
        .unwrap_err();
        assert!(err.contains("local parameters"), "{err}");
    }

    #[test]
    fn sort_accepts_a_full_clause_or_a_field_plus_direction() {
        let n = normalized(
            serde_json::json!({ "sort": { "sortOrder": "cve_publicDate asc" } }),
            SearchKind::Cve,
        );
        assert_eq!(n.sort.as_deref(), Some("cve_publicDate asc"));

        let n = normalized(
            serde_json::json!({ "sortField": "cve_publicDate" }),
            SearchKind::Cve,
        );
        assert_eq!(n.sort.as_deref(), Some("cve_publicDate desc"));

        let n = normalized(
            serde_json::json!({ "sort": { "sortField": "lastModifiedDate", "sortOrder": "asc" } }),
            SearchKind::Cve,
        );
        assert_eq!(n.sort.as_deref(), Some("lastModifiedDate asc"));
    }

    #[test]
    fn sort_rejects_fields_outside_the_documented_set() {
        let err = normalize(
            input(serde_json::json!({ "sortField": "score" })),
            SearchKind::Cve,
        )
        .unwrap_err();
        assert!(err.contains("not supported"), "{err}");

        let err = normalize(
            input(serde_json::json!({ "sortOrder": "cve_publicDate sideways" })),
            SearchKind::Cve,
        )
        .unwrap_err();
        assert!(err.contains("asc or desc"), "{err}");
    }

    #[test]
    fn advisory_update_date_sort_maps_to_the_current_field_name() {
        let n = normalized(
            serde_json::json!({ "sortOrder": "portal_update_date desc" }),
            SearchKind::Errata,
        );
        assert_eq!(n.sort.as_deref(), Some("errata_updated_date desc"));
    }

    #[test]
    fn severity_level_sort_reports_the_index_gap() {
        let err = normalize(
            input(serde_json::json!({ "sortField": "portal_severity_level" })),
            SearchKind::Errata,
        )
        .unwrap_err();
        assert!(err.contains("not available in this index yet"), "{err}");
    }

    #[test]
    fn input_is_accepted_as_an_object_or_a_json_string() {
        let raw: RawSearchInput =
            serde_json::from_value(serde_json::json!({ "query": "log4j" })).unwrap();
        assert_eq!(raw.resolve().unwrap().query.as_deref(), Some("log4j"));

        let raw: RawSearchInput =
            serde_json::from_value(serde_json::json!(r#"{"query":"log4j"}"#)).unwrap();
        assert_eq!(raw.resolve().unwrap().query.as_deref(), Some("log4j"));
    }

    #[test]
    fn a_bad_json_string_input_reports_why() {
        let raw: RawSearchInput = serde_json::from_value(serde_json::json!("{not json")).unwrap();
        assert!(raw.resolve().unwrap_err().contains("must be valid JSON"));

        let raw: RawSearchInput = serde_json::from_value(serde_json::json!("[1,2]")).unwrap();
        assert!(raw
            .resolve()
            .unwrap_err()
            .contains("must decode to an object"));
    }
}
