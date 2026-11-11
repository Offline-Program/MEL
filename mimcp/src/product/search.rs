// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! The `search_products` pipeline, ported faithfully from the online product
//! MCP server + subgraph gateway.
//!
//! Online, `search_products` runs: reject empty name ->
//! `RewriteProductNamesHandler` (version-strip + alias rewrite) ->
//! `KnownProductIdHandler` (short-circuit well-known products / uuids to an exact
//! hit) -> GraphQL `products_search(filter:{name, fuzziness: LOW}, first: 5)`
//! (Fuse.js over a name+alternateNames corpus) -> rank + attach low-relevance
//! notes. Each stage is reproduced here:
//!
//! - [`resolve_product_name`] ports `rh_fastmcp_internal.product_names.resolve`.
//! - [`known_product_id`] ports `app/data/product_known_ids.py`.
//! - [`build_search_index`] ports the gateway's corpus join
//!   (`findOrCreateMapping` + `getRedHatPrefixEnhancedProductName`) over the PLC
//!   catalog and `web-products.json`.
//! - [`ProductSearchIndex::search`] wraps the Fuse port with the gateway's LOW
//!   threshold (<= 0.2) and relevance rounding.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::product::catalog::{ProductCatalog, ProductRecord, WebProduct};
use crate::product::fuse::FuseIndex;
use crate::product::records::SearchProductHit;

/// Scores at or below this (on the 0-1 relevance scale) carry a low-relevance
/// caveat. Mirrors `LOW_RELEVANCE_THRESHOLD` in the online `search_products`.
const LOW_RELEVANCE_THRESHOLD: f64 = 0.9;

/// The low-relevance caveat text, copied verbatim from the online server.
const LOW_RELEVANCE_NOTE: &str =
    "Product details were found for this match. Please note that the relevance \
     score indicates this result may or may not correspond to the product you \
     are seeking. Kindly verify before proceeding.";

/// Gateway fuzziness LOW threshold: item scores above this are dropped.
const LOW_THRESHOLD: f64 = 0.2;

/// Maximum hits returned, mirroring the online `products_search(first: 5)`.
const MAX_HITS: usize = 5;

/// Well-known product name -> uuid, ported from `product_known_ids.py`. These
/// uuids match the PLC catalog uuids, so a short-circuited hit is directly usable
/// with `get_product_by_id`.
const KNOWN_PRODUCT_IDS: &[(&str, &str)] = &[
    (
        "Red Hat Enterprise Linux",
        "0579380b-2d8f-4cc9-9997-99ef12d3435c",
    ),
    (
        "Red Hat OpenShift Container Platform",
        "9bbc4758-50e0-4b73-89dc-2bae80f1d394",
    ),
    (
        "Red Hat Ansible Automation Platform",
        "d2c793b1-dec9-42a9-b4bc-4295b66d7cfc",
    ),
    (
        "Red Hat OpenStack Platform",
        "6ecffb49-dafd-4335-a0de-c50839bc43b4",
    ),
    (
        "Red Hat OpenShift Data Foundation",
        "cc168755-3265-4da0-b436-0c23b7905396",
    ),
    ("Red Hat Quay", "bb66192f-e0d8-43ab-9790-435e32fbf9f2"),
    (
        "Red Hat Ceph Storage",
        "e53cdf38-86bb-473c-a6e2-7358e7afe3c7",
    ),
    (
        "Red Hat JBoss Enterprise Application Platform",
        "f08b73c1-395e-47a5-8482-0946e76526d4",
    ),
    (
        "Red Hat Virtualization",
        "70edeac8-9c3f-4b71-a5b4-a1b6c2a5b8bf",
    ),
    (
        "Red Hat Developer Hub",
        "2597f851-41f0-4b3c-bdac-d8c224bd3c71",
    ),
    (
        "Red Hat build of Keycloak",
        "5de41357-e188-4b5a-99ea-fad4ca57db78",
    ),
    ("Red Hat Lightspeed", "f4210477-88f3-41f8-ae10-e6610e608e1e"),
    (
        "Red Hat Satellite Server",
        "30888478-ca60-4bfa-82d9-e247e530f755",
    ),
];

/// Alias groups (canonical, short names), ported from
/// `rh_fastmcp_internal/product_names/data/product-name-aliases.yaml`. Short
/// names are matched case-insensitively after version stripping.
const ALIAS_GROUPS: &[(&str, &[&str])] = &[
    ("Red Hat Enterprise Linux", &["rhel", "enterprise linux"]),
    ("Red Hat Enterprise Linux AI", &["rhel ai"]),
    (
        "Red Hat OpenShift Container Platform",
        &["openshift", "ocp", "ocp4", "openshift 4"],
    ),
    (
        "Red Hat OpenShift Container Platform 3",
        &["ocp3", "openshift 3"],
    ),
    (
        "Red Hat OpenShift AI Self-Managed",
        &["openshift ai", "rhoai", "openshift data science"],
    ),
    (
        "Red Hat OpenShift Data Foundation",
        &["odf", "ocs", "data foundation"],
    ),
    (
        "Red Hat OpenShift Virtualization",
        &["cnv", "openshift virtualization"],
    ),
    ("Red Hat OpenShift Service Mesh", &["ossm", "service mesh"]),
    ("Red Hat OpenShift GitOps", &["gitops"]),
    ("Red Hat OpenShift Pipelines", &["pipelines"]),
    ("Red Hat OpenShift Serverless", &["serverless"]),
    ("Red Hat OpenShift Dev Spaces", &["codeready", "dev spaces"]),
    (
        "Red Hat Ansible Automation Platform",
        &[
            "ansible",
            "aap",
            "ansible automation platform",
            "ansible tower",
            "tower",
        ],
    ),
    (
        "Red Hat Satellite Server",
        &["satellite", "red hat satellite"],
    ),
    ("Red Hat OpenStack Platform", &["openstack", "rhosp"]),
    ("Red Hat Virtualization", &["rhv"]),
    (
        "Red Hat Advanced Cluster Management for Kubernetes",
        &["rhacm", "acm", "advanced cluster management"],
    ),
    (
        "Red Hat Advanced Cluster Security for Kubernetes",
        &["rhacs", "acs", "stackrox"],
    ),
    (
        "Red Hat JBoss Enterprise Application Platform",
        &["jboss", "eap", "jboss eap"],
    ),
    ("Red Hat JBoss Web Server", &["jws", "jboss web server"]),
    ("AMQ broker", &["activemq", "amq broker"]),
    ("streams for Apache Kafka", &["kafka", "amq streams"]),
    (
        "Red Hat Developer Hub",
        &["rhdh", "developer hub", "backstage"],
    ),
    (
        "Red Hat Developer Toolset",
        &["devtools", "developer toolset", "rhdt"],
    ),
    (
        "Red Hat Lightspeed",
        &["insights", "red hat insights", "lightspeed"],
    ),
    ("single sign-on", &["rhsso", "sso"]),
    (
        "Red Hat build of Keycloak",
        &["keycloak", "rhbk", "build of keycloak"],
    ),
    ("Red Hat build of Quarkus", &["quarkus"]),
    ("Red Hat build of OpenJDK", &["openjdk", "jdk"]),
    ("Red Hat build of Apache Camel for Spring Boot", &["camel"]),
    ("Red Hat Fuse", &["fuse", "integration"]),
    (
        "Red Hat 3scale API Management",
        &["3scale", "api management"],
    ),
    ("Red Hat Ceph Storage", &["ceph", "ceph storage"]),
    ("Red Hat Gluster Storage", &["gluster", "gluster storage"]),
    ("Red Hat Quay", &["quay"]),
    ("migration toolkit for virtualization", &["mtv"]),
    ("migration toolkit for containers", &["mtc"]),
    ("migration toolkit for applications", &["mta"]),
    ("Red Hat Device Edge", &["rhde"]),
    (
        "Red Hat Process Automation Manager",
        &["pam", "process automation"],
    ),
    ("Red Hat Decision Manager", &["rhdm", "decision manager"]),
];

/// Lazily-built lowercased short-name -> canonical lookup.
fn alias_lookup() -> &'static HashMap<String, &'static str> {
    static LOOKUP: OnceLock<HashMap<String, &'static str>> = OnceLock::new();
    LOOKUP.get_or_init(|| {
        let mut map = HashMap::new();
        for (canonical, shorts) in ALIAS_GROUPS {
            for short in *shorts {
                map.insert(short.to_lowercase(), *canonical);
            }
        }
        map
    })
}

/// Case-insensitive string equality (approximates the gateway's
/// locale-accent-sensitive `matchIgnoreCase`).
fn match_ignore_case(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// True when `token` is a bare version token, e.g. `8`, `4.14`, `8-beta`,
/// `2.7.x`. Ports the `VERSION_TOKEN` regex from `resolve.py`.
fn is_version_token(token: &str) -> bool {
    // Grammar: digits(.digits)* optionally followed by -(beta|latest|word).
    let (head, tail) = match token.split_once('-') {
        Some((h, t)) => (h, Some(t)),
        None => (token, None),
    };
    if head.is_empty() {
        return false;
    }
    let mut parts = head.split('.');
    if !parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    match tail {
        None => true,
        // `[\w-]+` (letters, digits, underscore, hyphen); non-empty.
        Some(t) => {
            !t.is_empty()
                && t.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        }
    }
}

/// Removes bare version tokens from a product name (`resolve.strip_version_tokens`).
fn strip_version_tokens(name: &str) -> String {
    name.split_whitespace()
        .filter(|t| !is_version_token(t))
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_owned()
}

/// Resolves a user-supplied product name to its canonical form, mirroring
/// `resolve_product_name(...).canonical` (which `RewriteProductNamesHandler`
/// writes back onto the `name` variable).
///
/// Strips version tokens, normalizes whitespace/case for alias lookup, and
/// returns the canonical name on an alias hit; otherwise returns the
/// version-stripped name (or the original when stripping emptied it).
pub fn resolve_product_name(text: &str) -> String {
    let original = text.trim();
    if original.is_empty() {
        return text.to_owned();
    }
    let stripped = strip_version_tokens(original);
    if stripped.is_empty() {
        return original.to_owned();
    }
    let normalized = stripped.to_lowercase();
    let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(canonical) = alias_lookup().get(&normalized) {
        return (*canonical).to_owned();
    }
    stripped
}

/// Returns `true` if `s` is a canonical UUID (`8-4-4-4-12` hex). Ports
/// `UUID_PATTERN` from `product_known_ids.py`.
fn is_uuid(s: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != groups.len() {
        return false;
    }
    parts
        .iter()
        .zip(groups.iter())
        .all(|(p, &len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Looks up a well-known product by canonical name (case-insensitive), returning
/// `(canonical_name, uuid)`. Ports `lookup_known_product_id`.
fn known_product_id(name: &str) -> Option<(&'static str, &'static str)> {
    let key = name.trim().to_lowercase();
    KNOWN_PRODUCT_IDS
        .iter()
        .find(|(canonical, _)| canonical.to_lowercase() == key)
        .map(|&(canonical, uuid)| (canonical, uuid))
}

/// Looks up the canonical name for a known uuid (case-insensitive).
fn canonical_for_uuid(uuid: &str) -> Option<&'static str> {
    let key = uuid.to_lowercase();
    KNOWN_PRODUCT_IDS
        .iter()
        .find(|(_, u)| u.to_lowercase() == key)
        .map(|&(canonical, _)| canonical)
}

/// Enhances a product name by toggling the `"Red Hat "` prefix (case-insensitive
/// prefix check). Ports `getRedHatPrefixEnhancedProductName`.
fn red_hat_prefix_enhanced(name: &str) -> String {
    if name.to_lowercase().starts_with("red hat ") {
        name[8..].to_owned()
    } else {
        format!("Red Hat {name}")
    }
}

/// One corpus entry used to build the Fuse index.
struct CorpusEntry {
    /// Primary searchable name (web product name, or lifecycle name when created).
    name: String,
    /// Alternate searchable names (web aliases plus joined lifecycle names).
    alternate_names: Vec<String>,
    /// The PLC uuid this entry resolves to, once a lifecycle product joins it.
    /// Entries without one are not searchable (the online `sources: LIFECYCLE`).
    lifecycle_uuid: Option<String>,
}

impl CorpusEntry {
    /// Appends `name` to the alternate names unless already present
    /// (case-insensitive), mirroring `uniqueArrayIgnoreCase`.
    fn add_alternate(&mut self, name: &str) {
        if !self
            .alternate_names
            .iter()
            .any(|a| match_ignore_case(a, name))
        {
            self.alternate_names.push(name.to_owned());
        }
    }
}

/// The built `search_products` index: a Fuse index plus the uuid each record
/// resolves to.
pub struct ProductSearchIndex {
    /// The Fuse index over `(name, alternateNames)` corpus entries.
    fuse: FuseIndex,
    /// uuid per Fuse record, aligned by index.
    uuids: Vec<String>,
}

impl ProductSearchIndex {
    /// Runs the Fuse search, applies the gateway's LOW (<= 0.2) filter, rounds to
    /// a relevance score, resolves each hit back to a product, and caps at
    /// [`MAX_HITS`]. Hits are returned best-first.
    fn search(&self, catalog: &ProductCatalog, query: &str) -> Vec<SearchProductHit> {
        self.fuse
            .search(query)
            .into_iter()
            .filter(|h| h.score <= LOW_THRESHOLD)
            .take(MAX_HITS)
            .map(|h| {
                let uuid = &self.uuids[h.index];
                let record = catalog.by_uuid(uuid);
                let relevance = ((1.0 - h.score) * 100.0).round() / 100.0;
                let note =
                    (relevance <= LOW_RELEVANCE_THRESHOLD).then(|| LOW_RELEVANCE_NOTE.to_owned());
                SearchProductHit {
                    id: Some(uuid.clone()),
                    name: record.and_then(|r| r.name.clone()),
                    former_names: record.and_then(|r| r.former_names.clone()),
                    relevance_score: Some(relevance),
                    note,
                }
            })
            .collect()
    }
}

/// Builds the `search_products` corpus and Fuse index from the PLC catalog and
/// web products, porting the gateway's `findOrCreateMapping` join.
///
/// Web products seed the corpus (supplying `alternateNames`); each lifecycle
/// (PLC) product is then matched into an existing entry by exact name,
/// `"Red Hat "`-prefix-insensitive name, or alternate-name match, or else a
/// name-only entry is created. Only entries that ended up carrying a lifecycle
/// uuid are searchable (the online `sources: LIFECYCLE`).
pub fn build_search_index(products: &[ProductRecord], web: &[WebProduct]) -> ProductSearchIndex {
    let mut corpus: Vec<CorpusEntry> = web
        .iter()
        .map(|w| CorpusEntry {
            name: w.name.clone(),
            alternate_names: w.alternate_names.clone().unwrap_or_default(),
            lifecycle_uuid: None,
        })
        .collect();

    for product in products {
        let Some(name) = product.name.as_deref() else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        join_lifecycle_product(&mut corpus, name, &product.uuid);
    }

    debug_assert!(!corpus.is_empty() || products.is_empty());

    let (fuse_docs, uuids): (Vec<(String, Vec<String>)>, Vec<String>) = corpus
        .into_iter()
        .filter_map(|e| {
            e.lifecycle_uuid
                .map(|uuid| ((e.name, e.alternate_names), uuid))
        })
        .unzip();

    ProductSearchIndex {
        fuse: FuseIndex::build(&fuse_docs),
        uuids,
    }
}

/// Joins one lifecycle product into the corpus, mirroring
/// `findExistingMappingByName` + the create branch of `findOrCreateMapping`.
fn join_lifecycle_product(corpus: &mut Vec<CorpusEntry>, name: &str, uuid: &str) {
    // 1. Exact name match always wins and overwrites the lifecycle uuid.
    if let Some(entry) = corpus.iter_mut().find(|e| match_ignore_case(&e.name, name)) {
        entry.lifecycle_uuid = Some(uuid.to_owned());
        return;
    }

    let enhanced = red_hat_prefix_enhanced(name);

    // 2. "Red Hat" prefix-insensitive name match.
    if let Some(entry) = corpus
        .iter_mut()
        .find(|e| match_ignore_case(&e.name, &enhanced))
    {
        entry.add_alternate(name);
        if entry.lifecycle_uuid.is_none() {
            entry.lifecycle_uuid = Some(uuid.to_owned());
        }
        return;
    }

    // 3. Alternate-name match (exact or prefix-insensitive).
    if let Some(entry) = corpus.iter_mut().find(|e| {
        e.alternate_names
            .iter()
            .any(|a| match_ignore_case(a, name) || match_ignore_case(a, &enhanced))
    }) {
        entry.add_alternate(name);
        if entry.lifecycle_uuid.is_none() {
            entry.lifecycle_uuid = Some(uuid.to_owned());
        }
        return;
    }

    // 4. No match: create a new name-only entry carrying this lifecycle uuid.
    corpus.push(CorpusEntry {
        name: name.to_owned(),
        alternate_names: Vec::new(),
        lifecycle_uuid: Some(uuid.to_owned()),
    });
}

/// Runs the full `search_products` pipeline for a (non-empty, pre-trimmed) query.
///
/// Applies alias rewrite + version stripping, the known-id / uuid short-circuit
/// (exact hit, relevance 1.0), then the Fuse-backed corpus search.
pub fn search_products(catalog: &ProductCatalog, raw_name: &str) -> Vec<SearchProductHit> {
    let rewritten = resolve_product_name(raw_name);

    // Known-id / uuid short-circuit (KnownProductIdHandler).
    if is_uuid(&rewritten) {
        if let Some(canonical) = canonical_for_uuid(&rewritten) {
            if let Some((canonical_name, uuid)) = known_product_id(canonical) {
                return vec![exact_hit(canonical_name, uuid)];
            }
        }
    } else if let Some((canonical_name, uuid)) = known_product_id(&rewritten) {
        return vec![exact_hit(canonical_name, uuid)];
    }

    catalog.search_index().search(catalog, &rewritten)
}

/// Builds the exact (relevance 1.0, no note) hit the known-id short-circuit
/// returns. Mirrors `build_products_search_raw` (former_names `[]`).
fn exact_hit(name: &str, uuid: &str) -> SearchProductHit {
    SearchProductHit {
        id: Some(uuid.to_owned()),
        name: Some(name.to_owned()),
        former_names: Some(Vec::new()),
        relevance_score: Some(1.0),
        note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_version_tokens() {
        assert_eq!(strip_version_tokens("openshift 4.14"), "openshift");
        assert_eq!(strip_version_tokens("rhel 8"), "rhel");
        assert_eq!(strip_version_tokens("rhel 8-beta"), "rhel");
        assert_eq!(
            strip_version_tokens("Red Hat Enterprise Linux"),
            "Red Hat Enterprise Linux"
        );
        // All-version input strips to empty.
        assert_eq!(strip_version_tokens("8"), "");
    }

    #[test]
    fn resolves_aliases_after_version_strip() {
        assert_eq!(resolve_product_name("rhel"), "Red Hat Enterprise Linux");
        assert_eq!(resolve_product_name("rhel 8"), "Red Hat Enterprise Linux");
        assert_eq!(
            resolve_product_name("OCP 4.14"),
            "Red Hat OpenShift Container Platform"
        );
        // Unknown alias: returns the version-stripped name unchanged.
        assert_eq!(resolve_product_name("Some Product 9"), "Some Product");
        // Empty after strip: original preserved.
        assert_eq!(resolve_product_name("8"), "8");
    }

    #[test]
    fn detects_uuids() {
        assert!(is_uuid("0579380b-2d8f-4cc9-9997-99ef12d3435c"));
        assert!(is_uuid("0579380B-2D8F-4CC9-9997-99EF12D3435C"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("Red Hat Enterprise Linux"));
    }

    #[test]
    fn toggles_red_hat_prefix() {
        assert_eq!(red_hat_prefix_enhanced("OpenShift"), "Red Hat OpenShift");
        assert_eq!(red_hat_prefix_enhanced("Red Hat Quay"), "Quay");
        assert_eq!(red_hat_prefix_enhanced("red hat quay"), "quay");
    }

    fn rec(uuid: &str, name: &str) -> ProductRecord {
        ProductRecord {
            uuid: uuid.to_owned(),
            name: Some(name.to_owned()),
            former_names: None,
            is_operator: None,
            is_layered_product: None,
            release_cadence: None,
            package: None,
            link: None,
            footnote: None,
            show_final_minor_release: None,
            show_openshift_compatibility: None,
            all_phases: Vec::new(),
            versions: Vec::new(),
        }
    }

    fn web(name: &str, alts: &[&str]) -> WebProduct {
        WebProduct {
            name: name.to_owned(),
            alternate_names: Some(alts.iter().map(|s| s.to_string()).collect()),
            categories: None,
        }
    }

    #[test]
    fn corpus_join_matches_exact_prefix_alias_and_creates() {
        // Neutral, fictional names that are neither known-ids nor aliases, so the
        // corpus path (not the short-circuit) is exercised.
        let web = vec![
            web("Zeta Tool", &[]),           // exact-name join target
            web("Acme Widget", &["AW"]),     // prefix-insensitive join target
            web("Orbit Mesh", &["Orbiter"]), // alternate-name join target
        ];
        let products = vec![
            rec("u-zeta", "Zeta Tool"),           // exact name match
            rec("u-acme", "Red Hat Acme Widget"), // prefix-insensitive -> "Acme Widget"
            rec("u-orbit", "Orbiter"),            // matches via alternate name
            rec("u-new", "Standalone Gadget"),    // no match -> created name-only
        ];
        let catalog = ProductCatalog::from_parts(products, web);

        let hits = search_products(&catalog, "Zeta Tool");
        assert_eq!(hits[0].id.as_deref(), Some("u-zeta"));

        let hits = search_products(&catalog, "Red Hat Acme Widget");
        assert_eq!(hits[0].id.as_deref(), Some("u-acme"));

        let hits = search_products(&catalog, "Orbiter");
        assert_eq!(hits[0].id.as_deref(), Some("u-orbit"));

        let hits = search_products(&catalog, "Standalone Gadget");
        assert_eq!(hits[0].id.as_deref(), Some("u-new"));
    }

    #[test]
    fn known_id_short_circuits_to_exact_hit() {
        let catalog = ProductCatalog::from_parts(Vec::new(), Vec::new());
        // Alias -> canonical -> known id, even with an empty corpus.
        let hits = search_products(&catalog, "rhel");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name.as_deref(), Some("Red Hat Enterprise Linux"));
        assert_eq!(
            hits[0].id.as_deref(),
            Some("0579380b-2d8f-4cc9-9997-99ef12d3435c")
        );
        assert_eq!(hits[0].relevance_score, Some(1.0));
        assert_eq!(hits[0].former_names, Some(Vec::new()));
        assert!(hits[0].note.is_none());

        // A known uuid short-circuits too.
        let hits = search_products(&catalog, "0579380b-2d8f-4cc9-9997-99ef12d3435c");
        assert_eq!(hits[0].name.as_deref(), Some("Red Hat Enterprise Linux"));
    }

    #[test]
    fn unknown_query_returns_empty() {
        let catalog = ProductCatalog::from_parts(Vec::new(), Vec::new());
        assert!(search_products(&catalog, "totally unknown zzzxyz").is_empty());
    }
}
