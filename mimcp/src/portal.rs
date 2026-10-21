// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Access to the lexical `portal` Solr collection.
//!
//! The security tools (CVE and errata) are exact-ID lookups and structured
//! `filterQuery` searches, so they target the lexical `portal` index rather than
//! the chunked `portal-rag` index used by the hybrid `search` tool. The two
//! indexes have different schemas, hence a distinct document type and query
//! builder here.

use serde::{Deserialize, Serialize};

/// `documentKind` value identifying a CVE document.
pub const KIND_CVE: &str = "Cve";

/// `documentKind` value identifying an errata (advisory) document.
pub const KIND_ERRATA: &str = "Errata";

/// Fields returned for CVE search hits (`search_cves`).
pub const CVE_SUMMARY_FL: &str = "\
    url_slug,cve_details,cve_threatSeverity,cve_affected_products,\
    cve_publicDate,cve_updated_date,lastModifiedDate";

/// Fields returned for a full CVE record (`get_cve_by_id`,
/// `list_cve_affected_products`).
pub const CVE_DETAIL_FL: &str = "\
    url_slug,cve_details,cve_threatSeverity,cve_affected_products,\
    cve_publicDate,cve_created_date,cve_updated_date,lastModifiedDate,\
    view_uri,exploit_known,details_source,cve_mitigation,cve_external_references,\
    cve_bugzilla_url,cve_bugzilla_id,cve_bugzilla_description,\
    cvss2_nvd_score,cvss2_nvd_vector,cvss2_redhat_score,cvss2_redhat_vector,\
    cvss3_nvd_score,cvss3_nvd_vector,cvss3_redhat_score,cvss3_redhat_vector";

/// Fields returned for advisory search hits (`search_advisories`).
pub const ERRATA_SUMMARY_FL: &str = "\
    id,allTitle,portal_advisory_type,portal_severity,portal_synopsis,\
    portal_description,portal_summary,portal_solution,portal_publication_date,\
    errata_updated_date,lastModifiedDate,portal_product_names,view_uri,\
    errata_cves,errata_bugzillas,errata_references";

/// Fields returned for a single advisory record (`get_errata_by_id`) and for
/// CVE-to-advisory linkage (`list_advisories_by_cve`).
pub const ERRATA_DETAIL_FL: &str = "\
    id,portal_synopsis,portal_advisory_type,portal_severity,portal_product_names,\
    portal_publication_date,errata_updated_date,lastModifiedDate,errata_bugzillas";

/// Fields returned for an advisory's package payload (`list_advisory_packages`).
pub const ERRATA_PACKAGES_FL: &str = "id,errata_packages";

/// A query against the lexical `portal` collection.
///
/// `fq` holds already-rendered filter clauses; the mandatory `documentKind`
/// clause is always a separate entry so a malformed client-supplied clause
/// cannot widen the result set beyond the requested document kind.
pub struct PortalQuery {
    /// Main query string (`q`).
    pub query: String,
    /// Filter clauses, each sent as its own `fq` entry (AND-combined by Solr).
    pub filters: Vec<String>,
    /// Comma-separated field list (`fl`).
    pub fields: &'static str,
    /// Maximum number of documents to return (`rows`).
    pub rows: u32,
    /// Zero-based offset of the first document to return (`start`).
    pub start: u32,
    /// Optional `sort` clause, e.g. `cve_publicDate desc`.
    pub sort: Option<String>,
}

impl PortalQuery {
    /// Builds a query restricted to a single `documentKind`.
    pub fn new(kind: &str, query: impl Into<String>, fields: &'static str) -> Self {
        Self {
            query: query.into(),
            filters: vec![format!("documentKind:{kind}")],
            fields,
            rows: 10,
            start: 0,
            sort: None,
        }
    }

    /// Builds an exact-ID lookup: a single document, no sort.
    pub fn lookup(kind: &str, query: impl Into<String>, fields: &'static str) -> Self {
        let mut q = Self::new(kind, query, fields);
        q.rows = 1;
        q
    }

    /// Appends a filter clause.
    pub fn filter(mut self, clause: impl Into<String>) -> Self {
        self.filters.push(clause.into());
        self
    }

    /// Sets the page window.
    pub fn page(mut self, rows: u32, start: u32) -> Self {
        self.rows = rows;
        self.start = start;
        self
    }

    /// Sets the sort clause.
    pub fn sorted(mut self, sort: Option<String>) -> Self {
        self.sort = sort;
        self
    }
}

/// Top-level response from the `portal` collection.
#[derive(Debug, Deserialize)]
pub struct PortalResponse {
    /// The response body containing matched documents.
    pub response: PortalResponseBody,
}

/// Body of a `portal` collection response.
#[derive(Debug, Deserialize)]
pub struct PortalResponseBody {
    /// Total number of documents matching the query.
    #[serde(rename = "numFound")]
    pub num_found: u64,
    /// Zero-based offset of the first returned document.
    #[serde(default)]
    pub start: u64,
    /// The returned documents (limited by `rows`).
    pub docs: Vec<PortalDoc>,
}

impl PortalResponseBody {
    /// Returns the first matched document, if any.
    pub fn first(self) -> Option<PortalDoc> {
        self.docs.into_iter().next()
    }
}

/// Normalizes a field Solr may return as a scalar or an array into
/// `Option<Vec<String>>`. Mirrors the lenient coercion used for the PortalRag
/// index: a single unexpected shape must not fail the whole response, so
/// non-string values and null elements are dropped rather than erroring.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde_json::Value;

    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(Value::String(s)) => Some(vec![s]),
        Some(Value::Array(items)) => {
            let strings: Vec<String> = items
                .into_iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect();
            (!strings.is_empty()).then_some(strings)
        }
        _ => None,
    })
}

/// Normalizes a field that should surface as a single string but which Solr may
/// return as a one-element array (the upstream security MCP applies the same
/// coercion to its date fields). Non-string scalars are stringified so a
/// numeric or boolean value still round-trips rather than vanishing.
fn scalar_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde_json::Value;

    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(Value::String(s)) => Some(s),
        Some(Value::Array(items)) => items.into_iter().next().and_then(|v| match v {
            Value::String(s) => Some(s),
            Value::Null => None,
            other => Some(other.to_string()),
        }),
        Some(Value::Null) | None => None,
        Some(other) => Some(other.to_string()),
    })
}

/// A document from the lexical `portal` collection.
///
/// Every field is optional: which ones are populated depends on the
/// `documentKind` and on the `fl` the query asked for.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct PortalDoc {
    // --- shared ---
    /// Business identifier. For errata this is the advisory ID (`RHSA-2024:1234`);
    /// for CVEs it is the page path, so CVE code reads `url_slug` instead.
    #[serde(default)]
    pub id: Option<String>,
    /// Full page title.
    #[serde(rename = "allTitle", default, deserialize_with = "scalar_string")]
    pub all_title: Option<String>,
    /// Site-relative canonical URL.
    #[serde(default, deserialize_with = "scalar_string")]
    pub view_uri: Option<String>,
    /// Index-wide last-modified timestamp, used as a fallback update date.
    #[serde(
        rename = "lastModifiedDate",
        default,
        deserialize_with = "scalar_string"
    )]
    pub last_modified_date: Option<String>,

    // --- CVE ---
    /// CVE identifier, e.g. `CVE-2024-1234`.
    #[serde(default, deserialize_with = "scalar_string")]
    pub url_slug: Option<String>,
    /// Vulnerability description.
    #[serde(rename = "cve_details", default, deserialize_with = "scalar_string")]
    pub cve_details: Option<String>,
    /// Red Hat threat severity rating.
    #[serde(
        rename = "cve_threatSeverity",
        default,
        deserialize_with = "scalar_string"
    )]
    pub cve_threat_severity: Option<String>,
    /// Date the CVE was made public.
    #[serde(rename = "cve_publicDate", default, deserialize_with = "scalar_string")]
    pub cve_public_date: Option<String>,
    /// Date the CVE record was created.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cve_created_date: Option<String>,
    /// Date the CVE record was last updated.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cve_updated_date: Option<String>,
    /// Whether a known exploit exists.
    #[serde(default)]
    pub exploit_known: Option<bool>,
    /// Source of the description (`Red Hat` or `Mitre`).
    #[serde(default, deserialize_with = "scalar_string")]
    pub details_source: Option<String>,
    /// Recommended mitigation steps.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cve_mitigation: Option<String>,
    /// URLs to external resources.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub cve_external_references: Option<Vec<String>>,
    /// Bugzilla issue URL.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cve_bugzilla_url: Option<String>,
    /// Bugzilla issue ID.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cve_bugzilla_id: Option<String>,
    /// Bugzilla issue description.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cve_bugzilla_description: Option<String>,
    /// One compact JSON object per affected product release.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub cve_affected_products: Option<Vec<String>>,
    /// NVD CVSS v2 base score.
    #[serde(default)]
    pub cvss2_nvd_score: Option<f64>,
    /// NVD CVSS v2 vector string.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cvss2_nvd_vector: Option<String>,
    /// Red Hat CVSS v2 base score.
    #[serde(default)]
    pub cvss2_redhat_score: Option<f64>,
    /// Red Hat CVSS v2 vector string.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cvss2_redhat_vector: Option<String>,
    /// NVD CVSS v3 base score.
    #[serde(default)]
    pub cvss3_nvd_score: Option<f64>,
    /// NVD CVSS v3 vector string.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cvss3_nvd_vector: Option<String>,
    /// Red Hat CVSS v3 base score.
    #[serde(default)]
    pub cvss3_redhat_score: Option<f64>,
    /// Red Hat CVSS v3 vector string.
    #[serde(default, deserialize_with = "scalar_string")]
    pub cvss3_redhat_vector: Option<String>,

    // --- errata ---
    /// Advisory type, e.g. `Security Advisory`.
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_advisory_type: Option<String>,
    /// Advisory severity.
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_severity: Option<String>,
    /// Advisory synopsis (short title).
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_synopsis: Option<String>,
    /// Advisory description.
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_description: Option<String>,
    /// Advisory topic/summary.
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_summary: Option<String>,
    /// Advisory solution text.
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_solution: Option<String>,
    /// Advisory publication date.
    #[serde(default, deserialize_with = "scalar_string")]
    pub portal_publication_date: Option<String>,
    /// Advisory last-update date.
    #[serde(default, deserialize_with = "scalar_string")]
    pub errata_updated_date: Option<String>,
    /// Products the advisory applies to.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub portal_product_names: Option<Vec<String>>,
    /// CVEs fixed by the advisory.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub errata_cves: Option<Vec<String>>,
    /// Bugzilla issues fixed by the advisory.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub errata_bugzillas: Option<Vec<String>>,
    /// External references cited by the advisory.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub errata_references: Option<Vec<String>>,
    /// Raw package NVRA strings shipped by the advisory.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub errata_packages: Option<Vec<String>>,
}

impl PortalDoc {
    /// Returns the advisory's update date, falling back to the index-wide
    /// last-modified timestamp when the advisory-specific field is absent.
    pub fn advisory_update_date(&self) -> Option<String> {
        self.errata_updated_date
            .clone()
            .or_else(|| self.last_modified_date.clone())
    }

    /// Returns the CVE's update date, falling back to the index-wide
    /// last-modified timestamp.
    pub fn cve_update_date(&self) -> Option<String> {
        self.cve_updated_date
            .clone()
            .or_else(|| self.last_modified_date.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: serde_json::Value) -> PortalDoc {
        serde_json::from_value(json).expect("PortalDoc should deserialize")
    }

    #[test]
    fn multivalued_fields_accept_scalar_and_array() {
        let d = doc(serde_json::json!({
            "errata_cves": "CVE-2021-44228",
            "portal_product_names": ["RHEL 8", "RHEL 9"],
        }));
        assert_eq!(d.errata_cves, Some(vec!["CVE-2021-44228".to_owned()]));
        assert_eq!(
            d.portal_product_names,
            Some(vec!["RHEL 8".to_owned(), "RHEL 9".to_owned()])
        );
    }

    #[test]
    fn scalar_fields_unwrap_single_element_arrays() {
        let d = doc(serde_json::json!({ "cve_publicDate": ["2021-12-10T00:00:00Z"] }));
        assert_eq!(d.cve_public_date.as_deref(), Some("2021-12-10T00:00:00Z"));
    }

    #[test]
    fn unexpected_shapes_do_not_fail_the_response() {
        // A single odd value must not abort deserialization of the whole hit.
        let d = doc(serde_json::json!({
            "errata_cves": ["CVE-2021-44228", null, 42],
            "portal_severity": null,
        }));
        assert_eq!(d.errata_cves, Some(vec!["CVE-2021-44228".to_owned()]));
        assert_eq!(d.portal_severity, None);
    }

    #[test]
    fn empty_multivalued_field_becomes_none() {
        let d = doc(serde_json::json!({ "errata_packages": [] }));
        assert_eq!(d.errata_packages, None);
    }

    #[test]
    fn update_dates_fall_back_to_last_modified() {
        let d = doc(serde_json::json!({ "lastModifiedDate": "2024-01-02T00:00:00Z" }));
        assert_eq!(
            d.advisory_update_date().as_deref(),
            Some("2024-01-02T00:00:00Z")
        );
        assert_eq!(d.cve_update_date().as_deref(), Some("2024-01-02T00:00:00Z"));

        let d = doc(serde_json::json!({
            "errata_updated_date": "2024-03-04T00:00:00Z",
            "cve_updated_date": "2024-05-06T00:00:00Z",
            "lastModifiedDate": "2024-01-02T00:00:00Z",
        }));
        assert_eq!(
            d.advisory_update_date().as_deref(),
            Some("2024-03-04T00:00:00Z")
        );
        assert_eq!(d.cve_update_date().as_deref(), Some("2024-05-06T00:00:00Z"));
    }

    #[test]
    fn query_always_carries_a_document_kind_filter() {
        let q = PortalQuery::new(KIND_CVE, "*:*", CVE_SUMMARY_FL);
        assert_eq!(q.filters, vec!["documentKind:Cve".to_owned()]);
        assert_eq!(q.rows, 10);
        assert_eq!(q.start, 0);

        let q = PortalQuery::lookup(KIND_ERRATA, "id:\"RHSA-2024:1234\"", ERRATA_DETAIL_FL)
            .filter("portal_severity:Critical");
        assert_eq!(q.rows, 1);
        assert_eq!(
            q.filters,
            vec![
                "documentKind:Errata".to_owned(),
                "portal_severity:Critical".to_owned()
            ]
        );
    }
}
