// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Output records for the security tools.
//!
//! These mirror the `outputSchema` models of the upstream Red Hat security MCP
//! server so RHOKP is a drop-in replacement for clients written against it:
//! same field names, same nesting, same null-when-absent behaviour. Where a
//! value cannot be sourced from the offline index the field is emitted as
//! `null` rather than omitted, matching the upstream shape.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::packages::parse_nvra;
use crate::portal::PortalDoc;

/// A CVSS score and vector from a single source.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CvssScore {
    /// Numeric base score (0.0 - 10.0).
    pub score: Option<f64>,
    /// CVSS vector string.
    pub vector: Option<String>,
}

impl CvssScore {
    /// Builds a score, returning `None` when neither component is present so an
    /// empty source is omitted rather than surfacing as a hollow object.
    fn new(score: Option<f64>, vector: Option<String>) -> Option<Self> {
        (score.is_some() || vector.is_some()).then_some(Self { score, vector })
    }
}

/// CVSS scores for one version, broken down by scoring source.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CvssSource {
    /// NVD's score for this CVE.
    pub nvd: Option<CvssScore>,
    /// Red Hat Product Security's score for this CVE.
    #[serde(rename = "redHat")]
    pub red_hat: Option<CvssScore>,
}

impl CvssSource {
    /// Builds a source pair, returning `None` when neither source scored.
    fn new(nvd: Option<CvssScore>, red_hat: Option<CvssScore>) -> Option<Self> {
        (nvd.is_some() || red_hat.is_some()).then_some(Self { nvd, red_hat })
    }
}

/// One affected-product row of a CVE record.
///
/// Deserialized from the compact JSON objects stored in the multiValued
/// `cve_affected_products` Solr field, then re-serialized into the tool output.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct AffectedProduct {
    /// Red Hat product name.
    pub product_name: Option<String>,
    /// Fix state, e.g. `Fixed`, `Affected`, `Will not fix`.
    pub state: Option<String>,
    /// Download package string, when present.
    pub package: Option<String>,
    /// Per-product impact rating, when present.
    pub impact: Option<String>,
    /// Justification for a "Not affected" determination, when present.
    pub justification: Option<String>,
    /// Per-release CVSS v2 scoring.
    ///
    /// Always `null`: the offline index does not carry per-release CVSS, so
    /// the field is serialized for shape parity but never read back from the
    /// stored row. The CVE-level scores on [`CveDetail`] are the nearest
    /// equivalent. Tracked as a gap against upstream
    /// `list_cve_affected_products`.
    #[serde(skip_deserializing)]
    pub cvss2: Option<CvssSource>,
    /// Per-release CVSS v3 scoring. Always `null`; see [`Self::cvss2`].
    #[serde(skip_deserializing)]
    pub cvss3: Option<CvssSource>,
}

/// The compact affected-product projection returned by CVE *search* hits.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CveStatePackage {
    /// Red Hat product name.
    pub product_name: Option<String>,
    /// Download package string.
    pub package: Option<String>,
    /// Fix state.
    pub state: Option<String>,
}

/// Parses the stored per-row JSON of `cve_affected_products`.
///
/// A row that fails to parse is skipped rather than failing the whole record:
/// one malformed row must not make an otherwise good CVE unreadable.
fn affected_products(doc: &PortalDoc) -> Vec<AffectedProduct> {
    doc.cve_affected_products
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|row| match serde_json::from_str::<AffectedProduct>(row) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                tracing::warn!(error = %e, row, "skipping unparseable affected-product row");
                None
            }
        })
        .collect()
}

/// A CVE summary row returned by `search_cves`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CveSummary {
    /// CVE identifier.
    pub cve_id: Option<String>,
    /// Vulnerability description.
    pub description: Option<String>,
    /// Red Hat threat severity rating.
    pub severity: Option<String>,
    /// Affected products, as product/package/state triples.
    pub affected_products: Option<Vec<CveStatePackage>>,
    /// Date the CVE was made public.
    pub public_date: Option<String>,
    /// Date the CVE record was last updated.
    pub updated_date: Option<String>,
}

impl From<PortalDoc> for CveSummary {
    fn from(doc: PortalDoc) -> Self {
        let products: Vec<CveStatePackage> = affected_products(&doc)
            .into_iter()
            .map(|p| CveStatePackage {
                product_name: p.product_name,
                package: p.package,
                state: p.state,
            })
            .collect();

        Self {
            cve_id: doc.url_slug.clone(),
            description: doc.cve_details.clone(),
            severity: doc.cve_threat_severity.clone(),
            affected_products: (!products.is_empty()).then_some(products),
            public_date: doc.cve_public_date.clone(),
            updated_date: doc.cve_update_date(),
        }
    }
}

/// Pagination metadata for `search_cves`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchMetadata {
    /// Total number of matching documents.
    pub total: Option<u64>,
    /// Zero-based offset of the first returned row.
    pub start: Option<u64>,
}

/// Result payload for `search_cves`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchCvesResult {
    /// Totals for the query.
    pub metadata: Option<SearchMetadata>,
    /// Matching CVE summaries.
    pub cve: Option<Vec<CveSummary>>,
}

/// Output of `search_cves`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchCvesOutput {
    /// The search result.
    pub cves: Option<SearchCvesResult>,
}

/// A Bugzilla issue linked to a CVE.
#[derive(Debug, Serialize, JsonSchema)]
pub struct BugzillaReference {
    /// URL to the Bugzilla issue.
    pub url: Option<String>,
    /// Bugzilla issue ID.
    pub id: Option<String>,
    /// Bugzilla issue description.
    pub description: Option<String>,
}

/// A full CVE record, as returned by `get_cve_by_id` and
/// `list_cve_affected_products`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct CveDetail {
    /// CVE identifier.
    pub cve_id: Option<String>,
    /// Vulnerability description.
    pub description: Option<String>,
    /// Red Hat threat severity rating. Distinct from the CVSS scores below.
    pub severity: Option<String>,
    /// CVSS v2 scores. Conditional: typically present only on older records.
    pub cvss2: Option<CvssSource>,
    /// CVSS v3 scores.
    pub cvss3: Option<CvssSource>,
    /// Date the CVE record was created.
    pub created_date: Option<String>,
    /// Date the CVE was made public.
    pub public_date: Option<String>,
    /// Date the CVE record was last updated.
    pub updated_date: Option<String>,
    /// Canonical URL for the CVE page.
    pub cve_url: Option<String>,
    /// Alias of [`Self::cve_url`], present for upstream shape compatibility.
    pub url: Option<String>,
    /// Affected product releases.
    pub affected_products: Option<Vec<AffectedProduct>>,
    /// Whether a known exploit exists.
    pub exploit_known: Option<bool>,
    /// Linked Bugzilla issue.
    pub bugzilla: Option<BugzillaReference>,
    /// URLs to external resources.
    pub external_references: Option<Vec<String>>,
    /// Recommended mitigation steps.
    pub mitigation: Option<String>,
    /// Source of the description (`Red Hat` or `Mitre`).
    pub details_source: Option<String>,
}

impl CveDetail {
    /// Builds a full CVE record from an index document.
    pub fn from_doc(doc: PortalDoc) -> Self {
        let products = affected_products(&doc);
        let bugzilla = (doc.cve_bugzilla_url.is_some()
            || doc.cve_bugzilla_id.is_some()
            || doc.cve_bugzilla_description.is_some())
        .then(|| BugzillaReference {
            url: doc.cve_bugzilla_url.clone(),
            id: doc.cve_bugzilla_id.clone(),
            description: doc.cve_bugzilla_description.clone(),
        });

        Self {
            cve_id: doc.url_slug.clone(),
            description: doc.cve_details.clone(),
            severity: doc.cve_threat_severity.clone(),
            cvss2: CvssSource::new(
                CvssScore::new(doc.cvss2_nvd_score, doc.cvss2_nvd_vector.clone()),
                CvssScore::new(doc.cvss2_redhat_score, doc.cvss2_redhat_vector.clone()),
            ),
            cvss3: CvssSource::new(
                CvssScore::new(doc.cvss3_nvd_score, doc.cvss3_nvd_vector.clone()),
                CvssScore::new(doc.cvss3_redhat_score, doc.cvss3_redhat_vector.clone()),
            ),
            created_date: doc.cve_created_date.clone(),
            public_date: doc.cve_public_date.clone(),
            updated_date: doc.cve_update_date(),
            cve_url: doc.view_uri.clone(),
            url: doc.view_uri.clone(),
            affected_products: Some(products),
            exploit_known: doc.exploit_known,
            bugzilla,
            external_references: doc.cve_external_references.clone(),
            mitigation: doc.cve_mitigation.clone(),
            details_source: doc.details_source.clone(),
        }
    }

    /// Restricts `affected_products` to one page.
    ///
    /// `page` is 1-indexed to match the upstream contract; `None` means the
    /// first page. A page past the end yields an empty list, which is how
    /// upstream signals "stop paging".
    pub fn paginate_affected_products(mut self, limit: u32, page: Option<u32>) -> Self {
        let limit = limit.max(1) as usize;
        let page = page.unwrap_or(1).max(1) as usize;
        let offset = (page - 1).saturating_mul(limit);
        let products = self.affected_products.take().unwrap_or_default();
        self.affected_products = Some(products.into_iter().skip(offset).take(limit).collect());
        self
    }
}

/// Output of `get_cve_by_id`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GetCveByIdOutput {
    /// The CVE record, or `null` when no CVE matches.
    pub cve: Option<CveDetail>,
}

/// Output of `list_cve_affected_products`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListCveAffectedProductsOutput {
    /// The CVE record with its affected products, or `null` when no CVE matches.
    pub cve_with_affected_products: Option<CveDetail>,
}

/// Extracts the four-digit year from an advisory ID such as `RHSA-2024:1234`.
fn advisory_year(id: Option<&str>) -> Option<u32> {
    id?.split(['-', ':'])
        .find(|part| part.len() == 4 && part.chars().all(|c| c.is_ascii_digit()))
        .and_then(|year| year.parse().ok())
}

/// An advisory summary row returned by `search_advisories`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AdvisorySummary {
    /// Advisory identifier.
    pub id: Option<String>,
    /// Page title.
    pub title: Option<String>,
    /// Advisory type.
    pub advisory_type: Option<String>,
    /// Advisory severity.
    pub severity: Option<String>,
    /// Short synopsis.
    pub synopsis: Option<String>,
    /// Full description.
    pub description: Option<String>,
    /// Topic summary.
    pub summary: Option<String>,
    /// Remediation steps.
    pub solution: Option<String>,
    /// Publication date.
    pub public_date: Option<String>,
    /// Last-update date.
    pub update_date: Option<String>,
    /// Products the advisory applies to.
    pub product_names: Option<Vec<String>>,
    /// Canonical URL.
    pub url: Option<String>,
    /// Year of issue, derived from the advisory ID.
    pub year: Option<u32>,
    /// CVEs fixed by the advisory.
    pub cves: Option<Vec<String>>,
    /// Bugzilla issues fixed by the advisory.
    pub bugzillas: Option<Vec<String>>,
    /// External references.
    pub references: Option<Vec<String>>,
}

impl From<PortalDoc> for AdvisorySummary {
    fn from(doc: PortalDoc) -> Self {
        Self {
            year: advisory_year(doc.id.as_deref()),
            update_date: doc.advisory_update_date(),
            id: doc.id,
            title: doc.all_title,
            advisory_type: doc.portal_advisory_type,
            severity: doc.portal_severity,
            synopsis: doc.portal_synopsis,
            description: doc.portal_description,
            summary: doc.portal_summary,
            solution: doc.portal_solution,
            public_date: doc.portal_publication_date,
            product_names: doc.portal_product_names,
            url: doc.view_uri,
            cves: doc.errata_cves,
            bugzillas: doc.errata_bugzillas,
            references: doc.errata_references,
        }
    }
}

/// Totals for `search_advisories`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchAdvisoriesMetadata {
    /// Total number of matching advisories.
    pub total: Option<u64>,
}

/// Result payload for `search_advisories`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchAdvisoriesResult {
    /// Matching advisory summaries.
    pub advisory: Option<Vec<AdvisorySummary>>,
    /// Totals for the query.
    pub metadata: Option<SearchAdvisoriesMetadata>,
}

/// Output of `search_advisories`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchAdvisoriesOutput {
    /// The search result.
    pub advisories: Option<SearchAdvisoriesResult>,
}

/// A single advisory record returned by `get_errata_by_id`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ErratumDetail {
    /// Advisory identifier.
    pub advisory_id: Option<String>,
    /// Short synopsis.
    pub synopsis: Option<String>,
    /// Advisory type.
    #[serde(rename = "type")]
    pub advisory_type: Option<String>,
    /// Advisory severity.
    pub severity: Option<String>,
    /// Products the advisory applies to.
    pub affected_products: Option<Vec<String>>,
    /// Publication date.
    pub issue_date: Option<String>,
    /// Last-update date.
    pub updated_date: Option<String>,
    /// Bugzilla issues fixed by the advisory.
    pub bugzillas: Option<Vec<String>>,
}

impl From<PortalDoc> for ErratumDetail {
    fn from(doc: PortalDoc) -> Self {
        Self {
            updated_date: doc.advisory_update_date(),
            advisory_id: doc.id,
            synopsis: doc.portal_synopsis,
            advisory_type: doc.portal_advisory_type,
            severity: doc.portal_severity,
            affected_products: doc.portal_product_names,
            issue_date: doc.portal_publication_date,
            bugzillas: doc.errata_bugzillas,
        }
    }
}

/// Totals for `get_errata_by_id`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ErratumMetadata {
    /// Number of matching advisories (at most one).
    pub total_record_count: Option<u64>,
}

/// Result payload for `get_errata_by_id`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ErratumResult {
    /// The matching advisory, as a single-element list.
    pub advisory: Option<Vec<ErratumDetail>>,
    /// Totals for the lookup.
    pub metadata: Option<ErratumMetadata>,
}

/// Output of `get_errata_by_id`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GetErrataByIdOutput {
    /// The lookup result.
    pub erratum: Option<ErratumResult>,
}

/// An advisory linked to a CVE, returned by `list_advisories_by_cve`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LinkedAdvisory {
    /// Advisory identifier.
    pub id: Option<String>,
    /// Short synopsis.
    pub synopsis: Option<String>,
    /// Advisory type.
    #[serde(rename = "type")]
    pub advisory_type: Option<String>,
    /// Advisory severity.
    pub severity: Option<String>,
    /// Publication date.
    pub issued: Option<String>,
    /// Last-update date.
    pub modified: Option<String>,
    /// Products the advisory applies to.
    pub product_names: Option<Vec<String>>,
}

impl From<PortalDoc> for LinkedAdvisory {
    fn from(doc: PortalDoc) -> Self {
        Self {
            modified: doc.advisory_update_date(),
            id: doc.id,
            synopsis: doc.portal_synopsis,
            advisory_type: doc.portal_advisory_type,
            severity: doc.portal_severity,
            issued: doc.portal_publication_date,
            product_names: doc.portal_product_names,
        }
    }
}

/// Result payload for `list_advisories_by_cve`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AdvisoriesByCveResult {
    /// Advisories linked to the CVE.
    pub advisory: Option<Vec<LinkedAdvisory>>,
}

/// Output of `list_advisories_by_cve`.
///
/// The `advisoires` key is misspelled upstream; it is reproduced verbatim so
/// clients written against the upstream server keep working unchanged.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListAdvisoriesByCveOutput {
    /// The linked advisories.
    pub advisoires: Option<AdvisoriesByCveResult>,
}

/// One package shipped by an advisory.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AdvisoryPackage {
    /// Package architecture, e.g. `x86_64`, `noarch`, `src`.
    pub architecture: Option<String>,
    /// SHA256 checksum.
    ///
    /// Always `null`: checksums come from RHSM upstream, which the offline
    /// index has no equivalent of. See also [`Self::repo_tags`] and
    /// [`Self::summary`].
    #[serde(rename = "SHA256")]
    pub sha256: Option<String>,
    /// RPM filename.
    pub package: Option<String>,
    /// Package name.
    pub name: Option<String>,
    /// Package release.
    pub release: Option<String>,
    /// Repository tags. Always `null`; see [`Self::sha256`].
    pub repo_tags: Option<Vec<String>>,
    /// Package summary. Always `null`; see [`Self::sha256`].
    pub summary: Option<String>,
    /// Package version.
    pub version: Option<String>,
}

impl AdvisoryPackage {
    /// Builds a package row from a raw NVRA string.
    pub fn from_nvra(raw: &str) -> Self {
        let parsed = parse_nvra(raw);
        Self {
            architecture: parsed.architecture,
            sha256: None,
            package: Some(raw.to_owned()),
            name: parsed.name,
            release: parsed.release,
            repo_tags: None,
            summary: None,
            version: parsed.version,
        }
    }
}

/// Pagination metadata for `list_advisory_packages`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PackagePagination {
    /// Number of rows in this page.
    pub count: Option<usize>,
    /// Zero-based offset of this page.
    pub offset: Option<u32>,
    /// Maximum rows per page.
    pub max_limit: Option<u32>,
}

/// Result payload for `list_advisory_packages`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct AdvisoryPackagesResult {
    /// The page of packages.
    pub packages: Option<Vec<AdvisoryPackage>>,
    /// Page metadata.
    pub pagination: Option<PackagePagination>,
}

/// Output of `list_advisory_packages`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListAdvisoryPackagesOutput {
    /// The advisory's package payload.
    pub advisory: Option<AdvisoryPackagesResult>,
}

impl ListAdvisoryPackagesOutput {
    /// Builds one page of package rows from an advisory's raw NVRA strings.
    pub fn page(raw: &[String], limit: u32, offset: u32) -> Self {
        let packages: Vec<AdvisoryPackage> = raw
            .iter()
            .skip(offset as usize)
            .take(limit as usize)
            .map(|s| AdvisoryPackage::from_nvra(s))
            .collect();

        Self {
            advisory: Some(AdvisoryPackagesResult {
                pagination: Some(PackagePagination {
                    count: Some(packages.len()),
                    offset: Some(offset),
                    max_limit: Some(limit),
                }),
                packages: Some(packages),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(json: serde_json::Value) -> PortalDoc {
        serde_json::from_value(json).expect("PortalDoc should deserialize")
    }

    fn json_of<T: Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).expect("record should serialize")
    }

    #[test]
    fn cve_detail_maps_every_upstream_field() {
        let detail = CveDetail::from_doc(doc(serde_json::json!({
            "url_slug": "CVE-2021-44228",
            "cve_details": "A flaw was found in log4j.",
            "cve_threatSeverity": "Critical",
            "cve_publicDate": "2021-12-10T00:00:00Z",
            "cve_created_date": "2021-12-09T00:00:00Z",
            "cve_updated_date": "2021-12-15T00:00:00Z",
            "view_uri": "/security/cve/CVE-2021-44228/",
            "exploit_known": true,
            "details_source": "Red Hat",
            "cve_mitigation": "<p>Set log4j2.formatMsgNoLookups</p>",
            "cve_external_references": ["https://example.test/advisory"],
            "cve_bugzilla_url": "https://bugzilla.redhat.com/show_bug.cgi?id=2030932",
            "cve_bugzilla_id": "2030932",
            "cve_bugzilla_description": "log4j: RCE",
            "cvss3_redhat_score": 9.8,
            "cvss3_redhat_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss3_nvd_score": 10.0,
            "cvss3_nvd_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cve_affected_products": [
                r#"{"product_name":"Red Hat Enterprise Linux 8","state":"Affected","package":"log4j","impact":"Critical"}"#,
            ],
        })));

        let json = json_of(&detail);
        assert_eq!(json["cve_id"], "CVE-2021-44228");
        assert_eq!(json["severity"], "Critical");
        assert_eq!(json["created_date"], "2021-12-09T00:00:00Z");
        assert_eq!(json["updated_date"], "2021-12-15T00:00:00Z");
        assert_eq!(json["exploit_known"], true);
        assert_eq!(json["details_source"], "Red Hat");
        assert_eq!(json["cve_url"], "/security/cve/CVE-2021-44228/");
        assert_eq!(json["url"], "/security/cve/CVE-2021-44228/");
        assert_eq!(json["bugzilla"]["id"], "2030932");
        assert_eq!(json["cvss3"]["redHat"]["score"], 9.8);
        assert_eq!(json["cvss3"]["nvd"]["score"], 10.0);
        assert_eq!(
            json["external_references"][0],
            "https://example.test/advisory"
        );
        assert_eq!(
            json["affected_products"][0]["product_name"],
            "Red Hat Enterprise Linux 8"
        );
        assert_eq!(json["affected_products"][0]["impact"], "Critical");
        // CVSS v2 absent on this record, and per-release CVSS is never available.
        assert!(json["cvss2"].is_null());
        assert!(json["affected_products"][0]["cvss3"].is_null());
    }

    #[test]
    fn cve_detail_omits_empty_cvss_and_bugzilla() {
        let detail = CveDetail::from_doc(doc(serde_json::json!({ "url_slug": "CVE-2024-0001" })));
        let json = json_of(&detail);
        assert!(json["cvss2"].is_null());
        assert!(json["cvss3"].is_null());
        assert!(json["bugzilla"].is_null());
        // The key must still be present, as an empty list, so clients can page.
        assert_eq!(json["affected_products"], serde_json::json!([]));
    }

    #[test]
    fn malformed_affected_product_row_is_skipped_not_fatal() {
        let detail = CveDetail::from_doc(doc(serde_json::json!({
            "url_slug": "CVE-2024-0002",
            "cve_affected_products": [
                "{not json",
                r#"{"product_name":"RHEL 9","state":"Fixed"}"#,
            ],
        })));
        let products = detail.affected_products.expect("products present");
        assert_eq!(products.len(), 1);
        assert_eq!(products[0].product_name.as_deref(), Some("RHEL 9"));
    }

    #[test]
    fn affected_products_paginate_one_indexed() {
        let rows: Vec<String> = (1..=5)
            .map(|i| format!(r#"{{"product_name":"p{i}","state":"Affected"}}"#))
            .collect();
        let build = || {
            CveDetail::from_doc(doc(serde_json::json!({
                "url_slug": "CVE-2024-0003",
                "cve_affected_products": rows,
            })))
        };

        let names = |d: CveDetail| -> Vec<String> {
            d.affected_products
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| p.product_name)
                .collect()
        };

        // No page given means the first page.
        assert_eq!(
            names(build().paginate_affected_products(2, None)),
            ["p1", "p2"]
        );
        assert_eq!(
            names(build().paginate_affected_products(2, Some(1))),
            ["p1", "p2"]
        );
        assert_eq!(
            names(build().paginate_affected_products(2, Some(2))),
            ["p3", "p4"]
        );
        assert_eq!(
            names(build().paginate_affected_products(2, Some(3))),
            ["p5"]
        );
        // Past the end: empty, which is how clients learn to stop.
        assert!(names(build().paginate_affected_products(2, Some(4))).is_empty());
        // Page 0 is clamped to the first page rather than underflowing.
        assert_eq!(
            names(build().paginate_affected_products(2, Some(0))),
            ["p1", "p2"]
        );
    }

    #[test]
    fn advisory_summary_derives_year_from_id() {
        let summary = AdvisorySummary::from(doc(serde_json::json!({
            "id": "RHSA-2021:5106",
            "portal_synopsis": "log4j security update",
            "portal_advisory_type": "Security Advisory",
            "portal_severity": "Important",
            "errata_cves": ["CVE-2021-44228"],
            "errata_updated_date": "2021-12-15T00:00:00Z",
        })));
        assert_eq!(summary.year, Some(2021));
        assert_eq!(summary.update_date.as_deref(), Some("2021-12-15T00:00:00Z"));
        assert_eq!(summary.cves, Some(vec!["CVE-2021-44228".to_owned()]));
    }

    #[test]
    fn advisory_year_handles_both_separators_and_junk() {
        assert_eq!(advisory_year(Some("RHSA-2024:1234")), Some(2024));
        assert_eq!(advisory_year(Some("RHBA-2016-0144")), Some(2016));
        assert_eq!(advisory_year(Some("nonsense")), None);
        assert_eq!(advisory_year(None), None);
    }

    #[test]
    fn erratum_detail_renames_type_key() {
        let detail = ErratumDetail::from(doc(serde_json::json!({
            "id": "RHSA-2024:1234",
            "portal_advisory_type": "Security Advisory",
        })));
        let json = json_of(&detail);
        assert_eq!(json["type"], "Security Advisory");
        assert_eq!(json["advisory_id"], "RHSA-2024:1234");
        assert!(json.get("advisory_type").is_none());
    }

    #[test]
    fn linked_advisory_output_preserves_upstream_key_spelling() {
        let output = ListAdvisoriesByCveOutput {
            advisoires: Some(AdvisoriesByCveResult { advisory: None }),
        };
        let json = json_of(&output);
        assert!(
            json.get("advisoires").is_some(),
            "upstream misspelling is intentional"
        );
        assert!(json.get("advisories").is_none());
    }

    #[test]
    fn package_page_slices_and_reports_pagination() {
        let raw: Vec<String> = vec![
            "log4j-2.17.0-1.el8.noarch".to_owned(),
            "kernel-4.18.0-305.el8.x86_64".to_owned(),
            "openssl-1.1.1k-5.el8.src".to_owned(),
        ];
        let json = json_of(&ListAdvisoryPackagesOutput::page(&raw, 2, 1));
        let packages = json["advisory"]["packages"].as_array().expect("packages");
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0]["name"], "kernel");
        assert_eq!(packages[0]["version"], "4.18.0");
        assert_eq!(packages[0]["release"], "305.el8");
        assert_eq!(packages[0]["architecture"], "x86_64");
        assert_eq!(packages[0]["package"], "kernel-4.18.0-305.el8.x86_64");
        // Unobtainable from the offline index.
        assert!(packages[0]["SHA256"].is_null());
        assert!(packages[0]["repo_tags"].is_null());
        assert!(packages[0]["summary"].is_null());
        assert_eq!(json["advisory"]["pagination"]["count"], 2);
        assert_eq!(json["advisory"]["pagination"]["offset"], 1);
        assert_eq!(json["advisory"]["pagination"]["max_limit"], 2);
    }

    #[test]
    fn package_page_past_the_end_is_empty() {
        let raw = vec!["log4j-2.17.0-1.el8.noarch".to_owned()];
        let json = json_of(&ListAdvisoryPackagesOutput::page(&raw, 10, 50));
        assert_eq!(json["advisory"]["packages"], serde_json::json!([]));
        assert_eq!(json["advisory"]["pagination"]["count"], 0);
    }
}
