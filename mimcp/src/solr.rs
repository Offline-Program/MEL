// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

use std::sync::Arc;

use anyhow::Result;
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::tools::Tool;

/// Solr collection name used by RHOKP.
const COLLECTION: &str = "portal-rag";

/// Comma-separated Solr field list returned by lexical search queries.
const FIELD_LIST: &str = "\
    doc_id,id,content_type,title,product,product_version,\
    category,chunk,score,online_source_url,source_path,headings";

/// Comma-separated Solr field list returned by hybrid search queries.
/// Includes `originalScore()` for the pre-rerank score.
const HYBRID_FIELD_LIST: &str = "\
    doc_id,id,content_type,title,product,product_version,\
    category,chunk,score,online_source_url,source_path,headings,\
    originalScore()";

/// The Solr index a query targets. Each index has its own schema and thus its
/// own filter type ([`PortalFilter`] / [`PortalRagFilter`]).
pub enum Index {
    /// Lexical-only RHOKP search index.
    Portal,
    /// RHOKP RAG index.
    PortalRag,
}

/// Typed filter for the lexical-only [`Index::Portal`] schema, rendered as a
/// Solr `fq` clause.
pub enum PortalFilter<'a> {
    /// Filter by `documentKind` (e.g. `Cve`, `documentation`).
    DocumentKind(&'a str),
}

/// A single product restriction: a product slug and the versions to narrow it
/// to. Analogous to a Solr-style `fq` filter, but structured so the server (not
/// the client) renders the `fq` clause.
///
/// An empty `versions` slice matches the product regardless of version.
pub struct ProductVersions<'a> {
    /// Product slug to match exactly (e.g. `openshift_container_platform`).
    pub product: &'a str,
    /// Versions of this product to include, OR-combined. Empty means all
    /// versions.
    pub versions: &'a [String],
}

/// Typed filter for the [`Index::PortalRag`] schema, rendered as a Solr `fq`
/// clause.
pub enum PortalRagFilter<'a> {
    /// Filter by `content_type` (e.g. `Cve_chunk`, `documentation_chunk`).
    ContentType(&'a str),
    /// Restrict results to a set of products, each optionally narrowed to
    /// versions. Rendered as a single OR-of-products `fq` clause.
    Products(&'a [ProductVersions<'a>]),
    /// Filter by `category` (e.g. `documentation`).
    Category(&'a str),
}

/// A tool's Solr filter, resolved to the [`Index`] it targets.
///
/// The variant selects the index; the inner `Option` is the extra `fq` clause
/// to apply. `None` means the index's mandatory base filter is sufficient and
/// no additional `fq` is added (e.g. the broad hybrid `search`).
pub enum SolrFilter {
    /// Target the lexical-only [`Index::Portal`].
    Portal(Option<PortalFilter<'static>>),
    /// Target the [`Index::PortalRag`].
    PortalRag(Option<PortalRagFilter<'static>>),
}

impl From<Tool> for SolrFilter {
    fn from(tool: Tool) -> Self {
        match tool {
            // Broad hybrid search: no extra fq, relies on the mandatory
            // `is_chunk:true` base filter of the PortalRag index.
            Tool::Search => SolrFilter::PortalRag(None),
            // CVE search, one version per index.
            Tool::CveSearchPortal => {
                SolrFilter::Portal(Some(PortalFilter::DocumentKind("Cve")))
            }
            Tool::CveSearchRag => {
                SolrFilter::PortalRag(Some(PortalRagFilter::ContentType("Cve_chunk")))
            }
            // CVE lookup by ID, one version per index.
            Tool::CveGetPortal => SolrFilter::Portal(Some(PortalFilter::DocumentKind("Cve"))),
            Tool::CveGetRag => {
                SolrFilter::PortalRag(Some(PortalRagFilter::ContentType("Cve_parent")))
            }
            // Documentation search.
            Tool::DocsSearch => {
                SolrFilter::PortalRag(Some(PortalRagFilter::ContentType("documentation_chunk")))
            }
        }
    }
}

impl PortalFilter<'_> {
    /// Renders this filter as a Solr `fq` clause string.
    pub(crate) fn to_fq(&self) -> String {
        match self {
            Self::DocumentKind(v) => format!("documentKind:{v}"),
        }
    }
}

impl PortalRagFilter<'_> {
    /// Renders this filter as a Solr `fq` clause string.
    ///
    /// [`Self::Products`] carries client-supplied product/version values (the
    /// `search` tool exposes them as parameters), so each value is quoted and
    /// escaped via [`quote_solr_value`] to prevent it from breaking out of its
    /// clause and injecting arbitrary Solr query syntax. [`Self::ContentType`]
    /// and [`Self::Category`] are only ever constructed from trusted in-crate
    /// constants, so they are rendered verbatim.
    pub(crate) fn to_fq(&self) -> String {
        match self {
            Self::ContentType(v) => format!("content_type:{v}"),
            Self::Products(products) => render_products_fq(products),
            Self::Category(v) => format!("category:{v}"),
        }
    }
}

/// Renders a set of product restrictions into a single Solr `fq` clause.
///
/// Products are OR-combined; within a product, its versions are OR-combined and
/// AND-ed with the product match. A product with no versions matches regardless
/// of version. All product and version values are client-supplied, so they are
/// quoted and escaped via [`quote_solr_value`] to keep each value contained
/// within its clause.
///
/// Returns an empty string when `products` is empty; callers must not add an
/// empty `fq` clause (the search path only pushes this filter when at least one
/// product is present).
fn render_products_fq(products: &[ProductVersions<'_>]) -> String {
    let clauses: Vec<String> = products
        .iter()
        .map(|pv| {
            let product = format!("product:{}", quote_solr_value(pv.product));
            if pv.versions.is_empty() {
                product
            } else {
                let versions = pv
                    .versions
                    .iter()
                    .map(|v| format!("product_version:{}", quote_solr_value(v)))
                    .collect::<Vec<_>>()
                    .join(" OR ");
                format!("({product} AND ({versions}))")
            }
        })
        .collect();

    match clauses.len() {
        0 => String::new(),
        1 => clauses.into_iter().next().unwrap_or_default(),
        _ => format!("({})", clauses.join(" OR ")),
    }
}

/// HTTP client for querying a Solr instance hosting the RHOKP `portal-rag` collection.
#[derive(Clone)]
pub struct SolrClient {
    http: Client,
    select_url: Url,
    hybrid_url: Url,
    health_url: Url,
}

impl SolrClient {
    /// Creates a new Solr client targeting the given base URL.
    ///
    /// Returns `Err` if any of the endpoint URLs cannot be constructed
    /// from `solr_base`.
    pub fn new(solr_base: Url) -> Result<Arc<Self>> {
        let select_url = solr_base.join(&format!("solr/{COLLECTION}/select"))?;
        let hybrid_url = solr_base.join(&format!("solr/{COLLECTION}/hybrid-search"))?;
        let health_url = solr_base.join(&format!("solr/{COLLECTION}/admin/ping"))?;

        Ok(Arc::new(Self {
            http: Client::new(),
            select_url,
            hybrid_url,
            health_url,
        }))
    }

    /// Checks that Solr is reachable and the collection is available.
    ///
    /// Returns `Err` if the health check request fails or returns a
    /// non-2xx status code.
    pub async fn health_check(&self) -> Result<()> {
        let url = self.health_url.clone();
        again::retry(|| async {
            self.http
                .get(url.clone())
                .send()
                .await
                .map_err(anyhow::Error::from)?
                .error_for_status()
                .map_err(anyhow::Error::from)?;
            Ok(())
        })
        .await
    }

    /// Performs a lexical search against Solr's `/select` endpoint, targeting
    /// the [`Index::Portal`] schema.
    ///
    /// `filters` are appended as Solr `fq` clauses.
    ///
    /// Returns `Err` if the HTTP request fails, the server responds with a
    /// non-2xx status code, or the response body cannot be deserialized.
    pub async fn search(
        &self,
        query: &str,
        rows: u32,
        filters: &[PortalFilter<'_>],
    ) -> Result<SolrResponse> {
        let extra_fq: Vec<String> = filters.iter().map(PortalFilter::to_fq).collect();
        let payload = SolrPayload {
            params: SolrParams::lexical(query, rows, &extra_fq),
        };

        let url = append_wt_json(self.select_url.clone());

        again::retry(|| {
            let payload = &payload;
            let url = url.clone();
            async move {
                self.http
                    .post(url)
                    .json(payload)
                    .send()
                    .await
                    .map_err(anyhow::Error::from)?
                    .error_for_status()
                    .map_err(anyhow::Error::from)?
                    .json::<SolrResponse>()
                    .await
                    .map_err(anyhow::Error::from)
            }
        })
        .await
    }

    /// Performs a hybrid search (keyword + semantic rerank) against Solr,
    /// targeting the [`Index::PortalRag`] schema.
    ///
    /// The `vector` is formatted into a `{!vectorSimilarity}` local param
    /// and used as the rerank query. The keyword query runs first, then the
    /// top 10,000 results are reranked by vector similarity.
    ///
    /// `filters` are appended as Solr `fq` clauses after the mandatory
    /// `is_chunk:true` filter.
    ///
    /// Returns `Err` if the HTTP request fails, the server responds with a
    /// non-2xx status code, or the response body cannot be deserialized.
    pub async fn hybrid_search(
        &self,
        query: &str,
        vector: &[f32],
        rows: u32,
        filters: &[PortalRagFilter<'_>],
    ) -> Result<SolrResponse> {
        let extra_fq: Vec<String> = filters.iter().map(PortalRagFilter::to_fq).collect();
        let payload = SolrPayload {
            params: SolrParams::hybrid(query, vector, rows, &extra_fq),
        };

        let url = append_wt_json(self.hybrid_url.clone());

        again::retry(|| {
            let payload = &payload;
            let url = url.clone();
            async move {
                self.http
                    .post(url)
                    .json(payload)
                    .send()
                    .await
                    .map_err(anyhow::Error::from)?
                    .error_for_status()
                    .map_err(anyhow::Error::from)?
                    .json::<SolrResponse>()
                    .await
                    .map_err(anyhow::Error::from)
            }
        })
        .await
    }

    /// Fetches a parent document by ID from Solr.
    ///
    /// Uses a wildcard suffix on `doc_id` so callers can pass either the
    /// bare identifier (e.g. `CVE-2024-1234`) or the full path
    /// (`/security/cve/CVE-2024-1234`). `filter_fq` is a rendered `fq` clause
    /// that restricts to the parent variant of the target index (e.g.
    /// `content_type:Cve_parent` for PortalRag or `documentKind:Cve` for
    /// Portal).
    ///
    /// Returns `Err` if the HTTP request fails, the server responds with a
    /// non-2xx status code, or the response body cannot be deserialized.
    pub async fn get_by_id(&self, doc_id: &str, filter_fq: &str) -> Result<SolrResponse> {
        let payload = SolrPayload {
            params: SolrParams::get_by_id(doc_id, filter_fq),
        };

        let url = append_wt_json(self.select_url.clone());

        again::retry(|| {
            let payload = &payload;
            let url = url.clone();
            async move {
                self.http
                    .post(url)
                    .json(payload)
                    .send()
                    .await
                    .map_err(anyhow::Error::from)?
                    .error_for_status()
                    .map_err(anyhow::Error::from)?
                    .json::<SolrResponse>()
                    .await
                    .map_err(anyhow::Error::from)
            }
        })
        .await
    }
}

/// Appends `wt=json` to a URL's query parameters.
fn append_wt_json(mut url: Url) -> Url {
    url.query_pairs_mut().append_pair("wt", "json");
    url
}

/// Formats a float vector as a Solr-compatible string: `[0.1,0.2,...]`.
fn format_vector(vector: &[f32]) -> String {
    let mut out = String::with_capacity(vector.len() * 10);
    out.push('[');
    for (i, v) in vector.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&v.to_string());
    }
    out.push(']');
    out
}

/// JSON payload sent to Solr endpoints.
#[derive(Serialize)]
struct SolrPayload {
    params: SolrParams,
}

/// Query parameters nested inside [`SolrPayload`].
#[derive(Serialize)]
struct SolrParams {
    q: String,
    rows: String,
    fl: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fq: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rqq: Option<String>,
}

impl SolrParams {
    /// Constructs parameters for a lexical search query.
    ///
    /// Unlike the hybrid path, no `is_chunk:true` base filter is applied: that
    /// field only exists in the PortalRag schema, not the lexical Portal index.
    fn lexical(query: &str, rows: u32, extra_fq: &[String]) -> Self {
        let fq: Vec<String> = extra_fq.to_vec();
        Self {
            q: query.to_owned(),
            rows: rows.to_string(),
            fl: FIELD_LIST.to_owned(),
            fq,
            rq: None,
            rqq: None,
        }
    }

    /// Constructs parameters for a hybrid search query with vector reranking.
    fn hybrid(query: &str, vector: &[f32], rows: u32, extra_fq: &[String]) -> Self {
        let vector_str = format_vector(vector);
        let mut fq: Vec<String> = vec!["is_chunk:true".to_owned()];
        fq.extend(extra_fq.iter().cloned());
        Self {
            q: query.to_owned(),
            rows: rows.to_string(),
            fl: HYBRID_FIELD_LIST.to_owned(),
            fq,
            rq: Some(
                "{!rerank reRankQuery=$rqq reRankDocs=10000 reRankWeight=2 reRankOperator=multiply}"
                    .to_owned(),
            ),
            rqq: Some(format!(
                "{{!vectorSimilarity f=chunk_vector minReturn=0.7}}{vector_str}"
            )),
        }
    }

    /// Constructs parameters for a parent document lookup by ID. `filter_fq` is
    /// a pre-rendered `fq` clause (e.g. `content_type:Cve_parent`).
    fn get_by_id(doc_id: &str, filter_fq: &str) -> Self {
        let escaped = escape_solr_query(doc_id);
        Self {
            q: format!("doc_id:*{escaped}"),
            rows: "1".to_owned(),
            fl: FIELD_LIST.to_owned(),
            fq: vec![filter_fq.to_owned()],
            rq: None,
            rqq: None,
        }
    }
}

/// Wraps a client-supplied `fq` value in a Solr phrase quote.
///
/// The value is enclosed in double quotes so that whitespace and Solr query
/// operators inside it are treated as literal text rather than query syntax,
/// preventing a value from breaking out of its `fq` clause. Within a quoted
/// phrase only the backslash and the double quote are special, so those two
/// characters are backslash-escaped.
fn quote_solr_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if matches!(c, '\\' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Escapes characters that have special meaning in Solr query syntax.
fn escape_solr_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(
            c,
            '+' | '-'
                | '&'
                | '|'
                | '!'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '^'
                | '"'
                | '~'
                | '*'
                | '?'
                | ':'
                | '/'
                | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Top-level Solr JSON response.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SolrResponse {
    /// The response body containing matched documents.
    pub response: SolrResponseBody,
}

/// Body of a Solr search response.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SolrResponseBody {
    /// Total number of documents matching the query.
    #[serde(rename = "numFound")]
    pub num_found: u64,
    /// The returned documents (limited by the `rows` parameter).
    pub docs: Vec<SolrDoc>,
}

/// A single document returned by Solr. All fields are optional because Solr
/// may omit any field depending on the document and collection schema.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SolrDoc {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_source_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headings: Option<String>,
    #[serde(rename = "originalScore()", skip_serializing_if = "Option::is_none")]
    pub original_score: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_payload(payload: &SolrPayload) -> serde_json::Value {
        serde_json::to_value(payload).expect("SolrPayload should serialize")
    }

    fn s(val: &str) -> String {
        val.to_owned()
    }

    #[test]
    fn hybrid_without_extra_fq_has_only_is_chunk() {
        let payload = SolrPayload {
            params: SolrParams::hybrid("openshift", &[0.1, 0.2], 5, &[]),
        };
        let json = parse_payload(&payload);
        let fq = json["params"]["fq"].as_array().unwrap();
        assert_eq!(fq.len(), 1);
        assert_eq!(fq[0], "is_chunk:true");
    }

    #[test]
    fn hybrid_with_extra_fq_appends_filters() {
        let filters = [s("content_type:Cve_chunk"), s("product:OpenShift")];
        let payload = SolrPayload {
            params: SolrParams::hybrid("openshift", &[0.1, 0.2], 5, &filters),
        };
        let json = parse_payload(&payload);
        let fq = json["params"]["fq"].as_array().unwrap();
        assert_eq!(fq.len(), 3);
        assert_eq!(fq[0], "is_chunk:true");
        assert_eq!(fq[1], "content_type:Cve_chunk");
        assert_eq!(fq[2], "product:OpenShift");
    }

    #[test]
    fn lexical_without_extra_fq_has_no_fq() {
        let payload = SolrPayload {
            params: SolrParams::lexical("openshift", 5, &[]),
        };
        let json = parse_payload(&payload);
        // The lexical Portal index has no `is_chunk` field, so no base filter.
        assert!(json["params"].get("fq").is_none());
    }

    #[test]
    fn lexical_with_extra_fq_uses_filters_verbatim() {
        let filters = [s("documentKind:Cve")];
        let payload = SolrPayload {
            params: SolrParams::lexical("openshift", 5, &filters),
        };
        let json = parse_payload(&payload);
        let fq = json["params"]["fq"].as_array().unwrap();
        assert_eq!(fq.len(), 1);
        assert_eq!(fq[0], "documentKind:Cve");
    }

    #[test]
    fn hybrid_fq_values_are_all_strings() {
        let payload = SolrPayload {
            params: SolrParams::hybrid("q", &[0.1], 5, &[]),
        };
        let json = parse_payload(&payload);
        let fq = json["params"]["fq"].as_array().unwrap();
        assert!(
            fq.iter().all(|v| v.as_str().is_some()),
            "all fq values should be strings"
        );
    }

    #[test]
    fn hybrid_fq_preserves_insertion_order() {
        let filters = [s("a:1"), s("b:2"), s("c:3")];
        let payload = SolrPayload {
            params: SolrParams::hybrid("q", &[0.1], 5, &filters),
        };
        let json = parse_payload(&payload);
        let fq: Vec<&str> = json["params"]["fq"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(fq, vec!["is_chunk:true", "a:1", "b:2", "c:3"]);
    }

    #[test]
    fn portal_filter_document_kind_renders_correctly() {
        assert_eq!(PortalFilter::DocumentKind("Cve").to_fq(), "documentKind:Cve");
    }

    #[test]
    fn portal_rag_filter_content_type_renders_correctly() {
        assert_eq!(
            PortalRagFilter::ContentType("Cve_chunk").to_fq(),
            "content_type:Cve_chunk"
        );
    }

    /// Helper: build a [`ProductVersions`] from a product slug and versions.
    fn pv<'a>(product: &'a str, versions: &'a [String]) -> ProductVersions<'a> {
        ProductVersions { product, versions }
    }

    #[test]
    fn products_filter_single_product_no_versions_renders_bare_clause() {
        let items = [pv("openshift_container_platform", &[])];
        assert_eq!(
            PortalRagFilter::Products(&items).to_fq(),
            "product:\"openshift_container_platform\""
        );
    }

    #[test]
    fn products_filter_single_product_with_versions_ands_version_or_group() {
        let versions = [s("4.19"), s("4.20")];
        let items = [pv("openshift_container_platform", &versions)];
        assert_eq!(
            PortalRagFilter::Products(&items).to_fq(),
            "(product:\"openshift_container_platform\" AND \
             (product_version:\"4.19\" OR product_version:\"4.20\"))"
        );
    }

    #[test]
    fn products_filter_multiple_products_are_or_combined() {
        let ocp_versions = [s("4.20")];
        let items = [
            pv("openshift_container_platform", &ocp_versions),
            pv("rhel", &[]),
        ];
        assert_eq!(
            PortalRagFilter::Products(&items).to_fq(),
            "((product:\"openshift_container_platform\" AND \
             (product_version:\"4.20\")) OR product:\"rhel\")"
        );
    }

    #[test]
    fn products_filter_product_with_spaces_is_quoted() {
        let items = [pv("Red Hat Enterprise Linux", &[])];
        assert_eq!(
            PortalRagFilter::Products(&items).to_fq(),
            "product:\"Red Hat Enterprise Linux\""
        );
    }

    #[test]
    fn products_filter_escapes_injection_attempt() {
        // A value that tries to close the phrase and inject an OR clause must
        // stay contained: the embedded quote is backslash-escaped.
        let items = [pv("x\" OR is_chunk:true OR product:\"y", &[])];
        assert_eq!(
            PortalRagFilter::Products(&items).to_fq(),
            "product:\"x\\\" OR is_chunk:true OR product:\\\"y\""
        );
    }

    #[test]
    fn products_filter_empty_renders_empty_string() {
        assert_eq!(PortalRagFilter::Products(&[]).to_fq(), "");
    }

    #[test]
    fn quote_solr_value_escapes_backslash_and_quote() {
        assert_eq!(quote_solr_value(r#"a\b"c"#), r#""a\\b\"c""#);
    }

    #[test]
    fn portal_rag_filter_category_renders_correctly() {
        assert_eq!(
            PortalRagFilter::Category("documentation").to_fq(),
            "category:documentation"
        );
    }

    #[test]
    fn tool_maps_to_expected_index_and_filter() {
        assert!(matches!(
            SolrFilter::from(Tool::Search),
            SolrFilter::PortalRag(None)
        ));
        assert!(matches!(
            SolrFilter::from(Tool::CveSearchPortal),
            SolrFilter::Portal(Some(PortalFilter::DocumentKind("Cve")))
        ));
        assert!(matches!(
            SolrFilter::from(Tool::CveSearchRag),
            SolrFilter::PortalRag(Some(PortalRagFilter::ContentType("Cve_chunk")))
        ));
        assert!(matches!(
            SolrFilter::from(Tool::CveGetRag),
            SolrFilter::PortalRag(Some(PortalRagFilter::ContentType("Cve_parent")))
        ));
    }
}
