//! Solr HTTP client and response types.

use std::sync::Arc;

use anyhow::Result;
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

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

/// HTTP client for querying a Solr instance hosting the RHOKP `portal-rag` collection.
#[derive(Clone)]
pub struct SolrClient {
    /// HTTP client for issuing Solr requests.
    http: Client,
    /// URL for the `/select` endpoint.
    select_url: Url,
    /// URL for the `/hybrid-search` endpoint.
    hybrid_url: Url,
    /// URL for the `/admin/ping` health check.
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

    /// Performs a lexical search against Solr's `/select` endpoint.
    ///
    /// Returns `Err` if the HTTP request fails, the server responds with a
    /// non-2xx status code, or the response body cannot be deserialized.
    pub async fn search(&self, query: &str, rows: u32) -> Result<SolrResponse> {
        let payload = SolrPayload {
            params: SolrParams::lexical(query, rows, &[]),
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

    /// Performs a hybrid search (keyword + semantic rerank) against Solr.
    ///
    /// The `vector` is formatted into a `{!vectorSimilarity}` local param
    /// and used as the rerank query. The keyword query runs first, then the
    /// top 10,000 results are reranked by vector similarity.
    ///
    /// When `content_type` is `Some`, an additional `fq` clause restricts
    /// results to that content type.
    ///
    /// Returns `Err` if the HTTP request fails, the server responds with a
    /// non-2xx status code, or the response body cannot be deserialized.
    pub async fn hybrid_search(
        &self,
        query: &str,
        vector: &[f32],
        rows: u32,
        content_type: Option<&str>,
    ) -> Result<SolrResponse> {
        let ct_filter;
        let extra_fq = match content_type {
            Some(ct) => {
                ct_filter = format!("content_type:{ct}");
                vec![ct_filter.as_str()]
            }
            None => vec![],
        };
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
    /// (`/security/cve/CVE-2024-1234`). The `content_type` parameter
    /// restricts to the parent variant (e.g. `Cve_parent`).
    ///
    /// Returns `Err` if the HTTP request fails, the server responds with a
    /// non-2xx status code, or the response body cannot be deserialized.
    pub async fn get_by_id(&self, doc_id: &str, content_type: &str) -> Result<SolrResponse> {
        let payload = SolrPayload {
            params: SolrParams::get_by_id(doc_id, content_type),
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
    /// Query parameters for this request.
    params: SolrParams,
}

/// Query parameters nested inside [`SolrPayload`].
#[derive(Serialize)]
struct SolrParams {
    /// Main query string.
    q: String,
    /// Maximum number of results.
    rows: String,
    /// Comma-separated field list.
    fl: String,
    /// Filter queries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fq: Vec<String>,
    /// Rerank query specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    rq: Option<String>,
    /// Rerank query body (referenced by `rq` via `$rqq`).
    #[serde(skip_serializing_if = "Option::is_none")]
    rqq: Option<String>,
}

impl SolrParams {
    /// Constructs parameters for a lexical search query.
    fn lexical(query: &str, rows: u32, extra_fq: &[&str]) -> Self {
        let mut fq: Vec<String> = vec!["is_chunk:true".to_owned()];
        fq.extend(extra_fq.iter().map(|s| (*s).to_owned()));
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
    fn hybrid(query: &str, vector: &[f32], rows: u32, extra_fq: &[&str]) -> Self {
        let vector_str = format_vector(vector);
        let mut fq: Vec<String> = vec!["is_chunk:true".to_owned()];
        fq.extend(extra_fq.iter().map(|s| (*s).to_owned()));
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

    /// Constructs parameters for a parent document lookup by ID.
    fn get_by_id(doc_id: &str, content_type: &str) -> Self {
        let escaped = escape_solr_query(doc_id);
        Self {
            q: format!("doc_id:*{escaped}"),
            rows: "1".to_owned(),
            fl: FIELD_LIST.to_owned(),
            fq: vec![format!("content_type:{content_type}")],
            rq: None,
            rqq: None,
        }
    }
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
    /// Parent document identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_id: Option<String>,
    /// Solr unique document ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Document content type (e.g. `Cve_chunk`, `documentation_chunk`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Document title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Product name(s) associated with this document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<serde_json::Value>,
    /// Product version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    /// Content category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Text chunk content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk: Option<String>,
    /// Relevance score assigned by Solr.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Public URL for the source document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_source_url: Option<String>,
    /// Filesystem path to the source document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Section headings from the source document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headings: Option<String>,
    /// Pre-rerank score from `originalScore()` function.
    #[serde(rename = "originalScore()", skip_serializing_if = "Option::is_none")]
    pub original_score: Option<f64>,
}
