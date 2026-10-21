// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, RoleServer, ServerHandler};

use crate::embed::Embedder;
use crate::portal::{
    PortalDoc, PortalQuery, PortalResponseBody, CVE_DETAIL_FL, CVE_SUMMARY_FL, ERRATA_DETAIL_FL,
    ERRATA_PACKAGES_FL, ERRATA_SUMMARY_FL, KIND_CVE, KIND_ERRATA,
};
use crate::records::{
    AdvisoriesByCveResult, AdvisorySummary, CveDetail, CveSummary, ErratumDetail, ErratumMetadata,
    ErratumResult, GetCveByIdOutput, GetErrataByIdOutput, LinkedAdvisory,
    ListAdvisoriesByCveOutput, ListAdvisoryPackagesOutput, ListCveAffectedProductsOutput,
    SearchAdvisoriesMetadata, SearchAdvisoriesOutput, SearchAdvisoriesResult, SearchCvesOutput,
    SearchCvesResult, SearchMetadata,
};
use crate::search_input::{
    normalize, normalize_advisory_id, normalize_cve_id, RawSearchInput, SearchKind,
};
use crate::solr::{
    quote_solr_value, PortalFilter, PortalRagFilter, ProductVersions, SolrClient, SolrFilter,
    SolrResponse,
};

/// Upper bound on the number of results a single search can return.
const MAX_ROWS: u32 = 20;

/// Defines the [`Tool`] enum from a single list of `Variant => "tool_name"`
/// pairs, deriving [`Tool::ALL`] and [`Tool::name`] from the same source so
/// they cannot drift out of sync as tools are added or removed.
macro_rules! define_tools {
    ( $( $(#[$meta:meta])* $variant:ident => $name:literal ),+ $(,)? ) => {
        /// Every MCP tool exposed by this server.
        ///
        /// This enum is the single source of truth for tool identity. Each
        /// variant's [`Tool::name`] must match the corresponding `#[tool]`
        /// method name below; the `tool_names_match_router` test enforces that.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        pub enum Tool {
            $( $(#[$meta])* $variant, )+
        }

        impl Tool {
            /// Every tool variant, for exhaustive iteration.
            pub const ALL: &'static [Tool] = &[ $( Tool::$variant ),+ ];

            /// The name of the tool, matching its `#[tool]` method name.  The tool name is presented to, and requested by, MCP clients.
            pub const fn name(self) -> &'static str {
                match self {
                    $( Tool::$variant => $name, )+
                }
            }
        }
    };
}

define_tools! {
    // Lexical keyword search. Commented out until the lexical Portal index is
    // wired up; re-enable alongside a `search_lexical` router method.
    // SearchLexical => "search_lexical",
    /// Hybrid (keyword + semantic) search.
    Search => "search",
    /// CVE search against the lexical Portal index.
    CveSearchPortal => "cve_search_portal",
    /// CVE search against the PortalRag index.
    CveSearchRag => "cve_search_rag",
    /// Documentation hybrid search.
    DocsSearch => "docs_search",
    /// CVE lookup by ID against the lexical Portal index.
    CveGetPortal => "cve_get_portal",
    /// CVE lookup by ID against the PortalRag index.
    CveGetRag => "cve_get_rag",

    // Security tools: offline reimplementations of the upstream Red Hat
    // security MCP server's surface, backed by the lexical `portal`
    // collection. Names, inputs and outputs match upstream so clients written
    // against it work unchanged.
    /// CVE discovery by keyword and structured filters.
    SearchCves => "search_cves",
    /// Full CVE record by exact identifier.
    GetCveById => "get_cve_by_id",
    /// Compact affected-product impact for one CVE.
    ListCveAffectedProducts => "list_cve_affected_products",
    /// Advisory discovery by keyword and structured filters.
    SearchAdvisories => "search_advisories",
    /// Full advisory record by exact identifier.
    GetErrataById => "get_errata_by_id",
    /// Advisories linked to a known CVE.
    ListAdvisoriesByCve => "list_advisories_by_cve",
    /// Package payload of a known advisory.
    ListAdvisoryPackages => "list_advisory_packages",
}

impl Tool {
    /// Resolves a name to its [`Tool`].
    ///
    /// Returns `None` if `name` does not correspond to any known tool.
    pub fn from_name(name: &str) -> Option<Tool> {
        Tool::ALL.iter().copied().find(|t| t.name() == name)
    }
}

/// Returns the default value for the `rows` field on search requests.
fn default_rows() -> u32 {
    5
}

/// Parameters for the `search_lexical` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct LexicalSearchRequest {
    #[schemars(description = "Search query for Red Hat documentation, errata, CVEs, etc.")]
    pub query: String,

    #[schemars(description = "Maximum number of results to return (1-20, default 5)")]
    #[serde(default = "default_rows")]
    pub rows: u32,
}

/// A single product restriction for the structured search filter: a product
/// and, optionally, the versions of that product to narrow results to.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ProductFilter {
    #[schemars(
        description = "Product slug to match exactly, e.g. \"openshift_container_platform\". \
                       Matched exactly against the document's product field (no wildcards)."
    )]
    pub product: String,

    #[schemars(
        description = "Versions of this product to include, e.g. [\"4.19\", \"4.20\"]. \
                       Matched exactly against the document's product_version field and \
                       OR-combined. Omit or leave empty to match the product regardless of \
                       version."
    )]
    #[serde(default)]
    pub versions: Vec<String>,
}

/// Parameters for the `search` (hybrid) MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HybridSearchRequest {
    #[schemars(description = "Search query for Red Hat documentation, errata, CVEs, etc.")]
    pub query: String,

    #[schemars(description = "Maximum number of results to return (1-20, default 5)")]
    #[serde(default = "default_rows")]
    pub rows: u32,

    #[schemars(
        description = "Optional structured product filter restricting results to the listed \
                       products (OR-combined). Each entry names a product and, optionally, the \
                       versions of that product to include. Omit or leave empty to search across \
                       all products."
    )]
    #[serde(default)]
    pub products: Vec<ProductFilter>,
}

/// Parameters for content-type-specific search tools.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ContentSearchRequest {
    #[schemars(description = "Search query")]
    pub query: String,

    #[schemars(description = "Maximum number of results to return (1-20, default 5)")]
    #[serde(default = "default_rows")]
    pub rows: u32,
}

/// Parameters for document lookup by ID.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetByIdRequest {
    #[schemars(description = "Document identifier (e.g. CVE-2024-1234, RHSA-2024:1234)")]
    pub id: String,
}

/// Upper bound on advisories returned for a single CVE by
/// `list_advisories_by_cve`. Upstream returns every linked advisory; a cap
/// keeps one pathological CVE from returning an unbounded page.
const MAX_LINKED_ADVISORIES: u32 = 200;

/// Returns the default affected-product page size for `get_cve_by_id`.
fn default_affected_products_limit() -> u32 {
    10
}

/// Returns the default package page size for `list_advisory_packages`.
fn default_package_limit() -> u32 {
    50
}

/// Parameters for `search_cves` and `search_advisories`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SecuritySearchRequest {
    /// The search input, as an object or a JSON string encoding one.
    #[schemars(
        description = "Search input object (or a JSON string encoding one) with a required \
                       `query` (use \"*:*\" when only filters apply), optional \
                       `pagination.rows` (default 10, max 100) and `pagination.start` \
                       (default 0), optional structured filters, and optional \
                       `sort.sortOrder` of the form \"<field> asc|desc\"."
    )]
    pub input: RawSearchInput,
}

/// Parameters for tools that take a CVE identifier alone.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct CveIdRequest {
    /// The CVE to look up.
    #[schemars(description = "CVE-2024-1234")]
    pub cve_id: String,
}

/// Parameters for `get_cve_by_id`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetCveByIdRequest {
    /// The CVE to look up.
    #[schemars(description = "CVE-2024-1234")]
    pub cve_id: String,

    /// Affected-product page size.
    #[schemars(description = "Maximum number of affected product releases to return")]
    #[serde(default = "default_affected_products_limit")]
    pub affected_products_limit: u32,

    /// Affected-product page number, 1-indexed.
    #[schemars(
        description = "1-indexed page number of affected product releases; increment to page \
                       through results"
    )]
    #[serde(default)]
    pub affected_products_page: Option<u32>,
}

/// Parameters for tools that take an advisory identifier alone.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AdvisoryIdRequest {
    /// The advisory to look up.
    #[schemars(description = "RHSA-2024:1234")]
    pub advisory_id: String,
}

/// Parameters for `list_advisory_packages`.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListAdvisoryPackagesRequest {
    /// The advisory whose packages to list.
    #[schemars(description = "RHSA-2024:1234")]
    pub advisory_id: String,

    /// Package page size.
    #[schemars(description = "Maximum number of packages to return (default 50)")]
    #[serde(default = "default_package_limit")]
    pub limit: u32,

    /// Zero-based offset of the package page.
    #[schemars(description = "Zero-based offset of the first package to return (default 0)")]
    #[serde(default)]
    pub offset: u32,
}

/// Defines which tools an endpoint exposes via `list_tools`.
#[derive(Clone)]
pub enum ToolSet {
    /// Hybrid search only, by default.  This default may change in the future.
    Default,
    /// All tools.
    All,
    /// CVE tools only.
    Cves,
    /// Documentation tools only.
    Docs,
    /// Errata (advisory) tools only.
    Errata,
    /// The upstream-parity Red Hat security tool surface: CVEs and advisories.
    Security,
}

impl ToolSet {
    pub fn allowed_tools(&self) -> &'static [Tool] {
        match self {
            Self::Default => &[Tool::Search],
            Self::All => &[
                Tool::Search,
                Tool::CveSearchPortal,
                Tool::CveSearchRag,
                Tool::DocsSearch,
                Tool::CveGetPortal,
                Tool::CveGetRag,
                Tool::SearchCves,
                Tool::GetCveById,
                Tool::ListCveAffectedProducts,
                Tool::SearchAdvisories,
                Tool::GetErrataById,
                Tool::ListAdvisoriesByCve,
                Tool::ListAdvisoryPackages,
            ],
            Self::Cves => &[
                Tool::CveSearchPortal,
                Tool::CveSearchRag,
                Tool::CveGetPortal,
                Tool::CveGetRag,
                Tool::SearchCves,
                Tool::GetCveById,
                Tool::ListCveAffectedProducts,
                Tool::ListAdvisoriesByCve,
            ],
            Self::Docs => &[Tool::DocsSearch],
            Self::Errata => &[
                Tool::SearchAdvisories,
                Tool::GetErrataById,
                Tool::ListAdvisoriesByCve,
                Tool::ListAdvisoryPackages,
            ],
            Self::Security => &[
                Tool::SearchCves,
                Tool::GetCveById,
                Tool::ListCveAffectedProducts,
                Tool::SearchAdvisories,
                Tool::GetErrataById,
                Tool::ListAdvisoriesByCve,
                Tool::ListAdvisoryPackages,
            ],
        }
    }

    /// Returns `true` if this tool set exposes `tool`.
    fn allows(&self, tool: Tool) -> bool {
        self.allowed_tools().contains(&tool)
    }

    fn instructions(&self) -> String {
        match self {
            Self::Default | Self::All => {
                "RHOKP MCP provides search access to Red Hat product documentation, \
                 errata, and CVEs from the Offline Knowledge Portal."
                    .to_owned()
            }
            Self::Cves => {
                "RHOKP MCP CVE endpoint. Search and retrieve Red Hat CVE records.".to_owned()
            }
            Self::Docs => {
                "RHOKP MCP documentation endpoint. Search Red Hat product documentation.".to_owned()
            }
            Self::Errata => {
                "RHOKP MCP errata endpoint. Search and retrieve Red Hat advisories.".to_owned()
            }
            Self::Security => "RHOKP MCP security endpoint. Offline search and retrieval of Red \
                 Hat CVE records and security advisories."
                .to_owned(),
        }
    }
}

/// MCP server that exposes RHOKP search tools backed by a Solr instance.
#[derive(Clone)]
pub struct MimcpServer {
    solr: Arc<SolrClient>,
    embedder: Arc<Embedder>,
    tool_set: ToolSet,
}

impl MimcpServer {
    /// Creates a new MCP server backed by the given Solr client and embedder.
    pub fn new(solr: Arc<SolrClient>, embedder: Arc<Embedder>) -> Self {
        Self {
            solr,
            embedder,
            tool_set: ToolSet::Default,
        }
    }

    pub fn with_tool_set(mut self, tool_set: ToolSet) -> Self {
        self.tool_set = tool_set;
        self
    }

    /// Runs a search for `tool`, dispatching to the lexical Portal index or the
    /// hybrid PortalRag index based on [`SolrFilter::from`].
    ///
    /// `products`, when non-empty, restricts hybrid (PortalRag) results via an
    /// additional OR-of-products `fq` clause the server builds from the
    /// structured filter. It is ignored for the lexical Portal index, which does
    /// not carry the `product`/`product_version` fields.
    ///
    /// Returns `Err` if embedding (PortalRag only) or the Solr query fails.
    async fn run_search(
        &self,
        tool: Tool,
        query: &str,
        rows: u32,
        products: &[ProductFilter],
    ) -> Result<Json<SolrResponse>, ErrorData> {
        let rows = rows.clamp(1, MAX_ROWS);

        let result = match SolrFilter::from(tool) {
            SolrFilter::Portal(filter) => {
                let filters: Vec<PortalFilter> = filter.into_iter().collect();
                self.solr.search(query, rows, &filters).await.map_err(|e| {
                    tracing::error!(error = %e, tool = tool.name(), "solr lexical search failed");
                    ErrorData::internal_error(format!("Solr query failed: {e}"), None)
                })?
            }
            SolrFilter::PortalRag(filter) => {
                let vector = self.embedder.embed(query).map_err(|e| {
                    tracing::error!(error = %e, "embedding generation failed");
                    ErrorData::internal_error(format!("Embedding failed: {e}"), None)
                })?;
                let mut filters: Vec<PortalRagFilter> = filter.into_iter().collect();
                let product_versions: Vec<ProductVersions> = products
                    .iter()
                    .map(|p| ProductVersions {
                        product: &p.product,
                        versions: &p.versions,
                    })
                    .collect();
                if !product_versions.is_empty() {
                    filters.push(PortalRagFilter::Products(&product_versions));
                }
                self.solr
                    .hybrid_search(query, &vector, rows, &filters)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, tool = tool.name(), "solr hybrid search failed");
                        ErrorData::internal_error(format!("Solr hybrid query failed: {e}"), None)
                    })?
            }
        };

        Ok(Json(result))
    }

    /// Fetches a document by ID for `tool`, using the parent-variant filter for
    /// the tool's target index.
    ///
    /// Returns `Err` if the tool has no lookup filter or the Solr query fails.
    async fn run_get(&self, tool: Tool, id: &str) -> Result<Json<SolrResponse>, ErrorData> {
        let filter_fq = match SolrFilter::from(tool) {
            SolrFilter::Portal(Some(filter)) => filter.to_fq(),
            SolrFilter::PortalRag(Some(filter)) => filter.to_fq(),
            SolrFilter::Portal(None) | SolrFilter::PortalRag(None) => {
                return Err(ErrorData::internal_error(
                    format!("tool {} has no lookup filter", tool.name()),
                    None,
                ));
            }
        };

        let result = self.solr.get_by_id(id, &filter_fq).await.map_err(|e| {
            tracing::error!(error = %e, id, tool = tool.name(), "solr get_by_id failed");
            ErrorData::internal_error(format!("Solr query failed: {e}"), None)
        })?;

        Ok(Json(result))
    }

    /// Runs a query against the lexical `portal` collection.
    ///
    /// Returns `Err` if the Solr query fails.
    async fn portal(
        &self,
        tool: Tool,
        query: PortalQuery,
    ) -> Result<PortalResponseBody, ErrorData> {
        let result = self.solr.portal_query(&query).await.map_err(|e| {
            tracing::error!(error = %e, tool = tool.name(), "solr portal query failed");
            ErrorData::internal_error(format!("Solr query failed: {e}"), None)
        })?;
        Ok(result.response)
    }

    /// Fetches a single CVE document by identifier.
    ///
    /// The CVE page's business identifier lives in `url_slug`; the `id` field
    /// holds the page path, so it is not the lookup key here.
    ///
    /// Returns `Err` if `cve_id` is malformed or the Solr query fails, and
    /// `Ok(None)` when no CVE matches.
    async fn cve_doc(
        &self,
        tool: Tool,
        cve_id: &str,
        fields: &'static str,
    ) -> Result<Option<PortalDoc>, ErrorData> {
        let id = normalize_cve_id(cve_id).map_err(|e| ErrorData::invalid_params(e, None))?;
        let query = PortalQuery::lookup(
            KIND_CVE,
            format!("url_slug:{}", quote_solr_value(&id)),
            fields,
        );
        Ok(self.portal(tool, query).await?.first())
    }

    /// Fetches a single advisory document by identifier.
    ///
    /// Returns `Err` if `advisory_id` is malformed or the Solr query fails, and
    /// `Ok(None)` when no advisory matches.
    async fn advisory_doc(
        &self,
        tool: Tool,
        advisory_id: &str,
        fields: &'static str,
    ) -> Result<Option<PortalDoc>, ErrorData> {
        let id =
            normalize_advisory_id(advisory_id).map_err(|e| ErrorData::invalid_params(e, None))?;
        let query =
            PortalQuery::lookup(KIND_ERRATA, format!("id:{}", quote_solr_value(&id)), fields);
        Ok(self.portal(tool, query).await?.first())
    }

    /// Runs a client-supplied search against one document kind of the lexical
    /// `portal` collection.
    ///
    /// Returns `Err` if the input is invalid or the Solr query fails.
    async fn portal_search(
        &self,
        tool: Tool,
        input: RawSearchInput,
        kind: SearchKind,
        document_kind: &str,
        fields: &'static str,
    ) -> Result<PortalResponseBody, ErrorData> {
        let input = input
            .resolve()
            .and_then(|input| normalize(input, kind))
            .map_err(|e| ErrorData::invalid_params(e, None))?;

        let mut query = PortalQuery::new(document_kind, input.query, fields)
            .page(input.rows, input.start)
            .sorted(input.sort);
        query.filters.extend(input.filters);

        self.portal(tool, query).await
    }
}

#[tool_router]
impl MimcpServer {
    // Lexical keyword search. Commented out until the lexical Portal index is
    // wired up; re-enable alongside the `SearchLexical` `Tool` variant.
    // #[tool(
    //     description = "Lexical keyword search across Red Hat product documentation, errata, CVEs, and knowledge base articles. Use search for better relevance."
    // )]
    // async fn search_lexical(
    //     &self,
    //     Parameters(req): Parameters<LexicalSearchRequest>,
    // ) -> Result<Json<SolrResponse>, ErrorData> {
    //     self.run_search(Tool::SearchLexical, &req.query, req.rows).await
    // }

    #[tool(
        description = "Hybrid search combining keyword matching with semantic relevance reranking. Produces more relevant results than plain lexical search. Use this for natural language questions about Red Hat products, CVEs, errata, and documentation."
    )]
    async fn search(
        &self,
        Parameters(req): Parameters<HybridSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_search(Tool::Search, &req.query, req.rows, &req.products)
            .await
    }

    #[tool(description = "Search Red Hat CVE records against the lexical Portal index.")]
    async fn cve_search_portal(
        &self,
        Parameters(req): Parameters<LexicalSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_search(Tool::CveSearchPortal, &req.query, req.rows, &[])
            .await
    }

    #[tool(description = "Search Red Hat CVE records using hybrid semantic and keyword matching.")]
    async fn cve_search_rag(
        &self,
        Parameters(req): Parameters<HybridSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_search(Tool::CveSearchRag, &req.query, req.rows, &req.products)
            .await
    }

    #[tool(
        description = "Search Red Hat product documentation using hybrid semantic and keyword matching."
    )]
    async fn docs_search(
        &self,
        Parameters(req): Parameters<ContentSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_search(Tool::DocsSearch, &req.query, req.rows, &[])
            .await
    }

    /// Returns `Err` if the Solr query fails.
    #[tool(
        description = "Fetch a specific CVE by its identifier (e.g. CVE-2024-1234) from the lexical Portal index."
    )]
    async fn cve_get_portal(
        &self,
        Parameters(req): Parameters<GetByIdRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_get(Tool::CveGetPortal, &req.id).await
    }

    /// Returns `Err` if the Solr query fails.
    #[tool(
        description = "Fetch a specific CVE by its identifier (e.g. CVE-2024-1234) from the PortalRag index."
    )]
    async fn cve_get_rag(
        &self,
        Parameters(req): Parameters<GetByIdRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_get(Tool::CveGetRag, &req.id).await
    }

    #[tool(
        description = "Search Red Hat CVE records using free-text queries and optional index \
                       filters. Use for discovery, triage, and candidate selection across many \
                       CVEs - not for exact-ID lookup (use get_cve_by_id).\n\n\
                       Input: object with required `query` (use \"*:*\" when only filters \
                       apply), pagination via `pagination.rows` (default 10) and \
                       `pagination.start` (default 0), and an optional `filter.filterQuery` \
                       string for structured filtering (combine criteria with AND, alternate \
                       values with OR). Typical fragments include `documentKind` and product \
                       scoping via `platform_state_string:(<product>*)` (escape spaces with \\\\; \
                       trailing * for minor versions). When severity or a date range is given, \
                       AND these into `filter.filterQuery` and use `query` \"*:*\" if there is \
                       no keyword:\n\
                       - Severity: `cve_threatSeverity:<value>` - Critical, Important, \
                       Moderate, Low.\n\
                       - Date: `cve_publicDate:([<start>T00:00:00.000Z TO <end>T23:59:59.000Z])`\n\n\
                       Sort only when needed via `sort.sortOrder` (`<field> asc|desc`): \
                       cve_publicDate, lastModifiedDate, or cve_threatSeverity. Do not invent \
                       extra filterQuery fields or sort options.\n\n\
                       Returns: `metadata.total` and `metadata.start` plus summary rows - CVE \
                       ID, short description, threat severity, affected products (product_name, \
                       package, state), and public and last-modified dates. A total of 0 with \
                       an empty results array means no matches, and is still a successful \
                       response."
    )]
    async fn search_cves(
        &self,
        Parameters(req): Parameters<SecuritySearchRequest>,
    ) -> Result<Json<SearchCvesOutput>, ErrorData> {
        let body = self
            .portal_search(
                Tool::SearchCves,
                req.input,
                SearchKind::Cve,
                KIND_CVE,
                CVE_SUMMARY_FL,
            )
            .await?;

        Ok(Json(SearchCvesOutput {
            cves: Some(SearchCvesResult {
                metadata: Some(SearchMetadata {
                    total: Some(body.num_found),
                    start: Some(body.start),
                }),
                cve: Some(body.docs.into_iter().map(CveSummary::from).collect()),
            }),
        }))
    }

    #[tool(
        description = "Fetch a single Red Hat CVE record by exact identifier (e.g. \
                       CVE-2024-1234). Exact-ID retrieval only - not for discovery or keyword \
                       search.\n\n\
                       Returns: severity, description, CVSS v2 and v3 scores and vectors from \
                       both NVD and Red Hat sources, created/public/updated dates, affected \
                       products (name, state, package, impact), exploit status, Bugzilla \
                       references, external references, mitigation guidance, details source, \
                       and the canonical CVE URL.\n\n\
                       Additional conditions:\n\
                       - Distinguish the Red Hat severity rating from CVSS scores and vectors.\n\
                       - If CVSS v2 is returned for older records, note it as conditional.\n\n\
                       Constraints: exact cve_id match; null if missing. Paginate \
                       affected_products with `affected_products_limit` (default 10) and \
                       `affected_products_page` (1-indexed); increment until empty."
    )]
    async fn get_cve_by_id(
        &self,
        Parameters(req): Parameters<GetCveByIdRequest>,
    ) -> Result<Json<GetCveByIdOutput>, ErrorData> {
        let doc = self
            .cve_doc(Tool::GetCveById, &req.cve_id, CVE_DETAIL_FL)
            .await?;

        Ok(Json(GetCveByIdOutput {
            cve: doc.map(|doc| {
                CveDetail::from_doc(doc).paginate_affected_products(
                    req.affected_products_limit,
                    req.affected_products_page,
                )
            }),
        }))
    }

    #[tool(
        description = "Retrieve affected product entries for a single CVE by identifier (e.g. \
                       CVE-2024-1234). Use for compact product-impact scoping - triage, \
                       blast-radius estimation, ownership routing, or ticket enrichment - when \
                       full CVE detail is not needed.\n\n\
                       Returns: CVE ID, description, severity, created/public/updated dates, \
                       CVE URL, and affected products (name, package, state, impact, and \
                       not-affected justification when present). Per-release CVSS is not \
                       available offline and is always null; use the CVE-level cvss2/cvss3 from \
                       get_cve_by_id instead. When the CVE exists but has no linked product \
                       rows, returns CVE metadata with an empty affected-products list.\n\n\
                       Constraints: one CVE at a time; exact cve_id match required."
    )]
    async fn list_cve_affected_products(
        &self,
        Parameters(req): Parameters<CveIdRequest>,
    ) -> Result<Json<ListCveAffectedProductsOutput>, ErrorData> {
        let doc = self
            .cve_doc(Tool::ListCveAffectedProducts, &req.cve_id, CVE_DETAIL_FL)
            .await?;

        Ok(Json(ListCveAffectedProductsOutput {
            cve_with_affected_products: doc.map(CveDetail::from_doc),
        }))
    }

    #[tool(
        description = "Search Red Hat advisories using free-text queries and optional filters. \
                       Use for discovery, triage, and candidate selection across multiple \
                       errata records. Not for exact-ID lookup - use get_errata_by_id.\n\n\
                       Input: `query` required; use \"*:*\" when no keyword applies. Optional \
                       filters via `filter.filterQueries` (structured query strings, ANDed):\n\
                       - Type: `portal_advisory_type:\"<value>\"` - RHSA -> \"Security \
                       Advisory\", RHEA -> \"Product Enhancement Advisory\", RHBA -> \"Bug Fix \
                       Advisory\"\n\
                       - Severity: `portal_severity:\"<value>\"` - Critical, Important, \
                       Moderate, Low, None\n\
                       - Product: `portal_product_filter:<product>|<variant>|<version>|<arch>` \
                       (use * for unknown segments; escape spaces with \\\\)\n\
                       - Date range: `portal_publication_date:([<start>T00:00:00.000Z TO \
                       <end>T23:59:59.000Z])`\n\n\
                       Pagination via `pagination.rows` (default 10, max 100) and \
                       `pagination.start` (default 0). Sort via `sort.sortOrder`: id, \
                       portal_advisory_type, portal_publication_date, or portal_update_date \
                       (asc/desc).\n\n\
                       Returns: total match count and summary rows - advisory ID, synopsis, \
                       type, severity, product names, publication and updated dates, CVEs, \
                       Bugzillas, references, and advisory URL. Use returned advisory IDs for \
                       follow-up lookups with get_errata_by_id."
    )]
    async fn search_advisories(
        &self,
        Parameters(req): Parameters<SecuritySearchRequest>,
    ) -> Result<Json<SearchAdvisoriesOutput>, ErrorData> {
        let body = self
            .portal_search(
                Tool::SearchAdvisories,
                req.input,
                SearchKind::Errata,
                KIND_ERRATA,
                ERRATA_SUMMARY_FL,
            )
            .await?;

        Ok(Json(SearchAdvisoriesOutput {
            advisories: Some(SearchAdvisoriesResult {
                advisory: Some(body.docs.into_iter().map(AdvisorySummary::from).collect()),
                metadata: Some(SearchAdvisoriesMetadata {
                    total: Some(body.num_found),
                }),
            }),
        }))
    }

    #[tool(
        description = "Fetch a single Red Hat advisory by exact ID (e.g. RHSA-2024:1234, \
                       RHEA-2024:1234, RHBA-2024:1234). In this domain \"advisory\", \
                       \"erratum\" and \"errata\" are the same record type. Exact-ID retrieval \
                       only - not for discovery or package-level analysis.\n\n\
                       Returns: synopsis, type, severity, affected products, issue and updated \
                       dates, and Bugzilla references. Returns an empty result when no advisory \
                       matches.\n\n\
                       Constraints: exact ID match required; returns at most one record."
    )]
    async fn get_errata_by_id(
        &self,
        Parameters(req): Parameters<AdvisoryIdRequest>,
    ) -> Result<Json<GetErrataByIdOutput>, ErrorData> {
        let doc = self
            .advisory_doc(Tool::GetErrataById, &req.advisory_id, ERRATA_DETAIL_FL)
            .await?;

        let advisory: Vec<ErratumDetail> = doc.into_iter().map(ErratumDetail::from).collect();
        Ok(Json(GetErrataByIdOutput {
            erratum: Some(ErratumResult {
                metadata: Some(ErratumMetadata {
                    total_record_count: Some(advisory.len() as u64),
                }),
                advisory: Some(advisory),
            }),
        }))
    }

    #[tool(
        description = "Retrieve Red Hat advisories linked to a single CVE by identifier (e.g. \
                       CVE-2024-1234). Use when you have a known CVE and need its associated \
                       errata for remediation planning, patch workflows, or product-scoped \
                       impact routing.\n\n\
                       Returns: one entry per advisory, each with erratum ID, synopsis, type, \
                       severity, issue and modified dates, and affected product names. A single \
                       CVE may map to multiple advisories across product releases. Returns an \
                       empty list when the CVE is unknown or has no linked errata."
    )]
    async fn list_advisories_by_cve(
        &self,
        Parameters(req): Parameters<CveIdRequest>,
    ) -> Result<Json<ListAdvisoriesByCveOutput>, ErrorData> {
        // The CVE document does not carry its advisories, but advisories carry
        // the CVEs they fix in the indexed `errata_cves` field, so the linkage
        // is resolved from the errata side.
        let cve_id =
            normalize_cve_id(&req.cve_id).map_err(|e| ErrorData::invalid_params(e, None))?;
        let query = PortalQuery::new(
            KIND_ERRATA,
            format!("errata_cves:{}", quote_solr_value(&cve_id)),
            ERRATA_DETAIL_FL,
        )
        .page(MAX_LINKED_ADVISORIES, 0);

        let body = self.portal(Tool::ListAdvisoriesByCve, query).await?;

        Ok(Json(ListAdvisoriesByCveOutput {
            advisoires: Some(AdvisoriesByCveResult {
                advisory: Some(body.docs.into_iter().map(LinkedAdvisory::from).collect()),
            }),
        }))
    }

    #[tool(
        description = "Retrieve package entries for a single Red Hat advisory by ID (e.g. \
                       RHSA-2024:1234). Use when you have a known advisory and need its package \
                       payload for patch planning, deployment workflows, or package \
                       verification.\n\n\
                       Returns: one row per package with name, version, release, architecture \
                       and RPM filename, plus pagination metadata (count, offset, max_limit). \
                       SHA256 checksums, repository tags and per-package summaries are not \
                       available offline and are always null.\n\n\
                       Constraints: one advisory at a time; exact ID match required. Supports \
                       pagination via `limit` (default 50) and `offset` (default 0). A single \
                       advisory may span multiple pages - continue paging until the packages \
                       list is empty before concluding no further packages exist."
    )]
    async fn list_advisory_packages(
        &self,
        Parameters(req): Parameters<ListAdvisoryPackagesRequest>,
    ) -> Result<Json<ListAdvisoryPackagesOutput>, ErrorData> {
        let doc = self
            .advisory_doc(
                Tool::ListAdvisoryPackages,
                &req.advisory_id,
                ERRATA_PACKAGES_FL,
            )
            .await?;

        let packages = doc.and_then(|d| d.errata_packages).unwrap_or_default();
        Ok(Json(ListAdvisoryPackagesOutput::page(
            &packages,
            req.limit.max(1),
            req.offset,
        )))
    }

    // Errata tools disabled for now; re-enable alongside the errata `Tool`
    // variants.
    // #[tool(
    //     description = "Search Red Hat errata advisories using hybrid semantic and keyword matching."
    // )]
    // async fn errata_search(
    //     &self,
    //     Parameters(req): Parameters<ContentSearchRequest>,
    // ) -> Result<Json<SolrResponse>, ErrorData> {
    //     self.run_search(Tool::ErrataSearch, &req.query, req.rows).await
    // }

    // #[tool(description = "Fetch a specific erratum by its advisory ID (e.g. RHSA-2024:1234).")]
    // async fn errata_get(
    //     &self,
    //     Parameters(req): Parameters<GetByIdRequest>,
    // ) -> Result<Json<SolrResponse>, ErrorData> {
    //     self.run_get(Tool::ErrataGet, &req.id).await
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn registered_tool_names() -> HashSet<String> {
        MimcpServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    /// Guards against a [`Tool`] variant's name drifting from the actual
    /// #[tool] method name - a rename on one side without the other would
    /// mean the enum (and thus endpoint scoping) no longer matches the router.
    #[test]
    fn tool_names_match_router() {
        let registered = registered_tool_names();
        for &tool in Tool::ALL {
            assert!(
                registered.contains(tool.name()),
                "Tool::{tool:?} name {:?} not found in tool router. Registered: {registered:?}",
                tool.name()
            );
        }
    }

    /// Every registered #[tool] method must map back to a [`Tool`] variant, so
    /// a newly-added tool method can't slip past the enum and, with it, past
    /// the endpoint-scoping enforcement in `call_tool`.
    #[test]
    fn router_has_no_unknown_tools() {
        for name in registered_tool_names() {
            assert!(
                Tool::from_name(&name).is_some(),
                "router exposes tool {name:?} with no matching Tool variant"
            );
        }
    }

    /// Catches a new [`Tool`] variant being added without including it in
    /// ToolSet::All, which would make the tool unreachable from /mcp/all.
    #[test]
    fn all_toolset_covers_every_enabled_tool() {
        let allowed: HashSet<Tool> = ToolSet::All.allowed_tools().iter().copied().collect();
        for &tool in Tool::ALL {
            assert!(
                allowed.contains(&tool),
                "Tool::{tool:?} missing from ToolSet::All"
            );
        }
    }

    /// Prevents a per-content-type ToolSet variant from advertising a
    /// tool that ToolSet::All doesn't include - which would mean the
    /// scoped endpoint exposes something the "everything" endpoint hides.
    #[test]
    fn toolset_subsets_are_subsets_of_all() {
        let all: HashSet<Tool> = ToolSet::All.allowed_tools().iter().copied().collect();
        for variant in [
            ToolSet::Cves,
            ToolSet::Docs,
            ToolSet::Errata,
            ToolSet::Security,
        ] {
            for &tool in variant.allowed_tools() {
                assert!(
                    all.contains(&tool),
                    "{tool:?} in a ToolSet variant but not in ToolSet::All"
                );
            }
        }
    }

    /// The default endpoint must expose only the hybrid `search` tool.
    #[test]
    fn default_toolset_is_hybrid_search() {
        assert_eq!(ToolSet::Default.allowed_tools(), &[Tool::Search]);
        assert_eq!(Tool::Search.name(), "search");
        assert!(!ToolSet::Default.allows(Tool::CveSearchRag));
    }

    /// The security endpoint must expose exactly the upstream Red Hat security
    /// MCP tool names, so a client written against that server can be pointed
    /// at RHOKP unchanged. Adding or renaming one here is a breaking change for
    /// those clients.
    #[test]
    fn security_toolset_matches_the_upstream_tool_surface() {
        let names: HashSet<&str> = ToolSet::Security
            .allowed_tools()
            .iter()
            .map(|t| t.name())
            .collect();
        let expected: HashSet<&str> = HashSet::from([
            "search_cves",
            "get_cve_by_id",
            "list_cve_affected_products",
            "search_advisories",
            "get_errata_by_id",
            "list_advisories_by_cve",
            "list_advisory_packages",
        ]);
        assert_eq!(names, expected);
    }

    /// `get_cve_by_id` must apply upstream's affected-product paging defaults
    /// when a client sends only the identifier.
    #[test]
    fn get_cve_by_id_request_defaults_match_upstream() {
        let req: GetCveByIdRequest =
            serde_json::from_value(serde_json::json!({ "cve_id": "CVE-2024-1234" }))
                .expect("minimal request should deserialize");
        assert_eq!(req.affected_products_limit, 10);
        assert_eq!(req.affected_products_page, None);
    }

    /// `list_advisory_packages` must apply upstream's paging defaults.
    #[test]
    fn list_advisory_packages_request_defaults_match_upstream() {
        let req: ListAdvisoryPackagesRequest =
            serde_json::from_value(serde_json::json!({ "advisory_id": "RHSA-2024:1234" }))
                .expect("minimal request should deserialize");
        assert_eq!(req.limit, 50);
        assert_eq!(req.offset, 0);
    }

    /// A search request must accept `input` both as an object and as the JSON
    /// string some MCP clients send.
    #[test]
    fn security_search_request_accepts_both_input_forms() {
        let object: SecuritySearchRequest =
            serde_json::from_value(serde_json::json!({ "input": { "query": "log4j" } }))
                .expect("object input should deserialize");
        assert!(matches!(object.input, RawSearchInput::Object(_)));

        let text: SecuritySearchRequest =
            serde_json::from_value(serde_json::json!({ "input": r#"{"query":"log4j"}"# }))
                .expect("string input should deserialize");
        assert!(matches!(text.input, RawSearchInput::Text(_)));
    }

    /// The structured `products` filter must default to empty when a client
    /// omits it, preserving the pre-filtering request contract.
    #[test]
    fn hybrid_request_products_default_to_empty() {
        let req: HybridSearchRequest =
            serde_json::from_value(serde_json::json!({ "query": "how to configure sso" }))
                .expect("minimal request should deserialize");
        assert_eq!(req.rows, default_rows());
        assert!(req.products.is_empty());
    }

    /// A client supplying a structured `products` filter must have it parsed
    /// into the request so `run_search` can turn it into an `fq` clause.
    #[test]
    fn hybrid_request_parses_products_filter() {
        let req: HybridSearchRequest = serde_json::from_value(serde_json::json!({
            "query": "how to configure sso",
            "products": [
                {"product": "openshift_container_platform", "versions": ["4.19", "4.20"]},
                {"product": "rhel"},
            ],
        }))
        .expect("request with a products filter should deserialize");
        assert_eq!(req.products.len(), 2);
        assert_eq!(req.products[0].product, "openshift_container_platform");
        assert_eq!(req.products[0].versions, vec!["4.19", "4.20"]);
        assert_eq!(req.products[1].product, "rhel");
        assert!(req.products[1].versions.is_empty());
    }
}

fn server_info(tool_set: &ToolSet) -> ServerInfo {
    ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
        .with_server_info(Implementation::new("mimcp", env!("CARGO_PKG_VERSION")))
        .with_instructions(tool_set.instructions())
}

#[tool_handler]
impl ServerHandler for MimcpServer {
    fn get_info(&self) -> ServerInfo {
        server_info(&self.tool_set)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if tracing::enabled!(tracing::Level::TRACE) {
            if let Ok(json) = serde_json::to_string_pretty(&request) {
                tracing::trace!(direction = "in", method = "tools/call", "\n{json}");
            }
        }

        // Enforce endpoint scoping: a tool that this endpoint's ToolSet does not
        // expose must not be callable, even though the underlying tool_router
        // knows how to dispatch every tool. Without this, list_tools would hide
        // a tool while call_tool would still happily execute it.
        match Tool::from_name(request.name.as_ref()) {
            Some(tool) if self.tool_set.allows(tool) => {}
            _ => {
                return Err(ErrorData::invalid_params(
                    format!("tool {:?} is not available on this endpoint", request.name),
                    None,
                ));
            }
        }

        let tcc = ToolCallContext::new(self, request, context);
        let result = Self::tool_router().call(tcc).await;
        if tracing::enabled!(tracing::Level::TRACE) {
            match &result {
                Ok(r) => {
                    if let Ok(json) = serde_json::to_string_pretty(r) {
                        tracing::trace!(direction = "out", method = "tools/call", "\n{json}");
                    }
                }
                Err(e) => {
                    if let Ok(json) = serde_json::to_string_pretty(e) {
                        tracing::trace!(direction = "out", method = "tools/call", "\n{json}");
                    }
                }
            }
        }
        result
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let tools: Vec<rmcp::model::Tool> = Self::tool_router()
            .list_all()
            .into_iter()
            .filter(|t| {
                Tool::from_name(t.name.as_ref()).is_some_and(|tool| self.tool_set.allows(tool))
            })
            .collect();

        let result = ListToolsResult {
            tools,
            meta: None,
            next_cursor: None,
        };
        if tracing::enabled!(tracing::Level::TRACE) {
            if let Ok(json) = serde_json::to_string_pretty(&result) {
                tracing::trace!(direction = "out", method = "tools/list", "\n{json}");
            }
        }
        Ok(result)
    }
}
