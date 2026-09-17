// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, RoleServer, ServerHandler};

use crate::embed::Embedder;
use crate::solr::{
    PortalFilter, PortalRagFilter, ProductVersions, SolrClient, SolrFilter, SolrResponse,
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
    // Errata tools disabled for now; re-enable when errata coverage returns.
    // ErrataSearch => "errata_search",
    // ErrataGet => "errata_get",
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
    // Errata tools disabled for now; re-enable alongside the errata `Tool`
    // variants and router methods.
    // Errata,
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
            ],
            Self::Cves => &[
                Tool::CveSearchPortal,
                Tool::CveSearchRag,
                Tool::CveGetPortal,
                Tool::CveGetRag,
            ],
            Self::Docs => &[Tool::DocsSearch],
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

    #[tool(
        description = "Search Red Hat CVE records against the lexical Portal index."
    )]
    async fn cve_search_portal(
        &self,
        Parameters(req): Parameters<LexicalSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.run_search(Tool::CveSearchPortal, &req.query, req.rows, &[])
            .await
    }

    #[tool(
        description = "Search Red Hat CVE records using hybrid semantic and keyword matching."
    )]
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
        for variant in [ToolSet::Cves, ToolSet::Docs] {
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
