use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{RoleServer, schemars, tool, tool_handler, tool_router, ServerHandler};

use crate::embed::Embedder;
use crate::solr::{SolrClient, SolrResponse};

/// Upper bound on the number of results a single search can return.
const MAX_ROWS: u32 = 20;

pub mod tool_names {
    pub const CVE_SEARCH: &str = "cve_search";
    pub const DOCS_SEARCH: &str = "docs_search";
    pub const ERRATA_SEARCH: &str = "errata_search";
    pub const CVE_GET: &str = "cve_get";
    pub const ERRATA_GET: &str = "errata_get";
}

/// Returns the default value for the `rows` field on search requests.
fn default_rows() -> u32 {
    5
}

/// Parameters for the `search` MCP tool (lexical).
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchRequest {
    #[schemars(description = "Search query for Red Hat documentation, errata, CVEs, etc.")]
    pub query: String,

    #[schemars(description = "Maximum number of results to return (1-20, default 5)")]
    #[serde(default = "default_rows")]
    pub rows: u32,
}

/// Parameters for the `search_hybrid` MCP tool.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct HybridSearchRequest {
    #[schemars(description = "Search query for Red Hat documentation, errata, CVEs, etc.")]
    pub query: String,

    #[schemars(description = "Maximum number of results to return (1-20, default 5)")]
    #[serde(default = "default_rows")]
    pub rows: u32,
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
    /// All content-type-specific tools.
    Default,
    /// All tools (currently same as Default).
    All,
    /// CVE tools only.
    Cves,
    /// Documentation tools only.
    Docs,
    /// Errata tools only.
    Errata,
}

impl ToolSet {
    pub fn allowed_tools(&self) -> &[&str] {
        use tool_names::*;
        match self {
            Self::Default | Self::All => &[
                CVE_SEARCH,
                DOCS_SEARCH,
                ERRATA_SEARCH,
                CVE_GET,
                ERRATA_GET,
            ],
            Self::Cves => &[CVE_SEARCH, CVE_GET],
            Self::Docs => &[DOCS_SEARCH],
            Self::Errata => &[ERRATA_SEARCH, ERRATA_GET],
        }
    }

    fn instructions(&self) -> String {
        match self {
            Self::Default | Self::All => {
                "MiMCP provides search access to Red Hat product documentation, \
                 errata, and CVEs from the Offline Knowledge Portal."
                    .to_owned()
            }
            Self::Cves => {
                "MiMCP CVE endpoint. Search and retrieve Red Hat CVE records."
                    .to_owned()
            }
            Self::Docs => {
                "MiMCP documentation endpoint. Search Red Hat product documentation."
                    .to_owned()
            }
            Self::Errata => {
                "MiMCP errata endpoint. Search and retrieve Red Hat errata advisories."
                    .to_owned()
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

    async fn hybrid_search_filtered(
        &self,
        query: &str,
        rows: u32,
        content_type: &str,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        let rows = rows.clamp(1, MAX_ROWS);

        let vector = self.embedder.embed(query).map_err(|e| {
            tracing::error!(error = %e, "embedding generation failed");
            ErrorData::internal_error(format!("Embedding failed: {e}"), None)
        })?;

        let result = self
            .solr
            .hybrid_search(query, &vector, rows, Some(content_type))
            .await
            .map_err(|e| {
                tracing::error!(error = %e, content_type, "solr hybrid search failed");
                ErrorData::internal_error(format!("Solr hybrid query failed: {e}"), None)
            })?;

        Ok(Json(result))
    }
}

#[tool_router]
impl MimcpServer {
    #[tool(
        description = "Lexical keyword search across Red Hat product documentation, errata, CVEs, and knowledge base articles. Use search_hybrid for better relevance."
    )]
    async fn search(
        &self,
        Parameters(req): Parameters<SearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        let rows = req.rows.clamp(1, MAX_ROWS);

        let result = self.solr.search(&req.query, rows).await.map_err(|e| {
            tracing::error!(error = %e, "solr lexical search failed");
            ErrorData::internal_error(format!("Solr query failed: {e}"), None)
        })?;

        Ok(Json(result))
    }

    #[tool(
        description = "Hybrid search combining keyword matching with semantic relevance reranking. Produces more relevant results than plain lexical search. Use this for natural language questions about Red Hat products, CVEs, errata, and documentation."
    )]
    async fn search_hybrid(
        &self,
        Parameters(req): Parameters<HybridSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        let rows = req.rows.clamp(1, MAX_ROWS);

        let vector = self.embedder.embed(&req.query).map_err(|e| {
            tracing::error!(error = %e, "embedding generation failed");
            ErrorData::internal_error(format!("Embedding failed: {e}"), None)
        })?;

        let result = self
            .solr
            .hybrid_search(&req.query, &vector, rows, None)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "solr hybrid search failed");
                ErrorData::internal_error(format!("Solr hybrid query failed: {e}"), None)
            })?;

        Ok(Json(result))
    }

    #[tool(description = "Search Red Hat CVE records using hybrid semantic and keyword matching.")]
    async fn cve_search(
        &self,
        Parameters(req): Parameters<ContentSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.hybrid_search_filtered(&req.query, req.rows, "Cve_chunk")
            .await
    }

    #[tool(description = "Search Red Hat product documentation using hybrid semantic and keyword matching.")]
    async fn docs_search(
        &self,
        Parameters(req): Parameters<ContentSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.hybrid_search_filtered(&req.query, req.rows, "documentation_chunk")
            .await
    }

    #[tool(description = "Search Red Hat errata advisories using hybrid semantic and keyword matching.")]
    async fn errata_search(
        &self,
        Parameters(req): Parameters<ContentSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.hybrid_search_filtered(&req.query, req.rows, "errata_chunk")
            .await
    }

    /// Returns `Err` if the Solr query fails.
    #[tool(description = "Fetch a specific CVE by its identifier (e.g. CVE-2024-1234).")]
    async fn cve_get(
        &self,
        Parameters(req): Parameters<GetByIdRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        let result = self
            .solr
            .get_by_id(&req.id, "Cve_parent")
            .await
            .map_err(|e| {
                tracing::error!(error = %e, id = %req.id, "solr get_by_id failed");
                ErrorData::internal_error(format!("Solr query failed: {e}"), None)
            })?;
        Ok(Json(result))
    }

    /// Returns `Err` if the Solr query fails.
    #[tool(description = "Fetch a specific erratum by its advisory ID (e.g. RHSA-2024:1234).")]
    async fn errata_get(
        &self,
        Parameters(req): Parameters<GetByIdRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        let result = self
            .solr
            .get_by_id(&req.id, "errata_parent")
            .await
            .map_err(|e| {
                tracing::error!(error = %e, id = %req.id, "solr get_by_id failed");
                ErrorData::internal_error(format!("Solr query failed: {e}"), None)
            })?;
        Ok(Json(result))
    }
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

    /// Guards against a tool_names constant drifting from the actual
    /// #[tool] method name — a rename on one side without the other
    /// would silently hide the tool from all endpoints.
    #[test]
    fn tool_name_constants_match_router() {
        let registered = registered_tool_names();
        let constants = [
            tool_names::CVE_SEARCH,
            tool_names::DOCS_SEARCH,
            tool_names::ERRATA_SEARCH,
            tool_names::CVE_GET,
            tool_names::ERRATA_GET,
        ];
        for name in constants {
            assert!(
                registered.contains(name),
                "tool_names constant {name:?} not found in tool router. Registered: {registered:?}"
            );
        }
    }

    /// Catches a new tool_names constant being added without including
    /// it in ToolSet::All, which would make the tool unreachable from
    /// the /mcp and /mcp/all endpoints.
    #[test]
    fn all_toolset_covers_all_constants() {
        let allowed: HashSet<&str> = ToolSet::All.allowed_tools().iter().copied().collect();
        let constants = [
            tool_names::CVE_SEARCH,
            tool_names::DOCS_SEARCH,
            tool_names::ERRATA_SEARCH,
            tool_names::CVE_GET,
            tool_names::ERRATA_GET,
        ];
        for name in constants {
            assert!(
                allowed.contains(name),
                "tool_names constant {name:?} missing from ToolSet::All"
            );
        }
    }

    /// Prevents a per-content-type ToolSet variant from advertising a
    /// tool that ToolSet::All doesn't include — which would mean the
    /// scoped endpoint exposes something the "everything" endpoint hides.
    #[test]
    fn toolset_subsets_are_subsets_of_all() {
        let all: HashSet<&str> = ToolSet::All.allowed_tools().iter().copied().collect();
        for variant in [ToolSet::Cves, ToolSet::Docs, ToolSet::Errata] {
            for name in variant.allowed_tools() {
                assert!(
                    all.contains(name),
                    "{name:?} in a ToolSet variant but not in ToolSet::All"
                );
            }
        }
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
        let allowed = self.tool_set.allowed_tools();
        let tools: Vec<Tool> = Self::tool_router()
            .list_all()
            .into_iter()
            .filter(|t| allowed.contains(&t.name.as_ref()))
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
