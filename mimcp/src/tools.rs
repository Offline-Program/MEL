// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

use std::sync::Arc;

use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, RoleServer, ServerHandler};

use crate::embed::Embedder;
use crate::solr::{SolrClient, SolrFilter, SolrResponse};

/// Upper bound on the number of results a single search can return.
const MAX_ROWS: u32 = 20;

/// Defines the [`Tool`] enum from a single list of `Variant => "wire_name"`
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

            /// The wire name of the tool, matching its `#[tool]` method name.
            pub const fn name(self) -> &'static str {
                match self {
                    $( Tool::$variant => $name, )+
                }
            }
        }
    };
}

define_tools! {
    /// Lexical keyword search. Currently disabled (not in any active `ToolSet`).
    SearchLexical => "search_lexical",
    /// Hybrid (keyword + semantic) search.
    Search => "search",
    /// CVE hybrid search.
    CveSearch => "cve_search",
    /// Documentation hybrid search.
    DocsSearch => "docs_search",
    /// Errata hybrid search.
    ErrataSearch => "errata_search",
    /// CVE lookup by ID.
    CveGet => "cve_get",
    /// Errata lookup by ID.
    ErrataGet => "errata_get",
}

impl Tool {
    /// Resolves a wire name to its [`Tool`].
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

/// Parameters for the `search` (hybrid) MCP tool.
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
    /// Hybrid search only, by default.  This default may change in the future.
    Default,
    /// All tools.
    All,
    /// CVE tools only.
    Cves,
    /// Documentation tools only.
    Docs,
    /// Errata tools only.
    Errata,
}

impl ToolSet {
    pub fn allowed_tools(&self) -> &'static [Tool] {
        match self {
            Self::Default => &[Tool::Search],
            Self::All => &[
                Tool::Search,
                Tool::CveSearch,
                Tool::DocsSearch,
                Tool::ErrataSearch,
                Tool::CveGet,
                Tool::ErrataGet,
            ],
            Self::Cves => &[Tool::CveSearch, Tool::CveGet],
            Self::Docs => &[Tool::DocsSearch],
            Self::Errata => &[Tool::ErrataSearch, Tool::ErrataGet],
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
                "RHOKP MCP errata endpoint. Search and retrieve Red Hat errata advisories."
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
            .hybrid_search(query, &vector, rows, &[SolrFilter::ContentType(content_type)])
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
        description = "Lexical keyword search across Red Hat product documentation, errata, CVEs, and knowledge base articles. Use search for better relevance."
    )]
    async fn search_lexical(
        &self,
        Parameters(req): Parameters<LexicalSearchRequest>,
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
    async fn search(
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
            .hybrid_search(&req.query, &vector, rows, &[])
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

    #[tool(
        description = "Search Red Hat product documentation using hybrid semantic and keyword matching."
    )]
    async fn docs_search(
        &self,
        Parameters(req): Parameters<ContentSearchRequest>,
    ) -> Result<Json<SolrResponse>, ErrorData> {
        self.hybrid_search_filtered(&req.query, req.rows, "documentation_chunk")
            .await
    }

    #[tool(
        description = "Search Red Hat errata advisories using hybrid semantic and keyword matching."
    )]
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
    /// `SearchLexical` is intentionally excluded (disabled).
    #[test]
    fn all_toolset_covers_every_enabled_tool() {
        let allowed: HashSet<Tool> = ToolSet::All.allowed_tools().iter().copied().collect();
        for &tool in Tool::ALL {
            if tool == Tool::SearchLexical {
                continue;
            }
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
        for variant in [ToolSet::Cves, ToolSet::Docs, ToolSet::Errata] {
            for &tool in variant.allowed_tools() {
                assert!(
                    all.contains(&tool),
                    "{tool:?} in a ToolSet variant but not in ToolSet::All"
                );
            }
        }
    }

    /// The default endpoint must expose the hybrid `search` tool, never the
    /// lexical one.
    #[test]
    fn default_toolset_is_hybrid_search() {
        assert_eq!(ToolSet::Default.allowed_tools(), &[Tool::Search]);
        assert_eq!(Tool::Search.name(), "search");
        assert!(!ToolSet::Default.allows(Tool::SearchLexical));
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
