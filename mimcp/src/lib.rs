//! MiMCP — MCP server library for the Red Hat Offline Knowledge Portal (RHOKP).

pub mod embed;
pub mod solr;
pub mod tools;

use std::sync::Arc;

use anyhow::Result;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
    session::local::LocalSessionManager,
};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::embed::Embedder;
use crate::solr::SolrClient;
use crate::tools::{MimcpServer, ToolSet};

/// Configuration for constructing an MCP service.
pub struct MimcpConfig {
    /// Base URL of the Solr instance (e.g. `http://localhost:8983`).
    pub solr_url: Url,
    /// Token used to signal graceful shutdown of the MCP service.
    pub cancellation_token: CancellationToken,
}

/// Builds an axum `Router` with MCP services mounted at multiple endpoints.
///
/// Each endpoint exposes a different subset of tools:
/// - `/mcp` — all content-type-specific tools
/// - `/mcp/all` — all tools
/// - `/mcp/cves` — CVE tools only
/// - `/mcp/docs` — documentation tools only
///
/// Returns `Err` if the Solr endpoint URLs cannot be constructed, the Solr
/// health check fails, or the embedding model cannot be loaded.
pub async fn mcp_router(config: MimcpConfig) -> Result<axum::Router> {
    let solr = SolrClient::new(config.solr_url)?;

    tracing::info!("checking solr connectivity");
    solr.health_check().await?;
    tracing::info!("solr health check passed");

    tracing::info!("loading embedding model");
    let embedder = Arc::new(Embedder::new()?);
    tracing::info!("embedding model loaded");

    let ct = config.cancellation_token;

    let make_service = |tool_set: ToolSet| {
        let solr = Arc::clone(&solr);
        let embedder = Arc::clone(&embedder);
        let ct = ct.child_token();
        StreamableHttpService::new(
            move || {
                Ok(MimcpServer::new(Arc::clone(&solr), Arc::clone(&embedder))
                    .with_tool_set(tool_set.clone()))
            },
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default().with_cancellation_token(ct.clone()),
        )
    };

    let routes: &[(&str, ToolSet)] = &[
        ("/mcp/cves", ToolSet::Cves),
        ("/mcp/docs", ToolSet::Docs),
        ("/mcp/errata", ToolSet::Errata),
        ("/mcp/all", ToolSet::All),
        ("/mcp", ToolSet::Default),
    ];

    let mut router = axum::Router::new();
    for (path, tool_set) in routes {
        let tools = tool_set.allowed_tools().join(", ");
        tracing::info!(path, tools, "mounting endpoint");
        router = router.nest_service(*path, make_service(tool_set.clone()));
    }

    Ok(router)
}
