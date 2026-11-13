// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! MiMCP - MCP server library for the Red Hat Offline Knowledge Portal (RHOKP).

/// Embedding generation for the hybrid (RAG) search tools.
pub mod embed;
/// Solr client and query/filter types backing the MCP tools.
pub mod solr;
/// MCP tool definitions and the [`MimcpServer`] handler.
pub mod tools;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
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
    /// Directory containing the ONNX embedding model (`model.onnx`) and
    /// tokenizer (`tokenizer.json`).
    pub model_dir: PathBuf,
    /// Token used to signal graceful shutdown of the MCP service.
    pub cancellation_token: CancellationToken,
}

/// Builds an axum `Router` with the MCP service mounted.
///
/// Only the default `/mcp` endpoint is mounted today; it exposes the hybrid
/// `search` tool ([`ToolSet::Default`]). Content-type-scoped endpoints
/// (`/mcp/cves`, `/mcp/docs`, `/mcp/errata`, `/mcp/all`) are proof-of-concept
/// and remain commented out below until coordination with Lightforge evolves.
///
/// Returns `Err` if the Solr endpoint URLs cannot be constructed, the Solr
/// health check fails, or the embedding model cannot be loaded.
pub async fn mcp_router(config: MimcpConfig) -> Result<axum::Router> {
    let solr = SolrClient::new(config.solr_url)?;

    tracing::info!("checking solr connectivity");
    solr.health_check().await?;
    tracing::info!("solr health check passed");

    tracing::info!("loading embedding model");
    let embedder = Arc::new(Embedder::new(&config.model_dir)?);
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
            // Stateless mode: each POST is self-contained, so no per-session
            // state is held in a single pod's memory. This lets the MCP server
            // sit behind a multi-pod load balancer without session affinity or a
            // shared session store (otherwise round-robin yields "session not
            // found" when a request lands on a pod that didn't create the
            // session). json_response returns plain JSON instead of SSE, which
            // is appropriate for fast, synchronous operations with simple integrations.
            StreamableHttpServerConfig::default()
                .with_cancellation_token(ct.clone())
                // rmcp 3.x renamed stateful_mode to legacy_session_mode; sessions
                // only apply to pre-2026-07-28 protocol versions either way.
                .with_legacy_session_mode(false)
                // rmcp 3.x defaults to loopback-only Host validation; the RHOKP
                // MCP server is reached via the container's hostname from other
                // containers, so accept any Host (network access is governed by
                // the container platform, as in rmcp 2.x).
                .disable_allowed_hosts()
                .with_json_response(true),
        )
    };

    let routes: &[(&str, ToolSet)] = &[
        // Disabling the other routes so we can focus on the default hybrid search toolset first.  Re-enable the others as our coordination with Lightforge evolves.
        // ("/mcp/cves", ToolSet::Cves),
        // ("/mcp/docs", ToolSet::Docs),
        // ("/mcp/errata", ToolSet::Errata),
        // ("/mcp/all", ToolSet::All),
        ("/mcp", ToolSet::Default),
    ];

    let mut router = axum::Router::new();
    for (path, tool_set) in routes {
        let tools = tool_set
            .allowed_tools()
            .iter()
            .map(|t| t.name())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::info!(path, tools, "mounting endpoint");
        router = router.nest_service(path, make_service(tool_set.clone()));
    }

    Ok(router)
}
