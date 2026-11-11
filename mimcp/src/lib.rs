// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! MiMCP - MCP server library for the Red Hat Offline Knowledge Portal (RHOKP).

/// ONNX-backed text embedding support.
pub mod embed;
pub mod packages;
pub mod portal;
/// Offline product-lifecycle MCP tools backed by bundled PLC catalog JSON.
pub mod product;
pub mod records;
pub mod search_input;
/// Client for querying the Solr indexes backing the RHOKP portal.
pub mod solr;
/// MCP tool definitions and the [`MimcpServer`] implementation.
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
use crate::product::ProductCatalog;
use crate::solr::SolrClient;
use crate::tools::{MimcpServer, ToolSet};

/// Configuration for constructing an MCP service.
pub struct MimcpConfig {
    /// Base URL of the Solr instance (e.g. `http://localhost:8983`).
    pub solr_url: Url,
    /// Directory containing the ONNX embedding model (`model.onnx`) and
    /// tokenizer (`tokenizer.json`).
    pub model_dir: PathBuf,
    /// Directory containing the offline PLC product catalog: the shipped zola
    /// static `product-life-cycles/api/v1` tree (holding `products/index.json`
    /// and `web-products.json`).
    pub product_data_dir: PathBuf,
    /// Token used to signal graceful shutdown of the MCP service.
    pub cancellation_token: CancellationToken,
}

/// Builds an axum `Router` with the MCP service mounted.
///
/// Three endpoints are mounted: `/mcp`, exposing every tool ([`ToolSet::Default`]);
/// `/mcp/security`, the offline reimplementation of the online Red Hat security
/// MCP server's seven tools ([`ToolSet::Security`]); and `/mcp/product`, the
/// offline reimplementation of the online Red Hat product-lifecycle MCP server's
/// six tools ([`ToolSet::Product`]).
///
/// Returns `Err` if the Solr endpoint URLs cannot be constructed, the Solr
/// health check fails, the embedding model cannot be loaded, or the product
/// catalog cannot be loaded.
pub async fn mcp_router(config: MimcpConfig) -> Result<axum::Router> {
    let solr = SolrClient::new(config.solr_url)?;

    tracing::info!("checking solr connectivity");
    solr.health_check().await?;
    tracing::info!("solr health check passed");

    tracing::info!("loading embedding model");
    let embedder = Arc::new(Embedder::new(&config.model_dir)?);
    tracing::info!("embedding model loaded");

    tracing::info!("loading product catalog");
    let catalog = Arc::new(ProductCatalog::load(&config.product_data_dir)?);
    tracing::info!(
        products = catalog.products().len(),
        web_products = catalog.web_products().len(),
        "product catalog loaded"
    );

    let ct = config.cancellation_token;

    let make_service = |tool_set: ToolSet| {
        let solr = Arc::clone(&solr);
        let embedder = Arc::clone(&embedder);
        let catalog = Arc::clone(&catalog);
        let ct = ct.child_token();
        StreamableHttpService::new(
            move || {
                Ok(MimcpServer::new(
                    Arc::clone(&solr),
                    Arc::clone(&embedder),
                    Arc::clone(&catalog),
                )
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
                .with_stateful_mode(false)
                .with_json_response(true),
        )
    };

    let routes: &[(&str, ToolSet)] = &[
        ("/mcp", ToolSet::Default),
        // Offline reimplementation of the upstream Red Hat security MCP
        // server's tool surface, so clients written against it can point here
        // unchanged.
        ("/mcp/security", ToolSet::Security),
        // Offline reimplementation of the upstream Red Hat product-lifecycle MCP
        // server's tool surface.
        ("/mcp/product", ToolSet::Product),
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
        router = router.nest_service(*path, make_service(tool_set.clone()));
    }

    Ok(router)
}
