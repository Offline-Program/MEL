// Mimir Encrypted Launcher & supporting libraries
// Copyright (C) 2025  Red Hat, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Mimir HTTP server built on [Axum].
//!
//! # Entry point
//!
//! Call [`run`] to bind the server to the configured address and serve requests.  The function
//! does not return until the server shuts down.
//!
//! # Route table
//!
//! | Path prefix | Handler |
//! |---|---|
//! | `/en/documentation/…` | [`handlers::docs_redirect`] |
//! | `/solr/portal/select` | [`handlers::solr_proxy`] |
//! | `/solr/portal/select-errata` | [`handlers::solr_proxy`] |
//! | `/solr/portal/browse` | [`handlers::solr_proxy`] |
//! | `/solr/portal-rag/select` | [`handlers::solr_proxy`] |
//! | `/solr/portal-rag/semantic-search` | [`handlers::solr_proxy`] |
//! | `/solr/portal-rag/hybrid-search` | [`handlers::solr_proxy`] |
//! | `/product-life-cycles/api/v1/products/` | [`handlers::plc_api`] |
//! | `/hydra/rest/securitydata/csaf.json` | [`handlers::security_data_csaf`] |
//! | `/hydra/rest/securitydata/cve.json` | [`handlers::security_data_cve`] |
//! | `/*` (catch-all) | [`handlers::serve_static`] |

pub(crate) mod config;
pub(crate) mod file_backend;
pub(crate) mod handlers;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, Method, Uri},
    routing::get,
    Router,
};
use bytes::Bytes;

use config::ServerConfig;
use file_backend::FileBackend;
use handlers::{AppState, docs_redirect, parse_pmap, plc_api, security_data_csaf, security_data_cve, serve_static, solr_proxy};

/// Build and bind the Axum router, then serve requests until the process terminates.
///
/// The server shuts down gracefully on `SIGTERM` or `SIGINT`, finishing in-flight requests before
/// exiting.
pub(crate) async fn run<F: FileBackend>(config: ServerConfig, backend: F) -> Result<()> {
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let pmap = match backend.get("/pmap.txt").await {
        Ok(Some(f)) => parse_pmap(&String::from_utf8_lossy(&f.bytes)),
        _ => {
            eprintln!("Warning: pmap.txt not found; PLC API lookups will return 404");
            std::collections::HashMap::new()
        }
    };

    let state = Arc::new(AppState {
        config: config.clone(),
        backend,
        http_client,
        pmap,
    });

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
    eprintln!("Mimir HTTP server listening on {}", config.bind_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Wait for a shutdown signal (`SIGTERM` or `SIGINT`).
///
/// On Unix, both `SIGTERM` (sent by `podman stop` / `docker stop` / Kubernetes) and `SIGINT`
/// (`Ctrl-C` during development) trigger a graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { eprintln!("Received SIGINT, shutting down…"); }
            _ = sigterm.recv() => { eprintln!("Received SIGTERM, shutting down…"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        eprintln!("Received shutdown signal, shutting down…");
    }
}

/// Construct the Axum [`Router`] with all routes and shared state.
fn build_router<F: FileBackend>(state: Arc<AppState<F>>) -> Router {
    Router::new()
        // ── Legacy docs URL redirects ────────────────────────────────────────
        .route(
            "/en/documentation/{*path}",
            get(|s: State<Arc<AppState<F>>>, uri: Uri| docs_redirect(s, uri)),
        )
        // ── Solr reverse proxy ───────────────────────────────────────────────
        .route(
            "/solr/portal/select",
            get(solr_handler::<F>).post(solr_handler::<F>),
        )
        .route(
            "/solr/portal/select-errata",
            get(solr_handler::<F>).post(solr_handler::<F>),
        )
        .route(
            "/solr/portal/browse",
            get(solr_handler::<F>).post(solr_handler::<F>),
        )
        .route(
            "/solr/portal-rag/select",
            get(solr_handler::<F>).post(solr_handler::<F>),
        )
        .route(
            "/solr/portal-rag/semantic-search",
            get(solr_handler::<F>).post(solr_handler::<F>),
        )
        .route(
            "/solr/portal-rag/hybrid-search",
            get(solr_handler::<F>).post(solr_handler::<F>),
        )
        // ── Product Life-Cycle API ────────────────────────────────────────────
        .route("/product-life-cycles/api/v1/products/", get(plc_api::<F>))
        // ── Security Data API ─────────────────────────────────────────────────
        .route(
            "/hydra/rest/securitydata/csaf.json",
            get(security_data_csaf::<F>),
        )
        .route(
            "/hydra/rest/securitydata/cve.json",
            get(security_data_cve::<F>),
        )
        // ── Static file serving (catch-all) ───────────────────────────────────
        .route(
            "/{*path}",
            get(|s: State<Arc<AppState<F>>>, uri: Uri, headers: HeaderMap| {
                serve_static(s, uri, headers)
            }),
        )
        .route(
            "/",
            get(|s: State<Arc<AppState<F>>>, uri: Uri, headers: HeaderMap| {
                serve_static(s, uri, headers)
            }),
        )
        .with_state(state)
}

/// Adapts the Solr proxy handler to the unified Axum extractor signature.
async fn solr_handler<F: FileBackend>(
    state: State<Arc<AppState<F>>>,
    uri: Uri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    solr_proxy(state, uri, method, headers, body).await
}
