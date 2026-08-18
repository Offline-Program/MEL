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

//! MCP server lifecycle management for MEL.
//!
//! When `MCP_ENABLED=true`, spawns a background thread running a tokio runtime
//! that waits for Solr to become healthy, then serves the MCP router on an
//! internal-only address for Apache to reverse-proxy.

use std::time::Duration;

use mimcp::{mcp_router, MimcpConfig};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;

/// Environment variable that enables the MCP server. Same pattern as `ASK_RED_HAT_OFFLINE`.
const MCP_ENABLED_ENV: &str = "MCP_ENABLED";

/// Default Solr URL used by MCP when running inside the container.
const SOLR_URL: &str = "http://localhost:8983";

/// Address the MCP server binds to. Internal only - Apache proxies `/mcp` here.
const BIND_ADDR: &str = "127.0.0.1:3001";

/// Maximum number of Solr readiness poll attempts before giving up.
const SOLR_WAIT_ATTEMPTS: u32 = 60;

/// Delay between Solr readiness checks.
const SOLR_WAIT_INTERVAL: Duration = Duration::from_secs(2);

/// Returns `true` when the `MCP_ENABLED` env var is exactly `"true"`.
fn enabled() -> bool {
    matches!(std::env::var(MCP_ENABLED_ENV), Ok(v) if v == "true")
}

/// If MCP is enabled, spawns a background thread that starts a tokio runtime,
/// waits for Solr, and serves the MCP router.
///
/// Returns `Some(CancellationToken)` that the caller should cancel when MEL is
/// shutting down (i.e. when httpd exits). Returns `None` if MCP is disabled.
pub fn start() -> Option<CancellationToken> {
    if !enabled() {
        return None;
    }

    let ct = CancellationToken::new();
    let ct_child = ct.child_token();

    std::thread::spawn(move || {
        tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,mimcp=info".into()))
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();

        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("MCP: failed to create tokio runtime: {e}");
                return;
            }
        };

        rt.block_on(async move {
            if let Err(e) = run(ct_child).await {
                eprintln!("MCP: {e}");
            }
        });
    });

    Some(ct)
}

/// Waits for Solr, builds the MCP router, and serves it until cancelled.
///
/// Returns `Err` if Solr never becomes ready, the router fails to initialize,
/// or the TCP listener cannot bind.
async fn run(ct: CancellationToken) -> Result<(), Box<dyn std::error::Error>> {
    let solr_url: Url = SOLR_URL.parse()?;

    wait_for_solr(&solr_url, &ct).await?;

    let router = mcp_router(MimcpConfig {
        solr_url,
        cancellation_token: ct.child_token(),
    })
    .await?;

    let listener = tokio::net::TcpListener::bind(BIND_ADDR).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("MCP: listening on {local_addr}");

    axum::serve(listener, router)
        .with_graceful_shutdown(ct.cancelled_owned())
        .await?;

    Ok(())
}

/// Polls Solr's health endpoint until it responds successfully or the attempt
/// limit is exhausted.
///
/// Returns `Err` if Solr is still unreachable after [`SOLR_WAIT_ATTEMPTS`]
/// tries, or if the cancellation token fires first.
async fn wait_for_solr(
    solr_url: &Url,
    ct: &CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    let health_url = solr_url.join("solr/portal-rag/admin/ping")?;
    let client = reqwest::Client::new();

    for attempt in 1..=SOLR_WAIT_ATTEMPTS {
        if ct.is_cancelled() {
            return Err("shutdown before Solr became ready".into());
        }

        match client.get(health_url.clone()).send().await {
            Ok(resp) if resp.status().is_success() => {
                eprintln!("MCP: Solr ready (attempt {attempt}/{SOLR_WAIT_ATTEMPTS})");
                return Ok(());
            }
            Ok(resp) => {
                eprintln!(
                    "MCP: Solr not ready (HTTP {}), retrying ({attempt}/{SOLR_WAIT_ATTEMPTS})",
                    resp.status()
                );
            }
            Err(e) => {
                eprintln!(
                    "MCP: Solr not reachable ({e}), retrying ({attempt}/{SOLR_WAIT_ATTEMPTS})"
                );
            }
        }

        tokio::select! {
            () = ct.cancelled() => {
                return Err("shutdown before Solr became ready".into());
            }
            () = tokio::time::sleep(SOLR_WAIT_INTERVAL) => {}
        }
    }

    Err(format!(
        "Solr not ready after {} attempts ({} seconds)",
        SOLR_WAIT_ATTEMPTS,
        SOLR_WAIT_ATTEMPTS as u64 * SOLR_WAIT_INTERVAL.as_secs()
    )
    .into())
}
