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

//! Axum route handlers for all Mimir HTTP server behaviour.
//!
//! Each handler group corresponds to a logical section of the original Apache configuration:
//!
//! - [`serve_static`] — static file serving with SSI variable injection, on-the-fly
//!   decompression/decryption, and content-encoding negotiation.
//! - [`solr_proxy`] — transparent reverse proxy to the local Solr instance.
//! - [`plc_api`] — Product Life-Cycle API: `?name=` query string mapped to a static JSON file
//!   via `pmap.txt`.
//! - [`security_data_api`] — Security Data API: `?page=N` rewritten to a directory path.
//! - [`docs_redirect`] — Legacy documentation URL redirects.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Redirect, Response},
};
use bytes::Bytes;
use flate2::read::GzDecoder;
use mel_libs::crypt::try_decode_hex_aes_param;
use std::io::Read;

use super::{
    config::{ContentEncoding, ContentEncryption, ServerConfig},
    file_backend::FileBackend,
};

/// Shared application state threaded through every handler.
pub(crate) struct AppState<F: FileBackend> {
    /// Server configuration (ports, encryption mode, webroot, …).
    pub(crate) config: ServerConfig,
    /// The file storage backend.
    pub(crate) backend: F,
    /// The HTTP client used for proxying Solr requests.
    pub(crate) http_client: reqwest::Client,
}

// ---------------------------------------------------------------------------
// Docs URL redirect handler
// ---------------------------------------------------------------------------

/// Redirect legacy `en/documentation/…` URLs to Mimir's internal documentation paths.
///
/// Implements the Apache `RewriteRule` block:
/// ```text
/// RewriteRule "^en/documentation/([^/]+)/([^/]+)/html/([^/]+)/index/?" …
/// RewriteRule "^en/documentation/([^/]+)/([^/]+)/html-single/([^/]+)/index/?" …
/// ```
///
/// - `html/…` → redirect to `html/$doc/index/` if the multipage index file exists,
///   otherwise redirect to `html-single/$doc/index/`.
/// - `html-single/…` → always redirect to `html-single/$doc/index/`.
pub(crate) async fn docs_redirect<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    uri: Uri,
) -> Response {
    let path = uri.path();

    // Strip the leading `/en/documentation/` prefix to get `{product}/{version}/{format}/{doc}/…`
    let rest = match path.strip_prefix("/en/documentation/") {
        Some(r) => r,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let segments: Vec<&str> = rest.splitn(5, '/').collect();
    // Expected: [product, version, format ("html" or "html-single"), doc, …]
    if segments.len() < 4 {
        return StatusCode::NOT_FOUND.into_response();
    }

    let (product, version, format, doc) = (segments[0], segments[1], segments[2], segments[3]);

    let target = match format {
        "html-single" => {
            format!("/documentation/en-us/{product}/{version}/html-single/{doc}/index/")
        }
        "html" => {
            // Check whether the multipage index file exists on disk.
            let multipage_check = format!(
                "/documentation/en-us/{product}/{version}/html/{doc}/index/index.html"
            );
            let multipage_exists = state
                .backend
                .get(&multipage_check)
                .await
                .unwrap_or(None)
                .is_some();

            if multipage_exists {
                format!("/documentation/en-us/{product}/{version}/html/{doc}/index/")
            } else {
                format!("/documentation/en-us/{product}/{version}/html-single/{doc}/index/")
            }
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };

    Redirect::temporary(&target).into_response()
}

// ---------------------------------------------------------------------------
// Solr reverse proxy handler
// ---------------------------------------------------------------------------

/// Transparently proxy a request to the local Solr instance.
///
/// The request path and query string are forwarded unchanged.  The response body and
/// headers are streamed back to the client.
pub(crate) async fn solr_proxy<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    uri: Uri,
    method: axum::http::Method,
    req_headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Build the upstream URL by replacing the scheme+authority with the Solr base URL.
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or(uri.path());

    let upstream = format!("{}{}", state.config.solr_url, path_and_query);

    let mut req_builder = state.http_client.request(method, &upstream);

    // Forward a safe subset of request headers to Solr.
    for (name, value) in &req_headers {
        // Skip hop-by-hop headers.
        match name.as_str() {
            "host" | "connection" | "keep-alive" | "proxy-authenticate"
            | "proxy-authorization" | "te" | "trailers" | "transfer-encoding" | "upgrade" => {}
            _ => {
                req_builder = req_builder.header(name, value);
            }
        }
    }

    let upstream_response = match req_builder.body(body).send().await {
        Ok(r) => r,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let status = upstream_response.status();
    let resp_headers = upstream_response.headers().clone();
    let resp_bytes = match upstream_response.bytes().await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let mut response = Response::new(Body::from(resp_bytes));
    *response.status_mut() = status;

    // Forward response headers from Solr to the client.
    for (name, value) in &resp_headers {
        match name.as_str() {
            "connection" | "transfer-encoding" => {}
            _ => {
                response.headers_mut().insert(name, value.clone());
            }
        }
    }

    response
}

// ---------------------------------------------------------------------------
// Product Life-Cycle API handler
// ---------------------------------------------------------------------------

/// Query parameters for the PLC API endpoint.
#[derive(serde::Deserialize)]
pub(crate) struct PlcQuery {
    /// Product name, URL-encoded (e.g. `Red%20Hat%20Enterprise%20Linux`).
    name: Option<String>,
}

/// Serve the Product Life-Cycle API.
///
/// Maps `GET /product-life-cycles/api/v1/products/?name=<product name>` to a static JSON file
/// located at `/product-life-cycles/api/v1/products/<mapped-name>/index.json`, where the name
/// mapping is performed by a lookup in `pmap.txt`.
///
/// Without a `name` parameter the directory index (`index.json`) is returned directly.
pub(crate) async fn plc_api<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    Query(query): Query<PlcQuery>,
) -> Response {
    let path = match &query.name {
        Some(raw_name) => {
            // Lower-case the name and look it up in the pmap.
            let lower_name = raw_name.to_lowercase();
            let mapped = match lookup_pmap(&state, &lower_name).await {
                Some(m) => m,
                None => return StatusCode::NOT_FOUND.into_response(),
            };
            format!("/product-life-cycles/api/v1/products/{mapped}/index.json")
        }
        None => "/product-life-cycles/api/v1/products/index.json".to_string(),
    };

    serve_file(&state, &path, false).await
}

/// Read `pmap.txt` and return the mapped value for `key`, or `None` if not found.
///
/// The `pmap.txt` format is two tab-separated columns per line: `key<TAB>value`.
async fn lookup_pmap<F: FileBackend>(state: &AppState<F>, key: &str) -> Option<String> {
    let pmap_bytes = state
        .backend
        .get("/pmap.txt")
        .await
        .ok()??
        .bytes;

    let text = String::from_utf8_lossy(&pmap_bytes);
    for line in text.lines() {
        let mut cols = line.splitn(2, '\t');
        if let (Some(k), Some(v)) = (cols.next(), cols.next()) {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Security Data API handler
// ---------------------------------------------------------------------------

/// Query parameters for the Security Data API endpoint.
#[derive(serde::Deserialize)]
pub(crate) struct SecurityDataQuery {
    /// Page number for paginated CSAF or CVE data.
    page: Option<u64>,
}

/// Serve the Security Data API for CSAF data.
///
/// Rewrites `GET /hydra/rest/securitydata/csaf.json?page=N` to
/// `/hydra/rest/securitydata/csaf/{N}/index.json`, mirroring the Apache
/// `RewriteRule` with `[P,QSD,L]` flags.  Without a `page` parameter, the
/// base `index.json` is returned.
pub(crate) async fn security_data_csaf<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    Query(query): Query<SecurityDataQuery>,
) -> Response {
    let path = match query.page {
        Some(page) => format!("/hydra/rest/securitydata/csaf/{page}/index.json"),
        None => "/hydra/rest/securitydata/index.json".to_string(),
    };
    serve_file(&state, &path, false).await
}

/// Serve the Security Data API for CVE data.
///
/// Rewrites `GET /hydra/rest/securitydata/cve.json?page=N` to
/// `/hydra/rest/securitydata/cve/{N}/index.json`.  Without a `page` parameter,
/// the base `index.json` is returned.
pub(crate) async fn security_data_cve<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    Query(query): Query<SecurityDataQuery>,
) -> Response {
    let path = match query.page {
        Some(page) => format!("/hydra/rest/securitydata/cve/{page}/index.json"),
        None => "/hydra/rest/securitydata/index.json".to_string(),
    };
    serve_file(&state, &path, false).await
}

// ---------------------------------------------------------------------------
// Static file handler
// ---------------------------------------------------------------------------

/// Serve a static file for the given URI path, applying all content-encoding and
/// content-encryption pipeline steps required by the server configuration.
///
/// Pipeline per content mode (mirroring Apache's `SetOutputFilter` chains):
///
/// | `COMPRESSED` | `ENCRYPT` | paywall path? | Pipeline |
/// |---|---|---|---|
/// | false | false | — | read → deflate (Axum/tower-http handles) |
/// | true  | false | false (HTML) | read pre-gzip → gunzip → SSI → deflate |
/// | true  | false | false (JSON) | read pre-gzip → serve as-is or gunzip |
/// | false | true  | true  | read → decrypt → SSI → deflate |
/// | true  | true  | true  | read pre-gzip → decrypt → gunzip → SSI → deflate |
/// | true  | true  | false (HTML) | read pre-gzip → gunzip → SSI → deflate |
pub(crate) async fn serve_static<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    uri: Uri,
    req_headers: HeaderMap,
) -> Response {
    let raw_path = uri.path();

    // Resolve `index.html` for bare directory paths.
    let path = if raw_path.ends_with('/') || raw_path.is_empty() {
        format!("{raw_path}index.html")
    } else {
        raw_path.to_string()
    };

    let is_paywall = is_paywall_path(&path);
    let is_html = path.ends_with(".html");
    let is_json = path.ends_with(".json");
    let client_accepts_gzip = accepts_gzip(&req_headers);

    // Fetch raw bytes from the backend.
    let file = match state.backend.get(&path).await {
        Ok(Some(f)) => f,
        Ok(None) => return serve_not_found(&state).await,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let raw_bytes = file.bytes;
    let content_type = file.content_type;

    // Run the content pipeline.
    let (body_bytes, encoding_header) = match (
        state.config.content_encoding,
        &state.config.content_encryption,
        is_paywall,
        is_html,
        is_json,
    ) {
        // ── compressed + encrypted + paywall ──────────────────────────────────
        // Pipeline: decrypt → gunzip → SSI → (deflate handled by tower-http)
        (ContentEncoding::Precompressed, ContentEncryption::Encrypted { dek, iv }, true, _, _) => {
            let decrypted = match aes_decrypt(dek, iv, &raw_bytes) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let decompressed = match gunzip(&decrypted) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let processed = inject_ssi_vars(&state.config, decompressed);
            (processed, None)
        }

        // ── compressed + encrypted + non-paywall HTML ─────────────────────────
        // Pipeline: gunzip → SSI → (deflate handled by tower-http)
        (ContentEncoding::Precompressed, ContentEncryption::Encrypted { .. }, false, true, _) => {
            let decompressed = match gunzip(&raw_bytes) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let processed = inject_ssi_vars(&state.config, decompressed);
            (processed, None)
        }

        // ── plain + encrypted + paywall ───────────────────────────────────────
        // Pipeline: decrypt → SSI → (deflate handled by tower-http)
        (ContentEncoding::Plain, ContentEncryption::Encrypted { dek, iv }, true, _, _) => {
            let decrypted = match aes_decrypt(dek, iv, &raw_bytes) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let processed = inject_ssi_vars(&state.config, decrypted);
            (processed, None)
        }

        // ── compressed + non-paywall JSON ─────────────────────────────────────
        // Serve pre-gzipped as-is when client accepts gzip; otherwise gunzip first.
        (ContentEncoding::Precompressed, _, _, _, true) => {
            if client_accepts_gzip {
                (raw_bytes, Some("gzip"))
            } else {
                let decompressed = match gunzip(&raw_bytes) {
                    Ok(d) => d,
                    Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                (decompressed, None)
            }
        }

        // ── compressed + HTML (any encryption state for non-paywall) ──────────
        // Pipeline: gunzip → SSI → (deflate handled by tower-http)
        (ContentEncoding::Precompressed, _, _, true, _) => {
            let decompressed = match gunzip(&raw_bytes) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let processed = inject_ssi_vars(&state.config, decompressed);
            (processed, None)
        }

        // ── plain + HTML (unencrypted) ────────────────────────────────────────
        // SSI variable injection only.
        (ContentEncoding::Plain, ContentEncryption::Plain, _, true, _) => {
            let processed = inject_ssi_vars(&state.config, raw_bytes);
            (processed, None)
        }

        // ── everything else: serve bytes as-is ───────────────────────────────
        _ => (raw_bytes, None),
    };

    build_file_response(body_bytes, &content_type, encoding_header, is_html)
}

/// Serve the `404.html` error page, or a bare 404 if the error page itself is missing.
async fn serve_not_found<F: FileBackend>(state: &AppState<F>) -> Response {
    match state.backend.get("/404.html").await {
        Ok(Some(f)) => {
            let processed = inject_ssi_vars(&state.config, f.bytes);
            let mut resp = build_file_response(processed, "text/html; charset=utf-8", None, true);
            *resp.status_mut() = StatusCode::NOT_FOUND;
            resp
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serve a file directly by path, bypassing the full static-file pipeline.
///
/// Used for API endpoints (PLC, security data) where no decryption or SSI is needed.
async fn serve_file<F: FileBackend>(state: &AppState<F>, path: &str, _is_api: bool) -> Response {
    match state.backend.get(path).await {
        Ok(Some(f)) => build_file_response(f.bytes, &f.content_type, None, false),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Content pipeline helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `path` is under a paywall-protected directory (`/solutions/` or `/articles/`).
fn is_paywall_path(path: &str) -> bool {
    path.starts_with("/solutions/") || path.starts_with("/articles/")
}

/// Returns `true` if the `Accept-Encoding` header indicates gzip is acceptable.
fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("gzip"))
        .unwrap_or(false)
}

/// Decompress a gzip-compressed byte slice.
fn gunzip(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(input);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Decrypt a byte slice using AES-128-CTR with the given hex-encoded key and IV.
fn aes_decrypt(dek_hex: &str, iv_hex: &str, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let dek = try_decode_hex_aes_param(dek_hex)
        .map_err(|_| anyhow::anyhow!("invalid DEK hex"))?;
    let iv_param = try_decode_hex_aes_param(iv_hex)
        .map_err(|_| anyhow::anyhow!("invalid IV hex"))?;

    // Temporarily override IV via the openssl-based decrypt path.  mel_libs `dec()` uses the
    // global IV, so we call openssl directly here to honour the provided IV.
    use openssl::symm::{decrypt, Cipher};
    let plaintext = decrypt(Cipher::aes_128_ctr(), dek.data(), Some(iv_param.data()), ciphertext)
        .map_err(|e| anyhow::anyhow!("AES decryption failed: {e}"))?;
    Ok(plaintext)
}

/// Inject SSI (Server Side Include) environment variables into HTML content.
///
/// Apache's `mod_include` was used to substitute `<!--#echo var="VAR_NAME" -->` directives.
/// Mimir HTML pages reference two variables:
/// - `UNCLASSIFIED_BANNER` — inserts a banner element when set.
/// - `MIMIR_MISSING_ACCESS_KEY` — signals the page to show an access-key warning.
///
/// This function replaces the SSI echo directives with their resolved values.
fn inject_ssi_vars(config: &ServerConfig, bytes: Vec<u8>) -> Vec<u8> {
    let html = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => return e.into_bytes(),
    };

    let banner_value = config.unclassified_banner.as_deref().unwrap_or("");
    let missing_key_value = if config.missing_access_key { "true" } else { "" };

    let html = html
        .replace(
            r#"<!--#echo var="UNCLASSIFIED_BANNER" -->"#,
            banner_value,
        )
        .replace(
            r#"<!--#echo var="MIMIR_MISSING_ACCESS_KEY" -->"#,
            missing_key_value,
        );

    html.into_bytes()
}

/// Construct an HTTP response from body bytes, content type, optional encoding header, and whether
/// to add the `x-mimir-ssi` header present on all HTML responses.
fn build_file_response(
    body: Vec<u8>,
    content_type: &str,
    content_encoding: Option<&str>,
    is_html: bool,
) -> Response {
    let mut headers = HeaderMap::new();

    headers.insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap_or_else(|_| {
            HeaderValue::from_static("application/octet-stream")
        }),
    );

    if let Some(enc) = content_encoding {
        if let Ok(v) = HeaderValue::from_str(enc) {
            headers.insert(axum::http::header::CONTENT_ENCODING, v);
        }
    }

    if is_html {
        headers.insert("x-mimir-ssi", HeaderValue::from_static("true"));
    }

    (StatusCode::OK, headers, body).into_response()
}
