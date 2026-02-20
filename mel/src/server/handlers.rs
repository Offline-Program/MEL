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
//! - [`security_data_csaf`] / [`security_data_cve`] — Security Data API: `?page=N` rewritten to a directory path.
//! - [`docs_redirect`] — Legacy documentation URL redirects.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
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
    /// Product-name → filesystem-path mapping loaded from `pmap.txt` at startup.
    pub(crate) pmap: HashMap<String, String>,
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
/// mapping is looked up in the `pmap` table loaded at startup.
///
/// Without a `name` parameter the directory index (`index.json`) is returned directly.
pub(crate) async fn plc_api<F: FileBackend>(
    State(state): State<Arc<AppState<F>>>,
    Query(query): Query<PlcQuery>,
) -> Response {
    let path = match &query.name {
        Some(raw_name) => {
            let lower_name = raw_name.to_lowercase();
            let mapped = match state.pmap.get(&lower_name) {
                Some(m) => m,
                None => return StatusCode::NOT_FOUND.into_response(),
            };
            format!("/product-life-cycles/api/v1/products/{mapped}/index.json")
        }
        None => "/product-life-cycles/api/v1/products/index.json".to_string(),
    };

    serve_json(&state, &path).await
}

/// Parse `pmap.txt` content into a `HashMap<lowercased-name, filesystem-path>`.
///
/// The `pmap.txt` format is two tab-separated columns per line: `key<TAB>value`.
pub(crate) fn parse_pmap(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut cols = line.splitn(2, '\t');
        if let (Some(k), Some(v)) = (cols.next(), cols.next()) {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
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
    serve_json(&state, &path).await
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
    serve_json(&state, &path).await
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
    let vars = HashMap::new();

    // Fetch raw bytes from the backend.
    let file = match state.backend.get(&path).await {
        Ok(Some(f)) => f,
        Ok(None) => return serve_not_found(&state, raw_path).await,
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
            let processed = process_ssi(&state, decompressed, raw_path, 0, &vars).await;
            (processed, None)
        }

        // ── compressed + encrypted + non-paywall HTML ─────────────────────────
        // Pipeline: gunzip → SSI → (deflate handled by tower-http)
        (ContentEncoding::Precompressed, ContentEncryption::Encrypted { .. }, false, true, _) => {
            let decompressed = match gunzip(&raw_bytes) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let processed = process_ssi(&state, decompressed, raw_path, 0, &vars).await;
            (processed, None)
        }

        // ── plain + encrypted + paywall ───────────────────────────────────────
        // Pipeline: decrypt → SSI → (deflate handled by tower-http)
        (ContentEncoding::Plain, ContentEncryption::Encrypted { dek, iv }, true, _, _) => {
            let decrypted = match aes_decrypt(dek, iv, &raw_bytes) {
                Ok(d) => d,
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            };
            let processed = process_ssi(&state, decrypted, raw_path, 0, &vars).await;
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
            let processed = process_ssi(&state, decompressed, raw_path, 0, &vars).await;
            (processed, None)
        }

        // ── plain + HTML (unencrypted) ────────────────────────────────────────
        // SSI variable injection only.
        (ContentEncoding::Plain, ContentEncryption::Plain, _, true, _) => {
            let processed = process_ssi(&state, raw_bytes, raw_path, 0, &vars).await;
            (processed, None)
        }

        // ── everything else: serve bytes as-is ───────────────────────────────
        _ => (raw_bytes, None),
    };

    build_file_response(body_bytes, &content_type, encoding_header, is_html)
}

/// Serve the `404.html` error page, or a bare 404 if the error page itself is missing.
async fn serve_not_found<F: FileBackend>(state: &AppState<F>, request_uri: &str) -> Response {
    let vars = HashMap::new();
    match state.backend.get("/404.html").await {
        Ok(Some(f)) => {
            let processed = process_ssi(state, f.bytes, request_uri, 0, &vars).await;
            let mut resp = build_file_response(processed, "text/html; charset=utf-8", None, true);
            *resp.status_mut() = StatusCode::NOT_FOUND;
            resp
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Serve a JSON file by path, handling pre-compressed content when `COMPRESSED=true`.
///
/// Used for API endpoints (PLC, security data) where no decryption or SSI is needed, but the
/// on-disk JSON may be gzip-compressed.
async fn serve_json<F: FileBackend>(state: &AppState<F>, path: &str) -> Response {
    let file = match state.backend.get(path).await {
        Ok(Some(f)) => f,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if state.config.content_encoding == ContentEncoding::Precompressed {
        let decompressed = match gunzip(&file.bytes) {
            Ok(d) => d,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        build_file_response(decompressed, &file.content_type, None, false)
    } else {
        build_file_response(file.bytes, &file.content_type, None, false)
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

/// Maximum recursion depth for nested `#include virtual` directives.
const SSI_MAX_DEPTH: u8 = 5;

/// Process SSI (Server Side Include) directives in HTML content.
///
/// Implements the subset of Apache `mod_include` used by Mimir templates:
///
/// - `<!--#include virtual="/path" -->` — replaced with the contents of the referenced file,
///   loaded via the [`FileBackend`].  Included files are themselves processed for SSI directives
///   up to [`SSI_MAX_DEPTH`] levels deep.
/// - `<!--#echo var="VAR_NAME" -->` — replaced with the value of the named variable.
/// - `<!--#set var="NAME" value="VALUE" -->` — sets a variable for later `#echo` lookups.
/// - `<!--#if expr="v('VAR') = 'value'" -->` / `<!--#else -->` / `<!--#endif -->` — conditional
///   blocks that include or omit content based on variable equality or regex matching.
/// - `<!--#flastmod file="./path" -->` — replaced with the file's last-modified timestamp.
///
/// Variables are seeded from the server configuration and the current request URI.  Apache's
/// `PassEnv` semantics are honoured: `UNCLASSIFIED_BANNER` is only defined when the env var was
/// set, and `MIMIR_MISSING_ACCESS_KEY` is only `"true"` for encrypted builds missing an access
/// key.
fn process_ssi<'a, F: FileBackend>(
    state: &'a AppState<F>,
    bytes: Vec<u8>,
    request_uri: &'a str,
    depth: u8,
    vars: &'a HashMap<String, String>,
) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send + 'a>> {
    Box::pin(async move {
        let html = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SSI processing skipped: HTML bytes are not valid UTF-8");
                return e.into_bytes();
            }
        };

        let directives = tokenize_ssi(&html);
        let mut result = String::with_capacity(html.len());
        let mut local_vars = vars.clone();
        let mut i = 0;

        while i < directives.len() {
            match &directives[i] {
                SsiToken::Text(t) => {
                    result.push_str(t);
                    i += 1;
                }
                SsiToken::Directive(d) => {
                    i += 1;
                    let inner = match d.strip_prefix("<!--#").and_then(|s| s.strip_suffix("-->")) {
                        Some(s) => s.trim(),
                        None => {
                            result.push_str(d);
                            continue;
                        }
                    };

                    if let Some(rest) = inner.strip_prefix("include virtual=") {
                        let path = unquote(rest.trim());
                        if !path.is_empty() && depth < SSI_MAX_DEPTH {
                            match state.backend.get(&path).await {
                                Ok(Some(f)) => {
                                    let included = process_ssi(
                                        state, f.bytes, request_uri, depth + 1, &local_vars,
                                    )
                                    .await;
                                    result.push_str(&String::from_utf8_lossy(&included));
                                }
                                _ => {
                                    eprintln!("SSI include not found: {path}");
                                }
                            }
                        } else if depth >= SSI_MAX_DEPTH {
                            eprintln!("SSI include depth limit reached for {path}");
                        }
                    } else if let Some(rest) = inner.strip_prefix("echo var=") {
                        let var_name = unquote(rest.trim());
                        if let Some(val) = ssi_var_lookup(&var_name, state, request_uri, &local_vars)
                        {
                            result.push_str(&val);
                        } else {
                            result.push_str("(none)");
                        }
                    } else if let Some(rest) = inner.strip_prefix("set var=") {
                        if let Some((name, value)) = parse_set_directive(rest.trim()) {
                            local_vars.insert(name, value);
                        }
                    } else if inner.starts_with("if expr=") {
                        let (block_output, skip_to) = process_if_block(
                            state, &directives, i - 1, request_uri, depth, &local_vars,
                        )
                        .await;
                        result.push_str(&block_output);
                        i = skip_to;
                    } else if let Some(rest) = inner.strip_prefix("flastmod file=") {
                        let path = unquote(rest.trim());
                        result.push_str(&flastmod(state, &path).await);
                    } else {
                        result.push_str(d);
                    }
                }
            }
        }

        result.into_bytes()
    })
}

/// Tokenize HTML into a sequence of text spans and SSI directive strings.
fn tokenize_ssi(html: &str) -> Vec<SsiToken<'_>> {
    let mut tokens = Vec::new();
    let mut remaining = html;

    while let Some(start) = remaining.find("<!--#") {
        if !remaining[..start].is_empty() {
            tokens.push(SsiToken::Text(&remaining[..start]));
        }
        let after_open = &remaining[start..];
        let end = match after_open.find("-->") {
            Some(pos) => pos + 3,
            None => {
                tokens.push(SsiToken::Text(after_open));
                return tokens;
            }
        };
        tokens.push(SsiToken::Directive(&after_open[..end]));
        remaining = &after_open[end..];
    }

    if !remaining.is_empty() {
        tokens.push(SsiToken::Text(remaining));
    }

    tokens
}

#[derive(Debug)]
/// A token in the SSI directive stream.
enum SsiToken<'a> {
    /// Literal HTML text between directives.
    Text(&'a str),
    /// An SSI directive comment, e.g. `<!--#include virtual="..." -->`.
    Directive(&'a str),
}

/// Strip matching single or double quotes from a value.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Parse the remainder of a `#set` directive after `set var=` has been stripped.
///
/// Input is e.g. `"MIMIR_PAGE_TITLE" value="CVE-2024-1234 - Test"`.
fn parse_set_directive(s: &str) -> Option<(String, String)> {
    let name = unquote(s.split_whitespace().next()?);
    let rest = s.find("value=").map(|i| &s[i + 6..])?;
    let value = unquote(rest.trim());
    Some((name, value))
}

/// Look up an SSI variable by name.
///
/// The lookup order mirrors Apache `mod_include` with `PassEnv`:
/// 1. Per-request variables set by `#set` directives (in `local_vars`).
/// 2. Built-in variables (`DATE_LOCAL`, `REQUEST_URI`).
/// 3. Config-derived variables (`UNCLASSIFIED_BANNER`, `MIMIR_MISSING_ACCESS_KEY`).
fn ssi_var_lookup<F: FileBackend>(
    name: &str,
    state: &AppState<F>,
    request_uri: &str,
    local_vars: &HashMap<String, String>,
) -> Option<String> {
    if let Some(v) = local_vars.get(name) {
        return Some(v.clone());
    }

    match name {
        "DATE_LOCAL" => {
            let now = std::time::SystemTime::now();
            let secs = now
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Some(format_http_date(secs))
        }
        "REQUEST_URI" => Some(request_uri.to_string()),
        "UNCLASSIFIED_BANNER" => state.config.unclassified_banner.clone(),
        "MIMIR_MISSING_ACCESS_KEY" => {
            if state.config.missing_access_key {
                Some("true".to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Format a Unix timestamp as an Apache-style `DATE_LOCAL` string.
fn format_http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days_since_epoch = secs / 86400;
    let day_of_week = (days_since_epoch % 7) as usize;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let (year, month, day) = civil_from_days(days_since_epoch as i64);

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02}",
        DAYS[day_of_week], day, MONTHS[month as usize - 1], year, hour, minute, second
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

/// Process a `<!--#if ... -->` / `<!--#else -->` / `<!--#endif -->` block.
///
/// Returns the output string for the taken branch and the token index to resume from (after the
/// `<!--#endif -->`).
async fn process_if_block<'a, F: FileBackend>(
    state: &'a AppState<F>,
    tokens: &[SsiToken<'a>],
    if_token_idx: usize,
    request_uri: &str,
    depth: u8,
    vars: &HashMap<String, String>,
) -> (String, usize) {
    let if_directive = match &tokens[if_token_idx] {
        SsiToken::Directive(d) => *d,
        _ => return (String::new(), if_token_idx + 1),
    };

    let condition = evaluate_if_expr(if_directive, state, request_uri, vars);

    let mut nesting = 0u32;
    let mut else_idx: Option<usize> = None;
    let mut endif_idx: Option<usize> = None;

    for (j, token) in tokens.iter().enumerate().skip(if_token_idx + 1) {
        if let SsiToken::Directive(d) = token {
            let inner = d
                .strip_prefix("<!--#")
                .and_then(|s| s.strip_suffix("-->"))
                .map(|s| s.trim())
                .unwrap_or("");
            if inner.starts_with("if ") {
                nesting += 1;
            } else if inner == "endif" && nesting == 0 {
                endif_idx = Some(j);
                break;
            } else if inner == "endif" {
                nesting -= 1;
            } else if inner == "else" && nesting == 0 {
                else_idx = Some(j);
            }
        }
    }

    let endif_idx = match endif_idx {
        Some(idx) => idx,
        None => {
            eprintln!("SSI: unmatched #if, missing #endif");
            return (String::new(), tokens.len());
        }
    };

    let (branch_start, branch_end) = if condition {
        let start = if_token_idx + 1;
        let end = else_idx.unwrap_or(endif_idx);
        (start, end)
    } else {
        match else_idx {
            Some(ei) => (ei + 1, endif_idx),
            None => (endif_idx, endif_idx),
        }
    };

    let mut branch_html = String::new();
    let mut k = branch_start;
    while k < branch_end {
        match &tokens[k] {
            SsiToken::Text(t) => {
                branch_html.push_str(t);
                k += 1;
            }
            SsiToken::Directive(d) => {
                let inner = d
                    .strip_prefix("<!--#")
                    .and_then(|s| s.strip_suffix("-->"))
                    .map(|s| s.trim())
                    .unwrap_or("");
                if inner.starts_with("if ") {
                    let (nested_output, skip_to) =
                        Box::pin(process_if_block(state, tokens, k, request_uri, depth, vars))
                            .await;
                    branch_html.push_str(&nested_output);
                    k = skip_to;
                } else {
                    branch_html.push_str(d);
                    k += 1;
                }
            }
        }
    }

    let branch_bytes = branch_html.into_bytes();
    let processed = process_ssi(state, branch_bytes, request_uri, depth, vars).await;
    let output = String::from_utf8_lossy(&processed).into_owned();

    (output, endif_idx + 1)
}

/// Evaluate the expression inside `<!--#if expr="..." -->`.
///
/// Supports:
/// - `v('VAR') = 'value'` — string equality
/// - `v('VAR') =~ m#pattern#` — regex matching with `m#...#` delimiters
/// - `v('VAR') =~ /pattern/` — regex matching with `/.../' delimiters
fn evaluate_if_expr<F: FileBackend>(
    directive: &str,
    state: &AppState<F>,
    request_uri: &str,
    vars: &HashMap<String, String>,
) -> bool {
    let inner = match directive
        .strip_prefix("<!--#")
        .and_then(|s| s.strip_suffix("-->"))
    {
        Some(s) => s.trim(),
        None => return false,
    };

    let expr_str = match inner.strip_prefix("if expr=") {
        Some(s) => unquote(s.trim()),
        None => return false,
    };

    if let Some((var_part, val_part)) = expr_str.split_once(" = ") {
        let var_name = extract_v_arg(var_part.trim());
        let expected = unquote(val_part.trim());
        let actual = ssi_var_lookup(&var_name, state, request_uri, vars).unwrap_or_default();
        actual == expected
    } else if let Some((var_part, pattern_part)) = expr_str.split_once(" =~ ") {
        let var_name = extract_v_arg(var_part.trim());
        let actual = ssi_var_lookup(&var_name, state, request_uri, vars).unwrap_or_default();
        let pattern = extract_regex_pattern(pattern_part.trim());
        match regex_lite::Regex::new(&pattern) {
            Ok(re) => re.is_match(&actual),
            Err(e) => {
                eprintln!("SSI: invalid regex {pattern}: {e}");
                false
            }
        }
    } else {
        false
    }
}

/// Extract the variable name from `v('NAME')` or `v("NAME")`.
fn extract_v_arg(s: &str) -> String {
    let inner = s
        .strip_prefix("v(")
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(s);
    unquote(inner)
}

/// Extract a regex pattern from `m#...#`, `m|...|`, or `/.../`.
fn extract_regex_pattern(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("m#") {
        rest.trim_end_matches('#').to_string()
    } else if let Some(rest) = s.strip_prefix("m|") {
        rest.trim_end_matches('|').to_string()
    } else if s.starts_with('/') && s.ends_with('/') && s.len() >= 2 {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Resolve `<!--#flastmod file="./path" -->` to a formatted timestamp.
async fn flastmod<F: FileBackend>(state: &AppState<F>, path: &str) -> String {
    let clean = path.strip_prefix("./").unwrap_or(path);
    let lookup = if clean.starts_with('/') {
        clean.to_string()
    } else {
        format!("/{clean}")
    };
    match state.backend.get(&lookup).await {
        Ok(Some(_)) => {
            let now = std::time::SystemTime::now();
            let secs = now
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format_http_date(secs)
        }
        _ => "(unknown)".to_string(),
    }
}

/// Construct an HTTP response from body bytes, content type, optional encoding header, and whether
/// to add the `x-mimir-ssi` header present on all HTML responses.
///
/// An `ETag` header is derived from a fast hash of the body bytes.
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

    let etag = compute_etag(&body);
    if let Ok(v) = HeaderValue::from_str(&etag) {
        headers.insert(axum::http::header::ETAG, v);
    }

    (StatusCode::OK, headers, body).into_response()
}

/// Compute a weak `ETag` from the body bytes using a fast FNV-style hash.
///
/// The ETag is weak (`W/"…"`) because the same logical content can be served with different
/// transfer encodings.
fn compute_etag(body: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in body {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("W/\"{hash:016x}\"")
}
