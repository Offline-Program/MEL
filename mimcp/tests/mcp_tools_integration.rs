// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Integration tests that drive a running MCP server over streamable HTTP.
//!
//! These are black-box tests: they speak the MCP protocol to a server that is
//! already listening, exactly as a real client would. Nothing is started for
//! them, so a server must be running and backed by a populated RHOKP index.
//!
//! Gated behind the `live-mcp` feature so a plain `cargo test` stays hermetic:
//!
//!     target/release/mimcp serve --bind 0.0.0.0:8080 &
//!     cargo test -p mimcp --features live-mcp
//!
//! # Configuration
//!
//! Every knob has a default that matches a local `mimcp serve`, so the suite
//! runs with no environment at all. Point it elsewhere by setting:
//!
//! | Variable                 | Default                     | Meaning                              |
//! |--------------------------|-----------------------------|--------------------------------------|
//! | `RHOKP_MCP_URL`          | `http://localhost:8080/mcp` | The default endpoint (hybrid search) |
//! | `RHOKP_MCP_SECURITY_URL` | `{RHOKP_MCP_URL}/security`  | The upstream-parity security surface |
//! | `RHOKP_TEST_CVE`         | `CVE-2014-0160`             | A CVE the index is expected to hold  |
//! | `RHOKP_TEST_ADVISORY`    | `RHSA-2014:0376`            | An advisory fixing `RHOKP_TEST_CVE`  |
//!
//! `RHOKP_MCP_URL` is taken to point directly at an MCP endpoint, so it works
//! equally well against a deployed server:
//!
//!     RHOKP_MCP_URL=https://mimir.corp.redhat.com/mcp \
//!       cargo test -p mimcp --features live-mcp
//!
//! The two seed identifiers default to the Heartbleed CVE and its RHEL 6
//! erratum: old, stable records that any reasonably complete snapshot carries.
//! Override them when testing against a partial index.
//!
//! # Exposed surface
//!
//! This server is the offline implementation of the online Red Hat security
//! MCP server: same interface, different backing store. Two endpoints are
//! mounted, and between them they expose everything that should be callable:
//!
//! - `/mcp` - the hybrid `search` tool, which is ours alone and has no
//!   upstream counterpart.
//! - `/mcp/security` - the seven tools the online server registers, named and
//!   shaped to match so clients written against it work here unchanged.
//!
//! [`SECURITY_TOOLS`] mirrors the online server's `TOOLS` tuple in
//! `app/tools/tools.py`. If upstream adds or renames a tool, that constant and
//! `ToolSet::Security` are what need updating, and
//! [`security_endpoint_matches_the_online_tool_surface`] is the test that will
//! notice the drift.

#![cfg(feature = "live-mcp")]

use rmcp::model::{
    CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
    JsonObject,
};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt};
use serde_json::{json, Value};

/// Tools the default `/mcp` endpoint exposes, per [`ToolSet::Default`].
const DEFAULT_TOOLS: &[&str] = &["search"];

/// Tools the `/mcp/security` endpoint exposes, per `ToolSet::Security`.
///
/// These are exactly the tools the online security MCP server registers, in
/// the order its `TOOLS` tuple lists them. The two surfaces must agree.
const SECURITY_TOOLS: &[&str] = &[
    "search_cves",
    "get_cve_by_id",
    "list_cve_affected_products",
    "search_advisories",
    "get_errata_by_id",
    "list_advisories_by_cve",
    "list_advisory_packages",
];

/// A CVE identifier that is well-formed but should match nothing.
const ABSENT_CVE: &str = "CVE-1999-99999";

/// An advisory identifier that is well-formed but should match nothing.
const ABSENT_ADVISORY: &str = "RHSA-1999:9999";

/// Returns `var` from the environment, or `default` when it is unset or empty.
fn env_or(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
        _ => default.to_owned(),
    }
}

/// URL of the default MCP endpoint.
fn mcp_url() -> String {
    env_or("RHOKP_MCP_URL", "http://localhost:8080/mcp")
}

/// URL of a sub-endpoint of [`mcp_url`], overridable in its own right.
///
/// Deployments that front the endpoints separately can set the override; by
/// default the path is derived from `RHOKP_MCP_URL` the way `mcp_router` nests
/// its routes.
fn sub_url(var: &str, segment: &str) -> String {
    let derived = format!("{}/{segment}", mcp_url().trim_end_matches('/'));
    env_or(var, &derived)
}

/// URL of the upstream-parity security endpoint.
fn security_url() -> String {
    sub_url("RHOKP_MCP_SECURITY_URL", "security")
}

/// A CVE the index under test is expected to hold.
fn seed_cve() -> String {
    env_or("RHOKP_TEST_CVE", "CVE-2014-0160")
}

/// An advisory the index under test is expected to hold, fixing [`seed_cve`].
fn seed_advisory() -> String {
    env_or("RHOKP_TEST_ADVISORY", "RHSA-2014:0376")
}

/// Connects an MCP client to `url`.
///
/// Panics with the URL and the variable that sets it when the server is not
/// reachable, since every test in this file depends on the connection.
async fn connect(url: &str) -> RunningService<RoleClient, ClientInfo> {
    let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url.to_owned());
    let client_info = ClientInfo::new(
        ClientCapabilities::default(),
        Implementation::new("mimcp-integration-tests", env!("CARGO_PKG_VERSION")),
    );

    client_info.serve(transport).await.unwrap_or_else(|e| {
        panic!(
            "could not connect to the MCP server at {url}: {e}\n\
             Start one with `mimcp serve --bind 0.0.0.0:8080`, or set RHOKP_MCP_URL \
             to point at a running server."
        )
    })
}

/// Connects to the default endpoint.
async fn default_client() -> RunningService<RoleClient, ClientInfo> {
    connect(&mcp_url()).await
}

/// Connects to the security endpoint.
async fn security_client() -> RunningService<RoleClient, ClientInfo> {
    connect(&security_url()).await
}

/// Converts a `json!` object into tool-call arguments.
///
/// Panics if `value` is not a JSON object, which would be a bug in the test.
fn args(value: Value) -> JsonObject {
    value
        .as_object()
        .expect("tool arguments must be a JSON object")
        .clone()
}

/// Calls `tool` with `arguments`, returning the structured result payload.
///
/// Panics if the call fails; use [`call_expecting_error`] for the negative
/// cases.
async fn call(
    client: &RunningService<RoleClient, ClientInfo>,
    tool: &'static str,
    arguments: Value,
) -> Value {
    let result = client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(args(arguments)))
        .await
        .unwrap_or_else(|e| panic!("{tool} should succeed, got transport/protocol error: {e}"));

    assert_ne!(
        result.is_error,
        Some(true),
        "{tool} should not report a tool error, got {:?}",
        result.content
    );

    payload(&result, tool)
}

/// Calls `tool` expecting it to be rejected, returning the error message.
///
/// MCP surfaces a tool's `Err(ErrorData)` as a protocol error rather than a
/// successful result, so both shapes are accepted and reduced to a string.
async fn call_expecting_error(
    client: &RunningService<RoleClient, ClientInfo>,
    tool: &'static str,
    arguments: Value,
) -> String {
    match client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(args(arguments)))
        .await
    {
        Err(e) => e.to_string(),
        Ok(result) if result.is_error == Some(true) => format!("{:?}", result.content),
        Ok(result) => panic!("{tool} should have been rejected, got {result:?}"),
    }
}

/// Extracts a tool result's JSON payload.
///
/// Tools return `Json<T>`, which rmcp sends as `structuredContent`; the text
/// block is accepted as a fallback so the helper keeps working if a tool is
/// ever changed to return plain content.
fn payload(result: &CallToolResult, tool: &str) -> Value {
    if let Some(structured) = &result.structured_content {
        return structured.clone();
    }

    let text = result
        .content
        .iter()
        .find_map(|block| block.as_text().map(|t| t.text.clone()))
        .unwrap_or_else(|| panic!("{tool} returned neither structuredContent nor text content"));

    serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{tool} text content should be valid JSON: {e}\n{text}"))
}

/// Returns the names of the tools `client`'s endpoint exposes, sorted.
async fn tool_names(client: &RunningService<RoleClient, ClientInfo>) -> Vec<String> {
    let mut names: Vec<String> = client
        .list_all_tools()
        .await
        .expect("list_tools should succeed")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    names
}

/// Reads `pointer` out of `value`, panicking with context when it is absent.
fn at<'v>(value: &'v Value, pointer: &str) -> &'v Value {
    value.pointer(pointer).unwrap_or_else(|| {
        panic!(
            "expected {pointer} in response: {}",
            serde_json::to_string_pretty(value).unwrap_or_default()
        )
    })
}

/// Reads `pointer` as an array, panicking when it is absent or another type.
fn array<'v>(value: &'v Value, pointer: &str) -> &'v Vec<Value> {
    at(value, pointer)
        .as_array()
        .unwrap_or_else(|| panic!("{pointer} should be an array"))
}

// ---------------------------------------------------------------------------
// Endpoint surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn default_endpoint_exposes_only_the_hybrid_search_tool() {
    let client = default_client().await;

    let mut expected: Vec<String> = DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect();
    expected.sort();

    assert_eq!(
        tool_names(&client).await,
        expected,
        "the default endpoint should expose exactly ToolSet::Default"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn security_endpoint_matches_the_online_tool_surface() {
    let client = security_client().await;

    let mut expected: Vec<String> = SECURITY_TOOLS.iter().map(|s| s.to_string()).collect();
    expected.sort();

    // Exact equality in both directions: a missing tool breaks clients written
    // against the online server, and an extra one is a surface we never agreed
    // to support.
    assert_eq!(
        tool_names(&client).await,
        expected,
        "the security endpoint should expose exactly the online server's seven tools"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn no_tool_outside_the_agreed_surface_is_exposed_anywhere() {
    // The hybrid `search` tool plus the online server's seven. Anything else
    // reaching a client - a work-in-progress tool, a route left uncommented -
    // is a regression, whichever endpoint it shows up on.
    let mut agreed: Vec<&str> = DEFAULT_TOOLS
        .iter()
        .chain(SECURITY_TOOLS)
        .copied()
        .collect();
    agreed.sort_unstable();

    for url in [mcp_url(), security_url()] {
        let client = connect(&url).await;

        for name in tool_names(&client).await {
            assert!(
                agreed.contains(&name.as_str()),
                "{url} exposes {name}, which is outside the agreed surface {agreed:?}"
            );
        }

        client.cancel().await.ok();
    }
}

#[tokio::test]
async fn every_exposed_tool_is_described_and_schematized() {
    for url in [mcp_url(), security_url()] {
        let client = connect(&url).await;
        let tools = client
            .list_all_tools()
            .await
            .expect("list_tools should succeed");

        assert!(!tools.is_empty(), "{url} should expose at least one tool");

        for tool in tools {
            assert!(
                tool.description.as_deref().is_some_and(|d| !d.is_empty()),
                "tool {} on {url} should carry a non-empty description",
                tool.name
            );
            assert_eq!(
                tool.input_schema.get("type").and_then(Value::as_str),
                Some("object"),
                "tool {} on {url} should declare an object input schema",
                tool.name
            );
        }

        client.cancel().await.ok();
    }
}

#[tokio::test]
async fn endpoints_reject_tools_they_do_not_expose() {
    // list_tools hides out-of-set tools; call_tool must refuse them too, or the
    // endpoint scoping in MimcpServer::call_tool would be cosmetic.
    let client = default_client().await;
    let message = call_expecting_error(
        &client,
        "search_cves",
        json!({ "input": { "query": "*:*" } }),
    )
    .await;
    assert!(
        message.contains("not available on this endpoint"),
        "the default endpoint should refuse search_cves, got: {message}"
    );
    client.cancel().await.ok();

    let client = security_client().await;
    let message = call_expecting_error(&client, "search", json!({ "query": "kernel" })).await;
    assert!(
        message.contains("not available on this endpoint"),
        "the security endpoint should refuse search, got: {message}"
    );
    client.cancel().await.ok();
}

#[tokio::test]
async fn unknown_tool_names_are_rejected() {
    let client = default_client().await;
    let message = call_expecting_error(&client, "no_such_tool", json!({})).await;
    assert!(
        !message.is_empty(),
        "an unknown tool name should produce an error message"
    );
    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// search (hybrid) - /mcp
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_returns_documents_for_a_broad_query() {
    let client = default_client().await;

    let result = call(
        &client,
        "search",
        json!({ "query": "kernel security vulnerability", "rows": 5 }),
    )
    .await;

    let docs = array(&result, "/response/docs");
    assert!(
        !docs.is_empty(),
        "a broad query should match something in a populated index"
    );
    assert!(
        docs.len() <= 5,
        "search should return at most the requested 5 rows, got {}",
        docs.len()
    );
    assert!(
        at(&result, "/response/numFound").as_u64().is_some(),
        "search should report numFound"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_clamps_rows_to_the_maximum() {
    let client = default_client().await;

    // MAX_ROWS in tools.rs is 20; asking for more must not return more.
    let result = call(
        &client,
        "search",
        json!({ "query": "openshift installation", "rows": 500 }),
    )
    .await;

    assert!(
        array(&result, "/response/docs").len() <= 20,
        "search should clamp rows to MAX_ROWS (20)"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_product_filter_restricts_results() {
    let client = default_client().await;

    let result = call(
        &client,
        "search",
        json!({
            "query": "cluster installation",
            "rows": 10,
            "products": [{ "product": "openshift_container_platform" }],
        }),
    )
    .await;

    for doc in array(&result, "/response/docs") {
        let products = doc
            .get("product")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("filtered result should carry a product field: {doc}"));
        assert!(
            products
                .iter()
                .any(|p| p.as_str() == Some("openshift_container_platform")),
            "every filtered result must include openshift_container_platform, got {products:?}"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_product_and_version_filter_restricts_results() {
    let client = default_client().await;

    let result = call(
        &client,
        "search",
        json!({
            "query": "cluster installation",
            "rows": 10,
            "products": [{
                "product": "openshift_container_platform",
                "versions": ["4.20"],
            }],
        }),
    )
    .await;

    for doc in array(&result, "/response/docs") {
        assert_eq!(
            doc.get("product_version").and_then(Value::as_str),
            Some("4.20"),
            "every result must be version 4.20, got {doc}"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_tolerates_a_query_that_matches_nothing() {
    let client = default_client().await;

    // Zero matches is a successful response, not an error.
    let result = call(
        &client,
        "search",
        json!({ "query": "zzqqxx-no-such-term-zzqqxx", "rows": 5 }),
    )
    .await;

    assert!(
        at(&result, "/response/numFound").as_u64().is_some(),
        "an empty result set should still report numFound"
    );

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// search_cves - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_cves_returns_metadata_and_summary_rows() {
    let client = security_client().await;

    let result = call(
        &client,
        "search_cves",
        json!({ "input": { "query": "openssl", "pagination": { "rows": 5 } } }),
    )
    .await;

    let total = at(&result, "/cves/metadata/total")
        .as_u64()
        .expect("metadata.total should be a number");
    assert_eq!(
        at(&result, "/cves/metadata/start").as_u64(),
        Some(0),
        "metadata.start should echo the requested offset"
    );

    let rows = array(&result, "/cves/cve");
    assert!(
        rows.len() <= 5,
        "search_cves should honour pagination.rows, got {}",
        rows.len()
    );
    if total > 0 {
        assert!(
            !rows.is_empty(),
            "a non-zero total should come with at least one row"
        );
        assert!(
            rows[0].get("cve_id").and_then(Value::as_str).is_some(),
            "each summary row should carry a cve_id: {}",
            rows[0]
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_accepts_input_as_a_json_string() {
    let client = security_client().await;

    // RawSearchInput accepts the serialized form some clients send.
    let result = call(
        &client,
        "search_cves",
        json!({ "input": "{\"query\":\"openssl\",\"pagination\":{\"rows\":3}}" }),
    )
    .await;

    assert!(
        array(&result, "/cves/cve").len() <= 3,
        "the string form should be parsed and its pagination honoured"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_match_all_query_with_severity_filter() {
    let client = security_client().await;

    let result = call(
        &client,
        "search_cves",
        json!({
            "input": {
                "query": "*:*",
                "pagination": { "rows": 10 },
                "filter": { "filterQuery": "cve_threatSeverity:Critical" },
            }
        }),
    )
    .await;

    for row in array(&result, "/cves/cve") {
        assert_eq!(
            row.get("severity").and_then(Value::as_str),
            Some("Critical"),
            "every row must be Critical under that filter, got {row}"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_lowercase_severity_is_corrected() {
    let client = security_client().await;

    // The index stores capitalized severities; the server fixes the casing so a
    // lowercase clause does not silently match nothing.
    let lower = call(
        &client,
        "search_cves",
        json!({
            "input": {
                "query": "*:*",
                "pagination": { "rows": 1 },
                "filter": { "filterQuery": "cve_threatSeverity:critical" },
            }
        }),
    )
    .await;
    let upper = call(
        &client,
        "search_cves",
        json!({
            "input": {
                "query": "*:*",
                "pagination": { "rows": 1 },
                "filter": { "filterQuery": "cve_threatSeverity:Critical" },
            }
        }),
    )
    .await;

    assert_eq!(
        at(&lower, "/cves/metadata/total"),
        at(&upper, "/cves/metadata/total"),
        "lowercase and capitalized severity filters should match the same CVEs"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_pagination_advances_the_window() {
    let client = security_client().await;

    let first = call(
        &client,
        "search_cves",
        json!({ "input": { "query": "*:*", "pagination": { "rows": 1, "start": 0 } } }),
    )
    .await;
    let second = call(
        &client,
        "search_cves",
        json!({ "input": { "query": "*:*", "pagination": { "rows": 1, "start": 1 } } }),
    )
    .await;

    assert_eq!(
        at(&second, "/cves/metadata/start").as_u64(),
        Some(1),
        "metadata.start should reflect the requested offset"
    );

    let (first_rows, second_rows) = (array(&first, "/cves/cve"), array(&second, "/cves/cve"));
    if !first_rows.is_empty() && !second_rows.is_empty() {
        assert_ne!(
            first_rows[0].get("cve_id"),
            second_rows[0].get("cve_id"),
            "consecutive pages should not return the same CVE"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_rejects_solr_local_parameters() {
    let client = security_client().await;

    // Local params could switch query parsers; they are outside the contract.
    let message = call_expecting_error(
        &client,
        "search_cves",
        json!({
            "input": {
                "query": "*:*",
                "filter": { "filterQuery": "{!join from=a to=b}cve_threatSeverity:Low" },
            }
        }),
    )
    .await;

    assert!(
        message.contains("local parameters"),
        "a local-param clause should be refused, got: {message}"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_rejects_an_unsupported_sort_field() {
    let client = security_client().await;

    let message = call_expecting_error(
        &client,
        "search_cves",
        json!({ "input": { "query": "*:*", "sort": { "sortOrder": "not_a_field desc" } } }),
    )
    .await;

    assert!(
        !message.is_empty(),
        "an unsupported sort field should be refused"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_cves_rejects_input_that_is_not_json() {
    let client = security_client().await;

    let message = call_expecting_error(
        &client,
        "search_cves",
        json!({ "input": "not json at all" }),
    )
    .await;

    assert!(
        message.contains("valid JSON") || message.contains("search input"),
        "an unparseable input string should be refused, got: {message}"
    );

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// get_cve_by_id - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_cve_by_id_returns_the_requested_record() {
    let client = security_client().await;
    let cve_id = seed_cve();

    let result = call(&client, "get_cve_by_id", json!({ "cve_id": cve_id })).await;

    let cve = at(&result, "/cve");
    assert!(
        !cve.is_null(),
        "{cve_id} should exist in the index under test; set RHOKP_TEST_CVE to a \
         CVE this index holds if it does not"
    );
    assert_eq!(
        cve.get("cve_id").and_then(Value::as_str),
        Some(cve_id.as_str()),
        "the returned record should be the requested CVE"
    );
    assert!(
        cve.get("description")
            .and_then(Value::as_str)
            .is_some_and(|d| !d.is_empty()),
        "the CVE record should carry a description"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_cve_by_id_is_case_insensitive() {
    let client = security_client().await;
    let cve_id = seed_cve();

    let result = call(
        &client,
        "get_cve_by_id",
        json!({ "cve_id": cve_id.to_lowercase() }),
    )
    .await;

    assert_eq!(
        at(&result, "/cve").get("cve_id").and_then(Value::as_str),
        Some(cve_id.as_str()),
        "a lowercase identifier should be normalized before lookup"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_cve_by_id_returns_null_for_an_absent_cve() {
    let client = security_client().await;

    let result = call(&client, "get_cve_by_id", json!({ "cve_id": ABSENT_CVE })).await;

    assert!(
        at(&result, "/cve").is_null(),
        "a well-formed but unknown CVE should yield a null record, not an error"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_cve_by_id_rejects_a_malformed_identifier() {
    let client = security_client().await;

    for bad in ["not-a-cve", "CVE-24-1234", "CVE-2024", "CVE-9999-1234"] {
        let message =
            call_expecting_error(&client, "get_cve_by_id", json!({ "cve_id": bad })).await;
        assert!(
            message.contains("cve_id"),
            "{bad} should be refused with a cve_id message, got: {message}"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_cve_by_id_paginates_affected_products() {
    let client = security_client().await;
    let cve_id = seed_cve();

    let full = call(
        &client,
        "get_cve_by_id",
        json!({ "cve_id": cve_id, "affected_products_limit": 100 }),
    )
    .await;

    let total = at(&full, "/cve/affected_products")
        .as_array()
        .map_or(0, Vec::len);
    if total < 2 {
        // Nothing to page through; the unpaginated assertions above cover this
        // CVE, and a different seed would be needed to exercise paging.
        client.cancel().await.ok();
        return;
    }

    let page_one = call(
        &client,
        "get_cve_by_id",
        json!({ "cve_id": cve_id, "affected_products_limit": 1, "affected_products_page": 1 }),
    )
    .await;
    let page_two = call(
        &client,
        "get_cve_by_id",
        json!({ "cve_id": cve_id, "affected_products_limit": 1, "affected_products_page": 2 }),
    )
    .await;

    assert_eq!(
        array(&page_one, "/cve/affected_products").len(),
        1,
        "a limit of 1 should return a single affected product"
    );
    assert_ne!(
        array(&page_one, "/cve/affected_products")[0],
        array(&page_two, "/cve/affected_products")[0],
        "consecutive affected-product pages should differ"
    );

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// list_cve_affected_products - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_cve_affected_products_returns_the_cve_with_its_products() {
    let client = security_client().await;
    let cve_id = seed_cve();

    let result = call(
        &client,
        "list_cve_affected_products",
        json!({ "cve_id": cve_id }),
    )
    .await;

    let cve = at(&result, "/cve_with_affected_products");
    assert!(
        !cve.is_null(),
        "{cve_id} should exist in the index under test"
    );
    assert_eq!(
        cve.get("cve_id").and_then(Value::as_str),
        Some(cve_id.as_str()),
        "the record should be the requested CVE"
    );
    assert!(
        cve.get("affected_products").is_some(),
        "the record should carry an affected_products key, even when empty: {cve}"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_cve_affected_products_returns_null_for_an_absent_cve() {
    let client = security_client().await;

    let result = call(
        &client,
        "list_cve_affected_products",
        json!({ "cve_id": ABSENT_CVE }),
    )
    .await;

    assert!(
        at(&result, "/cve_with_affected_products").is_null(),
        "an unknown CVE should yield a null record, not an error"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_cve_affected_products_rejects_a_malformed_identifier() {
    let client = security_client().await;

    let message = call_expecting_error(
        &client,
        "list_cve_affected_products",
        json!({ "cve_id": "nonsense" }),
    )
    .await;

    assert!(
        message.contains("cve_id"),
        "a malformed identifier should be refused, got: {message}"
    );

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// search_advisories - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_advisories_returns_metadata_and_summary_rows() {
    let client = security_client().await;

    let result = call(
        &client,
        "search_advisories",
        json!({ "input": { "query": "kernel", "pagination": { "rows": 5 } } }),
    )
    .await;

    let total = at(&result, "/advisories/metadata/total")
        .as_u64()
        .expect("metadata.total should be a number");

    let rows = array(&result, "/advisories/advisory");
    assert!(
        rows.len() <= 5,
        "search_advisories should honour pagination.rows, got {}",
        rows.len()
    );
    if total > 0 {
        assert!(
            !rows.is_empty(),
            "a non-zero total should come with at least one row"
        );
        assert!(
            rows[0].get("id").and_then(Value::as_str).is_some(),
            "each summary row should carry an id: {}",
            rows[0]
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_advisories_filters_by_advisory_type() {
    let client = security_client().await;

    let result = call(
        &client,
        "search_advisories",
        json!({
            "input": {
                "query": "*:*",
                "pagination": { "rows": 10 },
                "filter": { "filterQueries": ["portal_advisory_type:\"Security Advisory\""] },
            }
        }),
    )
    .await;

    for row in array(&result, "/advisories/advisory") {
        assert_eq!(
            row.get("type").and_then(Value::as_str),
            Some("Security Advisory"),
            "every row must be a Security Advisory under that filter, got {row}"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_advisories_pagination_advances_the_window() {
    let client = security_client().await;

    let first = call(
        &client,
        "search_advisories",
        json!({ "input": { "query": "*:*", "pagination": { "rows": 1, "start": 0 } } }),
    )
    .await;
    let second = call(
        &client,
        "search_advisories",
        json!({ "input": { "query": "*:*", "pagination": { "rows": 1, "start": 1 } } }),
    )
    .await;

    let (first_rows, second_rows) = (
        array(&first, "/advisories/advisory"),
        array(&second, "/advisories/advisory"),
    );
    if !first_rows.is_empty() && !second_rows.is_empty() {
        assert_ne!(
            first_rows[0].get("id"),
            second_rows[0].get("id"),
            "consecutive pages should not return the same advisory"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn search_advisories_rejects_solr_local_parameters() {
    let client = security_client().await;

    let message = call_expecting_error(
        &client,
        "search_advisories",
        json!({
            "input": {
                "query": "*:*",
                "filter": { "filterQueries": ["{!terms f=id}RHSA-2024:0001"] },
            }
        }),
    )
    .await;

    assert!(
        message.contains("local parameters"),
        "a local-param clause should be refused, got: {message}"
    );

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// get_errata_by_id - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_errata_by_id_returns_a_single_advisory() {
    let client = security_client().await;
    let advisory_id = seed_advisory();

    let result = call(
        &client,
        "get_errata_by_id",
        json!({ "advisory_id": advisory_id }),
    )
    .await;

    assert_eq!(
        at(&result, "/erratum/metadata/total_record_count").as_u64(),
        Some(1),
        "{advisory_id} should resolve to exactly one record; set RHOKP_TEST_ADVISORY \
         to an advisory this index holds if it does not"
    );

    let advisories = array(&result, "/erratum/advisory");
    assert_eq!(
        advisories.len(),
        1,
        "exact-ID lookup returns at most one row"
    );
    assert_eq!(
        advisories[0].get("advisory_id").and_then(Value::as_str),
        Some(advisory_id.as_str()),
        "the returned record should be the requested advisory"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_errata_by_id_accepts_a_dash_separator() {
    let client = security_client().await;
    let advisory_id = seed_advisory();

    // Upstream accepts RHSA-2024-1234 as well as RHSA-2024:1234.
    let result = call(
        &client,
        "get_errata_by_id",
        json!({ "advisory_id": advisory_id.replace(':', "-") }),
    )
    .await;

    assert_eq!(
        array(&result, "/erratum/advisory")
            .first()
            .and_then(|a| a.get("advisory_id"))
            .and_then(Value::as_str),
        Some(advisory_id.as_str()),
        "the dash form should normalize to the colon form"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_errata_by_id_returns_empty_for_an_absent_advisory() {
    let client = security_client().await;

    let result = call(
        &client,
        "get_errata_by_id",
        json!({ "advisory_id": ABSENT_ADVISORY }),
    )
    .await;

    assert_eq!(
        at(&result, "/erratum/metadata/total_record_count").as_u64(),
        Some(0),
        "an unknown advisory should report zero records"
    );
    assert!(
        array(&result, "/erratum/advisory").is_empty(),
        "an unknown advisory should return an empty list, not an error"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn get_errata_by_id_rejects_a_malformed_identifier() {
    let client = security_client().await;

    for bad in ["nonsense", "RHXX-2024:1234", "RHSA-24:1234"] {
        let message =
            call_expecting_error(&client, "get_errata_by_id", json!({ "advisory_id": bad })).await;
        assert!(
            message.contains("advisory_id"),
            "{bad} should be refused with an advisory_id message, got: {message}"
        );
    }

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// list_advisories_by_cve - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_advisories_by_cve_returns_linked_advisories() {
    let client = security_client().await;
    let cve_id = seed_cve();

    let result = call(
        &client,
        "list_advisories_by_cve",
        json!({ "cve_id": cve_id }),
    )
    .await;

    // The `advisoires` key is misspelled upstream and reproduced verbatim.
    let advisories = array(&result, "/advisoires/advisory");
    assert!(
        !advisories.is_empty(),
        "{cve_id} should have at least one linked advisory in the index under test"
    );

    for advisory in advisories {
        assert!(
            advisory.get("id").and_then(Value::as_str).is_some(),
            "each linked advisory should carry an id: {advisory}"
        );
    }

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisories_by_cve_includes_the_seed_advisory() {
    let client = security_client().await;
    let (cve_id, advisory_id) = (seed_cve(), seed_advisory());

    let result = call(
        &client,
        "list_advisories_by_cve",
        json!({ "cve_id": cve_id }),
    )
    .await;

    let ids: Vec<&str> = array(&result, "/advisoires/advisory")
        .iter()
        .filter_map(|a| a.get("id").and_then(Value::as_str))
        .collect();

    assert!(
        ids.contains(&advisory_id.as_str()),
        "{advisory_id} fixes {cve_id}, so it should appear among {ids:?}"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisories_by_cve_returns_empty_for_an_absent_cve() {
    let client = security_client().await;

    let result = call(
        &client,
        "list_advisories_by_cve",
        json!({ "cve_id": ABSENT_CVE }),
    )
    .await;

    assert!(
        array(&result, "/advisoires/advisory").is_empty(),
        "an unknown CVE should return an empty list, not an error"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisories_by_cve_rejects_a_malformed_identifier() {
    let client = security_client().await;

    let message = call_expecting_error(
        &client,
        "list_advisories_by_cve",
        json!({ "cve_id": "nonsense" }),
    )
    .await;

    assert!(
        message.contains("cve_id"),
        "a malformed identifier should be refused, got: {message}"
    );

    client.cancel().await.ok();
}

// ---------------------------------------------------------------------------
// list_advisory_packages - /mcp/security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_advisory_packages_returns_a_page_with_metadata() {
    let client = security_client().await;
    let advisory_id = seed_advisory();

    let result = call(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": advisory_id }),
    )
    .await;

    let packages = array(&result, "/advisory/packages");
    assert!(
        !packages.is_empty(),
        "{advisory_id} should ship at least one package in the index under test"
    );
    assert_eq!(
        at(&result, "/advisory/pagination/count").as_u64(),
        Some(packages.len() as u64),
        "pagination.count should match the number of rows returned"
    );
    assert_eq!(
        at(&result, "/advisory/pagination/offset").as_u64(),
        Some(0),
        "the default offset should be 0"
    );
    // Pins our default rather than upstream's: the online server documents a
    // default of 10 for `limit`. If that divergence is ever resolved in favour
    // of parity, this is the assertion that will need updating.
    assert_eq!(
        at(&result, "/advisory/pagination/max_limit").as_u64(),
        Some(50),
        "the default limit should be 50"
    );

    let package = &packages[0];
    assert!(
        package.get("name").and_then(Value::as_str).is_some(),
        "each package row should carry a name: {package}"
    );
    assert!(
        package.get("architecture").is_some(),
        "each package row should carry an architecture key: {package}"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisory_packages_respects_limit_and_offset() {
    let client = security_client().await;
    let advisory_id = seed_advisory();

    let all = call(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": advisory_id, "limit": 100 }),
    )
    .await;

    if array(&all, "/advisory/packages").len() < 2 {
        // Single-package advisory: nothing to page through.
        client.cancel().await.ok();
        return;
    }

    let first = call(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": advisory_id, "limit": 1, "offset": 0 }),
    )
    .await;
    let second = call(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": advisory_id, "limit": 1, "offset": 1 }),
    )
    .await;

    assert_eq!(
        array(&first, "/advisory/packages").len(),
        1,
        "a limit of 1 should return a single package"
    );
    assert_eq!(
        at(&second, "/advisory/pagination/offset").as_u64(),
        Some(1),
        "pagination.offset should echo the request"
    );
    assert_ne!(
        array(&first, "/advisory/packages")[0],
        array(&second, "/advisory/packages")[0],
        "consecutive package pages should differ"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisory_packages_past_the_end_returns_an_empty_page() {
    let client = security_client().await;

    let result = call(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": seed_advisory(), "limit": 10, "offset": 100_000 }),
    )
    .await;

    assert!(
        array(&result, "/advisory/packages").is_empty(),
        "an offset past the end should return an empty page, not an error"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisory_packages_returns_empty_for_an_absent_advisory() {
    let client = security_client().await;

    let result = call(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": ABSENT_ADVISORY }),
    )
    .await;

    assert!(
        array(&result, "/advisory/packages").is_empty(),
        "an unknown advisory should return an empty package list, not an error"
    );

    client.cancel().await.ok();
}

#[tokio::test]
async fn list_advisory_packages_rejects_a_malformed_identifier() {
    let client = security_client().await;

    let message = call_expecting_error(
        &client,
        "list_advisory_packages",
        json!({ "advisory_id": "nonsense" }),
    )
    .await;

    assert!(
        message.contains("advisory_id"),
        "a malformed identifier should be refused, got: {message}"
    );

    client.cancel().await.ok();
}
