# mimcp — agent guide

`mimcp` is the MCP server library for the Red Hat Offline Knowledge Portal
(RHOKP). It exposes search and lookup tools over a Solr backend to MCP clients —
hybrid and lexical search across Red Hat documentation, CVEs, and errata, plus
by-ID document lookups. This file is the orientation for anyone (human or agent)
working in this crate — read it before making changes so you don't have to
re-derive the architecture.

## How it fits together

- **`mel/src/mcp.rs`** (in the sibling `mel` crate) is the lifecycle glue: it
  boots this library inside the MEL container, waits for Solr to be healthy,
  and serves the router on `127.0.0.1:3001`. Apache reverse-proxies `/mcp`
  there. It is gated behind the `mcp` cargo feature on `mel`.
- **`src/lib.rs`** — `mcp_router()` builds the axum `Router`. Uses `rmcp` with
  the streamable-HTTP transport in **stateless mode** (`with_stateful_mode(false)`,
  `with_json_response(true)`) so the server can sit behind a multi-pod load
  balancer with no session affinity. Only `/mcp` with `ToolSet::Default` is
  mounted today; scoped endpoints (`/mcp/cves`, `/mcp/docs`, …) are written but
  commented out pending coordination.
- **`src/tools.rs`** — the MCP tools: the `Tool` enum, request structs,
  `#[tool]` methods, and `ToolSet` scoping. Most work happens here.
- **`src/solr.rs`** — the Solr HTTP client, typed `fq` filters, and response
  types.
- **`src/embed.rs`** — the ONNX embedding model (granite-embedding-30m,
  384-dim, CLS pooling + L2 norm) that produces the vector for hybrid search.

## Backend model

Everything resolves to a Solr query against the `portal-rag` collection. There
are **two indexes with different schemas**, modeled by the `Index` enum:

- `Portal` — lexical-only (fields like `documentKind`).
- `PortalRag` — the RAG index with chunks and vectors (fields `content_type`,
  `product`, `product_version`, `category`, `is_chunk`, `chunk_vector`). Note
  that `product`/`product_version` exist **only** on this index.

Two kinds of search back the tools:

- **Hybrid** (PortalRag): embeds the query, runs a keyword query first, then
  reranks the top results by vector similarity (`{!rerank}` +
  `{!vectorSimilarity f=chunk_vector}`, see `SolrParams::hybrid`). More relevant
  than lexical; this is the flagship `search` tool.
- **Lexical** (Portal): plain keyword query, no embedding (`SolrParams::lexical`).

Every tool is also one of two **operation shapes**, which determines the helper
it delegates to in `tools.rs`:

- **Search** — query + `rows` → a list of docs. Goes through `run_search`.
- **Get** — an `id` → a single parent doc, matched by a wildcard `doc_id`
  suffix so callers can pass a bare ID (`CVE-2024-1234`) or a full path. Goes
  through `run_get` → `SolrClient::get_by_id`.

## Tool catalog

The `Tool` enum in `tools.rs` is the source of truth. Current tools:

| Tool name           | Op     | Index     | Status                     |
| ------------------- | ------ | --------- | -------------------------- |
| `search`            | search | PortalRag | enabled (the only exposed tool today) |
| `cve_search_portal` | search | Portal    | defined, endpoint not mounted |
| `cve_search_rag`    | search | PortalRag | defined, endpoint not mounted |
| `docs_search`       | search | PortalRag | defined, endpoint not mounted |
| `cve_get_portal`    | get    | Portal    | defined, endpoint not mounted |
| `cve_get_rag`       | get    | PortalRag | defined, endpoint not mounted |

"Defined, endpoint not mounted" means the tool is implemented and wired into a
`ToolSet`, but its only route (e.g. `/mcp/cves`) is commented out in `lib.rs`,
so clients can't reach it yet. `search_lexical` and the errata tools
(`errata_search`, `errata_get`) are stubbed out in comments pending the lexical
Portal index and errata coverage.

`ToolSet` controls which tools an endpoint advertises: `Default` (only `search`,
mounted at `/mcp`), `All`, `Cves`, `Docs`. The per-index filter each tool
applies lives in `impl From<Tool> for SolrFilter` in `solr.rs`.

## Adding or changing a tool

A tool is wired through four seams. Touch all of them or the build fails:

1. **`tools.rs` — `define_tools!` macro.** Add a `Tool` variant → `"tool_name"`
   pair. This macro is the single source of truth for tool identity; the
   variant name must match the `#[tool]` method name.
2. **`tools.rs` — request struct + `#[tool]` method** inside the
   `#[tool_router] impl MimcpServer` block. Delegate to `run_search` /
   `run_get`.
3. **`solr.rs` — `impl From<Tool> for SolrFilter`.** Map the tool to the index
   and `fq` filter it targets (`SolrFilter::Portal(..)` / `PortalRag(..)`).
4. **`tools.rs` — `ToolSet`.** Add the tool to the relevant set(s) so an
   endpoint actually exposes it. Scoping is enforced in **both** `list_tools`
   (hides it) and `call_tool` (rejects it) — update the set, not just one path.

### Guardrails already in place

- **Consistency tests** in `tools.rs` fail the build on a mis-wired tool:
  `tool_names_match_router`, `router_has_no_unknown_tools`,
  `all_toolset_covers_every_enabled_tool`, `toolset_subsets_are_subsets_of_all`.
  Lean on them.
- **Solr injection is handled.** Client-supplied values go through
  `quote_solr_value` (phrase-quote + escape); trusted in-crate constants render
  verbatim. Route any new free-text/client input through the same quoting. See
  `products_filter_escapes_injection_attempt`.

## Products / filtering notes

- A structured `products` filter (product slug + optional versions) already
  exists as a parameter on the hybrid `search` tool: `ProductFilter` →
  `ProductVersions` → `render_products_fq` (products OR-combined, versions
  AND-ed within a product). Reuse this before building new product plumbing.
- `SolrDoc.product` is `Option<Vec<String>>` — a doc can belong to multiple
  products.
- `PortalRagFilter::Category` is defined and tested but not yet wired to any
  tool.
- The `products` filter applies only to PortalRag queries; it is ignored for
  the lexical Portal index (which lacks those fields).

## Testing

- Unit tests live inline in each module (`#[cfg(test)]`); run with `cargo test -p mimcp`.
- **Live-Solr integration tests** are in `tests/solr_integration.rs`, gated
  behind the `real-solr` feature and requiring `SOLR_URL` plus a `../models`
  dir with the ONNX model:
  `SOLR_URL=https://solr.example.com cargo test -p mimcp --features real-solr`.
