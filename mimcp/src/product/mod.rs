// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Offline implementation of the Red Hat product-lifecycle MCP tool surface.
//!
//! The online product MCP server (`mcp_server_for_red_hat_product_information`)
//! is a thin GraphQL proxy. This module reimplements its six live tools
//! (`list_products`, `get_product_by_id`, `get_operators`,
//! `list_lifecycle_definitions`, `list_product_types`, `search_products`) over
//! the PLC catalog extracted offline by `mimir-cli` into static JSON, so clients
//! written against the online server can point at RHOKP unchanged.

pub mod catalog;
pub mod definitions;
pub mod fuse;
pub mod records;
pub mod search;

pub use catalog::ProductCatalog;
