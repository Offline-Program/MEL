// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Loading and in-memory representation of the offline PLC product catalog.
//!
//! Two files produced by `mimir-cli` back the product tools (both under the
//! configured product data directory, which points at the shipped zola static
//! `product-life-cycles/api/v1` tree):
//!
//! - `products/index.json` - the full Product Lifecycle catalog. Its records are
//!   a snake_case **superset** of every field the online GraphQL product tools
//!   select, so no live GraphQL call is needed.
//! - `web-products.json` - `web_products_list` (name, `alternateNames`,
//!   categories). Supplies the `search_products` match corpus and the
//!   `list_product_types` categories, which the PLC REST API does not carry.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::product::search::{build_search_index, ProductSearchIndex};

/// Envelope of `products/index.json`: `{ "data": [ ...records ] }`.
#[derive(Debug, Deserialize)]
struct IndexFile {
    /// The product records.
    data: Vec<ProductRecord>,
}

/// One product record from `index.json`. Only the fields the six product tools
/// project are captured; the REST record carries more. All are optional because
/// different record types (operators, layered products, retired products)
/// populate different subsets, and the online tools emit `null` for absentees.
#[derive(Debug, Clone, Deserialize)]
pub struct ProductRecord {
    /// Stable product identifier; the `id` field the tools expose.
    pub uuid: String,
    /// Canonical product name.
    #[serde(default)]
    pub name: Option<String>,
    /// Prior names this product was known by.
    #[serde(default)]
    pub former_names: Option<Vec<String>>,
    /// Whether this product is an operator.
    #[serde(default)]
    pub is_operator: Option<bool>,
    /// Whether this product is a layered product.
    #[serde(default)]
    pub is_layered_product: Option<bool>,
    /// Human-readable release cadence.
    #[serde(default)]
    pub release_cadence: Option<String>,
    /// Package name.
    #[serde(default)]
    pub package: Option<String>,
    /// Canonical lifecycle page link.
    #[serde(default)]
    pub link: Option<String>,
    /// Footnote shown on the lifecycle page.
    #[serde(default)]
    pub footnote: Option<String>,
    /// Whether the lifecycle page shows the final minor release column.
    #[serde(default)]
    pub show_final_minor_release: Option<bool>,
    /// Whether the lifecycle page shows the OpenShift compatibility column.
    #[serde(default)]
    pub show_openshift_compatibility: Option<bool>,
    /// Lifecycle phase glossary entries for this product.
    #[serde(default)]
    pub all_phases: Vec<AllPhase>,
    /// Version/release rows.
    #[serde(default)]
    pub versions: Vec<VersionRecord>,
}

/// A glossary phase from a product's `all_phases`; the source for the derived
/// `list_lifecycle_definitions` tool.
#[derive(Debug, Clone, Deserialize)]
pub struct AllPhase {
    /// Internal phase name.
    #[serde(default)]
    pub name: Option<String>,
    /// Coarse phase type (`normal` / `extended`).
    #[serde(default)]
    pub ptype: Option<String>,
    /// Tooltip text; used as the derived `definition_text`.
    #[serde(default)]
    pub tooltip: Option<String>,
    /// Display label; used as the derived `display_name`.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// A version/release row from a product's `versions`.
#[derive(Debug, Clone, Deserialize)]
pub struct VersionRecord {
    /// Version name, e.g. `"RHEL 9.4"`.
    #[serde(default)]
    pub name: Option<String>,
    /// Support type, e.g. `"Full Support"`. (`type` in the REST record.)
    #[serde(rename = "type", default)]
    pub version_type: Option<String>,
    /// Support tier.
    #[serde(default)]
    pub tier: Option<String>,
    /// Final minor release string.
    #[serde(default)]
    pub final_minor_release: Option<String>,
    /// Last minor release string.
    #[serde(default)]
    pub last_minor_release: Option<String>,
    /// OpenShift compatibility string.
    #[serde(default)]
    pub openshift_compatibility: Option<String>,
    /// Extra dependencies. Note the REST field preserves the upstream
    /// `extra_dependences` misspelling; the tool output corrects it to
    /// `extra_dependencies`.
    #[serde(rename = "extra_dependences", default)]
    pub extra_dependencies: Option<Vec<String>>,
    /// Phase rows for this version.
    #[serde(default)]
    pub phases: Vec<PhaseRecord>,
}

/// A phase row within a version.
#[derive(Debug, Clone, Deserialize)]
pub struct PhaseRecord {
    /// Phase name.
    #[serde(default)]
    pub name: Option<String>,
    /// Phase date (ISO string, or `"N/A"`).
    #[serde(default)]
    pub date: Option<String>,
    /// How `date` should be formatted (`date` / `string`).
    #[serde(default)]
    pub date_format: Option<String>,
}

/// One entry from `web-products.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct WebProduct {
    /// Web product name; the join key against the PLC catalog.
    pub name: String,
    /// Alternate names/aliases; part of the `search_products` corpus.
    #[serde(rename = "alternateNames", default)]
    pub alternate_names: Option<Vec<String>>,
    /// Product categories; the `list_product_types` source.
    #[serde(default)]
    pub categories: Option<Vec<String>>,
}

/// The loaded, in-memory product catalog: records, a uuid index, web products,
/// and the pre-built `search_products` Fuse index.
pub struct ProductCatalog {
    /// Records in file order (the order `list_products` / `get_operators` page).
    products: Vec<ProductRecord>,
    /// uuid -> index into `products`.
    by_uuid: HashMap<String, usize>,
    /// Web products (categories + alternateNames).
    web_products: Vec<WebProduct>,
    /// Pre-built Fuse index + corpus for `search_products`.
    search_index: ProductSearchIndex,
}

impl ProductCatalog {
    /// Loads the catalog from `dir`, expected to contain `products/index.json`
    /// and `web-products.json`.
    ///
    /// Returns `Err` if either file is missing or malformed. Callers should
    /// treat this as fatal at startup (consistent with the Solr health check and
    /// embedding-model load), so the product endpoint never serves partial data.
    pub fn load(dir: &Path) -> Result<Self> {
        let index_path = dir.join("products").join("index.json");
        let index_raw = std::fs::read_to_string(&index_path)
            .with_context(|| format!("reading product catalog {}", index_path.display()))?;
        let index: IndexFile = serde_json::from_str(&index_raw)
            .with_context(|| format!("parsing product catalog {}", index_path.display()))?;

        let web_path = dir.join("web-products.json");
        let web_raw = std::fs::read_to_string(&web_path)
            .with_context(|| format!("reading web products {}", web_path.display()))?;
        let web_products: Vec<WebProduct> = serde_json::from_str(&web_raw)
            .with_context(|| format!("parsing web products {}", web_path.display()))?;

        Ok(Self::from_parts(index.data, web_products))
    }

    /// Assembles a catalog from already-parsed parts, building the uuid index
    /// and the search corpus. Shared by [`load`](Self::load) and tests.
    pub fn from_parts(products: Vec<ProductRecord>, web_products: Vec<WebProduct>) -> Self {
        let by_uuid = products
            .iter()
            .enumerate()
            .map(|(i, p)| (p.uuid.clone(), i))
            .collect();
        let search_index = build_search_index(&products, &web_products);
        Self {
            products,
            by_uuid,
            web_products,
            search_index,
        }
    }

    /// All records, in file order.
    pub fn products(&self) -> &[ProductRecord] {
        &self.products
    }

    /// Looks up a record by its uuid.
    pub fn by_uuid(&self, uuid: &str) -> Option<&ProductRecord> {
        self.by_uuid.get(uuid).map(|&i| &self.products[i])
    }

    /// All web products.
    pub fn web_products(&self) -> &[WebProduct] {
        &self.web_products
    }

    /// The pre-built `search_products` index.
    pub fn search_index(&self) -> &ProductSearchIndex {
        &self.search_index
    }
}
