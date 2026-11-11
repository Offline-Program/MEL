// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Derivation of `list_lifecycle_definitions` from the catalog.
//!
//! The online tool reads a dedicated `product_lifecycle_definitions` subgraph
//! that is not available offline. The PLC catalog does carry the same glossary,
//! spread across each product's `all_phases` (`display_name` + `tooltip`), so we
//! derive the definition set from there.
//!
//! This is an **approximation**: the online `phase_type` is an uppercase enum
//! sourced from the definitions subgraph, while the REST `ptype` is only
//! `normal`/`extended`. We derive `phase_type` from `display_name`
//! (uppercased, spaces -> `_`), which reproduces the common values
//! (`Full support` -> `FULL_SUPPORT`) without the subgraph.

use std::collections::BTreeMap;

use crate::product::catalog::ProductCatalog;
use crate::product::records::{
    LifecycleDefinition, LifecycleDefinitionsResult, ListLifecycleDefinitionsOutput,
};

/// Derives a uppercase phase-type token from a display name:
/// `"Full support"` -> `"FULL_SUPPORT"`. Whitespace runs collapse to a single
/// underscore; leading/trailing whitespace is trimmed.
fn derive_phase_type(display_name: &str) -> String {
    display_name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .to_uppercase()
}

/// Builds the `list_lifecycle_definitions` output by collecting the unique
/// lifecycle phases across all products, keyed by display name and sorted for
/// determinism.
pub fn list_lifecycle_definitions(catalog: &ProductCatalog) -> ListLifecycleDefinitionsOutput {
    // display_name -> definition_text (tooltip). BTreeMap gives a stable,
    // alphabetical order. The first non-null tooltip seen for a display name
    // wins; later products rarely disagree.
    let mut by_display: BTreeMap<String, Option<String>> = BTreeMap::new();

    for product in catalog.products() {
        for phase in &product.all_phases {
            let Some(display_name) = phase.display_name.as_deref() else {
                continue;
            };
            if display_name.trim().is_empty() {
                continue;
            }
            let entry = by_display.entry(display_name.to_owned()).or_insert(None);
            if entry.is_none() {
                if let Some(tooltip) = phase.tooltip.as_deref() {
                    if !tooltip.trim().is_empty() {
                        *entry = Some(tooltip.to_owned());
                    }
                }
            }
        }
    }

    let definitions = by_display
        .into_iter()
        .map(|(display_name, definition_text)| LifecycleDefinition {
            phase_type: Some(derive_phase_type(&display_name)),
            display_name: Some(display_name),
            definition_text,
        })
        .collect();

    ListLifecycleDefinitionsOutput {
        product_lifecycle_definitions: Some(LifecycleDefinitionsResult {
            definitions: Some(definitions),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_phase_type_from_display_name() {
        assert_eq!(derive_phase_type("Full support"), "FULL_SUPPORT");
        assert_eq!(
            derive_phase_type("General availability"),
            "GENERAL_AVAILABILITY"
        );
        assert_eq!(derive_phase_type("End of Life"), "END_OF_LIFE");
        assert_eq!(
            derive_phase_type("  Maintenance   Support "),
            "MAINTENANCE_SUPPORT"
        );
    }
}
