// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Output structs for the product tools and the projections that build them
//! from [`ProductRecord`]s.
//!
//! The online tools share one set of Pydantic models (`PlcProductSummary`,
//! `ProductVersionSummary`, `ProductPhase`) with every field optional and
//! `extra="allow"`; each tool's GraphQL query selects a different subset, and the
//! JSON dump emits the full model shape with `null` for fields that query did not
//! populate. We reproduce that exactly: one shared struct set, and per-tool
//! projections that set only the fields the corresponding query selected, leaving
//! the rest `None` (serialized as `null`, matching the crate's existing records).

use schemars::JsonSchema;
use serde::Serialize;

use crate::product::catalog::{ProductRecord, VersionRecord};

/// A product summary. Mirrors the upstream `PlcProductSummary` model: every
/// field optional, serialized with `null` when unset. Field order follows the
/// upstream model.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PlcProductSummary {
    /// Product uuid (`id` upstream).
    pub id: Option<String>,
    /// Canonical product name.
    pub name: Option<String>,
    /// OPL uuid. Absent from the PLC REST data (GraphQL-only), so always `null`.
    pub opl_uuid: Option<String>,
    /// Prior product names.
    pub former_names: Option<Vec<String>>,
    /// Whether the product is an operator.
    pub is_operator: Option<bool>,
    /// Whether the product is a layered product.
    pub is_layered_product: Option<bool>,
    /// Release cadence.
    pub release_cadence: Option<String>,
    /// Package name.
    pub package: Option<String>,
    /// Lifecycle page link.
    pub link: Option<String>,
    /// Footnote.
    pub footnote: Option<String>,
    /// Whether the final-minor-release column is shown.
    pub show_final_minor_release: Option<bool>,
    /// Whether the OpenShift-compatibility column is shown.
    pub show_openshift_compatibility: Option<bool>,
    /// Version rows.
    pub versions: Option<Vec<ProductVersionSummary>>,
}

/// A version summary. Mirrors upstream `ProductVersionSummary`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ProductVersionSummary {
    /// Version name (used by `list_products` / `get_operators`).
    pub name: Option<String>,
    /// Version name under the `version` key (used by `get_product_by_id`).
    pub version: Option<String>,
    /// Support type.
    #[serde(rename = "type")]
    pub version_type: Option<String>,
    /// Support tier.
    pub tier: Option<String>,
    /// Phase rows.
    pub phases: Option<Vec<ProductPhase>>,
    /// Final minor release.
    pub final_minor_release: Option<String>,
    /// Last minor release.
    pub last_minor_release: Option<String>,
    /// OpenShift compatibility.
    pub openshift_compatibility: Option<String>,
    /// Extra dependencies (corrected spelling of the REST `extra_dependences`).
    pub extra_dependencies: Option<Vec<String>>,
}

/// A phase within a version. Mirrors upstream `ProductPhase`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ProductPhase {
    /// Phase name.
    pub name: Option<String>,
    /// Phase date.
    pub date: Option<String>,
    /// Date format.
    pub date_format: Option<String>,
    /// Display name (unset by the version-phase queries).
    pub display_name: Option<String>,
    /// Phase type (unset by the version-phase queries).
    pub ptype: Option<String>,
}

/// `list_products` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListProductsOutput {
    /// Matching products.
    pub plc_products: Option<Vec<PlcProductSummary>>,
}

/// `get_product_by_id` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GetProductByIdOutput {
    /// The product, or `null` when no uuid matches.
    pub plc_product: Option<PlcProductSummary>,
}

/// `get_operators` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GetOperatorsOutput {
    /// The products (the first N, unfiltered - see the tool doc).
    pub plc_products: Option<Vec<PlcProductSummary>>,
}

/// One ranked hit from `search_products`. Mirrors upstream `SearchProductHit`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchProductHit {
    /// Product uuid.
    pub id: Option<String>,
    /// Canonical product name.
    pub name: Option<String>,
    /// Prior product names.
    pub former_names: Option<Vec<String>>,
    /// Relevance in `[0, 1]`; 1.0 for exact/known-ID hits.
    pub relevance_score: Option<f64>,
    /// Low-relevance caveat, present only when `relevance_score <= 0.9`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `search_products` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SearchProductsOutput {
    /// Ranked matches, best first.
    pub products: Vec<SearchProductHit>,
}

/// One derived lifecycle definition. Mirrors upstream `LifecycleDefinition`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LifecycleDefinition {
    /// Derived uppercase phase type (e.g. `FULL_SUPPORT`).
    pub phase_type: Option<String>,
    /// Display name.
    pub display_name: Option<String>,
    /// Definition text (derived from the phase tooltip).
    pub definition_text: Option<String>,
}

/// Inner result object for `list_lifecycle_definitions`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct LifecycleDefinitionsResult {
    /// The definitions.
    pub definitions: Option<Vec<LifecycleDefinition>>,
}

/// `list_lifecycle_definitions` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListLifecycleDefinitionsOutput {
    /// The definitions result.
    pub product_lifecycle_definitions: Option<LifecycleDefinitionsResult>,
}

/// `list_product_types` output.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListProductTypesOutput {
    /// Sorted, unique product categories.
    pub product_types: Vec<String>,
}

/// Projects a record for `list_products` (GraphQL `list_products.graphql`).
///
/// Selected: id, name, opl_uuid (always null), former_names, is_operator,
/// release_cadence, package, link; versions `{ name, phases{date,name}, type,
/// tier }`.
pub fn list_products_summary(r: &ProductRecord) -> PlcProductSummary {
    PlcProductSummary {
        id: Some(r.uuid.clone()),
        name: r.name.clone(),
        opl_uuid: None,
        former_names: r.former_names.clone(),
        is_operator: r.is_operator,
        is_layered_product: None,
        release_cadence: r.release_cadence.clone(),
        package: r.package.clone(),
        link: r.link.clone(),
        footnote: None,
        show_final_minor_release: None,
        show_openshift_compatibility: None,
        versions: Some(r.versions.iter().map(list_products_version).collect()),
    }
}

/// Version projection for `list_products`: `{ name, type, tier, phases{date,name} }`.
fn list_products_version(v: &VersionRecord) -> ProductVersionSummary {
    ProductVersionSummary {
        name: v.name.clone(),
        version: None,
        version_type: v.version_type.clone(),
        tier: v.tier.clone(),
        phases: Some(
            v.phases
                .iter()
                .map(|p| ProductPhase {
                    name: p.name.clone(),
                    date: p.date.clone(),
                    date_format: None,
                    display_name: None,
                    ptype: None,
                })
                .collect(),
        ),
        final_minor_release: None,
        last_minor_release: None,
        openshift_compatibility: None,
        extra_dependencies: None,
    }
}

/// Projects a record for `get_operators` (GraphQL `get_operators.graphql`).
///
/// Selected: id, name, former_names, show_final_minor_release,
/// is_layered_product, is_operator, show_openshift_compatibility,
/// release_cadence, package, link; versions `{ name, type, last_minor_release,
/// final_minor_release, phases{name,date,date_format}, openshift_compatibility }`.
pub fn operator_summary(r: &ProductRecord) -> PlcProductSummary {
    PlcProductSummary {
        id: Some(r.uuid.clone()),
        name: r.name.clone(),
        opl_uuid: None,
        former_names: r.former_names.clone(),
        is_operator: r.is_operator,
        is_layered_product: r.is_layered_product,
        release_cadence: r.release_cadence.clone(),
        package: r.package.clone(),
        link: r.link.clone(),
        footnote: None,
        show_final_minor_release: r.show_final_minor_release,
        show_openshift_compatibility: r.show_openshift_compatibility,
        versions: Some(r.versions.iter().map(operator_version).collect()),
    }
}

/// Version projection for `get_operators`: `{ name, type, last_minor_release,
/// final_minor_release, openshift_compatibility, phases{name,date,date_format} }`.
fn operator_version(v: &VersionRecord) -> ProductVersionSummary {
    ProductVersionSummary {
        name: v.name.clone(),
        version: None,
        version_type: v.version_type.clone(),
        tier: None,
        phases: Some(v.phases.iter().map(full_phase).collect()),
        final_minor_release: v.final_minor_release.clone(),
        last_minor_release: v.last_minor_release.clone(),
        openshift_compatibility: v.openshift_compatibility.clone(),
        extra_dependencies: None,
    }
}

/// Projects a record for `get_product_by_id` (GraphQL `get_product_by_id.graphql`).
///
/// Selected: id, name, former_names, is_operator, is_layered_product,
/// release_cadence, package, link; versions `{ version, type, tier,
/// final_minor_release, openshift_compatibility, extra_dependencies,
/// phases{name,date,date_format} }`.
pub fn product_by_id_summary(r: &ProductRecord) -> PlcProductSummary {
    PlcProductSummary {
        id: Some(r.uuid.clone()),
        name: r.name.clone(),
        opl_uuid: None,
        former_names: r.former_names.clone(),
        is_operator: r.is_operator,
        is_layered_product: r.is_layered_product,
        release_cadence: r.release_cadence.clone(),
        package: r.package.clone(),
        link: r.link.clone(),
        footnote: None,
        show_final_minor_release: None,
        show_openshift_compatibility: None,
        versions: Some(r.versions.iter().map(product_by_id_version).collect()),
    }
}

/// Version projection for `get_product_by_id`: `{ version, type, tier,
/// final_minor_release, openshift_compatibility, extra_dependencies,
/// phases{name,date,date_format} }`.
fn product_by_id_version(v: &VersionRecord) -> ProductVersionSummary {
    ProductVersionSummary {
        name: None,
        version: v.name.clone(),
        version_type: v.version_type.clone(),
        tier: v.tier.clone(),
        phases: Some(v.phases.iter().map(full_phase).collect()),
        final_minor_release: v.final_minor_release.clone(),
        last_minor_release: None,
        openshift_compatibility: v.openshift_compatibility.clone(),
        extra_dependencies: v.extra_dependencies.clone(),
    }
}

/// Phase projection selecting `{ name, date, date_format }` (used by
/// `get_operators` and `get_product_by_id`).
fn full_phase(p: &crate::product::catalog::PhaseRecord) -> ProductPhase {
    ProductPhase {
        name: p.name.clone(),
        date: p.date.clone(),
        date_format: p.date_format.clone(),
        display_name: None,
        ptype: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::product::catalog::{PhaseRecord, ProductRecord, VersionRecord};
    use serde_json::{json, Value};

    /// A fully-populated record, so a projection setting a field to `None`
    /// reflects a deliberate per-tool omission, not missing source data.
    fn full_record() -> ProductRecord {
        ProductRecord {
            uuid: "u-1".to_owned(),
            name: Some("Red Hat Enterprise Linux".to_owned()),
            former_names: Some(vec!["RHEL Classic".to_owned()]),
            is_operator: Some(false),
            is_layered_product: Some(true),
            release_cadence: Some("Every 6 months".to_owned()),
            package: Some("rhel".to_owned()),
            link: Some("https://example.test/rhel".to_owned()),
            footnote: Some("a footnote".to_owned()),
            show_final_minor_release: Some(true),
            show_openshift_compatibility: Some(false),
            all_phases: Vec::new(),
            versions: vec![VersionRecord {
                name: Some("RHEL 9".to_owned()),
                version_type: Some("Full Support".to_owned()),
                tier: Some("Premium".to_owned()),
                final_minor_release: Some("9.10".to_owned()),
                last_minor_release: Some("9.9".to_owned()),
                openshift_compatibility: Some("4.x".to_owned()),
                extra_dependencies: Some(vec!["dep-a".to_owned()]),
                phases: vec![PhaseRecord {
                    name: Some("Full support".to_owned()),
                    date: Some("2025-01-01".to_owned()),
                    date_format: Some("date".to_owned()),
                }],
            }],
        }
    }

    fn json_of<T: Serialize>(v: &T) -> Value {
        serde_json::to_value(v).expect("serializes")
    }

    #[test]
    fn list_products_projects_the_upstream_field_subset() {
        let v = json_of(&list_products_summary(&full_record()));
        // Selected top-level fields.
        assert_eq!(v["id"], json!("u-1"));
        assert_eq!(v["name"], json!("Red Hat Enterprise Linux"));
        assert_eq!(v["former_names"], json!(["RHEL Classic"]));
        assert_eq!(v["is_operator"], json!(false));
        assert_eq!(v["release_cadence"], json!("Every 6 months"));
        assert_eq!(v["package"], json!("rhel"));
        assert_eq!(v["link"], json!("https://example.test/rhel"));
        // opl_uuid is always null; fields outside the query are null.
        assert_eq!(v["opl_uuid"], Value::Null);
        assert_eq!(v["is_layered_product"], Value::Null);
        assert_eq!(v["footnote"], Value::Null);
        assert_eq!(v["show_final_minor_release"], Value::Null);
        assert_eq!(v["show_openshift_compatibility"], Value::Null);
        // Version uses the `name` key; phases carry only name+date.
        let ver = &v["versions"][0];
        assert_eq!(ver["name"], json!("RHEL 9"));
        assert_eq!(ver["version"], Value::Null);
        assert_eq!(ver["type"], json!("Full Support"));
        assert_eq!(ver["tier"], json!("Premium"));
        assert_eq!(ver["final_minor_release"], Value::Null);
        assert_eq!(ver["last_minor_release"], Value::Null);
        assert_eq!(ver["openshift_compatibility"], Value::Null);
        assert_eq!(ver["extra_dependencies"], Value::Null);
        let phase = &ver["phases"][0];
        assert_eq!(phase["name"], json!("Full support"));
        assert_eq!(phase["date"], json!("2025-01-01"));
        assert_eq!(phase["date_format"], Value::Null);
    }

    #[test]
    fn get_product_by_id_uses_version_key_and_extra_dependencies() {
        let v = json_of(&product_by_id_summary(&full_record()));
        assert_eq!(v["id"], json!("u-1"));
        assert_eq!(v["is_layered_product"], json!(true));
        // opl_uuid / footnote / show_* are outside this query.
        assert_eq!(v["opl_uuid"], Value::Null);
        assert_eq!(v["footnote"], Value::Null);
        assert_eq!(v["show_final_minor_release"], Value::Null);
        let ver = &v["versions"][0];
        // Uses the `version` key (not `name`) and the corrected
        // `extra_dependencies` spelling; last_minor_release is not selected.
        assert_eq!(ver["version"], json!("RHEL 9"));
        assert_eq!(ver["name"], Value::Null);
        assert_eq!(ver["tier"], json!("Premium"));
        assert_eq!(ver["final_minor_release"], json!("9.10"));
        assert_eq!(ver["last_minor_release"], Value::Null);
        assert_eq!(ver["extra_dependencies"], json!(["dep-a"]));
        assert_eq!(v["versions"][0]["phases"][0]["date_format"], json!("date"));
    }

    #[test]
    fn get_operators_selects_operator_fields() {
        let v = json_of(&operator_summary(&full_record()));
        // show_* and is_layered_product are selected here.
        assert_eq!(v["show_final_minor_release"], json!(true));
        assert_eq!(v["show_openshift_compatibility"], json!(false));
        assert_eq!(v["is_layered_product"], json!(true));
        assert_eq!(v["footnote"], Value::Null);
        let ver = &v["versions"][0];
        // Uses `name`; tier and extra_dependencies are not selected;
        // last_minor_release is.
        assert_eq!(ver["name"], json!("RHEL 9"));
        assert_eq!(ver["version"], Value::Null);
        assert_eq!(ver["tier"], Value::Null);
        assert_eq!(ver["last_minor_release"], json!("9.9"));
        assert_eq!(ver["final_minor_release"], json!("9.10"));
        assert_eq!(ver["extra_dependencies"], Value::Null);
        assert_eq!(ver["phases"][0]["date_format"], json!("date"));
    }

    #[test]
    fn search_hit_omits_note_when_absent_but_keeps_other_keys() {
        let hit = SearchProductHit {
            id: Some("u-1".to_owned()),
            name: Some("Red Hat Enterprise Linux".to_owned()),
            former_names: Some(Vec::new()),
            relevance_score: Some(1.0),
            note: None,
        };
        let v = json_of(&hit);
        assert_eq!(v["relevance_score"], json!(1.0));
        assert_eq!(v["former_names"], json!([]));
        // `note` is skipped when None (matches upstream, which only sets it on
        // low-relevance hits).
        assert!(v.get("note").is_none());
    }
}
