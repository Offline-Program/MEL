//! Integration tests against a live Solr instance.
//!
//! Gated behind the `real-solr` feature and require the `SOLR_URL`
//! environment variable. Run them from the parent repo where the URL
//! is configured:
//!
//!     SOLR_URL=https://solr.example.com cargo test -p mimcp --features real-solr

#![cfg(feature = "real-solr")]

use mimcp::embed::Embedder;
use mimcp::portal::{
    PortalQuery, CVE_DETAIL_FL, ERRATA_DETAIL_FL, ERRATA_PACKAGES_FL, ERRATA_SUMMARY_FL, KIND_CVE,
    KIND_ERRATA,
};
use mimcp::records::{AdvisorySummary, CveDetail, ErratumDetail, ListAdvisoryPackagesOutput};
use mimcp::solr::{PortalRagFilter, ProductVersions, SolrClient};
use url::Url;

/// Builds a product restriction covering every version of `product`.
fn product_filter(product: &str) -> ProductVersions<'_> {
    ProductVersions {
        product,
        versions: &[],
    }
}

/// Directory holding the ONNX model and tokenizer, relative to this crate.
fn model_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../models")
}

fn solr_url() -> Url {
    let raw = std::env::var("SOLR_URL").expect("SOLR_URL must be set for integration tests");
    Url::parse(&raw).expect("SOLR_URL must be a valid URL")
}

fn solr_client() -> std::sync::Arc<SolrClient> {
    SolrClient::new(solr_url()).expect("SolrClient::new should not fail")
}

#[tokio::test]
async fn hybrid_search_content_type_filter_restricts_results() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "kernel vulnerability";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let unfiltered = solr
        .hybrid_search(query, &vector, 10, &[])
        .await
        .expect("unfiltered hybrid search should succeed");

    let filtered = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::ContentType("Cve_chunk")],
        )
        .await
        .expect("filtered hybrid search should succeed");

    assert!(
        !unfiltered.response.docs.is_empty(),
        "unfiltered search should return results for a broad query"
    );

    for doc in &filtered.response.docs {
        assert_eq!(
            doc.content_type.as_deref(),
            Some("Cve_chunk"),
            "every filtered result must have content_type=Cve_chunk, got {:?}",
            doc.content_type
        );
    }

    assert!(
        filtered.response.num_found <= unfiltered.response.num_found,
        "filtered count ({}) should not exceed unfiltered count ({})",
        filtered.response.num_found,
        unfiltered.response.num_found
    );
}

#[tokio::test]
async fn hybrid_search_content_type_docs_only() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "installing openshift";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::ContentType("documentation_chunk")],
        )
        .await
        .expect("docs-only hybrid search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "docs search for 'installing openshift' should return results"
    );

    for doc in &result.response.docs {
        assert_eq!(
            doc.content_type.as_deref(),
            Some("documentation_chunk"),
            "every result must be documentation_chunk, got {:?}",
            doc.content_type
        );
    }
}

#[tokio::test]
async fn hybrid_search_content_type_errata_only() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "kernel security update";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::ContentType("errata_chunk")],
        )
        .await
        .expect("errata-only hybrid search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "errata search for 'kernel security update' should return results"
    );

    for doc in &result.response.docs {
        assert_eq!(
            doc.content_type.as_deref(),
            Some("errata_chunk"),
            "every result must be errata_chunk, got {:?}",
            doc.content_type
        );
    }
}

#[tokio::test]
async fn hybrid_search_product_filter_ocp() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "cluster installation";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::Products(&[product_filter(
                "openshift_container_platform",
            )])],
        )
        .await
        .expect("OCP product-filtered search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "OCP product search for 'cluster installation' should return results"
    );

    for doc in &result.response.docs {
        let slugs = doc
            .product
            .as_deref()
            .expect("product field should be present");
        assert!(
            slugs.iter().any(|s| s == "openshift_container_platform"),
            "every result must include openshift_container_platform in product, got: {slugs:?}"
        );
    }
}

#[tokio::test]
async fn hybrid_search_product_filter_rhel() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "kernel configuration";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::Products(&[product_filter(
                "red_hat_enterprise_linux",
            )])],
        )
        .await
        .expect("RHEL product-filtered search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "RHEL product search for 'kernel configuration' should return results"
    );

    for doc in &result.response.docs {
        let slugs = doc
            .product
            .as_deref()
            .expect("product field should be present");
        assert!(
            slugs.iter().any(|s| s == "red_hat_enterprise_linux"),
            "every result must include red_hat_enterprise_linux in product, got: {slugs:?}"
        );
    }
}

#[tokio::test]
async fn hybrid_search_product_and_version_ocp_4_20() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "cluster installation";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::Products(&[ProductVersions {
                product: "openshift_container_platform",
                versions: &[String::from("4.20")],
            }])],
        )
        .await
        .expect("OCP 4.20 product+version search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "OCP 4.20 search for 'cluster installation' should return results"
    );

    for doc in &result.response.docs {
        let slugs = doc
            .product
            .as_deref()
            .expect("product field should be present");
        assert!(
            slugs.iter().any(|s| s == "openshift_container_platform"),
            "product must include openshift_container_platform, got: {slugs:?}"
        );
        assert_eq!(
            doc.product_version.as_deref(),
            Some("4.20"),
            "product_version must be 4.20, got {:?}",
            doc.product_version
        );
    }
}

#[tokio::test]
async fn hybrid_search_product_and_version_rhel_10() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "kernel configuration";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[PortalRagFilter::Products(&[ProductVersions {
                product: "red_hat_enterprise_linux",
                versions: &[String::from("10")],
            }])],
        )
        .await
        .expect("RHEL 10 product+version search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "RHEL 10 search for 'kernel configuration' should return results"
    );

    for doc in &result.response.docs {
        let slugs = doc
            .product
            .as_deref()
            .expect("product field should be present");
        assert!(
            slugs.iter().any(|s| s == "red_hat_enterprise_linux"),
            "product must include red_hat_enterprise_linux, got: {slugs:?}"
        );
        assert_eq!(
            doc.product_version.as_deref(),
            Some("10"),
            "product_version must be 10, got {:?}",
            doc.product_version
        );
    }
}

#[tokio::test]
async fn hybrid_search_version_filter_narrows_product_results() {
    let solr = solr_client();
    let embedder = Embedder::new(model_dir()).expect("embedder should load");
    let query = "cluster installation";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let product_only = solr
        .hybrid_search(
            query,
            &vector,
            20,
            &[PortalRagFilter::Products(&[product_filter(
                "openshift_container_platform",
            )])],
        )
        .await
        .expect("product-only search should succeed");

    let product_and_version = solr
        .hybrid_search(
            query,
            &vector,
            20,
            &[PortalRagFilter::Products(&[ProductVersions {
                product: "openshift_container_platform",
                versions: &[String::from("4.20")],
            }])],
        )
        .await
        .expect("product+version search should succeed");

    assert!(
        product_and_version.response.num_found <= product_only.response.num_found,
        "product+version count ({}) should not exceed product-only count ({})",
        product_and_version.response.num_found,
        product_only.response.num_found
    );
}

#[tokio::test]
async fn lexical_search_returns_results() {
    let solr = solr_client();

    let result = solr
        .search("CVE kernel", 5, &[])
        .await
        .expect("lexical search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "lexical search for 'CVE kernel' should return results"
    );
}

// --- security tools: the lexical `portal` collection ---
//
// These exercise the field mapping the CVE and errata tools depend on, which
// unit tests cannot cover: that the documents Solr actually returns populate
// the upstream-parity records.

/// A CVE expected to be present in the index, used as a retrieval fixture.
const FIXTURE_CVE: &str = "CVE-2021-44228";

/// An advisory expected to be present in the index, used as a retrieval fixture.
const FIXTURE_ADVISORY: &str = "RHSA-2021:5106";

#[tokio::test]
async fn get_cve_by_id_populates_the_record() {
    let solr = solr_client();
    let response = solr
        .portal_query(&PortalQuery::lookup(
            KIND_CVE,
            format!("url_slug:\"{FIXTURE_CVE}\""),
            CVE_DETAIL_FL,
        ))
        .await
        .expect("CVE lookup should succeed");

    let doc = response
        .response
        .first()
        .unwrap_or_else(|| panic!("{FIXTURE_CVE} should be in the index"));
    let detail = CveDetail::from_doc(doc);

    assert_eq!(detail.cve_id.as_deref(), Some(FIXTURE_CVE));
    assert!(detail.description.is_some(), "description should be stored");
    assert!(detail.severity.is_some(), "severity should be stored");
    assert!(detail.public_date.is_some(), "public date should be stored");
    assert!(
        detail.affected_products.is_some_and(|p| !p.is_empty()),
        "an affected CVE should have affected-product rows"
    );
}

#[tokio::test]
async fn cve_lookup_is_exact_not_prefix() {
    let solr = solr_client();
    let response = solr
        .portal_query(&PortalQuery::lookup(
            KIND_CVE,
            "url_slug:\"CVE-0000-00000\"".to_owned(),
            CVE_DETAIL_FL,
        ))
        .await
        .expect("lookup of a missing CVE should still succeed");

    assert_eq!(
        response.response.num_found, 0,
        "a nonexistent CVE must return no documents rather than a near match"
    );
}

#[tokio::test]
async fn get_errata_by_id_populates_the_record() {
    let solr = solr_client();
    let response = solr
        .portal_query(&PortalQuery::lookup(
            KIND_ERRATA,
            format!("id:\"{FIXTURE_ADVISORY}\""),
            ERRATA_DETAIL_FL,
        ))
        .await
        .expect("advisory lookup should succeed");

    let doc = response
        .response
        .first()
        .unwrap_or_else(|| panic!("{FIXTURE_ADVISORY} should be in the index"));
    let detail = ErratumDetail::from(doc);

    assert_eq!(detail.advisory_id.as_deref(), Some(FIXTURE_ADVISORY));
    assert!(detail.synopsis.is_some(), "synopsis should be stored");
    assert!(
        detail.advisory_type.is_some(),
        "advisory type should be stored"
    );
    assert!(detail.issue_date.is_some(), "issue date should be stored");
}

#[tokio::test]
async fn list_advisories_by_cve_resolves_from_the_errata_side() {
    let solr = solr_client();
    let response = solr
        .portal_query(
            &PortalQuery::new(
                KIND_ERRATA,
                format!("errata_cves:\"{FIXTURE_CVE}\""),
                ERRATA_DETAIL_FL,
            )
            .page(50, 0),
        )
        .await
        .expect("CVE-to-advisory query should succeed");

    assert!(
        !response.response.docs.is_empty(),
        "{FIXTURE_CVE} should have at least one linked advisory; an empty result \
         means errata_cves is not populated or not indexed"
    );

    for doc in response.response.docs {
        let id = doc.id.clone();
        let advisory = ErratumDetail::from(doc);
        assert!(
            advisory.advisory_id.is_some(),
            "every linked advisory must carry an ID, got {id:?}"
        );
    }
}

#[tokio::test]
async fn search_advisories_filters_by_type_and_returns_summary_fields() {
    let solr = solr_client();
    let response = solr
        .portal_query(
            &PortalQuery::new(KIND_ERRATA, "kernel".to_owned(), ERRATA_SUMMARY_FL)
                .filter("portal_advisory_type:\"Security Advisory\"")
                .page(10, 0),
        )
        .await
        .expect("advisory search should succeed");

    assert!(
        !response.response.docs.is_empty(),
        "a search for 'kernel' security advisories should return results"
    );

    for doc in response.response.docs {
        let summary = AdvisorySummary::from(doc);
        assert_eq!(
            summary.advisory_type.as_deref(),
            Some("Security Advisory"),
            "the type filter must be honoured"
        );
        assert!(summary.id.is_some(), "every hit must carry an advisory ID");
        assert!(
            summary.year.is_some(),
            "year must be derivable from the advisory ID {:?}",
            summary.id
        );
    }
}

#[tokio::test]
async fn search_cves_filters_by_severity() {
    let solr = solr_client();
    let response = solr
        .portal_query(
            &PortalQuery::new(KIND_CVE, "*:*".to_owned(), CVE_DETAIL_FL)
                .filter("cve_threatSeverity:Critical")
                .page(10, 0),
        )
        .await
        .expect("CVE severity search should succeed");

    assert!(
        !response.response.docs.is_empty(),
        "there should be at least one Critical CVE in the index"
    );

    for doc in response.response.docs {
        let detail = CveDetail::from_doc(doc);
        assert_eq!(
            detail.severity.as_deref(),
            Some("Critical"),
            "the severity filter must be honoured"
        );
    }
}

#[tokio::test]
async fn list_advisory_packages_parses_stored_nvra_strings() {
    let solr = solr_client();
    let response = solr
        .portal_query(&PortalQuery::lookup(
            KIND_ERRATA,
            format!("id:\"{FIXTURE_ADVISORY}\""),
            ERRATA_PACKAGES_FL,
        ))
        .await
        .expect("advisory package lookup should succeed");

    let doc = response
        .response
        .first()
        .unwrap_or_else(|| panic!("{FIXTURE_ADVISORY} should be in the index"));
    let raw = doc
        .errata_packages
        .clone()
        .expect("errata_packages should be stored on a security advisory");

    let result = ListAdvisoryPackagesOutput::page(&raw, 10, 0)
        .advisory
        .expect("page should be present");
    let packages = result.packages.expect("packages should be present");

    assert!(!packages.is_empty(), "advisory should ship packages");
    for package in &packages {
        assert!(
            package.name.is_some(),
            "every package row must parse to at least a name, got {:?}",
            package.package
        );
    }
}
