//! Integration tests against a live Solr instance.
//!
//! Gated behind the `real-solr` feature and require the `SOLR_URL`
//! environment variable. Run them from the parent repo where the URL
//! is configured:
//!
//!     SOLR_URL=https://solr.example.com cargo test -p mimcp --features real-solr

#![cfg(feature = "real-solr")]

use mimcp::embed::Embedder;
use mimcp::solr::{SolrClient, SolrFilter};
use url::Url;

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
    let embedder = Embedder::new().expect("embedder should load");
    let query = "kernel vulnerability";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let unfiltered = solr
        .hybrid_search(query, &vector, 10, &[])
        .await
        .expect("unfiltered hybrid search should succeed");

    let filtered = solr
        .hybrid_search(query, &vector, 10, &[SolrFilter::ContentType("Cve_chunk")])
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
    let embedder = Embedder::new().expect("embedder should load");
    let query = "installing openshift";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(query, &vector, 10, &[SolrFilter::ContentType("documentation_chunk")])
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
    let embedder = Embedder::new().expect("embedder should load");
    let query = "kernel security update";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(query, &vector, 10, &[SolrFilter::ContentType("errata_chunk")])
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
    let embedder = Embedder::new().expect("embedder should load");
    let query = "cluster installation";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[SolrFilter::Product("openshift_container_platform")],
        )
        .await
        .expect("OCP product-filtered search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "OCP product search for 'cluster installation' should return results"
    );

    for doc in &result.response.docs {
        let products = doc.product.as_ref().expect("product field should be present");
        let product_arr = products.as_array().expect("product should be an array");
        let slugs: Vec<&str> = product_arr.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            slugs.contains(&"openshift_container_platform"),
            "every result must include openshift_container_platform in product, got: {slugs:?}"
        );
    }
}

#[tokio::test]
async fn hybrid_search_product_filter_rhel() {
    let solr = solr_client();
    let embedder = Embedder::new().expect("embedder should load");
    let query = "kernel configuration";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[SolrFilter::Product("red_hat_enterprise_linux")],
        )
        .await
        .expect("RHEL product-filtered search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "RHEL product search for 'kernel configuration' should return results"
    );

    for doc in &result.response.docs {
        let products = doc.product.as_ref().expect("product field should be present");
        let product_arr = products.as_array().expect("product should be an array");
        let slugs: Vec<&str> = product_arr.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            slugs.contains(&"red_hat_enterprise_linux"),
            "every result must include red_hat_enterprise_linux in product, got: {slugs:?}"
        );
    }
}

#[tokio::test]
async fn hybrid_search_product_and_version_ocp_4_20() {
    let solr = solr_client();
    let embedder = Embedder::new().expect("embedder should load");
    let query = "cluster installation";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[
                SolrFilter::Product("openshift_container_platform"),
                SolrFilter::ProductVersion("4.20"),
            ],
        )
        .await
        .expect("OCP 4.20 product+version search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "OCP 4.20 search for 'cluster installation' should return results"
    );

    for doc in &result.response.docs {
        let products = doc.product.as_ref().expect("product field should be present");
        let product_arr = products.as_array().expect("product should be an array");
        let slugs: Vec<&str> = product_arr.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            slugs.contains(&"openshift_container_platform"),
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
    let embedder = Embedder::new().expect("embedder should load");
    let query = "kernel configuration";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let result = solr
        .hybrid_search(
            query,
            &vector,
            10,
            &[
                SolrFilter::Product("red_hat_enterprise_linux"),
                SolrFilter::ProductVersion("10"),
            ],
        )
        .await
        .expect("RHEL 10 product+version search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "RHEL 10 search for 'kernel configuration' should return results"
    );

    for doc in &result.response.docs {
        let products = doc.product.as_ref().expect("product field should be present");
        let product_arr = products.as_array().expect("product should be an array");
        let slugs: Vec<&str> = product_arr.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            slugs.contains(&"red_hat_enterprise_linux"),
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
    let embedder = Embedder::new().expect("embedder should load");
    let query = "cluster installation";
    let vector = embedder.embed(query).expect("embedding should succeed");

    let product_only = solr
        .hybrid_search(
            query,
            &vector,
            20,
            &[SolrFilter::Product("openshift_container_platform")],
        )
        .await
        .expect("product-only search should succeed");

    let product_and_version = solr
        .hybrid_search(
            query,
            &vector,
            20,
            &[
                SolrFilter::Product("openshift_container_platform"),
                SolrFilter::ProductVersion("4.20"),
            ],
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
        .search("CVE kernel", 5)
        .await
        .expect("lexical search should succeed");

    assert!(
        !result.response.docs.is_empty(),
        "lexical search for 'CVE kernel' should return results"
    );
}
