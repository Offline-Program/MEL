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

//! Runtime configuration for the Mimir HTTP server, derived from environment variables.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// How the static content files are stored on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentEncoding {
    /// Files are stored as plain text and will be compressed on-the-fly for the client.
    Plain,
    /// Files are stored pre-compressed with gzip.  HTML is decompressed, SSI-processed, then
    /// re-compressed.  JSON is served with `Content-Encoding: gzip` when the client accepts it.
    Precompressed,
}

/// Whether paywall content (solutions, articles) is encrypted on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContentEncryption {
    /// Content is stored in plaintext.
    Plain,
    /// Paywall content is AES-128-CTR encrypted.  `dek` and `iv` are required to decrypt it.
    Encrypted {
        /// The Data Encryption Key, as a hex string.
        dek: &'static str,
        /// The Initialisation Vector, as a hex string.
        iv: &'static str,
    },
}

/// Runtime configuration for the Mimir HTTP server.
#[derive(Debug, Clone)]
pub(crate) struct ServerConfig {
    /// The socket address the server will bind to.
    pub(crate) bind_addr: SocketAddr,
    /// The root directory from which static files are served.
    #[cfg(not(feature = "squashfs"))]
    pub(crate) webroot: String,
    /// The URL of the Solr instance to proxy search requests to.
    pub(crate) solr_url: String,
    /// How content files are stored on disk.
    pub(crate) content_encoding: ContentEncoding,
    /// Whether paywall content is encrypted on disk.
    pub(crate) content_encryption: ContentEncryption,
    /// If set, the server will inject an unclassified banner SSI variable into HTML responses.
    pub(crate) unclassified_banner: Option<String>,
    /// If true, the server will signal to HTML pages that the access key is missing.
    pub(crate) missing_access_key: bool,
    /// TLS configuration, if valid certificates were found.
    pub(crate) tls: Option<TlsConfig>,
}

/// Validated TLS certificate and key paths.
#[derive(Debug, Clone)]
pub(crate) struct TlsConfig {
    /// Path to the PEM-encoded certificate (or chain) file.
    pub(crate) cert_path: PathBuf,
    /// Path to the PEM-encoded private key file.
    pub(crate) key_path: PathBuf,
    /// The socket address the HTTPS listener will bind to.
    pub(crate) bind_addr: SocketAddr,
}

impl ServerConfig {
    /// Build a `ServerConfig` from environment variables and the optional decrypted DEK.
    ///
    /// `dek_hex` and `iv_hex` must be `'static` because they are derived from compile-time
    /// `option_env!` or from a `OnceLock<String>` that lives for the process lifetime.
    pub(crate) fn from_env(
        dek_hex: Option<&'static str>,
        iv_hex: Option<&'static str>,
    ) -> Self {
        let port: u16 = std::env::var("MIMIR_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);

        let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));

        #[cfg(not(feature = "squashfs"))]
        let webroot = std::env::var("MIMIR_WEBROOT")
            .unwrap_or_else(|_| "/var/www/html".to_string());

        let solr_url = std::env::var("MIMIR_SOLR_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8983".to_string());

        let compressed = std::env::var("COMPRESSED")
            .map(|v| v.trim() == "true")
            .unwrap_or(false);

        let content_encoding = if compressed {
            ContentEncoding::Precompressed
        } else {
            ContentEncoding::Plain
        };

        let content_encryption = match (dek_hex, iv_hex) {
            (Some(dek), Some(iv)) => ContentEncryption::Encrypted { dek, iv },
            _ => ContentEncryption::Plain,
        };

        let unclassified_banner = std::env::var("UNCLASSIFIED_BANNER").ok();

        let missing_access_key = false;

        let tls = TlsConfig::detect("/opt/app-root/httpd-ssl", 8443);

        Self {
            bind_addr,
            #[cfg(not(feature = "squashfs"))]
            webroot,
            solr_url,
            content_encoding,
            content_encryption,
            unclassified_banner,
            missing_access_key,
            tls,
        }
    }
}

impl TlsConfig {
    /// Scan `tls_dir` for certificate and key files.
    ///
    /// The expected layout matches the documented `httpd-ssl/` volume:
    ///
    /// ```text
    /// httpd-ssl/
    /// ├── certs/
    /// │   └── <name>.pem
    /// └── private/
    ///     └── <name>.pem
    /// ```
    ///
    /// Returns `None` (with an info log) if neither directory exists.  Exits the process with an
    /// error if the directory structure is present but incomplete or contains invalid files.
    fn detect(tls_dir: &str, tls_port: u16) -> Option<Self> {
        let base = Path::new(tls_dir);
        let certs_dir = base.join("certs");
        let private_dir = base.join("private");

        if !base.exists() {
            eprintln!("INFO: TLS directory {tls_dir} not found; HTTPS listener disabled");
            return None;
        }

        let cert_path = find_single_pem(&certs_dir, "certificate");
        let key_path = find_single_pem(&private_dir, "private key");

        let (cert_path, key_path) = match (cert_path, key_path) {
            (Some(c), Some(k)) => (c, k),
            _ => std::process::exit(1),
        };

        if let Err(e) = validate_pem_pair(&cert_path, &key_path) {
            eprintln!("ERROR: TLS certificate validation failed: {e}");
            std::process::exit(1);
        }

        eprintln!(
            "INFO: TLS certificates loaded from {tls_dir}; HTTPS listener will bind to port {tls_port}"
        );

        Some(Self {
            cert_path,
            key_path,
            bind_addr: SocketAddr::from(([0, 0, 0, 0], tls_port)),
        })
    }
}

/// Find exactly one `.pem` file in `dir`.  Returns `None` (after logging an error) if the
/// directory is missing, empty, or contains more than one `.pem` file.
fn find_single_pem(dir: &Path, label: &str) -> Option<PathBuf> {
    if !dir.is_dir() {
        eprintln!("ERROR: TLS {label} directory not found: {}", dir.display());
        return None;
    }

    let pems: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("pem"))
            .collect(),
        Err(e) => {
            eprintln!("ERROR: cannot read TLS {label} directory {}: {e}", dir.display());
            return None;
        }
    };

    match pems.len() {
        0 => {
            eprintln!("ERROR: no .pem {label} file found in {}", dir.display());
            None
        }
        1 => Some(pems.into_iter().next().unwrap()),
        n => {
            eprintln!(
                "ERROR: expected exactly one .pem {label} file in {}, found {n}",
                dir.display()
            );
            None
        }
    }
}

/// Validate that the certificate and key can be parsed and that the key matches the certificate.
fn validate_pem_pair(cert_path: &Path, key_path: &Path) -> Result<(), String> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())
        .map_err(|e| format!("failed to create SSL context: {e}"))?;

    builder
        .set_certificate_chain_file(cert_path)
        .map_err(|e| format!("invalid certificate {}: {e}", cert_path.display()))?;

    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| format!("invalid private key {}: {e}", key_path.display()))?;

    builder
        .check_private_key()
        .map_err(|e| format!("private key does not match certificate: {e}"))?;

    Ok(())
}
