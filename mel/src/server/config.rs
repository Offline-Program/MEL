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

        Self {
            bind_addr,
            webroot,
            solr_url,
            content_encoding,
            content_encryption,
            unclassified_banner,
            missing_access_key,
        }
    }
}
