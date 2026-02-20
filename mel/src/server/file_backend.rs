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

//! Abstraction over file storage backends.
//!
//! The [`FileBackend`] trait decouples the HTTP handlers from any particular storage system.
//! The default implementation, [`LocalFileBackend`], reads files from the local filesystem.
//! Future backends (e.g. S3, in-memory) can be swapped in without changing the handler logic.

use anyhow::Result;

/// The result of a successful file lookup.
pub(crate) struct FileResponse {
    /// The raw bytes of the file.
    pub(crate) bytes: Vec<u8>,
    /// The MIME type inferred from the file path.
    pub(crate) content_type: String,
}

/// An abstraction over a file storage backend.
///
/// Implementors provide a single method, [`FileBackend::get`], which resolves a logical path
/// (relative to the webroot) to file bytes and a content type.  The path will always be an
/// absolute path rooted at `/`, e.g. `/about/index.html`.
pub(crate) trait FileBackend: Send + Sync + 'static {
    /// Fetch the file at `path`.  Returns `None` if the file does not exist.
    fn get(&self, path: &str) -> impl std::future::Future<Output = Result<Option<FileResponse>>> + Send;
}

/// A [`FileBackend`] that reads files from the local filesystem under a configured webroot.
#[derive(Debug)]
pub(crate) struct LocalFileBackend {
    /// Absolute path to the directory that is the root of the web content, e.g. `/var/www/html`.
    webroot: String,
}

impl LocalFileBackend {
    /// Create a new `LocalFileBackend` serving files from `webroot`.
    pub(crate) fn new(webroot: impl Into<String>) -> Self {
        Self {
            webroot: webroot.into(),
        }
    }

    /// Resolve a URL path to a filesystem path under the webroot.
    ///
    /// Strips any leading `/` from `path`, rejects paths containing `..` segments to prevent
    /// directory traversal, and joins the remainder to the webroot.
    fn resolve(&self, path: &str) -> Option<std::path::PathBuf> {
        let stripped = path.trim_start_matches('/');
        if stripped.split('/').any(|seg| seg == "..") {
            return None;
        }
        Some(std::path::Path::new(&self.webroot).join(stripped))
    }
}

impl FileBackend for LocalFileBackend {
    async fn get(&self, path: &str) -> Result<Option<FileResponse>> {
        let fs_path = match self.resolve(path) {
            Some(p) => p,
            None => return Ok(None),
        };

        match tokio::fs::read(&fs_path).await {

            Ok(bytes) => {
                let content_type = mime_guess::from_path(&fs_path)
                    .first_or_octet_stream()
                    .to_string();

                Ok(Some(FileResponse { bytes, content_type }))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
