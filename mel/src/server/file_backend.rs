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
#[cfg(feature = "squashfs")]
use std::{io::Read, path::Path, sync::Arc};

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
#[cfg(not(feature = "squashfs"))]
#[derive(Debug)]
pub(crate) struct LocalFileBackend {
    /// Absolute path to the directory that is the root of the web content, e.g. `/var/www/html`.
    webroot: String,
}

#[cfg(not(feature = "squashfs"))]
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

#[cfg(not(feature = "squashfs"))]
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

// ── SquashFS backend ────────────────────────────────────────────────────────

/// Default path to the squashfs archive inside the container image.
#[cfg(feature = "squashfs")]
pub(crate) const SQSH_DEFAULT_PATH: &str = "/assets.sqsh";

/// A [`FileBackend`] that reads files from a SquashFS archive.
///
/// The archive is opened once at startup.  File lookups use binary search on the sorted
/// node list (O(log n) for 1.3M nodes).  Decompression happens inside
/// [`tokio::task::spawn_blocking`] to avoid blocking the async executor.
#[cfg(feature = "squashfs")]
pub(crate) struct SquashfsFileBackend {
    /// The opened archive reader, shared across request handlers.
    reader: Arc<backhand::FilesystemReader<'static>>,
}

#[cfg(feature = "squashfs")]
impl SquashfsFileBackend {
    /// Open a squashfs archive at `path`.
    ///
    /// The file is read into memory so the `FilesystemReader` owns a `'static` buffer,
    /// allowing it to be shared across threads via `Arc`.
    pub(crate) fn open(path: &str) -> Result<Self> {
        eprintln!("Opening squashfs archive: {path}");
        let data = std::fs::read(path)?;
        let cursor = std::io::Cursor::new(data);
        let reader = backhand::FilesystemReader::from_reader(cursor)?;

        let file_count = reader
            .files()
            .filter(|n| matches!(n.inner, backhand::InnerNode::File(_)))
            .count();
        eprintln!("Squashfs archive loaded: {file_count} files");

        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Look up a node by path using binary search on the sorted node list.
    fn find_file<'a>(
        reader: &'a backhand::FilesystemReader<'_>,
        path: &str,
    ) -> Option<&'a backhand::SquashfsFileReader> {
        let search_path = Path::new(path);
        let nodes = &reader.root.nodes;
        let idx = nodes
            .binary_search_by(|n| n.fullpath.as_path().cmp(search_path))
            .ok()?;
        match &nodes[idx].inner {
            backhand::InnerNode::File(file) => Some(file),
            _ => None,
        }
    }

    /// Normalize a request path to the format used inside the archive (absolute, no `..`).
    /// Returns `None` if the path contains traversal segments.
    fn normalize(path: &str) -> Option<String> {
        let stripped = path.trim_start_matches('/');
        if stripped.split('/').any(|seg| seg == "..") {
            return None;
        }
        if path.starts_with('/') {
            Some(path.to_string())
        } else {
            Some(format!("/{path}"))
        }
    }

    /// Synchronously read a file from the archive by path.
    ///
    /// Used by tests and available for the caching layer.
    #[cfg(test)]
    pub(crate) fn read_file_sync(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let normalized = match Self::normalize(path) {
            Some(p) => p,
            None => return Ok(None),
        };

        let file = match Self::find_file(&self.reader, &normalized) {
            Some(f) => f,
            None => return Ok(None),
        };

        let mut reader = self.reader.file(file).reader();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    /// Get an `Arc` clone of the underlying reader for use in closures.
    pub(crate) fn reader(&self) -> Arc<backhand::FilesystemReader<'static>> {
        self.reader.clone()
    }
}

#[cfg(feature = "squashfs")]
impl FileBackend for SquashfsFileBackend {
    async fn get(&self, path: &str) -> Result<Option<FileResponse>> {
        let normalized = match Self::normalize(path) {
            Some(p) => p,
            None => return Ok(None),
        };

        let reader = self.reader.clone();

        let result = tokio::task::spawn_blocking(move || -> Result<Option<FileResponse>> {
            let file = match Self::find_file(&reader, &normalized) {
                Some(f) => f,
                None => return Ok(None),
            };

            let mut sqsh_reader = reader.file(file).reader();
            let mut buf = Vec::new();
            sqsh_reader.read_to_end(&mut buf)?;

            let content_type = mime_guess::from_path(&normalized)
                .first_or_octet_stream()
                .to_string();

            Ok(Some(FileResponse {
                bytes: buf,
                content_type,
            }))
        })
        .await??;

        Ok(result)
    }
}

#[cfg(all(test, feature = "squashfs"))]
mod tests {
    use super::*;

    /// Path to the test squashfs archive at the repo root.
    const TEST_SQSH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../assets.sqsh"
    );

    fn open_test_archive() -> SquashfsFileBackend {
        SquashfsFileBackend::open(TEST_SQSH).expect("failed to open test squashfs archive")
    }

    #[test]
    fn open_archive() {
        let backend = open_test_archive();
        // Sanity: the archive should have a large number of files
        let file_count = backend
            .reader
            .files()
            .filter(|n| matches!(n.inner, backhand::InnerNode::File(_)))
            .count();
        assert!(file_count > 100_000, "expected >100k files, got {file_count}");
    }

    #[test]
    fn read_robots_txt() {
        let backend = open_test_archive();
        let content = backend
            .read_file_sync("/robots.txt")
            .expect("read error")
            .expect("robots.txt not found");
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("User-agent"), "unexpected content: {text}");
    }

    #[test]
    fn read_index_html() {
        let backend = open_test_archive();
        let content = backend
            .read_file_sync("/index.html")
            .expect("read error")
            .expect("index.html not found");
        assert!(!content.is_empty());
        let text = String::from_utf8_lossy(&content);
        assert!(text.contains("<html") || text.contains("<!DOCTYPE") || text.contains("<!doctype"));
    }

    #[test]
    fn read_404_html() {
        let backend = open_test_archive();
        let content = backend
            .read_file_sync("/404.html")
            .expect("read error")
            .expect("404.html not found");
        assert!(!content.is_empty());
    }

    #[test]
    fn read_nonexistent_returns_none() {
        let backend = open_test_archive();
        let result = backend
            .read_file_sync("/this/path/does/not/exist.html")
            .expect("read error");
        assert!(result.is_none());
    }

    #[test]
    fn path_traversal_rejected() {
        let result = SquashfsFileBackend::normalize("/../etc/passwd");
        assert!(result.is_none());
    }

    #[test]
    fn normalize_adds_leading_slash() {
        let result = SquashfsFileBackend::normalize("robots.txt");
        assert_eq!(result, Some("/robots.txt".to_string()));
    }

    #[test]
    fn mime_type_html() {
        let backend = open_test_archive();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt
            .block_on(backend.get("/index.html"))
            .expect("read error")
            .expect("index.html not found");
        assert_eq!(resp.content_type, "text/html");
    }

    #[test]
    fn mime_type_css() {
        let backend = open_test_archive();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt
            .block_on(backend.get("/pico.min.css"))
            .expect("read error")
            .expect("pico.min.css not found");
        assert_eq!(resp.content_type, "text/css");
    }

    #[test]
    fn read_pmap_txt() {
        let backend = open_test_archive();
        let content = backend
            .read_file_sync("/pmap.txt")
            .expect("read error")
            .expect("pmap.txt not found");
        let text = String::from_utf8_lossy(&content);
        // pmap.txt should contain product name mappings
        assert!(!text.is_empty());
    }
}
