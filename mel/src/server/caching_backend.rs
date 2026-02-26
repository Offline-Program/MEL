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

//! A caching wrapper around any [`FileBackend`].
//!
//! [`CachingBackend`] stores responses by path in a concurrent map.  It can be pre-warmed
//! at startup with paths that are known to be hot (e.g. the 6 SSI include files that appear
//! on every page).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use super::file_backend::{FileBackend, FileResponse};

/// A [`FileBackend`] wrapper that caches responses by path.
///
/// Cached entries are stored as `Arc<CachedFile>` so clones are cheap.  The cache is
/// populated on first access and never evicted (the content is static within a given build).
pub(crate) struct CachingBackend<F: FileBackend> {
    /// The underlying backend that does the real I/O.
    inner: F,
    /// Cached file contents, keyed by normalized path.
    cache: tokio::sync::RwLock<HashMap<String, Arc<CachedFile>>>,
}

/// A cached file entry.
struct CachedFile {
    /// The raw bytes of the file.
    bytes: Vec<u8>,
    /// The MIME type.
    content_type: String,
}

impl<F: FileBackend> CachingBackend<F> {
    /// Wrap `inner` in a caching layer.
    pub(crate) fn new(inner: F) -> Self {
        Self {
            inner,
            cache: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Pre-warm the cache with the given paths.  Paths that don't exist in the backend
    /// are silently skipped.
    pub(crate) async fn warm(&self, paths: &[&str]) -> Result<()> {
        for &path in paths {
            if let Some(resp) = self.inner.get(path).await? {
                let entry = Arc::new(CachedFile {
                    bytes: resp.bytes,
                    content_type: resp.content_type,
                });
                self.cache.write().await.insert(path.to_string(), entry);
            }
        }
        Ok(())
    }
}

impl<F: FileBackend> FileBackend for CachingBackend<F> {
    async fn get(&self, path: &str) -> Result<Option<FileResponse>> {
        // Check cache first (read lock — concurrent readers allowed)
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(path) {
                return Ok(Some(FileResponse {
                    bytes: entry.bytes.clone(),
                    content_type: entry.content_type.clone(),
                }));
            }
        }

        // Cache miss — fetch from inner backend
        let resp = self.inner.get(path).await?;

        // Store in cache if the file exists
        if let Some(ref file) = resp {
            let entry = Arc::new(CachedFile {
                bytes: file.bytes.clone(),
                content_type: file.content_type.clone(),
            });
            self.cache.write().await.insert(path.to_string(), entry);
        }

        Ok(resp)
    }
}
