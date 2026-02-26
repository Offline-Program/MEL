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

//! Streaming file backend trait for large files.
//!
//! [`StreamingBackend`] returns a byte stream instead of buffering the entire file in memory.
//! This is intended for large files like `img_dedup.json` (62MB) and multi-MB PDFs.
//!
//! **Implementation is deferred** — this module defines the trait only.  The existing
//! [`FileBackend`](super::file_backend::FileBackend) `Vec<u8>` approach is used for now.

use anyhow::Result;

/// A streaming file response.
pub(crate) struct StreamingResponse {
    /// The response body as an Axum body (streamed).
    pub(crate) body: axum::body::Body,
    /// The MIME type inferred from the file path.
    pub(crate) content_type: String,
    /// The total content length, if known.
    pub(crate) content_length: Option<u64>,
}

/// A backend that can serve files as byte streams.
///
/// Unlike [`FileBackend`](super::file_backend::FileBackend), which buffers the entire file
/// in memory, `StreamingBackend` yields chunks incrementally.  This is important for files
/// that are tens of megabytes.
pub(crate) trait StreamingBackend: Send + Sync + 'static {
    /// Fetch a file as a stream.  Returns `None` if the file does not exist.
    fn get_stream(
        &self,
        path: &str,
    ) -> impl std::future::Future<Output = Result<Option<StreamingResponse>>> + Send;
}
