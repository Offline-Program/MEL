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

#![warn(clippy::missing_docs_in_private_items, missing_docs)]

//! MEL error conditions.

use std::fmt::Display;

/// Error conditions that MEL can encounter.  When stringified, the messages contain error codes
/// which are unique, and error messages which are sometimes identical across several variants.
/// When debugging a deployed Mimir error message, use the error code to identify the error
/// condition.
#[derive(Debug, PartialEq)]
pub(crate) enum MelError {
    /// User didn't provide an access key.
    AccessKeyMissing,
    /// User's access key has an invalid/unparsable format.  For example, it may be missing
    /// components.
    AccessKeyInvalidFormat,
    /// The user's ACCESS_KEY couldn't decrypt solr index.
    SolrIndexDecryptionFailed,
    /// couldn't decompress and extract the solr tarball
    SolrUnpackFailed,
    /// Couldn't read the TokenMap file.
    MimirTokenMapUnreadable,
    /// The user's ACCESS_KEY's user ID and org ID didn't map to an EDEK in the TokenMap.
    EdekMissing,
    /// Key derivation failed (turning the user's ACCESS_KEY into an AES-128 key).
    KekCreationFailed,
    /// Decrypting the user's EDEK into a DEK failed.
    EdekDecryptionFailed,
    /// The EDEK was decrypted but the result is the wrong size.
    DecryptedDekWrongSize,
    /// No solr index was found.
    SolrIndexNotFound,
    /// The token from the ACCESS_KEY is not present in the tokens cache.
    TokenMissing,
    /// Solr process failed.
    SolrProcessFailed,
    /// Apache httpd process failed.
    HttpdProcessFailed,
    /// User's access key's is cryptographically invalid (the hash component doesn't validate).
    AccessKeyInvalidBindHash,
    /// The TokenMap file is empty.
    MimirTokenMapEmpty,
    /// The TokenMap file has very few records.
    MimirTokenMapMeager,
}

impl From<&MelError> for &str {
    fn from(err: &MelError) -> Self {
        // Error messages for MelError variants.
        match err {
            MelError::AccessKeyMissing => "ERR_001: Please provide a valid ACCESS_KEY",
            MelError::AccessKeyInvalidFormat => "ERR_002: Please provide a valid ACCESS_KEY",
            MelError::SolrIndexDecryptionFailed => "ERR_003: Please provide a valid ACCESS_KEY",
            MelError::MimirTokenMapUnreadable => "ERR_004: Decryption failed.",
            MelError::EdekMissing => "ERR_005: Decryption failed.",
            MelError::KekCreationFailed => "ERR_006: Decryption failed.",
            MelError::EdekDecryptionFailed => "ERR_007: Decryption failed.",
            MelError::DecryptedDekWrongSize => "ERR_008: Decryption failed.",
            MelError::SolrIndexNotFound => "ERR_009: Solr search index is missing.",
            MelError::TokenMissing => "ERR_010: Please provide a valid ACCESS_KEY.",
            MelError::SolrProcessFailed => "ERR_011: Failed to launch Solr (search).",
            MelError::HttpdProcessFailed => "ERR_012: Failed to launch Apache httpd.",
            MelError::SolrUnpackFailed => "ERR_013: Failed to unpack the solr index archive.",
            MelError::AccessKeyInvalidBindHash => "ERR_014: Please provide a valid ACCESS_KEY.",
            MelError::MimirTokenMapEmpty => "ERR_015: RHOKP image contains no token data; please contact Red Hat support.",
            MelError::MimirTokenMapMeager => "ERR_016: RHOKP image contains very little token data; if your ACCESS_KEY is not accepted please contact Red Hat support.",
        }
    }
}

impl From<MelError> for &str {
    fn from(err: MelError) -> Self {
        (&err).into()
    }
}

impl Display for MelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.into())
    }
}
