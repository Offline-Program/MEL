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

use const_format::concatcp;

use crate::{ask::ASK_ENV, infer::INFERENCE_URL_ENV};

/// Error conditions that MEL can encounter.  When stringified, the messages contain error codes
/// which are unique, and error messages which are sometimes identical across several variants.
/// When debugging a deployed Mimir error message, use the error code to identify the error
/// condition.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MelError {
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
    /// The TokenMap file has very few records.  Treated as a warning.
    MimirTokenMapMeager,
    /// An INFERENCE_URL was provided but ASK_RED_HAT_OFFLINE is not enabled (so there's no reason
    /// to have inference).
    InferenceUrlButNoAsk,
    /// INFERENCE_URL was provided but the value is not a valid URL.
    InferenceUrlInvalid,
    /// Error initializing the inference.json file.
    InferenceUrlWrite,
    /// ASK_RED_HAT_OFFLINE is set to "true" but no INFERENCE_URL was provided.
    AskButNoInferenceUrl,
}

impl MelError {
    /// Retrieve a description of the error.
    #[rustfmt::skip]
    fn message(&self) -> &str {
        // Error messages for MelError variants.
        match self {
            MelError::AccessKeyMissing          => "ERR_001: ACCESS_KEY could not be validated.",
            MelError::AccessKeyInvalidFormat    => "ERR_002: ACCESS_KEY could not be validated.",
            MelError::SolrIndexDecryptionFailed => "ERR_003: ACCESS_KEY could not be validated.",
            MelError::MimirTokenMapUnreadable   => "ERR_004: Decryption failed.",
            MelError::EdekMissing               => "ERR_005: Decryption failed.",
            MelError::KekCreationFailed         => "ERR_006: Decryption failed.",
            MelError::EdekDecryptionFailed      => "ERR_007: Decryption failed.",
            MelError::DecryptedDekWrongSize     => "ERR_008: Decryption failed.",
            MelError::SolrIndexNotFound         => "ERR_009: Solr search index is missing.",
            MelError::TokenMissing              => "ERR_010: ACCESS_KEY could not be validated.",
            MelError::SolrProcessFailed         => "ERR_011: Failed to launch Solr (search).",
            MelError::HttpdProcessFailed        => "ERR_012: Failed to launch Apache httpd.",
            MelError::SolrUnpackFailed          => "ERR_013: Failed to unpack the solr index archive.",
            MelError::AccessKeyInvalidBindHash  => "ERR_014: ACCESS_KEY could not be validated.",
            MelError::MimirTokenMapEmpty        => "ERR_015: RHOKP image contains no token data.",
            MelError::MimirTokenMapMeager       => "ERR_016: RHOKP image contains very little token data.",
            MelError::InferenceUrlButNoAsk      => concatcp!("ERR_017: ", INFERENCE_URL_ENV, " was provided but ", ASK_ENV, " is not enabled."),
            MelError::InferenceUrlInvalid       => concatcp!("ERR_018: The provided ", INFERENCE_URL_ENV, " value is not a valid URL."),
            MelError::InferenceUrlWrite         => "ERR_019: Could not write inference.json.",
            MelError::AskButNoInferenceUrl      => concatcp!("ERR_020: ", ASK_ENV, " is enabled but ", INFERENCE_URL_ENV, " was not provided."),
        }
    }

    /// Retrieve a remediation suggestion for the error.
    #[rustfmt::skip]
    fn remediation(&self) -> &str {
        const GET_MAK: &str = "Retrieve an ACCESS_KEY from https://access.redhat.com/offline/access";
        const NEW_IMAGE_OR_SUPPORT: &str = "Please retrieve a new RHOKP image from registry.redhat.io, or contact Red Hat support.";
        const NEW_MAK_OR_SUPPORT: &str = "Please retrieve a new ACCESS_KEY from https://access.redhat.com/offline/access or contact Red Hat support.";
        const DOUBLE_CHECK_MAK: &str = "Verify the ACCESS_KEY matches what is listed in https://access.redhat.com/offline/access";

        match self {
            MelError::AccessKeyMissing          => GET_MAK,
            MelError::AccessKeyInvalidFormat    => DOUBLE_CHECK_MAK,
            MelError::SolrIndexDecryptionFailed => NEW_IMAGE_OR_SUPPORT,
            MelError::MimirTokenMapUnreadable   => NEW_IMAGE_OR_SUPPORT,
            MelError::EdekMissing               => NEW_IMAGE_OR_SUPPORT,
            MelError::KekCreationFailed         => NEW_IMAGE_OR_SUPPORT,
            MelError::EdekDecryptionFailed      => NEW_IMAGE_OR_SUPPORT,
            MelError::DecryptedDekWrongSize     => NEW_IMAGE_OR_SUPPORT,
            MelError::SolrIndexNotFound         => NEW_IMAGE_OR_SUPPORT,
            MelError::TokenMissing              => NEW_MAK_OR_SUPPORT,
            MelError::SolrProcessFailed         => NEW_IMAGE_OR_SUPPORT,
            MelError::HttpdProcessFailed        => NEW_IMAGE_OR_SUPPORT,
            MelError::SolrUnpackFailed          => NEW_IMAGE_OR_SUPPORT,
            MelError::AccessKeyInvalidBindHash  => DOUBLE_CHECK_MAK,
            MelError::MimirTokenMapEmpty        => NEW_IMAGE_OR_SUPPORT,
            MelError::MimirTokenMapMeager       => NEW_IMAGE_OR_SUPPORT,
            MelError::InferenceUrlButNoAsk      => concatcp!("When launching the container, provide the following environment variable: ", ASK_ENV, "=true"),
            MelError::InferenceUrlInvalid       => "Ensure the provided value is a valid URL.",
            MelError::InferenceUrlWrite         => NEW_IMAGE_OR_SUPPORT,
            MelError::AskButNoInferenceUrl      => concatcp!("Provide an environment variable, ", INFERENCE_URL_ENV, "='<url>' where <url> points to a Lightspeed Stack instance."),
        }
    }
}

impl Display for MelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())?;
        f.write_str(" ")?;
        f.write_str(self.remediation())
    }
}
