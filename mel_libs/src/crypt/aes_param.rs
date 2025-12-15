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

//! `aes_param` is for dealing with buffers used in AES encryption, such as encryption keys and IVs.

use super::AES_BLOCK_BYTES;
use hex::FromHexError;
use openssl::rand::rand_bytes;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// AESParam is a buffer of `AES_BLOCK_BYTES` bytes, a length chosen to line up with AES
/// block size.  It is used to store AES keys and IVs.
#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub struct AESParam {
    /// The data buffer of the AESParam.
    data: [u8; AES_BLOCK_BYTES],
    /// A pre-computed hex representation of the data buffer.
    hex: String,
}

pub struct NoEntropyAvailable;

/// Error condition when creating an AESParam from a buffer.
#[derive(Debug)]
pub enum AESParamFromBytesError {
    /// Buffer length did not match AES block size (`AES_BLOCK_BYTES`).
    BadAESParamWidth,
}

/// Error condition when creating an AESParam from a hex string.
#[derive(Debug)]
pub enum AESParamFromHexError {
    /// Decoded hex length did not match AES block size (`AES_BLOCK_BYTES`).
    BadAESParamWidth,
    /// Hex decoding failed.
    BadHex(FromHexError),
}

impl Display for AESParamFromHexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            AESParamFromHexError::BadAESParamWidth => "AESParamWidth incorrect".to_string(),
            AESParamFromHexError::BadHex(h) => format!("{h}"),
        };
        write!(f, "{msg}")
    }
}

impl AESParam {
    /// Create a new AESParam with the given bytes.  Returns Err(()) if the byte count doesn't
    /// match AES_BLOCK_BYTES.
    pub fn new(data: &[u8]) -> Result<Self, AESParamFromBytesError> {
        if data.len() == AES_BLOCK_BYTES {
            let mut buf = [0u8; AES_BLOCK_BYTES];
            buf.copy_from_slice(data); // this _should_ never panic because we've just checked the
                                       // length

            Ok(Self {
                data: buf,
                hex: hex::encode(buf),
            })
        } else {
            Err(AESParamFromBytesError::BadAESParamWidth)
        }
    }

    /// Create a new AESParam from a hex string.  Returns Err(()) if the byte count doesn't
    /// match AES_BLOCK_BYTES or the hex is not decodable.
    pub fn from_hex(hex: &str) -> Result<Self, AESParamFromHexError> {
        let data = hex::decode(hex).map_err(AESParamFromHexError::BadHex)?;

        if data.len() == AES_BLOCK_BYTES {
            let mut buf = [0u8; AES_BLOCK_BYTES];
            buf.copy_from_slice(&data); // this _should_ never panic because we've just checked the
                                        // length

            Ok(Self {
                data: buf,
                hex: hex.to_string(),
            })
        } else {
            Err(AESParamFromHexError::BadAESParamWidth)
        }
    }

    /// Create a new AES param (key or iv) of the pre-configured width, generated randomly by
    /// openssl's entropy source.  Returns Err if openssl reports no source of entropy is
    /// available.
    pub fn try_new_random() -> Result<Self, NoEntropyAvailable> {
        let mut buf = [0u8; AES_BLOCK_BYTES];
        rand_bytes(&mut buf).map_err(|_| NoEntropyAvailable)?;
        Self::new(&buf).map_err(|_| NoEntropyAvailable)
    }

    /// Get a reference to the data buffer.
    pub fn data(&self) -> &[u8; AES_BLOCK_BYTES] {
        &self.data
    }

    /// Convert the data to a hex representation.
    pub fn as_hex(&self) -> &str {
        &self.hex
    }
}

impl Serialize for AESParam {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // serialization (here) and deserialization elsewhere are string-based and use AESParam's
        // `hex` field
        serializer.serialize_str(&self.hex)
    }
}

impl<'de> Deserialize<'de> for AESParam {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex: String = Deserialize::deserialize(deserializer)?;

        AESParam::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}
