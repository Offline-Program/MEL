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

//! Types for the components of an access key.

use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::crypt::hash_hex;

/// Newtype for the User ID component of the access key.
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct UserID(
    String, /* Changing this data type will almost certainly disable all existing access keys*/
);

impl UserID {
    /// Create a UserID.
    pub fn new(id: &str) -> UserID {
        UserID(id.to_string())
    }

    /// Returns a reference to UserID's internal String.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for UserID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Newtype for the Org ID component of the access key.
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct OrgID(
    String, /* Changing this data type will almost certainly disable all existing access keys*/
);

impl OrgID {
    /// Create an OrgID.
    pub fn new(id: &str) -> OrgID {
        OrgID(id.to_string())
    }

    /// Returns a reference to OrgID's internal String.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for OrgID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Newtype for the Token component of the access key.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Serialize, Deserialize)]
pub struct Token(
    String, /* Changing this data type will almost certainly disable all existing access keys*/
);

impl Token {
    /// The length (in bytes) token hex strings should be truncated to.
    pub const HEX_LEN: usize = 8;

    /// Create a Token.
    pub fn new(token: &str) -> Token {
        Token(token.to_string())
    }

    /// Returns a reference to Token's internal String.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Create a new token based on a truncated hash of this one.
    pub fn hash(&self) -> Token {
        Token::new(&hash_hex(self.0.as_str(), Token::HEX_LEN))
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
