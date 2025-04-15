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

//! `access_key` contains functionality for reading, writing, and validating Mimir Access Keys.

pub mod components;

use components::{OrgID, Token, UserID};
use hex::FromHexError;
use sha2::{Digest, Sha256};
use std::fmt::Display;

use crate::crypt;

/// Represents a user's access key.  Sometimes abbreviated MAK, for Mimir Access Key.
#[derive(Debug, Eq, PartialEq)]
pub struct AccessKey {
    /// The user's User ID.
    user_id: UserID,
    /// The user's Org ID.
    org_id: OrgID,
    /// The token from the pre-seeded token database that was bound to this user_id and org_id.
    token: Token,
    /// A cryptographic hash of the other components of the access key and a secret.
    bind_hash: String,
}

/// Error conditions which can occur when parsing an ACCESS_KEY from a string.
#[derive(Debug)]
pub enum InvalidAccessKey {
    /// The plaintext access key did not have three components (components are "user id", "org id",
    /// and "hash", separated by underscores).
    MissingComponents,
    /// The "hash" component in the access key provided by the user did not match the hash of the "user id" and "org id".
    BadHash,
}

impl TryFrom<&str> for AccessKey {
    type Error = InvalidAccessKey;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // scan for underscore separators, starting from the right, so that the first access key
        // component (user_id) can contain underscores without throwing off parsing.

        // third underscore
        let three = value
            .rfind('_')
            .ok_or(InvalidAccessKey::MissingComponents)?;
        let vtrim = &value[0..three];

        // second underscore
        let two = vtrim
            .rfind('_')
            .ok_or(InvalidAccessKey::MissingComponents)?;
        let vtrim = &value[0..two];

        // first underscore (not counting underscores that may be present in the user_id)
        let one = vtrim
            .rfind('_')
            .ok_or(InvalidAccessKey::MissingComponents)?;

        // handle empty components
        let empty_user_id = one == 0;
        let empty_org_id = one + 1 == two;
        let empty_token = two + 1 == three;
        let empty_hash = three + 1 == value.len();

        if empty_user_id || empty_org_id || empty_token || empty_hash {
            return Err(InvalidAccessKey::MissingComponents);
        }

        // get pointers to components
        let user_id = value[0..one].to_string();
        let org_id = value[one + 1..two].to_string();
        let token = value[two + 1..three].to_string();
        let hashed_ids = value[three + 1..].to_string();

        let user_id = UserID::new(&user_id);
        let org_id = OrgID::new(&org_id);
        let token = Token::new(&token);

        let access_key = AccessKey {
            user_id,
            org_id,
            token,
            bind_hash: hashed_ids,
        };

        if !access_key.is_valid() {
            return Err(InvalidAccessKey::BadHash);
        }

        Ok(access_key)
    }
}

impl AccessKey {
    /// Create a plaintext (non-hashed) string of an access key for a given user_id, org_id, and
    /// secret.
    pub fn plaintext(user_id: &str, org_id: &str, token: &str) -> String {
        let mak = AccessKey::new(user_id, org_id, token);
        format!("{}_{}_{}_{}", user_id, org_id, token, mak.bind_hash)
    }

    /// Create an AccessKey from already-hashed user_id, org_id, and hash component values.
    pub fn new(user_id: &str, org_id: &str, token: &str) -> AccessKey {
        let user_id = UserID::new(user_id);
        let org_id = OrgID::new(org_id);
        let token = Token::new(token);
        AccessKey {
            bind_hash: hex::encode(AccessKey::generate_hash(&user_id, &org_id, &token)),
            user_id,
            token,
            org_id,
        }
    }

    /// Create a hash from user_id, org_id, and token.
    fn generate_hash(user_id: &UserID, org_id: &OrgID, token: &Token) -> Vec<u8> {
        let mut hasher = Sha256::new();

        hasher.update(user_id.as_str().as_bytes());
        hasher.update(org_id.as_str().as_bytes());
        hasher.update(token.as_str().as_bytes());
        hasher.update(crypt::get_salt());

        let hash = &hasher.finalize()[..];

        // truncate to 8 bytes, 64 bits, 16 hex characters
        // even with 100,000 tokens, the odds of a collision are very low (2.71e-10)
        hash[0..8].to_vec()
    }

    /// Create a hash for this access key.
    fn hash(&self) -> Vec<u8> {
        AccessKey::generate_hash(&self.user_id, &self.org_id, &self.token)
    }

    /// Given a hex string, decode it to be used as a
    pub fn decode_hex_secret(secret_hex: &str) -> Result<Vec<u8>, FromHexError> {
        hex::decode(secret_hex.trim().as_bytes())
    }

    /// Get the access key's org_id.
    pub fn get_org_id(&self) -> &OrgID {
        &self.org_id
    }

    /// Get the access key's user_id.
    pub fn get_user_id(&self) -> &UserID {
        &self.user_id
    }

    /// Get the access key's token.
    pub fn get_token(&self) -> &Token {
        &self.token
    }

    /// Get the access key's bind hash.
    pub fn get_bind_hash(&self) -> &str {
        &self.bind_hash
    }

    /// Returns true if the "hash" component of the access key matches the hash of the UserID,
    /// OrgID, and secret.
    fn is_valid(&self) -> bool {
        hex::encode(self.hash()) == self.get_bind_hash()
    }
}

impl Display for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}_{}_{}_{}",
            self.user_id, self.org_id, self.token, self.bind_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::crypt::set_salt;

    use super::*;

    #[test]
    fn parse_valid_access_key() {
        set_salt(&[0; 8]);
        const MAK: &str = "ettin_1234_f1f2f3f4f5f6f7f8_b1f5bbdce806424d";
        let mak = AccessKey::try_from(MAK).unwrap();
        assert!(mak.is_valid());
        assert_eq!(
            mak,
            AccessKey {
                user_id: UserID::new("ettin"),
                org_id: OrgID::new("1234"),
                token: Token::new("f1f2f3f4f5f6f7f8"),
                bind_hash: "b1f5bbdce806424d".to_string(),
            }
        );
    }

    #[test]
    fn underscore_in_username() {
        set_salt(&[0; 8]);
        let s = "foo_bar_313131_b1b2b3b4b5b6b7b8_aacbb2869020bb9f";
        let mak = AccessKey::try_from(s).unwrap();
        assert_eq!(
            mak,
            AccessKey {
                user_id: UserID::new("foo_bar"),
                org_id: OrgID::new("313131"),
                token: Token::new("b1b2b3b4b5b6b7b8"),
                bind_hash: "aacbb2869020bb9f".to_string(),
            }
        );
    }

    #[test]
    fn missing_user_id() {
        assert!(AccessKey::try_from("_1234_ffff").is_err());
    }

    #[test]
    fn missing_org_id() {
        assert!(AccessKey::try_from("fingon__ffff").is_err());
    }

    #[test]
    fn missing_hash() {
        assert!(AccessKey::try_from("mim_1234_").is_err());
    }

    #[test]
    fn missing_all() {
        assert!(AccessKey::try_from("____").is_err());
    }

    #[test]
    fn completely_wrong() {
        assert!(AccessKey::try_from("abcd").is_err());
    }

    #[test]
    fn empty() {
        assert!(AccessKey::try_from("").is_err());
    }

    #[test]
    fn display() {
        set_salt(&[0; 8]);
        let mak = AccessKey::new("curufinwe", "586878", "aaaa");
        assert_eq!(&mak.to_string(), "curufinwe_586878_aaaa_cb3bf5052740b8e7");
    }

    #[test]
    fn hash() {
        set_salt(&[0; 8]);
        let mak = AccessKey::new("tinuviel", "88888", "9192939495969798");
        let hashed = mak.hash();
        assert_eq!(&hashed, &[218, 13, 194, 52, 24, 169, 153, 87]);
    }

    #[test]
    fn validity() {
        set_salt(&[0; 8]);
        let mak = AccessKey::new("cuivienen", "eaeaeaea", "f2f3f4f5f6f7f8f9");
        let hashed = mak.hash();
        assert_eq!(&hashed, &[213, 57, 88, 140, 45, 224, 186, 88]);
    }
}
