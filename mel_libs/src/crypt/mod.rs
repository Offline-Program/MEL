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

//! Cryptographic features used by Mimir.

mod aes_param;

pub use aes_param::AESParam;

use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkcs5::pbkdf2_hmac,
    symm::{decrypt, encrypt, Cipher},
};
use sha2::Digest as _;
use std::sync::OnceLock;

/// The AES block size.  `128` implies AES-128.  Must be either 128, 192, or 256.
const AES_BLOCK_SIZE: usize = 128;

/// The AES block size, in bytes.
const AES_BLOCK_BYTES: usize = AES_BLOCK_SIZE / 8;

/// Problems when parsing hex strings for use in Mimir's AES encryption features.
#[derive(Debug)]
pub enum MimirAESHexProblem {
    /// An invalid hex character was encountered.
    InvalidHexCharacter {
        /// The invalid character.
        c: char,
        /// The index of the invalid char.
        index: usize,
    },
    /// The hex string was invalid due to having a non-even length.
    OddLength,
    /// The hex string was invalid due to being a length that doesn't match the AES block size.
    InvalidStringLength,
}

/// Returns the bytes for the AES IV.
/// Panics with a helpful error message if the IV provided during compilation is invalid.
pub fn iv() -> AESParam {
    // For our use case, a zeroed-out IV is adequate, confirmed by Simo.
    AESParam::new(&[0; AES_BLOCK_BYTES]).unwrap(/* won't panic so long as the array is AES_BLOCK_BYTES long */)
}

/// Try to decode a string slice into an AESParam.  Returns Err if the hex string is invalid hex,
/// or decodes to a length that doesn't match the AES block size in use by Mimir
/// (`AES_BLOCK_SIZE`).
pub fn try_decode_hex_aes_param(hex: &str) -> Result<AESParam, MimirAESHexProblem> {
    let mut buf = [0u8; AES_BLOCK_BYTES];
    hex::decode_to_slice(hex, &mut buf as &mut [u8]).map_err(
        |from_hex_err| match from_hex_err {
            hex::FromHexError::InvalidHexCharacter { c, index } => {
                MimirAESHexProblem::InvalidHexCharacter { c, index }
            }
            hex::FromHexError::OddLength => MimirAESHexProblem::OddLength,
            hex::FromHexError::InvalidStringLength => MimirAESHexProblem::InvalidStringLength,
        },
    )?;
    let param = AESParam::new(&buf);
    param.map_err(|_| MimirAESHexProblem::InvalidStringLength)
}

thread_local! {
    static MIMIR_SALT: OnceLock<Vec<u8>> = const { OnceLock::new() };
}

/// Override MIMIR_SALT.  For use in tests only.
pub fn set_salt(salt: &[u8]) {
    MIMIR_SALT.with(|shared_salt| shared_salt.set(salt.to_vec()).unwrap());
}

/// Get MIMIR_SALT.
pub fn get_salt() -> Vec<u8> {
    // MEL's build.rs verifies MIMIR_SALT's existence and length so it is not required here.  The
    // unused fallback will never be used provided ENCRYPT is "true".

    /// The salt to use if none is provided by the environment.
    const SALT_UNUSED_FALLBACK: &str = "0000000000000000";

    MIMIR_SALT.with(|shared_salt| {
        shared_salt
            .get_or_init(|| {
                let general_salt = option_env!("MIMIR_SALT").unwrap_or(SALT_UNUSED_FALLBACK);
                let nums = hex::decode(general_salt.trim()).unwrap();
                nums
            })
            .to_vec()
    })
}

/// Get MIMIR_SALT as a hex string.
pub fn get_salt_hex() -> String {
    hex::encode(get_salt())
}

/// Generate an AES key from a string (usually a MAK Token).  Returns None if _anything_ goes wrong with
/// key derivation.
// Change return type to Result if the error kind ever becomes important.
pub fn create_kek(phrase: &str) -> Option<AESParam> {
    /// Rounds of PBKDF2 to perform.
    const PBKDF2_ROUNDS: usize = 10;

    let hash = MessageDigest::sha256();
    let mut key = [0; AES_BLOCK_BYTES];

    pbkdf2_hmac(
        phrase.as_bytes(),
        &get_salt(),
        PBKDF2_ROUNDS,
        hash,
        &mut key,
    )
    .ok()?;

    AESParam::new(&key).ok()
}

/// Use the given key to encrypt the given payload.
pub fn enc(key: &AESParam, payload: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let encrypted = encrypt(
        Cipher::aes_128_ctr(),
        key.data(),
        Some(iv().data()),
        payload,
    );
    encrypted
}

/// Use the given key to decrypt the given payload.
pub fn dec(key: &AESParam, encrypted_payload: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let dek_dec = decrypt(
        Cipher::aes_128_ctr(),
        key.data(),
        Some(iv().data()),
        encrypted_payload,
    );
    dek_dec
}

/// Hash a string with sha256, truncate to `len` bytes, and return the hex representation.
pub fn hash_hex(val: &str, len: usize) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(get_salt());
    hasher.update(val.as_bytes());
    let hash = &hasher.finalize()[..len];

    hex::encode(hash)
}

#[cfg(test)]
mod crypt_tests {
    use super::*;

    #[test]
    fn create_kek_works() {
        set_salt(&[0; 8]);
        // MAK generated with:
        //   User ID: foo
        //    Org ID: bar
        //     Token: 1234123412341234
        //      SALT: 1111111111111111
        let mak = "foo_bar_1234123412341234_6637076bc17c1bfe";

        let expected = AESParam::new(&[
            118, 138, 190, 250, 54, 168, 16, 164, 167, 242, 13, 225, 211, 110, 203, 193,
        ])
        .unwrap();

        assert_eq!(create_kek(mak).unwrap().data(), expected.data());
    }

    #[test]
    fn aes_block_size_pin() {
        // This test is here to ensure that AES block size is not idly changed.  Changing it will
        // have a massive consequences, including invalidating all Mimir access keys in use by
        // users for all encrypted builds.

        assert_eq!(
            AES_BLOCK_SIZE, 128,
            "one does not simply change AES_BLOCK_SIZE"
        );
        assert_eq!(
            AES_BLOCK_BYTES, 16,
            "one does not simply change AES_BLOCK_BYTES"
        );
    }
}
