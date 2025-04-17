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

//! TokenMap reads and writes a file of seeded tokens and adorns them with encrypted DEKs.

use anyhow::Context;
use csv::{ReaderBuilder, WriterBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{hash_map, HashMap},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

use crate::{
    access_key::components::Token,
    crypt::{create_kek, enc, AESParam},
};

/// TokenMap is a map of Tokens to EDEKs.  Tokens are pre-seeded into Mimir images in advance of
/// users' registering for an access key.  EDEKs are `None` at first, until an encrypted load step
/// takes place, where they become `Some`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenMap {
    /// Map Tokens to optional EDEKs.  EDEKs are None when the token has not been used to wrap the
    /// current build's DEK yet.
    token_map: HashMap<Token, Option<AESParam>>,
}

impl TokenMap {
    /// Create a new, empty TokenMap.
    pub fn new() -> TokenMap {
        TokenMap {
            token_map: HashMap::new(),
        }
    }

    /// Get an EDEK by its token.  The outer option is Some if the Token exists.  The inner Option
    /// is Some if the EDEK has been created.
    pub fn get(&self, token: &Token) -> Option<&Option<AESParam>> {
        self.token_map.get(token)
    }

    /// Add a token to the TokenMap list, with an optional EDEK.  If `edek` is `Some`, assign the an
    /// EDEK (encrypted data encryption key) to the given token.
    fn set(&mut self, token: &Token, edek: Option<AESParam>) {
        self.token_map.insert(token.clone(), edek);
    }

    /// Save this Token/EDEK map to disk as a tsv file.
    pub fn save(&self, tsv_path: &Path) -> anyhow::Result<()> {
        /// Serialize tokenmap to tsv format.
        fn serialize_to_tsv<W: Write>(tm: &TokenMap, writer: W) -> anyhow::Result<()> {
            let mut wtr = WriterBuilder::new().delimiter(b'\t').from_writer(writer);

            for rec in tm.token_map.iter() {
                wtr.serialize(rec).with_context(|| {
                    format!(
                        "Couldn't serialize token '{}' with edek '{:?}'",
                        rec.0, rec.1
                    )
                })?;
            }

            wtr.flush()?;
            Ok(())
        }

        let tsv_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(tsv_path)?;

        serialize_to_tsv(self, tsv_file)
    }

    /// Load a tsv file containing tokens.  Returns None if deserialization fails for any reason.
    pub fn load(tsv_path: &Path) -> anyhow::Result<TokenMap> {
        /// Deserialize the tsv.
        fn deserialize_from_tsv<R: Read>(reader: R) -> anyhow::Result<TokenMap> {
            let mut rdr = ReaderBuilder::new()
                .delimiter(b'\t')
                .has_headers(false)
                .from_reader(reader);

            // turn the deserialized iter into an TokenMap
            // TODO: refactor this to emit a error type that MEL can intercept and map to its own MelError type (see CPOFF-1674)
            let tm = TokenMap::from_iter(rdr.deserialize().filter_map(|rec| rec.ok()));

            Ok(tm)
        }

        let tsv_file = File::open(tsv_path)?;

        deserialize_from_tsv(tsv_file)
    }

    /// Load a plaintext tokens file, which is formatted the same way as the two-column tsv, but
    /// with only one column, so essentially just a text file.
    pub fn load_plaintext(tsv_path: &Path) -> anyhow::Result<TokenMap> {
        let f = File::open(tsv_path)?;
        let reader = BufReader::new(f);

        let mut tm = TokenMap::new();

        for line in reader.lines() {
            let token = Token::new(&line?);
            tm.set(&token, None);
        }

        Ok(tm)
    }

    /// Given a DEK, encrypt it with each user's KEK and update the TokenMap's the new EDEK.
    pub fn wrap_dek(&mut self, dek: &AESParam) {
        for token_map in self.token_map.iter_mut() {
            if let Some(kek) = create_kek(token_map.0.as_str()) {
                if let Ok(edek) = enc(&kek, dek.data()) {
                    let edek = AESParam::new(&edek);
                    *token_map.1 = edek.ok();
                }
            }
        }
    }

    /// Hash the token values so they're not so easy to associate with the token component of an
    /// access key.
    pub fn hash_tokens(&mut self) {
        let mut hashed_tokens = HashMap::new();

        for (token, aes_param) in self.token_map.drain() {
            hashed_tokens.insert(token.hash(), aes_param);
        }

        self.token_map = hashed_tokens;
    }

    /// Returns an iterator over the token / edek pairs.
    pub fn iter(&self) -> hash_map::Iter<Token, Option<AESParam>> {
        self.token_map.iter()
    }

    /// Returns the number of tokens.
    pub fn len(&self) -> usize {
        self.token_map.len()
    }

    /// Returns `true` if there are no tokens.
    pub fn is_empty(&self) -> bool {
        self.token_map.is_empty()
    }

    /// Check validity of the TokenMap.  Returns `Ok` if the TokenMap is valid, otherwise returns
    /// `Err` containing information about the validity problem.
    pub fn validate(&self) -> Result<(), InvalidTokenMap> {
        use InvalidTokenMap::*;
        const MIN_VALID_TOKEN_COUNT: usize = 8;

        if self.is_empty() {
            Err(Empty)
        } else if self.len() < MIN_VALID_TOKEN_COUNT {
            Err(Meager {
                actual: self.len(),
                expected_min: MIN_VALID_TOKEN_COUNT,
            })
        } else {
            Ok(())
        }
    }
}

/// TokenMap validity problems.
#[derive(Debug)]
pub enum InvalidTokenMap {
    /// TokenMap is empty.
    Empty,
    /// TokenMap has very few records and is probably incomplete.
    Meager {
        /// The actual number of tokens.
        actual: usize,
        /// The expected minimum number of tokens.
        expected_min: usize,
    },
}

// For converting the deserialized iterator into TokenMap.
impl FromIterator<(Token, Option<AESParam>)> for TokenMap {
    fn from_iter<T: IntoIterator<Item = (Token, Option<AESParam>)>>(iter: T) -> Self {
        let mut tm = TokenMap::new();
        iter.into_iter()
            .for_each(|(token, edek): (Token, Option<AESParam>)| tm.set(&token, edek));
        tm
    }
}

impl Default for TokenMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        access_key::AccessKey,
        crypt::{dec, set_salt},
    };

    use super::*;

    #[test]
    fn save_load() {
        use std::env::temp_dir;
        use std::process::Command;

        set_salt(&[0; 8]);

        let time =
            String::from_utf8(Command::new("date").arg("+%s").output().unwrap().stdout).unwrap();
        let time = time.trim();

        let tokens_dir = temp_dir().join("mimir").join("token_map_load_test");
        let tokens_file = tokens_dir.join(format!("tokens-test-{time}"));
        std::fs::create_dir_all(&tokens_dir).unwrap();

        let mut tm = TokenMap::new();

        let token = Token::new("fefefefefefefefe");

        tm.set(
            &token,
            AESParam::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).ok(),
        );
        // serialize
        tm.save(&tokens_file).unwrap();

        // deserialize
        let tm = TokenMap::load(&tokens_file).unwrap();

        assert_eq!(
            tm.get(&token).unwrap(),
            &Some(AESParam::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).unwrap())
        );
    }

    #[test]
    fn load_no_tabs() {
        // test loading a file with no tabs (a single-column tsv, if that makes sense)
        let tokens_file = Path::new("src/token_map/tests/single_column_tokens");

        let tm = TokenMap::load_plaintext(tokens_file).unwrap();

        assert_eq!(tm.len(), 5);
    }

    #[test]
    fn paywall_security_e2e_test() {
        set_salt(&[0; 8]);

        // create access key from user id and org id and token

        let user_id = "beleg";
        let org_id = "123456";
        let token_hex = "0123456789abcdef";
        let token = Token::new(token_hex);

        let access_key = AccessKey::new(user_id, org_id, token_hex);

        assert_eq!(
            access_key.to_string(),
            "beleg_123456_0123456789abcdef_6c91532a31304197".to_string()
        );

        // create a TokenMap list
        let mut tm = TokenMap::new();
        tm.set(&token, None);

        // generate dek
        let dek = AESParam::new(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).unwrap();

        // generate content
        let content = "hello world";

        // encrypt content with dek
        let encrypted_content = enc(&dek, content.as_bytes()).unwrap();

        // wrap dek
        tm.wrap_dek(&dek);

        // provide access key (as text)
        let edek = tm.get(&token).unwrap().as_ref().unwrap();

        // create kek from access key
        let kek = create_kek(token.as_str()).unwrap();

        // unwrap dek
        let decrypted_dek = dec(&kek, edek.data()).unwrap();

        assert_eq!(dek.data().to_vec(), decrypted_dek);

        // decrypt content with unwrapped dek
        let decrypted_content =
            dec(&AESParam::new(&decrypted_dek).unwrap(), &encrypted_content).unwrap();

        assert_eq!(decrypted_content, "hello world".as_bytes().to_vec());
    }
}
