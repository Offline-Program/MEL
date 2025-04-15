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

use mel_libs::access_key::AccessKey;
use std::{env, process};

fn main() {
    validate_crypt_env("MIMIR_SALT", 16);
}

fn validate_crypt_env(env_name: &str, env_len: usize) {
    println!("cargo:rerun-if-env-changed=ENCRYPT");

    // if ENCRYPT is true, validate the env var; otherwise ignore it
    if env::var("ENCRYPT").is_ok_and(|e| e.trim() == "true") {
        println!("cargo:rerun-if-env-changed={env_name}");
        if let Ok(env_val) = env::var(env_name) {
            if let Err(err) = AccessKey::decode_hex_secret(&env_val) {
                eprintln!(
                    "Invalid environment variable {env_name}: hex decoding failed due to: {err}"
                );
                process::exit(1);
            }
            if env_val.len() != env_len {
                eprintln!("Invalid environment variable {env_name}: please set it to a {env_len}-character hex string in order to build MEL");
                process::exit(1);
            }
        } else {
            eprintln!("Missing environment variable {env_name}: please set it to a {env_len}-character hex string in order to build MEL");
            process::exit(1);
        }
    }
}
