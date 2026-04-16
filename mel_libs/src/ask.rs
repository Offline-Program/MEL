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

//! Handler functions for enabling Ask Red Hat Offline, conversational search.

use std::sync::OnceLock;

/// The name of the environment variable used to enable the Ask Red Hat offline conversational
/// search.
pub const ASK_ENV: &str = "ASK_RED_HAT_OFFLINE";

/// Return whether the offline conversational search is enabled.  The check is case-sensitive: only
/// the exact value `"true"` is accepted.  Values like `"TRUE"`, `"True"`, or `"1"` will not
/// enable the feature.
pub fn ask_enabled() -> bool {
    static ASK_ENABLED: OnceLock<bool> = OnceLock::new();
    *ASK_ENABLED.get_or_init(|| check_env(ASK_ENV))
}

/// Checks whether an environment variable is equal to "true".
fn check_env(env_name: &str) -> bool {
    matches!(std::env::var(env_name), Ok(e) if e == "true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enabled_when_set_to_true() {
        std::env::set_var(ASK_ENV, "true");
        assert!(check_env(ASK_ENV));
    }

    #[test]
    fn test_disabled_when_not_set() {
        std::env::remove_var(ASK_ENV);
        assert!(!check_env(ASK_ENV));
    }

    #[test]
    fn test_disabled_when_set_to_false() {
        std::env::set_var(ASK_ENV, "false");
        assert!(!check_env(ASK_ENV));
    }

    #[test]
    fn test_disabled_when_set_to_nonempty_non_true() {
        std::env::set_var(ASK_ENV, "1");
        assert!(!check_env(ASK_ENV));
    }

    #[test]
    fn test_disabled_when_set_to_uppercase_true() {
        std::env::set_var(ASK_ENV, "TRUE");
        assert!(!check_env(ASK_ENV));
    }
}
