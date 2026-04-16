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
