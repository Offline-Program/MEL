//! Offline virtual assistant.

use std::sync::OnceLock;

/// The name of the environment variable used to enable the offline virtual assistant.
const OFFLINE_VIRTUAL_ASSISTANT_ENV: &str = "OFFLINE_VIRTUAL_ASSISTANT";

/// Return whether the offline virtual assistant is enabled.  The check is case-sensitive: only
/// the exact value `"true"` is accepted.  Values like `"TRUE"`, `"True"`, or `"1"` will not
/// enable the assistant.
pub fn assistant_enabled() -> bool {
    static ASSISTANT_ENABLED: OnceLock<bool> = OnceLock::new();
    *ASSISTANT_ENABLED.get_or_init(|| check_env(OFFLINE_VIRTUAL_ASSISTANT_ENV))
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
        std::env::set_var(OFFLINE_VIRTUAL_ASSISTANT_ENV, "true");
        assert!(check_env(OFFLINE_VIRTUAL_ASSISTANT_ENV));
    }

    #[test]
    fn test_disabled_when_not_set() {
        std::env::remove_var(OFFLINE_VIRTUAL_ASSISTANT_ENV);
        assert!(!check_env(OFFLINE_VIRTUAL_ASSISTANT_ENV));
    }

    #[test]
    fn test_disabled_when_set_to_false() {
        std::env::set_var(OFFLINE_VIRTUAL_ASSISTANT_ENV, "false");
        assert!(!check_env(OFFLINE_VIRTUAL_ASSISTANT_ENV));
    }

    #[test]
    fn test_disabled_when_set_to_nonempty_non_true() {
        std::env::set_var(OFFLINE_VIRTUAL_ASSISTANT_ENV, "1");
        assert!(!check_env(OFFLINE_VIRTUAL_ASSISTANT_ENV));
    }

    #[test]
    fn test_disabled_when_set_to_uppercase_true() {
        std::env::set_var(OFFLINE_VIRTUAL_ASSISTANT_ENV, "TRUE");
        assert!(!check_env(OFFLINE_VIRTUAL_ASSISTANT_ENV));
    }
}
