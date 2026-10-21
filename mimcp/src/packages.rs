// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) Red Hat, Inc.

//! Parsing of raw package strings into structured rows.
//!
//! The index stores an advisory's packages as opaque NVRA strings
//! (`name-version-release.arch`, optionally suffixed `.rpm`), so
//! `list_advisory_packages` splits them at response time. Upstream sources the
//! same tool from RHSM, which additionally carries a checksum, repository tags
//! and a per-package summary; none of those exist offline, so those fields are
//! always null.

/// The parts of a package string that can be recovered from an NVRA.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Nvra {
    /// Package name.
    pub name: Option<String>,
    /// Package version, with any epoch prefix removed.
    pub version: Option<String>,
    /// Package release.
    pub release: Option<String>,
    /// Package architecture.
    pub architecture: Option<String>,
}

/// Returns `true` if `token` looks like an RPM architecture: a short run of
/// alphanumerics and underscores. This is deliberately shape-based rather than
/// an allowlist, so new architectures parse without a code change; the cost is
/// that a version-like trailing segment could be misread, which the dash check
/// in [`parse_nvra`] guards against.
fn is_arch(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 16
        && token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && token.chars().any(|c| c.is_ascii_alphabetic())
}

/// Strips an `epoch:` prefix from a version, e.g. `1:2.17.0` -> `2.17.0`.
fn strip_epoch(version: &str) -> &str {
    match version.split_once(':') {
        Some((epoch, rest)) if epoch.chars().all(|c| c.is_ascii_digit()) && !epoch.is_empty() => {
            rest
        }
        _ => version,
    }
}

/// Splits a package string into name, version, release and architecture.
///
/// Parsing is best-effort: anything that does not look like an NVRA yields the
/// whole string as [`Nvra::name`] with the other parts unset, so an unexpected
/// upstream format degrades to a usable row rather than an error.
pub fn parse_nvra(raw: &str) -> Nvra {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Nvra::default();
    }

    // `.rpm` is optional in the stored strings; drop it before looking for the
    // architecture so `...x86_64.rpm` and `...x86_64` parse identically.
    let body = trimmed
        .strip_suffix(".rpm")
        .or_else(|| trimmed.strip_suffix(".RPM"))
        .unwrap_or(trimmed);

    let fallback = || Nvra {
        name: Some(trimmed.to_owned()),
        ..Nvra::default()
    };

    // Architecture is the final dot-separated segment, but only when it looks
    // like one: `log4j-2.17.0` has a trailing `0` segment that must not be
    // mistaken for an arch.
    let (rest, architecture) = match body.rsplit_once('.') {
        Some((rest, arch)) if is_arch(arch) && !arch.contains('-') => (rest, Some(arch.to_owned())),
        _ => (body, None),
    };

    // Everything before the arch is `name-version-release`; name may itself
    // contain dashes, so split from the right.
    let Some((name_version, release)) = rest.rsplit_once('-') else {
        return fallback();
    };
    let Some((name, version)) = name_version.rsplit_once('-') else {
        return fallback();
    };
    if name.is_empty() || version.is_empty() || release.is_empty() {
        return fallback();
    }

    Nvra {
        name: Some(name.to_owned()),
        version: Some(strip_epoch(version).to_owned()),
        release: Some(release.to_owned()),
        architecture,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nvra(name: &str, version: &str, release: &str, arch: Option<&str>) -> Nvra {
        Nvra {
            name: Some(name.to_owned()),
            version: Some(version.to_owned()),
            release: Some(release.to_owned()),
            architecture: arch.map(str::to_owned),
        }
    }

    #[test]
    fn parses_a_plain_nvra() {
        assert_eq!(
            parse_nvra("log4j-2.17.0-1.el8.noarch"),
            nvra("log4j", "2.17.0", "1.el8", Some("noarch"))
        );
        assert_eq!(
            parse_nvra("kernel-4.18.0-305.el8.x86_64"),
            nvra("kernel", "4.18.0", "305.el8", Some("x86_64"))
        );
    }

    #[test]
    fn keeps_dashes_inside_the_package_name() {
        assert_eq!(
            parse_nvra("java-1.8.0-openjdk-1.8.0.312.b07-2.el8_5.x86_64"),
            nvra(
                "java-1.8.0-openjdk",
                "1.8.0.312.b07",
                "2.el8_5",
                Some("x86_64")
            )
        );
    }

    #[test]
    fn handles_src_and_rpm_suffix() {
        assert_eq!(
            parse_nvra("openssl-1.1.1k-5.el8.src"),
            nvra("openssl", "1.1.1k", "5.el8", Some("src"))
        );
        assert_eq!(
            parse_nvra("openssl-1.1.1k-5.el8.src.rpm"),
            nvra("openssl", "1.1.1k", "5.el8", Some("src"))
        );
    }

    #[test]
    fn strips_an_epoch_from_the_version() {
        assert_eq!(
            parse_nvra("bash-1:5.1.8-2.el9.x86_64"),
            nvra("bash", "5.1.8", "2.el9", Some("x86_64"))
        );
        // A non-numeric prefix is part of the version, not an epoch.
        assert_eq!(strip_epoch("v1:2"), "v1:2");
    }

    #[test]
    fn missing_architecture_still_parses_name_version_release() {
        assert_eq!(
            parse_nvra("log4j-2.17.0-1"),
            nvra("log4j", "2.17.0", "1", None)
        );
    }

    #[test]
    fn a_trailing_numeric_segment_is_not_mistaken_for_an_arch() {
        // `0` has no alphabetic character, so it stays part of the release.
        assert_eq!(
            parse_nvra("log4j-2.17.0-1.el8.0"),
            nvra("log4j", "2.17.0", "1.el8.0", None)
        );
    }

    #[test]
    fn strings_without_enough_dashes_degrade_to_a_bare_name() {
        // Fewer than two dashes cannot be an NVRA, so the whole string is kept
        // as the name rather than being mangled into empty parts.
        for raw in ["single", "two-parts", "-leading", "trailing-"] {
            let parsed = parse_nvra(raw);
            assert_eq!(parsed.name.as_deref(), Some(raw), "input {raw:?}");
            assert_eq!(parsed.version, None, "input {raw:?}");
            assert_eq!(parsed.release, None, "input {raw:?}");
        }

        assert_eq!(parse_nvra(""), Nvra::default());
        assert_eq!(parse_nvra("   "), Nvra::default());
    }

    #[test]
    fn any_three_dash_separated_string_parses_as_an_nvra() {
        // There is no way to tell `not-an-nvra` from a real name-version-release,
        // so it parses rather than being rejected. Package strings in the index
        // are always NVRAs, so this is the useful behaviour.
        assert_eq!(parse_nvra("not-an-nvra"), nvra("not", "an", "nvra", None));
    }

    #[test]
    fn whitespace_is_trimmed_before_parsing() {
        assert_eq!(
            parse_nvra("  log4j-2.17.0-1.el8.noarch  "),
            nvra("log4j", "2.17.0", "1.el8", Some("noarch"))
        );
    }
}
