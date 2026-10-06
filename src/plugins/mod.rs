//! P1a plugin package pipeline (task `1bf0e85`).
//!
//! UNGATED by design: P1a is reachable from the default v1 alpha build, so
//! nothing here may sit behind `cfg(v2-kernel-probe)`. The gated
//! `crate::package_manifest` (`native.package-manifest@1`) is untouched;
//! the only shared code is `crate::canonical_json`.
//!
//! Submodules land incrementally: `manifest_v2` (S1, pure @2 manifest),
//! `import` (S2, host importer), `source_local` (S3, local-folder adapter),
//! `bridge_alpha` (S3, v1 bridge into alpha tabs).

pub mod bridge_alpha;
pub mod import;
pub mod manifest_v2;
pub mod source_local;

#[cfg(test)]
mod boundary_tests {
    /// Acceptance 8: P1a performs no network I/O. This scan is hygiene, not
    /// proof: the real guarantees are structural — the adapter takes only
    /// `&Path` (see `source_local::read_folder`), the importer only `&[u8]`
    /// maps, and the bridge returns install values without calling
    /// install/preview/adopt (plus the e2e consent test proving launch
    /// refuses `adoption_unverified` until fresh attested preview+adopt).
    /// Scanned files: the four implementation modules minus their
    /// `#[cfg(test)]` regions (test helpers may use `Command`/`tempfile`).
    /// This file is excluded: it holds the token lists themselves.
    const SOURCES: &[&str] = &[
        include_str!("manifest_v2.rs"),
        include_str!("import.rs"),
        include_str!("source_local.rs"),
        include_str!("bridge_alpha.rs"),
    ];

    /// Implementation code before the test module.
    fn implementation(source: &str) -> &str {
        match source.find("#[cfg(test)]") {
            Some(index) => &source[..index],
            None => source,
        }
    }

    const NETWORK_TOKENS: &[&str] = &[
        "reqwest",
        "hyper",
        "std::net",
        "tokio::net",
        "tokio::io",
        "TcpStream",
        "UdpSocket",
        "socket2",
        "mio",
        "curl",
        "isahc",
        // `surf::` with the trailing colons: bare `surf` collides with
        // `surface`, which P1a uses legitimately throughout.
        "surf::",
        "ureq",
        "http::",
        "std::process",
        "Command::new",
    ];

    /// Consent rule (D4): no path under `src/plugins/` may drive preview or
    /// adoption — every new digest needs a fresh human approval through the
    /// existing alpha tab path, and the bridge only returns install values.
    const CONSENT_TOKENS: &[&str] = &[
        "manage_alpha_tabs",
        "append_control_event",
        "AlphaTabAdopt",
        "with_verified_alpha_tab",
        "preview_authority",
        "do_install",
        "do_preview",
        "do_adopt",
    ];

    #[test]
    fn no_network_or_consent_path_references() {
        for source in SOURCES {
            let implementation = implementation(source);
            for token in NETWORK_TOKENS.iter().chain(CONSENT_TOKENS.iter()) {
                assert!(
                    !implementation.contains(token),
                    "src/plugins/ must not reference '{token}'"
                );
            }
        }
    }
}
