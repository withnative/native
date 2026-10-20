//! Guard: production `Caller` constructions in `held/` must carry real hosting
//! context (design 08b4c21 §3, slice S0).
//!
//! Counter visibility is positive-proof and deny-by-default: a bare
//! `Caller::authenticated(..)` carries no hosting database, so it is a
//! non-owner. A hosted route that built its caller that way would silently
//! demote the workspace owner. Every production construction under `held/`
//! must therefore go through the verified hosted seam in one construction:
//! `with_verified_hosted_activity` attaches the hosting database and catalog
//! footing, and `with_hosting_owner` carries the real owner bit. Without the
//! second, a site is silently non-owner. Test-only fixtures are out of scope.
//! V2 instead uses `with_verified_hosted_v2_identity`, which requires the owner
//! bit in the same call after sealed kernel admission, without a v1 roster.
//!
//! Also banned in production `held/`: the test-only `with_hosting_context`
//! seam (it folds member footing for everyone), `Caller::member_copy` (a
//! member copy never serves from a hosted route) and `Caller::local_owner`
//! (the local-operator marker; a hosted route must not claim it).

use std::fs;
use std::path::{Path, PathBuf};

/// Test-only fixtures that deliberately build a bare authenticated caller with
/// no hosting plane, with the exact number of bare constructions each may hold.
/// A second bare construction in the same file fails the pin. Paths are
/// relative to the repository root.
const FIXTURE_ALLOWLIST: &[(&str, usize)] = &[("held/evidence/src/bin/mcp_executor_fixture.rs", 1)];

/// Directories under a crate's `src/` that hold test code only (the files of a
/// `#[cfg(test)] mod tests` declared in the parent module). Any other `tests`
/// directory under `src/` is scanned as production source. Paths are relative
/// to the repository root.
const TEST_ONLY_SOURCE_DIRS: &[&str] = &["held/runtime/src/tests", "held/hosting/src/http/tests"];

/// Constructions that must not appear in production `held/` source at all.
const BANNED_IN_PRODUCTION: &[&str] = &[
    "with_hosting_context(",
    "Caller::member_copy(",
    "Caller::local_owner(",
];

fn rust_sources(repository_root: &Path, root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if path.is_dir() {
            // `target` is build output (which can hold vendored sources) and
            // dot-directories are tooling; walking them makes the scan non-
            // deterministic across a clean checkout and a built tree. A
            // crate's own `tests/` directory (a sibling of its Cargo.toml) is
            // cargo integration tests; the listed `src/` test directories hold
            // test modules. Every other `tests` directory is scanned.
            let relative = path.strip_prefix(repository_root).unwrap();
            let integration_tests = name == "tests"
                && path
                    .parent()
                    .is_some_and(|parent| parent.join("Cargo.toml").is_file());
            let test_only_source = TEST_ONLY_SOURCE_DIRS
                .iter()
                .any(|dir| relative == Path::new(dir));
            if integration_tests || test_only_source || name == "target" || name.starts_with('.') {
                continue;
            }
            rust_sources(repository_root, &path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

/// The production prefix of a source file: everything before the first
/// `#[cfg(test)] mod` test module. In this tree every test module is the tail
/// of its file, so this bounds production source. Only a `mod` item is treated
/// as the boundary, so a `#[cfg(test)]` helper item does not truncate the scan.
fn production_prefix(source: &str) -> &str {
    const MARKER: &str = "#[cfg(test)]";
    let mut search = 0;
    while let Some(relative) = source[search..].find(MARKER) {
        let index = search + relative;
        let after = source[index + MARKER.len()..].trim_start();
        if after.starts_with("mod ") || after.starts_with("pub mod ") {
            return &source[..index];
        }
        search = index + MARKER.len();
    }
    source
}

#[test]
fn production_held_authenticated_callers_attach_hosting_context() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in TEST_ONLY_SOURCE_DIRS {
        assert!(
            repository_root.join(dir).is_dir(),
            "TEST_ONLY_SOURCE_DIRS names a directory that no longer exists: {dir}"
        );
    }
    let root = repository_root.join("held");
    let mut files = Vec::new();
    rust_sources(repository_root, &root, &mut files);
    let mut violations = Vec::new();
    for path in files {
        let relative = path.strip_prefix(repository_root).unwrap();
        let allowed_bare = FIXTURE_ALLOWLIST
            .iter()
            .find(|(allowed, _)| relative == Path::new(allowed))
            .map(|(_, count)| *count);
        let source = fs::read_to_string(&path).unwrap();
        // Test-only code is out of scope; a new production caller must be
        // added above the file's tail test module.
        let production = production_prefix(&source);
        let line_of = |index: usize| production[..index].matches('\n').count() + 1;
        let mut bare = 0;
        let mut rest = production;
        let mut offset = 0;
        while let Some(index) = rest.find("Caller::authenticated(") {
            let statement_end = rest[index..]
                .find(';')
                .map(|end| index + end)
                .unwrap_or(rest.len());
            let statement = &rest[index..statement_end];
            if allowed_bare.is_some() {
                bare += 1;
            } else if statement.contains("with_verified_hosted_v2_identity(") {
                // This verified v2 seam requires the current role in its
                // signature and carries no fabricated v1 activity roster.
            } else if !statement.contains("with_verified_hosted_activity(") {
                violations.push(format!(
                    "{}:{} lacks with_verified_hosted_activity(",
                    relative.display(),
                    line_of(offset + index)
                ));
            } else if !statement.contains("with_hosting_owner(") {
                violations.push(format!(
                    "{}:{} lacks with_hosting_owner( in the same construction",
                    relative.display(),
                    line_of(offset + index)
                ));
            }
            let next = (statement_end + 1).min(rest.len());
            offset += next;
            rest = &rest[next..];
        }
        if let Some(allowed) = allowed_bare {
            if bare != allowed {
                violations.push(format!(
                    "{} holds {bare} bare Caller::authenticated( constructions; the fixture allowlist permits {allowed}",
                    relative.display()
                ));
            }
        }
        for banned in BANNED_IN_PRODUCTION {
            let mut from = 0;
            while let Some(found) = production[from..].find(banned) {
                let index = from + found;
                violations.push(format!(
                    "{}:{} uses {banned} in production source",
                    relative.display(),
                    line_of(index)
                ));
                from = index + banned.len();
            }
        }
    }
    assert!(
        violations.is_empty(),
        "production held/ callers must be built through with_verified_hosted_activity plus \
         with_hosting_owner(real role), and must not use the banned seams: {violations:#?}"
    );
}
