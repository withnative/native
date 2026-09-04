//! Stamp the build's source revision into the binary (task 142e0d2; revised by
//! task 1205e69 to resolve from the environment only).
//!
//! `railway up` uploads a directory tarball and records no commit SHA, so the
//! platform cannot say what is running. Neither could the binary: `engine_info`
//! reported `CARGO_PKG_VERSION`, which is `0.0.0`. The stamp makes the artifact
//! self-identifying on the deploy paths where provenance matters.
//!
//! Resolution order, first hit wins:
//!
//!   1. `NATIVE_CE_GIT_SHA`      — explicit, and what the Dockerfile passes.
//!      `.git/` is in `.dockerignore`, so inside the image this is the ONLY
//!      path that works.
//!   2. `RAILWAY_GIT_COMMIT_SHA` — injected by Railway when the service builds
//!      from a connected GitHub repo.
//!   3. `"dev"`                  — everything else, deliberately including
//!      local builds inside a git repository.
//!
//! The first revision of this script interrogated git directly and watched
//! HEAD, the current branch ref, and packed-refs so the stamp could follow
//! commits. That coupling had a cost out of all proportion to its value:
//! `src/lib.rs` consumes the stamp through `env!`, so every commit changed the
//! stamped value and invalidated the entire root library — a full recompile
//! and a relink of every binary with zero source change, in every worktree,
//! on every commit. Both real deploy paths set the variable explicitly, so
//! the git interrogation only ever fed local `engine_info` output. `"dev"`
//! says exactly what a local binary is; the repository, not the binary, is
//! the authority on local provenance.
//!
//! The two `rerun-if-env-changed` directives below are the script's complete
//! input set: with no `rerun-if-changed` paths, the script reruns only when a
//! stamp source actually changes (or when this file itself is edited, which
//! cargo always tracks). Builds — and commits — no longer touch it.
//!
//! Nothing here goes near the frozen DDL. `FROZEN_DDL_SHA256` fingerprints
//! `src/schema/ddl.rs` only; a per-build value reaching that surface would make
//! `frozen-ddl` unreproducible, which is the one thing this must not do.

fn main() {
    // The isolated cloud qualification package compiles the shared Turso
    // adapter under this private cfg; declaring it here keeps ordinary root
    // builds warning-free without enabling the cloud path.
    println!("cargo:rustc-check-cfg=cfg(turso_cloud_contract)");
    println!("cargo:rerun-if-env-changed=NATIVE_CE_GIT_SHA");
    println!("cargo:rerun-if-env-changed=RAILWAY_GIT_COMMIT_SHA");

    let revision = resolve_revision();
    // The local standby refuses to serve unless it can observe a 40-character
    // lowercase hex source identity in its own bytes, because that identity is
    // a compatibility-gate input pinned by the snapshot manifest. A "dev" stamp
    // is correct for ordinary local builds and fatal for a standby artifact, and
    // the difference used to be invisible until first run. Say so at build time.
    if !is_full_commit_sha(&revision) {
        println!(
            "cargo:warning=NATIVE_CE_GIT_SHA is {revision:?}, not a 40-character commit SHA. \
             This is fine for ordinary builds, but a standby artifact built this way cannot \
             serve: it will start in status-only mode and refuse every snapshot-backed read. \
             Set NATIVE_CE_GIT_SHA to the full commit SHA when packaging the standby."
        );
    }
    println!("cargo:rustc-env=NATIVE_CE_GIT_SHA={}", short(&revision));
    println!("cargo:rustc-env=NATIVE_CE_FULL_GIT_SHA={revision}");
}

fn resolve_revision() -> String {
    for key in ["NATIVE_CE_GIT_SHA", "RAILWAY_GIT_COMMIT_SHA"] {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim();
            if !value.is_empty() {
                return value.to_ascii_lowercase();
            }
        }
    }
    "dev".to_string()
}

/// First 12 hex characters — unambiguous in practice, and short enough to read
/// in a log line. Anything that is not a plain hex sha is passed through intact
/// rather than truncated into nonsense.
fn short(sha: &str) -> String {
    let sha = sha.trim();
    if sha.len() > 12 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        sha[..12].to_string()
    } else {
        sha.to_string()
    }
}

/// A full lowercase commit SHA, the only stamp a standby artifact can serve on.
fn is_full_commit_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
