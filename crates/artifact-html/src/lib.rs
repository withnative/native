//! HTML artifact surface: the sanitizer/launch pipeline (`html`) and the
//! external verifier client (`verify`).
//!
//! This crate is storage-independent by construction: it never sees a
//! database handle, authorization state, or the event log. The DB-aware
//! artifact host stays in `native-ce` (`src/mcp/tools/artifacts.rs`) and
//! consumes these modules through the root's re-export shims, so public
//! `native_ce::artifact_html::*` / `native_ce::artifact_verify::*` paths
//! are unchanged.
//!
//! Failures carry a message only; the root crate maps [`Error`] into its
//! own engine error at the composition boundary (one `From` impl in
//! `src/error.rs`), mirroring the `native-artifact-runtime` precedent.

pub mod html;
pub mod verify;

/// A message-carrying failure from the HTML artifact surface.
///
/// The `engine` constructor mirrors the root error's constructor shape so
/// the moved modules read identically to their in-root history; rendered
/// messages are byte-identical.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub fn engine(message: impl Into<String>) -> Self {
        Error(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
