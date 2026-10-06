//! Refusal codes for the co-edit session core.

use std::fmt;

/// Refusal codes. The `as_str` spelling is the wire-stable contract —
/// it must match these exact strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusalCode {
    UndeclaredSession,
    Forbidden,
    RecordUnsupported,
    TooLarge,
    TooManyPeers,
    ForeignClientId,
    BadDocShape,
    RateLimited,
    AccessLost,
}

impl RefusalCode {
    /// Wire-stable string for this refusal code.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UndeclaredSession => "undeclared_session",
            Self::Forbidden => "forbidden",
            Self::RecordUnsupported => "record_unsupported",
            Self::TooLarge => "too_large",
            Self::TooManyPeers => "too_many_peers",
            Self::ForeignClientId => "foreign_client_id",
            Self::BadDocShape => "bad_doc_shape",
            // TODO(increment 4): rate limiting is not enforced yet; the
            // variant exists so the code surface is stable when it lands.
            Self::RateLimited => "rate_limited",
            // TODO(increment 4): access-loss tracking is not enforced yet;
            // same stability note as above.
            Self::AccessLost => "access_lost",
        }
    }
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused co-edit operation: a machine-readable code plus a
/// human-readable detail for logs (never AUTHORITATIVE on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Machine-readable refusal code.
    pub code: RefusalCode,
    /// Human-readable detail for server logs.
    pub detail: String,
}

impl Refused {
    #[must_use]
    pub fn new(code: RefusalCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Refused {}
