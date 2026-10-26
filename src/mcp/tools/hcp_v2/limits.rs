//! Size bounds.

/// Largest entry this module will write, measured **encoded**: the length of
/// the entry's JSON text encoded again as a JSON string (every quote,
/// backslash and control character escaped), as it sits in an event payload.
/// It is a quarter of Native SQL's 256 KiB encoded-cell bound, and the bound
/// the control event validation enforces
/// ([`crate::control::HCP_ENTRY_MAX_ENCODED_BYTES`]), so an entry that fits
/// here can always be appended.
pub(super) const MAX_ENTRY_BYTES: usize = crate::control::HCP_ENTRY_MAX_ENCODED_BYTES;

/// Whether a serialized entry is within the bound, measured encoded.
pub(super) fn fits(body: &str) -> bool {
    crate::control::hcp_entry_fits(body)
}

/// Longest preference (the statement) a client or the person may write.
pub(super) const MAX_PREFERENCE_BYTES: usize = 8 * 1024;
/// Longest short text field: a dimension, a purpose, a reason.
pub(super) const MAX_SHORT_TEXT_BYTES: usize = 2 * 1024;
