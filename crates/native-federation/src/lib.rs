//! Experimental Native federation runtime.
//!
//! The relay validates and stores already-encrypted profile envelopes. The
//! identity submodule owns account-scoped custody, principal lifecycle, and
//! eject/adoption continuity. Both currently target only
//! `native-fed/experimental-jose-hpke-1`; this is not a stable Rust API.

mod address;
pub mod authority;
pub mod crypto;
mod error;
pub mod identity;
pub mod relay;

pub use authority::{
    AuthenticatedCaller, DirectoryAuthority, PreverifiedSnapshotAuthority, PrincipalAddress,
};
pub use error::{Error, Result};
pub use identity::*;
pub use relay::{
    relay_router, CleanupReport, DeliveryNotifier, Relay, RelayClock, RelayConfig, RelayError,
    RelayLimits, RelaySigner, SystemClock,
};
