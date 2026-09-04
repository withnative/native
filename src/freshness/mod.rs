//! Experimental agent-speed context-freshness kernel.
//!
//! Unit/Revision/Occurrence plus the internal Receipt-driven runtime. Public
//! tools and UI remain deliberately out of scope while the contract calibrates.

#[cfg(feature = "experimental-agent-intents")]
mod agent_intents;
mod domain;
mod kernel;
mod runtime;

#[cfg(feature = "experimental-agent-intents")]
pub use agent_intents::*;
pub use domain::*;
pub use kernel::*;
pub use runtime::*;
