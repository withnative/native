//! Storage- and runtime-independent contracts shared by Native's query
//! engines and adapters.
//!
//! This member deliberately owns no database handles, authorization provider,
//! MCP caller, realtime hub, projector, or backend adapter. The root crate
//! preserves its established public paths through thin facade modules.

mod error;
pub mod events;
pub mod principal;
pub mod sql_contract;

pub use error::QueryError;
pub use events::ContentInvalidation;
pub use principal::QueryPrincipal;

pub type Result<T> = std::result::Result<T, QueryError>;
