//! Transport-neutral dispatch seam for a resolved federated lens.
//!
//! The MCP protocol and executor depend on this capability rather than the
//! hosted catalogue/router implementation that resolves a lens.

use futures::future::BoxFuture;
use serde_json::{Map, Value};

use super::{ResolvedToolExposure, ToolRegistry};

/// Operations required to expose one already-authorized lens through MCP.
#[doc(hidden)]
pub trait LensDispatch: Send + Sync {
    fn exposure_policy(&self, registry: &ToolRegistry) -> ResolvedToolExposure;

    fn tools_list(&self, registry: &ToolRegistry, modern: bool) -> crate::Result<Value>;

    fn run_context<'a>(
        &'a self,
        registry: &'a ToolRegistry,
        arguments: &'a Value,
    ) -> BoxFuture<'a, Value>;

    fn tools_call<'a>(
        &'a self,
        registry: &'a ToolRegistry,
        params: &'a Map<String, Value>,
        modern: bool,
    ) -> BoxFuture<'a, std::result::Result<Value, (i64, String)>>;

    /// Authoritative revision used to pin executor descriptors for this lens.
    fn revision(&self) -> i64;
}
