//! Consumer-neutral, read-only agent-sessions broker over the node's Unix
//! socket, backed by a local Paseo daemon connection.
//!
//! Slice 1 owns a separate daemon connection (`native-session-broker`), a
//! host table keyed by the hello `serverId` with a node-minted epoch per
//! connection, and five intercepted tools (capabilities/list/history/follow/
//! unfollow) that are never forwarded upstream. Push goes out as JSON-RPC
//! notifications on the connection that followed.

pub mod broker;
pub mod config;
pub mod daemon;
pub mod protocol;
pub mod remote;
pub mod routing;
#[cfg(test)]
pub(crate) mod test_support;

pub use config::load_agent_sessions;

/// True for the five intercepted tool names.
pub fn is_agent_sessions_tool(name: &str) -> bool {
    matches!(
        name,
        protocol::TOOL_CAPABILITIES
            | protocol::TOOL_LIST
            | protocol::TOOL_HISTORY
            | protocol::TOOL_FOLLOW
            | protocol::TOOL_UNFOLLOW
    )
}
