//! Root composition facade for the extracted query-contract error.

pub(crate) use native_query_contract::QueryError;

/// One-hop construction used across the query engine modules: a typed contract
/// violation mapped to the root error at this composition boundary.
pub(crate) fn contract_violation(message: impl Into<String>) -> crate::Error {
    QueryError::contract(message).into()
}
