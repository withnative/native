//! `query::error` — typed local error categories for the query layer.
//!
//! Query contract code constructs these without depending on the root error.
//! The root crate owns the composition mapping into `native_ce::Error`.
//!
//! The variant set is deliberately minimal: only the categories query
//! actually produces today. Storage/encoding failures continue to flow
//! through `?` as root errors at the public read APIs — widening this enum
//! is extraction-phase work, not a prerequisite for one-way edges.

use super::sql_contract::QuerySqlErrorCategory;

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    /// A read-contract rule was violated (validation, paging, selector, or
    /// shape errors). Renders exactly the message the root `Error::engine`
    /// constructor previously carried.
    #[error("{0}")]
    Contract(String),
    /// A categorized `query_sql` failure. Renders the stable
    /// `query_sql [category]: detail` sentinel shape that
    /// `sql_contract::ensure_categorized` recognizes.
    #[error("query_sql [{}]: {detail}", category.as_str())]
    Sql {
        category: QuerySqlErrorCategory,
        detail: String,
    },
    /// JSON encoding failure while enforcing the encoded-parameter budget.
    /// Transparent rendering preserves the root's previous `Error::Json`
    /// message byte-for-byte.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl QueryError {
    pub fn contract(message: impl Into<String>) -> Self {
        QueryError::Contract(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_message_is_preserved_verbatim() {
        let error = QueryError::contract("tree max_depth must be >= 0");
        assert_eq!(error.to_string(), "tree max_depth must be >= 0");
    }

    #[test]
    fn sql_variant_renders_the_categorized_sentinel_shape() {
        let error = QueryError::Sql {
            category: QuerySqlErrorCategory::InvalidArguments,
            detail: "boom".into(),
        };
        let rendered = error.to_string();
        assert!(rendered.starts_with("query_sql ["));
        assert_eq!(
            rendered,
            format!(
                "query_sql [{}]: boom",
                QuerySqlErrorCategory::InvalidArguments.as_str()
            )
        );
    }
}
