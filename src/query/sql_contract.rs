//! Compatibility and root-error facade for the extracted SQL contract.

pub use native_query_contract::sql_contract::*;

/// Construct a stable categorized `query_sql` error at the root composition
/// boundary. Adapters keep returning `native_ce::Error` through this facade.
pub fn categorized_error(category: QuerySqlErrorCategory, detail: impl AsRef<str>) -> crate::Error {
    native_query_contract::QueryError::Sql {
        category,
        detail: detail.as_ref().to_string(),
    }
    .into()
}

/// Keep backend-specific detail while ensuring every public tool failure has a
/// stable category. Unexpected setup/cleanup failures become `engine` at the
/// outer boundary.
pub fn ensure_categorized(error: crate::Error) -> crate::Error {
    let detail = error.to_string();
    if detail.starts_with("query_sql [") {
        error
    } else {
        categorized_error(QuerySqlErrorCategory::Engine, detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_profile_version_matches_the_linked_runtime() {
        assert_eq!(
            QuerySqlProfile::SqliteLocal.contract().dialect.version,
            rusqlite::version()
        );
    }

    #[test]
    fn root_error_facade_preserves_categorized_rendering() {
        let error = categorized_error(QuerySqlErrorCategory::InvalidArguments, "boom");
        assert_eq!(error.to_string(), "query_sql [invalid_arguments]: boom");
        assert_eq!(
            ensure_categorized(error).to_string(),
            "query_sql [invalid_arguments]: boom"
        );

        let uncategorized = crate::Error::engine("backend failed");
        assert_eq!(
            ensure_categorized(uncategorized).to_string(),
            "query_sql [engine]: backend failed"
        );
    }

    #[test]
    fn canonical_guide_tracks_contract_metadata() {
        let guide = include_str!("../mcp/guides/query-sql.md");
        let generated = render_guide_contract_markdown();
        assert!(guide.contains(&generated));

        let guide_contract = guide_contract();
        let capability = capability_contract(QuerySqlProfile::SqliteLocal);
        assert_eq!(capability.limits, guide_contract.limits);
        assert_eq!(capability.logical_catalog, guide_contract.logical_catalog);
        assert_eq!(capability.result_encoding, guide_contract.result_encoding);
        assert_eq!(capability.error_categories, guide_contract.error_categories);
        assert_eq!(capability.known_profiles, guide_contract.profiles);
    }
}
