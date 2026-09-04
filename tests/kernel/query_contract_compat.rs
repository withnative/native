//! Compile-time and wire compatibility for the extracted query contracts.

#[test]
fn established_query_contract_paths_compile_and_share_the_same_types() {
    use native_ce::query::sql_contract::*;

    let top_level = native_ce::query::QueryPrincipal::authenticated("alice");
    let nested: native_ce::query::principal::QueryPrincipal = top_level.clone();
    assert_eq!(nested.credential(), "alice");
    assert!(!nested.trusted_local_bypass());

    let _: QuerySqlLimits = LIMITS;
    let _: QuerySqlProfileContract = QuerySqlProfile::SqliteLocal.contract();
    assert_eq!(MAX_ROWS, 1_000);

    let via_query = native_ce::query::events::ContentInvalidation {
        local_seq: 7,
        id: "evt-1".into(),
        record_id: "rec-1".into(),
        event_type: "record.updated".into(),
        created_at: "2026-08-12T00:00:00Z".into(),
    };
    let via_realtime: native_ce::realtime::ContentInvalidation = via_query;
    let value = serde_json::to_value(via_realtime).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "local_seq": 7,
            "id": "evt-1",
            "record_id": "rec-1",
            "type": "record.updated",
            "created_at": "2026-08-12T00:00:00Z"
        })
    );
}
