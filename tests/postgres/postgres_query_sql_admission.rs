use native_ce::postgres::query_sql::validate;
use native_ce::query::sql_contract::{QuerySqlParameter, QuerySqlRequest};

fn request(sql: &str) -> QuerySqlRequest {
    QuerySqlRequest {
        sql: sql.into(),
        parameters: Vec::new(),
    }
}

#[test]
fn postgres_query_sql_closed_ast_admission_contract() {
    for sql in [
        "SELECT id, lower(name) FROM records WHERE name IS NOT NULL ORDER BY id LIMIT 10 OFFSET 1",
        "WITH chosen AS (SELECT id FROM records) SELECT count(*) FROM chosen",
        "SELECT row_number() OVER (ORDER BY id), id FROM records",
        "SELECT * FROM records WHERE id IN (SELECT record_id FROM facet_values)",
        "SELECT * FROM (VALUES (1), (2)) AS values_fixture(value)",
        "SELECT ARRAY[1,2] AS unsupported_array_output",
    ] {
        validate(&request(sql)).unwrap_or_else(|error| panic!("{sql}: {error}"));
    }
    for sql in [
        "SELECT * FROM pg_catalog.pg_roles",
        "SELECT * FROM public.records",
        "SELECT current_setting('role')",
        "SELECT 1 LIMIT current_setting('role')::int",
        "SELECT 1 OFFSET current_setting('role')::int",
        "SELECT sum(id) FILTER (WHERE current_setting('role')='x') FROM records",
        "SELECT sum(id) OVER (ORDER BY current_setting('role')) FROM records",
        "SELECT 1::pg_catalog.int4",
        "SELECT 1 OPERATOR(pg_catalog.+) 2",
        "SELECT id FROM records ORDER BY id USING OPERATOR(pg_catalog.<)",
        "SELECT * FROM records FOR UPDATE",
        "WITH records AS (SELECT 1) SELECT * FROM records",
        "WITH first AS (SELECT * FROM second), second AS (SELECT 1) SELECT * FROM first",
        "WITH outer_cte AS (WITH hidden AS (SELECT 1) SELECT * FROM hidden) SELECT * FROM hidden",
        "WITH RECURSIVE walk AS (SELECT * FROM walk) SELECT * FROM walk",
        "WITH changed AS (DELETE FROM records RETURNING id) SELECT * FROM changed",
        "SELECT * FROM records TABLESAMPLE SYSTEM (1)",
    ] {
        assert!(validate(&request(sql)).is_err(), "admitted {sql}");
    }
    let typed = QuerySqlRequest {
        sql: "SELECT $1::text FROM records WHERE id=$2".into(),
        parameters: vec![
            QuerySqlParameter::Text {
                value: Some("label".into()),
            },
            QuerySqlParameter::Text {
                value: Some("record".into()),
            },
        ],
    };
    validate(&typed).unwrap();
    let missing = QuerySqlRequest {
        sql: "SELECT $2 FROM records".into(),
        parameters: vec![QuerySqlParameter::Text {
            value: Some("x".into()),
        }],
    };
    assert!(validate(&missing).is_err());
}
