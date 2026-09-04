use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use serde_json::{json, Value};

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic.
/// `program-missing-runtime`
const PROGRAM_MISSING_RUNTIME: &str = "700c9000-0000-4000-8000-000000000001";
/// `program-wrong-runtime`
const PROGRAM_WRONG_RUNTIME: &str = "700c9000-0000-4000-8000-000000000002";
/// `program-unknown-kind`
const PROGRAM_UNKNOWN_KIND: &str = "700c9000-0000-4000-8000-000000000003";
/// `program-recipe`
const PROGRAM_RECIPE: &str = "700c9000-0000-4000-8000-000000000004";
/// `ordinary-document`
const ORDINARY_DOCUMENT: &str = "700c9000-0000-4000-8000-000000000005";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), Caller::local(), tool, args).await
}

#[tokio::test]
async fn program_kinds_require_their_exact_declared_interpreters() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();

    let missing = call(&registry, &db, "create_record", json!({
        "id":PROGRAM_MISSING_RUNTIME,"type":"Program","kind":"recipe","body":"summarize changes",
        "reason":"Prove Program interpreter admission."
    })).await.unwrap_err().to_string();
    assert!(
        missing.contains("requires declared interpreter 'native.recipe.v1'"),
        "{missing}"
    );

    let wrong = call(&registry, &db, "create_record", json!({
        "id":PROGRAM_WRONG_RUNTIME,"type":"Program","kind":"module","body":"export const nativeModule = {}",
        "facets":{"runtime":"native.mdx.v1"},"reason":"Prove exact module interpreter admission."
    })).await.unwrap_err().to_string();
    assert!(
        wrong.contains("requires declared interpreter 'native.mdx.v2'"),
        "{wrong}"
    );

    let unknown = call(&registry, &db, "create_record", json!({
        "id":PROGRAM_UNKNOWN_KIND,"type":"Program","kind":"workflow","body":"run",
        "facets":{"runtime":"native.recipe.v1"},"reason":"Prove unsupported Program kinds fail closed."
    })).await.unwrap_err().to_string();
    assert!(
        unknown.contains("unsupported Program kind 'workflow'"),
        "{unknown}"
    );

    let recipe = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id":PROGRAM_RECIPE,"type":"Program","kind":"recipe","body":"summarize changes",
            "facets":{"runtime":"native.recipe.v1"},"reason":"Create the governed recipe carrier."
        }),
    )
    .await
    .unwrap();
    assert_eq!(recipe["type"], "Program");
    assert_eq!(recipe["kind"], "recipe");

    let remove_runtime = call(&registry, &db, "update_record", json!({
        "id":PROGRAM_RECIPE,"facets":{"runtime":null},"reason":"Prove interpreter removal fails."
    })).await.unwrap_err().to_string();
    assert!(
        remove_runtime.contains("requires declared interpreter 'native.recipe.v1'"),
        "{remove_runtime}"
    );

    db.close().await;
}

#[tokio::test]
async fn ordinary_updates_cannot_promote_documents_to_programs() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id":ORDINARY_DOCUMENT,"type":"Document","kind":"note","body":"content",
            "reason":"Create an immutable-type fixture."
        }),
    )
    .await
    .unwrap();
    let error = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id":ORDINARY_DOCUMENT,"type":"Program","reason":"Attempt a forbidden promotion."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unknown field `type`"), "{error}");
    db.close().await;
}
