//! CI guard for the authoritative policy write funnel.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn normalized(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn without_query_sql_test_fixture_writes(relative: &Path, source: &str) -> String {
    let normalized_source = normalized(source);
    if relative != Path::new("src/turso_local.rs") {
        return normalized_source;
    }

    // These writes seed only query_sql's feature-gated authorization fixtures.
    // The two-principal seeds interpolate pinned UUID consts rather than naming
    // ids inline: the record-id rule admits only canonical UUIDs, and the
    // fixture must reference the same records it creates. The expected text is
    // therefore the format template, which keeps this guard exact.
    // Split at the test module first so moving any exception into runtime code
    // makes this guard fail rather than silently enlarging Turso's write funnel.
    let test_module = normalized("#[cfg(all(test, feature = \"turso-tests\"))] mod tests {");
    let (runtime, tests) = normalized_source
        .split_once(&test_module)
        .expect("Turso query_sql fixture exceptions must remain in the test-only module");
    let mut tests = tests.to_string();
    let fixtures = [
        (
            "QUERY_SQL_PARITY_FIXTURE record policy seed",
            "INSERT INTO record_policies(record_id,created_at) SELECT id,'2026-01-01T00:00:00.000Z' FROM records WHERE id LIKE 'parity:%'",
        ),
        (
            "query_sql two-principal record policy seed",
            "INSERT INTO record_policies(record_id,created_at) VALUES \
             ('{PRIVATE_ALICE}','2026-01-01T00:00:00.000Z'), \
             ('{PRIVATE_BOB}','2026-01-01T00:00:00.000Z');",
        ),
        (
            "query_sql two-principal policy entry seed",
            "INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES \
             ('{PRIVATE_ALICE}','account','account:alice','allow','view'), \
             ('{PRIVATE_BOB}','account','account:bob','allow','view');",
        ),
    ];
    for (site, fixture) in fixtures {
        let fixture = normalized(fixture);
        let occurrences = tests.matches(&fixture).count();
        assert_eq!(
            occurrences, 1,
            "{site} must remain one exact query_sql test-only policy write"
        );
        tests = tests.replacen(&fixture, "", 1);
    }
    format!("{runtime} {tests}")
}

#[test]
fn policy_projection_writes_are_confined_to_the_projector_and_explicit_exceptions() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    let mutation = Regex::new(
        r"(?is)\b(?:insert(?:\s+or\s+\w+)?\s+into|update|delete\s+from)\s+(?:record_policies|policy_entries)\b",
    )
    .unwrap();
    let portable_statement_mutation = Regex::new(
        r#"(?is)\bstatement\s*\(\s*statementkind::(?:insert|update|delete)\s*,\s*"(?:record_policies|policy_entries)""#,
    )
    .unwrap();
    // One named production projector per supported local substrate. SQLite
    // owns literal SQL; Turso owns portable StatementTemplate mutations.
    let projectors = [("src/policy.rs", 4, 0), ("src/turso_local/policy.rs", 0, 4)];
    let explicit_exceptions = [
        // Narrow corruption fixtures embedded in module tests.
        ("src/authorization.rs", 1),
        ("src/query/sql.rs", 1),
        // The whats_changed before/after benchmark has one reusable viewable
        // policy fixture and one deliberately hidden malformed-row fixture;
        // each inserts one anchor and one entry. The exact four statement
        // sites keep this test-only exception auditable.
        ("src/mcp/tools/history/whats_changed_bench.rs", 4),
        // Fresh-file Turso genesis atomically pairs the canonical root event with
        // its two projection rows before exposing a handle. Runtime mutation is
        // not admitted through this exception.
        ("src/turso_local.rs", 2),
    ];
    let mut violations = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap();
        let source = fs::read_to_string(&path).unwrap();
        let normalized_source = without_query_sql_test_fixture_writes(relative, &source);
        let matches = mutation.find_iter(&normalized_source).collect::<Vec<_>>();
        let projector = projectors
            .iter()
            .find(|(projector, _, _)| relative == Path::new(projector));
        let expected_direct = projector
            .map(|(_, direct, _)| *direct)
            .or_else(|| {
                explicit_exceptions
                    .iter()
                    .find_map(|(allowed, count)| (relative == Path::new(allowed)).then_some(*count))
            })
            .unwrap_or(0);
        let portable_matches = portable_statement_mutation
            .find_iter(&normalized_source)
            .count();
        let expected_portable = projector.map(|(_, _, portable)| *portable).unwrap_or(0);
        if matches.len() != expected_direct || portable_matches != expected_portable {
            violations.push(format!(
                "{}: expected {expected_direct} direct and {expected_portable} portable authorized write(s), found {} direct and {portable_matches} portable",
                relative.display(), matches.len()
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "policy projection writes bypass the policy projector: {violations:#?}"
    );
}
