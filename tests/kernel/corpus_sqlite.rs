//! SQLite execution of the shared scenario corpus, plus the corpus-wide
//! structural guards that only need to run once (this target is in the
//! always-on default lane).

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::contract::{ContractHarness, DeliveredMessageFixture, SqliteHarness, TestCaller};
use native_ce::portable_sql::{AdapterBoundary, Backend};
use native_ce::{Error, Result};
use serde_json::{json, Value};

#[tokio::test]
async fn sqlite_executes_the_full_shared_scenario_corpus() {
    let harness = SqliteHarness::new();
    let run = crate::corpus::run_full_corpus(&harness, Backend::Sqlite)
        .await
        .unwrap();
    crate::corpus::assert_full_proof(&run, &crate::corpus::CORPUS_OPERATIONS);
}

struct FailingHarness {
    closes: AtomicUsize,
}

impl ContractHarness for FailingHarness {
    type Database = ();

    async fn fresh_logical_database(&self) -> Result<Self::Database> {
        Ok(())
    }

    async fn call(
        &self,
        _database: &Self::Database,
        _caller: TestCaller,
        _tool: &str,
        _arguments: Value,
    ) -> Result<Value> {
        Err(Error::engine("deliberate corpus regression failure"))
    }

    async fn provision_member(
        &self,
        _database: &Self::Database,
        _person_id: &str,
        _account_id: &str,
        _principal_id: &str,
    ) -> Result<()> {
        Err(Error::engine("unused failing harness capability"))
    }

    async fn deliver_message_fixture(
        &self,
        _database: &Self::Database,
        _sender: TestCaller,
        _fixture: DeliveredMessageFixture<'_>,
    ) -> Result<()> {
        Err(Error::engine("unused failing harness capability"))
    }

    async fn assert_replay_equivalent(&self, _database: &Self::Database) -> Result<()> {
        Ok(())
    }

    async fn close(&self, _database: &Self::Database) {
        self.closes.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn scenario_database_is_closed_when_execution_fails() {
    let harness = FailingHarness {
        closes: AtomicUsize::new(0),
    };

    let outcome = crate::corpus::run_full_corpus(&harness, Backend::Sqlite).await;

    assert!(outcome.is_err());
    assert_eq!(harness.closes.load(Ordering::SeqCst), 1);
}

#[test]
fn a_declared_divergence_downgrades_full_proof_deterministically() {
    let accounted = crate::corpus::scenarios()
        .into_iter()
        .map(|scenario| scenario.id)
        .collect::<Vec<_>>();
    let mut executed = accounted.clone();
    let divergent = crate::corpus::slice("create_record")[0];
    executed.retain(|scenario| *scenario != divergent);
    executed.reverse();
    let run = crate::corpus::CorpusRun {
        backend: Backend::Turso,
        accounted,
        executed,
        divergences: vec![crate::corpus::AccountedDivergence {
            scenario: divergent,
            boundary: AdapterBoundary::LogicalQuery,
            justification: "Regression fixture for an explicitly declared divergence.",
        }],
    };

    let proof = crate::corpus::proof_for(&run, "create_record");
    assert_eq!(proof.level, crate::corpus::ProofLevel::Partial);
    assert_eq!(proof.accounted, crate::corpus::slice("create_record"));
    assert_eq!(proof.divergences[0].scenario, divergent);
}

#[test]
fn no_executed_scenarios_is_explicit_none_proof() {
    let accounted = crate::corpus::scenarios()
        .into_iter()
        .map(|scenario| scenario.id)
        .collect::<Vec<_>>();
    let operation_slice = crate::corpus::slice("create_record");
    let executed = accounted
        .iter()
        .copied()
        .filter(|scenario| !operation_slice.contains(scenario))
        .collect();
    let divergences = operation_slice
        .iter()
        .copied()
        .map(|scenario| crate::corpus::AccountedDivergence {
            scenario,
            boundary: AdapterBoundary::LogicalQuery,
            justification: "Regression fixture for an explicitly declared divergence.",
        })
        .collect();
    let run = crate::corpus::CorpusRun {
        backend: Backend::Postgres,
        accounted,
        executed,
        divergences,
    };

    assert_eq!(
        crate::corpus::proof_for(&run, "create_record").level,
        crate::corpus::ProofLevel::None
    );
}

#[test]
fn corpus_table_is_well_formed() {
    crate::corpus::validate_scenarios(&crate::corpus::scenarios()).unwrap();
    for operation in crate::corpus::CORPUS_OPERATIONS {
        assert!(
            !crate::corpus::slice(operation).is_empty(),
            "governed corpus operation {operation:?} has no scenario"
        );
    }
}

#[test]
fn corpus_rejects_scenarios_that_dodge_the_shared_contract() {
    fn probe(
        id: &'static str,
        operation: &'static str,
        divergences: Vec<crate::corpus::Divergence>,
    ) -> crate::corpus::Scenario {
        crate::corpus::Scenario {
            id,
            operation,
            fixture: vec![],
            setup: vec![],
            invocation: crate::corpus::ToolCall {
                caller: crate::contract::TestCaller::Local,
                tool: operation,
                arguments: json!({}),
            },
            expect: crate::corpus::Expect::Result(vec![]),
            post: crate::corpus::PostCondition {
                records: vec![],
                updated_events: vec![],
            },
            divergences,
        }
    }
    let everywhere = |boundary: AdapterBoundary| {
        [Backend::Sqlite, Backend::Postgres, Backend::Turso]
            .into_iter()
            .map(|backend| crate::corpus::Divergence {
                backend,
                boundary,
                justification: "A justification long enough to pass the length floor.",
            })
            .collect::<Vec<_>>()
    };

    // A scenario that diverges on every backend proves nothing and is refused.
    let error = crate::corpus::validate_scenarios(&[probe(
        "get_record/skipped-everywhere",
        "get_record",
        everywhere(AdapterBoundary::LogicalQuery),
    )])
    .unwrap_err();
    assert!(error.contains("diverges on every backend"), "{error}");

    // Duplicate divergence declarations for one backend are refused.
    let error = crate::corpus::validate_scenarios(&[probe(
        "get_record/duplicate-divergence",
        "get_record",
        vec![
            crate::corpus::Divergence {
                backend: Backend::Turso,
                boundary: AdapterBoundary::Search,
                justification: "A justification long enough to pass the length floor.",
            },
            crate::corpus::Divergence {
                backend: Backend::Turso,
                boundary: AdapterBoundary::Search,
                justification: "A justification long enough to pass the length floor.",
            },
        ],
    )])
    .unwrap_err();
    assert!(error.contains("more than one divergence"), "{error}");

    // A divergence without a written justification is refused.
    let error = crate::corpus::validate_scenarios(&[probe(
        "get_record/unjustified-divergence",
        "get_record",
        vec![crate::corpus::Divergence {
            backend: Backend::Turso,
            boundary: AdapterBoundary::Search,
            justification: "no",
        }],
    )])
    .unwrap_err();
    assert!(error.contains("written justification"), "{error}");

    // An operation outside the governed list is refused.
    let error = crate::corpus::validate_scenarios(&[probe(
        "ungoverned_operation/refused",
        "ungoverned_operation",
        vec![],
    )])
    .unwrap_err();
    assert!(error.contains("ungoverned operation"), "{error}");

    // The invocation must exercise the operation the scenario claims.
    let mut mismatched = probe("get_record/tool-mismatch", "get_record", vec![]);
    mismatched.invocation.tool = "update_record";
    let error = crate::corpus::validate_scenarios(&[mismatched]).unwrap_err();
    assert!(error.contains("claims operation"), "{error}");
}

#[test]
fn corpus_scenarios_do_not_cross_the_physical_storage_boundary() {
    let source = include_str!("../contract/corpus.rs");
    for forbidden in [
        "sqlx::",
        "turso::",
        "PgPool",
        ".pool()",
        "create_database",
        "tempfile",
        "PRAGMA ",
        "SELECT ",
        "INSERT INTO",
        "DELETE FROM",
        "CREATE TABLE",
        "SqliteHarness",
        "PostgresHarness",
        "TursoHarness",
    ] {
        assert!(
            !source.contains(forbidden),
            "shared corpus contains backend-specific token {forbidden:?}"
        );
    }
}
