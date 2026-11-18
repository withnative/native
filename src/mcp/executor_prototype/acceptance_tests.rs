//! The acceptance declaration: coverage of every write operation, and the
//! invariants that tie it to the rest of the operation contract.

use std::collections::BTreeSet;

use super::acceptance::{declaration, requires_acceptance, Acceptance, Reason, ACCEPTANCE_TABLE};
use super::tests::registry;
use super::*;

/// Writes composed only in some builds, so the frozen audit has no row for
/// them: the publication source exists only on the v2 engine with its tools
/// registered. A build that does not serve them cannot check them by serving,
/// so they are listed here and must be declared in every build; the v2 build
/// (the one `check-new-operation.sh` runs) also checks they are really served.
///
/// Development package operations (`records_read.describe_package_operations`
/// and `.call_package_operation`, feature `package-cel-dev`) are registered
/// reads, so they are deliberately absent from the table; see
/// `development_package_operations_are_undeclared_reads`.
const COMPOSED_ONLY_IN_SOME_BUILDS: [(&str, &str); 2] = [
    ("records_write", "manage_publication.publish"),
    ("records_write", "manage_publication.unpublish"),
];

fn audit_rows() -> Vec<AuditRow> {
    serde_json::from_str::<Audit>(AUDIT).unwrap().audit_rows
}

fn every_experimental() -> ExperimentalExecutors {
    ExperimentalExecutors::from_env_value(Some(format!(
        "{EXPERIMENTAL_FRESHNESS_EXECUTOR},{EXPERIMENTAL_SQL_WRITE_EXECUTOR}"
    )))
    .unwrap()
}

/// Every contract any build of the catalogue serves, from both surfaces and
/// every engine this build can select, with the experimental executors on.
fn served_contracts() -> Vec<((String, String), OperationAccess)> {
    use crate::mcp::registry::EngineKind;
    let registry = registry();
    let rows = audit_rows();
    let experimental = every_experimental();
    let engines = [
        EngineKind::Sqlite,
        #[cfg(feature = "v2-kernel-probe")]
        EngineKind::KernelV2,
    ];
    let mut served = Vec::new();
    for engine in engines {
        for surface in [ExecutorSurface::Ordinary, ExecutorSurface::Lens] {
            let built =
                build_contracts_for_hosting(&registry, engine, &rows, surface, true, &experimental)
                    .unwrap();
            served.extend(
                built
                    .contracts
                    .into_iter()
                    .map(|(pair, contract)| (pair, contract.access)),
            );
        }
        // The ordinary catalogue also composes the sources added per build.
        let ordinary = build_ordinary_catalogue(&registry, engine, true, &experimental).unwrap();
        served.extend(
            ordinary
                .contracts
                .into_iter()
                .map(|(pair, contract)| (pair, contract.access)),
        );
    }
    #[cfg(feature = "v2-kernel-probe")]
    served.extend(v2_composed_contracts());
    served
}

/// The v2 engine's catalogue over a registry with the publication tool and the
/// v2 tools registered, which composes the publication, saved-tab and (with
/// `package-cel-dev`) package-operation sources.
#[cfg(feature = "v2-kernel-probe")]
fn v2_composed_contracts() -> Vec<((String, String), OperationAccess)> {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::tools::register_publication_management_tool(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    build_ordinary_catalogue(
        &registry,
        crate::mcp::registry::EngineKind::KernelV2,
        true,
        &every_experimental(),
    )
    .unwrap()
    .contracts
    .into_iter()
    .map(|(pair, contract)| (pair, contract.access))
    .collect()
}

#[test]
fn the_table_lists_each_operation_once() {
    let mut seen = BTreeSet::new();
    for (executor, operation, _) in ACCEPTANCE_TABLE {
        assert!(
            seen.insert((*executor, *operation)),
            "{executor}.{operation} is declared twice"
        );
    }
}

/// The author's checkpoint: an operation the catalogue serves as a mutation
/// has no way to be left undeclared, and a read is never declared. A new
/// write operation fails here until its author has chosen.
#[test]
fn every_served_mutation_is_declared_and_no_read_is() {
    // The list of composed-only writes is checked against the registry where
    // the registry can serve them: the v2 build (the one check-new-operation.sh
    // runs) serves exactly these as writes.
    #[cfg(feature = "v2-kernel-probe")]
    {
        let composed: BTreeMap<_, _> = v2_composed_contracts().into_iter().collect();
        for (executor, operation) in COMPOSED_ONLY_IN_SOME_BUILDS {
            assert_eq!(
                composed.get(&(executor.to_string(), operation.to_string())),
                Some(&OperationAccess::Mutation),
                "{executor}.{operation} is listed as composed but the v2 build does not serve it as a write"
            );
        }
    }
    let served = served_contracts();
    assert!(
        served.len() > 100,
        "the fixture catalogue should serve the whole surface, got {}",
        served.len()
    );
    let mut undeclared = BTreeSet::new();
    let mut declared_reads = BTreeSet::new();
    for ((executor, operation), access) in served {
        match (access, declaration(&executor, &operation).is_some()) {
            (OperationAccess::Mutation, false) => {
                undeclared.insert(format!("{executor}.{operation}"));
            }
            (OperationAccess::Read, true) => {
                declared_reads.insert(format!("{executor}.{operation}"));
            }
            _ => {}
        }
    }
    assert!(
        undeclared.is_empty(),
        "writes with no requires_acceptance declaration: add each to ACCEPTANCE_TABLE in \
         src/mcp/executor_prototype/acceptance.rs: {undeclared:?}"
    );
    assert!(
        declared_reads.is_empty(),
        "reads must not be declared (they always project requires_acceptance = false); \
         remove from ACCEPTANCE_TABLE: {declared_reads:?}"
    );
}

/// A rename or removal must not leave a stale row behind that no longer
/// describes anything.
#[test]
fn every_declaration_names_an_operation_that_exists() {
    let mut known: BTreeSet<(String, String)> = audit_rows()
        .into_iter()
        .map(|row| (row.candidate_executor, row.candidate_operation))
        .collect();
    known.extend(
        COMPOSED_ONLY_IN_SOME_BUILDS
            .iter()
            .map(|(executor, operation)| (executor.to_string(), operation.to_string())),
    );
    for (executor, operation, _) in ACCEPTANCE_TABLE {
        assert!(
            known.contains(&(executor.to_string(), operation.to_string())),
            "{executor}.{operation} is declared but is not an operation in the audit"
        );
    }
}

/// A plan-gated operation binds its execution to a hosted preview, so it can
/// never be run locally first. Every plan-required pair must be `Required`.
#[test]
fn every_plan_gated_operation_requires_acceptance() {
    for (executor, operation, _) in write_operations::PLAN_POLICY_TABLE {
        assert!(
            requires_acceptance(executor, operation),
            "{executor}.{operation} requires a plan, so it must declare requires_acceptance"
        );
    }
}

/// The catalogue column is the declaration, for every row it serves, on both
/// the full and the read-only standby projection.
#[test]
fn the_catalogue_column_projects_the_declaration() {
    let catalogue = build_ordinary_catalogue(
        &registry(),
        crate::mcp::registry::EngineKind::Sqlite,
        false,
        &ExperimentalExecutors::empty(),
    )
    .unwrap();
    let snapshot = project_catalog_operations_snapshot(
        &catalogue.contracts,
        &catalogue.operations_by_executor,
    );
    assert!(snapshot.iter().any(|row| row.requires_acceptance));
    assert!(snapshot.iter().any(|row| !row.requires_acceptance));
    for row in snapshot.iter() {
        assert_eq!(
            row.requires_acceptance,
            requires_acceptance(&row.executor, &row.operation),
            "{}.{}",
            row.executor,
            row.operation
        );
        if row.access == "read" {
            assert!(
                !row.requires_acceptance,
                "{}.{}",
                row.executor, row.operation
            );
        }
    }
    let wait = |operation: &str| {
        snapshot
            .iter()
            .find(|row| row.operation == operation)
            .unwrap_or_else(|| panic!("{operation} is served"))
            .requires_acceptance
    };
    assert!(!wait("create_record"));
    assert!(wait("create_many"));
    assert!(wait("delete_record"));
    assert!(wait("manage_messages.send"));
}

/// What is declared today, spelled out, so a change to a meaningful
/// declaration shows up in review as a change here.
#[test]
fn declarations_that_matter_today() {
    for (executor, operation) in [
        ("records_write", "create_record"),
        ("records_write", "update_record"),
        ("records_write", "merge_body"),
        ("records_write", "attach_text"),
        ("records_write", "manage_links.add"),
        // Reversible, and only the caller sees their own local copy.
        ("records_lifecycle", "archive_record"),
        ("records_write", "claim_unowned_record"),
        ("records_write", "resolve_suggestions.accept"),
        ("records_write", "resolve_suggestions.reject"),
    ] {
        assert_eq!(
            declaration(executor, operation),
            Some(Acceptance::LocalFirst),
            "{executor}.{operation}"
        );
    }
    // Replaying `create_many` creates its records again. It is held today
    // regardless (see `node::hold::HELD_DESPITE_REQUIRING_ACCEPTANCE`).
    assert_eq!(
        declaration("records_write", "create_many"),
        Some(Acceptance::Required(Reason::ReplayDuplicates))
    );
    for (executor, operation, reason) in [
        ("records_delete", "delete_record", Reason::Delete),
        ("identity_resolve", "materialize_record", Reason::Exclusive),
        ("records_write", "correct_record_type", Reason::PlanGated),
        (
            "messaging_write",
            "manage_messages.send",
            Reason::OutsideEffect,
        ),
        ("external_import", "attach_from_url", Reason::OutsideEffect),
        (
            "artifacts_execute",
            "invoke_artifact_interaction",
            Reason::OutsideEffect,
        ),
        (
            "records_write",
            "manage_publication.publish",
            Reason::OutsideEffect,
        ),
        ("access_admin", "manage_record_policy.grant", Reason::Admin),
        (
            "membership_admin",
            "manage_memberships.set_role",
            Reason::Admin,
        ),
        ("identity_admin", "manage_bindings.add", Reason::Admin),
        ("schema_admin", "manage_schema_config.write", Reason::Admin),
    ] {
        assert_eq!(
            declaration(executor, operation),
            Some(Acceptance::Required(reason)),
            "{executor}.{operation}"
        );
    }
    // An undeclared pair is local-first, per the default.
    assert!(!requires_acceptance("records_write", "not_an_operation"));
}

/// Whatever the build serves, these writes must be declared. Unlike the
/// served-contracts test this holds in every build, so removing one of these
/// rows fails even where the source is not composed.
#[test]
fn composed_writes_are_declared() {
    for (executor, operation) in COMPOSED_ONLY_IN_SOME_BUILDS {
        assert!(
            declaration(executor, operation).is_some(),
            "{executor}.{operation} is composed in some builds and must be declared"
        );
    }
}
