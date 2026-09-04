//! The shared logical scenario corpus.
//!
//! One table of (fixture, operation invocation, expected logical result)
//! defined once and executed identically by every storage backend through the
//! narrow [`ContractHarness`] seam. This module stays above the physical
//! storage boundary: fixtures and invocations are MCP tool calls, and every
//! expectation is a logical value normalized once for all backends — never per
//! backend.
//!
//! Policy, in priority order:
//!
//! 1. Adding a [`Scenario`] to [`scenarios`] automatically applies to all
//!    backends. A runner cannot opt out: [`run_full_corpus`] iterates the
//!    whole table and accounts for every scenario as executed or explicitly
//!    diverged. There is no runner-side skip parameter.
//! 2. "Full proof" for an operation is objective: the whole corpus slice for
//!    that operation (see [`slice`]) passes on that backend. This is the
//!    intended replacement for subjective F-versus-P reviewer judgement in
//!    the backend contract classification codes.
//! 3. Per-backend divergence is only expressible as a [`Divergence`] declared
//!    in the table itself, and each divergence must name one of the eight
//!    [`AdapterBoundary`] categories plus a written justification.
//!
//! Normalization notes (shared, not per backend):
//! - An absent or null `body`/`summary` normalizes to the empty string. The
//!   engine already defines the absent body as equivalent to the empty string
//!   for `if_body_digest` guards, so this collapse loses no logical meaning.
//! - Facets normalize to sorted `{key, value}` pairs.
//! - History events are filtered to the portable event vocabulary
//!   (`record.created`, `record.updated`) because archive and facet writes
//!   legitimately serialize differently per backend while remaining logically
//!   equivalent; the post-condition still pins the resulting record state.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use native_ce::portable_sql::{AdapterBoundary, Backend};
use native_ce::{Error, Result};

use crate::contract::{ContractHarness, DeliveredMessageFixture, TestCaller};

/// Operations currently covered by the corpus. Every scenario's operation
/// must come from this list, and every backend run must execute at least one
/// scenario per operation.
pub const CORPUS_OPERATIONS: [&str; 6] = [
    "create_record",
    "get_record",
    "update_record",
    "delete_record",
    "archive_record",
    "get_history",
];

const REASON: &str = "Execute the shared scenario corpus.";

fn legacy_capability_denial_divergences() -> Vec<Divergence> {
    vec![
        Divergence {
            backend: Backend::Postgres,
            boundary: AdapterBoundary::LogicalQuery,
            justification: "The unsupported Postgres adapter still preserves the legacy missing-equivalent capability denial until backend parity work lands.",
        },
        Divergence {
            backend: Backend::Turso,
            boundary: AdapterBoundary::LogicalQuery,
            justification: "The unsupported Turso adapter still preserves the legacy missing-equivalent capability denial until backend parity work lands.",
        },
    ]
}

/// One MCP tool invocation expressed logically.
pub struct ToolCall {
    pub caller: TestCaller,
    pub tool: &'static str,
    pub arguments: Value,
}

/// Backend-neutral fixture setup that cannot be expressed as a product tool
/// call. These steps establish authenticated identities and delivered-message
/// visibility without exposing a backend pool, schema, or file to the corpus.
pub enum Setup {
    ProvisionMember {
        person_id: &'static str,
        account_id: &'static str,
        principal_id: &'static str,
    },
    DeliverMessage {
        sender_account_id: &'static str,
        id: &'static str,
        name: &'static str,
        body: &'static str,
        recipient_id: &'static str,
        idempotency_key: &'static str,
    },
    RestrictRecordToAccount {
        record_id: &'static str,
        account_id: &'static str,
    },
    CreateAttribution {
        record_id: &'static str,
    },
    ActivateInstructionSource {
        record_id: &'static str,
        binding_id: &'static str,
    },
}

fn local(tool: &'static str, arguments: Value) -> ToolCall {
    ToolCall {
        caller: TestCaller::Local,
        tool,
        arguments,
    }
}

/// Expected logical outcome of the scenario's operation invocation.
pub enum Expect {
    /// The invocation succeeds and each JSON pointer resolves to exactly the
    /// given value in the corpus-normalized result.
    Result(Vec<(&'static str, Value)>),
    /// The invocation fails and its error message contains this stable
    /// fragment on every backend.
    Error {
        contains: &'static str,
    },
    ExactError {
        equals: &'static str,
    },
}

/// Logical state that must hold after the invocation, observed only through
/// MCP reads and normalized identically for every backend.
pub struct PostCondition {
    /// Exact corpus-normalized record snapshots, keyed by record id.
    pub records: Vec<(&'static str, Value)>,
    /// Exact number of `record.updated` events per record. This pins write
    /// atomicity: a rejected guarded write must append no update event.
    pub updated_events: Vec<(&'static str, usize)>,
}

/// An explicit, justified per-backend divergence. This is the only channel
/// through which a backend may not execute a scenario.
pub struct Divergence {
    pub backend: Backend,
    pub boundary: AdapterBoundary,
    pub justification: &'static str,
}

pub struct Scenario {
    pub id: &'static str,
    /// Backend-contract operation this scenario is evidence for.
    pub operation: &'static str,
    /// Setup tool calls; each must succeed on every backend.
    pub fixture: Vec<ToolCall>,
    /// Portable harness setup performed after the fixture calls.
    pub setup: Vec<Setup>,
    /// The operation invocation under test. Its tool must equal `operation`.
    pub invocation: ToolCall,
    pub expect: Expect,
    pub post: PostCondition,
    pub divergences: Vec<Divergence>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The corpus table. Adding an entry here applies to all backends with no
/// further wiring.
pub fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            id: "create_record/full-shape",
            operation: "create_record",
            fixture: vec![],
            setup: vec![],
            invocation: local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000008",
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "Corpus create",
                    "body": "created body",
                    "lifecycle": "open",
                    "facets": { "priority": "high" },
                    "reason": REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/id", json!("c0d90000-0000-4000-8000-000000000008")),
                ("/name", json!("Corpus create")),
                ("/body", json!("created body")),
                ("/body_digest", json!(sha256_hex(b"created body"))),
                ("/archived", json!(false)),
                ("/facets", json!([{ "key": "priority", "value": "high" }])),
            ]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000008",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000008",
                        "type": "WorkItem",
                        "kind": "task",
                        "name": "Corpus create",
                        "body": "created body",
                        "lifecycle": "open",
                        "facets": [{ "key": "priority", "value": "high" }],
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000008", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "create_record/minimal-without-body",
            operation: "create_record",
            fixture: vec![],
            setup: vec![],
            invocation: local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000009",
                    "type": "Document",
                    "kind": "note",
                    "name": "Minimal",
                    "reason": REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/id", json!("c0d90000-0000-4000-8000-000000000009")),
                ("/body", json!("")),
                ("/body_digest", json!(sha256_hex(b""))),
                ("/archived", json!(false)),
                ("/facets", json!([])),
            ]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000009",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000009",
                        "type": "Document",
                        "kind": "note",
                        "name": "Minimal",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000009", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "get_record/found-and-missing",
            operation: "get_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000029",
                    "type": "Document",
                    "kind": "note",
                    "name": "Present",
                    "body": "present body",
                    "facets": { "stage": "draft" },
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "get_record",
                json!({ "ids": ["c0d90000-0000-4000-8000-000000000029", "c0d90000-0000-4000-8000-000000000026"] }),
            ),
            expect: Expect::Result(vec![
                ("/records/0/status", json!("found")),
                ("/records/0/body", json!("present body")),
                (
                    "/records/0/body_digest",
                    json!(sha256_hex(b"present body")),
                ),
                (
                    "/records/0/facets",
                    json!([{ "key": "stage", "value": "draft" }]),
                ),
                ("/records/1", json!({ "status": "not_found" })),
            ]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000029",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000029",
                        "type": "Document",
                        "kind": "note",
                        "name": "Present",
                        "body": "present body",
                        "facets": [{ "key": "stage", "value": "draft" }],
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000029", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/fields-and-facets",
            operation: "update_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000047",
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "Before",
                    "body": "before body",
                    "lifecycle": "open",
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000047",
                    "name": "After",
                    "summary": "after summary",
                    "body": "after body",
                    "if_body_digest": sha256_hex(b"before body"),
                    "facets": { "priority": "high" },
                    "reason": REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/name", json!("After")),
                ("/summary", json!("after summary")),
                ("/body", json!("after body")),
                ("/body_digest", json!(sha256_hex(b"after body"))),
                ("/facets", json!([{ "key": "priority", "value": "high" }])),
            ]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000047",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000047",
                        "type": "WorkItem",
                        "kind": "task",
                        "name": "After",
                        "summary": "after summary",
                        "body": "after body",
                        "lifecycle": "open",
                        "facets": [{ "key": "priority", "value": "high" }],
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000047", 1)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/facet-overwrite",
            operation: "update_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000046",
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "Facet before",
                    "facets": { "priority": "low" },
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000046",
                    "name": "Facet after",
                    "facets": { "priority": "high" },
                    "reason": REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/name", json!("Facet after")),
                ("/facets", json!([{ "key": "priority", "value": "high" }])),
            ]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000046",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000046",
                        "type": "WorkItem",
                        "kind": "task",
                        "name": "Facet after",
                        "lifecycle": "open",
                        "facets": [{ "key": "priority", "value": "high" }],
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000046", 1)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/homogeneous-multi-target",
            operation: "update_record",
            fixture: vec![
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000055",
                        "type":"WorkItem",
                        "kind":"task",
                        "name":"Multi first",
                        "maturity":"exploratory",
                        "facets":{"triage":"untriaged"},
                        "reason":REASON
                    }),
                ),
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000056",
                        "type":"WorkItem",
                        "kind":"task",
                        "name":"Multi second",
                        "maturity":"exploratory",
                        "facets":{"triage":"untriaged"},
                        "reason":REASON
                    }),
                ),
            ],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "ids":[
                        "c0d90000-0000-4000-8000-000000000055",
                        "c0d90000-0000-4000-8000-000000000056"
                    ],
                    "facets":{"triage":"completed"},
                    "maturity":"active",
                    "if_facets":{"triage":"untriaged"},
                    "if_maturity":"exploratory",
                    "reason":REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/requested", json!(2)),
                ("/changed", json!(2)),
                ("/unchanged", json!(0)),
                ("/results/0/index", json!(0)),
                ("/results/0/status", json!("changed")),
                ("/results/1/index", json!(1)),
                ("/results/1/status", json!("changed")),
            ]),
            post: PostCondition {
                records: vec![
                    (
                        "c0d90000-0000-4000-8000-000000000055",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000055",
                            "type":"WorkItem",
                            "kind":"task",
                            "name":"Multi first",
                            "lifecycle":"open",
                            "maturity":"active",
                            "facets":[{"key":"triage","value":"completed"}],
                        })),
                    ),
                    (
                        "c0d90000-0000-4000-8000-000000000056",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000056",
                            "type":"WorkItem",
                            "kind":"task",
                            "name":"Multi second",
                            "lifecycle":"open",
                            "maturity":"active",
                            "facets":[{"key":"triage","value":"completed"}],
                        })),
                    ),
                ],
                updated_events: vec![
                    ("c0d90000-0000-4000-8000-000000000055", 1),
                    ("c0d90000-0000-4000-8000-000000000056", 1),
                ],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/homogeneous-multi-target-noop",
            operation: "update_record",
            fixture: [
                "c0d90000-0000-4000-8000-000000000057",
                "c0d90000-0000-4000-8000-000000000058",
            ]
            .into_iter()
            .map(|id| {
                local(
                    "create_record",
                    json!({
                        "id":id,"type":"WorkItem","kind":"task","name":"Already reconciled",
                        "maturity":"active","facets":{"triage":"completed"},"reason":REASON
                    }),
                )
            })
            .collect(),
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "ids":[
                        "c0d90000-0000-4000-8000-000000000057",
                        "c0d90000-0000-4000-8000-000000000058"
                    ],
                    "facets":{"triage":"completed"},"maturity":"active","reason":REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/requested", json!(2)),
                ("/changed", json!(0)),
                ("/unchanged", json!(2)),
            ]),
            post: PostCondition {
                records: vec![
                    (
                        "c0d90000-0000-4000-8000-000000000057",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000057",
                            "type":"WorkItem","kind":"task","name":"Already reconciled",
                            "lifecycle":"open","maturity":"active",
                            "facets":[{"key":"triage","value":"completed"}],
                        })),
                    ),
                    (
                        "c0d90000-0000-4000-8000-000000000058",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000058",
                            "type":"WorkItem","kind":"task","name":"Already reconciled",
                            "lifecycle":"open","maturity":"active",
                            "facets":[{"key":"triage","value":"completed"}],
                        })),
                    ),
                ],
                updated_events: vec![
                    ("c0d90000-0000-4000-8000-000000000057", 0),
                    ("c0d90000-0000-4000-8000-000000000058", 0),
                ],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/homogeneous-multi-target-mixed-stale",
            operation: "update_record",
            fixture: vec![
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000059",
                        "type":"WorkItem","kind":"task","name":"Current cohort member",
                        "maturity":"active","reason":REASON
                    }),
                ),
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000060",
                        "type":"WorkItem","kind":"task","name":"Stale cohort member",
                        "maturity":"review","reason":REASON
                    }),
                ),
            ],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "ids":[
                        "c0d90000-0000-4000-8000-000000000059",
                        "c0d90000-0000-4000-8000-000000000060"
                    ],
                    "maturity":"done","if_maturity":"active","reason":REASON
                }),
            ),
            expect: Expect::Error {
                contains: "nothing was written",
            },
            post: PostCondition {
                records: vec![
                    (
                        "c0d90000-0000-4000-8000-000000000059",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000059",
                            "type":"WorkItem","kind":"task","name":"Current cohort member",
                            "lifecycle":"open","maturity":"active",
                        })),
                    ),
                    (
                        "c0d90000-0000-4000-8000-000000000060",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000060",
                            "type":"WorkItem","kind":"task","name":"Stale cohort member",
                            "lifecycle":"open","maturity":"review",
                        })),
                    ),
                ],
                updated_events: vec![
                    ("c0d90000-0000-4000-8000-000000000059", 0),
                    ("c0d90000-0000-4000-8000-000000000060", 0),
                ],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/homogeneous-multi-target-relocation",
            operation: "update_record",
            fixture: vec![
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000061",
                        "type":"Collection","kind":"folder","name":"Shared destination","reason":REASON
                    }),
                ),
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000062",
                        "type":"Document","kind":"note","name":"First relocated record","reason":REASON
                    }),
                ),
                local(
                    "create_record",
                    json!({
                        "id":"c0d90000-0000-4000-8000-000000000063",
                        "type":"Document","kind":"note","name":"Second relocated record","reason":REASON
                    }),
                ),
            ],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "ids":[
                        "c0d90000-0000-4000-8000-000000000062",
                        "c0d90000-0000-4000-8000-000000000063"
                    ],
                    "home_id":"c0d90000-0000-4000-8000-000000000061",
                    "if_home_id":native_ce::schema::UNFILED_RECORD_ID,
                    "reason":REASON
                }),
            ),
            expect: Expect::Result(vec![
                ("/requested", json!(2)),
                ("/changed", json!(2)),
                ("/unchanged", json!(0)),
            ]),
            post: PostCondition {
                records: vec![
                    (
                        "c0d90000-0000-4000-8000-000000000062",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000062",
                            "type":"Document","kind":"note","name":"First relocated record",
                            "home_id":"c0d90000-0000-4000-8000-000000000061",
                        })),
                    ),
                    (
                        "c0d90000-0000-4000-8000-000000000063",
                        found_record(json!({
                            "id":"c0d90000-0000-4000-8000-000000000063",
                            "type":"Document","kind":"note","name":"Second relocated record",
                            "home_id":"c0d90000-0000-4000-8000-000000000061",
                        })),
                    ),
                ],
                updated_events: vec![
                    ("c0d90000-0000-4000-8000-000000000062", 1),
                    ("c0d90000-0000-4000-8000-000000000063", 1),
                ],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/unguarded-whole-body-rejected",
            operation: "update_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000054",
                    "type": "Document",
                    "kind": "note",
                    "name": "Unguarded",
                    "body": "the body a concurrent editor is holding",
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000054",
                    "body": "must not land",
                    "reason": REASON
                }),
            ),
            expect: Expect::Error {
                contains: "unguarded whole-body write refused",
            },
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000054",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000054",
                        "type": "Document",
                        "kind": "note",
                        "name": "Unguarded",
                        "body": "the body a concurrent editor is holding",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000054", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/unguarded-body-clear-rejected",
            operation: "update_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000044",
                    "type": "Document",
                    "kind": "note",
                    "name": "Clearing is replacement",
                    "body": "content that clearing would destroy",
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000044",
                    "body": null,
                    "reason": REASON
                }),
            ),
            expect: Expect::Error {
                contains: "unguarded whole-body write refused",
            },
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000044",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000044",
                        "type": "Document",
                        "kind": "note",
                        "name": "Clearing is replacement",
                        "body": "content that clearing would destroy",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000044", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/stale-body-digest-rejected",
            operation: "update_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000049",
                    "type": "Document",
                    "kind": "note",
                    "name": "Guarded",
                    "body": "guarded body",
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000049",
                    "body": "must not land",
                    "if_body_digest": sha256_hex(b"a body this record never held"),
                    "reason": REASON
                }),
            ),
            expect: Expect::Error {
                contains: "body digest conflict",
            },
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000049",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000049",
                        "type": "Document",
                        "kind": "note",
                        "name": "Guarded",
                        "body": "guarded body",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000049", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "update_record/empty-digest-matches-absent-body",
            operation: "update_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000048",
                    "type": "Document",
                    "kind": "note",
                    "name": "First body",
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "update_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000048",
                    "body": "the first body",
                    "if_body_digest": sha256_hex(b""),
                    "reason": REASON
                }),
            ),
            expect: Expect::Result(vec![("/body", json!("the first body"))]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000048",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000048",
                        "type": "Document",
                        "kind": "note",
                        "name": "First body",
                        "body": "the first body",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000048", 1)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/tombstones-and-preserves-state",
            operation: "delete_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000019",
                    "type": "Document",
                    "kind": "note",
                    "name": "Delete me",
                    "body": "preserved body",
                    "facets": { "priority": "high" },
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "delete_record",
                json!({ "id": "c0d90000-0000-4000-8000-000000000019", "reason": REASON }),
            ),
            expect: Expect::Result(vec![("/deleted", json!(true))]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000019",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000019",
                        "type": "Document",
                        "kind": "note",
                        "name": "Delete me",
                        "body": "preserved body",
                        "deleted": true,
                        "facets": [{ "key": "priority", "value": "high" }],
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000019", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/stale-content-revision-rejected",
            operation: "delete_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000024",
                    "type": "Document",
                    "kind": "note",
                    "name": "Still live",
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "delete_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000024",
                    "if_content_seq": 0,
                    "reason": REASON
                }),
            ),
            expect: Expect::Error {
                contains: "content revision conflict",
            },
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000024",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000024",
                        "type": "Document",
                        "kind": "note",
                        "name": "Still live",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000024", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/live-homed-child-rejected",
            operation: "delete_record",
            fixture: vec![
                local(
                    "create_record",
                    json!({
                        "id": "c0d90000-0000-4000-8000-000000000016",
                        "type": "Collection",
                        "kind": "folder",
                        "name": "Occupied folder",
                        "reason": REASON
                    }),
                ),
                local(
                    "create_record",
                    json!({
                        "id": "c0d90000-0000-4000-8000-000000000012",
                        "type": "Document",
                        "kind": "note",
                        "name": "Homed child",
                        "home_id": "c0d90000-0000-4000-8000-000000000016",
                        "reason": REASON
                    }),
                ),
            ],
            setup: vec![],
            invocation: local(
                "delete_record",
                json!({ "id": "c0d90000-0000-4000-8000-000000000016", "reason": REASON }),
            ),
            expect: Expect::Error {
                contains: "still has live homed members",
            },
            post: PostCondition {
                records: vec![
                    (
                        "c0d90000-0000-4000-8000-000000000016",
                        found_record(json!({
                            "id": "c0d90000-0000-4000-8000-000000000016",
                            "type": "Collection",
                            "kind": "folder",
                            "name": "Occupied folder",
                        })),
                    ),
                    (
                        "c0d90000-0000-4000-8000-000000000012",
                        found_record(json!({
                            "id": "c0d90000-0000-4000-8000-000000000012",
                            "type": "Document",
                            "kind": "note",
                            "name": "Homed child",
                            "home_id": "c0d90000-0000-4000-8000-000000000016",
                        })),
                    ),
                ],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000016", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/edit-capability-is-insufficient-for-manage",
            operation: "delete_record",
            fixture: vec![
                local("create_record", json!({"id":"c0d90000-0000-4000-8000-000000000015","type":"Entity","kind":"person","name":"Editor","reason":REASON})),
                local("create_record", json!({"id":"c0d90000-0000-4000-8000-000000000014","type":"Document","kind":"note","name":"Edit only","reason":REASON})),
            ],
            setup: vec![
                Setup::ProvisionMember {
                    person_id: "c0d90000-0000-4000-8000-000000000015",
                    account_id: "acct:corpus-delete-editor",
                    principal_id: "native/corpus-delete-editor",
                },
                Setup::RestrictRecordToAccount {
                    record_id: "c0d90000-0000-4000-8000-000000000014",
                    account_id: "acct:corpus-delete-editor",
                },
            ],
            invocation: ToolCall {
                caller: TestCaller::member("acct:corpus-delete-editor"),
                tool: "delete_record",
                arguments: json!({"id":"c0d90000-0000-4000-8000-000000000014","reason":REASON}),
            },
            expect: Expect::ExactError {
                equals: "delete_record: record c0d90000-0000-4000-8000-000000000014 requires manage capability; caller has edit capability",
            },
            post: PostCondition {
                records: vec![("c0d90000-0000-4000-8000-000000000014", found_record(json!({"id":"c0d90000-0000-4000-8000-000000000014","type":"Document","kind":"note","name":"Edit only"})))],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000014", 0)],
            },
            divergences: legacy_capability_denial_divergences(),
        },
        Scenario {
            id: "delete_record/protected-root-refused",
            operation: "delete_record",
            fixture: vec![],
            setup: vec![],
            invocation: local("delete_record", json!({"id":"native:root","reason":REASON})),
            expect: Expect::ExactError {
                equals: "cannot apply record.deleted: engine filing record native:root cannot be removed",
            },
            post: PostCondition { records: vec![], updated_events: vec![] },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/protected-unfiled-refused",
            operation: "delete_record",
            fixture: vec![],
            setup: vec![],
            invocation: local("delete_record", json!({"id":"native:unfiled","reason":REASON})),
            expect: Expect::ExactError {
                equals: "cannot apply record.deleted: engine filing record native:unfiled cannot be removed",
            },
            post: PostCondition { records: vec![], updated_events: vec![] },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/attribution-is-missing-equivalent",
            operation: "delete_record",
            fixture: vec![],
            setup: vec![Setup::CreateAttribution { record_id: "c0d90000-0000-4000-8000-000000000011" }],
            invocation: local("delete_record", json!({"id":"c0d90000-0000-4000-8000-000000000011","reason":REASON})),
            expect: Expect::ExactError {
                equals: "delete_record: record c0d90000-0000-4000-8000-000000000011 does not exist",
            },
            post: PostCondition { records: vec![], updated_events: vec![] },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/active-instruction-source-refused",
            operation: "delete_record",
            fixture: vec![local("create_record", json!({"id":"c0d90000-0000-4000-8000-000000000018","type":"Document","kind":"note","name":"Active instruction","reason":REASON}))],
            setup: vec![Setup::ActivateInstructionSource {
                record_id: "c0d90000-0000-4000-8000-000000000018",
                binding_id: "c0d90000-0000-4000-8000-000000000017",
            }],
            invocation: local("delete_record", json!({"id":"c0d90000-0000-4000-8000-000000000018","reason":REASON})),
            expect: Expect::ExactError {
                equals: "delete_record: record c0d90000-0000-4000-8000-000000000018 is an active instruction source referenced by binding c0d90000-0000-4000-8000-000000000017 (database); disable or remove those bindings/programme sources before deleting it",
            },
            post: PostCondition {
                records: vec![("c0d90000-0000-4000-8000-000000000018", found_record(json!({"id":"c0d90000-0000-4000-8000-000000000018","type":"Document","kind":"note","name":"Active instruction"})))],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000018", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "delete_record/terminal-retry-exact-error",
            operation: "delete_record",
            fixture: vec![
                local("create_record", json!({"id":"c0d90000-0000-4000-8000-000000000025","type":"Document","kind":"note","name":"Terminal","reason":REASON})),
                local("delete_record", json!({"id":"c0d90000-0000-4000-8000-000000000025","reason":REASON})),
            ],
            setup: vec![],
            invocation: local("delete_record", json!({"id":"c0d90000-0000-4000-8000-000000000025","reason":REASON})),
            expect: Expect::ExactError {
                equals: "cannot apply record.deleted: record c0d90000-0000-4000-8000-000000000025 is deleted (tombstoned)",
            },
            post: PostCondition {
                records: vec![("c0d90000-0000-4000-8000-000000000025", found_record(json!({"id":"c0d90000-0000-4000-8000-000000000025","type":"Document","kind":"note","name":"Terminal","deleted":true})))],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000025", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "archive_record/archives-and-preserves-state",
            operation: "archive_record",
            fixture: vec![local(
                "create_record",
                json!({
                    "id": "c0d90000-0000-4000-8000-000000000003",
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "To archive",
                    "body": "kept body",
                    "lifecycle": "open",
                    "facets": { "priority": "high" },
                    "reason": REASON
                }),
            )],
            setup: vec![],
            invocation: local(
                "archive_record",
                json!({ "id": "c0d90000-0000-4000-8000-000000000003", "reason": REASON }),
            ),
            expect: Expect::Result(vec![("/changed", json!(true))]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000003",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000003",
                        "type": "WorkItem",
                        "kind": "task",
                        "name": "To archive",
                        "body": "kept body",
                        "lifecycle": "open",
                        "archived": true,
                        "facets": [{ "key": "priority", "value": "high" }],
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000003", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "archive_record/noop-when-already-archived",
            operation: "archive_record",
            fixture: vec![
                local(
                    "create_record",
                    json!({
                        "id": "c0d90000-0000-4000-8000-000000000002",
                        "type": "Document",
                        "kind": "note",
                        "name": "Archive twice",
                        "reason": REASON
                    }),
                ),
                local(
                    "archive_record",
                    json!({ "id": "c0d90000-0000-4000-8000-000000000002", "reason": REASON }),
                ),
            ],
            setup: vec![],
            invocation: local(
                "archive_record",
                json!({ "id": "c0d90000-0000-4000-8000-000000000002", "reason": REASON }),
            ),
            expect: Expect::Result(vec![("/changed", json!(false))]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000002",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000002",
                        "type": "Document",
                        "kind": "note",
                        "name": "Archive twice",
                        "archived": true,
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000002", 0)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "get_history/creation-then-guarded-update",
            operation: "get_history",
            fixture: vec![
                local(
                    "create_record",
                    json!({
                        "id": "c0d90000-0000-4000-8000-000000000042",
                        "type": "Document",
                        "kind": "note",
                        "name": "History",
                        "body": "first",
                        "reason": REASON
                    }),
                ),
                local(
                    "update_record",
                    json!({
                        "id": "c0d90000-0000-4000-8000-000000000042",
                        "body": "second",
                        "if_body_digest": sha256_hex(b"first"),
                        "reason": REASON
                    }),
                ),
            ],
            setup: vec![],
            invocation: local(
                "get_history",
                json!({ "record_id": "c0d90000-0000-4000-8000-000000000042", "detail": "full" }),
            ),
            expect: Expect::Result(vec![(
                "/events",
                json!([
                    { "type": "record.created" },
                    { "type": "record.updated", "body": "second" },
                ]),
            )]),
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000042",
                    found_record(json!({
                        "id": "c0d90000-0000-4000-8000-000000000042",
                        "type": "Document",
                        "kind": "note",
                        "name": "History",
                        "body": "second",
                    })),
                )],
                updated_events: vec![("c0d90000-0000-4000-8000-000000000042", 1)],
            },
            divergences: vec![],
        },
        Scenario {
            id: "create_record/unbound-member-rejected-without-write",
            operation: "create_record",
            fixture: vec![],
            setup: vec![],
            invocation: ToolCall {
                caller: TestCaller::member("acct:corpus-unbound"),
                tool: "create_record",
                arguments: json!({
                    "id": "c0d90000-0000-4000-8000-000000000010",
                    "type": "Document",
                    "kind": "note",
                    "name": "Must not exist",
                    "reason": REASON
                }),
            },
            expect: Expect::Error {
                contains: "portable account binding",
            },
            post: PostCondition {
                records: vec![(
                    "c0d90000-0000-4000-8000-000000000010",
                    json!({ "status": "not_found" }),
                )],
                updated_events: vec![],
            },
            divergences: vec![],
        },
        private_message_denied_read_scenario(),
        private_message_denied_update_scenario(),
        private_message_denied_delete_scenario(),
        private_message_denied_archive_scenario(),
        private_message_denied_history_scenario(),
        private_message_authorized_history_scenario(),
    ]
}

fn private_message_fixture(
    sender_id: &'static str,
    recipient_id: &'static str,
    outsider_id: &'static str,
) -> Vec<ToolCall> {
    vec![
        local(
            "create_record",
            json!({
                "id": sender_id, "type": "Entity", "kind": "person",
                "name": "Corpus sender", "reason": REASON
            }),
        ),
        local(
            "create_record",
            json!({
                "id": recipient_id, "type": "Entity", "kind": "person",
                "name": "Corpus recipient", "reason": REASON
            }),
        ),
        local(
            "create_record",
            json!({
                "id": outsider_id, "type": "Entity", "kind": "person",
                "name": "Corpus outsider", "reason": REASON
            }),
        ),
    ]
}

fn private_message_setup(
    sender_id: &'static str,
    recipient_id: &'static str,
    outsider_id: &'static str,
    message_id: &'static str,
    body: &'static str,
    idempotency_key: &'static str,
) -> Vec<Setup> {
    vec![
        Setup::ProvisionMember {
            person_id: sender_id,
            account_id: "acct:corpus-sender",
            principal_id: "native/corpus-sender",
        },
        Setup::ProvisionMember {
            person_id: recipient_id,
            account_id: "acct:corpus-recipient",
            principal_id: "native/corpus-recipient",
        },
        Setup::ProvisionMember {
            person_id: outsider_id,
            account_id: "acct:corpus-outsider",
            principal_id: "native/corpus-outsider",
        },
        Setup::DeliverMessage {
            sender_account_id: "acct:corpus-sender",
            id: message_id,
            name: "Private corpus message",
            body,
            recipient_id,
            idempotency_key,
        },
    ]
}

fn private_message_post(message_id: &'static str, body: &'static str) -> PostCondition {
    PostCondition {
        records: vec![(
            message_id,
            found_record(json!({
                "id": message_id,
                "type": "Message",
                "kind": "text",
                "name": "Private corpus message",
                "body": body,
                "facets": [{ "key": "expectation", "value": "reply" }],
            })),
        )],
        updated_events: vec![(message_id, 0)],
    }
}

fn private_message_denied_read_scenario() -> Scenario {
    let (sender, recipient, outsider, message) = (
        "c0d90000-0000-4000-8000-000000000032",
        "c0d90000-0000-4000-8000-000000000031",
        "c0d90000-0000-4000-8000-000000000028",
        "c0d90000-0000-4000-8000-000000000030",
    );
    Scenario {
        id: "get_record/unauthorized-is-indistinguishable-from-missing",
        operation: "get_record",
        fixture: private_message_fixture(sender, recipient, outsider),
        setup: private_message_setup(
            sender,
            recipient,
            outsider,
            message,
            "private get body",
            "c0d90000-0000-4000-8000-000000000027",
        ),
        invocation: ToolCall {
            caller: TestCaller::member("acct:corpus-outsider"),
            tool: "get_record",
            arguments: json!({ "ids": [message] }),
        },
        expect: Expect::Result(vec![("/records/0", json!({ "status": "not_found" }))]),
        post: private_message_post(message, "private get body"),
        divergences: vec![],
    }
}

fn private_message_denied_update_scenario() -> Scenario {
    let (sender, recipient, outsider, message) = (
        "c0d90000-0000-4000-8000-000000000053",
        "c0d90000-0000-4000-8000-000000000052",
        "c0d90000-0000-4000-8000-000000000050",
        "c0d90000-0000-4000-8000-000000000051",
    );
    Scenario {
        id: "update_record/recipient-cannot-mutate-sender-message",
        operation: "update_record",
        fixture: private_message_fixture(sender, recipient, outsider),
        setup: private_message_setup(
            sender,
            recipient,
            outsider,
            message,
            "private update body",
            "c0d90000-0000-4000-8000-000000000045",
        ),
        invocation: ToolCall {
            caller: TestCaller::member("acct:corpus-recipient"),
            tool: "update_record",
            arguments: json!({ "id": message, "body": "must not land", "reason": REASON }),
        },
        expect: Expect::ExactError {
            equals: "update_record: record c0d90000-0000-4000-8000-000000000051 requires edit capability; caller has view capability",
        },
        post: private_message_post(message, "private update body"),
        divergences: legacy_capability_denial_divergences(),
    }
}

fn private_message_denied_archive_scenario() -> Scenario {
    let (sender, recipient, outsider, message) = (
        "c0d90000-0000-4000-8000-000000000007",
        "c0d90000-0000-4000-8000-000000000006",
        "c0d90000-0000-4000-8000-000000000004",
        "c0d90000-0000-4000-8000-000000000005",
    );
    Scenario {
        id: "archive_record/recipient-cannot-archive-sender-message",
        operation: "archive_record",
        fixture: private_message_fixture(sender, recipient, outsider),
        setup: private_message_setup(
            sender,
            recipient,
            outsider,
            message,
            "private archive body",
            "c0d90000-0000-4000-8000-000000000001",
        ),
        invocation: ToolCall {
            caller: TestCaller::member("acct:corpus-recipient"),
            tool: "archive_record",
            arguments: json!({ "id": message, "reason": REASON }),
        },
        expect: Expect::ExactError {
            equals: "archive_record: record c0d90000-0000-4000-8000-000000000005 requires manage capability; caller has view capability",
        },
        post: private_message_post(message, "private archive body"),
        divergences: legacy_capability_denial_divergences(),
    }
}

fn private_message_denied_history_scenario() -> Scenario {
    let (sender, recipient, outsider, message) = (
        "c0d90000-0000-4000-8000-000000000043",
        "c0d90000-0000-4000-8000-000000000041",
        "c0d90000-0000-4000-8000-000000000039",
        "c0d90000-0000-4000-8000-000000000040",
    );
    Scenario {
        id: "get_history/unauthorized-is-indistinguishable-from-missing",
        operation: "get_history",
        fixture: private_message_fixture(sender, recipient, outsider),
        setup: private_message_setup(
            sender,
            recipient,
            outsider,
            message,
            "private history body",
            "c0d90000-0000-4000-8000-000000000038",
        ),
        invocation: ToolCall {
            caller: TestCaller::member("acct:corpus-outsider"),
            tool: "get_history",
            arguments: json!({ "record_id": message }),
        },
        expect: Expect::Error {
            contains: "does not exist",
        },
        post: private_message_post(message, "private history body"),
        divergences: vec![],
    }
}

fn private_message_denied_delete_scenario() -> Scenario {
    let (sender, recipient, outsider, message) = (
        "c0d90000-0000-4000-8000-000000000023",
        "c0d90000-0000-4000-8000-000000000022",
        "c0d90000-0000-4000-8000-000000000020",
        "c0d90000-0000-4000-8000-000000000021",
    );
    Scenario {
        id: "delete_record/recipient-cannot-delete-sender-message",
        operation: "delete_record",
        fixture: private_message_fixture(sender, recipient, outsider),
        setup: private_message_setup(
            sender,
            recipient,
            outsider,
            message,
            "private delete body",
            "c0d90000-0000-4000-8000-000000000013",
        ),
        invocation: ToolCall {
            caller: TestCaller::member("acct:corpus-recipient"),
            tool: "delete_record",
            arguments: json!({ "id": message, "reason": REASON }),
        },
        expect: Expect::ExactError {
            equals: "delete_record: record c0d90000-0000-4000-8000-000000000021 requires manage capability; caller has view capability",
        },
        post: private_message_post(message, "private delete body"),
        divergences: legacy_capability_denial_divergences(),
    }
}

fn private_message_authorized_history_scenario() -> Scenario {
    let (sender, recipient, outsider, message) = (
        "c0d90000-0000-4000-8000-000000000037",
        "c0d90000-0000-4000-8000-000000000036",
        "c0d90000-0000-4000-8000-000000000034",
        "c0d90000-0000-4000-8000-000000000035",
    );
    Scenario {
        id: "get_history/authorized-recipient-sees-portable-history",
        operation: "get_history",
        fixture: private_message_fixture(sender, recipient, outsider),
        setup: private_message_setup(
            sender,
            recipient,
            outsider,
            message,
            "private authorized history body",
            "c0d90000-0000-4000-8000-000000000033",
        ),
        invocation: ToolCall {
            caller: TestCaller::member("acct:corpus-recipient"),
            tool: "get_history",
            arguments: json!({ "record_id": message }),
        },
        expect: Expect::Result(vec![("/events", json!([{ "type": "record.created" }]))]),
        post: private_message_post(message, "private authorized history body"),
        divergences: vec![],
    }
}

/// Complete an expected found-record value with the corpus defaults so every
/// scenario states only what it cares about while the comparison stays exact.
fn found_record(partial: Value) -> Value {
    let mut record = json!({
        "status": "found",
        "id": null,
        "type": null,
        "kind": null,
        "name": null,
        "body": "",
        "summary": "",
        "lifecycle": null,
        "maturity": null,
        "home_id": native_ce::schema::UNFILED_RECORD_ID,
        "archived": false,
        "deleted": false,
        "facets": [],
        "body_digest": null,
    });
    let defaults = record.as_object_mut().expect("defaults are an object");
    for (key, value) in partial.as_object().expect("partial is an object") {
        assert!(
            defaults.contains_key(key),
            "expected record key {key:?} is outside the corpus snapshot shape"
        );
        defaults.insert(key.clone(), value.clone());
    }
    // Every ordinary record shape carries the write token, so the corpus pins
    // it rather than letting a backend quietly omit it. Derived from the body
    // the snapshot already states: a null or empty body hashes as `""`, exactly
    // as the write guard compares it.
    if defaults
        .get("body_digest")
        .is_none_or(|digest| digest.is_null())
    {
        let body = defaults
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        defaults.insert("body_digest".into(), json!(sha256_hex(body.as_bytes())));
    }
    record
}

/// The corpus-owned logical projection of one record, identical for every
/// backend. Keys outside this shape (physical timestamps, storage defaults
/// such as home or ownership routing) are deliberately excluded until they
/// are proven portable.
fn normalize_record(record: &Value) -> Value {
    let status = record
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("found");
    if status != "found" {
        return json!({ "status": status });
    }
    let text_or_empty = |key: &str| match record.get(key) {
        Some(Value::String(text)) => Value::String(text.clone()),
        _ => Value::String(String::new()),
    };
    let optional_text = |key: &str| match record.get(key) {
        Some(Value::String(text)) => Value::String(text.clone()),
        _ => Value::Null,
    };
    let lifecycle = match record
        .get("lifecycle_interpretation")
        .and_then(|interpretation| interpretation.get("status"))
        .and_then(Value::as_str)
    {
        Some("governed") => record["lifecycle_interpretation"]["value"]
            .get("raw")
            .cloned()
            .unwrap_or(Value::Null),
        Some("unclassified") => record["lifecycle_interpretation"]
            .get("raw")
            .cloned()
            .unwrap_or(Value::Null),
        _ => Value::Null,
    };
    let mut facets = record
        .get("facets")
        .and_then(Value::as_array)
        .map(|facets| {
            facets
                .iter()
                .map(|facet| {
                    json!({
                        "key": facet.get("key").cloned().unwrap_or(Value::Null),
                        "value": facet.get("value").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    facets.sort_by(|left, right| {
        let key = |facet: &Value, field: &str| {
            facet
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        (key(left, "key"), key(left, "value")).cmp(&(key(right, "key"), key(right, "value")))
    });
    json!({
        "status": "found",
        "id": record.get("id").cloned().unwrap_or(Value::Null),
        "type": record.get("type").cloned().unwrap_or(Value::Null),
        "kind": record.get("kind").cloned().unwrap_or(Value::Null),
        "name": record.get("name").cloned().unwrap_or(Value::Null),
        "body": text_or_empty("body"),
        "summary": text_or_empty("summary"),
        "lifecycle": lifecycle,
        "maturity": optional_text("maturity"),
        "home_id": optional_text("home_id"),
        "archived": record.get("archived").and_then(Value::as_bool).unwrap_or(false),
        "deleted": record.get("deleted_at").is_some_and(|value| !value.is_null()),
        "facets": facets,
        "body_digest": optional_text("body_digest"),
    })
}

/// Event types whose presence and order are part of the portable contract.
/// Backends may additionally serialize archive/facet writes as their own
/// event shapes; those stay outside the corpus event projection while the
/// record post-conditions pin the resulting state.
const PORTABLE_EVENT_TYPES: [&str; 2] = ["record.created", "record.updated"];

fn normalize_history(result: &Value) -> Value {
    let events = result
        .get("events")
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter(|event| {
                    event
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| PORTABLE_EVENT_TYPES.contains(&kind))
                })
                .map(|event| {
                    let kind = event.get("type").cloned().unwrap_or(Value::Null);
                    if kind == json!("record.updated") {
                        let body = match event.pointer("/payload/body") {
                            Some(Value::String(text)) => Value::String(text.clone()),
                            _ => Value::String(String::new()),
                        };
                        json!({ "type": kind, "body": body })
                    } else {
                        json!({ "type": kind })
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({ "events": events })
}

/// Normalize an invocation result once for all backends, per tool.
fn normalize_result(tool: &str, result: &Value) -> Value {
    match tool {
        "get_record" => {
            let records = result
                .get("records")
                .and_then(Value::as_array)
                .map(|records| records.iter().map(normalize_record).collect::<Vec<_>>())
                .unwrap_or_default();
            json!({ "records": records })
        }
        "get_history" => normalize_history(result),
        "create_record" => {
            let mut record = normalize_record(result);
            record
                .as_object_mut()
                .expect("normalized record is an object")
                .remove("status");
            record
        }
        "update_record" if result.get("results").is_some() => result.clone(),
        "update_record" => {
            let mut record = normalize_record(result);
            record
                .as_object_mut()
                .expect("normalized record is an object")
                .remove("status");
            record
        }
        "delete_record" => {
            json!({ "deleted": result.get("deleted").cloned().unwrap_or(Value::Null) })
        }
        "archive_record" => {
            json!({ "changed": result.get("changed").cloned().unwrap_or(Value::Null) })
        }
        _ => result.clone(),
    }
}

/// One scenario that was accounted for by an explicit divergence instead of
/// being executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountedDivergence {
    pub scenario: &'static str,
    pub boundary: AdapterBoundary,
    pub justification: &'static str,
}

/// The executable proof level for one operation on one backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofLevel {
    /// Every scenario in the operation's corpus slice executed and none
    /// diverged.
    Full,
    /// At least one scenario executed, but an explicit divergence kept the
    /// entire slice from executing.
    Partial,
    /// No scenario in the operation's slice executed; every scenario was
    /// accounted for by an explicit divergence.
    None,
}

/// Corpus proof for one governed operation.
#[derive(Debug, PartialEq, Eq)]
pub struct OperationProof {
    pub operation: &'static str,
    pub level: ProofLevel,
    /// The complete scenario slice the runner accounted for.
    pub accounted: Vec<&'static str>,
    /// The subset that actually executed.
    pub executed: Vec<&'static str>,
    pub divergences: Vec<AccountedDivergence>,
}

/// Outcome of one full corpus run on one backend.
pub struct CorpusRun {
    pub backend: Backend,
    /// Every scenario visited by the runner, whether executed or diverged.
    pub accounted: Vec<&'static str>,
    /// Scenarios whose fixture, invocation, postconditions, and replay check
    /// all executed successfully.
    pub executed: Vec<&'static str>,
    pub divergences: Vec<AccountedDivergence>,
}

/// Validate the corpus table itself. Runners call this before executing, so a
/// malformed scenario fails every lane rather than silently narrowing one.
pub fn validate_scenarios(scenarios: &[Scenario]) -> std::result::Result<(), String> {
    let mut ids = std::collections::BTreeSet::new();
    for scenario in scenarios {
        if !ids.insert(scenario.id) {
            return Err(format!("duplicate corpus scenario id {:?}", scenario.id));
        }
        if !CORPUS_OPERATIONS.contains(&scenario.operation) {
            return Err(format!(
                "corpus scenario {:?} names ungoverned operation {:?}",
                scenario.id, scenario.operation
            ));
        }
        if !scenario.id.starts_with(&format!("{}/", scenario.operation)) {
            return Err(format!(
                "corpus scenario id {:?} must be namespaced under its operation {:?}",
                scenario.id, scenario.operation
            ));
        }
        if scenario.invocation.tool != scenario.operation {
            return Err(format!(
                "corpus scenario {:?} invokes {:?} but claims operation {:?}",
                scenario.id, scenario.invocation.tool, scenario.operation
            ));
        }
        let mut backends = std::collections::BTreeSet::new();
        for divergence in &scenario.divergences {
            if !backends.insert(format!("{:?}", divergence.backend)) {
                return Err(format!(
                    "corpus scenario {:?} declares more than one divergence for {:?}",
                    scenario.id, divergence.backend
                ));
            }
            if divergence.justification.trim().len() < 20 {
                return Err(format!(
                    "corpus scenario {:?} divergence for {:?} needs a written justification",
                    scenario.id, divergence.backend
                ));
            }
        }
        if backends.len() >= 3 {
            return Err(format!(
                "corpus scenario {:?} diverges on every backend; it proves nothing",
                scenario.id
            ));
        }
    }
    Ok(())
}

/// Execute every corpus scenario on one backend. Each scenario runs against a
/// fresh logical database. A scenario is either executed or reported as an
/// explicitly declared divergence; nothing can be skipped silently.
pub async fn run_full_corpus<H: ContractHarness>(
    harness: &H,
    backend: Backend,
) -> Result<CorpusRun> {
    let table = scenarios();
    validate_scenarios(&table).map_err(Error::engine)?;
    let mut run = CorpusRun {
        backend,
        accounted: Vec::new(),
        executed: Vec::new(),
        divergences: Vec::new(),
    };
    for scenario in &table {
        run.accounted.push(scenario.id);
        if let Some(divergence) = scenario
            .divergences
            .iter()
            .find(|divergence| divergence.backend == backend)
        {
            run.divergences.push(AccountedDivergence {
                scenario: scenario.id,
                boundary: divergence.boundary,
                justification: divergence.justification,
            });
            continue;
        }
        execute_scenario(harness, backend, scenario).await?;
        run.executed.push(scenario.id);
    }
    assert_eq!(
        run.accounted.len(),
        table.len(),
        "every corpus scenario must be accounted for on {backend:?}"
    );
    Ok(run)
}

async fn execute_scenario<H: ContractHarness>(
    harness: &H,
    backend: Backend,
    scenario: &Scenario,
) -> Result<()> {
    let database = harness.fresh_logical_database().await?;
    let outcome = execute_scenario_in_database(harness, backend, scenario, &database).await;
    harness.close(&database).await;
    outcome
}

async fn execute_scenario_in_database<H: ContractHarness>(
    harness: &H,
    backend: Backend,
    scenario: &Scenario,
    database: &H::Database,
) -> Result<()> {
    let context = |detail: &str| format!("corpus {:?} on {backend:?}: {detail}", scenario.id);
    for (index, call) in scenario.fixture.iter().enumerate() {
        harness
            .call(
                database,
                call.caller.clone(),
                call.tool,
                call.arguments.clone(),
            )
            .await
            .map_err(|error| {
                Error::engine(context(&format!(
                    "fixture call {index} ({}) failed: {error}",
                    call.tool
                )))
            })?;
    }
    for (index, setup) in scenario.setup.iter().enumerate() {
        let result = match setup {
            Setup::ProvisionMember {
                person_id,
                account_id,
                principal_id,
            } => {
                harness
                    .provision_member(database, person_id, account_id, principal_id)
                    .await
            }
            Setup::DeliverMessage {
                sender_account_id,
                id,
                name,
                body,
                recipient_id,
                idempotency_key,
            } => {
                harness
                    .deliver_message_fixture(
                        database,
                        TestCaller::member(*sender_account_id),
                        DeliveredMessageFixture {
                            id,
                            name,
                            body,
                            addressed_to: &[*recipient_id],
                            idempotency_key,
                        },
                    )
                    .await
            }
            Setup::RestrictRecordToAccount {
                record_id,
                account_id,
            } => {
                harness
                    .restrict_record_to_account_for_test(database, record_id, account_id)
                    .await
            }
            Setup::CreateAttribution { record_id } => {
                harness
                    .create_attribution_record_for_test(database, record_id)
                    .await
            }
            Setup::ActivateInstructionSource {
                record_id,
                binding_id,
            } => {
                harness
                    .activate_instruction_source_for_test(database, record_id, binding_id)
                    .await
            }
        };
        result.map_err(|error| {
            Error::engine(context(&format!(
                "portable setup step {index} failed: {error}"
            )))
        })?;
    }

    let invocation = &scenario.invocation;
    let outcome = harness
        .call(
            database,
            invocation.caller.clone(),
            invocation.tool,
            invocation.arguments.clone(),
        )
        .await;
    match &scenario.expect {
        Expect::Result(checks) => {
            let result = outcome
                .map_err(|error| Error::engine(context(&format!("invocation failed: {error}"))))?;
            let normalized = normalize_result(invocation.tool, &result);
            for (pointer, expected) in checks {
                let actual = normalized.pointer(pointer);
                if actual != Some(expected) {
                    return Err(Error::engine(format!(
                        "{} (normalized result: {normalized})",
                        context(&format!("pointer {pointer} mismatched"))
                    )));
                }
            }
        }
        Expect::Error { contains } => {
            let error = match outcome {
                Err(error) => error.to_string(),
                Ok(result) => {
                    return Err(Error::engine(context(&format!(
                        "expected an error but received {result}"
                    ))))
                }
            };
            if !error.contains(contains) {
                return Err(Error::engine(context(&format!(
                    "error {error:?} does not mention expected fragment {contains:?}"
                ))));
            }
        }
        Expect::ExactError { equals } => {
            let error = match outcome {
                Err(error) => error.to_string(),
                Ok(result) => {
                    return Err(Error::engine(context(&format!(
                        "expected exact error but received {result}"
                    ))))
                }
            };
            if error != *equals {
                return Err(Error::engine(context(&format!(
                    "error {error:?} did not equal {equals:?}"
                ))));
            }
        }
    }

    for (record_id, expected) in &scenario.post.records {
        let response = harness
            .call(
                database,
                TestCaller::Local,
                "get_record",
                json!({ "ids": [record_id] }),
            )
            .await
            .map_err(|error| {
                Error::engine(context(&format!(
                    "post read of {record_id} failed: {error}"
                )))
            })?;
        let actual = normalize_record(&response["records"][0]);
        if &actual != expected {
            return Err(Error::engine(context(&format!(
                "post-condition snapshot for {record_id} diverged: expected={expected}, actual={actual}"
            ))));
        }
    }
    for (record_id, expected_count) in &scenario.post.updated_events {
        let history = harness
            .call(
                database,
                TestCaller::Local,
                "get_history",
                json!({ "record_id": record_id }),
            )
            .await
            .map_err(|error| {
                Error::engine(context(&format!(
                    "post history of {record_id} failed: {error}"
                )))
            })?;
        let count = history["events"]
            .as_array()
            .map(|events| {
                events
                    .iter()
                    .filter(|event| event["type"] == "record.updated")
                    .count()
            })
            .unwrap_or(0);
        if count != *expected_count {
            return Err(Error::engine(context(&format!(
                "update-event count for {record_id} diverged"
            ))));
        }
    }

    harness
        .assert_replay_equivalent(database)
        .await
        .map_err(|error| {
            Error::engine(context(&format!("authoritative replay diverged: {error}")))
        })?;
    Ok(())
}

/// The whole corpus slice for one operation. "Full proof" for that operation
/// on a backend means exactly this slice passing there.
pub fn slice(operation: &str) -> Vec<&'static str> {
    scenarios()
        .iter()
        .filter(|scenario| scenario.operation == operation)
        .map(|scenario| scenario.id)
        .collect()
}

/// Classify one operation from the runner's explicit accounting. The corpus
/// table provides the canonical order, so the result is deterministic even if
/// a caller constructs the run vectors in a different order.
pub fn proof_for(run: &CorpusRun, operation: &'static str) -> OperationProof {
    let operation_slice = slice(operation);
    assert!(
        !operation_slice.is_empty(),
        "governed corpus operation {operation:?} has no scenario"
    );

    let accounted = operation_slice
        .iter()
        .copied()
        .filter(|id| run.accounted.contains(id))
        .collect::<Vec<_>>();
    assert_eq!(
        accounted, operation_slice,
        "corpus run on {:?} did not account for the entire {operation:?} slice",
        run.backend
    );
    let executed = operation_slice
        .iter()
        .copied()
        .filter(|id| run.executed.contains(id))
        .collect::<Vec<_>>();
    let divergences = operation_slice
        .iter()
        .filter_map(|id| {
            run.divergences
                .iter()
                .find(|divergence| divergence.scenario == *id)
                .copied()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        executed.len() + divergences.len(),
        operation_slice.len(),
        "corpus run on {:?} did not resolve every {operation:?} scenario as executed or diverged",
        run.backend
    );

    let level = if divergences.is_empty() && executed.len() == operation_slice.len() {
        ProofLevel::Full
    } else if executed.is_empty() {
        ProofLevel::None
    } else {
        ProofLevel::Partial
    };
    OperationProof {
        operation,
        level,
        accounted,
        executed,
        divergences,
    }
}

/// Require executable Full proof for each named operation.
pub fn assert_full_proof(run: &CorpusRun, operations: &[&'static str]) {
    assert_run_is_complete(run);
    for operation in operations {
        let proof = proof_for(run, operation);
        assert_eq!(
            proof.level,
            ProofLevel::Full,
            "corpus proof for {:?} on {:?} is {:?}: executed={:?}, divergences={:?}",
            operation,
            run.backend,
            proof.level,
            proof.executed,
            proof.divergences
        );
    }
}

/// Assert a corpus run accounted for the whole table exactly once. This is
/// deliberately weaker than [`assert_full_proof`]: explicit divergences count
/// as accounted, but never as executed.
pub fn assert_run_is_complete(run: &CorpusRun) {
    let table = scenarios();
    let mut accounted: Vec<&str> = run.accounted.clone();
    accounted.sort_unstable();
    let mut all: Vec<&str> = table.iter().map(|scenario| scenario.id).collect();
    all.sort_unstable();
    assert_eq!(
        accounted, all,
        "corpus run on {:?} did not account for every scenario",
        run.backend
    );
    assert_eq!(
        run.executed.len() + run.divergences.len(),
        run.accounted.len(),
        "corpus run on {:?} did not distinguish every accounted scenario as executed or diverged",
        run.backend
    );
    for divergence in &run.divergences {
        assert!(
            !divergence.justification.trim().is_empty(),
            "corpus divergence for {:?} on {:?} lacks a justification ({:?})",
            divergence.scenario,
            run.backend,
            divergence.boundary
        );
    }
}
