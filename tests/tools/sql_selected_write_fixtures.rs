//! Independent public baseline and singular oracles for the three tasks fixed
//! in docs/sql-selected-bulk-write-v1-spec.md at 346f21b.
//!
//! No selector, compiler, resolver, prototype wire call, or query_sql is used.
//! Manifest/cohort/effect expectations come only from the table below. SQL is
//! read-only here, for authoritative state/log audits, never fixture injection
//! or target discovery. Each test constructs its own isolated database.

use std::collections::BTreeMap;

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

pub(super) const SETUP_ACCOUNT: &str = "acct:sql-write-fixture-setup";
pub(super) const SELECTION_ACCOUNT: &str = "acct:sql-write-fixture-selection";
pub(super) const REASON: &str =
    "Apply the independently fixed folder task through its public singular API.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Label {
    F,
    G,
    S,
    D,
    A,
    B,
    C,
    X,
    N,
    O,
    H,
    T,
}

impl Label {
    // Safe caller-supplied v4 ids, fixed before any public create call. The
    // same manifest can be used in independent oracle/preview databases.
    pub(super) const fn id(self) -> &'static str {
        match self {
            Self::F => "c0510000-0000-4000-8000-000000000001",
            Self::G => "c0510000-0000-4000-8000-000000000002",
            Self::S => "c0510000-0000-4000-8000-000000000003",
            Self::D => "c0510000-0000-4000-8000-000000000004",
            Self::A => "c0510000-0000-4000-8000-000000000005",
            Self::B => "c0510000-0000-4000-8000-000000000006",
            Self::C => "c0510000-0000-4000-8000-000000000007",
            Self::X => "c0510000-0000-4000-8000-000000000008",
            Self::N => "c0510000-0000-4000-8000-000000000009",
            Self::O => "c0510000-0000-4000-8000-00000000000a",
            Self::H => "c0510000-0000-4000-8000-00000000000b",
            Self::T => "c0510000-0000-4000-8000-00000000000c",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct BaselineRow {
    pub(super) label: Label,
    pub(super) home: Label,
    pub(super) triage: &'static str,
    pub(super) archived: bool,
    pub(super) review: &'static str,
    pub(super) visible: bool,
    pub(super) tombstoned: bool,
}

pub(super) const BASELINE: [BaselineRow; 8] = [
    BaselineRow {
        label: Label::A,
        home: Label::F,
        triage: "ready",
        archived: false,
        review: "pending",
        visible: true,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::B,
        home: Label::F,
        triage: "ready",
        archived: false,
        review: "approved",
        visible: true,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::C,
        home: Label::F,
        triage: "ready",
        archived: true,
        review: "pending",
        visible: true,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::X,
        home: Label::F,
        triage: "hold",
        archived: false,
        review: "pending",
        visible: true,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::N,
        home: Label::S,
        triage: "ready",
        archived: false,
        review: "pending",
        visible: true,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::O,
        home: Label::G,
        triage: "ready",
        archived: false,
        review: "pending",
        visible: true,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::H,
        home: Label::F,
        triage: "ready",
        archived: false,
        review: "pending",
        visible: false,
        tombstoned: false,
    },
    BaselineRow {
        label: Label::T,
        home: Label::F,
        triage: "ready",
        archived: false,
        review: "pending",
        visible: true,
        tombstoned: true,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Task {
    Review,
    Relate,
    Archive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EventIntent {
    FacetAssertion,
    CreatePropositionAndSupport,
    AddSupport,
    ArchiveFacet,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ExpectedEffect {
    pub(super) label: Label,
    // None for relationships: assertion intent does not promise a reducer
    // transition of the existing effective/epistemic state.
    pub(super) state_changed: Option<bool>,
    pub(super) before: Value,
    pub(super) after: Value,
    pub(super) event_intent: EventIntent,
}

impl Task {
    pub(super) fn cohort(self) -> Vec<Label> {
        BASELINE
            .iter()
            .filter(|row| {
                row.home == Label::F
                    && row.visible
                    && !row.tombstoned
                    && row.triage == "ready"
                    && (self == Self::Archive || !row.archived)
            })
            .map(|row| row.label)
            .collect()
    }

    pub(super) fn ids(self) -> Vec<&'static str> {
        self.cohort().into_iter().map(Label::id).collect()
    }

    pub(super) fn expected_effects(self) -> Vec<ExpectedEffect> {
        self.cohort()
            .into_iter()
            .map(|label| {
                let row = BASELINE.iter().find(|row| row.label == label).unwrap();
                match self {
                    Self::Review => ExpectedEffect {
                        label,
                        state_changed: Some(row.review != "approved"),
                        before: json!(row.review),
                        after: json!("approved"),
                        event_intent: EventIntent::FacetAssertion,
                    },
                    Self::Relate => ExpectedEffect {
                        label,
                        state_changed: None,
                        before: json!({"proposition_present": label == Label::B}),
                        after: json!({"support_assertion_intended": true}),
                        event_intent: if label == Label::B {
                            EventIntent::AddSupport
                        } else {
                            EventIntent::CreatePropositionAndSupport
                        },
                    },
                    Self::Archive => ExpectedEffect {
                        label,
                        state_changed: Some(!row.archived),
                        before: json!(row.archived),
                        after: json!(true),
                        event_intent: if row.archived {
                            EventIntent::None
                        } else {
                            EventIntent::ArchiveFacet
                        },
                    },
                }
            })
            .collect()
    }
}

pub(super) struct Fixture {
    pub(super) db: Db,
    pub(super) registry: ToolRegistry,
    pub(super) setup_receipts: Vec<Value>,
    pub(super) visibility_receipts: Vec<Value>,
}

impl Fixture {
    pub(super) fn selection_caller(&self) -> Caller {
        Caller::authenticated(SELECTION_ACCOUNT).with_hosting_owner(false)
    }

    pub(super) fn setup_caller(&self) -> Caller {
        Caller::authenticated(SETUP_ACCOUNT).with_hosting_owner(false)
    }

    pub(super) async fn call_as(
        &self,
        caller: Caller,
        tool: &str,
        args: Value,
    ) -> native_ce::Result<Value> {
        let result = self
            .registry
            .call(self.db.clone(), caller, tool, args)
            .await;
        self.db.drain_captures_for_tests().await;
        result
    }

    pub(super) async fn call(&self, tool: &str, args: Value) -> Value {
        self.call_as(self.selection_caller(), tool, args)
            .await
            .unwrap()
    }

    pub(super) async fn setup_call(&self, tool: &str, args: Value) -> Value {
        self.call_as(self.setup_caller(), tool, args).await.unwrap()
    }

    pub(super) async fn new() -> Self {
        let db = create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        let mut fixture = Self {
            db,
            registry,
            setup_receipts: Vec::new(),
            visibility_receipts: Vec::new(),
        };

        // Engine-local initialization uses only the same public tools. No
        // synthetic account binding or projection row is needed. All later
        // setup writes and singular oracles use ordinary authenticated accounts.
        let schema = fixture
            .call_as(
                Caller::local(),
                "manage_schema_config",
                json!({
                    "action":"write", "data":{"shapes":{"Document:note":{"facets":{
                        "triage_state":{"values":["ready","hold"]},
                        "review_state":{"values":["pending","approved"]}
                    }}}}
                }),
            )
            .await
            .unwrap();
        fixture.setup_receipts.push(schema);
        for (label, home, folder) in [
            (Label::F, None, true),
            (Label::G, None, true),
            (Label::S, Some(Label::F), true),
            (Label::D, Some(Label::G), false),
        ] {
            fixture.create(label, home, folder, None).await;
            fixture.policy(label, Some("view")).await;
        }
        for row in BASELINE {
            fixture
                .create(row.label, Some(row.home), false, Some(row))
                .await;
            fixture
                .policy(row.label, row.visible.then_some("manage"))
                .await;
        }
        let archived = fixture.setup_call("archive_record", json!({"id":Label::C.id(),"reason":"Establish the fixed already-archived member C."})).await;
        fixture.setup_receipts.push(archived);
        let deleted = fixture
            .setup_call(
                "delete_record",
                json!({"id":Label::T.id(),"reason":"Establish the fixed tombstoned distractor T."}),
            )
            .await;
        fixture.setup_receipts.push(deleted);
        let link = fixture.setup_call("manage_links", json!({"action":"add","source_id":Label::B.id(),"target_id":Label::D.id(),"relationship":"relates_to"})).await;
        fixture.setup_receipts.push(link);
        fixture.assert_baseline().await;
        fixture
    }

    async fn create(
        &mut self,
        label: Label,
        home: Option<Label>,
        folder: bool,
        row: Option<BaselineRow>,
    ) {
        let mut args = json!({"id":label.id(),"name":format!("{label:?}"),"type":if folder {"Collection"} else {"Document"},"kind":if folder {"folder"} else {"note"},"reason":"Construct the independent, fixed public fixture manifest."});
        if let Some(home) = home {
            args["home_id"] = json!(home.id());
        }
        if folder {
            args["persistence"] = json!("enduring");
        }
        if label == Label::D {
            args["body"] = json!("The explicitly designated decision destination, outside F.");
        }
        if let Some(row) = row {
            args["facets"] = json!({"triage_state":row.triage,"review_state":row.review});
        }
        let receipt = self
            .call_as(Caller::local(), "create_record", args)
            .await
            .unwrap();
        assert_eq!(receipt["id"], label.id());
        self.setup_receipts.push(receipt);
    }

    async fn policy(&mut self, label: Label, selection_capability: Option<&str>) {
        let list = self
            .call_as(
                Caller::local(),
                "manage_record_policy",
                json!({"action":"list","record_id":label.id()}),
            )
            .await
            .unwrap();
        let mut entries = vec![
            json!({"subject":{"kind":"account","account_id":SETUP_ACCOUNT},"capability":"manage"}),
        ];
        if let Some(capability) = selection_capability {
            entries.push(json!({"subject":{"kind":"account","account_id":SELECTION_ACCOUNT},"capability":capability}));
        }
        let receipt = self.call_as(Caller::local(), "manage_record_policy", json!({"action":"replace","record_id":label.id(),"entries":entries,"if_policy_revision":list["policy_revision"],"reason":"Fix exact authenticated authority independently of inherited member grants."})).await.unwrap();
        self.setup_receipts.push(receipt);
    }

    pub(super) async fn assert_baseline(&mut self) {
        assert_eq!(Task::Review.cohort(), vec![Label::A, Label::B]);
        assert_eq!(Task::Relate.cohort(), vec![Label::A, Label::B]);
        assert_eq!(Task::Archive.cohort(), vec![Label::A, Label::B, Label::C]);
        assert_eq!(Task::Review.ids(), vec![Label::A.id(), Label::B.id()]);
        assert_eq!(self.selection_caller().credential(), SELECTION_ACCOUNT);
        let schema = self
            .call("manage_schema_config", json!({"action":"read"}))
            .await;
        for (key, values) in [
            ("triage_state", json!(["ready", "hold"])),
            ("review_state", json!(["pending", "approved"])),
        ] {
            let definition = &schema["resolved"]["shapes"]["Document:note"]["facets"][key];
            assert_eq!(definition["values"], values);
            assert!(
                definition.get("type").is_none(),
                "text uses the public default lane"
            );
        }
        for label in [Label::F, Label::G, Label::S, Label::D] {
            let read = self.call("get_record", json!({"ids":[label.id()]})).await;
            let record = &read["records"][0];
            assert_eq!(record["status"], "found");
            assert_eq!(
                record["type"],
                if label == Label::D {
                    "Document"
                } else {
                    "Collection"
                }
            );
            assert_eq!(
                record["kind"],
                if label == Label::D { "note" } else { "folder" }
            );
            if label != Label::D {
                assert_eq!(record["persistence"], "enduring");
            }
            if label == Label::S {
                assert_eq!(record["home_id"], Label::F.id());
                assert!(public_facet(record, "triage_state").is_none());
                assert!(public_facet(record, "review_state").is_none());
            }
            if label == Label::D {
                assert_eq!(record["home_id"], Label::G.id());
            }
            let policy = self
                .call(
                    "manage_record_policy",
                    json!({"action":"inspect","record_id":label.id()}),
                )
                .await;
            assert_eq!(policy["caller_capability"], "view");
            self.visibility_receipts.push(read);
        }
        for row in BASELINE {
            let read = self
                .call("get_record", json!({"ids":[row.label.id()]}))
                .await;
            let record = &read["records"][0];
            assert_eq!(
                record["status"],
                if row.visible && !row.tombstoned {
                    "found"
                } else {
                    "not_found"
                }
            );
            if row.visible && !row.tombstoned {
                assert_eq!(record["home_id"], row.home.id());
                assert_eq!(record["archived"], row.archived);
                assert_eq!(
                    public_facet(record, "triage_state"),
                    Some(json!(row.triage))
                );
                assert_eq!(
                    public_facet(record, "review_state"),
                    Some(json!(row.review))
                );
                assert_eq!(
                    self.call(
                        "manage_record_policy",
                        json!({"action":"inspect","record_id":row.label.id()})
                    )
                    .await["caller_capability"],
                    "manage"
                );
            }
            // H's other-account policy, rather than a hidden projection edit,
            // and T's public tombstone are also established from setup reads.
            let setup_read = self
                .setup_call("get_record", json!({"ids":[row.label.id()]}))
                .await;
            if row.label == Label::H {
                assert_eq!(setup_read["records"][0]["status"], "found");
                assert!(setup_read["records"][0]["owner_id"].is_null());
                let policy = self
                    .setup_call(
                        "manage_record_policy",
                        json!({"action":"list","record_id":row.label.id()}),
                    )
                    .await;
                assert_eq!(policy["entries"].as_array().unwrap().len(), 1);
                assert_eq!(policy["entries"][0]["subject"]["account_id"], SETUP_ACCOUNT);
            }
            if row.label == Label::T {
                assert_eq!(setup_read["records"][0]["status"], "not_found");
            }
            self.visibility_receipts.push(read);
        }
        let audit = self.snapshot().await;
        let tombstone = audit.row("records", "id", Label::T.id());
        assert!(tombstone["deleted_at"].is_string());
        for row in BASELINE {
            let actual = audit.row("records", "id", row.label.id());
            assert_eq!(actual["home_id"], row.home.id());
            assert!(
                actual["owner_id"].is_null(),
                "selection must not inherit owner Manage"
            );
        }
        assert!(audit.relationship_for(Label::A, Label::D).is_none());
        let existing = audit.relationship_for(Label::B, Label::D).unwrap();
        assert_eq!(existing["status"], "active");
        assert_eq!(audit.assertions_for(existing).len(), 1);
        assert_eq!(audit.assertions_for(existing)[0]["stance"], "support");
        assert_eq!(
            audit.assertions_for(existing)[0]["rationale"],
            "manage_links compatibility add"
        );
        // Repeated audits must be stable even after public reads/capture drain.
        assert_eq!(audit, self.snapshot().await);
    }

    pub(super) async fn snapshot(&self) -> DomainSnapshot {
        DomainSnapshot::read(&self.db).await
    }

    pub(super) async fn singular_oracle(&self, task: Task) -> Oracle {
        let before = self.snapshot().await;
        let mut receipts = Vec::new();
        for label in task.cohort() {
            receipts.push(match task {
                Task::Review => self.call("update_record", json!({"id":label.id(),"facets":{"review_state":"approved"},"reason":REASON})).await,
                Task::Relate => self.call("manage_links", json!({"action":"add","source_id":label.id(),"target_id":Label::D.id(),"relationship":"relates_to"})).await,
                Task::Archive => self.call("archive_record", json!({"id":label.id(),"reason":REASON})).await,
            });
        }
        Oracle {
            task,
            expected: task.expected_effects(),
            receipts,
            before,
            after: self.snapshot().await,
        }
    }
}

fn public_facet(record: &Value, key: &str) -> Option<Value> {
    record["facets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|facet| facet["key"] == key)
        .map(|facet| facet["value"].clone())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct EventHeads {
    pub(super) content: i64,
    pub(super) relationship: i64,
    pub(super) policy: i64,
    // Attestations have no sequence: exact rows plus count/set hash audit
    // their append head instead of assuming content seq covers that domain.
    pub(super) attestations: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DomainSnapshot {
    pub(super) rows: BTreeMap<String, Vec<Value>>,
    pub(super) heads: EventHeads,
    pub(super) sha256: String,
}

impl DomainSnapshot {
    async fn read(db: &Db) -> Self {
        // Full bounded fixture domains, including canonical claim columns in
        // records and claim metadata. Plan-store/activity/read-capture tables
        // are deliberately outside this domain snapshot. Future prepare tests
        // still need separate dispatch instrumentation; hashes cannot prove
        // that a dispatch which had no effects was never attempted.
        const TABLES: &[&str] = &[
            "records",
            "facet_values",
            "facet_observations",
            "links",
            "relationships",
            "relationship_endpoints",
            "relationship_assertion_heads",
            "relationship_local_admissions",
            "effective_relationships",
            "relationship_legacy_links",
            "relationship_endpoint_activity",
            "record_policies",
            "policy_entries",
            "policy_events",
            "bindings",
            "schema_config",
            "meta_events",
            "vocabularies",
            "vocabulary_values",
            "binding_audit",
            "act_state",
            "content_events",
            "content_event_claim_meta",
            "content_event_sources",
            "relationship_events",
            "provenance_action_attestations",
            "provenance_action_events",
            "provenance_action_outputs",
            "provenance_local_attestation_authority",
            "provenance_attestation_validity_events",
        ];
        const MAX_ROWS: usize = 10_000;
        let mut tx = db.pool().begin().await.unwrap();
        let mut rows = BTreeMap::new();
        for table in TABLES {
            // Introspection is audit-only. All table names are fixed above;
            // columns come from the engine's schema, never caller SQL.
            let columns: Vec<String> = sqlx::query(&format!("PRAGMA table_info(\"{table}\")"))
                .fetch_all(&mut *tx)
                .await
                .unwrap()
                .iter()
                .map(|row| row.get("name"))
                .collect();
            assert!(!columns.is_empty(), "missing audit domain {table}");
            let fields = columns
                .iter()
                .map(|column| {
                    let quoted = column.replace('"', "\"\"");
                    let literal = column.replace('\'', "''");
                    format!("'{literal}',\"{quoted}\"")
                })
                .collect::<Vec<_>>()
                .join(",");
            let query = format!("SELECT json_object({fields}) AS audit_row FROM \"{table}\" ORDER BY audit_row LIMIT {}", MAX_ROWS + 1);
            let raw: Vec<String> = sqlx::query_scalar(&query)
                .fetch_all(&mut *tx)
                .await
                .unwrap();
            assert!(
                raw.len() <= MAX_ROWS,
                "audit overflow must refuse, never truncate {table}"
            );
            rows.insert(
                (*table).to_owned(),
                raw.iter()
                    .map(|row| serde_json::from_str(row).unwrap())
                    .collect::<Vec<Value>>(),
            );
        }
        tx.commit().await.unwrap();
        let head = |table: &str| {
            rows[table]
                .iter()
                .filter_map(|row| row["seq"].as_i64())
                .max()
                .unwrap_or(0)
        };
        let heads = EventHeads {
            content: head("content_events"),
            relationship: head("relationship_events"),
            policy: head("policy_events"),
            attestations: rows["provenance_action_attestations"].len(),
        };
        let encoded = serde_json::to_vec(&rows).unwrap();
        assert!(
            encoded.len() <= 16 * 1024 * 1024,
            "bounded fixture audit overflow"
        );
        let mut digest = Sha256::new();
        digest.update(b"independent-public-sql-write-fixture-audit.v1\0");
        digest.update(encoded);
        Self {
            rows,
            heads,
            sha256: format!("{:x}", digest.finalize()),
        }
    }

    pub(super) fn row(&self, table: &str, key: &str, value: &str) -> &Value {
        self.rows[table]
            .iter()
            .find(|row| row[key] == value)
            .unwrap_or_else(|| panic!("missing {table}.{key}={value}"))
    }

    pub(super) fn content_since(&self, head: i64) -> Vec<&Value> {
        let mut events: Vec<_> = self.rows["content_events"]
            .iter()
            .filter(|row| row["seq"].as_i64().unwrap() > head)
            .collect();
        events.sort_by_key(|row| row["seq"].as_i64().unwrap());
        events
    }

    pub(super) fn relationships_since(&self, head: i64) -> Vec<&Value> {
        let mut events: Vec<_> = self.rows["relationship_events"]
            .iter()
            .filter(|row| row["seq"].as_i64().unwrap() > head)
            .collect();
        events.sort_by_key(|row| row["seq"].as_i64().unwrap());
        events
    }

    pub(super) fn relationship_for(&self, source: Label, target: Label) -> Option<&Value> {
        self.rows["relationships"].iter().find(|relationship| {
            relationship["relationship_type"] == "relates_to"
                && [("source", source), ("target", target)]
                    .iter()
                    .all(|(role, label)| {
                        self.rows["relationship_endpoints"].iter().any(|endpoint| {
                            endpoint["relationship_id"] == relationship["relationship_id"]
                                && endpoint["relationship_origin_db_id"]
                                    == relationship["relationship_origin_db_id"]
                                && endpoint["role"] == *role
                                && endpoint["record_id"] == label.id()
                        })
                    })
        })
    }

    pub(super) fn assertions_for(&self, relationship: &Value) -> Vec<&Value> {
        self.rows["relationship_assertion_heads"]
            .iter()
            .filter(|row| {
                row["relationship_id"] == relationship["relationship_id"]
                    && row["relationship_origin_db_id"] == relationship["relationship_origin_db_id"]
            })
            .collect()
    }

    pub(super) fn facet(&self, label: Label, key: &str) -> Option<&Value> {
        self.rows["facet_values"]
            .iter()
            .find(|row| row["record_id"] == label.id() && row["key"] == key)
    }
}

pub(super) struct Oracle {
    pub(super) task: Task,
    pub(super) expected: Vec<ExpectedEffect>,
    pub(super) receipts: Vec<Value>,
    pub(super) before: DomainSnapshot,
    pub(super) after: DomainSnapshot,
}

impl Oracle {
    pub(super) fn assert_public_effects(&self) {
        assert_eq!(self.expected, self.task.expected_effects());
        assert_eq!(self.receipts.len(), self.task.cohort().len());
        assert_eq!(self.before.heads.policy, self.after.heads.policy);
        for table in [
            "record_policies",
            "policy_entries",
            "schema_config",
            "bindings",
        ] {
            assert_eq!(
                self.before.rows[table], self.after.rows[table],
                "oracle changed {table}"
            );
        }
        assert!(self.after.rows["content_event_claim_meta"]
            .iter()
            .all(|row| row["claim_class"] == "other"));
        for row in &self.after.rows["records"] {
            for key in ["claimed_by_account", "claimed_run_key", "claimed_at"] {
                assert!(row[key].is_null(), "oracle acquired a claim");
            }
        }
        for label in [Label::X, Label::N, Label::O, Label::H, Label::T] {
            assert_eq!(
                self.before.row("records", "id", label.id()),
                self.after.row("records", "id", label.id())
            );
            for key in ["triage_state", "review_state", "archived"] {
                assert_eq!(self.before.facet(label, key), self.after.facet(label, key));
            }
        }
        match self.task {
            Task::Review => {
                self.assert_facet_events("review_state", "approved", &[Label::A, Label::B]);
                assert_eq!(
                    self.before.facet(Label::C, "review_state"),
                    self.after.facet(Label::C, "review_state")
                );
                assert_eq!(
                    self.before.facet(Label::A, "review_state").unwrap()["value"],
                    "pending"
                );
                assert_eq!(
                    self.before.facet(Label::B, "review_state").unwrap()["value"],
                    "approved"
                );
                for label in [Label::A, Label::B] {
                    assert_eq!(
                        self.after.facet(label, "review_state").unwrap()["value"],
                        "approved"
                    );
                }
                assert_eq!(self.expected[0].state_changed, Some(true));
                assert_eq!(self.expected[1].state_changed, Some(false));
                assert_eq!(self.expected[1].event_intent, EventIntent::FacetAssertion);
                assert_eq!(
                    self.before.rows["relationship_events"],
                    self.after.rows["relationship_events"]
                );
            }
            Task::Archive => {
                self.assert_facet_events("archived", "true", &[Label::A, Label::B]);
                for label in [Label::A, Label::B, Label::C] {
                    assert_eq!(
                        self.after.facet(label, "archived").unwrap()["value"],
                        "true"
                    );
                }
                assert_eq!(self.receipts[0]["changed"], true);
                assert_eq!(self.receipts[1]["changed"], true);
                assert_eq!(self.receipts[2]["changed"], false);
                assert_eq!(
                    self.before.row("records", "id", Label::C.id()),
                    self.after.row("records", "id", Label::C.id())
                );
                assert_eq!(
                    self.before.facet(Label::C, "archived"),
                    self.after.facet(Label::C, "archived")
                );
                assert_eq!(self.expected[2].event_intent, EventIntent::None);
                assert_eq!(
                    self.before.rows["relationship_events"],
                    self.after.rows["relationship_events"]
                );
            }
            Task::Relate => self.assert_relationship_events(),
        }
    }

    fn assert_facet_events(&self, key: &str, value: &str, labels: &[Label]) {
        let events = self.after.content_since(self.before.heads.content);
        assert_eq!(events.len(), labels.len(), "exact authoritative append set");
        for (event, label) in events.iter().zip(labels) {
            assert_eq!(event["record_id"], label.id());
            assert_eq!(event["type"], "facet.set");
            assert_eq!(event["actor"], SELECTION_ACCOUNT);
            let payload: Value = serde_json::from_str(event["payload"].as_str().unwrap()).unwrap();
            assert_eq!(payload["key"], key);
            assert_eq!(payload["value"], value);
            assert_eq!(payload["reason"], REASON);
            assert!(
                payload["vocab_ref"].is_null(),
                "default text lane has no vocabulary identity"
            );
            let observations: Vec<_> = self.after.rows["facet_observations"]
                .iter()
                .filter(|row| row["event_seq"] == event["seq"])
                .collect();
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0]["record_id"], label.id());
            assert_eq!(observations[0]["key"], key);
            assert_eq!(observations[0]["value"], value);
            let outputs: Vec<_> = self.after.rows["provenance_action_outputs"]
                .iter()
                .filter(|output| {
                    output["output_domain"] == "content" && output["output_event_id"] == event["id"]
                })
                .collect();
            assert_eq!(
                outputs.len(),
                1,
                "actual event must have its authoritative action output"
            );
            let attestation_id = outputs[0]["action_attestation_id"].as_str().unwrap();
            let attestation =
                self.after
                    .row("provenance_action_attestations", "id", attestation_id);
            assert_eq!(attestation["principal"], SELECTION_ACCOUNT);
            assert_eq!(
                attestation["operation"],
                if self.task == Task::Review {
                    "update_record"
                } else {
                    "archive_record"
                }
            );
            assert!(!self.before.rows["provenance_action_attestations"]
                .iter()
                .any(|row| row["id"] == attestation_id));
        }
        assert_eq!(
            self.after.heads.attestations - self.before.heads.attestations,
            labels.len()
        );
    }

    fn assert_relationship_events(&self) {
        // Relationship support need not advance endpoint content versions.
        assert_eq!(
            self.before.rows["content_events"],
            self.after.rows["content_events"]
        );
        assert_eq!(self.before.rows["records"], self.after.rows["records"]);
        assert_eq!(
            self.before.rows["facet_values"],
            self.after.rows["facet_values"]
        );
        let events = self
            .after
            .relationships_since(self.before.heads.relationship);
        assert_eq!(
            events
                .iter()
                .map(|event| event["type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "relationship.created.v1",
                "assertion.created.v1",
                "assertion.created.v1"
            ]
        );
        let a = self.after.relationship_for(Label::A, Label::D).unwrap();
        let old_b = self.before.relationship_for(Label::B, Label::D).unwrap();
        let b = self.after.relationship_for(Label::B, Label::D).unwrap();
        assert_eq!(
            old_b, b,
            "existing proposition is unchanged by added support"
        );
        assert_eq!(self.after.assertions_for(a).len(), 1);
        assert_eq!(self.before.assertions_for(old_b).len(), 1);
        assert_eq!(self.after.assertions_for(b).len(), 2);
        assert!(
            self.after
                .assertions_for(b)
                .iter()
                .any(|assertion| assertion == &self.before.assertions_for(old_b)[0]),
            "the old support assertion must remain unchanged"
        );
        for label in [Label::A, Label::B] {
            let links: Vec<_> = self.after.rows["links"]
                .iter()
                .filter(|link| {
                    link["source_id"] == label.id()
                        && link["target_id"] == Label::D.id()
                        && link["relationship"] == "relates_to"
                })
                .collect();
            assert_eq!(
                links.len(),
                1,
                "support re-add must not duplicate the compatibility link"
            );
            assert!(links[0]["note"].is_null());
        }
        assert_eq!(events[0]["relationship_id"], a["relationship_id"]);
        assert_eq!(events[1]["relationship_id"], a["relationship_id"]);
        assert_eq!(events[2]["relationship_id"], b["relationship_id"]);
        let created: Value = serde_json::from_str(events[0]["payload"].as_str().unwrap()).unwrap();
        assert_eq!(created["relationship_type"], "relates_to");
        assert_eq!(created["endpoint_semantics"], "directed");
        assert_eq!(created["endpoints"][0]["record_id"], Label::A.id());
        assert_eq!(created["endpoints"][1]["record_id"], Label::D.id());
        for event in &events {
            assert_eq!(event["actor"], SELECTION_ACCOUNT);
        }
        for (index, event) in events.iter().enumerate().skip(1) {
            let assertion: Value =
                serde_json::from_str(event["payload"].as_str().unwrap()).unwrap();
            assert_eq!(assertion["stance"], "support");
            assert_eq!(assertion["semantic_claimant"], SELECTION_ACCOUNT);
            assert_eq!(assertion["rationale"], "manage_links compatibility add");
            let parents = assertion["causal_parents"].as_array().unwrap();
            if index == 1 {
                assert!(parents.is_empty());
            } else {
                assert_eq!(parents.len(), 1);
                let old_assertion = self.before.assertions_for(old_b)[0];
                assert_eq!(parents[0]["assertion_id"], old_assertion["assertion_id"]);
                assert_eq!(
                    parents[0]["assertion_issuer_origin_db_id"],
                    old_assertion["issuer_origin_db_id"]
                );
                assert_eq!(parents[0]["head_event_id"], old_assertion["last_event_id"]);
                assert_eq!(
                    parents[0]["head_stream_version"],
                    old_assertion["stream_version"]
                );
            }
            let attestation_id = assertion["authoring_action_attestation_id"]
                .as_str()
                .unwrap();
            let attestation =
                self.after
                    .row("provenance_action_attestations", "id", attestation_id);
            assert_eq!(attestation["principal"], SELECTION_ACCOUNT);
            assert_eq!(attestation["operation"], "manage_links");
            let outputs: Vec<_> = self.after.rows["provenance_action_outputs"]
                .iter()
                .filter(|output| output["action_attestation_id"] == attestation_id)
                .collect();
            assert_eq!(outputs.len(), if index == 1 { 2 } else { 1 });
            for output in &outputs {
                assert_eq!(output["output_domain"], "relationship");
            }
            assert!(outputs
                .iter()
                .any(|output| output["output_event_id"] == event["id"]));
            if index == 1 {
                assert!(outputs
                    .iter()
                    .any(|output| output["output_event_id"] == events[0]["id"]));
            }
        }
        assert_eq!(
            self.after.heads.attestations - self.before.heads.attestations,
            2
        );
    }
}

#[tokio::test]
async fn independent_task1_public_baseline_and_same_value_facet_assertion_oracle() {
    let fixture = Fixture::new().await;
    fixture
        .singular_oracle(Task::Review)
        .await
        .assert_public_effects();
}

#[tokio::test]
async fn independent_task2_public_baseline_and_directed_relationship_support_oracle() {
    let fixture = Fixture::new().await;
    fixture
        .singular_oracle(Task::Relate)
        .await
        .assert_public_effects();
}

#[tokio::test]
async fn independent_task3_public_baseline_and_already_archived_no_event_oracle() {
    let fixture = Fixture::new().await;
    fixture
        .singular_oracle(Task::Archive)
        .await
        .assert_public_effects();
}
