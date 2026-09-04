use std::collections::BTreeMap;

use native_ce::Result;
use serde_json::{json, Map, Value};

/// Caller identities understood by the portable contract corpus.
///
/// A backend harness owns the conversion from these logical identities to its
/// concrete dispatch context. Shared scenarios therefore do not depend on
/// `native_ce::mcp::Caller` or hosting-specific routing details.
#[derive(Clone, Debug)]
pub enum TestCaller {
    /// Trusted local operator used for fixture setup and standalone calls.
    Local,
    /// An authenticated member identified by a portable account credential.
    Member { account_id: String },
}

impl TestCaller {
    pub fn member(account_id: impl Into<String>) -> Self {
        Self::Member {
            account_id: account_id.into(),
        }
    }
}

/// Backend-neutral description of a delivered Message used by shared tests.
#[derive(Clone, Copy, Debug)]
pub struct DeliveredMessageFixture<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub body: &'a str,
    pub addressed_to: &'a [&'a str],
    pub idempotency_key: &'a str,
}

/// Test-only contract implemented by each physical storage backend.
///
/// The associated database type is intentionally opaque to scenario code. The
/// shared corpus can dispatch real MCP tools, take a canonical logical
/// snapshot, and ask the backend to verify authoritative replay, but it cannot
/// inspect a pool, path, SQL dialect, or physical row type.
///
/// A future `PostgresHarness` should implement this trait beside the SQLite
/// implementation and run the same functions in `scenarios`; it should not
/// introduce a production storage trait merely to satisfy these tests.
pub trait ContractHarness: Sync {
    type Database: Clone + Send + Sync;

    async fn fresh_logical_database(&self) -> Result<Self::Database>;

    async fn call(
        &self,
        database: &Self::Database,
        caller: TestCaller,
        tool: &str,
        arguments: Value,
    ) -> Result<Value>;

    /// Bind one portable person fixture to the authenticated identities used
    /// by [`TestCaller::Member`]. This is harness setup, not an observable
    /// product operation; authorization assertions still dispatch through MCP.
    async fn provision_member(
        &self,
        database: &Self::Database,
        person_id: &str,
        account_id: &str,
        principal_id: &str,
    ) -> Result<()>;

    /// Restrict one fixture record to an account so shared scenarios can
    /// assert that boundary lookups do not become existence oracles.
    async fn restrict_record_to_account_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        account_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id, account_id);
        Err(native_ce::Error::engine(
            "contract harness does not support policy restriction fixtures",
        ))
    }

    /// Create a governed attribution-shaped fixture through a backend's
    /// authoritative test seam. General record tools must never discover it
    /// by prefix.
    async fn create_attribution_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id);
        Err(native_ce::Error::engine(
            "contract harness does not support attribution fixtures",
        ))
    }

    /// Seed one record the way an older build left it behind: a projected
    /// `record.created` with a caller-chosen, non-UUID id. Today's admission
    /// rule refuses such an id, so this is the only way to state the
    /// historical shapes that boundary resolution must still answer for.
    async fn create_historical_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        name: &str,
    ) -> Result<()> {
        let _ = (database, record_id, name);
        Err(native_ce::Error::engine(
            "contract harness does not support historical record fixtures",
        ))
    }

    /// Tombstone one fixture without changing its policy. View scenarios use
    /// this to prove that authorization is evaluated before any tombstone
    /// diagnostic can become an existence oracle.
    async fn tombstone_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id);
        Err(native_ce::Error::engine(
            "contract harness does not support tombstone fixtures",
        ))
    }

    /// Create one governed suggestion fixture, optionally attached to a
    /// bearer through `part_of` and optionally tombstoned.
    async fn create_suggestion_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        bearer_id: Option<&str>,
        home_id: Option<&str>,
        tombstoned: bool,
    ) -> Result<()> {
        let _ = (database, record_id, bearer_id, home_id, tombstoned);
        Err(native_ce::Error::engine(
            "contract harness does not support suggestion fixtures",
        ))
    }

    /// Mark a populated container archived in the physical projection. The
    /// production write path correctly rejects archiving a container with
    /// live children; this fixture seam exists to exercise defensive read
    /// pruning against imported or legacy state that already has that shape.
    async fn mark_record_archived_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id);
        Err(native_ce::Error::engine(
            "contract harness does not support archived projection fixtures",
        ))
    }

    /// Rehome one fixture directly so the shared read contract can prove that
    /// a governed hidden intermediate prunes its otherwise ordinary child.
    async fn rehome_record_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        home_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id, home_id);
        Err(native_ce::Error::engine(
            "contract harness does not support projection rehome fixtures",
        ))
    }

    /// Install more scoped dependency links than the portable dashboard may
    /// inspect so the shared receipt proves bounded rejection in each
    /// adapter's physical store.
    async fn create_dashboard_link_overflow_for_test(
        &self,
        database: &Self::Database,
        source_id: &str,
    ) -> Result<()> {
        let _ = (database, source_id);
        Err(native_ce::Error::engine(
            "contract harness does not support dashboard overflow fixtures",
        ))
    }

    /// Seed more unauthorized lexical rows and unrelated links than search's
    /// physical caps. The caller-visible result must be unchanged because
    /// eligibility precedes every result- or error-affecting bound.
    async fn create_search_hidden_overflow_for_test(
        &self,
        database: &Self::Database,
        home_id: &str,
        policy_anchor_id: &str,
    ) -> Result<()> {
        let _ = (database, home_id, policy_anchor_id);
        Err(native_ce::Error::engine(
            "contract harness does not support search overflow fixtures",
        ))
    }

    async fn activate_instruction_source_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
        binding_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id, binding_id);
        Err(native_ce::Error::engine(
            "contract harness does not support instruction-source fixtures",
        ))
    }

    /// Install one identical typed schema and vocabulary projection. The
    /// product mutation tools for these rows are outside the current portable
    /// backend slice; observable facet calls still cross production dispatch.
    async fn install_facet_governance_fixture_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        let _ = database;
        Err(native_ce::Error::engine(
            "contract harness does not support facet governance fixtures",
        ))
    }

    /// Install one over-limit current facet set and governing vocabulary for
    /// explicit physical receipts of the two 10,000-row response caps.
    async fn install_facet_bounds_overflow_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<()> {
        let _ = (database, record_id);
        Err(native_ce::Error::engine(
            "contract harness does not support facet overflow fixtures",
        ))
    }

    /// Install governed records that ordinary record tools must treat as
    /// missing: an attribution and a malformed comment projection.
    async fn install_ineligible_facet_records_for_test(
        &self,
        database: &Self::Database,
    ) -> Result<()> {
        let _ = database;
        Err(native_ce::Error::engine(
            "contract harness does not support governed facet eligibility fixtures",
        ))
    }

    /// Add one schema row scoped to a caller-hidden collection.
    async fn install_hidden_scoped_facet_schema_for_test(
        &self,
        database: &Self::Database,
        scope_id: &str,
    ) -> Result<()> {
        let _ = (database, scope_id);
        Err(native_ce::Error::engine(
            "contract harness does not support scoped facet schema fixtures",
        ))
    }

    async fn facet_event_count_for_test(
        &self,
        database: &Self::Database,
        record_id: &str,
    ) -> Result<i64> {
        let _ = (database, record_id);
        Err(native_ce::Error::engine(
            "contract harness does not support facet event counts",
        ))
    }

    /// Establish a delivered Message fixture with an addressed audience.
    ///
    /// This is a semantic contract capability rather than a portable product
    /// tool: each backend must use its supported atomic write path, and the
    /// resulting events and audience projection remain subject to the shared
    /// authorization and replay assertions.
    async fn deliver_message_fixture(
        &self,
        database: &Self::Database,
        sender: TestCaller,
        fixture: DeliveredMessageFixture<'_>,
    ) -> Result<()>;

    /// Replay authoritative state using the backend's own conformance path and
    /// fail if the rebuilt logical projections differ from the live state.
    async fn assert_replay_equivalent(&self, database: &Self::Database) -> Result<()>;

    async fn close(&self, database: &Self::Database);

    /// Read a stable subset of logical record state through MCP tools only.
    ///
    /// Generated timestamps and transport echoes are deliberately excluded.
    /// Records and facets are explicitly ordered, making snapshots comparable
    /// across physical backends without prescribing their schemas.
    async fn logical_snapshot(
        &self,
        database: &Self::Database,
        caller: TestCaller,
        record_ids: &[&str],
    ) -> Result<Value> {
        let mut ids = record_ids.to_vec();
        ids.sort_unstable();
        ids.dedup();

        let response = self
            .call(
                database,
                caller.clone(),
                "get_record",
                json!({ "ids": ids }),
            )
            .await?;
        let mut records = BTreeMap::new();
        for record in response["records"].as_array().into_iter().flatten() {
            let Some(id) = record.get("id").and_then(Value::as_str) else {
                continue;
            };
            let mut logical = Map::new();
            for key in [
                "status",
                "id",
                "type",
                "kind",
                "name",
                "body",
                "summary",
                "home_id",
                "lifecycle",
                "owner_id",
                "persistence",
                "maturity",
                "archived",
            ] {
                if let Some(value) = record.get(key) {
                    logical.insert(key.to_string(), value.clone());
                }
            }
            logical.insert(
                "deleted".into(),
                Value::Bool(
                    record
                        .get("deleted_at")
                        .is_some_and(|value| !value.is_null()),
                ),
            );

            let mut facets = record
                .get("facets")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            facets.sort_by(|left, right| {
                left.get("key")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("key").and_then(Value::as_str).unwrap_or(""))
                    .then_with(|| {
                        left.get("value")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .cmp(right.get("value").and_then(Value::as_str).unwrap_or(""))
                    })
            });
            logical.insert("facets".into(), Value::Array(facets));

            records.insert(id.to_string(), Value::Object(logical));
        }
        Ok(json!({ "records": records }))
    }
}
