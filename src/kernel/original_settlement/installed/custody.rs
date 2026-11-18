//! Canonical evidence that hosted observed an authenticated installed write.
//! A committed observation says nothing about the original write's outcome.

use super::*;
use crate::coedit::live::kernel_writes::{
    owned_result, KernelBodyWrite, KernelTransaction, KernelWriteMode,
};

const OBSERVE: &str = "native.node.observe-original.v1";
const RECEIPT: &str = r#"{"observed":true}"#;
const PAGE_SIZE: usize = 64;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedWrite {
    pub sequence: u64,
    pub original_binding_sha256: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationPage {
    pub high_water: u64,
    pub observed: Vec<ObservedWrite>,
    pub next_after: Option<u64>,
}

pub(super) struct Scope {
    account: String,
    principal: String,
    origin: String,
    key_scope: String,
}

impl Scope {
    pub(super) fn new(route: &AuthenticatedRoute<'_>, install: &str) -> Result<Self> {
        if !digest(install) {
            return Err(Error::auth("invalid installed custody authority"));
        }
        let key_scope = sha(
            "native.node.custody-scope.v1\0",
            &json!([
                route.account,
                route.principal,
                route.database,
                route.origin,
                install
            ]),
        );
        Ok(Self {
            account: route.account.into(),
            principal: route.principal.into(),
            origin: route.origin.into(),
            key_scope,
        })
    }

    fn key(&self, sequence: u64) -> String {
        // Equal-width hexadecimal keeps BINARY order equal to full u64 order.
        format!("{}:{sequence:016x}", self.key_scope)
    }

    async fn require_current_on(&self, conn: &mut SqliteConnection) -> Result<()> {
        let principal: Option<String> = sqlx::query_scalar(
            "SELECT principal_id FROM main.kernel_principals WHERE auth_binding=? AND kind='account'",
        )
        .bind(&self.account)
        .fetch_optional(&mut *conn)
        .await?;
        if principal.as_deref() != Some(self.principal.as_str())
            || fences::origin_on(conn).await? != self.origin
        {
            return Err(Error::auth("installed custody authority changed"));
        }
        if !fences::typed_on(conn).await? {
            return Err(unverified());
        }
        fences::require_current_guards_on(conn).await
    }

    pub(super) async fn require_observed_on(
        &self,
        conn: &mut SqliteConnection,
        sequence: u64,
        binding: &str,
    ) -> Result<()> {
        let key = self.key(sequence);
        match lookup_outcome_on(conn, &self.principal, OBSERVE, &key).await? {
            KeyedOutcome::Accepted {
                request, receipt, ..
            } if self
                .checked_fact(&key, &request, &receipt)?
                .original_binding_sha256
                == binding =>
            {
                Ok(())
            }
            _ => Err(unverified()),
        }
    }

    fn checked_fact(&self, key: &str, request: &str, receipt: &str) -> Result<ObservedWrite> {
        let fact: ObservedWrite = serde_json::from_str(request)?;
        if fact.sequence == 0
            || key != self.key(fact.sequence)
            || !digest(&fact.original_binding_sha256)
            || receipt != RECEIPT
        {
            return Err(unverified());
        }
        Ok(fact)
    }
}

fn unverified() -> Error {
    Error::engine("installed custody observation coverage unverified")
}

/// Record a signed write before dispatch. The verified install, sequence and
/// original must come from the same authenticated request. The route guard
/// must recheck catalog database admission and retain the deployment Write
/// lease through physical writer settlement.
pub async fn observe(
    db: &Db,
    route: &AuthenticatedRoute<'_>,
    install: &str,
    sequence: u64,
    original: &Original,
) -> Result<()> {
    let scope = Scope::new(route, install)?;
    if (
        original.account_id.as_str(),
        original.principal_id.as_str(),
        original.database_id.as_str(),
        original.origin_database_id.as_str(),
    ) != (route.account, route.principal, route.database, route.origin)
    {
        return Err(Error::auth("invalid installed custody authority"));
    }
    let (binding, _) = recompute_binding(original)?;
    if sequence == 0
        || binding != original.expected_binding_sha256
        || crate::mcp::executor_prototype::original_settlement_contract(
            original.journal_variant,
            &original.operation,
            original.arguments["action"].as_str(),
            &original.catalog_executor,
            &original.catalog_operation,
            Some(&original.retained_contract_digest),
        )?
        .as_deref()
            != Some(original.retained_contract_digest.as_str())
    {
        return Err(invalid());
    }

    let fact = ObservedWrite {
        sequence,
        original_binding_sha256: binding,
    };
    let guard = route.guard.clone();
    let db = db.clone();
    owned_result(db.clone(), async move {
        let caller = crate::mcp::registry::Caller::authenticated(&scope.account);
        let body = KernelBodyWrite::acquire(&db, &caller, None, KernelWriteMode::Metadata).await?;
        let owner = SettlementOwner { body, guard };
        let mut tx = KernelTransaction::begin(&db, owner, SettlementOwner::quarantine).await?;
        let work = async {
            let (conn, owner) = tx.parts();
            owner.guard.recheck().await?;
            scope.require_current_on(conn).await?;
            observe_on(&db, conn, &scope, &fact).await?;
            owner.body.validate_in(conn).await
        }
        .await;
        match work {
            Ok(()) => tx.commit().await.map(|_| ()),
            Err(error) => Err(tx.rollback(error).await),
        }
    })
    .await
}

async fn observe_on(
    db: &Db,
    conn: &mut SqliteConnection,
    scope: &Scope,
    fact: &ObservedWrite,
) -> Result<()> {
    let key = scope.key(fact.sequence);
    let high_water = high_water_on(conn, scope).await?;
    match lookup_outcome_on(conn, &scope.principal, OBSERVE, &key).await? {
        KeyedOutcome::Accepted {
            request, receipt, ..
        } => {
            if scope.checked_fact(&key, &request, &receipt)? != *fact {
                return Err(Error::conflict(
                    "installed custody sequence bound to another original",
                ));
            }
            return Ok(());
        }
        KeyedOutcome::Terminal { .. } => return Err(unverified()),
        KeyedOutcome::Absent if fact.sequence <= high_water => {
            return Err(Error::conflict(
                "installed custody sequence is below the high-water",
            ));
        }
        KeyedOutcome::Absent => {}
    }
    receipts::record_on(
        db,
        conn,
        &mut crate::act::ActAllocation::new(),
        receipts::Outcome {
            principal: &scope.principal,
            operation: OBSERVE,
            key: &key,
            request: &serde_json::to_string(fact)?,
            receipt: RECEIPT,
        },
    )
    .await
}

/// Read the exclusive cursor page and current high-water from one snapshot.
/// A later request opens a new snapshot and may report a higher high-water.
pub async fn read_page(
    db: &Db,
    route: &AuthenticatedRoute<'_>,
    install: &str,
    after_sequence: u64,
) -> Result<ObservationPage> {
    let scope = Scope::new(route, install)?;
    route.guard.recheck().await?;
    let mut tx = db.pool().begin().await?;
    scope.require_current_on(&mut tx).await?;
    let high_water = high_water_on(&mut tx, &scope).await?;
    let mut observed = scan_on(
        &mut tx,
        &scope,
        &scope.key(after_sequence),
        false,
        PAGE_SIZE + 1,
    )
    .await?;
    let next_after = if observed.len() > PAGE_SIZE {
        observed.pop();
        observed.last().map(|fact| fact.sequence)
    } else {
        None
    };
    tx.rollback().await?;
    Ok(ObservationPage {
        high_water,
        observed,
        next_after,
    })
}

async fn high_water_on(conn: &mut SqliteConnection, scope: &Scope) -> Result<u64> {
    // Read one extra row to detect duplicate canonical events at the maximum.
    let lower = format!("{}:", scope.key_scope);
    Ok(scan_on(conn, scope, &lower, true, 2)
        .await?
        .first()
        .map_or(0, |fact| fact.sequence))
}

#[derive(sqlx::FromRow)]
struct Projected {
    operation_key: String,
    request_json: String,
    receipt_json: Option<String>,
    outcome_kind: String,
    terminal_json: Option<String>,
    retired_record_id: Option<String>,
}

async fn scan_on(
    conn: &mut SqliteConnection,
    scope: &Scope,
    lower: &str,
    descending: bool,
    limit: usize,
) -> Result<Vec<ObservedWrite>> {
    // Both bounded ranges use the same exclusive bounds and binary order.
    // Scanning canonical keys independently catches missing projection rows,
    // including at the high-water and at the end of a page.
    // ';' immediately follows ':' in BINARY order.
    let upper = format!("{};", scope.key_scope);
    let order = if descending { "DESC" } else { "ASC" };
    let projection = format!(
        "SELECT operation_key,request_json,receipt_json,outcome_kind,terminal_json,retired_record_id
         FROM main.kernel_mcp_write_receipts
         WHERE principal_id=? AND operation=? AND operation_key>? AND operation_key<?
         ORDER BY operation_key {order} LIMIT ?"
    );
    let projected: Vec<Projected> = sqlx::query_as(&projection)
        .bind(&scope.principal)
        .bind(OBSERVE)
        .bind(lower)
        .bind(&upper)
        .bind(limit as i64)
        .fetch_all(&mut *conn)
        .await?;

    let canonical = format!(
        "SELECT payload FROM main.content_events
         WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_receipt_recorded.v1'
         AND actor=? AND CAST(json_extract(payload,'$.operation') AS TEXT)=?
         AND CAST(json_extract(payload,'$.operation_key') AS TEXT)>?
         AND CAST(json_extract(payload,'$.operation_key') AS TEXT)<?
         ORDER BY CAST(json_extract(payload,'$.operation_key') AS TEXT) {order} LIMIT ?"
    );
    let events: Vec<String> = sqlx::query_scalar(&canonical)
        .bind(&scope.principal)
        .bind(OBSERVE)
        .bind(lower)
        .bind(&upper)
        .bind(limit as i64)
        .fetch_all(conn)
        .await?;

    if events.len() != projected.len() {
        return Err(unverified());
    }
    projected
        .into_iter()
        .zip(events)
        .map(|(row, payload)| {
            let event: receipts::Fact = serde_json::from_str(&payload)?;
            if event.operation != OBSERVE
                || event.operation_key != row.operation_key
                || event.request_json != row.request_json
                || row.receipt_json.as_deref() != Some(event.receipt_json.as_str())
                || row.outcome_kind != "accepted"
                || row.terminal_json.is_some()
                || row.retired_record_id.is_some()
            {
                return Err(unverified());
            }
            scope.checked_fact(&row.operation_key, &event.request_json, &event.receipt_json)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::original_settlement::tests::{create, route, world};

    const INSTALL_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const INSTALL_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[tokio::test]
    async fn exact_retry_does_not_append_again() {
        let w = world().await;
        let route = route(&w);
        let original = create(&w, "retry").original;
        let count = || {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM main.content_events
                 WHERE record_id='kernel:mcp-write-receipts'
                 AND type='kernel.mcp_write_receipt_recorded.v1'
                 AND json_extract(payload,'$.operation')=?",
            )
            .bind(OBSERVE)
            .fetch_one(w.db.pool())
        };
        observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .unwrap();
        observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .unwrap();
        assert_eq!(count().await.unwrap(), 1);
        assert_eq!(
            serde_json::to_value(read_page(&w.db, &route, INSTALL_A, 0).await.unwrap()).unwrap(),
            json!({
                "high_water": 1,
                "observed": [{
                    "sequence": 1,
                    "original_binding_sha256": original.expected_binding_sha256,
                }],
                "next_after": null,
            })
        );
    }

    #[tokio::test]
    async fn conflicting_and_stale_slots_fail_closed() {
        let w = world().await;
        let route = route(&w);
        let original = create(&w, "original").original;
        let other = create(&w, "other").original;
        observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .unwrap();
        observe(&w.db, &route, INSTALL_A, 3, &other).await.unwrap();
        assert!(matches!(
            observe(&w.db, &route, INSTALL_A, 1, &other).await,
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            observe(&w.db, &route, INSTALL_A, 2, &original).await,
            Err(Error::Conflict(_))
        ));
        observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .unwrap();
        let page = read_page(&w.db, &route, INSTALL_A, 0).await.unwrap();
        assert_eq!(page.high_water, 3);
        assert_eq!(
            page.observed
                .iter()
                .map(|fact| fact.sequence)
                .collect::<Vec<_>>(),
            [1, 3]
        );
    }

    #[tokio::test]
    async fn observations_are_install_scoped_and_require_the_current_account() {
        let w = world().await;
        let route = route(&w);
        let original = create(&w, "a").original;
        let other = create(&w, "b").original;
        observe(&w.db, &route, INSTALL_A, 9, &original)
            .await
            .unwrap();
        assert_eq!(
            read_page(&w.db, &route, INSTALL_B, 0)
                .await
                .unwrap()
                .high_water,
            0
        );
        observe(&w.db, &route, INSTALL_B, 9, &other).await.unwrap();
        for (install, original) in [(INSTALL_A, &original), (INSTALL_B, &other)] {
            let page = read_page(&w.db, &route, install, 0).await.unwrap();
            assert_eq!(page.high_water, 9);
            assert_eq!(
                page.observed[0].original_binding_sha256,
                original.expected_binding_sha256
            );
        }

        // An actual second account cannot act as the enrolled principal.
        let wrong = AuthenticatedRoute {
            account: "acct:admin",
            ..route
        };
        let mut forged = original;
        forged.account_id = wrong.account.into();
        forged.expected_binding_sha256 = recompute_binding(&forged).unwrap().0;
        assert!(matches!(
            observe(&w.db, &wrong, INSTALL_A, 10, &forged).await,
            Err(Error::Auth(_))
        ));
        assert!(matches!(
            read_page(&w.db, &wrong, INSTALL_A, 0).await,
            Err(Error::Auth(_))
        ));
    }

    #[tokio::test]
    async fn observation_survives_operation_refusal() {
        let w = world().await;
        let route = route(&w);
        let original = create(&w, "abandoned").original;
        let result = installed::settle(
            &w.db,
            &route,
            INSTALL_A,
            installed::Action::Abandon,
            original.clone(),
        )
        .await
        .unwrap();
        assert_eq!(result["verdict"], "unapplied_terminal");
        observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .unwrap();
        assert!(matches!(
            installed::write(&w.db, &route, INSTALL_A, 1, original.clone()).await,
            Err(Error::Conflict(_))
        ));
        let page = read_page(&w.db, &route, INSTALL_A, 0).await.unwrap();
        assert_eq!(page.high_water, 1);
        assert_eq!(
            page.observed[0].original_binding_sha256,
            original.expected_binding_sha256
        );
    }

    #[tokio::test]
    async fn bounded_pages_keep_unsigned_sequence_order() {
        let w = world().await;
        let route = route(&w);
        let original = create(&w, "paged").original;
        for sequence in 1..=PAGE_SIZE as u64 {
            observe(&w.db, &route, INSTALL_A, sequence, &original)
                .await
                .unwrap();
        }
        observe(&w.db, &route, INSTALL_A, u64::MAX, &original)
            .await
            .unwrap();
        let first = read_page(&w.db, &route, INSTALL_A, 0).await.unwrap();
        assert_eq!(first.high_water, u64::MAX);
        assert_eq!(first.observed.len(), PAGE_SIZE);
        assert_eq!(first.next_after, Some(PAGE_SIZE as u64));
        let last = read_page(&w.db, &route, INSTALL_A, first.next_after.unwrap())
            .await
            .unwrap();
        assert_eq!(last.high_water, u64::MAX);
        assert_eq!(last.observed.len(), 1);
        assert_eq!(last.observed[0].sequence, u64::MAX);
        assert_eq!(last.next_after, None);
    }

    #[tokio::test]
    async fn missing_projection_is_neither_an_empty_page_nor_a_free_slot() {
        let w = world().await;
        let route = route(&w);
        let original = create(&w, "missing-projection").original;
        observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .unwrap();
        sqlx::query("DELETE FROM main.kernel_mcp_write_receipts WHERE operation=?")
            .bind(OBSERVE)
            .execute(w.db.write_pool())
            .await
            .unwrap();
        assert!(read_page(&w.db, &route, INSTALL_A, 0).await.is_err());
        assert!(observe(&w.db, &route, INSTALL_A, 1, &original)
            .await
            .is_err());
    }
}
