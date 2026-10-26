//! Storage for HCP v2 entries: sealed Native events, folded.
//!
//! A person's entries are the ordered fold of their admitted HCP events
//! ([`super::fold`]): v1 `hcp_state` control events or v2 principal-private
//! content events and atomic projections. Every operation reads the
//! person's events, validates, and appends the events it implies; the
//! person's private record for the entry is a *view* of that state, written
//! afterwards ([`super::view`]).
//!
//! **Why the events are the authority.** An entry record is an ordinary
//! Native record: the person, and any agent holding their access, can edit,
//! share or transfer it. So its body and facets are never read as evidence.
//! The aggregate the events live in is derived from the authenticated
//! [`Caller`]'s account ([`crate::control::hcp_state_aggregate_id`]); a record,
//! a share or a transfer cannot name it. No generic tool can append an
//! `hcp.*` event: the constructor needs [`super::HcpWriteSeal`], which only
//! this module tree can mint.
//!
//! Subject pseudonyms come from a server-held key
//! ([`super::client::PseudonymKey`]); nothing about them is stored in the
//! person's workspace.

use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use crate::control::{
    ControlEventPayload, HcpClientPayload, HcpEntryStatusSetPayload, HcpEntryVersionedPayload,
    NewControlEvent,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;

use super::client::{ClientIdentity, PseudonymKey};
use super::fold::{self, Fold, FoldedEntry, StoredEvent};
use super::model::Entry;

const MAX_REASON_CHARS: usize = 500;

pub(super) const URN_PREFIX: &str = "urn:uuid:";

pub(super) fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `urn:uuid:<id>` for a record id.
pub(super) fn entry_urn(record_id: &str) -> String {
    format!("{URN_PREFIX}{record_id}")
}

/// The record id behind an entry URN, or `None` when `urn` cannot name an
/// entry. A malformed identifier is "no such entry", not a distinct error.
pub(super) fn record_id_of(urn: &str) -> Option<String> {
    let id = urn.strip_prefix(URN_PREFIX)?;
    let parsed = uuid::Uuid::parse_str(id).ok()?;
    (parsed.hyphenated().to_string() == id).then(|| id.to_string())
}

/// The identifier entries carry for the Context Subject. It is never shown to
/// a Context Client, which sees its own pseudonym instead, and it is derived
/// from the account alone so it does not move if the pseudonym key is
/// replaced.
pub(super) fn stored_subject_id_of(account: &str) -> String {
    let digest = sha256_hex(&format!("hcp-v2/stored-subject|{account}"));
    format!("urn:native:hcp:subject:{}", &digest[..32])
}

/// An entry as it stands for clients.
#[derive(Clone, Debug)]
pub(super) struct Stored {
    /// The current version, with its current status.
    pub entry: Entry,
    /// Every version, oldest first (`versions[n - 1]` is version `n`).
    pub versions: Vec<Entry>,
}

impl From<&FoldedEntry> for Stored {
    fn from(folded: &FoldedEntry) -> Self {
        Stored {
            entry: folded.current().clone(),
            versions: folded.versions.clone(),
        }
    }
}

/// A write transaction over the person's HCP state.
pub(super) type WriteTx = Transaction<'static, Sqlite>;

pub(super) struct Store<'a> {
    pub(super) db: &'a Db,
    kernel_principal: Option<String>,
    pub(super) caller: &'a Caller,
    key: Option<PseudonymKey>,
    pub client: ClientIdentity,
    /// The account identity, hashed before it is written into a facet.
    pub person: String,
    pub(super) correlation_id: String,
}

impl<'a> Store<'a> {
    pub(super) fn new(
        db: &'a Db,
        caller: &'a Caller,
        client: ClientIdentity,
        key: PseudonymKey,
    ) -> Self {
        Self {
            db,
            kernel_principal: None,
            caller,
            key: Some(key),
            client,
            person: sha256_hex(caller.actor()),
            correlation_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub(super) fn is_kernel(&self) -> bool {
        self.kernel_principal.is_some()
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) async fn new_kernel(
        db: &'a Db,
        caller: &'a Caller,
        client: ClientIdentity,
        key: PseudonymKey,
    ) -> Result<Self> {
        let principal = crate::mcp::kernel_v2::principal(db, caller).await?;
        let mut store = Self::new(db, caller, client, key);
        store.person = sha256_hex(&principal);
        store.kernel_principal = Some(principal);
        Ok(store)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(super) fn management_kernel(db: &'a Db, caller: &'a Caller, principal: String) -> Self {
        Self {
            db,
            caller,
            key: None,
            client: ClientIdentity::native(),
            person: sha256_hex(&principal),
            kernel_principal: Some(principal),
            correlation_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// The authenticated account the aggregate is derived from.
    pub(super) fn account(&self) -> &str {
        self.kernel_principal
            .as_deref()
            .unwrap_or_else(|| self.caller.credential())
    }

    pub(super) fn stored_subject_id(&self) -> String {
        stored_subject_id_of(self.account())
    }

    /// The identifier this client sees for the person.
    pub(super) fn pseudonym(&self) -> String {
        self.key
            .as_ref()
            .expect("context client key")
            .pseudonym(self.caller.actor(), &self.client.id)
    }

    /// The reason Native records for a write. The client's own reason, where
    /// the operation takes one, is shown to the person in history.
    pub(super) fn reason(&self, what: &str, client_reason: Option<&str>) -> String {
        let mut reason = format!(
            "HCP v2 {what} via client {} (correlation {})",
            self.client.id, self.correlation_id
        );
        if let Some(client_reason) = client_reason {
            let trimmed: String = client_reason.chars().take(MAX_REASON_CHARS).collect();
            reason.push_str(": ");
            reason.push_str(&trimmed);
        }
        reason
    }

    pub(super) fn client_payload(&self) -> HcpClientPayload {
        payload_of(&self.client)
    }

    // ---- reading ----------------------------------------------------------

    /// The caller's `hcp_state` events in log order, only those of `entry_id`
    /// when it is given. The aggregate is derived from the caller's account,
    /// so another person's events are never read.
    pub(super) async fn events(
        &self,
        conn: &mut SqliteConnection,
        entry_id: Option<&str>,
    ) -> Result<Vec<StoredEvent>> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            return super::kernel::events(conn, self.account(), entry_id).await;
        }
        let aggregate = crate::control::hcp_state_aggregate_id(self.account());
        let rows = sqlx::query(
            "SELECT seq, type, payload FROM control_events \
              WHERE aggregate_kind = 'hcp_state' AND aggregate_id = ?1 \
                AND (?2 IS NULL OR json_extract(payload, '$.entry_id') = ?2) \
              ORDER BY seq",
        )
        .bind(aggregate)
        .bind(entry_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(StoredEvent {
                    seq: row.try_get("seq")?,
                    event_type: row.try_get("type")?,
                    payload: row.try_get("payload")?,
                })
            })
            .collect()
    }

    pub(super) fn fold_events(&self, events: &[StoredEvent]) -> Fold {
        fold::fold(self.account(), &self.stored_subject_id(), events)
    }

    /// Every entry of the caller, folded from the log as it stands.
    pub(super) async fn fold_all(&self) -> Result<Fold> {
        let mut conn = self.db.write_pool().acquire().await?;
        let events = self.events(&mut conn, None).await?;
        Ok(self.fold_events(&events))
    }

    pub(super) async fn fold_all_in(&self, tx: &mut WriteTx) -> Result<Fold> {
        let events = self.events(tx, None).await?;
        Ok(self.fold_events(&events))
    }

    /// The entry with this URN, if it is one the caller created: any malformed,
    /// unknown or someone else's identifier reads as `None`.
    #[cfg(test)]
    pub(super) async fn entry(&self, urn: &str) -> Result<Option<Stored>> {
        let mut conn = self.db.write_pool().acquire().await?;
        self.entry_on(&mut conn, urn).await
    }

    /// [`Store::entry`] inside a write transaction, so the version a write
    /// builds on is the one it appends after.
    pub(super) async fn entry_in(&self, tx: &mut WriteTx, urn: &str) -> Result<Option<Stored>> {
        self.entry_on(tx, urn).await
    }

    async fn entry_on(&self, conn: &mut SqliteConnection, urn: &str) -> Result<Option<Stored>> {
        if record_id_of(urn).is_none() {
            return Ok(None);
        }
        let events = self.events(conn, Some(urn)).await?;
        Ok(self.fold_events(&events).entries.get(urn).map(Stored::from))
    }

    /// The folded entry (digests and event counts included), for the view.
    pub(super) async fn folded(&self, urn: &str) -> Result<Option<FoldedEntry>> {
        if record_id_of(urn).is_none() {
            return Ok(None);
        }
        let mut conn = self.db.write_pool().acquire().await?;
        let events = self.events(&mut conn, Some(urn)).await?;
        Ok(self.fold_events(&events).entries.remove(urn))
    }

    pub(super) async fn folded_in(
        &self,
        tx: &mut WriteTx,
        urn: &str,
    ) -> Result<Option<FoldedEntry>> {
        let events = self.events(tx, Some(urn)).await?;
        Ok(self.fold_events(&events).entries.remove(urn))
    }

    // ---- writing ----------------------------------------------------------

    /// Open the one write transaction an operation runs in. Writers are
    /// serialized by it, so the state an operation reads is the state its
    /// events are appended to.
    pub(super) async fn begin(&self) -> Result<WriteTx> {
        let tx = crate::db::begin_write(self.db.write_pool()).await?;
        #[cfg(feature = "v2-kernel-probe")]
        let mut tx = tx;
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            if !crate::kernel::hosted_identity::admitted(&mut tx, self.account()).await? {
                return Err(Error::engine("database membership not found"));
            }
            crate::kernel::app_installs::admit_dispatched_on(&mut tx, self.account()).await?;
        }
        Ok(tx)
    }

    /// Commit an operation's transaction.
    pub(super) async fn commit(&self, tx: WriteTx) -> Result<()> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            return self.db.commit_kernel_content(tx).await;
        }
        self.db.commit_control(tx).await
    }

    /// Append the first version of a new entry.
    pub(super) async fn append_add(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        entry: &Entry,
    ) -> Result<()> {
        self.append_versioned(
            tx,
            act,
            entry,
            "add",
            None,
            None,
            1,
            payload_of(&self.client),
            self.reason("add", None),
            sha256_hex(&entry.0.to_string()),
        )
        .await?;
        self.evaluate_conflicts(tx, act, entry.id(), None).await
    }

    /// Append `next` as the version after `current`.
    pub(super) async fn append_update(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        current: &Stored,
        next: &Entry,
        client_reason: &str,
    ) -> Result<()> {
        let prior_category = (current.entry.category() != next.category())
            .then(|| current.entry.category().to_string());
        self.append_versioned(
            tx,
            act,
            next,
            "update",
            prior_category,
            Some(client_reason),
            next.version(),
            payload_of(&self.client),
            self.reason("update", Some(client_reason)),
            sha256_hex(&next.0.to_string()),
        )
        .await?;
        self.evaluate_conflicts(tx, act, next.id(), Some(&current.entry))
            .await
    }

    /// Append `next` as the version the person's edit of the view of `current`
    /// makes. Native itself is the submitting client: the client whose call
    /// happened to notice the edit did not make it. `edited_digest` is the
    /// digest of the body the person wrote: it is the view body this event
    /// answers, and it is stale from now on (the fold also learns the digest
    /// of the normalised `next`).
    pub(super) async fn append_native_edit(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        current: &Entry,
        next: &Entry,
        edited_digest: &str,
    ) -> Result<()> {
        let prior_category =
            (current.category() != next.category()).then(|| current.category().to_string());
        self.append_versioned(
            tx,
            act,
            next,
            "native-edit",
            prior_category,
            None,
            next.version(),
            payload_of(&ClientIdentity::native()),
            format!(
                "HCP v2 native-edit: the person edited the entry's view in Native (correlation {})",
                self.correlation_id
            ),
            edited_digest.to_string(),
        )
        .await?;
        self.evaluate_conflicts(tx, act, next.id(), Some(current))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn append_versioned(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        entry: &Entry,
        cause: &str,
        prior_category: Option<String>,
        client_reason: Option<&str>,
        version: u64,
        client: HcpClientPayload,
        reason: String,
        view_digest: String,
    ) -> Result<()> {
        let payload = HcpEntryVersionedPayload {
            account_id: self.account().to_string(),
            entry_id: entry.id().to_string(),
            version,
            cause: cause.to_string(),
            prior_category,
            client,
            reason: client_reason.map(str::to_string),
            entry: entry.0.clone(),
            view_digest,
        };
        // One identity per version of an entry: a second event for the same
        // version is refused by the log itself, not only ignored by the fold.
        let key = format!("hcp-state:{}:{}:v{version}", self.account(), entry.id());
        self.append(
            tx,
            act,
            key,
            reason,
            ControlEventPayload::HcpEntryVersioned(payload),
        )
        .await?;
        Ok(())
    }

    /// Append a status change of `current`'s version to `to`.
    pub(super) async fn append_status(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        current: &Stored,
        to: &str,
        cause: &str,
        client_reason: &str,
    ) -> Result<()> {
        self.append_transition(
            tx,
            act,
            current,
            to,
            cause,
            client_reason,
            None,
            self.client_payload(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn append_transition(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        current: &Stored,
        to: &str,
        cause: &str,
        reason: &str,
        related: Option<&str>,
        client: HcpClientPayload,
    ) -> Result<()> {
        let entry_id = current.entry.id().to_string();
        let version = current.entry.version();
        let folded = self
            .folded_in(tx, &entry_id)
            .await?
            .ok_or_else(|| Error::engine("an entry being changed has no state in the log"))?;
        let mut viewed = current.entry.clone();
        viewed.set_status(to);
        let payload = HcpEntryStatusSetPayload {
            account_id: self.account().to_string(),
            entry_id: entry_id.clone(),
            version,
            from: current.entry.status().to_string(),
            to: to.to_string(),
            cause: cause.to_string(),
            related_entry_id: related.map(str::to_string),
            client,
            reason: Some(reason.to_string()),
            view_digest: Some(sha256_hex(&viewed.view_body())),
        };
        let key = format!(
            "hcp-state:{}:{entry_id}:v{version}:status:{}",
            self.account(),
            folded.status_events(version)
        );
        self.append(
            tx,
            act,
            key,
            self.reason(cause_label(cause), Some(reason)),
            ControlEventPayload::HcpEntryStatusSet(payload),
        )
        .await
    }

    pub(super) async fn append(
        &self,
        tx: &mut WriteTx,
        act: &mut crate::act::ActAllocation,
        key: String,
        reason: String,
        payload: ControlEventPayload,
    ) -> Result<()> {
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            return super::kernel::append(self.db, tx, act, self.account(), key, reason, payload)
                .await;
        }
        let event = NewControlEvent::hcp_state(
            &super::HcpWriteSeal::mint(),
            key,
            self.caller.run_key().map(str::to_owned),
            reason,
            payload,
        )?;
        crate::control::append_control_event_in(tx, event, act).await?;
        Ok(())
    }
}

pub(super) fn payload_of(client: &ClientIdentity) -> HcpClientPayload {
    HcpClientPayload {
        id: client.id.clone(),
        name: client.name.clone(),
        operator_id: client.operator_id.clone(),
        operator_name: client.operator_name.clone(),
    }
}

fn cause_label(cause: &str) -> &'static str {
    match cause {
        "client_delete" => "delete",
        _ => "status change",
    }
}
