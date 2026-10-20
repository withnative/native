//! Hosted saved-session identity, admission and source alignment planning.
//!
//! Saved-session writer primitives (design `f38936b` §§4.2, 5.1–5.4,
//! 6.1–6.6). This module owns:
//!
//! - the hosted transport path: `call_executor` write envelopes with
//!   `no_hold`, forced JSON, no run key and no intent, plus direct-tool
//!   reads, all through the node's real `WriteGate`/`Upstream`;
//! - staged, reconstructible owner-private session identity (Saved-sessions
//!   root → session folder → session record), with crash-tolerant retry;
//! - append/admit: one frozen position-keyed step create at a time, strict
//!   success/conflict/uncertain handling, and verified adoption of a
//!   foreign committed step that provably extends the verified head.
//!
//! Full hosted-chain verification reconstructs `E`; pure alignment plans
//! distinguish rebuilds from known rewinds, including identical regeneration.
//! Marker creates use the same frozen position-keyed transport.
//! Session-state mutations use frozen proposals and a generation/writer lease.
//! Takeover CAS includes its observed heartbeat; failed ownership guards latch
//! a durable stop. Heartbeats are saving-only and continuity notes append-only.
//! The supervisor drives these primitives behind connection selection guards.
//! Provider live/rebuild and quote qualification remain separate admission
//! obligations; this module never starts a service.
//!
//! ## Transport shape (read from engine source)
//!
//! Writes are `tools/call` frames in `call_executor` envelope form
//! (`gate.rs` preserves a caller-supplied non-blank `idempotency_key`;
//! `failover.rs` unwraps the envelope). `format: "json"` keeps structured
//! receipts (`render.rs` strips it before handler parsing). Reads name the
//! registered tool directly (`query_record`, `get_record`, `get_history`,
//! `manage_record_policy`) and pass through the gate unjournaled.
//!
//! ## Authority boundaries
//!
//! - **Binding + server fence** are checked before every send: the local
//!   store binding must match the expected (account, db), and the live
//!   daemon server id must equal the binding's. A changed server id means
//!   the daemon home was reset; nothing is written under the stale binding.
//! - **Owner identity is positive**: the caller's canonical person is
//!   resolved from the Saved-sessions root's own account-only policy entry
//!   (the engine derives it from the canonical account binding), and every
//!   folder/record must be owned by exactly that person. Folders are
//!   verified through their effective policy: mode `inherit`, our own
//!   `manage`, administration authorised, and — for newly created
//!   identities — anchored at the verified root. An existing folder that
//!   the owner has legitimately shared under a channel anchor is accepted
//!   unchanged (never moved, never required to sit under the root).
//! - **Admission is verified, never assumed**: a conflicting position is
//!   adopted only when exactly one owner-owned record extends the verified
//!   head, recomputes to its own `fp`/`cid`, and has create evidence plus
//!   owner-only side effects. Deviation anywhere in that trajectory — even
//!   edited and reverted — refuses. Adoption always leaves the checkpoint
//!   flagged `needs_realign` and reports that alignment is required; this
//!   slice never claims the saving is current.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::error::{Error, Result};

use super::session_persist::{
    chain_root, Binding, FrozenStateProposal, FrozenStepRequest, ProposalKind, SessionStore,
    WriteOutcome, STEP_KIND,
};
use super::session_projection::{fingerprint_step, ProjectedStep, StepKind};

// ---------------------------------------------------------------------------
// Bounds and wire names
// ---------------------------------------------------------------------------

/// Step-query page size: design §5.5 pages history in 100s.
pub const QUERY_PAGE_LIMIT: i64 = 100;
/// Total hosted steps read for one identity/admission pass.
pub const MAX_HOSTED_STEPS: usize = 10_000;
/// History pages followed per record before refusing as partial.
pub const MAX_HISTORY_PAGES: usize = 5;
/// Saved-sessions root lookup facet (§5.1).
pub const ROOT_ACCOUNT_FACET: &str = "native.saved_sessions.account";
/// Session folder marker facet (§5.1).
pub const FOLDER_FACET: &str = "native.session.folder";
/// Saver side-effect facet for quoted replies (§7.3).
pub const QUOTE_LINK_FACET: &str = "native.session.quote_link";
pub(super) const SCHEMA_REQUIRED: &str = "saved-session lifecycle schema is not admitted";

/// Immutable facet keys a step may carry. Anything else is a foreign or
/// out-of-contract write and refuses admission.
const IMMUTABLE_FACET_KEYS: &[&str] = &[
    "native.session.pos",
    "native.session.cid",
    "native.session.parent_cid",
    "native.session.fp",
    "native.session.step_kind",
    "native.session.part_index",
    "native.session.base_len",
    "native.session.branch_no",
    "native.session.occurred_at",
];

// ---------------------------------------------------------------------------
// Binding and server-id fencing (§§4.2, 6.2)
// ---------------------------------------------------------------------------

/// Refuse before any canonical write unless the local binding, the expected
/// account/db, and the live daemon `server_id` all agree.
pub fn check_send_binding(
    store_binding: &Binding,
    account_id: &str,
    db_id: &str,
    daemon_server_id: &str,
) -> Result<()> {
    if daemon_server_id.trim().is_empty() {
        return Err(Error::engine("saver daemon server-id is empty"));
    }
    if store_binding.account_id != account_id || store_binding.db_id != db_id {
        return Err(Error::engine(
            "saver binding mismatch: refusing hosted write under a foreign (account, db)",
        ));
    }
    if store_binding.server_id != daemon_server_id {
        return Err(Error::engine(
            "saver server-id changed: refusing hosted write (old host sessions stay ended)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Remote shapes
// ---------------------------------------------------------------------------

/// One hosted step row, parsed strictly. Only rows carrying the full
/// immutable identity can be admitted; anything else refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStep {
    pub record_id: String,
    pub owner_id: String,
    pub home_id: String,
    pub pos: u64,
    pub body: String,
    pub cid: String,
    pub parent_cid: String,
    pub fp: String,
    pub step_kind: String,
    pub part_index: u32,
    pub base_len: Option<u64>,
    pub branch_no: Option<u64>,
}

/// One hosted history event. `actor` names the caller credential that
/// authored it (person ids appear on records, credentials on events).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEvent {
    pub etype: String,
    pub payload: Value,
    pub actor: Option<String>,
}

/// Hydrated identity facts for one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowIdentity {
    pub id: String,
    pub owner_id: Option<String>,
    pub home_id: Option<String>,
}

/// Session identity: the folder and record the writer needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub folder_id: String,
    pub record_id: String,
}

/// The verified Saved-sessions root plus the caller's canonical person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRoot {
    pub id: String,
    pub name: String,
    /// Canonical person id the engine reports for our account, tied to the
    /// root's own owner. Every later owner comparison uses this value.
    pub owner: String,
}

/// Effective policy view from `manage_record_policy ... action list`.
///
/// Every field the ownership decision needs is retained: the mode, the
/// caller's capability, whether the caller may administer the policy, the
/// authorization target and policy anchor, and each entry's subject with
/// the engine-resolved bound person for account subjects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyView {
    pub record_id: String,
    pub target_id: String,
    pub anchor_id: String,
    pub mode: String,
    pub caller_capability: String,
    pub policy_administration_authorized: bool,
    pub entries: Vec<PolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    /// `members`, `person` or `account`.
    pub subject_kind: String,
    /// Account id (account subjects) or person record id (person subjects).
    pub subject_id: String,
    /// Engine-resolved bound person for an account subject, when visible.
    pub person_id: Option<String>,
    pub capability: String,
}

/// Flatten a hydrated facets ARRAY into a string map. Numeric values arrive
/// as strings on the hydrated row.
fn facet_map(row: &Value) -> Result<BTreeMap<String, String>> {
    let array = row
        .get("facets")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::engine("hosted row facets are missing"))?;
    let mut out = BTreeMap::new();
    for f in array {
        let key = f
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("hosted facet entry has no key"))?;
        let value = f
            .get("value")
            .ok_or_else(|| Error::engine(format!("hosted facet {key} has no value")))?;
        let text = value
            .as_str()
            .map(str::to_owned)
            .or_else(|| value.as_u64().map(|n| n.to_string()))
            .or_else(|| value.as_bool().map(|b| b.to_string()))
            .ok_or_else(|| Error::engine(format!("hosted facet {key} is not scalar")))?;
        out.insert(key.to_owned(), text);
    }
    Ok(out)
}

/// Strict step parser for hydrated `records[]` rows.
pub fn parse_remote_step(row: &Value) -> Result<RemoteStep> {
    let object = row
        .as_object()
        .ok_or_else(|| Error::engine("hosted step row is not an object"))?;
    match object.get("status").and_then(Value::as_str) {
        None | Some("found") => {}
        Some(other) => {
            return Err(Error::engine(format!(
                "hosted step row is not visible: {other}"
            )));
        }
    }
    let string_field = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::engine(format!("hosted step field {key} is missing")))
    };
    let facets = facet_map(row)?;
    let facet = |key: &str| {
        facets
            .get(key)
            .cloned()
            .ok_or_else(|| Error::engine(format!("hosted step facet {key} is missing")))
    };
    let numeric = |key: &str| {
        facet(key)?
            .parse::<u64>()
            .map_err(|_| Error::engine(format!("hosted step facet {key} is not a number")))
    };
    let base_len = match facets.get("native.session.base_len") {
        None => None,
        Some(text) => Some(
            text.parse::<u64>()
                .map_err(|_| Error::engine("hosted step base_len is not a number"))?,
        ),
    };
    Ok(RemoteStep {
        record_id: string_field("id")?,
        owner_id: string_field("owner_id")?,
        home_id: string_field("home_id")?,
        pos: numeric("native.session.pos")?,
        body: string_field("body")?,
        cid: facet("native.session.cid")?,
        parent_cid: facet("native.session.parent_cid")?,
        fp: facet("native.session.fp")?,
        step_kind: facet("native.session.step_kind")?,
        part_index: u32::try_from(numeric("native.session.part_index")?)
            .map_err(|_| Error::engine("hosted step part_index exceeds u32"))?,
        base_len,
        branch_no: facets
            .get("native.session.branch_no")
            .map(|text| {
                text.parse::<u64>()
                    .map_err(|_| Error::engine("hosted step branch_no is not a number"))
            })
            .transpose()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSessionState {
    pub identity: RowIdentity,
    pub claim: LeaseClaim,
    pub facets: BTreeMap<String, String>,
}

pub fn parse_remote_session(row: &Value) -> Result<RemoteSessionState> {
    let identity = parse_row_identity(row)?;
    let facets = facet_map(row)?;
    let required = |key: &str| {
        facets
            .get(key)
            .filter(|s| !s.is_empty())
            .cloned()
            .ok_or_else(|| Error::engine(format!("session state lacks {key}")))
    };
    let generation = required("native.session.writer_generation")?
        .parse::<u64>()
        .map_err(|_| Error::engine("invalid writer generation"))?;
    let writer = required("native.session.writer")?;
    let last_seen_at = required("native.session.last_seen_at")?;
    chrono::DateTime::parse_from_rfc3339(&last_seen_at)
        .map_err(|_| Error::engine("invalid session heartbeat time"))?;
    Ok(RemoteSessionState {
        identity,
        claim: LeaseClaim {
            generation,
            writer,
            last_seen_at,
        },
        facets,
    })
}

/// Strict event parser: `type` required, payload defaulted to null, actor
/// preserved whenever the engine discloses it.
pub fn parse_remote_event(event: &Value) -> Result<RemoteEvent> {
    let object = event
        .as_object()
        .ok_or_else(|| Error::engine("hosted history event is not an object"))?;
    let etype = object
        .get("type")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::engine("hosted history event has no type"))?;
    Ok(RemoteEvent {
        etype,
        payload: object.get("payload").cloned().unwrap_or(Value::Null),
        actor: object
            .get("actor")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Identity projection out of a hydrated row.
pub fn parse_row_identity(row: &Value) -> Result<RowIdentity> {
    let object = row
        .as_object()
        .ok_or_else(|| Error::engine("hosted row is not an object"))?;
    match object.get("status").and_then(Value::as_str) {
        None | Some("found") => {}
        Some(other) => {
            return Err(Error::engine(format!(
                "hosted record is not visible: {other}"
            )));
        }
    }
    Ok(RowIdentity {
        id: object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("hosted row has no id"))?
            .to_owned(),
        owner_id: object
            .get("owner_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        home_id: object
            .get("home_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// Strict policy-list parser. Unknown or partial shapes refuse — a policy
/// we cannot fully read must never authorise a write.
pub fn parse_policy_view(reply: &Option<String>) -> Result<PolicyView> {
    let text = reply
        .as_deref()
        .ok_or_else(|| Error::engine("hosted policy read has no reply"))?;
    let value: Value = serde_json::from_str(text)
        .map_err(|_| Error::engine("hosted policy read reply is not JSON"))?;
    if value.get("error").is_some() || value.pointer("/result/isError") == Some(&Value::Bool(true))
    {
        return Err(Error::engine("hosted policy read refused"));
    }
    let content = value
        .pointer("/result/structuredContent")
        .or_else(|| value.pointer("/result"))
        .and_then(Value::as_object)
        .ok_or_else(|| Error::engine("hosted policy view is missing"))?;
    let field = |key: &str| {
        content
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Error::engine(format!("hosted policy view lacks {key}")))
    };
    let mut entries = Vec::new();
    for entry in content
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::engine("hosted policy view lacks entries"))?
    {
        let subject = entry
            .get("subject")
            .and_then(Value::as_object)
            .ok_or_else(|| Error::engine("hosted policy entry lacks subject"))?;
        let kind = subject
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("hosted policy subject lacks kind"))?
            .to_owned();
        let subject_id = subject
            .get("account_id")
            .or_else(|| subject.get("person_record_id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let person_id = subject
            .get("person")
            .and_then(|person| person.get("record_id"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        let capability = entry
            .get("capability")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("hosted policy entry lacks capability"))?
            .to_owned();
        entries.push(PolicyEntry {
            subject_kind: kind,
            subject_id,
            person_id,
            capability,
        });
    }
    Ok(PolicyView {
        record_id: field("record_id")?,
        target_id: field("authorization_target_id")?,
        anchor_id: field("anchor_id")?,
        mode: field("mode")?,
        caller_capability: field("caller_capability")?,
        policy_administration_authorized: content
            .get("policy_administration_authorized")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                Error::engine("hosted policy view lacks policy_administration_authorized")
            })?,
        entries,
    })
}

// ---------------------------------------------------------------------------
// Positive ownership verification (§5.1, S1 F4)
// ---------------------------------------------------------------------------

/// Verify a Saved-sessions root is the owner's own private root, and return
/// the caller's canonical person.
///
/// Requirements, all positive: explicit mode; the policy is anchored on and
/// targeted at the root itself; our account is the sole grant with
/// `manage`; we may administer the policy; and the engine's resolved bound
/// person for our account equals the record's owner. Absence of any of
/// these refuses — custody flags, facet matches and guessed owners are not
/// evidence.
pub fn verify_own_root(view: &PolicyView, account_id: &str) -> Result<String> {
    if view.mode != "explicit" {
        return Err(Error::engine(
            "saved-sessions root is not explicitly private: refusing",
        ));
    }
    if view.anchor_id != view.record_id || view.target_id != view.record_id {
        return Err(Error::engine(
            "saved-sessions root is not self-anchored: refusing",
        ));
    }
    if view.caller_capability != "manage" || !view.policy_administration_authorized {
        return Err(Error::engine(
            "saver cannot administer the saved-sessions root: refusing",
        ));
    }
    if view.entries.len() != 1 {
        return Err(Error::engine(
            "saved-sessions root grants more than our account: refusing",
        ));
    }
    let entry = &view.entries[0];
    if entry.subject_kind != "account"
        || entry.subject_id != account_id
        || entry.capability != "manage"
    {
        return Err(Error::engine(
            "saved-sessions root is not account-only for us: refusing",
        ));
    }
    entry
        .person_id
        .clone()
        .ok_or_else(|| Error::engine("saved-sessions root has no visible bound person: refusing"))
}

/// Verify an existing session folder is legitimately ours.
///
/// `new_identity` requires the folder to inherit the verified root exactly
/// (anchor == root). An **existing** folder may be anchored anywhere the
/// owner has legitimately placed it — a channel after sharing — and is
/// accepted unchanged, provided it inherits rather than carries its own
/// policy, we hold `manage`, administration is authorised, and its owner is
/// positively our canonical person. It is never moved or re-homed.
pub fn verify_folder_policy(
    view: &PolicyView,
    root: &VerifiedRoot,
    new_identity: bool,
) -> Result<()> {
    if view.mode != "inherit" {
        return Err(Error::engine(
            "session folder carries its own policy instead of inheriting: refusing",
        ));
    }
    if view.anchor_id == view.record_id {
        return Err(Error::engine(
            "session folder policy anchor is the folder itself: refusing",
        ));
    }
    if view.target_id != view.record_id {
        return Err(Error::engine(
            "session folder authorization target is not the folder: refusing",
        ));
    }
    if view.caller_capability != "manage" || !view.policy_administration_authorized {
        return Err(Error::engine(
            "saver cannot administer the session folder: refusing",
        ));
    }
    if new_identity && view.anchor_id != root.id {
        return Err(Error::engine(
            "new session folder does not inherit the verified root: refusing",
        ));
    }
    Ok(())
}

/// Positively bind a record's owner to the canonical person. Missing,
/// empty or mismatched owners refuse.
pub fn require_owner(row: &RowIdentity, root: &VerifiedRoot) -> Result<()> {
    match row.owner_id.as_deref() {
        Some(owner) if owner == root.owner => Ok(()),
        Some(_) => Err(Error::engine(
            "record is owned by a different person: refusing",
        )),
        None => Err(Error::engine("record has no owner: refusing")),
    }
}

// ---------------------------------------------------------------------------
// Verified admission (§6.3)
// ---------------------------------------------------------------------------

/// What the verified head requires at `pos`.
#[derive(Debug, Clone)]
pub struct AdmissionExpectation {
    pub pos: u64,
    /// Owner person the admitted record must belong to.
    pub owner_id: String,
    /// Credential that must have authored every mutation.
    pub actor: String,
    /// Folder the record must be homed in.
    pub home_id: String,
    /// Verified parent: the checkpoint head cid, or the chain root at 1.
    pub head_cid: String,
}

/// Why adoption was refused. Every variant stops the writer and rebuilds
/// from the last verified prefix; none overwrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainErrorKind {
    NoneFound,
    SeveralFound,
    NotOwnerOwned,
    Misplaced,
    ParentMismatch,
    /// Recomputed `fp`/`cid` disagree with the stored facets.
    ContentInconsistent,
    /// Create evidence missing or disagreeing on body/home/facets.
    CreateMismatch,
    /// A non-owner or out-of-contract mutation occurred at any point.
    HistoryTamper,
    HistoryUnreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Adopt,
    Refuse(ChainErrorKind),
}

/// Recompute `fp` and `cid` from the candidate's own bytes.
fn recomputed_chain(found: &RemoteStep) -> Result<(String, String)> {
    use super::session_persist::chain_next;
    let kind = match found.step_kind.as_str() {
        "user" => StepKind::User,
        "agent" => StepKind::Agent,
        "tools" => StepKind::Tools,
        "error" => StepKind::Error,
        "compacted" => StepKind::Compacted,
        "rewound" => StepKind::Rewound,
        "resync" => StepKind::Resync,
        _ => {
            return Err(Error::engine(
                "hosted step kind is not admitted in this slice",
            ))
        }
    };
    let marker = matches!(kind, StepKind::Rewound | StepKind::Resync);
    if marker != found.base_len.is_some()
        || (marker && found.part_index != 0)
        || (!marker && found.branch_no.is_some())
    {
        return Err(Error::engine("invalid marker shape"));
    }
    let fp = fingerprint_step(kind, found.part_index, &found.body);
    let cid = chain_next(&found.parent_cid, &fp)?;
    Ok((fp, cid))
}

/// Verified admission read: exactly one owner-owned record at `pos` that
/// extends the verified head, is self-consistent under recomputation, and
/// whose whole history is the owner's create plus owner-only side effects.
pub fn validate_admission(
    expected: &AdmissionExpectation,
    candidates: &[RemoteStep],
    history: Option<&[RemoteEvent]>,
) -> AdmissionVerdict {
    if candidates.is_empty() {
        return AdmissionVerdict::Refuse(ChainErrorKind::NoneFound);
    }
    if candidates.len() > 1 {
        return AdmissionVerdict::Refuse(ChainErrorKind::SeveralFound);
    }
    let found = &candidates[0];
    if found.owner_id != expected.owner_id {
        return AdmissionVerdict::Refuse(ChainErrorKind::NotOwnerOwned);
    }
    if found.home_id != expected.home_id || found.pos != expected.pos {
        return AdmissionVerdict::Refuse(ChainErrorKind::Misplaced);
    }
    if found.parent_cid != expected.head_cid {
        return AdmissionVerdict::Refuse(ChainErrorKind::ParentMismatch);
    }
    let (fp, cid) = match recomputed_chain(found) {
        Ok(pair) => pair,
        Err(_) => return AdmissionVerdict::Refuse(ChainErrorKind::ContentInconsistent),
    };
    if fp != found.fp || cid != found.cid {
        return AdmissionVerdict::Refuse(ChainErrorKind::ContentInconsistent);
    }
    let Some(history) = history else {
        return AdmissionVerdict::Refuse(ChainErrorKind::HistoryUnreadable);
    };
    if history.is_empty() {
        return AdmissionVerdict::Refuse(ChainErrorKind::HistoryUnreadable);
    }
    match history_allows_adopt(found, &expected.actor, history) {
        Ok(()) => AdmissionVerdict::Adopt,
        Err(kind) => AdmissionVerdict::Refuse(kind),
    }
}

/// Full history validation in one trajectory pass.
///
/// `get_history` exposes no `act`/command metadata (`event_to_value` drops
/// it), so transaction grouping is reconstructed from value trajectories:
///
/// - `history[0]` must be `record.created` by our credential with the
///   candidate's body and home.
/// - Every mutation must be authored by our credential. Facet keys outside
///   the immutable set plus `quote_link` refuse immediately.
/// - An immutable key's **first** set establishes it; any later set to a
///   different value refuses on the spot, even if a later set reverts it.
///   A revert masks a fork window that another writer may have adopted, so
///   the deviation itself is the violation. Same-value re-sets (creation
///   bursts) pass.
/// - `quote_link` sets/unsets pass as the owner side effect; link additions
///   must name this record; keyed-receipt bookkeeping passes.
/// - Everything else — edits, unsets of immutable keys, unknown types,
///   undisclosed actors on mutations — refuses.
/// - The folded immutable values must finally equal the candidate.
fn history_allows_adopt(
    found: &RemoteStep,
    actor: &str,
    history: &[RemoteEvent],
) -> std::result::Result<(), ChainErrorKind> {
    let Some(first) = history.first() else {
        return Err(ChainErrorKind::HistoryUnreadable);
    };
    if first.etype != "record.created" || first.actor.as_deref() != Some(actor) {
        return Err(ChainErrorKind::CreateMismatch);
    }
    let payload = &first.payload;
    if payload.get("body").and_then(Value::as_str) != Some(found.body.as_str())
        || payload.get("home_id").and_then(Value::as_str) != Some(found.home_id.as_str())
    {
        return Err(ChainErrorKind::CreateMismatch);
    }
    let mut folded: BTreeMap<String, String> = BTreeMap::new();
    for event in &history[1..] {
        match event.etype.as_str() {
            "receipt.committed.v1" => {}
            "facet.set" => {
                let (Some(key), Some(value)) = (
                    event.payload.get("key").and_then(Value::as_str),
                    event.payload.get("value"),
                ) else {
                    return Err(ChainErrorKind::HistoryTamper);
                };
                if event.actor.as_deref() != Some(actor) {
                    return Err(ChainErrorKind::HistoryTamper);
                }
                if key == QUOTE_LINK_FACET {
                    continue;
                }
                if !IMMUTABLE_FACET_KEYS.contains(&key) {
                    return Err(ChainErrorKind::HistoryTamper);
                }
                let text = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => return Err(ChainErrorKind::HistoryTamper),
                };
                match folded.get(key) {
                    Some(current) if current != &text => return Err(ChainErrorKind::HistoryTamper),
                    Some(_) => {}
                    None => {
                        folded.insert(key.to_owned(), text);
                    }
                }
            }
            "facet.unset" => {
                let Some(key) = event.payload.get("key").and_then(Value::as_str) else {
                    return Err(ChainErrorKind::HistoryTamper);
                };
                if event.actor.as_deref() != Some(actor) {
                    return Err(ChainErrorKind::HistoryTamper);
                }
                if key != QUOTE_LINK_FACET {
                    return Err(ChainErrorKind::HistoryTamper);
                }
            }
            "link.added" => {
                if event.actor.as_deref() != Some(actor) {
                    return Err(ChainErrorKind::HistoryTamper);
                }
                let source = event.payload.get("source_id").and_then(Value::as_str);
                if source != Some(found.record_id.as_str()) {
                    return Err(ChainErrorKind::HistoryTamper);
                }
            }
            _ => return Err(ChainErrorKind::HistoryTamper),
        }
    }
    let expect = [
        ("native.session.pos", found.pos.to_string()),
        ("native.session.cid", found.cid.clone()),
        ("native.session.parent_cid", found.parent_cid.clone()),
        ("native.session.fp", found.fp.clone()),
        ("native.session.step_kind", found.step_kind.clone()),
        ("native.session.part_index", found.part_index.to_string()),
    ];
    for (key, value) in expect {
        if folded.get(key) != Some(&value) {
            return Err(ChainErrorKind::CreateMismatch);
        }
    }
    for (key, value) in [
        ("native.session.base_len", found.base_len),
        ("native.session.branch_no", found.branch_no),
    ] {
        match (value, folded.get(key)) {
            (None, None) => {}
            (Some(n), Some(text)) if text == &n.to_string() => {}
            _ => return Err(ChainErrorKind::CreateMismatch),
        }
    }
    Ok(())
}

/// A fully verified hosted chain: every step owner-checked, chained from
/// the true chain root, self-consistent, and create-evidenced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// Admitted head position (`None` for an empty folder).
    pub head_pos: Option<u64>,
    /// Admitted head chain id.
    pub head_cid: Option<String>,
    /// Admitted head fingerprint.
    pub head_fp: Option<String>,
    /// Source-equivalent sequence rebuilt from hosted alone.
    pub e: Vec<String>,
    /// Last branch identity admitted from immutable marker history. Used to
    /// resume after a marker commit but before the session branch ack.
    pub marker_branch: Option<u64>,
}

/// Verify a complete hosted chain from the true chain root (§§5.4, 6.4):
/// gap-free positions starting at 1, owner match on every step, parent
/// continuity from `chain_root(server, agent)`, recomputed `fp`/`cid`
/// equality, and full admission validation (create evidence plus
/// owner-only side effects) per step. Markers truncate `E` without entering
/// it. Anything unverifiable refuses: the caller rebuilds nothing and
/// adopts nothing.
pub fn verify_hosted_chain(
    server_id: &str,
    agent_id: &str,
    owner_id: &str,
    actor: &str,
    folder_id: &str,
    steps_with_history: &[(RemoteStep, Vec<RemoteEvent>)],
) -> Result<VerifiedChain> {
    use super::session_persist::chain_root;
    if steps_with_history.len() > MAX_HOSTED_STEPS {
        return Err(Error::engine("hosted step history exceeds fold bound"));
    }
    let mut ordered: Vec<&(RemoteStep, Vec<RemoteEvent>)> = steps_with_history.iter().collect();
    ordered.sort_by_key(|(s, _)| s.pos);
    if ordered.is_empty() {
        return Ok(VerifiedChain {
            head_pos: None,
            head_cid: None,
            head_fp: None,
            e: Vec::new(),
            marker_branch: None,
        });
    }
    if ordered[0].0.pos != 1 {
        return Err(Error::engine(
            "hosted chain does not start at position 1: refusing rebuild",
        ));
    }
    let mut expected_parent = chain_root(server_id, agent_id)?;
    let mut e: Vec<String> = Vec::new();
    let mut marker_branch = None;
    let mut next_pos = 1u64;
    for (step, history) in &ordered {
        if step.pos != next_pos {
            return Err(Error::engine(
                "hosted step positions are gapped or duplicated: refusing rebuild",
            ));
        }
        next_pos = next_pos.saturating_add(1);
        let expected = AdmissionExpectation {
            pos: step.pos,
            owner_id: owner_id.to_owned(),
            actor: actor.to_owned(),
            home_id: folder_id.to_owned(),
            head_cid: expected_parent.clone(),
        };
        match validate_admission(&expected, std::slice::from_ref(step), Some(history)) {
            AdmissionVerdict::Adopt => {}
            AdmissionVerdict::Refuse(kind) => {
                return Err(Error::engine(format!(
                    "hosted chain breaks at pos {}: {kind:?}",
                    step.pos
                )));
            }
        }
        expected_parent = step.cid.clone();
        if step.step_kind == "rewound" || step.step_kind == "resync" {
            if let Some(branch) = step.branch_no {
                if marker_branch.is_some_and(|old| branch < old) {
                    return Err(Error::engine("hosted marker branch regressed"));
                }
                marker_branch = Some(branch);
            }
            let base_len = step
                .base_len
                .ok_or_else(|| Error::engine("hosted marker lacks base_len"))?;
            super::session_persist::check_marker_base_len(base_len, e.len())?;
            e.truncate(base_len as usize);
        } else {
            e.push(step.fp.clone());
        }
    }
    let (last, _) = ordered.last().expect("nonempty verified above");
    Ok(VerifiedChain {
        head_pos: Some(last.pos),
        head_cid: Some(last.cid.clone()),
        head_fp: Some(last.fp.clone()),
        e,
        marker_branch,
    })
}

// ---------------------------------------------------------------------------
// Source alignment (§6.4)
// ---------------------------------------------------------------------------

/// Snapshot identity returned on every projected page. Mixing pages across
/// epochs, branches or cuts cannot establish a rewind boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSnapshot {
    pub epoch: String,
    pub branch: Option<u64>,
    pub kept_seq_end: Option<u64>,
}

/// Hosted state lease. A restart may replace its own instance's boot; a
/// different instance needs a heartbeat older than twelve minutes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseClaim {
    pub generation: u64,
    pub writer: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityNote {
    pub at: String,
    pub from_pos: u64,
}

fn continuity_notes(text: Option<&String>) -> Result<Vec<ContinuityNote>> {
    let notes: Vec<ContinuityNote> = match text {
        Some(text) => serde_json::from_str(text)
            .map_err(|_| Error::engine("invalid saved-session continuity notes"))?,
        None => Vec::new(),
    };
    for note in &notes {
        chrono::DateTime::parse_from_rfc3339(&note.at)
            .map_err(|_| Error::engine("invalid continuity note time"))?;
    }
    Ok(notes)
}

pub fn heartbeat_due(last_write_ms: i64, now_ms: i64, saving: bool) -> bool {
    saving && i128::from(now_ms) - i128::from(last_write_ms) >= 5 * 60 * 1000
}

pub fn confirmed_pos_due(last_progress_ms: i64, now_ms: i64, catching_up: bool) -> bool {
    catching_up && i128::from(now_ms) - i128::from(last_progress_ms) >= 30 * 1000
}

/// State writers cannot erase continuity qualifications or acknowledge a
/// missed branch gap without appending its durable disclosure.
fn validate_state_facets(
    state: &RemoteSessionState,
    patch: &BTreeMap<String, Value>,
) -> Result<()> {
    const ALLOWED: &[&str] = &[
        "native.session.state",
        "native.session.paused_reason",
        "native.session.last_seen_at",
        "native.session.last_step_at",
        "native.session.activity",
        "native.session.confirmed_pos",
        "native.session.host_label",
        "native.session.provider",
        "native.session.model",
        "native.session.source_branch",
        "native.session.continuity",
        "native.session.continuity_at",
        "native.session.continuity_notes",
    ];
    if patch.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(Error::engine(
            "state patch contains a protected or unknown facet",
        ));
    }
    if let Some(value) = patch.get("native.session.state") {
        if !matches!(
            value.as_str(),
            Some("saving" | "paused" | "ended" | "stopped" | "error")
        ) {
            return Err(Error::engine("invalid saved-session state"));
        }
    }
    let old_notes = continuity_notes(state.facets.get("native.session.continuity_notes"))?;
    let new_notes = if let Some(value) = patch.get("native.session.continuity_notes") {
        let text = value
            .as_str()
            .ok_or_else(|| Error::engine("continuity notes cannot be unset"))?
            .to_owned();
        let notes = continuity_notes(Some(&text))?;
        if !notes.starts_with(&old_notes) {
            return Err(Error::engine("continuity notes must be append-only"));
        }
        notes
    } else {
        old_notes.clone()
    };
    let assumed = patch
        .get("native.session.continuity")
        .and_then(Value::as_str)
        .or_else(|| {
            state
                .facets
                .get("native.session.continuity")
                .map(String::as_str)
        });
    if patch
        .get("native.session.continuity")
        .is_some_and(|v| v.as_str() != Some("assumed_by_content"))
    {
        return Err(Error::engine("continuity qualification cannot be cleared"));
    }
    if new_notes.len() > old_notes.len() && assumed != Some("assumed_by_content") {
        return Err(Error::engine(
            "continuity note requires its visible qualification",
        ));
    }
    if patch.contains_key("native.session.continuity")
        && old_notes.is_empty()
        && new_notes.is_empty()
    {
        return Err(Error::engine(
            "continuity qualification requires its durable note",
        ));
    }
    if let Some(at) = patch.get("native.session.continuity_at") {
        chrono::DateTime::parse_from_rfc3339(
            at.as_str()
                .ok_or_else(|| Error::engine("invalid continuity time"))?,
        )
        .map_err(|_| Error::engine("invalid continuity time"))?;
        if new_notes
            .last()
            .is_none_or(|note| Some(note.at.as_str()) != at.as_str())
        {
            return Err(Error::engine(
                "continuity time must name the retained disclosure",
            ));
        }
    }
    if let Some(activity) = patch.get("native.session.activity") {
        if !matches!(
            activity.as_str(),
            Some("working" | "idle" | "waiting_permission")
        ) {
            return Err(Error::engine("invalid saved-session activity"));
        }
    }
    if let Some(position) = patch.get("native.session.confirmed_pos") {
        let new = position
            .as_u64()
            .ok_or_else(|| Error::engine("invalid confirmed position"))?;
        let old = state
            .facets
            .get("native.session.confirmed_pos")
            .map(|s| s.parse::<u64>())
            .transpose()
            .map_err(|_| Error::engine("invalid hosted confirmed position"))?;
        if old.is_some_and(|old| new < old) {
            return Err(Error::engine("confirmed position cannot regress"));
        }
    }
    if let Some(branch) = patch.get("native.session.source_branch") {
        let new = branch
            .as_u64()
            .ok_or_else(|| Error::engine("invalid source branch"))?;
        let old = state
            .facets
            .get("native.session.source_branch")
            .map(|s| s.parse::<u64>())
            .transpose()
            .map_err(|_| Error::engine("invalid hosted source branch"))?;
        if old.is_some_and(|old| new < old) {
            return Err(Error::engine("source branch cannot regress"));
        }
        let gap = old.map_or(new > 0, |old| new - old > 1);
        if gap && (new_notes.len() == old_notes.len() || assumed != Some("assumed_by_content")) {
            return Err(Error::engine(
                "branch gap requires a new durable continuity note",
            ));
        }
    }
    Ok(())
}

pub fn takeover_eligible(claim: &LeaseClaim, server: &str, instance: &str, now: i64) -> bool {
    let parts: Vec<_> = claim.writer.split('/').collect();
    if (parts.len() == 2 || parts.len() == 3)
        && parts.iter().all(|part| !part.is_empty())
        && parts[0] == server
        && parts[1] == instance
    {
        return true;
    }
    chrono::DateTime::parse_from_rfc3339(&claim.last_seen_at)
        .is_ok_and(|seen| i128::from(now) - i128::from(seen.timestamp()) > 12 * 60)
}

/// Eligibility evidence is part of the CAS. A holder heartbeat that lands
/// after the read defeats the takeover, even when the generation is unchanged.
pub fn lease_takeover_arguments(
    record_id: &str,
    claim: &LeaseClaim,
    own_writer: &str,
    now: &str,
) -> Result<Value> {
    if record_id.is_empty() || own_writer.is_empty() {
        return Err(Error::engine(
            "lease takeover needs record and writer identities",
        ));
    }
    chrono::DateTime::parse_from_rfc3339(now)
        .map_err(|_| Error::engine("lease takeover time is invalid"))?;
    let generation = claim
        .generation
        .checked_add(1)
        .ok_or_else(|| Error::engine("writer generation exhausted"))?;
    Ok(json!({
        "ids": [record_id], "reason": "Adopt saved session writer",
        "facets": {"native.session.writer_generation": generation,
            "native.session.writer": own_writer, "native.session.last_seen_at": now},
        "if_facets": {"native.session.writer_generation": claim.generation,
            "native.session.writer": claim.writer, "native.session.last_seen_at": claim.last_seen_at},
        "idempotency_key": format!("nss3:lease:{record_id}:g{generation}"),
    }))
}

/// All state mutations, including heartbeats, consume the same durable
/// sequence under the exact held generation and boot identity.
pub fn state_update_arguments(
    record_id: &str,
    claim: &LeaseClaim,
    sequence: u64,
    facets: BTreeMap<String, Value>,
) -> Result<Value> {
    if record_id.is_empty()
        || claim.writer.is_empty()
        || facets.is_empty()
        || facets.contains_key("native.session.writer_generation")
        || facets.contains_key("native.session.writer")
    {
        return Err(Error::engine("invalid saved-session state patch"));
    }
    Ok(json!({
        "ids": [record_id], "reason": "Saved session state", "facets": facets,
        "if_facets": {"native.session.writer_generation": claim.generation, "native.session.writer": claim.writer},
        "idempotency_key": format!("nss3:state:{record_id}:g{}:s{sequence}", claim.generation),
    }))
}

impl SourceSnapshot {
    pub fn check_page(&self, page: &Self) -> Result<()> {
        if self.epoch.is_empty() || self != page {
            return Err(Error::engine(
                "source snapshot changed: restart timeline fetch",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerKind {
    Rewound,
    Resync,
}

impl MarkerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rewound => "rewound",
            Self::Resync => "resync",
        }
    }
}

/// A plan does not acknowledge a branch. The driver must persist any
/// continuity disclosure under its state lease and confirm the marker and
/// suffix before acknowledging `source_branch` and its cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlignmentPlan {
    pub marker: Option<MarkerKind>,
    /// Zero-based next source index, also the marker's `base_len`.
    pub base_len: usize,
    pub source_branch: Option<u64>,
    pub continuity_assumed: bool,
}

fn longest_common_prefix(e: &[String], t: &[ProjectedStep]) -> usize {
    e.iter()
        .zip(t)
        .take_while(|(fp, step)| **fp == step.fingerprint)
        .count()
}

/// Compare from the beginning, never by timestamps or a matching suffix.
/// Branch advances use only steps wholly before the cut, even if the new
/// branch regenerated byte-identical content. Every split part carries its
/// entire group's source span, so a straddling group contributes no parts.
/// `unknown_continuity` also covers delayed replacement fetches on ordinary
/// hosts; the caller must retain the resulting disclosure append-only.
pub fn plan_alignment(
    e: &[String],
    t: &[ProjectedStep],
    acknowledged_branch: Option<u64>,
    snapshot: &SourceSnapshot,
    observed_replacement: bool,
    unknown_continuity: bool,
) -> Result<AlignmentPlan> {
    let metadata = t
        .iter()
        .map(super::session_projection::SourceStepMeta::from_step)
        .collect::<Result<Vec<_>>>()?;
    plan_alignment_meta(
        e,
        &metadata,
        acknowledged_branch,
        snapshot,
        observed_replacement,
        unknown_continuity,
    )
}

pub(super) fn plan_alignment_meta(
    e: &[String],
    t: &[super::session_projection::SourceStepMeta],
    acknowledged_branch: Option<u64>,
    snapshot: &SourceSnapshot,
    observed_replacement: bool,
    unknown_continuity: bool,
) -> Result<AlignmentPlan> {
    snapshot.check_page(snapshot)?;
    let branch_advanced = match (acknowledged_branch, snapshot.branch) {
        (Some(old), Some(new)) if new < old => {
            return Err(Error::engine(
                "source branch regressed: cannot acknowledge snapshot",
            ));
        }
        (Some(old), Some(new)) => new > old,
        (None, Some(new)) => new > 0,
        _ => false,
    };
    let continuity_assumed = unknown_continuity
        || match (acknowledged_branch, snapshot.branch) {
            (Some(old), Some(new)) => new.saturating_sub(old) > 1,
            (None, Some(new)) => new > 0,
            (Some(_), None) => true,
            (None, None) => false,
        };
    let rewind = branch_advanced || observed_replacement;
    let prefix = if branch_advanced {
        let cut = snapshot
            .kept_seq_end
            .ok_or_else(|| Error::engine("advanced source branch lacks keptSeqEnd"))?;
        let kept = t.iter().take_while(|step| step.seq_end <= cut).count();
        &t[..kept]
    } else {
        t
    };
    let base_len = e
        .iter()
        .zip(prefix)
        .take_while(|(saved, source)| **saved == source.fingerprint)
        .count();
    let marker = if rewind {
        Some(MarkerKind::Rewound)
    } else if base_len < e.len() {
        Some(MarkerKind::Resync)
    } else {
        None
    };
    Ok(AlignmentPlan {
        marker,
        base_len,
        source_branch: snapshot.branch,
        continuity_assumed,
    })
}

pub fn marker_body(kind: MarkerKind, host_label: &str, base_len: u64) -> String {
    match kind {
        MarkerKind::Rewound => format!("Rewound to step {base_len}."),
        MarkerKind::Resync => format!(
            "History on {host_label} changed after step {base_len}. Saved steps above are kept. What follows is the host's current history from that point."
        ),
    }
}

/// Freeze a marker request through the S3a frozen path (position-keyed,
/// chained, fingerprinted with the S2 formula over the marker kind).
#[allow(clippy::too_many_arguments)]
pub fn freeze_marker(
    store: &SessionStore,
    agent_id: &str,
    home_id: &str,
    kind: MarkerKind,
    host_label: &str,
    base_len: u64,
    e_len: usize,
    parent_cid_hex: &str,
    pos: u64,
    occurred_at: &str,
) -> Result<FrozenStepRequest> {
    super::session_persist::check_marker_base_len(base_len, e_len)?;
    let body = marker_body(kind, host_label, base_len);
    let step_kind = kind.as_str();
    let fp = {
        let sk = match kind {
            MarkerKind::Rewound => StepKind::Rewound,
            MarkerKind::Resync => StepKind::Resync,
        };
        fingerprint_step(sk, 0, &body)
    };
    FrozenStepRequest::freeze(
        store.binding(),
        agent_id,
        home_id,
        step_kind,
        &body,
        step_kind,
        0,
        Some(base_len),
        parent_cid_hex,
        &fp,
        pos,
        occurred_at,
    )
}

// ---------------------------------------------------------------------------
// Hosted message builders (pure; transport in `GateSink`)
// ---------------------------------------------------------------------------

/// Monotonic JSON-RPC id source for saver-built frames.
#[derive(Debug, Default)]
pub struct FrameIds {
    next: u64,
}

impl FrameIds {
    pub fn next(&mut self) -> u64 {
        self.next = self.next.saturating_add(1).max(1);
        self.next
    }
}

/// One executor envelope: `params.name` names the executor and its
/// arguments carry the operation, the operation arguments and forced JSON.
/// This is the form the node's executor surface dispatches (and the form
/// `failover::target` unwraps). It never sets `run_key` or `parent_key`, so
/// resolved intent stays absent.
pub fn call_message(id: u64, executor: &str, operation: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": executor,
            "arguments": {
                "operation": operation,
                "arguments": arguments,
                "format": "json",
            },
        },
    })
}

/// Step-create arguments: exactly the frozen [`FrozenStepRequest::wire_request`]
/// plus the position key. Sent verbatim on every attempt.
pub fn step_create_arguments(request: &FrozenStepRequest) -> Value {
    let mut args = request.wire_request();
    if let Some(object) = args.as_object_mut() {
        object.insert("idempotency_key".into(), Value::String(request.key.clone()));
    }
    args
}

/// Keyed Saved-sessions root creation. `access_policy` is the single
/// literal `"account_only"` (the account is always the authenticated
/// caller, never a payload field).
pub fn create_root_arguments(account_id: &str, root_name: &str) -> Result<Value> {
    if account_id.trim().is_empty() || root_name.trim().is_empty() {
        return Err(Error::engine("saver root creation needs account and name"));
    }
    Ok(json!({
        "type": "Collection",
        "kind": "folder",
        "name": root_name,
        "reason": "Saved agent sessions",
        "facets": {ROOT_ACCOUNT_FACET: account_id},
        "access_policy": "account_only",
        "idempotency_key": format!("nss3:root:{account_id}"),
    }))
}

/// Keyed session-folder creation. No `access_policy`: the folder inherits
/// Saved sessions, so moving it shares it.
pub fn create_session_folder_arguments(
    server_id: &str,
    agent_id: &str,
    root_id: &str,
    title: &str,
) -> Result<Value> {
    if title.trim().is_empty() || root_id.trim().is_empty() {
        return Err(Error::engine("saver folder creation needs root and title"));
    }
    Ok(json!({
        "type": "Collection",
        "kind": "folder",
        "home_id": root_id,
        "name": title,
        "reason": "Saved agent session",
        "facets": {
            FOLDER_FACET: 1,
            "native.session.host_id": server_id,
            "native.session.agent_id": agent_id,
        },
        "idempotency_key": format!("nss3:{server_id}:{agent_id}:folder"),
    }))
}

/// Keyed session-record creation with the initial writer facets. Body is a
/// short static explanation written once; no `access_policy`.
#[allow(clippy::too_many_arguments)]
pub fn create_session_record_arguments(
    server_id: &str,
    agent_id: &str,
    folder_id: &str,
    title: &str,
    account_id: &str,
    db_id: &str,
    host_label: &str,
    provider: &str,
    own_writer: &str,
    now_rfc3339: &str,
) -> Result<Value> {
    if folder_id.trim().is_empty() || title.trim().is_empty() {
        return Err(Error::engine(
            "saver record creation needs folder and title",
        ));
    }
    Ok(json!({
        "type": "Document",
        "kind": "agent-session",
        "lifecycle": "open",
        "home_id": folder_id,
        "name": title,
        "reason": "Saved agent session",
        "body": "Saved agent conversation. Steps below are immutable curated records written by the execution-host saver.",
        "facets": {
            "native.session.host_id": server_id,
            "native.session.agent_id": agent_id,
            "native.session.binding": format!("{account_id}/{db_id}"),
            "native.session.host_label": host_label,
            "native.session.provider": provider,
            "native.session.state": "saving",
            "native.session.last_seen_at": now_rfc3339,
            "native.session.writer_generation": 1,
            "native.session.writer": own_writer,
            "native.session.projection": "nss-projection.v1",
        },
        "idempotency_key": format!("nss3:{server_id}:{agent_id}:record"),
    }))
}

/// Step-history query: `query_record` over the session folder in position
/// order. Hydration follows per page (pipeline rows carry no facets).
pub fn query_steps_arguments(folder_id: &str, offset: i64) -> Result<Value> {
    if folder_id.trim().is_empty() {
        return Err(Error::engine("saver step query needs a folder id"));
    }
    Ok(json!({
        "steps": [{
            "step": "filter",
            "home_id": folder_id,
            "types": ["Document"],
            "kinds": [STEP_KIND],
        }],
        "facet_order": {
            "key": "native.session.pos",
            "lane": "number",
            "direction": "asc",
        },
        "limit": QUERY_PAGE_LIMIT,
        "offset": offset,
    }))
}

/// Saved-sessions root lookup by account facet.
pub fn find_root_arguments(account_id: &str) -> Result<Value> {
    if account_id.trim().is_empty() {
        return Err(Error::engine("saver root lookup needs an account id"));
    }
    Ok(json!({
        "steps": [{
            "step": "filter",
            "types": ["Collection"],
            "kinds": ["folder"],
            "facets": [{"key": ROOT_ACCOUNT_FACET, "eq": account_id}],
        }],
        "limit": 10,
    }))
}

/// Session-folder lookup by host/agent facets.
pub fn find_session_folder_arguments(server_id: &str, agent_id: &str) -> Result<Value> {
    if server_id.trim().is_empty() || agent_id.trim().is_empty() {
        return Err(Error::engine("saver folder lookup needs server and agent"));
    }
    Ok(json!({
        "steps": [{
            "step": "filter",
            "types": ["Collection"],
            "kinds": ["folder"],
            "facets": [
                {"key": "native.session.host_id", "eq": server_id},
                {"key": "native.session.agent_id", "eq": agent_id},
            ],
        }],
        "limit": 10,
    }))
}

/// Session-record lookup inside a folder.
pub fn session_record_lookup_arguments(folder_id: &str) -> Result<Value> {
    if folder_id.trim().is_empty() {
        return Err(Error::engine("saver record lookup needs a folder id"));
    }
    Ok(json!({
        "steps": [{
            "step": "filter",
            "home_id": folder_id,
            "types": ["Document"],
            "kinds": ["agent-session"],
        }],
        "limit": 10,
    }))
}

/// One full-detail history page, optionally resuming after a local seq.
pub fn history_arguments_paged(record_id: &str, after: Option<i64>) -> Result<Value> {
    if record_id.trim().is_empty() {
        return Err(Error::engine("saver history read needs a record id"));
    }
    let mut args = json!({
        "record_id": record_id,
        "limit": 1000,
        "order": "oldest_first",
        "detail": "full",
    });
    if let Some(seq) = after {
        args.as_object_mut()
            .expect("history arguments are an object")
            .insert("after_seq".into(), Value::from(seq));
    }
    Ok(args)
}

/// Effective-policy read for one record (`manage_record_policy` list).
pub fn policy_arguments(record_id: &str) -> Result<Value> {
    if record_id.trim().is_empty() {
        return Err(Error::engine("saver policy read needs a record id"));
    }
    Ok(json!({ "record_id": record_id }))
}

// ---------------------------------------------------------------------------
// Reply classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendClass {
    Committed,
    /// Position key taken: run the verified adoption read.
    Conflict,
    /// Real key refused by name (non-SQLite backend). Stop, never unkeyed.
    KeyRefused,
    /// Read-only or nothing sent: keep the spool and back off.
    NotSent,
    /// Timeout/dropped/unparsed: resend identical bytes.
    Uncertain,
    AuthRefused,
    /// Hosted positively refused the request itself.
    Refused,
}

#[derive(Debug, Clone)]
pub struct GateVerdict {
    pub auth_refused: bool,
    pub attempt: AttemptClass,
    pub reply: Option<String>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptClass {
    Answered,
    NotSent,
    Stopped,
    Lost,
    Unclear,
}

fn is_key_refusal_text(text: &str) -> bool {
    text.contains("idempotency_key") && text.contains("supported on the SQLite engine only")
}

fn is_read_only_reply(reply: &str) -> bool {
    #[cfg(feature = "mcp-executor-prototype")]
    {
        super::hold::is_deployment_read_only(reply)
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    {
        reply.contains("DEPLOYMENT_READ_ONLY")
    }
}

/// Classify one send. Order: auth, attempt class, key refusal, conflict,
/// read-only, committed-but-unbounded receipt, partial markers, positive
/// refusal, receipt. A possibly-committed step is never quarantined on an
/// ambiguous receipt.
pub fn classify_send(verdict: &GateVerdict) -> SendClass {
    if verdict.auth_refused {
        return SendClass::AuthRefused;
    }
    match verdict.attempt {
        AttemptClass::NotSent | AttemptClass::Stopped => return SendClass::NotSent,
        AttemptClass::Lost | AttemptClass::Unclear => return SendClass::Uncertain,
        AttemptClass::Answered => {}
    }
    let Some(reply) = verdict.reply.as_deref() else {
        return SendClass::Uncertain;
    };
    if is_key_refusal_text(reply) {
        return SendClass::KeyRefused;
    }
    let parsed: Option<Value> = serde_json::from_str(reply).ok();
    let error_code = parsed
        .as_ref()
        .and_then(|v| {
            v.pointer("/result/structuredContent/error_code")
                .or_else(|| v.pointer("/error/data/error_code"))
                .or_else(|| v.pointer("/error/data/upstream_body/error_code"))
        })
        .and_then(Value::as_str);
    if error_code == Some(crate::error::IDEMPOTENCY_CONFLICT_CODE) {
        return SendClass::Conflict;
    }
    if is_read_only_reply(reply) {
        return SendClass::NotSent;
    }
    let Some(parsed) = parsed else {
        return SendClass::Uncertain;
    };
    // Applied but the receipt could not be rebuilt: committed.
    if parsed.pointer("/result/structuredContent/applied") == Some(&Value::Bool(true)) {
        return SendClass::Committed;
    }
    let partial = parsed
        .pointer("/result/structuredContent/applied")
        .and_then(Value::as_str)
        == Some("partial")
        || parsed.pointer("/result/structuredContent/partial") == Some(&Value::Bool(true))
        || matches!(
            parsed
                .pointer("/result/structuredContent/outcome")
                .and_then(Value::as_str),
            Some("unknown" | "uncertain" | "partial")
        );
    if partial {
        return SendClass::Uncertain;
    }
    let refused = parsed.get("error").is_some()
        || parsed.pointer("/result/isError") == Some(&Value::Bool(true))
        || parsed.pointer("/result/structuredContent/applied") == Some(&Value::Bool(false))
        || matches!(verdict.http_status, Some(400..=499));
    if refused {
        return SendClass::Refused;
    }
    if parsed.get("result").is_some_and(|r| !r.is_null()) {
        SendClass::Committed
    } else {
        SendClass::Uncertain
    }
}

/// Fold a send class into the S3a outcome table.
pub fn outcome_of(class: SendClass) -> WriteOutcome {
    match class {
        SendClass::Committed => WriteOutcome::Success,
        SendClass::Conflict => WriteOutcome::Conflict,
        SendClass::KeyRefused => WriteOutcome::KeyRefused,
        SendClass::NotSent => WriteOutcome::NotSent,
        SendClass::Uncertain => WriteOutcome::Unclear,
        SendClass::AuthRefused => WriteOutcome::AuthRefused,
        SendClass::Refused => WriteOutcome::ValidationRefused,
    }
}

// ---------------------------------------------------------------------------
// Hosted sink trait
// ---------------------------------------------------------------------------

/// One ordered step page plus whether more follow.
#[derive(Debug, Clone)]
pub struct StepPage {
    pub steps: Vec<RemoteStep>,
    pub has_more: bool,
}

/// Keyed-creation result. `Taken` means the key exists with different
/// arguments: re-read, never overwrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateResult {
    Created { record_id: Option<String> },
    Taken,
}

/// The domain I/O the writer needs. Implementations must never write the
/// local replica, never invent run or intent, and never retry a refused key
/// without its key.
pub trait HostedSink {
    async fn check_session_schema(&self) -> Result<()> {
        Ok(())
    }
    async fn read_session(&self, record_id: &str) -> Result<RemoteSessionState>;
    async fn update_state(&self, arguments: Value) -> Result<SendClass>;
    async fn create_step(&self, request: &FrozenStepRequest) -> Result<SendClass>;
    async fn query_steps(&self, folder_id: &str, offset: i64) -> Result<StepPage>;
    async fn step_history(&self, record_id: &str) -> Result<Vec<RemoteEvent>>;
    async fn find_root(&self, account_id: &str) -> Result<Option<VerifiedRoot>>;
    async fn find_session_folder(&self, server_id: &str, agent_id: &str) -> Result<Option<String>>;
    async fn find_session_record(&self, folder_id: &str) -> Result<Option<String>>;
    async fn read_row(&self, record_id: &str) -> Result<RowIdentity>;
    async fn read_policy(&self, record_id: &str) -> Result<PolicyView>;
    async fn create_keyed(&self, arguments: Value, key: String) -> Result<CreateResult>;
    async fn add_quote_link(&self, _arguments: Value) -> Result<SendClass> {
        Ok(SendClass::KeyRefused)
    }
}

// ---------------------------------------------------------------------------
// Writer driver
// ---------------------------------------------------------------------------

/// What `send_next` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendAction {
    /// Committed and confirmed; head advanced to `pos`.
    Advanced {
        pos: u64,
    },
    /// Conflicting position adopted after verification. `alignment_required`
    /// is always true in this slice: the checkpoint is flagged and full
    /// alignment is S3b-ii.
    ConflictResolved {
        adopted: bool,
        alignment_required: bool,
    },
    /// Uncertain or not sent: spool kept for byte-identical retry.
    RetryLater,
    StoppedAuth,
    StoppedUnsupported,
    Quarantined,
}

/// Daemon source cursor behind a confirm (S3c supplies it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCursor {
    pub epoch: String,
    pub seq_end: u64,
}

/// Total-loss detector: no checkpoint beside a surviving spool means local
/// state was lost, not that the session is new. Hosted verification and
/// full alignment must run first.
pub fn needs_full_alignment(store: &SessionStore, agent_id: &str) -> Result<bool> {
    if store.load_checkpoint(agent_id)?.needs_realign {
        return Ok(true);
    }
    Ok(!store.has_checkpoint(agent_id)? && store.has_spool(agent_id)?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureOutcome {
    Created(SessionIdentity),
    Existing(SessionIdentity),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAction {
    Held,
    Written,
    /// An older pending request settled. Recompute the desired state and
    /// claim under this boot before proposing another mutation.
    Settled,
    RetryLater,
    Superseded,
    NotEligible,
    AuthRefused,
    Unsupported,
    NotDue,
}

pub struct CatchupContext {
    pub agent_id: String,
    pub daemon_server_id: String,
    pub boot_id: String,
    pub host_label: String,
    pub observed_replacement: bool,
    pub unknown_continuity: bool,
}

/// Monotonic pacing/progress carried only from an actual prior window run.
#[derive(Debug, Clone, Default)]
pub(super) struct CatchupClock {
    last_attempt_ms: Option<u64>,
    last_progress_ms: Option<u64>,
}

/// One admitted source window. Restart prepares a new run from a full fetch
/// and verified hosted chain; a cached fetch cursor cannot restart curation.
pub struct CatchupRun {
    context: CatchupContext,
    source: super::session_catchup::CompleteTimeline,
    plan: AlignmentPlan,
    next_source: usize,
    marker_pending: bool,
    expected_head: (Option<u64>, Option<String>),
    alignment_gen: u64,
    last_attempt_ms: Option<u64>,
    last_progress_ms: Option<u64>,
    acknowledgement_at: Option<String>,
    disclosure_from_pos: u64,
    stopped: bool,
    complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatchupAction {
    Advanced {
        pos: u64,
    },
    Paced,
    RetryLater,
    Realign,
    State(StateAction),
    Complete,
    /// This bounded window settled, but the source suffix is not exhausted.
    /// No source-branch acknowledgement has been written.
    WindowComplete,
    /// Deterministically refused batch; preserve quarantine and stop this run.
    Quarantined,
}

impl CatchupRun {
    pub(super) fn clock(&self) -> CatchupClock {
        CatchupClock {
            last_attempt_ms: self.last_attempt_ms,
            last_progress_ms: self.last_progress_ms,
        }
    }
    pub fn agent_id(&self) -> &str {
        &self.context.agent_id
    }
    pub fn window_token(&self) -> Option<uuid::Uuid> {
        self.source.window_token()
    }
    pub(super) fn confirmed_step_matches(
        &self,
        index: usize,
        expected: &super::session_projection::SourceStepMeta,
    ) -> Result<bool> {
        if index >= self.next_source {
            return Ok(false);
        }
        Ok(
            super::session_projection::SourceStepMeta::from_step(self.source.step(index)?)?
                == *expected,
        )
    }
    pub fn confirmed_cursor(&self) -> Result<SourceCursor> {
        self.source.confirmed_cursor(self.next_source)
    }
    pub fn settled_action(&self) -> Option<CatchupAction> {
        self.complete.then(|| {
            if self.source.exhausted() {
                CatchupAction::Complete
            } else {
                CatchupAction::WindowComplete
            }
        })
    }
    pub fn confirmed_source_prefix(&self) -> usize {
        self.next_source
    }
    pub fn source_snapshot(&self) -> &SourceSnapshot {
        &self.source.snapshot
    }
}

/// A replacement binding permits only host retirement. Every ordinary
/// send continues to require the actual current daemon server identity.
enum WritePurpose<'a> {
    Current(&'a str),
    Retire(&'a Binding),
}

/// One writer over a store and a sink. No background tasks, no daemon reads.
pub struct Writer<'a, S> {
    store: &'a SessionStore,
    sink: &'a S,
    server_id: String,
    account_id: String,
    db_id: String,
    instance_id: String,
}

impl<'a, S> Writer<'a, S>
where
    S: HostedSink,
{
    pub(super) async fn read_owned_session_state(
        &self,
        agent_id: &str,
    ) -> Result<RemoteSessionState> {
        let checkpoint = self.store.load_checkpoint(agent_id)?;
        let folder = checkpoint
            .folder_id
            .as_deref()
            .ok_or_else(|| Error::engine("state write needs session folder"))?;
        let record = checkpoint
            .session_record_id
            .as_deref()
            .ok_or_else(|| Error::engine("state write needs session record"))?;
        let root = self.verified_root().await?;
        self.verify_folder(&root, folder).await?;
        let state = self.sink.read_session(record).await?;
        require_owner(&state.identity, &root)?;
        if state.identity.id != record || state.identity.home_id.as_deref() != Some(folder) {
            return Err(Error::engine("hosted session state identity mismatch"));
        }
        Ok(state)
    }

    fn proposal(
        &self,
        agent: &str,
        record: &str,
        kind: ProposalKind,
        generation: u64,
        writer: &str,
        arguments: Value,
    ) -> Result<FrozenStateProposal> {
        let key = arguments
            .get("idempotency_key")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("state proposal lacks key"))?
            .to_owned();
        Ok(FrozenStateProposal {
            version: 1,
            binding: self.store.binding().clone(),
            agent_id: agent.to_owned(),
            record_id: record.to_owned(),
            kind,
            generation,
            writer: writer.to_owned(),
            key,
            arguments,
        })
    }

    fn stop_state_writer(&self, agent_id: &str) -> Result<StateAction> {
        self.store.latch_lease_stopped(agent_id)?;
        self.store.drop_proposal(agent_id)?;
        Ok(StateAction::Superseded)
    }

    /// A keyed replay can succeed after another holder has taken over.
    /// Check the live lease both before sending and after every success;
    /// adopt/latch durably before removing the frozen request.
    async fn settle_state_proposal(
        &self,
        agent_id: &str,
        pending: &FrozenStateProposal,
    ) -> Result<StateAction> {
        let state = self.read_owned_session_state(agent_id).await?;
        if pending.record_id != state.identity.id {
            return Err(Error::engine(
                "pending state proposal targets another session",
            ));
        }
        let target_held =
            state.claim.generation == pending.generation && state.claim.writer == pending.writer;
        let guard = &pending.arguments["if_facets"];
        let takeover_still_matches = matches!(
            pending.kind,
            ProposalKind::Lease | ProposalKind::Retire | ProposalKind::Transition
        ) && guard["native.session.writer_generation"]
            == json!(state.claim.generation)
            && guard["native.session.writer"] == json!(state.claim.writer)
            && guard["native.session.last_seen_at"] == json!(state.claim.last_seen_at);
        if !target_held && !takeover_still_matches {
            return self.stop_state_writer(agent_id);
        }
        let class = self.sink.update_state(pending.arguments.clone()).await?;
        match outcome_of(class) {
            WriteOutcome::Success => {
                let admitted = self.read_owned_session_state(agent_id).await?;
                if admitted.claim.generation != pending.generation
                    || admitted.claim.writer != pending.writer
                {
                    return self.stop_state_writer(agent_id);
                }
                if pending.kind == ProposalKind::Retire
                    && admitted
                        .facets
                        .get("native.session.state")
                        .is_none_or(|s| s != "ended")
                {
                    return Err(Error::engine("retirement receipt lacks its ended state"));
                }
                // A state replay proves that mutation, not a recovered
                // sequence counter. After checkpoint loss only a new lease
                // generation can safely restart state keys at zero.
                if matches!(
                    pending.kind,
                    ProposalKind::Lease | ProposalKind::Retire | ProposalKind::Transition
                ) {
                    self.store
                        .adopt_lease(agent_id, pending.generation, &pending.writer)?;
                }
                let last_seen_ms =
                    chrono::DateTime::parse_from_rfc3339(&admitted.claim.last_seen_at)
                        .map_err(|_| Error::engine("invalid admitted heartbeat"))?
                        .timestamp_millis();
                self.store.mark_proposal_settled(
                    agent_id,
                    pending,
                    last_seen_ms,
                    admitted
                        .facets
                        .get("native.session.state")
                        .map(String::as_str),
                )?;
                self.store.drop_proposal(agent_id)?;
                Ok(StateAction::Settled)
            }
            WriteOutcome::Conflict | WriteOutcome::ValidationRefused => {
                self.stop_state_writer(agent_id)
            }
            WriteOutcome::NotSent | WriteOutcome::Lost | WriteOutcome::Unclear => {
                Ok(StateAction::RetryLater)
            }
            WriteOutcome::AuthRefused => Ok(StateAction::AuthRefused),
            WriteOutcome::KeyRefused => Ok(StateAction::Unsupported),
        }
    }

    async fn quarantine_lifecycle_proposal(
        &self,
        agent: &str,
        pending: &FrozenStateProposal,
    ) -> Result<()> {
        // A lost lease reply may already have committed. Admit only that
        // exact own-instance target from live owner-checked state; never
        // replay its ordinary request after a host reset.
        if matches!(pending.kind, ProposalKind::Lease | ProposalKind::Transition) {
            let live = self.read_owned_session_state(agent).await?;
            let cp = self.store.load_checkpoint(agent)?;
            if !cp.lease_stopped
                && live.claim.generation == pending.generation
                && live.claim.writer == pending.writer
                && live
                    .claim
                    .writer
                    .starts_with(&format!("{}/{}/", self.server_id, self.instance_id))
            {
                self.store
                    .adopt_lease(agent, pending.generation, &pending.writer)?;
            }
        }
        self.store.quarantine_fenced_proposal(agent)
    }

    /// End an old host only after an authenticated replacement was observed.
    /// No ordinary pending request is replayed across the host boundary. A
    /// generation CAS fences every older state proposal before closing.
    pub async fn retire_host_session(
        &self,
        agent: &str,
        current: &Binding,
        boot: &str,
        now: &str,
    ) -> Result<StateAction> {
        self.gate(WritePurpose::Retire(current))?;
        if boot.is_empty() || boot.contains('/') {
            return Err(Error::engine("invalid retirement boot identity"));
        }
        self.store.retire_host()?;
        self.store.mark_needs_realign(agent)?;
        if let Some(pending) = self.store.load_proposal(agent)? {
            if pending.kind == ProposalKind::Retire {
                let action = self.settle_state_proposal(agent, &pending).await?;
                if action == StateAction::Settled {
                    self.store.latch_lease_stopped(agent)?;
                }
                return Ok(action);
            }
            self.quarantine_lifecycle_proposal(agent, &pending).await?;
        }
        let state = self.read_owned_session_state(agent).await?;
        let cp = self.store.load_checkpoint(agent)?;
        if state
            .facets
            .get("native.session.state")
            .is_some_and(|s| s == "ended")
        {
            self.store.latch_lease_stopped(agent)?;
            return Ok(StateAction::NotDue);
        }
        let own_prefix = format!("{}/{}/", self.server_id, self.instance_id);
        if cp.lease_stopped
            || cp.lease_writer.as_deref() != Some(state.claim.writer.as_str())
            || cp.writer_generation != state.claim.generation
            || !state.claim.writer.starts_with(&own_prefix)
        {
            return self.stop_state_writer(agent);
        }
        let generation = state
            .claim
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::engine("retirement generation exhausted"))?;
        let writer = self.own_writer(boot);
        let mut args = lease_takeover_arguments(&state.identity.id, &state.claim, &writer, now)?;
        let key = format!("nss3:retire:{}:g{generation}", state.identity.id);
        args["idempotency_key"] = json!(key);
        args["reason"] = json!("End saved session after daemon identity reset");
        args["facets"]["native.session.state"] = json!("ended");
        args["lifecycle"] = json!("closed");
        let pending = self.proposal(
            agent,
            &state.identity.id,
            ProposalKind::Retire,
            generation,
            &writer,
            args,
        )?;
        self.store.freeze_proposal(&pending)?;
        let action = self.settle_state_proposal(agent, &pending).await?;
        if action == StateAction::Settled {
            self.store.latch_lease_stopped(agent)?;
        }
        Ok(action)
    }

    /// A lifecycle transition fences state replies already in flight under
    /// the previous generation. It never claims a foreign or lost lease.
    #[allow(clippy::too_many_arguments)]
    pub async fn transition_session(
        &self,
        agent: &str,
        daemon_server: &str,
        boot: &str,
        now: &str,
        state: &str,
        reason: Option<&str>,
    ) -> Result<StateAction> {
        self.gate(WritePurpose::Current(daemon_server))?;
        if !matches!(state, "paused" | "stopped" | "ended" | "error")
            || boot.is_empty()
            || boot.contains('/')
        {
            return Err(Error::engine("invalid saver lifecycle transition"));
        }
        if self.store.load_checkpoint(agent)?.lease_stopped {
            return Ok(StateAction::Superseded);
        }
        self.store.mark_needs_realign(agent)?;
        if let Some(pending) = self.store.load_proposal(agent)? {
            if pending.kind == ProposalKind::Transition {
                return self.settle_state_proposal(agent, &pending).await;
            }
            self.quarantine_lifecycle_proposal(agent, &pending).await?;
        }
        let live = self.read_owned_session_state(agent).await?;
        let cp = self.store.load_checkpoint(agent)?;
        if cp.writer_generation != live.claim.generation
            || cp.lease_writer.as_deref() != Some(live.claim.writer.as_str())
            || !live
                .claim
                .writer
                .starts_with(&format!("{}/{}/", self.server_id, self.instance_id))
        {
            return self.stop_state_writer(agent);
        }
        if live
            .facets
            .get("native.session.state")
            .is_some_and(|s| s == state)
            && cp.settled_proposal_key.as_deref()
                == Some(
                    format!(
                        "nss3:transition:{}:g{}",
                        live.identity.id, live.claim.generation
                    )
                    .as_str(),
                )
            && reason.is_none_or(|r| {
                live.facets
                    .get("native.session.paused_reason")
                    .is_some_and(|s| s == r)
            })
        {
            return Ok(StateAction::NotDue);
        }
        let generation = live
            .claim
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::engine("lifecycle generation exhausted"))?;
        let writer = self.own_writer(boot);
        let mut args = lease_takeover_arguments(&live.identity.id, &live.claim, &writer, now)?;
        args["idempotency_key"] = json!(format!(
            "nss3:transition:{}:g{generation}",
            live.identity.id
        ));
        args["reason"] = json!("Saved session lifecycle transition");
        args["facets"]["native.session.state"] = json!(state);
        if let Some(reason) = reason {
            args["facets"]["native.session.paused_reason"] = json!(reason);
        }
        if state == "ended" {
            args["lifecycle"] = json!("closed");
        }
        let pending = self.proposal(
            agent,
            &live.identity.id,
            ProposalKind::Transition,
            generation,
            &writer,
            args,
        )?;
        self.store.freeze_proposal(&pending)?;
        self.settle_state_proposal(agent, &pending).await
    }

    pub async fn claim_state_lease(
        &self,
        agent_id: &str,
        daemon_server_id: &str,
        boot_id: &str,
        now: &str,
    ) -> Result<StateAction> {
        self.gate(WritePurpose::Current(daemon_server_id))?;
        let checkpoint = self.store.load_checkpoint(agent_id)?;
        if checkpoint.lease_stopped {
            return Ok(StateAction::Superseded);
        }
        if let Some(pending) = self.store.load_proposal(agent_id)? {
            return self.settle_state_proposal(agent_id, &pending).await;
        }
        if boot_id.is_empty() || boot_id.contains('/') {
            return Err(Error::engine("invalid saver boot identity"));
        }
        let time = chrono::DateTime::parse_from_rfc3339(now)
            .map_err(|_| Error::engine("invalid lease claim time"))?;
        let state = self.read_owned_session_state(agent_id).await?;
        let writer = self.own_writer(boot_id);
        if state.claim.generation == checkpoint.writer_generation && state.claim.writer == writer {
            self.store
                .adopt_lease(agent_id, state.claim.generation, &writer)?;
            return Ok(StateAction::Held);
        }
        if !takeover_eligible(
            &state.claim,
            &self.server_id,
            &self.instance_id,
            time.timestamp(),
        ) {
            return Ok(StateAction::NotEligible);
        }
        let arguments = lease_takeover_arguments(&state.identity.id, &state.claim, &writer, now)?;
        let generation = state
            .claim
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::engine("writer generation exhausted"))?;
        let pending = self.proposal(
            agent_id,
            &state.identity.id,
            ProposalKind::Lease,
            generation,
            &writer,
            arguments,
        )?;
        self.store.freeze_proposal(&pending)?;
        match self.settle_state_proposal(agent_id, &pending).await? {
            StateAction::Settled => Ok(StateAction::Held),
            other => Ok(other),
        }
    }

    pub async fn write_session_state(
        &self,
        agent_id: &str,
        daemon_server_id: &str,
        boot_id: &str,
        now: &str,
        mut facets: BTreeMap<String, Value>,
    ) -> Result<StateAction> {
        self.gate(WritePurpose::Current(daemon_server_id))?;
        let checkpoint = self.store.load_checkpoint(agent_id)?;
        if checkpoint.lease_stopped {
            return Ok(StateAction::Superseded);
        }
        if let Some(pending) = self.store.load_proposal(agent_id)? {
            return self.settle_state_proposal(agent_id, &pending).await;
        }
        chrono::DateTime::parse_from_rfc3339(now)
            .map_err(|_| Error::engine("invalid state write time"))?;
        let state = self.read_owned_session_state(agent_id).await?;
        let writer = self.own_writer(boot_id);
        if state.claim.generation != checkpoint.writer_generation
            || state.claim.writer != writer
            || checkpoint.lease_writer.as_deref() != Some(writer.as_str())
        {
            return self.stop_state_writer(agent_id);
        }
        facets.insert("native.session.last_seen_at".into(), json!(now));
        validate_state_facets(&state, &facets)?;
        if facets
            .get("native.session.confirmed_pos")
            .and_then(Value::as_u64)
            .is_some_and(|position| position > checkpoint.head_pos.unwrap_or(0))
        {
            return Err(Error::engine(
                "progress exceeds the locally confirmed chain",
            ));
        }
        let sequence = self
            .store
            .reserve_state_seq(agent_id, state.claim.generation, &writer)?;
        let guarded_keys = [
            "native.session.continuity_notes",
            "native.session.source_branch",
        ];
        let mut guards = Vec::new();
        for key in guarded_keys
            .into_iter()
            .filter(|key| facets.contains_key(*key))
        {
            let expected =
                match state.facets.get(key) {
                    None => Value::Null,
                    Some(text) if key == "native.session.source_branch" => json!(text
                        .parse::<u64>()
                        .map_err(|_| Error::engine("invalid hosted source branch guard"))?),
                    Some(text) => json!(text),
                };
            guards.push((key, expected));
        }
        let mut arguments =
            state_update_arguments(&state.identity.id, &state.claim, sequence, facets)?;
        for (key, expected) in guards {
            arguments["if_facets"][key] = expected;
        }
        if arguments["facets"]["native.session.state"] == json!("saving") {
            arguments["lifecycle"] = json!("open");
        }
        if arguments["facets"]["native.session.state"] == json!("ended") {
            arguments["lifecycle"] = json!("closed");
        }
        let pending = self.proposal(
            agent_id,
            &state.identity.id,
            ProposalKind::State,
            state.claim.generation,
            &writer,
            arguments,
        )?;
        self.store.freeze_proposal(&pending)?;
        match self.settle_state_proposal(agent_id, &pending).await? {
            StateAction::Settled => Ok(StateAction::Written),
            other => Ok(other),
        }
    }

    /// Only saving sessions receive beats, at most once per five minutes.
    /// A recent confirmed step or state mutation suppresses the separate beat.
    pub async fn heartbeat(
        &self,
        agent_id: &str,
        daemon_server_id: &str,
        boot_id: &str,
        now: &str,
    ) -> Result<StateAction> {
        self.gate(WritePurpose::Current(daemon_server_id))?;
        let checkpoint = self.store.load_checkpoint(agent_id)?;
        if checkpoint.lease_stopped {
            return Ok(StateAction::Superseded);
        }
        if let Some(pending) = self.store.load_proposal(agent_id)? {
            return self.settle_state_proposal(agent_id, &pending).await;
        }
        let state = self.read_owned_session_state(agent_id).await?;
        let writer = self.own_writer(boot_id);
        if state.claim.generation != checkpoint.writer_generation
            || state.claim.writer != writer
            || checkpoint.lease_writer.as_deref() != Some(writer.as_str())
        {
            return self.stop_state_writer(agent_id);
        }
        let now_ms = chrono::DateTime::parse_from_rfc3339(now)
            .map_err(|_| Error::engine("invalid heartbeat time"))?
            .timestamp_millis();
        let seen_ms = chrono::DateTime::parse_from_rfc3339(&state.claim.last_seen_at)
            .map_err(|_| Error::engine("invalid hosted heartbeat"))?
            .timestamp_millis();
        if !heartbeat_due(
            seen_ms.max(checkpoint.last_hosted_write_ms),
            now_ms,
            state
                .facets
                .get("native.session.state")
                .is_some_and(|s| s == "saving"),
        ) {
            return Ok(StateAction::NotDue);
        }
        self.write_session_state(agent_id, daemon_server_id, boot_id, now, BTreeMap::new())
            .await
    }

    /// Call after the alignment marker and suffix are confirmed. Branch
    /// acknowledgement and its required disclosure commit in the same guarded
    /// state mutation; later updates cannot clear the append-only note list.
    pub async fn acknowledge_source_alignment(
        &self,
        agent_id: &str,
        daemon_server_id: &str,
        boot_id: &str,
        now: &str,
        from_pos: u64,
        plan: &AlignmentPlan,
    ) -> Result<StateAction> {
        self.gate(WritePurpose::Current(daemon_server_id))?;
        if self.store.load_checkpoint(agent_id)?.lease_stopped {
            return Ok(StateAction::Superseded);
        }
        if let Some(pending) = self.store.load_proposal(agent_id)? {
            return self.settle_state_proposal(agent_id, &pending).await;
        }
        let state = self.read_owned_session_state(agent_id).await?;
        let mut facets = BTreeMap::new();
        if let Some(branch) = plan.source_branch {
            facets.insert("native.session.source_branch".into(), json!(branch));
        }
        if plan.continuity_assumed {
            let mut notes = continuity_notes(state.facets.get("native.session.continuity_notes"))?;
            notes.push(ContinuityNote {
                at: now.to_owned(),
                from_pos,
            });
            facets.insert(
                "native.session.continuity".into(),
                json!("assumed_by_content"),
            );
            facets.insert("native.session.continuity_at".into(), json!(now));
            facets.insert(
                "native.session.continuity_notes".into(),
                json!(serde_json::to_string(&notes)
                    .map_err(|_| Error::engine("continuity note encoding failed"))?),
            );
        }
        if facets.is_empty() {
            return Ok(StateAction::NotDue);
        }
        self.write_session_state(agent_id, daemon_server_id, boot_id, now, facets)
            .await
    }

    pub fn new(
        store: &'a SessionStore,
        sink: &'a S,
        server_id: &str,
        account_id: &str,
        db_id: &str,
        instance_id: &str,
    ) -> Self {
        Self {
            store,
            sink,
            server_id: server_id.to_owned(),
            account_id: account_id.to_owned(),
            db_id: db_id.to_owned(),
            instance_id: instance_id.to_owned(),
        }
    }

    /// Binding + server fence for every canonical write.
    fn gate(&self, purpose: WritePurpose<'_>) -> Result<()> {
        match purpose {
            WritePurpose::Current(daemon_server_id) => {
                check_send_binding(
                    self.store.binding(),
                    &self.account_id,
                    &self.db_id,
                    daemon_server_id,
                )?;
                if self.store.host_retired()? {
                    return Err(Error::engine("old saver host is durably retired"));
                }
            }
            WritePurpose::Retire(current) => {
                current.validate()?;
                let old = self.store.binding();
                if old.server_id != self.server_id
                    || old.account_id != self.account_id
                    || old.db_id != self.db_id
                    || current.account_id != old.account_id
                    || current.db_id != old.db_id
                    || current.server_id == old.server_id
                {
                    return Err(Error::engine(
                        "host retirement requires a real replacement in the same account/database",
                    ));
                }
            }
        }
        Ok(())
    }

    fn own_writer(&self, boot_id: &str) -> String {
        format!("{}/{}/{}", self.server_id, self.instance_id, boot_id)
    }
}

impl<'a, S> Writer<'a, S>
where
    S: HostedSink,
{
    /// Send the actionable spool entry once and resolve the outcome.
    ///
    /// The frozen request is sent verbatim; retries resend identical bytes
    /// under the identical position key. A conflict runs the verified
    /// adoption read. Adoption always leaves the checkpoint flagged for
    /// alignment and reports that alignment is required — this slice never
    /// claims the saving is current.
    pub async fn send_next(
        &self,
        agent_id: &str,
        daemon_server_id: &str,
        cursor: &SourceCursor,
    ) -> Result<SendAction> {
        self.gate(WritePurpose::Current(daemon_server_id))?;
        if needs_full_alignment(self.store, agent_id)? {
            return Err(Error::engine(
                "saver local state lost or awaiting realignment: hosted verification and full alignment must run first",
            ));
        }
        let Some(spooled) = self.store.load_spool(agent_id)? else {
            return Err(Error::engine("no actionable spool entry to send"));
        };
        let class = self.sink.create_step(&spooled).await?;
        match outcome_of(class) {
            WriteOutcome::Success => {
                let cp = self.store.confirm_spooled(
                    agent_id,
                    spooled.pos,
                    &spooled.facets.cid,
                    &spooled.facets.fp,
                    &cursor.epoch,
                    cursor.seq_end,
                )?;
                Ok(SendAction::Advanced {
                    pos: cp.head_pos.unwrap_or(spooled.pos),
                })
            }
            WriteOutcome::Conflict => {
                let adopted = self.adopt_at_pos(agent_id, spooled.pos).await?;
                Ok(SendAction::ConflictResolved {
                    adopted,
                    alignment_required: true,
                })
            }
            WriteOutcome::NotSent | WriteOutcome::Lost | WriteOutcome::Unclear => {
                Ok(SendAction::RetryLater)
            }
            WriteOutcome::AuthRefused => Ok(SendAction::StoppedAuth),
            WriteOutcome::KeyRefused => Ok(SendAction::StoppedUnsupported),
            WriteOutcome::ValidationRefused => {
                self.store.mark_needs_realign(agent_id)?;
                self.store.quarantine_spool(agent_id)?;
                Ok(SendAction::Quarantined)
            }
        }
    }

    /// Verified adoption read for a conflicted position.
    ///
    /// The expected owner is the canonical person established by the
    /// verified root, never the credential and never an arbitrary folder
    /// owner; the expected parent is the checkpoint head (or the chain root
    /// at position 1), never the spool's untrusted parent.
    pub async fn adopt_at_pos(&self, agent_id: &str, pos: u64) -> Result<bool> {
        let checkpoint = self.store.load_checkpoint(agent_id)?;
        let Some(folder_id) = checkpoint.folder_id.clone() else {
            return Err(Error::engine("saver adoption needs a session folder"));
        };
        let root = self.verified_root().await?;
        let anchor = self.verify_folder(&root, &folder_id).await?;
        let head_cid = match (&checkpoint.head_pos, &checkpoint.head_cid) {
            (Some(_), Some(cid)) => cid.clone(),
            (None, None) => {
                if pos != 1 {
                    return Err(Error::engine("headless adoption admits only position 1"));
                }
                chain_root(&self.server_id, agent_id)?
            }
            _ => return Err(Error::engine("saver checkpoint head is half-present")),
        };
        let candidates = self.steps_at_pos(&folder_id, pos).await?;
        let expected = AdmissionExpectation {
            pos,
            owner_id: anchor.owner.clone(),
            actor: self.account_id.clone(),
            home_id: folder_id.clone(),
            head_cid,
        };
        let history = match candidates.as_slice() {
            [only] => Some(self.sink.step_history(&only.record_id).await?),
            _ => None,
        };
        match validate_admission(&expected, &candidates, history.as_deref()) {
            AdmissionVerdict::Adopt => {
                let only = &candidates[0];
                if let Some(base_len) = only.base_len {
                    super::session_persist::check_marker_base_len(
                        base_len,
                        checkpoint.source_fps.len(),
                    )?;
                }
                // Durable flag BEFORE adoption, then quarantine the rejected
                // spool: a restart must realign, never replay the old map.
                self.store.mark_needs_realign(agent_id)?;
                self.store
                    .adopt_foreign_head(agent_id, pos, &only.cid, Vec::new())?;
                if self.store.has_spool(agent_id)? {
                    self.store.quarantine_spool(agent_id)?;
                }
                Ok(true)
            }
            AdmissionVerdict::Refuse(kind) => {
                self.store.mark_needs_realign(agent_id)?;
                if self.store.has_spool(agent_id)? {
                    let _ = self.store.quarantine_spool(agent_id);
                }
                Err(Error::engine(format!(
                    "saver chain refused at pos {pos}: {kind:?}; rebuild from last verified prefix"
                )))
            }
        }
    }

    /// Rebuild only from the complete, owner-verified hosted chain. Local
    /// cursor/head values never stand in for admission evidence here.
    pub async fn verified_chain(&self, agent_id: &str) -> Result<VerifiedChain> {
        self.verified_chain_steps(agent_id)
            .await
            .map(|(chain, _)| chain)
    }

    /// Recover quote candidates from full immutable create evidence, even
    /// after loss of every local cursor. This preparation performs no writes.
    pub(super) async fn quote_link_plan(
        &self,
        agent_id: &str,
    ) -> Result<Vec<super::session_quotes::QuoteLink>> {
        let (_, steps) = self.verified_chain_steps(agent_id).await?;
        Ok(super::session_quotes::plan(&steps))
    }

    async fn verified_chain_steps(
        &self,
        agent_id: &str,
    ) -> Result<(VerifiedChain, Vec<RemoteStep>)> {
        let checkpoint = self.store.load_checkpoint(agent_id)?;
        let folder_id = checkpoint
            .folder_id
            .ok_or_else(|| Error::engine("chain rebuild needs a session folder"))?;
        let root = self.verified_root().await?;
        let anchor = self.verify_folder(&root, &folder_id).await?;
        let mut steps_with_history = Vec::new();
        for step in self.all_folder_steps(&folder_id).await? {
            let history = self.sink.step_history(&step.record_id).await?;
            steps_with_history.push((step, history));
        }
        let chain = verify_hosted_chain(
            &self.server_id,
            agent_id,
            &anchor.owner,
            &self.account_id,
            &folder_id,
            &steps_with_history,
        )?;
        let mut steps: Vec<RemoteStep> = steps_with_history
            .into_iter()
            .map(|(step, _)| step)
            .collect();
        steps.sort_by_key(|step| step.pos);
        Ok((chain, steps))
    }

    /// Restartable owner-claimed quote side effects. Every frozen batch is
    /// matched against newly verified immutable history before any replay.
    /// A full local-state loss starts again at the true chain root; keys and
    /// ordinals come entirely from admitted content, not local row ids.
    pub(super) async fn recover_quote_links(
        &self,
        agent: &str,
        server: &str,
        boot: &str,
    ) -> Result<StateAction> {
        use super::session_quotes::{self, PendingQuotes};
        self.gate(WritePurpose::Current(server))?;
        self.verification_lease_pulse(agent, server, boot).await?;
        let verification = self.verified_chain_steps(agent);
        tokio::pin!(verification);
        let mut pulse = tokio::time::interval(std::time::Duration::from_secs(60));
        pulse.tick().await;
        let (_, steps) = loop {
            tokio::select! {
                result=&mut verification=>break result?,
                _=pulse.tick()=>self.verification_lease_pulse(agent,server,boot).await?,
            }
        };
        let batches = session_quotes::batches(&steps);
        let mut cp = self.store.load_checkpoint(agent)?;
        let scanned = cp
            .quote_scan
            .as_ref()
            .filter(|(pos, cid)| {
                steps
                    .iter()
                    .any(|step| step.pos == *pos && step.cid == *cid)
            })
            .map_or(0, |(pos, _)| *pos);
        // A pending request is not trusted merely because it was on disk.
        if let Some(pending) = &cp.quote_pending {
            if pending.next > pending.batch.links.len()
                || (pending.mark_unverified && pending.next == pending.batch.links.len())
                || !batches
                    .iter()
                    .any(|batch| batch == &pending.batch && batch.through_pos > scanned)
            {
                return Err(Error::engine(
                    "saved quote batch no longer matches admitted history",
                ));
            }
        }
        for batch in batches
            .into_iter()
            .filter(|batch| batch.through_pos > scanned)
        {
            let mut pending = match cp.quote_pending.take() {
                Some(pending) if pending.batch == batch => pending,
                Some(_) => {
                    return Err(Error::engine("saved quote batch skips the admitted prefix"))
                }
                None => PendingQuotes {
                    batch,
                    next: 0,
                    mark_unverified: false,
                },
            };
            while pending.next < pending.batch.links.len() {
                self.verification_lease_pulse(agent, server, boot).await?;
                cp = self.store.load_checkpoint(agent)?;
                if cp.lease_stopped {
                    return Ok(StateAction::Superseded);
                }
                let live = self.read_owned_session_state(agent).await?;
                if live.claim.writer != self.own_writer(boot)
                    || live.claim.generation != cp.writer_generation
                {
                    return self.stop_state_writer(agent);
                }
                cp.quote_pending = Some(pending.clone());
                self.store.save_checkpoint(&cp)?;
                let link = &pending.batch.links[pending.next];
                self.gate(WritePurpose::Current(server))?;
                let outcome = if pending.mark_unverified {
                    self.sink.update_state(json!({"ids":[link.source_id],"facets":{"native.session.quote_link":"unverified"},"reason":"Record unverified quoted reply","idempotency_key":format!("{}:unverified",link.key())})).await?
                } else {
                    self.sink.add_quote_link(json!({"source_id":link.source_id,"target_id":link.target_id,"relationship":"relates_to","note":"quoted reply","idempotency_key":link.key()})).await?
                };
                match outcome {
                    SendClass::Committed => {
                        pending.next += 1;
                        pending.mark_unverified = false;
                    }
                    SendClass::Refused if !pending.mark_unverified => {
                        pending.mark_unverified = true
                    }
                    SendClass::AuthRefused => return Ok(StateAction::AuthRefused),
                    SendClass::KeyRefused => return Ok(StateAction::Unsupported),
                    SendClass::NotSent | SendClass::Uncertain => {
                        return Ok(StateAction::RetryLater)
                    }
                    _ => {
                        return Err(Error::engine(
                            "quoted reply side effect was refused or conflicted",
                        ))
                    }
                }
                cp = self.store.load_checkpoint(agent)?;
                cp.quote_pending = Some(pending.clone());
                self.store.save_checkpoint(&cp)?;
            }
            cp = self.store.load_checkpoint(agent)?;
            cp.quote_scan = Some((pending.batch.through_pos, pending.batch.through_cid));
            cp.quote_pending = None;
            self.store.save_checkpoint(&cp)?;
        }
        Ok(StateAction::Written)
    }

    async fn verification_lease_pulse(&self, agent: &str, server: &str, boot: &str) -> Result<()> {
        loop {
            match self
                .heartbeat(agent, server, boot, &chrono::Utc::now().to_rfc3339())
                .await?
            {
                StateAction::Written | StateAction::NotDue => return Ok(()),
                // A replay may belong to an older mutation. Re-read through
                // heartbeat before claiming the lease is currently fresh.
                StateAction::Settled => {}
                StateAction::RetryLater => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await
                }
                StateAction::AuthRefused => {
                    return Err(Error::Auth(
                        "history verification heartbeat refused authentication".into(),
                    ))
                }
                _ => return Err(Error::engine("history verification lost its saving lease")),
            }
        }
    }

    /// Keep a saving lease fresh during a long read-only history fold. The
    /// verification future is paused while each metadata proposal settles;
    /// no two per-agent state writers run concurrently.
    pub(super) async fn verified_chain_live(
        &self,
        agent: &str,
        server: &str,
        boot: &str,
    ) -> Result<VerifiedChain> {
        self.gate(WritePurpose::Current(server))?;
        self.verification_lease_pulse(agent, server, boot).await?;
        let verification = self.verified_chain(agent);
        tokio::pin!(verification);
        let mut pulse = tokio::time::interval(std::time::Duration::from_secs(5 * 60));
        pulse.tick().await;
        loop {
            tokio::select! {
                result=&mut verification=>return result,
                _=pulse.tick()=>self.verification_lease_pulse(agent,server,boot).await?,
            }
        }
    }

    async fn steps_at_pos(&self, folder_id: &str, pos: u64) -> Result<Vec<RemoteStep>> {
        Ok(self
            .all_folder_steps(folder_id)
            .await?
            .into_iter()
            .filter(|s| s.pos == pos)
            .collect())
    }

    /// Every hosted step in a folder, position-ordered, within the bound.
    async fn all_folder_steps(&self, folder_id: &str) -> Result<Vec<RemoteStep>> {
        let mut steps = Vec::new();
        let mut offset = 0i64;
        loop {
            let page = self.sink.query_steps(folder_id, offset).await?;
            if page.steps.len() as i64 > QUERY_PAGE_LIMIT {
                return Err(Error::engine("hosted step page exceeds contract bound"));
            }
            let n = page.steps.len();
            steps.extend(page.steps);
            if steps.len() > MAX_HOSTED_STEPS {
                return Err(Error::engine("hosted step history exceeds fold bound"));
            }
            if n == 0 {
                if page.has_more {
                    return Err(Error::engine(
                        "hosted step query claims more pages but returned none",
                    ));
                }
                break;
            }
            if !page.has_more {
                break;
            }
            offset += n as i64;
        }
        steps.sort_by_key(|s| s.pos);
        Ok(steps)
    }
}

impl<S: HostedSink> Writer<'_, S> {
    /// Full restart alignment. The flag precedes every hosted verification
    /// read and every stale-spool quarantine. Only after those succeed does
    /// one checkpoint replace install head/E/cursor/generation/clear flag.
    pub async fn prepare_catchup(
        &self,
        source: super::session_catchup::CompleteTimeline,
        context: CatchupContext,
    ) -> Result<CatchupRun> {
        self.prepare_catchup_inner(source, context, false).await
    }
    pub(super) async fn prepare_catchup_live(
        &self,
        source: super::session_catchup::CompleteTimeline,
        context: CatchupContext,
    ) -> Result<CatchupRun> {
        self.prepare_catchup_inner(source, context, true).await
    }
    async fn prepare_catchup_inner(
        &self,
        source: super::session_catchup::CompleteTimeline,
        context: CatchupContext,
        live: bool,
    ) -> Result<CatchupRun> {
        self.gate(WritePurpose::Current(&context.daemon_server_id))?;
        let agent = &context.agent_id;
        if context.boot_id.is_empty()
            || context.boot_id.contains('/')
            || context.host_label.trim().is_empty()
        {
            return Err(Error::engine("invalid catch-up boot or host identity"));
        }
        if source.agent_id() != agent {
            return Err(Error::engine("source timeline belongs to another agent"));
        }
        if self.store.load_proposal(agent)?.is_some() {
            return Err(Error::engine(
                "settle pending state proposal before catch-up",
            ));
        }
        self.store.mark_needs_realign(agent)?;
        let state = self.read_owned_session_state(agent).await?;
        let mut cp = self.store.load_checkpoint(agent)?;
        let own = self.own_writer(&context.boot_id);
        if cp.lease_stopped
            || cp.writer_generation != state.claim.generation
            || cp.lease_writer.as_deref() != Some(own.as_str())
            || state.claim.writer != own
        {
            self.store.latch_lease_stopped(agent)?;
            return Err(Error::engine(
                "catch-up requires the currently admitted state writer",
            ));
        }
        let acknowledged = state
            .facets
            .get("native.session.source_branch")
            .map(|s| {
                s.parse::<u64>()
                    .map_err(|_| Error::engine("invalid acknowledged source branch"))
            })
            .transpose()?;
        let chain = if live {
            self.verified_chain_live(agent, &context.daemon_server_id, &context.boot_id)
                .await?
        } else {
            self.verified_chain(agent).await?
        };
        let fresh = self.store.load_checkpoint(agent)?;
        if fresh.lease_stopped
            || fresh.writer_generation != cp.writer_generation
            || fresh.lease_writer != cp.lease_writer
            || fresh.alignment_gen != cp.alignment_gen
            || fresh.head_pos != cp.head_pos
            || fresh.head_cid != cp.head_cid
        {
            return Err(Error::Conflict(
                "checkpoint changed during history verification".into(),
            ));
        }
        // A verification pulse may have reserved and settled state keys.
        // Preserve those fields when installing the alignment checkpoint.
        cp = fresh;
        if live {
            let current = self.read_owned_session_state(agent).await?;
            if current.claim.generation != cp.writer_generation || current.claim.writer != own {
                self.store.latch_lease_stopped(agent)?;
                return Err(Error::engine(
                    "saving lease changed during history verification",
                ));
            }
        }
        let unknown_continuity = context.unknown_continuity
            || (source.snapshot.branch.is_none()
                && (context.observed_replacement
                    || (chain.head_pos.is_some()
                        && cp.cursor_epoch.as_deref() != Some(source.snapshot.epoch.as_str()))));
        let plan = source.plan(
            &chain,
            acknowledged,
            context.observed_replacement,
            unknown_continuity,
        )?;
        let cursor = source.confirmed_cursor(plan.base_len)?;
        while self.store.has_spool(agent)? {
            self.store.quarantine_spool(agent)?;
        }
        cp.alignment_gen = cp
            .alignment_gen
            .checked_add(1)
            .ok_or_else(|| Error::engine("saver alignment generation exhausted"))?;
        cp.head_pos = chain.head_pos;
        cp.head_cid = chain.head_cid;
        cp.head_fp = chain.head_fp;
        cp.source_fps = chain.e;
        cp.cursor_epoch = Some(cursor.epoch);
        cp.cursor_seq_end = Some(cursor.seq_end);
        let next_pos = cp
            .head_pos
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| Error::engine("saved-session position exhausted"))?;
        cp.needs_realign = false;
        self.store.save_checkpoint(&cp)?;
        // On resumed markers, qualify the complete earlier history rather
        // than placing a lost branch-gap disclosure after an already-written
        // suffix. This is deliberately conservative after a crash.
        let disclosure_from_pos = if source.windowed()
            || (chain.marker_branch == plan.source_branch && plan.source_branch.is_some())
        {
            1
        } else {
            next_pos
        };
        let clock = source.clock.clone().unwrap_or_default();
        Ok(CatchupRun {
            next_source: plan.base_len,
            marker_pending: plan.marker.is_some(),
            expected_head: (cp.head_pos, cp.head_cid),
            alignment_gen: cp.alignment_gen,
            context,
            source,
            plan,
            last_attempt_ms: clock.last_attempt_ms,
            last_progress_ms: clock.last_progress_ms,
            acknowledgement_at: None,
            disclosure_from_pos,
            stopped: false,
            complete: false,
        })
    }

    /// Perform at most one hosted step attempt. `tick_ms` is monotonic time
    /// since the daemon driver's boot; wall-clock strings are metadata only.
    /// Every retry uses the surviving frozen spool; no request is re-keyed.
    pub async fn pump_catchup(
        &self,
        run: &mut CatchupRun,
        current: &SourceSnapshot,
        now: &str,
        tick_ms: u64,
    ) -> Result<CatchupAction> {
        self.gate(WritePurpose::Current(&run.context.daemon_server_id))?;
        let agent = &run.context.agent_id;
        if run.stopped {
            return Err(Error::engine(
                "catch-up run stopped: prepare a fresh verified alignment",
            ));
        }
        if run.source.snapshot.check_page(current).is_err() {
            self.store.mark_needs_realign(agent)?;
            run.stopped = true;
            return Ok(CatchupAction::Realign);
        }
        if run.complete {
            return Ok(if run.source.exhausted() {
                CatchupAction::Complete
            } else {
                CatchupAction::WindowComplete
            });
        }
        let cp = self.store.load_checkpoint(agent)?;
        if cp.lease_stopped {
            run.stopped = true;
            return Ok(CatchupAction::State(StateAction::Superseded));
        }
        if cp.needs_realign
            || cp.alignment_gen != run.alignment_gen
            || (cp.head_pos, cp.head_cid.clone()) != run.expected_head
        {
            self.store.mark_needs_realign(agent)?;
            run.stopped = true;
            return Ok(CatchupAction::Realign);
        }
        if !run.marker_pending && run.next_source == run.source.source_len() {
            if !run.source.exhausted() {
                run.complete = true;
                return Ok(CatchupAction::WindowComplete);
            }
            // Resolve a lost state response without appending a second note
            // after the identical keyed receipt settles.
            if let Some(at) = &run.acknowledgement_at {
                if self.store.load_proposal(agent)?.is_none() {
                    let state = self.read_owned_session_state(agent).await?;
                    if state.claim.generation != cp.writer_generation
                        || state.claim.writer != self.own_writer(&run.context.boot_id)
                    {
                        self.store.latch_lease_stopped(agent)?;
                        run.stopped = true;
                        return Ok(CatchupAction::State(StateAction::Superseded));
                    }
                    let branch_matches = run.plan.source_branch.is_none_or(|branch| {
                        state
                            .facets
                            .get("native.session.source_branch")
                            .is_some_and(|s| s == &branch.to_string())
                    });
                    let note_matches = !run.plan.continuity_assumed
                        || continuity_notes(state.facets.get("native.session.continuity_notes"))?
                            .iter()
                            .any(|note| note.at == *at && note.from_pos == run.disclosure_from_pos);
                    if branch_matches && note_matches {
                        run.complete = true;
                        return Ok(CatchupAction::Complete);
                    }
                    run.acknowledgement_at = None;
                }
            }
            if run.acknowledgement_at.is_none() {
                run.acknowledgement_at = Some(now.to_owned());
            }
            let action = self
                .acknowledge_source_alignment(
                    agent,
                    &run.context.daemon_server_id,
                    &run.context.boot_id,
                    now,
                    run.disclosure_from_pos,
                    &run.plan,
                )
                .await?;
            match action {
                StateAction::Written | StateAction::NotDue => {
                    run.complete = true;
                    Ok(CatchupAction::Complete)
                }
                StateAction::Superseded | StateAction::AuthRefused | StateAction::Unsupported => {
                    run.stopped = true;
                    Ok(CatchupAction::State(action))
                }
                _ => Ok(CatchupAction::State(action)),
            }
        } else {
            let last_progress = *run.last_progress_ms.get_or_insert(tick_ms);
            if tick_ms.saturating_sub(last_progress) >= 30_000 {
                let action = self
                    .write_session_state(
                        agent,
                        &run.context.daemon_server_id,
                        &run.context.boot_id,
                        now,
                        BTreeMap::from([(
                            "native.session.confirmed_pos".into(),
                            json!(cp.head_pos.unwrap_or(0)),
                        )]),
                    )
                    .await?;
                if action == StateAction::Written {
                    run.last_progress_ms = Some(tick_ms);
                } else if action == StateAction::Settled {
                    let state = self.read_owned_session_state(agent).await?;
                    if state.claim.generation != cp.writer_generation
                        || state.claim.writer != self.own_writer(&run.context.boot_id)
                    {
                        self.store.latch_lease_stopped(agent)?;
                        run.stopped = true;
                        return Ok(CatchupAction::State(StateAction::Superseded));
                    }
                    if state
                        .facets
                        .get("native.session.confirmed_pos")
                        .and_then(|s| s.parse::<u64>().ok())
                        == Some(cp.head_pos.unwrap_or(0))
                    {
                        run.last_progress_ms = Some(tick_ms);
                    }
                }
                if matches!(
                    action,
                    StateAction::Superseded | StateAction::AuthRefused | StateAction::Unsupported
                ) {
                    run.stopped = true;
                }
                return Ok(CatchupAction::State(action));
            }
            if run
                .last_attempt_ms
                .is_some_and(|last| tick_ms.saturating_sub(last) < 250)
            {
                return Ok(CatchupAction::Paced);
            }
            let pos = cp
                .head_pos
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| Error::engine("saved-session position exhausted"))?;
            let parent = cp
                .head_cid
                .clone()
                .unwrap_or(chain_root(&self.server_id, agent)?);
            let folder = cp
                .folder_id
                .as_deref()
                .ok_or_else(|| Error::engine("catch-up lacks folder"))?;
            let source_index = if run.marker_pending {
                run.plan.base_len
            } else {
                run.next_source + 1
            };
            let cursor = run.source.confirmed_cursor(source_index)?;
            let desired = if run.marker_pending {
                freeze_marker(
                    self.store,
                    agent,
                    folder,
                    run.plan.marker.expect("pending marker"),
                    &run.context.host_label,
                    run.plan.base_len as u64,
                    cp.source_fps.len(),
                    &parent,
                    pos,
                    now,
                )?
                .with_marker_branch(run.plan.source_branch)?
            } else {
                let step = run.source.step(run.next_source)?;
                FrozenStepRequest::freeze(
                    self.store.binding(),
                    agent,
                    folder,
                    step.kind.as_str(),
                    &step.body,
                    step.kind.as_str(),
                    step.part_index,
                    None,
                    &parent,
                    &step.fingerprint,
                    pos,
                    now,
                )?
            };
            if let Some(pending) = self.store.load_spool(agent)? {
                if pending.pos != desired.pos
                    || pending.home_id != desired.home_id
                    || pending.facets.parent_cid != desired.facets.parent_cid
                    || pending.facets.fp != desired.facets.fp
                    || pending.facets.base_len != desired.facets.base_len
                    || pending.facets.branch_no != desired.facets.branch_no
                {
                    self.store.mark_needs_realign(agent)?;
                    run.stopped = true;
                    return Ok(CatchupAction::Realign);
                }
            } else {
                self.store.freeze_spool(&desired, agent)?;
            }
            run.last_attempt_ms = Some(tick_ms);
            match self
                .send_next(agent, &run.context.daemon_server_id, &cursor)
                .await?
            {
                SendAction::Advanced { pos } => {
                    let cp = self.store.load_checkpoint(agent)?;
                    run.expected_head = (cp.head_pos, cp.head_cid);
                    if run.marker_pending {
                        run.marker_pending = false;
                    } else {
                        run.next_source += 1;
                    }
                    Ok(CatchupAction::Advanced { pos })
                }
                SendAction::RetryLater => Ok(CatchupAction::RetryLater),
                SendAction::ConflictResolved { .. } => {
                    run.stopped = true;
                    Ok(CatchupAction::Realign)
                }
                SendAction::StoppedAuth => {
                    run.stopped = true;
                    Ok(CatchupAction::State(StateAction::AuthRefused))
                }
                SendAction::StoppedUnsupported => {
                    run.stopped = true;
                    Ok(CatchupAction::State(StateAction::Unsupported))
                }
                SendAction::Quarantined => {
                    run.stopped = true;
                    Ok(CatchupAction::Quarantined)
                }
            }
        }
    }
}

/// A folder whose ownership and effective policy are verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderAnchor {
    pub folder_id: String,
    pub owner: String,
    /// Policy anchor: the verified root for new identities, a channel (or
    /// other collection) for a legitimately shared existing folder.
    pub anchor_id: String,
}

impl<'a, S> Writer<'a, S>
where
    S: HostedSink,
{
    /// The caller's verified Saved-sessions root, or a refusal.
    async fn verified_root(&self) -> Result<VerifiedRoot> {
        self.sink
            .find_root(&self.account_id)
            .await?
            .ok_or_else(|| Error::engine("no verified saved-sessions root: refusing"))
    }

    /// Read one folder and positively verify it: real owner, inherited
    /// policy, our own manage, administration authorised.
    pub async fn verify_folder(
        &self,
        root: &VerifiedRoot,
        folder_id: &str,
    ) -> Result<FolderAnchor> {
        let row = self.sink.read_row(folder_id).await?;
        require_owner(&row, root)?;
        let view = self.sink.read_policy(folder_id).await?;
        verify_folder_policy(&view, root, false)?;
        Ok(FolderAnchor {
            folder_id: row.id,
            owner: root.owner.clone(),
            anchor_id: view.anchor_id,
        })
    }

    /// Verify a folder we have just created: additionally, it must inherit
    /// the verified root exactly.
    async fn verify_new_folder(
        &self,
        root: &VerifiedRoot,
        folder_id: &str,
    ) -> Result<FolderAnchor> {
        let row = self.sink.read_row(folder_id).await?;
        require_owner(&row, root)?;
        let view = self.sink.read_policy(folder_id).await?;
        verify_folder_policy(&view, root, true)?;
        Ok(FolderAnchor {
            folder_id: row.id,
            owner: root.owner.clone(),
            anchor_id: view.anchor_id,
        })
    }

    /// Find or create the Saved-sessions root, verified end to end.
    async fn ensure_root(&self, root_name: &str) -> Result<VerifiedRoot> {
        if let Some(root) = self.sink.find_root(&self.account_id).await? {
            return Ok(root);
        }
        let args = create_root_arguments(&self.account_id, root_name)?;
        let key = format!("nss3:root:{}", self.account_id);
        // Created, replayed or taken: converge on the verified read.
        self.sink.create_keyed(args, key).await?;
        self.sink
            .find_root(&self.account_id)
            .await?
            .ok_or_else(|| Error::engine("saved-sessions root not found after create"))
    }

    /// Staged, reconstructible identity: root → folder → record.
    ///
    /// Each stage stands alone. An interrupted folder-create-before-record
    /// completes on the next pass — with a changed title, timestamp or boot
    /// id — by re-reading only the missing stage. A shared existing folder
    /// is accepted unchanged: it is never moved and never required to sit
    /// under the root.
    #[allow(clippy::too_many_arguments)]
    pub async fn ensure_session(
        &self,
        agent_id: &str,
        daemon_server_id: &str,
        root_name: &str,
        title: &str,
        host_label: &str,
        provider: &str,
        boot_id: &str,
        now_rfc3339: &str,
    ) -> Result<EnsureOutcome> {
        self.gate(WritePurpose::Current(daemon_server_id))?;
        // Read-only prerequisite: an execution host never grants itself schema
        // administration. Refuse before identity or lease writes if absent.
        self.sink.check_session_schema().await?;
        let root = self.ensure_root(root_name).await?;
        let mut created = false;

        // Stage 1 — folder.
        let folder_id = match self
            .sink
            .find_session_folder(&self.server_id, agent_id)
            .await?
        {
            Some(id) => id,
            None => {
                let key = format!("nss3:{}:{agent_id}:folder", self.server_id);
                let args =
                    create_session_folder_arguments(&self.server_id, agent_id, &root.id, title)?;
                match self.sink.create_keyed(args, key).await? {
                    CreateResult::Created {
                        record_id: Some(id),
                    } => {
                        created = true;
                        id
                    }
                    // Created without a receipt id, or the key is held by a
                    // drifted attempt: re-read only this stage.
                    CreateResult::Created { record_id: None } | CreateResult::Taken => self
                        .sink
                        .find_session_folder(&self.server_id, agent_id)
                        .await?
                        .ok_or_else(|| {
                            Error::engine("session folder key taken but the folder is not visible")
                        })?,
                }
            }
        };
        // A folder created in an earlier interrupted pass is still a known
        // existing folder; only a folder created by *this* call must anchor
        // at the root. Both cases verify ownership and policy positively.
        if created {
            self.verify_new_folder(&root, &folder_id).await?;
        } else {
            self.verify_folder(&root, &folder_id).await?;
        }

        // Stage 2 — record inside the verified folder.
        let record_id = match self.sink.find_session_record(&folder_id).await? {
            Some(id) => id,
            None => {
                let key = format!("nss3:{}:{agent_id}:record", self.server_id);
                let args = create_session_record_arguments(
                    &self.server_id,
                    agent_id,
                    &folder_id,
                    title,
                    &self.account_id,
                    &self.db_id,
                    host_label,
                    provider,
                    &self.own_writer(boot_id),
                    now_rfc3339,
                )?;
                match self.sink.create_keyed(args, key).await? {
                    CreateResult::Created {
                        record_id: Some(id),
                    } => {
                        created = true;
                        id
                    }
                    // Drifted metadata (title/time/boot) makes the key
                    // conflict; re-read only the record stage.
                    CreateResult::Created { record_id: None } | CreateResult::Taken => self
                        .sink
                        .find_session_record(&folder_id)
                        .await?
                        .ok_or_else(|| {
                            Error::engine("session record key taken but the record is not visible")
                        })?,
                }
            }
        };
        let record_row = self.sink.read_row(&record_id).await?;
        require_owner(&record_row, &root)?;
        if record_row.home_id.as_deref() != Some(folder_id.as_str()) {
            return Err(Error::engine(
                "session record is not homed in its session folder: refusing",
            ));
        }
        self.store
            .set_session_ids(agent_id, &root.id, &folder_id, &record_id)?;
        let identity = SessionIdentity {
            folder_id,
            record_id,
        };
        if created {
            Ok(EnsureOutcome::Created(identity))
        } else {
            Ok(EnsureOutcome::Existing(identity))
        }
    }
}

// ---------------------------------------------------------------------------
// Production adapter: real gate + real upstream (never started here)
// ---------------------------------------------------------------------------

/// Live hosted sink over the node's gate and upstream. Every write carries
/// `no_hold: true` with the caller-owned position key and no run or intent;
/// reads are plain unjournaled sends through the same transport.
#[cfg(feature = "mcp-executor-prototype")]
pub(super) struct GateSink {
    upstream: Arc<super::Upstream>,
    gate: Arc<super::gate::WriteGate>,
    frames: std::sync::Mutex<FrameIds>,
}

#[cfg(feature = "mcp-executor-prototype")]
impl GateSink {
    pub(super) fn new(upstream: Arc<super::Upstream>, gate: Arc<super::gate::WriteGate>) -> Self {
        Self {
            upstream,
            gate,
            frames: std::sync::Mutex::new(FrameIds::default()),
        }
    }

    async fn read_round_trip(&self, message: Value) -> Result<super::SendReport> {
        let report = self.round_trip(message).await;
        if matches!(report.failure, Some(super::Health::AuthRefused))
            || matches!(report.status, Some(401 | 403))
        {
            return Err(Error::Auth(
                "hosted saved-session read refused authentication".into(),
            ));
        }
        if matches!(report.failure, Some(super::Health::ProtocolFailed)) {
            return Err(Error::engine("hosted saved-session read protocol failed"));
        }
        if matches!(report.failure, Some(super::Health::Unreachable))
            || !matches!(report.attempt, super::Attempt::Answered)
            || matches!(report.status, Some(500..=599))
            || report.reply.is_none()
        {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "hosted saved-session read unavailable",
            )));
        }
        Ok(report)
    }

    fn next_frame_id(&self) -> u64 {
        self.frames.lock().expect("saver frame ids").next()
    }

    async fn round_trip(&self, message: Value) -> super::SendReport {
        let body = message.to_string();
        let caller = super::Caller::new(None, super::Cancel::new());
        self.gate
            .forward(
                &self.upstream,
                &super::gate::WriteRequest {
                    body: &body,
                    message: &message,
                    revision: None,
                    caller: &caller,
                    outage: None,
                    no_hold: true,
                },
                false,
            )
            .await
    }

    fn write_frame(&self, operation: &str, arguments: Value) -> Value {
        let id = self.next_frame_id();
        call_message(id, "records_write", operation, arguments)
    }

    /// Reads travel as `call_executor` envelopes too: the executor surface
    /// dispatches nothing by bare tool name.
    fn read_frame(&self, executor: &str, operation: &str, arguments: Value) -> Value {
        let id = self.next_frame_id();
        call_message(id, executor, operation, arguments)
    }

    fn classify(report: &super::SendReport) -> SendClass {
        let attempt = match report.attempt {
            super::Attempt::Answered => AttemptClass::Answered,
            super::Attempt::NotSent => AttemptClass::NotSent,
            super::Attempt::Stopped => AttemptClass::Stopped,
            super::Attempt::Lost => AttemptClass::Lost,
            super::Attempt::Unclear => AttemptClass::Unclear,
        };
        classify_send(&GateVerdict {
            auth_refused: matches!(report.failure, Some(super::Health::AuthRefused)),
            attempt,
            reply: report.reply.clone(),
            http_status: report.status,
        })
    }

    /// Ordered record ids from one query page plus the continuation flag.
    fn parse_id_page(reply: &Option<String>) -> Result<(Vec<String>, bool)> {
        let text = reply
            .as_deref()
            .ok_or_else(|| Error::engine("hosted step query has no reply"))?;
        let value: Value = serde_json::from_str(text)
            .map_err(|_| Error::engine("hosted step query reply is not JSON"))?;
        if value.get("error").is_some() {
            return Err(Error::engine("hosted step query refused"));
        }
        let content = value
            .pointer("/result/structuredContent")
            .or_else(|| value.pointer("/result"));
        let rows = content
            .and_then(|c| c.get("records"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::engine("hosted step query has no records"))?;
        if rows.len() as i64 > QUERY_PAGE_LIMIT {
            return Err(Error::engine(
                "hosted step query page exceeds contract bound",
            ));
        }
        let mut ids = Vec::with_capacity(rows.len());
        for row in rows {
            ids.push(
                row.get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::engine("hosted query row has no id"))?
                    .to_owned(),
            );
        }
        let has_more = content
            .and_then(|c| c.get("has_more"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Ok((ids, has_more))
    }

    /// Hydrated rows; a foreign/private id arrives as `not_found` and is
    /// absence, refused loudly rather than hydrated.
    fn parse_hydrated_rows(reply: &Option<String>) -> Result<Vec<Value>> {
        let text = reply
            .as_deref()
            .ok_or_else(|| Error::engine("hosted record read has no reply"))?;
        let value: Value = serde_json::from_str(text)
            .map_err(|_| Error::engine("hosted record read reply is not JSON"))?;
        if value.get("error").is_some() {
            return Err(Error::engine("hosted record read refused"));
        }
        let rows = value
            .pointer("/result/structuredContent/records")
            .or_else(|| value.pointer("/result/records"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::engine("hosted record read has no records"))?;
        for row in rows {
            match row.get("status").and_then(Value::as_str) {
                None | Some("found") => {}
                Some(other) => {
                    return Err(Error::engine(format!("hosted record not visible: {other}")));
                }
            }
        }
        Ok(rows.clone())
    }

    fn parse_record_row(reply: &Option<String>) -> Result<Value> {
        Self::parse_hydrated_rows(reply)?
            .into_iter()
            .next()
            .ok_or_else(|| Error::engine("hosted record read returned no rows"))
    }

    fn parse_history_page(reply: &Option<String>) -> Result<(Vec<RemoteEvent>, Option<i64>)> {
        let text = reply
            .as_deref()
            .ok_or_else(|| Error::engine("hosted history read has no reply"))?;
        let value: Value = serde_json::from_str(text)
            .map_err(|_| Error::engine("hosted history read reply is not JSON"))?;
        if value.get("error").is_some() {
            return Err(Error::engine("hosted history read refused"));
        }
        let content = value
            .pointer("/result/structuredContent")
            .or_else(|| value.pointer("/result"));
        let events = content
            .and_then(|c| c.get("events"))
            .and_then(Value::as_array)
            .ok_or_else(|| Error::engine("hosted history has no events"))?;
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            out.push(parse_remote_event(event)?);
        }
        let cursor = content
            .and_then(|c| c.get("next_after_local_seq"))
            .and_then(Value::as_i64);
        Ok((out, cursor))
    }

    fn receipt_record_id(reply: &Option<String>) -> Option<String> {
        let text = reply.as_deref()?;
        let value: Value = serde_json::from_str(text).ok()?;
        for pointer in ["/result/structuredContent/id", "/result/id"] {
            if let Some(id) = value.pointer(pointer).and_then(Value::as_str) {
                if !id.is_empty() {
                    return Some(id.to_owned());
                }
            }
        }
        None
    }
}

#[cfg(feature = "mcp-executor-prototype")]
impl GateSink {
    async fn read_step_page(&self, folder_id: &str, offset: i64) -> Result<StepPage> {
        let query = self.read_frame(
            "records_read",
            "query_record",
            query_steps_arguments(folder_id, offset)?,
        );
        let report = self.read_round_trip(query).await?;
        let (ids, has_more) = Self::parse_id_page(&report.reply)?;
        if ids.is_empty() {
            if has_more {
                return Err(Error::engine(
                    "hosted step query claims more pages but returned none",
                ));
            }
            return Ok(StepPage {
                steps: Vec::new(),
                has_more: false,
            });
        }
        let rows = self.hydrate(ids).await?;
        let mut steps = Vec::with_capacity(rows.len());
        for row in &rows {
            steps.push(parse_remote_step(row)?);
        }
        Ok(StepPage { steps, has_more })
    }

    /// Complete bounded history, oldest first, following the cursor.
    async fn read_full_history(&self, record_id: &str) -> Result<Vec<RemoteEvent>> {
        let mut events = Vec::new();
        let mut cursor: Option<i64> = None;
        for _ in 0..MAX_HISTORY_PAGES {
            let message = self.read_frame(
                "records_read",
                "get_history",
                history_arguments_paged(record_id, cursor)?,
            );
            let report = self.read_round_trip(message).await?;
            let (mut page, next) = Self::parse_history_page(&report.reply)?;
            events.append(&mut page);
            cursor = next;
            if cursor.is_none() {
                return Ok(events);
            }
        }
        Err(Error::engine(
            "hosted history exceeds the page bound: refusing partial validation",
        ))
    }

    async fn hydrate(&self, ids: Vec<String>) -> Result<Vec<Value>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let message = self.read_frame("records_read", "get_record", json!({"ids": ids}));
        let report = self.read_round_trip(message).await?;
        Self::parse_hydrated_rows(&report.reply)
    }

    async fn query_ids(&self, arguments: Value) -> Result<Vec<String>> {
        let message = self.read_frame("records_read", "query_record", arguments);
        let report = self.read_round_trip(message).await?;
        Ok(Self::parse_id_page(&report.reply)?.0)
    }
}

#[cfg(feature = "mcp-executor-prototype")]
impl HostedSink for GateSink {
    async fn check_session_schema(&self) -> Result<()> {
        fn content(reply: &Option<String>) -> Result<Value> {
            let parsed: Value = serde_json::from_str(
                reply
                    .as_deref()
                    .ok_or_else(|| Error::engine(SCHEMA_REQUIRED))?,
            )
            .map_err(|_| Error::engine(SCHEMA_REQUIRED))?;
            if parsed.get("error").is_some()
                || parsed.pointer("/result/isError") == Some(&Value::Bool(true))
            {
                return Err(Error::engine(SCHEMA_REQUIRED));
            }
            parsed
                .pointer("/result/structuredContent")
                .or_else(|| parsed.get("result"))
                .cloned()
                .ok_or_else(|| Error::engine(SCHEMA_REQUIRED))
        }
        let report = self
            .read_round_trip(self.read_frame(
                "schema_read",
                "preview_record_shape",
                json!({"type":"Document","kind":"agent-session"}),
            ))
            .await?;
        let preview = content(&report.reply)?;
        let shape = &preview["selection"]["effective_facet_shape"]["lifecycle"];
        if preview["selection"]["effective_kind"] != "agent-session"
            || preview["selection"]["kind_resolution"]["quarantined"].as_bool() != Some(false)
            || ["key", "label"].iter().any(|field| {
                shape["axis"][field]
                    .as_str()
                    .is_none_or(|s| s.trim().is_empty())
            })
        {
            return Err(Error::engine(SCHEMA_REQUIRED));
        }
        let vocabulary = shape["vocab"]
            .as_str()
            .or_else(|| shape["vocab_ref"].as_str())
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| Error::engine(SCHEMA_REQUIRED))?;
        let report=self.read_round_trip(self.read_frame("schema_read","manage_vocabularies.list_values",json!({"vocabulary":vocabulary.strip_prefix("rec:").unwrap_or(vocabulary),"status":"active","resolve_aliases":true}))).await?;
        let values = content(&report.reply)?;
        let values = values["values"]
            .as_array()
            .ok_or_else(|| Error::engine(SCHEMA_REQUIRED))?;
        for (token, terminality) in [("open", "open"), ("closed", "terminal_positive")] {
            if !values.iter().any(|v| {
                v["value"] == token && v["status"] == "active" && v["terminality"] == terminality
            }) {
                return Err(Error::engine(SCHEMA_REQUIRED));
            }
        }
        Ok(())
    }

    async fn read_session(&self, record_id: &str) -> Result<RemoteSessionState> {
        let message = self.read_frame("records_read", "get_record", json!({"ids": [record_id]}));
        let report = self.read_round_trip(message).await?;
        parse_remote_session(&Self::parse_record_row(&report.reply)?)
    }

    async fn add_quote_link(&self, arguments: Value) -> Result<SendClass> {
        if arguments
            .get("idempotency_key")
            .and_then(Value::as_str)
            .is_none_or(|s| s.is_empty())
        {
            return Err(Error::engine("quote link requires its stable key"));
        }
        let report = self
            .round_trip(self.write_frame("manage_links.add", arguments))
            .await;
        Ok(Self::classify(&report))
    }

    async fn update_state(&self, arguments: Value) -> Result<SendClass> {
        if arguments
            .get("idempotency_key")
            .and_then(Value::as_str)
            .is_none_or(|s| s.is_empty())
        {
            return Err(Error::engine("state write requires its frozen key"));
        }
        let report = self
            .round_trip(self.write_frame("update_record", arguments))
            .await;
        Ok(Self::classify(&report))
    }
    async fn create_step(&self, request: &FrozenStepRequest) -> Result<SendClass> {
        let message = self.write_frame("create_record", step_create_arguments(request));
        let report = self.round_trip(message).await;
        Ok(Self::classify(&report))
    }

    async fn query_steps(&self, folder_id: &str, offset: i64) -> Result<StepPage> {
        self.read_step_page(folder_id, offset).await
    }

    async fn step_history(&self, record_id: &str) -> Result<Vec<RemoteEvent>> {
        self.read_full_history(record_id).await
    }

    /// Root candidates are positively verified: policy proven private and
    /// self-anchored for our account, and the engine's resolved bound
    /// person equals the record's owner. Several matching roots refuse.
    async fn find_root(&self, account_id: &str) -> Result<Option<VerifiedRoot>> {
        let ids = self.query_ids(find_root_arguments(account_id)?).await?;
        let mut found = Vec::new();
        for row in self.hydrate(ids).await? {
            let facets = facet_map(&row).unwrap_or_default();
            if facets.get(ROOT_ACCOUNT_FACET).map(String::as_str) != Some(account_id) {
                continue;
            }
            let identity = parse_row_identity(&row)?;
            let view = self.read_policy(&identity.id).await?;
            // A candidate carrying our account facet must verify: an
            // unreadable, broadened or foreign-owned one refuses rather
            // than being skipped, so a second root is never created beside
            // an ownership we cannot prove.
            let bound_person = verify_own_root(&view, account_id)?;
            if identity.owner_id.as_deref() != Some(bound_person.as_str()) {
                return Err(Error::engine(
                    "saved-sessions root owner does not match the bound person: refusing",
                ));
            }
            found.push(VerifiedRoot {
                id: identity.id,
                name: row
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                owner: bound_person,
            });
        }
        if found.len() > 1 {
            return Err(Error::engine(
                "several saved-sessions roots for one account: refusing",
            ));
        }
        Ok(found.into_iter().next())
    }

    async fn find_session_folder(&self, server_id: &str, agent_id: &str) -> Result<Option<String>> {
        let ids = self
            .query_ids(find_session_folder_arguments(server_id, agent_id)?)
            .await?;
        let mut folders = Vec::new();
        for row in self.hydrate(ids).await? {
            let facets = facet_map(&row).unwrap_or_default();
            if facets.get("native.session.host_id").map(String::as_str) != Some(server_id)
                || facets.get("native.session.agent_id").map(String::as_str) != Some(agent_id)
            {
                continue;
            }
            folders.push(parse_row_identity(&row)?.id);
        }
        if folders.len() > 1 {
            return Err(Error::engine(
                "several session folders for one host/agent: refusing",
            ));
        }
        Ok(folders.into_iter().next())
    }

    async fn find_session_record(&self, folder_id: &str) -> Result<Option<String>> {
        let ids = self
            .query_ids(session_record_lookup_arguments(folder_id)?)
            .await?;
        let mut records = Vec::new();
        for row in self.hydrate(ids).await? {
            let identity = parse_row_identity(&row)?;
            if identity.home_id.as_deref() != Some(folder_id) {
                continue;
            }
            records.push(identity.id);
        }
        if records.len() > 1 {
            return Err(Error::engine(
                "several session records in one folder: refusing",
            ));
        }
        Ok(records.into_iter().next())
    }

    async fn read_row(&self, record_id: &str) -> Result<RowIdentity> {
        let message = self.read_frame("records_read", "get_record", json!({"ids": [record_id]}));
        let report = self.read_round_trip(message).await?;
        parse_row_identity(&Self::parse_record_row(&report.reply)?)
    }

    async fn read_policy(&self, record_id: &str) -> Result<PolicyView> {
        let message = self.read_frame(
            "access_read",
            "manage_record_policy.list",
            policy_arguments(record_id)?,
        );
        let report = self.read_round_trip(message).await?;
        parse_policy_view(&report.reply)
    }

    async fn create_keyed(&self, arguments: Value, key: String) -> Result<CreateResult> {
        // The builders already carry the key; the transport must never send
        // an unkeyed create, so make the key explicit and exact here.
        let mut arguments = arguments;
        let object = arguments
            .as_object_mut()
            .ok_or_else(|| Error::engine("hosted keyed create needs object arguments"))?;
        match object.get("idempotency_key").and_then(Value::as_str) {
            Some(existing) if existing == key => {}
            Some(_) => {
                return Err(Error::engine(
                    "hosted keyed create arguments disagree with the requested key",
                ))
            }
            None => {
                object.insert("idempotency_key".into(), Value::String(key));
            }
        }
        let message = self.write_frame("create_record", arguments);
        let report = self.round_trip(message).await;
        match Self::classify(&report) {
            SendClass::Committed => Ok(CreateResult::Created {
                record_id: Self::receipt_record_id(&report.reply),
            }),
            SendClass::Conflict => Ok(CreateResult::Taken),
            SendClass::AuthRefused => Err(Error::Auth(
                "hosted keyed create refused authentication".into(),
            )),
            SendClass::NotSent | SendClass::Uncertain => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "hosted keyed create has no confirmed receipt",
            ))),
            other => Err(Error::engine(format!(
                "hosted keyed create did not commit: {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::session_persist::{chain_next, Binding, SessionStore};
    use crate::node::session_projection::fingerprint_step;

    const SERVER: &str = "srv-a";
    const AGENT: &str = "agent-1";
    const ACCOUNT: &str = "acct-a";
    const DB: &str = "db-a";
    const PERSON: &str = "person-a";

    fn test_binding() -> Binding {
        Binding::new(SERVER, ACCOUNT, DB, None).unwrap()
    }

    fn open_store(dir: &std::path::Path) -> SessionStore {
        SessionStore::open(&dir.join("sessions"), test_binding()).unwrap()
    }

    fn sample_fp(body: &str) -> String {
        fingerprint_step(StepKind::Agent, 0, body)
    }

    fn cursor() -> SourceCursor {
        SourceCursor {
            epoch: "epoch-1".into(),
            seq_end: 41,
        }
    }

    fn answered(reply: &str) -> GateVerdict {
        GateVerdict {
            auth_refused: false,
            attempt: AttemptClass::Answered,
            reply: Some(reply.into()),
            http_status: None,
        }
    }

    #[test]
    fn classify_send_matrix() {
        use SendClass::*;
        // Clean receipts commit.
        assert_eq!(
            classify_send(&answered(r#"{"jsonrpc":"2.0","id":1,"result":{"id":"r"}}"#)),
            Committed
        );
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"applied":true}}}"#
            )),
            Committed
        );
        // Applied but the receipt could not be rebuilt: still committed.
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"structuredContent":{"applied":true}}}"#
            )),
            Committed
        );
        // Partial markers are uncertain, never receipts.
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"applied":"partial"}}}"#
            )),
            Uncertain
        );
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"outcome":"unknown"}}}"#
            )),
            Uncertain
        );
        // Ambiguous answers are uncertain, never quarantined on a guess.
        assert_eq!(classify_send(&answered("not json")), Uncertain);
        assert_eq!(
            classify_send(&answered(r#"{"jsonrpc":"2.0","id":1,"result":null}"#)),
            Uncertain
        );
        // Conflict via error_code, in both framed shapes.
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"structuredContent":{"error_code":"idempotency_conflict"}}}"#
            )),
            Conflict
        );
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"upstream_body":{"error_code":"idempotency_conflict"}}}}"#
            )),
            Conflict
        );
        // Non-SQLite key refusal stops, never unkeyed.
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"error":"update_record: idempotency_key is supported on the SQLite engine only, not postgres; retry without it"}}}"#
            )),
            KeyRefused
        );
        // Read-only is backoff, never quarantine.
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"structuredContent":{"error_code":"DEPLOYMENT_READ_ONLY","applied":false}}}"#
            )),
            NotSent
        );
        // Positive refusals stop the session.
        assert_eq!(
            classify_send(&answered(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"bad facets"}}"#
            )),
            Refused
        );
        // Auth wins over body inspection.
        assert_eq!(
            classify_send(&GateVerdict {
                auth_refused: true,
                attempt: AttemptClass::Answered,
                reply: Some(r#"{"error":"unauthorized","outcome":"refused"}"#.into()),
                http_status: Some(401),
            }),
            AuthRefused
        );
        let attempt_only = |attempt| GateVerdict {
            auth_refused: false,
            attempt,
            reply: None,
            http_status: None,
        };
        assert_eq!(classify_send(&attempt_only(AttemptClass::NotSent)), NotSent);
        assert_eq!(classify_send(&attempt_only(AttemptClass::Stopped)), NotSent);
        assert_eq!(classify_send(&attempt_only(AttemptClass::Lost)), Uncertain);
        assert_eq!(
            classify_send(&attempt_only(AttemptClass::Unclear)),
            Uncertain
        );
    }

    #[test]
    fn builders_force_json_and_carry_no_run_or_intent() {
        let frame = call_message(7, "records_write", "create_record", json!({"a": 1}));
        let text = serde_json::to_string(&frame).unwrap();
        assert!(!text.contains("run_key"));
        assert!(!text.contains("parent_key"));
        assert!(!text.contains("intent"));
        assert_eq!(frame["params"]["name"], json!("records_write"));
        assert_eq!(
            frame["params"]["arguments"]["operation"],
            json!("create_record")
        );
        assert_eq!(frame["params"]["arguments"]["format"], json!("json"));
        let read = call_message(8, "records_read", "query_record", json!({"steps": []}));
        assert_eq!(read["params"]["arguments"]["format"], json!("json"));
        assert_eq!(read["params"]["name"], json!("records_read"));
        assert!(!serde_json::to_string(&read).unwrap().contains("run_key"));
        // Root policy is the single literal, never an object.
        let root = create_root_arguments(ACCOUNT, "Saved").unwrap();
        assert_eq!(root["access_policy"], json!("account_only"));
        assert_eq!(root["idempotency_key"], json!("nss3:root:acct-a"));
        // Folder and record inherit: no policy of their own.
        let folder = create_session_folder_arguments(SERVER, AGENT, "root-1", "t").unwrap();
        assert!(folder.get("access_policy").is_none());
        assert_eq!(folder["facets"][FOLDER_FACET], json!(1));
        let record = create_session_record_arguments(
            SERVER,
            AGENT,
            "folder-1",
            "t",
            ACCOUNT,
            DB,
            "host",
            "claude",
            "srv-a/i/b",
            "now",
        )
        .unwrap();
        assert!(record.get("access_policy").is_none());
        assert_eq!(
            record["idempotency_key"],
            json!("nss3:srv-a:agent-1:record")
        );
        assert_eq!(
            record["facets"]["native.session.writer_generation"],
            json!(1)
        );
        // Frozen step args carry exactly wire_request plus the key.
        let store_dir = tempfile::tempdir().unwrap();
        let store = open_store(store_dir.path());
        let root_cid = chain_root(SERVER, AGENT).unwrap();
        let req = FrozenStepRequest::freeze(
            store.binding(),
            AGENT,
            "folder-1",
            "step",
            "hello",
            "agent",
            0,
            None,
            &root_cid,
            &sample_fp("hello"),
            1,
            "2026-10-17T00:00:00Z",
        )
        .unwrap();
        let mut expected = req.wire_request();
        expected
            .as_object_mut()
            .unwrap()
            .insert("idempotency_key".into(), Value::String(req.key.clone()));
        assert_eq!(step_create_arguments(&req), expected);
    }

    #[test]
    fn binding_and_server_fence() {
        let binding = test_binding();
        assert!(check_send_binding(&binding, ACCOUNT, DB, SERVER).is_ok());
        // Foreign account or db refuse.
        assert!(check_send_binding(&binding, "acct-b", DB, SERVER).is_err());
        assert!(check_send_binding(&binding, ACCOUNT, "db-b", SERVER).is_err());
        // A changed server id is a new host: refuse.
        assert!(check_send_binding(&binding, ACCOUNT, DB, "srv-reset").is_err());
        assert!(check_send_binding(&binding, ACCOUNT, DB, "  ").is_err());
    }

    fn policy(mode: &str, anchor: &str, record: &str, entries: Vec<PolicyEntry>) -> PolicyView {
        PolicyView {
            record_id: record.into(),
            target_id: record.into(),
            anchor_id: anchor.into(),
            mode: mode.into(),
            caller_capability: "manage".into(),
            policy_administration_authorized: true,
            entries,
        }
    }

    fn account_entry(account: &str, person: Option<&str>) -> PolicyEntry {
        PolicyEntry {
            subject_kind: "account".into(),
            subject_id: account.into(),
            person_id: person.map(str::to_owned),
            capability: "manage".into(),
        }
    }

    fn root() -> VerifiedRoot {
        VerifiedRoot {
            id: "root-1".into(),
            name: "Saved".into(),
            owner: PERSON.into(),
        }
    }

    #[test]
    fn root_policy_must_be_own_account_only() {
        // Positive: self-anchored explicit, sole account entry, visible
        // bound person == the root owner.
        let view = policy(
            "explicit",
            "root-1",
            "root-1",
            vec![account_entry(ACCOUNT, Some(PERSON))],
        );
        assert_eq!(verify_own_root(&view, ACCOUNT).unwrap(), PERSON);
        // Absent bound person fails closed.
        let view = policy(
            "explicit",
            "root-1",
            "root-1",
            vec![account_entry(ACCOUNT, None)],
        );
        assert!(verify_own_root(&view, ACCOUNT).is_err());
        // Inherited root refuses.
        let view = policy(
            "inherit",
            "parent",
            "root-1",
            vec![account_entry(ACCOUNT, Some(PERSON))],
        );
        assert!(verify_own_root(&view, ACCOUNT).is_err());
        // A broadened policy (members, or a second entry) refuses.
        let view = policy(
            "explicit",
            "root-1",
            "root-1",
            vec![
                account_entry(ACCOUNT, Some(PERSON)),
                PolicyEntry {
                    subject_kind: "members".into(),
                    subject_id: String::new(),
                    person_id: None,
                    capability: "view".into(),
                },
            ],
        );
        assert!(verify_own_root(&view, ACCOUNT).is_err());
        // Another account's entry refuses.
        let view = policy(
            "explicit",
            "root-1",
            "root-1",
            vec![account_entry("acct-b", Some("person-b"))],
        );
        assert!(verify_own_root(&view, ACCOUNT).is_err());
        // Administration must be authorised.
        let mut view = policy(
            "explicit",
            "root-1",
            "root-1",
            vec![account_entry(ACCOUNT, Some(PERSON))],
        );
        view.policy_administration_authorized = false;
        assert!(verify_own_root(&view, ACCOUNT).is_err());
    }

    #[test]
    fn folder_policy_new_versus_existing() {
        let root = root();
        // New identity: inherits exactly the root.
        let new_folder = policy("inherit", "root-1", "folder-1", vec![]);
        assert!(verify_folder_policy(&new_folder, &root, true).is_ok());
        // Existing shared folder under a channel anchor is accepted.
        let shared = policy("inherit", "channel-9", "folder-1", vec![]);
        assert!(verify_folder_policy(&shared, &root, false).is_ok());
        // But a new folder must not be anchored elsewhere.
        assert!(verify_folder_policy(&shared, &root, true).is_err());
        // A folder carrying its own policy refuses.
        let own = policy("explicit", "folder-1", "folder-1", vec![]);
        assert!(verify_folder_policy(&own, &root, false).is_err());
        // Administration not authorised refuses.
        let mut view = policy("inherit", "channel-9", "folder-1", vec![]);
        view.policy_administration_authorized = false;
        assert!(verify_folder_policy(&view, &root, false).is_err());
        // Owner must be the canonical person: no owner, or another person.
        let mut row = RowIdentity {
            id: "folder-1".into(),
            owner_id: Some(PERSON.into()),
            home_id: None,
        };
        assert!(require_owner(&row, &root).is_ok());
        row.owner_id = Some("person-b".into());
        assert!(require_owner(&row, &root).is_err());
        row.owner_id = None;
        assert!(require_owner(&row, &root).is_err());
    }

    fn step(pos: u64, body: &str, parent: &str, owner: &str) -> RemoteStep {
        let fp = sample_fp(body);
        RemoteStep {
            record_id: format!("r{pos}"),
            owner_id: owner.into(),
            home_id: "folder-1".into(),
            pos,
            body: body.into(),
            cid: chain_next(parent, &fp).unwrap(),
            parent_cid: parent.into(),
            fp,
            step_kind: "agent".into(),
            part_index: 0,
            base_len: None,
            branch_no: None,
        }
    }

    /// Engine-faithful history: create by the actor, one facet burst per
    /// immutable facet, then caller-supplied later events.
    fn birth(actor: &str, found: &RemoteStep, facets: &[(&str, String)]) -> Vec<RemoteEvent> {
        let mut history = vec![RemoteEvent {
            etype: "record.created".into(),
            payload: json!({
                "type": "Document", "kind": "agent-session-step",
                "name": "step", "body": found.body, "home_id": found.home_id,
                "reason": "Saved agent session step",
            }),
            actor: Some(actor.into()),
        }];
        for (key, value) in facets {
            history.push(RemoteEvent {
                etype: "facet.set".into(),
                payload: json!({"key": key, "value": value}),
                actor: Some(actor.into()),
            });
        }
        history
    }

    fn standard_facets(found: &RemoteStep) -> Vec<(&'static str, String)> {
        vec![
            ("native.session.pos", found.pos.to_string()),
            ("native.session.cid", found.cid.clone()),
            ("native.session.parent_cid", found.parent_cid.clone()),
            ("native.session.fp", found.fp.clone()),
            ("native.session.step_kind", found.step_kind.clone()),
            ("native.session.part_index", "0".into()),
            ("native.session.occurred_at", "2026-10-17T00:00:00Z".into()),
        ]
    }

    fn expectation(pos: u64, head: &str) -> AdmissionExpectation {
        AdmissionExpectation {
            pos,
            owner_id: PERSON.into(),
            actor: ACCOUNT.into(),
            home_id: "folder-1".into(),
            head_cid: head.into(),
        }
    }

    #[test]
    fn marker_branch_requires_immutable_create_evidence() {
        let root = chain_root("server", "agent").unwrap();
        let mut marker = step(1, "Rewound to step 0.", &root, PERSON);
        marker.step_kind = "rewound".into();
        marker.base_len = Some(0);
        marker.branch_no = Some(3);
        marker.fp = fingerprint_step(StepKind::Rewound, 0, &marker.body);
        marker.cid = chain_next(&root, &marker.fp).unwrap();
        let mut facets = standard_facets(&marker);
        facets.push(("native.session.base_len", "0".into()));
        facets.push(("native.session.branch_no", "3".into()));
        let valid = birth(ACCOUNT, &marker, &facets);
        assert_eq!(
            validate_admission(&expectation(1, &root), &[marker.clone()], Some(&valid)),
            AdmissionVerdict::Adopt
        );
        let mut edited = valid.clone();
        edited.push(RemoteEvent {
            etype: "facet.set".into(),
            payload: json!({"key":"native.session.branch_no","value":4}),
            actor: Some(ACCOUNT.into()),
        });
        edited.push(RemoteEvent {
            etype: "facet.set".into(),
            payload: json!({"key":"native.session.branch_no","value":3}),
            actor: Some(ACCOUNT.into()),
        });
        assert!(matches!(
            validate_admission(&expectation(1, &root), &[marker.clone()], Some(&edited)),
            AdmissionVerdict::Refuse(_)
        ));
        let without_branch: Vec<_> = valid
            .into_iter()
            .filter(|event| event.payload["key"] != "native.session.branch_no")
            .collect();
        assert!(matches!(
            validate_admission(&expectation(1, &root), &[marker], Some(&without_branch)),
            AdmissionVerdict::Refuse(_)
        ));
    }

    fn source(bodies: &[&str]) -> Vec<ProjectedStep> {
        bodies
            .iter()
            .enumerate()
            .map(|(i, body)| ProjectedStep {
                kind: StepKind::Agent,
                body: (*body).into(),
                part_index: 0,
                fingerprint: sample_fp(body),
                seq_start: i as u64 + 1,
                seq_end: i as u64 + 1,
            })
            .collect()
    }

    #[test]
    fn lease_eligibility_and_timing_boundaries_are_conservative() {
        let mut claim = LeaseClaim {
            generation: 7,
            writer: "srv-b/other/boot".into(),
            last_seen_at: "2026-10-17T00:00:00Z".into(),
        };
        let start = chrono::DateTime::parse_from_rfc3339(&claim.last_seen_at)
            .unwrap()
            .timestamp();
        assert!(!takeover_eligible(&claim, SERVER, "inst-1", start + 720));
        assert!(takeover_eligible(&claim, SERVER, "inst-1", start + 721));
        assert!(!takeover_eligible(&claim, SERVER, "inst-1", start - 1));
        claim.writer = "srv-a/inst-1/old-boot".into();
        assert!(takeover_eligible(&claim, SERVER, "inst-1", start));
        claim.generation = u64::MAX;
        assert!(lease_takeover_arguments(
            "record",
            &claim,
            "srv-a/inst-1/new",
            "2026-10-17T00:01:00Z"
        )
        .is_err());
        assert!(!heartbeat_due(1000, 300999, true));
        assert!(heartbeat_due(1000, 301000, true));
        assert!(!heartbeat_due(1000, 301000, false));
        assert!(!heartbeat_due(1000, 0, true));
        assert!(!confirmed_pos_due(1000, 30999, true));
        assert!(confirmed_pos_due(1000, 31000, true));
        assert!(!confirmed_pos_due(1000, 31000, false));
    }

    fn snapshot(branch: Option<u64>, cut: Option<u64>) -> SourceSnapshot {
        SourceSnapshot {
            epoch: "epoch".into(),
            branch,
            kept_seq_end: cut,
        }
    }

    #[test]
    fn alignment_compares_positions_and_labels_divergence() {
        let t = source(&["A", "B", "C", "X", "A", "B", "C", "Y"]);
        let e: Vec<_> = source(&["A", "B", "C", "Y"])
            .into_iter()
            .map(|s| s.fingerprint)
            .collect();
        let plan = plan_alignment(&e, &t, Some(0), &snapshot(Some(0), None), false, false).unwrap();
        assert_eq!(plan.base_len, 3, "never jump to the matching suffix");
        assert_eq!(plan.marker, Some(MarkerKind::Resync));
        let plan =
            plan_alignment(&e[..3], &t, Some(0), &snapshot(Some(0), None), false, false).unwrap();
        assert_eq!(plan.marker, None);
        assert_eq!(plan.base_len, 3);
    }

    #[test]
    fn alignment_known_rewind_resaves_identical_regeneration() {
        let t = source(&["A", "B", "C"]);
        let e: Vec<_> = t.iter().map(|s| s.fingerprint.clone()).collect();
        let plan =
            plan_alignment(&e, &t, Some(0), &snapshot(Some(1), Some(1)), false, false).unwrap();
        assert_eq!(plan.marker, Some(MarkerKind::Rewound));
        assert_eq!(plan.base_len, 1);
        assert!(!plan.continuity_assumed);
        // Even equality at the full kept prefix cannot erase an observed rewind.
        let plan =
            plan_alignment(&e, &t, Some(0), &snapshot(Some(1), Some(3)), false, false).unwrap();
        assert_eq!(plan.marker, Some(MarkerKind::Rewound));
        assert_eq!(plan.base_len, 3);
    }

    #[test]
    fn alignment_excludes_every_part_of_a_straddling_group() {
        let mut t = source(&["A", "group part 1", "group part 2"]);
        t[1].seq_end = 5;
        t[2].seq_start = 2;
        t[2].seq_end = 5;
        t[2].part_index = 1;
        t[2].fingerprint = fingerprint_step(t[2].kind, 1, &t[2].body);
        let e: Vec<_> = t.iter().map(|s| s.fingerprint.clone()).collect();
        let plan =
            plan_alignment(&e, &t, Some(2), &snapshot(Some(3), Some(3)), false, false).unwrap();
        assert_eq!(plan.base_len, 1);
        assert_eq!(plan.marker, Some(MarkerKind::Rewound));
    }

    #[test]
    fn alignment_missed_rewinds_compare_the_final_kept_prefix() {
        let e: Vec<_> = source(&["1", "2", "3", "4"])
            .into_iter()
            .map(|s| s.fingerprint)
            .collect();
        let t = source(&["1", "2", "3-prime", "4-prime"]);
        let plan =
            plan_alignment(&e, &t, Some(0), &snapshot(Some(2), Some(3)), false, false).unwrap();
        assert_eq!(plan.base_len, 2);
        assert!(plan.continuity_assumed);
        let identical = source(&["1", "2", "3", "4"]);
        assert!(
            plan_alignment(
                &e,
                &identical,
                Some(0),
                &snapshot(Some(2), Some(4)),
                false,
                false
            )
            .unwrap()
            .continuity_assumed
        );
        assert!(
            plan_alignment(&e, &identical, None, &snapshot(None, None), false, true)
                .unwrap()
                .continuity_assumed
        );
        assert_eq!(
            plan_alignment(&e, &identical, None, &snapshot(None, None), true, true)
                .unwrap()
                .marker,
            Some(MarkerKind::Rewound)
        );
    }

    #[test]
    fn source_snapshot_changes_and_missing_cuts_refuse_alignment() {
        let first = snapshot(Some(1), Some(2));
        assert!(first.check_page(&snapshot(Some(2), Some(2))).is_err());
        assert!(first.check_page(&snapshot(Some(1), Some(3))).is_err());
        let mut other = first.clone();
        other.epoch = "rebuilt".into();
        assert!(first.check_page(&other).is_err());
        assert!(plan_alignment(&[], &[], Some(2), &first, false, false).is_err());
        assert!(plan_alignment(&[], &[], Some(0), &snapshot(Some(1), None), false, false).is_err());
    }

    #[test]
    fn verified_chain_rebuilds_only_after_full_admission_and_marker_validation() {
        let root = chain_root(SERVER, AGENT).unwrap();
        let a = step(1, "A", &root, PERSON);
        let b = step(2, "B", &a.cid, PERSON);
        let mut marker = step(3, "Rewound to step 1.", &b.cid, PERSON);
        marker.step_kind = "rewound".into();
        marker.base_len = Some(1);
        marker.fp = fingerprint_step(StepKind::Rewound, 0, &marker.body);
        marker.cid = chain_next(&b.cid, &marker.fp).unwrap();
        let c = step(4, "C", &marker.cid, PERSON);
        let pair = |s: RemoteStep| {
            let mut facets = standard_facets(&s);
            if let Some(n) = s.base_len {
                facets.push(("native.session.base_len", n.to_string()));
            }
            let history = birth(ACCOUNT, &s, &facets);
            (s, history)
        };
        let chain = vec![pair(a.clone()), pair(b), pair(marker), pair(c.clone())];
        let verify = |chain: &[(RemoteStep, Vec<RemoteEvent>)]| {
            verify_hosted_chain(SERVER, AGENT, PERSON, ACCOUNT, "folder-1", chain)
        };
        let rebuilt = verify(&chain).unwrap();
        assert_eq!(rebuilt.e, vec![a.fp, c.fp]);
        assert_eq!(rebuilt.head_pos, Some(4));
        assert!(verify(&chain[1..]).is_err(), "must begin at the true root");
        let mut bad = chain.clone();
        bad[1].1.push(RemoteEvent {
            etype: "body.set".into(),
            actor: Some(ACCOUNT.into()),
            payload: json!({"body":"edited"}),
        });
        assert!(
            verify(&bad).is_err(),
            "content equality is not history proof"
        );
        let mut bad = chain.clone();
        bad[2].0.base_len = Some(9);
        bad[2] = pair(bad[2].0.clone());
        assert!(verify(&bad).is_err(), "marker cannot extend E");
        let mut bad = chain.clone();
        bad[1].0.owner_id = "foreign-person".into();
        assert!(verify(&bad).is_err());
        assert!(verify(&[chain[0].clone(), chain[0].clone()]).is_err());
    }

    #[test]
    fn admission_truth_table() {
        let root = chain_root(SERVER, AGENT).unwrap();
        let found = step(1, "hello", &root, PERSON);
        let history = birth(ACCOUNT, &found, &standard_facets(&found));
        let expected = expectation(1, &root);
        // Baseline adopts.
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Adopt
        );
        // Several records at a position refuse.
        assert_eq!(
            validate_admission(&expected, &[found.clone(), found.clone()], Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::SeveralFound)
        );
        // Foreign owner.
        let mut foreign = found.clone();
        foreign.owner_id = "person-b".into();
        assert_eq!(
            validate_admission(&expected, &[foreign], Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::NotOwnerOwned)
        );
        // Wrong folder.
        let mut misplaced = found.clone();
        misplaced.home_id = "folder-x".into();
        assert_eq!(
            validate_admission(&expected, &[misplaced], Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::Misplaced)
        );
        // Parent must extend the verified head.
        let mut forked = found.clone();
        forked.parent_cid = "f".repeat(64);
        assert_eq!(
            validate_admission(&expected, &[forked], Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::ParentMismatch)
        );
        // Retagged fp fails recomputation.
        let mut retagged = found.clone();
        retagged.fp = sample_fp("other");
        assert_eq!(
            validate_admission(&expected, &[retagged], Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::ContentInconsistent)
        );
        // Missing or empty history refuses.
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), None),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryUnreadable)
        );
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&[])),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryUnreadable)
        );
        // Missing create evidence refuses.
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history[1..])),
            AdmissionVerdict::Refuse(ChainErrorKind::CreateMismatch)
        );
    }

    #[test]
    fn history_trajectory_refuses_edits_even_reverted() {
        let root = chain_root(SERVER, AGENT).unwrap();
        let found = step(1, "hello", &root, PERSON);
        let expected = expectation(1, &root);
        // An immutable facet edited and reverted still refuses: the
        // deviation is the violation, not the final value.
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        history.push(RemoteEvent {
            etype: "facet.set".into(),
            payload: json!({"key": "native.session.pos", "value": 99}),
            actor: Some(ACCOUNT.into()),
        });
        history.push(RemoteEvent {
            etype: "facet.set".into(),
            payload: json!({"key": "native.session.pos", "value": 1}),
            actor: Some(ACCOUNT.into()),
        });
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryTamper)
        );
        // Same-value re-sets are creation bursts and pass.
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        history.push(RemoteEvent {
            etype: "facet.set".into(),
            payload: json!({"key": "native.session.pos", "value": 1}),
            actor: Some(ACCOUNT.into()),
        });
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Adopt
        );
        // An arbitrary extra facet refuses.
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        history.push(RemoteEvent {
            etype: "facet.set".into(),
            payload: json!({"key": "native.session.extra", "value": "x"}),
            actor: Some(ACCOUNT.into()),
        });
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryTamper)
        );
        // Unsetting an immutable facet refuses.
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        history.push(RemoteEvent {
            etype: "facet.unset".into(),
            payload: json!({"key": "native.session.pos"}),
            actor: Some(ACCOUNT.into()),
        });
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryTamper)
        );
        // A body edit event is not an allowed side effect.
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        history.push(RemoteEvent {
            etype: "record.updated".into(),
            payload: json!({"body": "edited"}),
            actor: Some(ACCOUNT.into()),
        });
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryTamper)
        );
        // Non-owner side effects refuse; owner side effects pass.
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        history.push(RemoteEvent {
            etype: "link.added".into(),
            payload: json!({"source_id": "r1", "target_id": "m", "relationship": "relates_to"}),
            actor: Some("acct-evil".into()),
        });
        assert_eq!(
            validate_admission(&expected, std::slice::from_ref(&found), Some(&history)),
            AdmissionVerdict::Refuse(ChainErrorKind::HistoryTamper)
        );
        let mut history = birth(ACCOUNT, &found, &standard_facets(&found));
        for (etype, payload) in [
            ("receipt.committed.v1", json!({})),
            ("facet.set", json!({"key": QUOTE_LINK_FACET, "value": "v"})),
            (
                "link.added",
                json!({"source_id": "r1", "target_id": "m", "relationship": "relates_to"}),
            ),
        ] {
            history.push(RemoteEvent {
                etype: etype.into(),
                payload,
                actor: Some(ACCOUNT.into()),
            });
        }
        assert_eq!(
            validate_admission(&expected, &[found], Some(&history)),
            AdmissionVerdict::Adopt
        );
    }

    // -- Real transport → real executor → SQLite --------------------------
    //
    // The rig below is the production path end to end: GateSink sends
    // through the node's WriteGate to a fake HTTP endpoint that forwards the
    // exact request body to the real `ExecutorPrototypeStdioServer`, which
    // dispatches against a real SQLite database. Faults are injected only at
    // the HTTP boundary (where a real network fault lives); no test decides
    // an outcome by hand.
    #[cfg(feature = "mcp-executor-prototype")]
    mod flow {
        use super::*;
        use crate::mcp::executor_prototype::ExecutorPrototypeStdioServer;
        use crate::mcp::registry::{Caller as McpCaller, ToolRegistry};
        use axum::{
            body::Bytes, extract::State, http::StatusCode, response::IntoResponse, routing::post,
            Router,
        };
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc as StdArc;
        use std::time::Duration;
        use tokio::net::TcpListener;

        /// One executor envelope, the only dispatch form the executor
        /// surface serves.
        fn call(executor: &str, operation: &str, arguments: Value) -> Value {
            json!({
                "jsonrpc":"2.0","id":900,"method":"tools/call",
                "params":{"name":executor,"arguments":{
                    "operation":operation,
                    "arguments":arguments,"format":"json",
                }},
            })
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Fault {
            Pass,
            Auth,
            Gateway,
            /// Forward the request (so it applies), then report a lost
            /// reply: the true uncertain-write window.
            LoseReply,
            LoseStateReply,
            /// Refuse before dispatch, as a read-only deployment would.
            ReadOnly,
            RejectStep,
            LoseQuoteReply,
        }

        struct Hosted {
            db: crate::Db,
            server: ExecutorPrototypeStdioServer,
            fault: std::sync::Mutex<Fault>,
            received: std::sync::Mutex<Vec<Value>>,
            pause_state_reply: std::sync::atomic::AtomicBool,
            state_committed: tokio::sync::Notify,
            release_state_reply: tokio::sync::Notify,
        }

        async fn handler(
            State(hosted): State<StdArc<Hosted>>,
            body: Bytes,
        ) -> axum::response::Response {
            let request: Value = match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
            };
            hosted.received.lock().unwrap().push(request.clone());
            let is_state = request
                .pointer("/params/arguments/operation")
                .and_then(Value::as_str)
                == Some("update_record")
                && request
                    .pointer("/params/arguments/arguments/idempotency_key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| {
                        ["nss3:state:", "nss3:transition:", "nss3:retire:"]
                            .iter()
                            .any(|prefix| key.starts_with(prefix))
                    });
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let fault = *hosted.fault.lock().unwrap();
            if fault == Fault::RejectStep
                && request
                    .pointer("/params/arguments/arguments/kind")
                    .and_then(Value::as_str)
                    == Some(STEP_KIND)
            {
                return axum::Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"fixture rejects this step"}})).into_response();
            }
            match fault {
                Fault::Auth => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        axum::Json(json!({"error":"unauthorized","outcome":"refused"})),
                    )
                        .into_response()
                }
                Fault::Gateway => {
                    return (StatusCode::BAD_GATEWAY, "<html>bad gateway</html>").into_response()
                }
                Fault::ReadOnly => {
                    return axum::Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {"isError": true,
                            "structuredContent": {"error_code": "DEPLOYMENT_READ_ONLY", "applied": false}},
                    }))
                    .into_response()
                }
                Fault::Pass | Fault::LoseReply | Fault::LoseStateReply | Fault::RejectStep | Fault::LoseQuoteReply => {}
            }
            let is_quote = request
                .pointer("/params/arguments/operation")
                .and_then(Value::as_str)
                == Some("manage_links.add");
            match hosted.server.handle_message(request).await {
                Some(reply) => {
                    if is_state
                        && hosted
                            .pause_state_reply
                            .swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        hosted.state_committed.notify_one();
                        hosted.release_state_reply.notified().await;
                    }
                    if fault == Fault::LoseReply
                        || (fault == Fault::LoseStateReply && is_state)
                        || (fault == Fault::LoseQuoteReply && is_quote)
                    {
                        // The write applied; the reply never arrives.
                        return (StatusCode::BAD_GATEWAY, "<html>lost</html>").into_response();
                    }
                    axum::Json(reply).into_response()
                }
                None => StatusCode::ACCEPTED.into_response(),
            }
        }

        struct Rig {
            _temp: tempfile::TempDir,
            store: SessionStore,
            sink: GateSink,
            hosted: StdArc<Hosted>,
            socket_dir: std::path::PathBuf,
            registry: StdArc<ToolRegistry>,
        }

        impl Rig {
            async fn new() -> Self {
                let temp = tempfile::tempdir().unwrap();
                let db = crate::create_database(":memory:").await.unwrap();
                let mut registry = ToolRegistry::new();
                crate::mcp::register_builtin_tools(&mut registry).unwrap();
                crate::mcp::register_surface_tools(&mut registry).unwrap();
                // Source proposal admitted only in this disposable database,
                // using ordinary owner schema operations, never raw SQL.
                let proposal: Value =
                    serde_json::from_str(include_str!("saved-session-lifecycle-proposal.json"))
                        .unwrap();
                let kind = &proposal["kind"];
                let proposed=registry.call(db.clone(),McpCaller::local(),"manage_vocabularies",json!({"action":"propose_value","vocabulary":kind["vocabulary"],"value":kind["value"],"gloss":kind["gloss"],"metadata":kind["metadata"]})).await.unwrap();
                registry
                    .call(
                        db.clone(),
                        McpCaller::local(),
                        "manage_vocabularies",
                        json!({"action":"promote_value","value_id":proposed["value_id"]}),
                    )
                    .await
                    .unwrap();
                registry
                    .call(
                        db.clone(),
                        McpCaller::local(),
                        "manage_vocabularies",
                        json!({"action":"create_vocabulary","name":proposal["vocabulary"]["name"]}),
                    )
                    .await
                    .unwrap();
                for value in proposal["vocabulary"]["values"].as_array().unwrap() {
                    let proposed=registry.call(db.clone(),McpCaller::local(),"manage_vocabularies",json!({"action":"propose_value","vocabulary":proposal["vocabulary"]["name"],"value":value["value"],"gloss":value["gloss"],"terminality":value["terminality"]})).await.unwrap();
                    registry
                        .call(
                            db.clone(),
                            McpCaller::local(),
                            "manage_vocabularies",
                            json!({"action":"promote_value","value_id":proposed["value_id"]}),
                        )
                        .await
                        .unwrap();
                }
                registry
                    .call(
                        db.clone(),
                        McpCaller::local(),
                        "manage_schema_config",
                        json!({"action":"write","data":proposal["shape_patch"]}),
                    )
                    .await
                    .unwrap();
                let registry = StdArc::new(registry);
                let caller = McpCaller::authenticated(ACCOUNT);
                let server =
                    ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller, None)
                        .await
                        .unwrap();
                // Portable account binding: the engine derives the person
                // from this canonical row, exactly as on hosted. Seeded
                // directly because creating it through the tool would need
                // the binding this row establishes.
                let person = uuid::Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence)
                     VALUES (?,'Entity','person','Owner A',?,?,'enduring')",
                )
                .bind(&person)
                .bind(crate::schema::UNFILED_RECORD_ID)
                .bind(crate::schema::ROOT_RECORD_ID)
                .execute(db.write_pool())
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                     VALUES (?, 'account', ?, 1)",
                )
                .bind(&person)
                .bind(ACCOUNT)
                .execute(db.write_pool())
                .await
                .unwrap();
                let hosted = StdArc::new(Hosted {
                    db,
                    server,
                    fault: std::sync::Mutex::new(Fault::Pass),
                    received: std::sync::Mutex::new(Vec::new()),
                    pause_state_reply: std::sync::atomic::AtomicBool::new(false),
                    state_committed: tokio::sync::Notify::new(),
                    release_state_reply: tokio::sync::Notify::new(),
                });
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let app_state = hosted.clone();
                tokio::spawn(async move {
                    let app = Router::new()
                        .route("/mcp/test-workspace", post(handler))
                        .with_state(app_state);
                    let _ = axum::serve(listener, app).await;
                });
                let token = temp.path().join("token");
                std::fs::write(&token, "test-token\n").unwrap();
                std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
                let socket_dir = temp.path().join("socket");
                std::fs::create_dir(&socket_dir).unwrap();
                std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                let config = crate::node::NodeConfig {
                    markdown_folder: None,
                    hosted_base_url: format!("http://{address}"),
                    home_id: "test-home".into(),
                    db_id: "test-workspace".into(),
                    credential_file: token,
                    socket_directory: socket_dir.clone(),
                    oauth_auth_file: None,
                    standby_config: None,
                    account_id: None,
                    refresh_config: None,
                    disk_floor_bytes: None,
                };
                let gate = StdArc::new(
                    crate::node::gate::WriteGate::open(&socket_dir, Default::default()).unwrap(),
                );
                let upstream = StdArc::new(
                    crate::node::Upstream::new(config, Duration::from_secs(30)).unwrap(),
                );
                let store = open_store(temp.path());
                Self {
                    _temp: temp,
                    store,
                    sink: GateSink::new(upstream, gate),
                    hosted,
                    socket_dir,
                    registry,
                }
            }

            fn writer(&self) -> Writer<'_, GateSink> {
                Writer::new(&self.store, &self.sink, SERVER, ACCOUNT, DB, "inst-1")
            }

            fn fault(&self, fault: Fault) {
                *self.hosted.fault.lock().unwrap() = fault;
            }

            fn reset(&self) {
                self.fault(Fault::Pass);
            }

            async fn ensure(&self, title: &str, boot: &str, now: &str) -> EnsureOutcome {
                self.writer()
                    .ensure_session(
                        AGENT,
                        SERVER,
                        "Saved sessions — owner",
                        title,
                        "scaleway",
                        "claude",
                        boot,
                        now,
                    )
                    .await
                    .unwrap()
            }

            fn journal_entries(&self) -> Vec<Value> {
                let dir = self.socket_dir.join("journal");
                let mut out = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) != Some("json") {
                            continue;
                        }
                        if let Ok(bytes) = std::fs::read(&path) {
                            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                                out.push(value);
                            }
                        }
                    }
                }
                out
            }
        }

        fn freeze_at(
            store: &SessionStore,
            folder: &str,
            pos: u64,
            parent: &str,
            body: &str,
        ) -> FrozenStepRequest {
            FrozenStepRequest::freeze(
                store.binding(),
                AGENT,
                folder,
                "step",
                body,
                "agent",
                0,
                None,
                parent,
                &sample_fp(body),
                pos,
                "2026-10-17T00:00:00Z",
            )
            .unwrap()
        }

        #[tokio::test]
        async fn missing_schema_refuses_before_identity_or_lease_writes() {
            let rig = Rig::new().await;
            let db = rig.hosted.db.clone();
            let kind = rig
                .registry
                .call(
                    db.clone(),
                    McpCaller::local(),
                    "preview_record_shape",
                    json!({"type":"Document","kind":"agent-session"}),
                )
                .await
                .unwrap();
            let value_id = &kind["selection"]["kind_resolution"]["canonical_value_id"];
            rig.registry
                .call(
                    db.clone(),
                    McpCaller::local(),
                    "manage_vocabularies",
                    json!({"action":"deprecate_value","value_id":value_id}),
                )
                .await
                .unwrap();
            let error = rig
                .writer()
                .ensure_session(
                    AGENT,
                    SERVER,
                    "Saved sessions",
                    "fixture",
                    "host",
                    "claude",
                    "boot-1",
                    "2026-10-18T00:00:00Z",
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                Error::engine(SCHEMA_REQUIRED).to_string()
            );
            rig.registry
                .call(
                    db.clone(),
                    McpCaller::local(),
                    "manage_vocabularies",
                    json!({"action":"promote_value","value_id":value_id}),
                )
                .await
                .unwrap();
            let rows = rig
                .registry
                .call(
                    db.clone(),
                    McpCaller::local(),
                    "manage_schema_config",
                    json!({"action":"read","layer":"user"}),
                )
                .await
                .unwrap();
            let row = &rows["rows"][0]["id"];
            rig.registry
                .call(
                    db.clone(),
                    McpCaller::local(),
                    "manage_schema_config",
                    json!({"action":"write","id":row,"data":{"shapes":{}}}),
                )
                .await
                .unwrap();
            let error = rig
                .writer()
                .ensure_session(
                    AGENT,
                    SERVER,
                    "Saved sessions",
                    "fixture",
                    "host",
                    "claude",
                    "boot-1",
                    "2026-10-18T00:00:00Z",
                )
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                Error::engine(SCHEMA_REQUIRED).to_string()
            );
            let cp = rig.store.load_checkpoint(AGENT).unwrap();
            assert!(
                cp.root_id.is_none() && cp.folder_id.is_none() && cp.session_record_id.is_none()
            );
            assert!(!cp.lease_stopped);
            {
                let received = rig.hosted.received.lock().unwrap();
                assert!(
                    received.iter().any(|frame| {
                        frame.pointer("/params/name").and_then(Value::as_str) == Some("schema_read")
                            && frame
                                .pointer("/params/arguments/operation")
                                .and_then(Value::as_str)
                                == Some("preview_record_shape")
                    }),
                    "readiness must consult hosted schema"
                );
                // WriteGate classifies each previously unseen operation by
                // reading this exact catalogue row before forwarding it. A
                // cold cache therefore includes SQL reads as well as the
                // readiness calls. Admit only these two exact read probes,
                // never arbitrary SQL or an identity/lease mutation.
                let readiness_only = |frame: &Value| {
                    let executor = frame.pointer("/params/name").and_then(Value::as_str);
                    let operation = frame
                        .pointer("/params/arguments/operation")
                        .and_then(Value::as_str);
                    (executor == Some("schema_read")
                        && matches!(operation, Some("preview_record_shape" | "manage_vocabularies.list_values")))
                        || (executor == Some("sql_read")
                            && operation == Some("query_sql")
                            && frame.get("id").and_then(Value::as_str) == Some("node-access")
                            && matches!(frame.pointer("/params/arguments/arguments/sql").and_then(Value::as_str),
                                Some("SELECT access, contract_digest FROM catalog_operations WHERE executor = 'schema_read' AND operation = 'preview_record_shape'"
                                    | "SELECT access, contract_digest FROM catalog_operations WHERE executor = 'schema_read' AND operation = 'manage_vocabularies.list_values'")))
                };
                assert!(
                    received.iter().all(readiness_only),
                    "unadmitted schema permits only read-only readiness probes: {received:#?}"
                );
            }
            assert!(
                rig.journal_entries().is_empty(),
                "schema refusal must not journal a write"
            );
            // An existing compatible type-level axis needs no replacement or
            // saver-specific axis name. The inherited declaration is enough.
            let proposal: Value =
                serde_json::from_str(include_str!("saved-session-lifecycle-proposal.json"))
                    .unwrap();
            let mut lifecycle = proposal["shape_patch"]["shapes"]["Document:agent-session"]
                ["facets"]["lifecycle"]
                .clone();
            lifecycle["axis"] = json!({"key":"document_state","label":"Document state"});
            rig.registry.call(db.clone(),McpCaller::local(),"manage_schema_config",json!({"action":"write","id":row,"data":{"shapes":{"Document":{"facets":{"lifecycle":lifecycle}}}}})).await.unwrap();
            rig.writer()
                .ensure_session(
                    AGENT,
                    SERVER,
                    "Saved sessions",
                    "fixture",
                    "host",
                    "claude",
                    "boot-1",
                    "2026-10-18T00:00:00Z",
                )
                .await
                .unwrap();
            assert!(rig
                .store
                .load_checkpoint(AGENT)
                .unwrap()
                .session_record_id
                .is_some());
        }

        #[tokio::test]
        async fn quote_recovery_reassembles_parts_and_survives_lost_reply_and_checkpoint_loss() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root = rig.store.load_checkpoint(AGENT).unwrap().root_id.unwrap();
            // Link attribution proves readable endpoints, never that this
            // target supplied the words. The UI's Message check is separate.
            let target=match rig.sink.create_keyed(json!({"type":"Document","kind":"note","name":"readable quoted source","body":"a reply","home_id":root,"reason":"Fixture quoted source","idempotency_key":"fixture-quote-target"}),"fixture-quote-target".into()).await.unwrap() {
                CreateResult::Created {record_id:Some(id)}=>id,
                other=>panic!("quoted source was not created: {other:?}"),
            };
            let text =
                include_str!("../../tests/fixtures/saved-session-quotes/desktop-envelope.txt")
                    .replace("123e4567-e89b-12d3-a456-426614174000", &target);
            let body = format!("[User] {text}");
            let cut = body.find(&format!("source=\"{target}")).unwrap() + 10;
            let mut parent = chain_root(SERVER, AGENT).unwrap();
            let mut first_id = None;
            for (part, text) in [&body[..cut], &body[cut..]].into_iter().enumerate() {
                let body = format!("{text} …({}/2)", part + 1);
                let fp = crate::node::session_projection::fingerprint_step(
                    crate::node::session_projection::StepKind::User,
                    part as u32,
                    &body,
                );
                let request = FrozenStepRequest::freeze(
                    rig.store.binding(),
                    AGENT,
                    &id.folder_id,
                    "user part",
                    &body,
                    "user",
                    part as u32,
                    None,
                    &parent,
                    &fp,
                    part as u64 + 1,
                    "2026-10-17T00:00:00Z",
                )
                .unwrap();
                rig.store.freeze_spool(&request, AGENT).unwrap();
                assert_eq!(
                    rig.writer()
                        .send_next(AGENT, SERVER, &cursor())
                        .await
                        .unwrap(),
                    SendAction::Advanced {
                        pos: part as u64 + 1
                    }
                );
                parent = request.facets.cid;
                if part == 0 {
                    first_id = Some(
                        rig.sink.query_steps(&id.folder_id, 0).await.unwrap().steps[0]
                            .record_id
                            .clone(),
                    );
                    rig.writer()
                        .claim_state_lease(
                            AGENT,
                            SERVER,
                            "boot-1",
                            &chrono::Utc::now().to_rfc3339(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        rig.writer()
                            .recover_quote_links(AGENT, SERVER, "boot-1")
                            .await
                            .unwrap(),
                        StateAction::Written
                    );
                    assert!(
                        rig.store
                            .load_checkpoint(AGENT)
                            .unwrap()
                            .quote_scan
                            .is_none(),
                        "incomplete split must remain unscanned"
                    );
                }
            }
            assert_eq!(rig.writer().quote_link_plan(AGENT).await.unwrap().len(), 2);
            rig.fault(Fault::LoseQuoteReply);
            assert_eq!(
                rig.writer()
                    .recover_quote_links(AGENT, SERVER, "boot-1")
                    .await
                    .unwrap(),
                StateAction::RetryLater
            );
            assert!(rig
                .store
                .load_checkpoint(AGENT)
                .unwrap()
                .quote_pending
                .is_some());
            // Both endpoints are Documents: relates_to is relationship-owned,
            // so it emits relationship events, not a content link.added event.
            // Remember the committed log before reopening, so a duplicate
            // assertion cannot hide behind projection convergence.
            let relationship_events: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
                    .fetch_one(rig.hosted.db.write_pool())
                    .await
                    .unwrap();
            assert!(relationship_events > 0);
            rig.fault(Fault::Pass);
            let reopened = open_store(rig._temp.path());
            let writer = Writer::new(&reopened, &rig.sink, SERVER, ACCOUNT, DB, "inst-1");
            assert_eq!(
                writer
                    .recover_quote_links(AGENT, SERVER, "boot-1")
                    .await
                    .unwrap(),
                StateAction::Written
            );
            assert!(reopened
                .load_checkpoint(AGENT)
                .unwrap()
                .quote_pending
                .is_none());
            let rows = rig.sink.query_steps(&id.folder_id, 0).await.unwrap().steps;
            let links = rig
                .registry
                .call(
                    rig.hosted.db.clone(),
                    McpCaller::authenticated(ACCOUNT),
                    "manage_links",
                    json!({"action":"list","record_id":first_id,"limit":200}),
                )
                .await
                .unwrap();
            assert_eq!(
                links["links_out"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(
                        |link| link["target_id"] == target && link["relationship"] == "relates_to"
                    )
                    .count(),
                1,
                "lost reply replays the original link"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationship_events")
                    .fetch_one(rig.hosted.db.write_pool())
                    .await
                    .unwrap(),
                relationship_events,
                "lost reply replay must not append another relationship assertion"
            );
            assert!(rig
                .sink
                .step_history(&rows[1].record_id)
                .await
                .unwrap()
                .iter()
                .any(|event| event.etype == "facet.set"
                    && event.payload["key"] == QUOTE_LINK_FACET
                    && event.payload["value"] == "unverified"));
            // Forget every per-agent local fact. Re-enrolment finds the same
            // hosted identity; full immutable history supplies quote jobs.
            std::fs::remove_file(
                rig._temp
                    .path()
                    .join("sessions")
                    .join(format!("{AGENT}.json")),
            )
            .unwrap();
            rig.ensure("t", "boot-2", &chrono::Utc::now().to_rfc3339())
                .await;
            assert_eq!(
                rig.writer()
                    .claim_state_lease(AGENT, SERVER, "boot-2", &chrono::Utc::now().to_rfc3339())
                    .await
                    .unwrap(),
                StateAction::Held
            );
            assert_eq!(
                rig.writer()
                    .recover_quote_links(AGENT, SERVER, "boot-2")
                    .await
                    .unwrap(),
                StateAction::Written
            );
            let links = rig
                .registry
                .call(
                    rig.hosted.db.clone(),
                    McpCaller::authenticated(ACCOUNT),
                    "manage_links",
                    json!({"action":"list","record_id":first_id,"limit":200}),
                )
                .await
                .unwrap();
            assert_eq!(
                links["links_out"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(
                        |link| link["target_id"] == target && link["relationship"] == "relates_to"
                    )
                    .count(),
                1,
                "full scan after state loss keeps the stable key"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationship_events")
                    .fetch_one(rig.hosted.db.write_pool())
                    .await
                    .unwrap(),
                relationship_events,
                "checkpoint loss must replay without new relationship events"
            );
            assert_eq!(
                rig.writer().verified_chain(AGENT).await.unwrap().head_pos,
                Some(2),
                "legitimate quote side effects remain admissible"
            );
        }

        #[tokio::test]
        async fn retirement_is_scoped_fenced_and_recovers_a_lost_reply_without_old_sends() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let before = writer.read_owned_session_state(AGENT).await.unwrap();
            let foreign = Binding::new("srv-reset", "foreign", DB, None).unwrap();
            assert!(writer
                .retire_host_session(AGENT, &foreign, "boot-1", "2026-10-17T00:00:01Z")
                .await
                .is_err());
            assert!(writer
                .retire_host_session(AGENT, &test_binding(), "boot-1", "2026-10-17T00:00:01Z")
                .await
                .is_err());
            assert!(!rig.store.host_retired().unwrap());
            let cp = rig.store.load_checkpoint(AGENT).unwrap();
            let spool = freeze_at(
                &rig.store,
                cp.folder_id.as_deref().unwrap(),
                1,
                &chain_root(SERVER, AGENT).unwrap(),
                "never replay after reset",
            );
            rig.store.freeze_spool(&spool, AGENT).unwrap();
            let current = Binding::new("srv-reset", ACCOUNT, DB, None).unwrap();
            rig.fault(Fault::LoseStateReply);
            assert_eq!(
                writer
                    .retire_host_session(AGENT, &current, "boot-1", "2026-10-17T00:00:01Z")
                    .await
                    .unwrap(),
                StateAction::RetryLater
            );
            assert!(rig.store.host_retired().unwrap());
            assert!(rig.store.load_spool(AGENT).unwrap().is_none());
            let reloaded = open_store(rig._temp.path());
            assert!(reloaded.host_retired().unwrap());
            let restarted = Writer::new(&reloaded, &rig.sink, SERVER, ACCOUNT, DB, "inst-1");
            assert!(restarted
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:02Z")
                .await
                .is_err());
            rig.reset();
            assert_eq!(
                restarted
                    .retire_host_session(AGENT, &current, "boot-1", "2026-10-17T00:00:02Z")
                    .await
                    .unwrap(),
                StateAction::Settled
            );
            let after = restarted.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(after.claim.generation, before.claim.generation + 1);
            assert_eq!(after.facets["native.session.state"], "ended");
            assert!(reloaded.load_checkpoint(AGENT).unwrap().lease_stopped);
            let lifecycle: String = sqlx::query_scalar("SELECT lifecycle FROM records WHERE id=?")
                .bind(&after.identity.id)
                .fetch_one(rig.hosted.db.write_pool())
                .await
                .unwrap();
            assert_eq!(lifecycle, "closed");
            assert_eq!(
                restarted
                    .retire_host_session(AGENT, &current, "boot-1", "2026-10-17T00:00:03Z")
                    .await
                    .unwrap(),
                StateAction::NotDue
            );
        }

        #[tokio::test]
        async fn reset_retirement_never_takes_a_foreign_live_lease() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let old = writer.read_owned_session_state(AGENT).await.unwrap();
            let args = lease_takeover_arguments(
                &old.identity.id,
                &old.claim,
                "srv-a/other-instance/other-boot",
                "2026-10-17T00:00:01Z",
            )
            .unwrap();
            assert_eq!(
                rig.sink.update_state(args).await.unwrap(),
                SendClass::Committed
            );
            let current = Binding::new("srv-reset", ACCOUNT, DB, None).unwrap();
            assert_eq!(
                writer
                    .retire_host_session(AGENT, &current, "boot-1", "2026-10-17T00:00:02Z")
                    .await
                    .unwrap(),
                StateAction::Superseded
            );
            let after = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(after.claim.writer, "srv-a/other-instance/other-boot");
            assert_ne!(after.facets["native.session.state"], "ended");
            assert!(rig.store.load_checkpoint(AGENT).unwrap().lease_stopped);
        }

        #[tokio::test]
        async fn stopped_generation_fences_a_late_saving_reply_and_owner_can_resume() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let old = writer.read_owned_session_state(AGENT).await.unwrap();
            let sequence = rig
                .store
                .reserve_state_seq(AGENT, old.claim.generation, &old.claim.writer)
                .unwrap();
            let args = state_update_arguments(
                &old.identity.id,
                &old.claim,
                sequence,
                BTreeMap::from([("native.session.state".into(), json!("saving"))]),
            )
            .unwrap();
            let pending = writer
                .proposal(
                    AGENT,
                    &old.identity.id,
                    ProposalKind::State,
                    old.claim.generation,
                    &old.claim.writer,
                    args.clone(),
                )
                .unwrap();
            rig.store.freeze_proposal(&pending).unwrap();
            assert_eq!(
                writer
                    .transition_session(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:00:01Z",
                        "stopped",
                        None
                    )
                    .await
                    .unwrap(),
                StateAction::Settled
            );
            assert_eq!(
                rig.sink.update_state(args).await.unwrap(),
                SendClass::Refused
            );
            let stopped = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(stopped.facets["native.session.state"], "stopped");
            assert_eq!(stopped.claim.generation, old.claim.generation + 1);
            assert!(!rig.store.load_checkpoint(AGENT).unwrap().lease_stopped);
            assert_eq!(
                writer
                    .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:02Z")
                    .await
                    .unwrap(),
                StateAction::Held
            );
            assert_eq!(
                writer
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:00:02Z",
                        BTreeMap::from([("native.session.state".into(), json!("saving"))])
                    )
                    .await
                    .unwrap(),
                StateAction::Written
            );
            let resumed = writer.read_owned_session_state(AGENT).await.unwrap();
            let lifecycle: String = sqlx::query_scalar("SELECT lifecycle FROM records WHERE id=?")
                .bind(&resumed.identity.id)
                .fetch_one(rig.hosted.db.write_pool())
                .await
                .unwrap();
            assert_eq!(lifecycle, "open");
        }

        async fn wait_live_state(rig: &Rig, wanted: &str) -> RemoteSessionState {
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    if let Ok(state) = rig.writer().read_owned_session_state(AGENT).await {
                        if state
                            .facets
                            .get("native.session.state")
                            .is_some_and(|s| s == wanted)
                        {
                            return state;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("hosted lifecycle state must settle")
        }

        #[tokio::test]
        async fn websocket_supervisor_saves_stops_resumes_without_duplicates_and_pauses_on_disconnect(
        ) {
            use crate::node::{
                daemon_client, session_identity::SaverIdentity, session_saver,
                session_supervisor::Supervisor,
            };
            use futures::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message;
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            rig.writer()
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let store = StdArc::new(open_store(rig._temp.path()));
            let sink = StdArc::new(GateSink::new(
                rig.sink.upstream.clone(),
                rig.sink.gate.clone(),
            ));
            let supervisor = StdArc::new(Supervisor::new(
                store,
                vec![],
                sink,
                SaverIdentity {
                    instance: "inst-1".into(),
                    boot: "boot-1".into(),
                },
                1024 * 1024,
                std::time::Instant::now(),
            ));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (commands, mut command_rx) = tokio::sync::mpsc::channel::<bool>(2);
            let (statuses, mut status_rx) = tokio::sync::mpsc::channel::<u8>(2);
            let observed = StdArc::new(std::sync::Mutex::new(Vec::<Value>::new()));
            let server_observed = observed.clone();
            let first = "123e4567-e89b-12d3-a456-426614174000";
            let second = "223e4567-e89b-12d3-a456-426614174000";
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                assert!(matches!(
                    ws.next().await.unwrap().unwrap(),
                    Message::Text(_)
                ));
                ws.send(Message::Text(json!({"type":"session","message":{"type":"status","payload":{
                    "status":"server_info","protocolVersion":1,"serverId":SERVER,"hostname":"fixture","version":"fixture","permissions":{}
                }}}).to_string().into())).await.unwrap();
                let mut phase = 0u8;
                loop {
                    tokio::select! {
                        command=command_rx.recv()=>{
                            if command!=Some(true) {let _=ws.close(None).await;break;}
                            phase=2;
                            let snapshot=json!({"id":AGENT,"provider":"claude","title":"fixture","status":"idle","activeTurn":null,"pendingPermissions":[],"labels":{"native.save":format!("v1;acct={ACCOUNT};db={DB};req={second}")}});
                            ws.send(Message::Text(json!({"type":"session","message":{"type":"agent_update","payload":{"kind":"upsert","agent":snapshot}}}).to_string().into())).await.unwrap();
                        }
                        frame=ws.next()=>{
                            let Some(Ok(Message::Text(text)))=frame else {break};
                            let envelope:Value=serde_json::from_str(&text).unwrap();
                            let message=&envelope["message"];
                            server_observed.lock().unwrap().push(message.clone());
                            match message["type"].as_str().unwrap() {
                                "fetch_agents_request"=>{
                                    let entries=vec![json!({"agent":{"id":AGENT,"provider":"claude","title":"fixture","status":"idle","activeTurn":null,"pendingPermissions":[],"labels":{"native.save":format!("v1;acct={ACCOUNT};db={DB};req={first}")}}})];
                                    // A complete metadata snapshot is the only authority
                                    // for delete/Stop classification; no fake empty page.
                                    let response=json!({"type":"fetch_agents_response","payload":{"requestId":message["requestId"],"entries":entries,"pageInfo":{"hasMore":false}}});
                                    ws.send(Message::Text(json!({"type":"session","message":response}).to_string().into())).await.unwrap();
                                }
                                "agent.timeline.set_subscription.request"=>{},
                                "fetch_agent_timeline_request"=>{
                                    let mut response=bounded_page(1,1,false);
                                    response["payload"]["requestId"]=message["requestId"].clone();
                                    ws.send(Message::Text(json!({"type":"session","message":response}).to_string().into())).await.unwrap();
                                }
                                "update_agent_request"=>{
                                    let status=message.pointer("/labels/native.save.status").and_then(Value::as_str).unwrap();
                                    if status.starts_with("ok:") && phase==0 {
                                        phase=1;
                                        let snapshot=json!({"id":AGENT,"provider":"claude","title":"fixture","status":"idle","activeTurn":null,"pendingPermissions":[],"labels":{"native.save":format!("off;req={second}")}});
                                        ws.send(Message::Text(json!({"type":"session","message":{"type":"agent_update","payload":{"kind":"upsert","agent":snapshot}}}).to_string().into())).await.unwrap();
                                        statuses.send(1).await.unwrap();
                                    } else if status.starts_with("ok:") && phase==2 {phase=3;statuses.send(2).await.unwrap();}
                                }
                                unexpected=>panic!("unexpected saver daemon capability: {unexpected}"),
                            }
                        }
                    }
                }
            });
            let home = tempfile::tempdir().unwrap();
            std::fs::write(
                home.path().join("paseo.pid"),
                json!({"listen":address.to_string()}).to_string(),
            )
            .unwrap();
            std::fs::write(home.path().join("local-credential"), "a".repeat(43)).unwrap();
            let credentials = daemon_client::read_daemon_credentials(home.path()).unwrap();
            let mut connection = daemon_client::DaemonConnection::connect(&credentials)
                .await
                .unwrap();
            let (_shutdown_tx, mut shutdown) = tokio::sync::watch::channel(false);
            let work = supervisor.clone();
            let reader = session_saver::drive_connection_with_worker(
                &mut connection,
                test_binding(),
                &mut shutdown,
                move |handle| work.run(handle),
            );
            tokio::pin!(reader);
            let assertions = async {
                assert_eq!(status_rx.recv().await, Some(1));
                let stopped = wait_live_state(&rig, "stopped").await;
                let first = rig.store.load_checkpoint(AGENT).unwrap();
                assert_eq!(first.source_fps.len(), 1);
                commands.send(true).await.unwrap();
                assert_eq!(status_rx.recv().await, Some(2));
                let resumed = wait_live_state(&rig, "saving").await;
                assert!(resumed.claim.generation >= stopped.claim.generation);
                let second = rig.store.load_checkpoint(AGENT).unwrap();
                assert_eq!(second.head_pos, first.head_pos);
                assert_eq!(second.source_fps, first.source_fps);
                {
                    let seen = observed.lock().unwrap();
                    assert!(seen.iter().any(|m| m
                        .pointer("/labels/native.save.status")
                        .and_then(Value::as_str)
                        == Some("accepted:223e4567-e89b-12d3-a456-426614174000")));
                }
                commands.send(false).await.unwrap();
            };
            let (outcome, ()) = tokio::time::timeout(Duration::from_secs(60), async {
                tokio::join!(&mut reader, assertions)
            })
            .await
            .expect("real reader and gated writer must make progress");
            assert!(matches!(outcome, Err(session_saver::SaverStop::Retry)));
            supervisor.disconnected().await;
            let paused = wait_live_state(&rig, "paused").await;
            assert_eq!(
                paused.facets["native.session.paused_reason"],
                "host_daemon_stopped"
            );
            let seen = paused.claim.last_seen_at;
            assert_eq!(
                rig.writer()
                    .heartbeat(AGENT, SERVER, "boot-1", "2099-01-01T00:00:00Z")
                    .await
                    .unwrap(),
                StateAction::NotDue
            );
            assert_eq!(
                rig.writer()
                    .read_owned_session_state(AGENT)
                    .await
                    .unwrap()
                    .claim
                    .last_seen_at,
                seen
            );
            server.await.unwrap();
        }

        #[tokio::test]
        async fn live_alignment_preserves_state_keys_reserved_by_a_verification_heartbeat() {
            let rig = Rig::new().await;
            let old = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
            rig.ensure("t", "boot-1", &old).await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", &old)
                .await
                .unwrap();
            let before = rig.store.load_checkpoint(AGENT).unwrap();
            writer
                .prepare_catchup_live(catchup_source(0, "one"), catchup_context())
                .await
                .unwrap();
            let after = rig.store.load_checkpoint(AGENT).unwrap();
            assert!(after.state_seq > before.state_seq);
            assert!(after.last_hosted_write_ms > before.last_hosted_write_ms);
            assert!(rig.store.load_proposal(AGENT).unwrap().is_none());
            assert_eq!(
                writer
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-1",
                        &chrono::Utc::now().to_rfc3339(),
                        BTreeMap::from([("native.session.activity".into(), json!("idle"))])
                    )
                    .await
                    .unwrap(),
                StateAction::Written
            );
        }

        #[tokio::test]
        async fn quarantined_step_is_terminal_and_records_guarded_canonical_error() {
            use crate::node::{
                session_actor::{self, Command},
                session_control::SaveStatus,
                session_identity::SaverIdentity,
                session_supervisor::Supervisor,
            };
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            rig.writer()
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let store = StdArc::new(open_store(rig._temp.path()));
            let sink = StdArc::new(GateSink::new(
                rig.sink.upstream.clone(),
                rig.sink.gate.clone(),
            ));
            let supervisor = StdArc::new(Supervisor::new(
                store,
                vec![],
                sink,
                SaverIdentity {
                    instance: "inst-1".into(),
                    boot: "boot-1".into(),
                },
                1024 * 1024,
                std::time::Instant::now(),
            ));
            let (handle, mut mailbox) = session_actor::mailbox(test_binding());
            mailbox.directory(&std::collections::HashMap::from([(AGENT.into(),json!({"id":AGENT,"provider":"claude","title":"fixture","status":"idle","activeTurn":null,"pendingPermissions":[],"labels":{"native.save":format!("v1;acct={ACCOUNT};db={DB};req=123e4567-e89b-12d3-a456-426614174000")}}))])).unwrap();
            rig.fault(Fault::RejectStep);
            let work = supervisor.run(handle);
            let assertions = async {
                loop {
                    match mailbox.commands.recv().await.unwrap() {
                        Command::Fetch {
                            agent,
                            selection,
                            reply,
                            ..
                        } => {
                            assert!(mailbox.selected(&agent, &selection));
                            reply.send(Ok(bounded_page(1, 1, false))).unwrap();
                        }
                        Command::Status { status, reply, .. } => {
                            reply.send(Ok(Some(status.clone()))).unwrap();
                            if matches!(&status,SaveStatus::Error{code} if code=="quarantined") {
                                break;
                            }
                        }
                    }
                }
                let error = wait_live_state(&rig, "error").await;
                assert_eq!(error.facets["native.session.state"], "error");
                assert!(rig.store.load_checkpoint(AGENT).unwrap().head_pos.is_none());
                let attempts = || {
                    rig.hosted
                        .received
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|r| {
                            r.pointer("/params/arguments/arguments/kind")
                                .and_then(Value::as_str)
                                == Some(STEP_KIND)
                        })
                        .count()
                };
                let before = attempts();
                assert_eq!(before, 1);
                tokio::time::sleep(Duration::from_millis(1200)).await;
                assert_eq!(
                    attempts(),
                    before,
                    "a quarantined batch must not retry automatically"
                );
                let spool = rig
                    ._temp
                    .path()
                    .join("sessions")
                    .join(format!("{AGENT}.spool"));
                assert!(std::fs::read_dir(spool).unwrap().any(|e| e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".json.quarantined")));
                mailbox.close();
            };
            tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(work, assertions)
            })
            .await
            .expect("quarantine must reach both canonical state and owner status");
            let reopened = StdArc::new(open_store(rig._temp.path()));
            assert_eq!(
                reopened
                    .load_checkpoint(AGENT)
                    .unwrap()
                    .terminal_save_code
                    .as_deref(),
                Some("quarantined")
            );
            let sink = StdArc::new(GateSink::new(
                rig.sink.upstream.clone(),
                rig.sink.gate.clone(),
            ));
            let supervisor = StdArc::new(Supervisor::new(
                reopened,
                vec![],
                sink,
                SaverIdentity {
                    instance: "inst-1".into(),
                    boot: "boot-2".into(),
                },
                1024 * 1024,
                std::time::Instant::now(),
            ));
            let (handle, mut mailbox) = session_actor::mailbox(test_binding());
            mailbox.directory(&std::collections::HashMap::from([(AGENT.into(),json!({"id":AGENT,"provider":"claude","title":"fixture","status":"idle","activeTurn":null,"pendingPermissions":[],"labels":{"native.save":format!("v1;acct={ACCOUNT};db={DB};req=123e4567-e89b-12d3-a456-426614174000")}}))])).unwrap();
            let work = supervisor.run(handle);
            let assertions = async {
                match mailbox.commands.recv().await.unwrap() {
                    Command::Status { status, reply, .. } => {
                        assert_eq!(
                            status,
                            SaveStatus::Error {
                                code: "quarantined".into()
                            }
                        );
                        reply.send(Ok(Some(status))).unwrap();
                    }
                    Command::Fetch { .. } => {
                        panic!("reconnecting must not retry a quarantined Save request")
                    }
                }
                mailbox.close();
            };
            tokio::time::timeout(Duration::from_secs(15), async {
                tokio::join!(work, assertions)
            })
            .await
            .expect("reopened terminal fence must report without fetching");
        }

        #[tokio::test]
        async fn ensure_creates_verified_identity_and_reconverges() {
            let rig = Rig::new().await;
            let created = match rig
                .ensure("My session", "boot-1", "2026-10-17T00:00:00Z")
                .await
            {
                EnsureOutcome::Created(id) => id,
                EnsureOutcome::Existing(_) => panic!("expected creation"),
            };
            let cp = rig.store.load_checkpoint(AGENT).unwrap();
            let root_id = cp.root_id.clone().expect("root stashed");
            assert_eq!(cp.folder_id.as_deref(), Some(created.folder_id.as_str()));
            assert_eq!(
                cp.session_record_id.as_deref(),
                Some(created.record_id.as_str())
            );
            // Root: explicit, self-anchored, sole account grant, Manage,
            // administrable, bound person == owner.
            let policy = rig.sink.read_policy(&root_id).await.unwrap();
            assert_eq!(policy.mode, "explicit");
            assert_eq!(policy.anchor_id, root_id);
            assert!(policy.policy_administration_authorized);
            assert_eq!(policy.entries.len(), 1);
            assert_eq!(policy.entries[0].subject_id, ACCOUNT);
            let bound = policy.entries[0].person_id.clone().unwrap();
            let root_row = rig.sink.read_row(&root_id).await.unwrap();
            assert_eq!(root_row.owner_id.as_deref(), Some(bound.as_str()));
            // Folder inherits the root; neither carries its own policy.
            let folder_policy = rig.sink.read_policy(&created.folder_id).await.unwrap();
            assert_eq!(folder_policy.mode, "inherit");
            assert_eq!(folder_policy.anchor_id, root_id);
            // Re-ensure with drifted title/time/boot reconverges to the same
            // identity and creates nothing new.
            let outcome = rig
                .ensure("Different title", "boot-9", "2026-10-18T09:00:00Z")
                .await;
            match outcome {
                EnsureOutcome::Existing(id) => {
                    assert_eq!(id.folder_id, created.folder_id);
                    assert_eq!(id.record_id, created.record_id);
                }
                // A record created here is also correct (only the record
                // stage was missing), but it must reuse the folder.
                EnsureOutcome::Created(id) => assert_eq!(id.folder_id, created.folder_id),
            }
            assert_eq!(
                rig.sink
                    .find_session_record(&created.folder_id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(created.record_id.as_str()),
                "exactly one session record"
            );
        }

        #[tokio::test]
        async fn folder_only_partial_creation_completes_with_drift() {
            let rig = Rig::new().await;
            // Stage 1 only: root and folder, as an interrupted first save
            // would leave them.
            let root_args = create_root_arguments(ACCOUNT, "Saved sessions — owner").unwrap();
            rig.sink
                .create_keyed(root_args, format!("nss3:root:{ACCOUNT}"))
                .await
                .unwrap();
            let root = rig.sink.find_root(ACCOUNT).await.unwrap().expect("root");
            let folder_args =
                create_session_folder_arguments(SERVER, AGENT, &root.id, "Old title").unwrap();
            let folder_key = format!("nss3:{SERVER}:{AGENT}:folder");
            rig.sink
                .create_keyed(folder_args, folder_key)
                .await
                .unwrap();
            let folder_id = rig
                .sink
                .find_session_folder(SERVER, AGENT)
                .await
                .unwrap()
                .expect("folder");
            // Retry with a different title, timestamp and boot id: the
            // folder key conflicts and the record stage must finish in the
            // SAME folder.
            let outcome = rig
                .ensure("New title", "boot-new", "2026-10-18T10:00:00Z")
                .await;
            let id = match outcome {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            assert_eq!(id.folder_id, folder_id, "folder reused, never duplicated");
            assert_eq!(
                rig.sink
                    .find_session_record(&folder_id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(id.record_id.as_str()),
                "the missing record stage completed"
            );
            assert_eq!(
                rig.sink
                    .find_session_folder(SERVER, AGENT)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(folder_id.as_str()),
                "still exactly one folder"
            );
        }

        #[tokio::test]
        async fn send_next_commits_confirms_and_never_holds() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            let req = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "hello");
            rig.store.freeze_spool(&req, AGENT).unwrap();
            let action = rig
                .writer()
                .send_next(AGENT, SERVER, &cursor())
                .await
                .unwrap();
            assert_eq!(action, SendAction::Advanced { pos: 1 });
            let cp = rig.store.load_checkpoint(AGENT).unwrap();
            assert_eq!(cp.head_pos, Some(1));
            assert_eq!(cp.head_cid.as_deref(), Some(req.facets.cid.as_str()));
            assert_eq!(cp.cursor_epoch.as_deref(), Some("epoch-1"));
            assert!(rig.store.load_spool(AGENT).unwrap().is_none());
            // Hosted holds exactly one step at position 1.
            let steps = rig.sink.query_steps(&id.folder_id, 0).await.unwrap().steps;
            assert_eq!(steps.len(), 1);
            assert_eq!(steps[0].pos, 1);
            assert_eq!(steps[0].body, "hello");
            // The saver's own write was never held for later replay.
            for entry in rig.journal_entries() {
                assert_ne!(
                    entry.get("state").and_then(Value::as_str),
                    Some("pending"),
                    "saver writes are never held: {entry}"
                );
            }
        }

        #[tokio::test]
        async fn verified_hosted_rebuild_folds_real_position_keyed_marker() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root = chain_root(SERVER, AGENT).unwrap();
            let first = freeze_at(&rig.store, &id.folder_id, 1, &root, "original");
            rig.store.freeze_spool(&first, AGENT).unwrap();
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::Advanced { pos: 1 }
            );
            let marker = freeze_marker(
                &rig.store,
                AGENT,
                &id.folder_id,
                MarkerKind::Rewound,
                "host",
                0,
                1,
                &first.facets.cid,
                2,
                "2026-10-17T00:01:00Z",
            )
            .unwrap()
            .with_marker_branch(Some(2))
            .unwrap();
            rig.store.freeze_spool(&marker, AGENT).unwrap();
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::Advanced { pos: 2 }
            );
            // Same content is a new position after an explicit rewind.
            let replay = freeze_at(&rig.store, &id.folder_id, 3, &marker.facets.cid, "original");
            rig.store.freeze_spool(&replay, AGENT).unwrap();
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::Advanced { pos: 3 }
            );
            let rebuilt = rig.writer().verified_chain(AGENT).await.unwrap();
            assert_eq!(rebuilt.head_pos, Some(3));
            assert_eq!(
                rebuilt.head_cid.as_deref(),
                Some(replay.facets.cid.as_str())
            );
            assert_eq!(rebuilt.e, vec![first.facets.fp]);
            assert_eq!(rebuilt.marker_branch, Some(2));
        }

        #[tokio::test]
        async fn a_holder_heartbeat_defeats_a_frozen_stale_takeover_cas() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let original = writer.read_owned_session_state(AGENT).await.unwrap();
            let at = chrono::DateTime::parse_from_rfc3339("2026-10-17T00:13:00Z").unwrap();
            assert!(takeover_eligible(
                &original.claim,
                SERVER,
                "another-instance",
                at.timestamp()
            ));
            let stale = lease_takeover_arguments(
                &original.identity.id,
                &original.claim,
                "srv-a/another-instance/boot",
                "2026-10-17T00:13:00Z",
            )
            .unwrap();
            assert_eq!(
                writer
                    .heartbeat(AGENT, SERVER, "boot-1", "2026-10-17T00:13:00Z")
                    .await
                    .unwrap(),
                StateAction::Written
            );
            assert_eq!(
                outcome_of(rig.sink.update_state(stale).await.unwrap()),
                WriteOutcome::ValidationRefused
            );
            let held = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(held.claim.generation, original.claim.generation);
            assert_eq!(held.claim.last_seen_at, "2026-10-17T00:13:00Z");
        }

        fn catchup_source(
            branch: u64,
            text: &str,
        ) -> crate::node::session_catchup::CompleteTimeline {
            use crate::node::session_catchup::TimelineFetch;
            let mut fetch = TimelineFetch::new(AGENT, 1024 * 1024).unwrap();
            fetch.accept(&json!({"type":"fetch_agent_timeline_response","payload":{
                "agentId":AGENT,"requestId":"source","projection":"projected","direction":"after",
                "epoch":"epoch","timelineBranch":branch,"keptSeqEnd":0,
                "reset":false,"staleCursor":false,"gap":false,"hasNewer":false,"error":null,
                "startCursor":{"epoch":"epoch","seq":1},"endCursor":{"epoch":"epoch","seq":1},
                "entries":[{"seqStart":1,"seqEnd":1,"timestamp":"2026-10-17T00:00:00Z",
                    "item":{"type":"user_message","text":text},"sourceSeqRanges":[{"startSeq":1,"endSeq":1}],"collapsed":[]}]}}), "source").unwrap();
            fetch.finish(false).unwrap()
        }

        fn catchup_context() -> CatchupContext {
            CatchupContext {
                agent_id: AGENT.into(),
                daemon_server_id: SERVER.into(),
                boot_id: "boot-1".into(),
                host_label: "host".into(),
                observed_replacement: false,
                unknown_continuity: false,
            }
        }

        fn bounded_page(first: u64, last: u64, more: bool) -> serde_json::Value {
            let entries: Vec<_> = (first..=last)
                .map(|seq| {
                    json!({
                        "seqStart":seq,"seqEnd":seq,"timestamp":"2026-10-17T00:00:00Z",
                        "item":{"type":"user_message","text":format!("message {seq}")},
                        "sourceSeqRanges":[],"collapsed":[]
                    })
                })
                .collect();
            json!({"type":"fetch_agent_timeline_response","payload":{
                "agentId":AGENT,"requestId":"source","projection":"projected","direction":"after",
                "epoch":"epoch","timelineBranch":1,"keptSeqEnd":0,
                "reset":false,"staleCursor":false,"gap":false,"hasNewer":more,"error":null,
                "startCursor":{"epoch":"epoch","seq":first},
                "endCursor":{"epoch":"epoch","seq":last},"entries":entries}})
        }

        async fn settle_bounded_window(
            writer: &Writer<'_, GateSink>,
            source: &mut crate::node::session_stream::BoundedSource,
            tick: &mut u64,
        ) -> CatchupAction {
            let produced = source.take_window().unwrap();
            let snapshot = produced.source.snapshot.clone();
            let mut context = catchup_context();
            context.observed_replacement = produced.observed_replacement;
            context.unknown_continuity = produced.unknown_continuity;
            let mut run = writer
                .prepare_catchup(produced.source, context)
                .await
                .unwrap();
            source.settle_from(&run).unwrap();
            for _ in 0..2048 {
                let now = chrono::DateTime::parse_from_rfc3339("2026-10-17T00:00:00Z").unwrap()
                    + chrono::Duration::milliseconds(*tick as i64);
                let action = writer
                    .pump_catchup(&mut run, &snapshot, &now.to_rfc3339(), *tick)
                    .await
                    .unwrap();
                *tick += 250;
                source.settle_from(&run).unwrap();
                match action {
                    CatchupAction::Complete | CatchupAction::WindowComplete => {
                        let chain = writer.verified_chain(AGENT).await.unwrap();
                        source.finish_window(&run, chain, &action).unwrap();
                        return action;
                    }
                    CatchupAction::Advanced { .. }
                    | CatchupAction::Paced
                    | CatchupAction::State(StateAction::Written | StateAction::Settled) => {}
                    unexpected => panic!("unexpected bounded writer action: {unexpected:?}"),
                }
            }
            panic!("bounded source did not settle");
        }

        #[tokio::test]
        async fn bounded_multipage_source_releases_only_confirmed_rows_and_refreshes_from_checkpoint(
        ) {
            use crate::node::session_stream::{BoundedSource, SourcePoll};
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            assert_eq!(
                writer
                    .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                    .await
                    .unwrap(),
                StateAction::Held
            );
            let before = writer.read_owned_session_state(AGENT).await.unwrap();
            let mut source = BoundedSource::new(
                AGENT,
                writer.verified_chain(AGENT).await.unwrap(),
                Some(1),
                Some("epoch".into()),
                false,
                false,
                4 * 1024 * 1024,
            )
            .unwrap();
            assert!(matches!(
                source.poll(false).unwrap(),
                SourcePoll::Fetch { cursor: None }
            ));
            source
                .accept_page(&bounded_page(1, 200, true), "source")
                .unwrap();
            assert_eq!(source.poll(false).unwrap(), SourcePoll::Window);
            assert_eq!(source.pending_entries(), 200);
            let mut tick = 0;
            assert_eq!(
                settle_bounded_window(&writer, &mut source, &mut tick).await,
                CatchupAction::WindowComplete
            );
            assert_eq!(source.pending_entries(), 0);
            let state = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(
                state.facets.get("native.session.source_branch"),
                before.facets.get("native.session.source_branch")
            );
            // A fresh pipeline must compare actual source to hosted E rather
            // than inventing old prefix bodies or skipping its first page.
            source = BoundedSource::new(
                AGENT,
                writer.verified_chain(AGENT).await.unwrap(),
                Some(1),
                Some("epoch".into()),
                false,
                false,
                4 * 1024 * 1024,
            )
            .unwrap();
            assert!(matches!(
                source.poll(false).unwrap(),
                SourcePoll::Fetch { cursor: None }
            ));
            source
                .accept_page(&bounded_page(1, 200, true), "source")
                .unwrap();
            assert_eq!(
                source.poll(false).unwrap(),
                SourcePoll::Fetch {
                    cursor: Some(json!({"epoch":"epoch","seq":200}))
                }
            );
            source
                .accept_page(&bounded_page(201, 250, false), "source")
                .unwrap();
            assert_eq!(source.poll(false).unwrap(), SourcePoll::Window);
            assert_eq!(source.pending_entries(), 50);
            assert_eq!(
                settle_bounded_window(&writer, &mut source, &mut tick).await,
                CatchupAction::Complete
            );
            assert_eq!(source.pending_entries(), 0);
            assert_eq!(writer.verified_chain(AGENT).await.unwrap().e.len(), 250);
            assert_eq!(
                rig.store.load_checkpoint(AGENT).unwrap().cursor_seq_end,
                Some(250)
            );
            source.refresh().unwrap();
            assert_eq!(
                source.poll(false).unwrap(),
                SourcePoll::Fetch {
                    cursor: Some(json!({"epoch":"epoch","seq":250}))
                }
            );
            let mut empty = bounded_page(251, 251, false);
            empty["payload"]["entries"] = json!([]);
            empty["payload"]["startCursor"] = serde_json::Value::Null;
            empty["payload"]["endCursor"] = serde_json::Value::Null;
            source.accept_page(&empty, "source").unwrap();
            assert_eq!(source.poll(false).unwrap(), SourcePoll::Window);
            assert_eq!(
                settle_bounded_window(&writer, &mut source, &mut tick).await,
                CatchupAction::Complete
            );
            assert_eq!(writer.verified_chain(AGENT).await.unwrap().e.len(), 250);
        }

        #[tokio::test]
        async fn bounded_windows_keep_pacing_and_progress_clock_across_short_windows() {
            use crate::node::session_stream::{BoundedSource, SourcePoll};
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let mut source = BoundedSource::new(
                AGENT,
                writer.verified_chain(AGENT).await.unwrap(),
                Some(1),
                Some("epoch".into()),
                false,
                false,
                1024 * 1024,
            )
            .unwrap();
            source.poll(false).unwrap();
            source
                .accept_page(&bounded_page(1, 1, true), "source")
                .unwrap();
            assert_eq!(source.poll(false).unwrap(), SourcePoll::Window);
            let mut tick = 0;
            settle_bounded_window(&writer, &mut source, &mut tick).await;
            source.poll(false).unwrap();
            source
                .accept_page(&bounded_page(2, 2, false), "source")
                .unwrap();
            assert_eq!(source.poll(false).unwrap(), SourcePoll::Window);
            let produced = source.take_window().unwrap();
            let snapshot = produced.source.snapshot.clone();
            let mut run = writer
                .prepare_catchup(produced.source, catchup_context())
                .await
                .unwrap();
            assert_eq!(run.last_progress_ms, Some(0));
            let last_attempt = run.last_attempt_ms.unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:01Z", last_attempt)
                    .await
                    .unwrap(),
                CatchupAction::Paced
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:30Z", 30_000)
                    .await
                    .unwrap(),
                CatchupAction::State(StateAction::Written)
            );
            assert_eq!(run.last_progress_ms, Some(30_000));
            assert_eq!(run.confirmed_source_prefix(), 1);
        }

        #[tokio::test]
        async fn partial_window_settlement_defers_branch_ack_until_actual_source_end() {
            use crate::node::session_catchup::{ComparedPrefix, CompleteTimeline};
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            assert_eq!(
                writer
                    .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                    .await
                    .unwrap(),
                StateAction::Held
            );
            let before = writer.read_owned_session_state(AGENT).await.unwrap();
            let source = catchup_source(3, "one");
            let snapshot = source.snapshot.clone();
            let chain = writer.verified_chain(AGENT).await.unwrap();
            let window = CompleteTimeline::window(
                AGENT,
                snapshot.clone(),
                ComparedPrefix::new(&chain),
                source.steps,
                None,
                Some(1),
                false,
            )
            .unwrap();
            let mut run = writer
                .prepare_catchup(window, catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:01Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 1 }
            );
            assert_eq!(run.confirmed_source_prefix(), 0);
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:02Z", 250)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 2 }
            );
            assert_eq!(run.confirmed_source_prefix(), 1);
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:03Z", 500)
                    .await
                    .unwrap(),
                CatchupAction::WindowComplete
            );
            let after = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(
                after.facets.get("native.session.source_branch"),
                before.facets.get("native.session.source_branch")
            );
            assert_eq!(
                after.facets.get("native.session.continuity_notes"),
                before.facets.get("native.session.continuity_notes")
            );
            let source = catchup_source(3, "one");
            let chain = writer.verified_chain(AGENT).await.unwrap();
            let mut prefix = ComparedPrefix::new(&chain);
            assert!(prefix.compare(&source.steps[0]).unwrap());
            let window = CompleteTimeline::window(
                AGENT,
                snapshot.clone(),
                prefix,
                vec![],
                None,
                Some(1),
                true,
            )
            .unwrap();
            let mut final_run = writer
                .prepare_catchup(window, catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut final_run, &snapshot, "2026-10-17T00:00:04Z", 750)
                    .await
                    .unwrap(),
                CatchupAction::Complete
            );
            let state = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(
                state
                    .facets
                    .get("native.session.source_branch")
                    .map(String::as_str),
                Some("3")
            );
            assert_eq!(
                continuity_notes(state.facets.get("native.session.continuity_notes"))
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(rig.store.load_checkpoint(AGENT).unwrap().head_pos, Some(2));
        }

        #[tokio::test]
        async fn catchup_restart_mid_split_rebuilds_prefix_without_skipping_parts() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            assert!(matches!(
                writer
                    .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                    .await
                    .unwrap(),
                StateAction::Held
            ));
            let text = "x".repeat(crate::node::session_projection::MAX_STEP_BYTES * 2);
            let source = catchup_source(0, &text);
            let parts = source.steps.len();
            let snapshot = source.snapshot.clone();
            let mut run = writer
                .prepare_catchup(source, catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:01Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 1 }
            );
            assert_eq!(
                rig.store.load_checkpoint(AGENT).unwrap().cursor_seq_end,
                Some(0)
            );
            drop(run); // Losing the in-memory curator cannot lose later parts.
            let mut run = writer
                .prepare_catchup(catchup_source(0, &text), catchup_context())
                .await
                .unwrap();
            for pos in 2..=parts as u64 {
                let tick = (pos - 2) * 250;
                assert_eq!(
                    writer
                        .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:02Z", tick)
                        .await
                        .unwrap(),
                    CatchupAction::Advanced { pos }
                );
                if pos < parts as u64 {
                    assert_eq!(
                        rig.store.load_checkpoint(AGENT).unwrap().cursor_seq_end,
                        Some(0)
                    );
                    assert_eq!(
                        writer
                            .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:02Z", tick + 249)
                            .await
                            .unwrap(),
                        CatchupAction::Paced
                    );
                }
            }
            assert_eq!(
                rig.store.load_checkpoint(AGENT).unwrap().cursor_seq_end,
                Some(1)
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:03Z", 1000)
                    .await
                    .unwrap(),
                CatchupAction::Complete
            );
            let verified = writer.verified_chain(AGENT).await.unwrap();
            assert_eq!(verified.head_pos, Some(parts as u64));
            assert_eq!(verified.e.len(), parts);
        }

        #[tokio::test]
        async fn catchup_marker_crash_and_lost_ack_resume_without_duplicate_marker_or_note() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let source = catchup_source(0, "identical");
            let snapshot = source.snapshot.clone();
            let mut run = writer
                .prepare_catchup(source, catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:01Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 1 }
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:02Z", 250)
                    .await
                    .unwrap(),
                CatchupAction::Complete
            );
            // Two missed branches demand durable qualification even though
            // the regenerated source is byte-identical.
            let source = catchup_source(2, "identical");
            let snapshot = source.snapshot.clone();
            let mut run = writer
                .prepare_catchup(source, catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:03Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 2 }
            );
            drop(run);
            let mut run = writer
                .prepare_catchup(catchup_source(2, "identical"), catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:04Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 3 }
            );
            rig.fault(Fault::LoseStateReply);
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:05Z", 250)
                    .await
                    .unwrap(),
                CatchupAction::State(StateAction::RetryLater)
            );
            rig.reset();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:06Z", 500)
                    .await
                    .unwrap(),
                CatchupAction::State(StateAction::Settled)
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:07Z", 750)
                    .await
                    .unwrap(),
                CatchupAction::Complete
            );
            let state = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(
                state
                    .facets
                    .get("native.session.source_branch")
                    .map(String::as_str),
                Some("2")
            );
            assert_eq!(
                continuity_notes(state.facets.get("native.session.continuity_notes"))
                    .unwrap()
                    .len(),
                1
            );
            let verified = writer.verified_chain(AGENT).await.unwrap();
            assert_eq!(verified.head_pos, Some(3));
            assert_eq!(verified.marker_branch, Some(2));
            assert_eq!(verified.e.len(), 1);
        }

        #[tokio::test]
        async fn catchup_snapshot_change_fences_before_any_create() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let mut run = writer
                .prepare_catchup(catchup_source(0, "one"), catchup_context())
                .await
                .unwrap();
            let changed = SourceSnapshot {
                epoch: "epoch".into(),
                branch: Some(1),
                kept_seq_end: Some(0),
            };
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &changed, "2026-10-17T00:00:01Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Realign
            );
            assert!(rig.store.load_checkpoint(AGENT).unwrap().needs_realign);
            assert!(!rig.store.has_spool(AGENT).unwrap());
            assert_eq!(writer.verified_chain(AGENT).await.unwrap().head_pos, None);
        }

        #[tokio::test]
        async fn catchup_progress_uses_confirmed_head_at_thirty_second_intervals() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let text = "x".repeat(crate::node::session_projection::MAX_STEP_BYTES * 2);
            let source = catchup_source(0, &text);
            let snapshot = source.snapshot.clone();
            let mut run = writer
                .prepare_catchup(source, catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:01Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 1 }
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:29Z", 29_999)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 2 }
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:30Z", 30_000)
                    .await
                    .unwrap(),
                CatchupAction::State(StateAction::Written)
            );
            let state = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(
                state
                    .facets
                    .get("native.session.confirmed_pos")
                    .map(String::as_str),
                Some("2")
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:30Z", 30_001)
                    .await
                    .unwrap(),
                CatchupAction::Paced
            );
            assert_eq!(
                writer
                    .pump_catchup(&mut run, &snapshot, "2026-10-17T00:00:31Z", 30_249)
                    .await
                    .unwrap(),
                CatchupAction::Advanced { pos: 3 }
            );
        }

        #[tokio::test]
        async fn catchup_rejects_other_agent_and_superseded_local_alignment() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let mut wrong = catchup_context();
            wrong.agent_id = "other-agent".into();
            assert!(writer
                .prepare_catchup(catchup_source(0, "one"), wrong)
                .await
                .is_err());
            assert!(!rig.store.has_checkpoint("other-agent").unwrap());
            let source = catchup_source(0, "one");
            let snapshot = source.snapshot.clone();
            let mut old = writer
                .prepare_catchup(source, catchup_context())
                .await
                .unwrap();
            let _new = writer
                .prepare_catchup(catchup_source(0, "one"), catchup_context())
                .await
                .unwrap();
            assert_eq!(
                writer
                    .pump_catchup(&mut old, &snapshot, "2026-10-17T00:00:01Z", 0)
                    .await
                    .unwrap(),
                CatchupAction::Realign
            );
            assert!(rig.store.load_checkpoint(AGENT).unwrap().needs_realign);
            assert!(!rig.store.has_spool(AGENT).unwrap());
            assert_eq!(writer.verified_chain(AGENT).await.unwrap().head_pos, None);
        }

        #[tokio::test]
        async fn heartbeat_only_runs_while_saving_and_after_five_minutes() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            assert_eq!(
                writer
                    .heartbeat(AGENT, SERVER, "boot-1", "2026-10-17T00:04:59Z")
                    .await
                    .unwrap(),
                StateAction::NotDue
            );
            assert_eq!(
                writer
                    .heartbeat(AGENT, SERVER, "boot-1", "2026-10-17T00:05:00Z")
                    .await
                    .unwrap(),
                StateAction::Written
            );
            assert_eq!(
                writer
                    .heartbeat(AGENT, SERVER, "boot-1", "2026-10-17T00:09:59Z")
                    .await
                    .unwrap(),
                StateAction::NotDue
            );
            writer
                .write_session_state(
                    AGENT,
                    SERVER,
                    "boot-1",
                    "2026-10-17T00:10:00Z",
                    BTreeMap::from([("native.session.state".into(), json!("paused"))]),
                )
                .await
                .unwrap();
            assert_eq!(
                writer
                    .heartbeat(AGENT, SERVER, "boot-1", "2026-10-17T01:00:00Z")
                    .await
                    .unwrap(),
                StateAction::NotDue
            );
        }

        #[tokio::test]
        async fn branch_ack_keeps_append_only_continuity_disclosure() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let mut plan = AlignmentPlan {
                marker: None,
                base_len: 0,
                source_branch: Some(0),
                continuity_assumed: false,
            };
            assert_eq!(
                writer
                    .acknowledge_source_alignment(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:01:00Z",
                        0,
                        &plan
                    )
                    .await
                    .unwrap(),
                StateAction::Written
            );
            plan.source_branch = Some(2);
            assert!(
                writer
                    .acknowledge_source_alignment(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:02:00Z",
                        7,
                        &plan
                    )
                    .await
                    .is_err(),
                "missed branches cannot be silently acknowledged"
            );
            plan.continuity_assumed = true;
            assert_eq!(
                writer
                    .acknowledge_source_alignment(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:02:00Z",
                        7,
                        &plan
                    )
                    .await
                    .unwrap(),
                StateAction::Written
            );
            plan.source_branch = Some(3);
            plan.continuity_assumed = false;
            writer
                .acknowledge_source_alignment(
                    AGENT,
                    SERVER,
                    "boot-1",
                    "2026-10-17T00:03:00Z",
                    8,
                    &plan,
                )
                .await
                .unwrap();
            let state = writer.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(
                state
                    .facets
                    .get("native.session.source_branch")
                    .map(String::as_str),
                Some("3")
            );
            let notes =
                continuity_notes(state.facets.get("native.session.continuity_notes")).unwrap();
            assert_eq!(
                notes,
                vec![ContinuityNote {
                    at: "2026-10-17T00:02:00Z".into(),
                    from_pos: 7
                }]
            );
            assert!(writer
                .write_session_state(
                    AGENT,
                    SERVER,
                    "boot-1",
                    "2026-10-17T00:04:00Z",
                    BTreeMap::from([("native.session.continuity_notes".into(), json!("[]"))])
                )
                .await
                .is_err());
            assert!(writer
                .write_session_state(
                    AGENT,
                    SERVER,
                    "boot-1",
                    "2026-10-17T00:04:00Z",
                    BTreeMap::from([("native.session.continuity".into(), Value::Null)])
                )
                .await
                .is_err());
            assert_eq!(
                continuity_notes(
                    writer
                        .read_owned_session_state(AGENT)
                        .await
                        .unwrap()
                        .facets
                        .get("native.session.continuity_notes")
                )
                .unwrap(),
                notes
            );
        }

        #[tokio::test]
        async fn lost_state_reply_retries_frozen_arguments_before_new_state() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let writer = rig.writer();
            writer
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            rig.fault(Fault::LoseStateReply);
            assert_eq!(
                writer
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:01:00Z",
                        BTreeMap::from([("native.session.state".into(), json!("paused"))])
                    )
                    .await
                    .unwrap(),
                StateAction::RetryLater
            );
            let pending = rig.store.load_proposal(AGENT).unwrap().unwrap();
            rig.reset();
            assert_eq!(
                writer
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:02:00Z",
                        BTreeMap::from([("native.session.state".into(), json!("saving"))])
                    )
                    .await
                    .unwrap(),
                StateAction::Settled
            );
            assert!(rig.store.load_proposal(AGENT).unwrap().is_none());
            assert_eq!(
                writer
                    .read_owned_session_state(AGENT)
                    .await
                    .unwrap()
                    .facets
                    .get("native.session.state")
                    .map(String::as_str),
                Some("paused")
            );
            let received = rig.hosted.received.lock().unwrap();
            let attempts: Vec<_> = received
                .iter()
                .filter_map(|message| message.pointer("/params/arguments/arguments"))
                .filter(|args| {
                    args.get("idempotency_key").and_then(Value::as_str)
                        == Some(pending.key.as_str())
                })
                .collect();
            assert!(attempts.len() >= 2);
            assert!(attempts.iter().all(|args| **args == pending.arguments));
            drop(received);
            for entry in rig.journal_entries() {
                assert_ne!(entry.get("state").and_then(Value::as_str), Some("pending"));
            }
        }

        #[tokio::test]
        async fn replayed_state_receipt_cannot_hide_a_takeover_before_reply() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let first = rig.writer();
            first
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:00:00Z")
                .await
                .unwrap();
            let original_generation = first
                .read_owned_session_state(AGENT)
                .await
                .unwrap()
                .claim
                .generation;
            let copy_dir = tempfile::tempdir().unwrap();
            let copied_store = SessionStore::open(
                &copy_dir.path().join("sessions"),
                rig.store.binding().clone(),
            )
            .unwrap();
            copied_store
                .save_checkpoint(&rig.store.load_checkpoint(AGENT).unwrap())
                .unwrap();
            let second = Writer::new(
                &copied_store,
                &rig.sink,
                SERVER,
                ACCOUNT,
                DB,
                &first.instance_id,
            );
            rig.fault(Fault::LoseStateReply);
            assert_eq!(
                first
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:01:00Z",
                        BTreeMap::from([("native.session.state".into(), json!("ended"))])
                    )
                    .await
                    .unwrap(),
                StateAction::RetryLater
            );
            rig.reset();
            rig.hosted
                .pause_state_reply
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let replay = first.claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:02:00Z");
            let takeover = async {
                rig.hosted.state_committed.notified().await;
                assert_eq!(
                    second
                        .claim_state_lease(AGENT, SERVER, "boot-2", "2026-10-17T00:02:00Z")
                        .await
                        .unwrap(),
                    StateAction::Held
                );
                assert_eq!(
                    second
                        .write_session_state(
                            AGENT,
                            SERVER,
                            "boot-2",
                            "2026-10-17T00:03:00Z",
                            BTreeMap::from([("native.session.state".into(), json!("saving"))])
                        )
                        .await
                        .unwrap(),
                    StateAction::Written
                );
                rig.hosted.release_state_reply.notify_one();
            };
            let (outcome, ()) = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::join!(replay, takeover)
            })
            .await
            .unwrap();
            assert_eq!(outcome.unwrap(), StateAction::Superseded);
            assert!(rig.store.load_checkpoint(AGENT).unwrap().lease_stopped);
            let state = second.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(state.claim.generation, original_generation + 1);
            assert_eq!(
                state.facets.get("native.session.state").map(String::as_str),
                Some("saving")
            );
        }

        #[tokio::test]
        async fn state_lease_restart_fences_a_copied_old_boot() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let current = rig.writer();
            assert_eq!(
                current
                    .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:01:00Z")
                    .await
                    .unwrap(),
                StateAction::Held
            );
            let original_generation = current
                .read_owned_session_state(AGENT)
                .await
                .unwrap()
                .claim
                .generation;
            let copy_dir = tempfile::tempdir().unwrap();
            let copied_store = SessionStore::open(
                &copy_dir.path().join("sessions"),
                rig.store.binding().clone(),
            )
            .unwrap();
            copied_store
                .save_checkpoint(&rig.store.load_checkpoint(AGENT).unwrap())
                .unwrap();
            let copied = Writer::new(
                &copied_store,
                &rig.sink,
                SERVER,
                ACCOUNT,
                DB,
                &current.instance_id,
            );
            assert_eq!(
                current
                    .claim_state_lease(AGENT, SERVER, "boot-2", "2026-10-17T00:02:00Z")
                    .await
                    .unwrap(),
                StateAction::Held
            );
            assert_eq!(
                copied
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-1",
                        "2026-10-17T00:03:00Z",
                        BTreeMap::from([("native.session.state".into(), json!("ended"))])
                    )
                    .await
                    .unwrap(),
                StateAction::Superseded
            );
            assert!(copied_store.load_checkpoint(AGENT).unwrap().lease_stopped);
            assert_eq!(
                copied
                    .claim_state_lease(AGENT, SERVER, "boot-3", "2026-10-17T01:00:00Z")
                    .await
                    .unwrap(),
                StateAction::Superseded
            );
            assert_eq!(
                current
                    .write_session_state(
                        AGENT,
                        SERVER,
                        "boot-2",
                        "2026-10-17T00:04:00Z",
                        BTreeMap::from([("native.session.state".into(), json!("saving"))])
                    )
                    .await
                    .unwrap(),
                StateAction::Written
            );
            let hosted = current.read_owned_session_state(AGENT).await.unwrap();
            assert_eq!(hosted.claim.generation, original_generation + 1);
            assert_eq!(
                hosted
                    .facets
                    .get("native.session.state")
                    .map(String::as_str),
                Some("saving")
            );
        }

        #[tokio::test]
        async fn copied_state_takeover_proposals_admit_only_one_current_writer() {
            let rig = Rig::new().await;
            rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            let first = rig.writer();
            first
                .claim_state_lease(AGENT, SERVER, "boot-1", "2026-10-17T00:01:00Z")
                .await
                .unwrap();
            let copy_dir = tempfile::tempdir().unwrap();
            let copied_store = SessionStore::open(
                &copy_dir.path().join("sessions"),
                rig.store.binding().clone(),
            )
            .unwrap();
            copied_store
                .save_checkpoint(&rig.store.load_checkpoint(AGENT).unwrap())
                .unwrap();
            let second = Writer::new(
                &copied_store,
                &rig.sink,
                SERVER,
                ACCOUNT,
                DB,
                &first.instance_id,
            );
            let state = first.read_owned_session_state(AGENT).await.unwrap();
            let next_generation = state.claim.generation.checked_add(1).unwrap();
            let prepare = |writer: &Writer<'_, GateSink>, boot: &str| {
                let owner = writer.own_writer(boot);
                writer
                    .proposal(
                        AGENT,
                        &state.identity.id,
                        ProposalKind::Lease,
                        next_generation,
                        &owner,
                        lease_takeover_arguments(
                            &state.identity.id,
                            &state.claim,
                            &owner,
                            "2026-10-17T00:02:00Z",
                        )
                        .unwrap(),
                    )
                    .unwrap()
            };
            let a = prepare(&first, "boot-2");
            let b = prepare(&second, "boot-3");
            rig.store.freeze_proposal(&a).unwrap();
            copied_store.freeze_proposal(&b).unwrap();
            let (a_result, b_result) = tokio::join!(
                first.settle_state_proposal(AGENT, &a),
                second.settle_state_proposal(AGENT, &b)
            );
            let outcomes = [a_result.unwrap(), b_result.unwrap()];
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|&&r| r == StateAction::Settled)
                    .count(),
                1
            );
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|&&r| r == StateAction::Superseded)
                    .count(),
                1
            );
            assert_eq!(
                first
                    .read_owned_session_state(AGENT)
                    .await
                    .unwrap()
                    .claim
                    .generation,
                next_generation
            );
        }

        #[tokio::test]
        async fn identity_recovery_preserves_lost_checkpoint_fence() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            let req = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "pending");
            rig.store.freeze_spool(&req, AGENT).unwrap();
            std::fs::remove_file(
                rig._temp
                    .path()
                    .join("sessions")
                    .join(format!("{AGENT}.json")),
            )
            .unwrap();
            assert!(needs_full_alignment(&rig.store, AGENT).unwrap());

            // The normal restart order resolves identity before sending the spool.
            assert_eq!(
                rig.ensure("renamed", "boot-2", "2026-10-18T00:00:00Z")
                    .await,
                EnsureOutcome::Existing(id.clone())
            );
            // Reopening proves that the identity write retained a durable fence.
            let reopened = open_store(rig._temp.path());
            let cp = reopened.load_checkpoint(AGENT).unwrap();
            assert!(cp.needs_realign);
            assert_eq!(cp.folder_id.as_deref(), Some(id.folder_id.as_str()));
            assert!(reopened.has_spool(AGENT).unwrap());
            // A fenced spool survives on disk but is intentionally not actionable.
            assert!(reopened.load_spool(AGENT).unwrap().is_none());
            let before = rig.hosted.received.lock().unwrap().len();
            let writer = Writer::new(&reopened, &rig.sink, SERVER, ACCOUNT, DB, "inst-1");
            assert!(writer.send_next(AGENT, SERVER, &cursor()).await.is_err());
            assert_eq!(rig.hosted.received.lock().unwrap().len(), before);
        }

        #[tokio::test]
        async fn uncertain_retry_resends_identical_bytes_once() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            let req = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "hello");
            let key = req.key.clone();
            rig.store.freeze_spool(&req, AGENT).unwrap();
            // The write applies; the reply is lost.
            rig.fault(Fault::LoseReply);
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::RetryLater
            );
            assert!(rig.store.load_spool(AGENT).unwrap().is_some());
            assert_eq!(rig.store.load_checkpoint(AGENT).unwrap().head_pos, None);
            // The retry replays the same key: committed once, no duplicate.
            rig.reset();
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::Advanced { pos: 1 }
            );
            let steps = rig.sink.query_steps(&id.folder_id, 0).await.unwrap().steps;
            assert_eq!(steps.len(), 1, "exactly one step after retry of {key}");
            // The two attempts carried identical frozen arguments.
            // The in-call gate may retry a keyed write more than once; every
            // attempt must carry byte-identical frozen arguments.
            let sent: Vec<Value> = rig
                .hosted
                .received
                .lock()
                .unwrap()
                .iter()
                .filter(|body| {
                    body.pointer("/params/arguments/operation")
                        .and_then(Value::as_str)
                        == Some("create_record")
                        && body
                            .pointer("/params/arguments/arguments/idempotency_key")
                            .and_then(Value::as_str)
                            == Some(key.as_str())
                })
                .map(|body| {
                    body.pointer("/params/arguments/arguments")
                        .cloned()
                        .unwrap()
                })
                .collect();
            assert!(
                sent.len() >= 2,
                "at least one retry observed: {}",
                sent.len()
            );
            for args in &sent[1..] {
                assert_eq!(args, &sent[0], "retries resend identical frozen arguments");
            }
        }

        #[tokio::test]
        async fn conflict_adopts_verified_foreign_step_then_requires_alignment() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            // A foreign writer commits position 1 with different bytes.
            let fp = sample_fp("foreign body");
            let cid = chain_next(&root_cid, &fp).unwrap();
            let foreign = rig
                .hosted
                .server
                .handle_message(call(
                    "records_write",
                    "create_record",
                    json!({
                        "type":"Document","kind":"agent-session-step",
                        "home_id": id.folder_id,"name":"step","body":"foreign body",
                        "reason":"Saved agent session step",
                        "facets":{
                            "native.session.pos":1,
                            "native.session.cid":cid,
                            "native.session.parent_cid":root_cid,
                            "native.session.fp":fp,
                            "native.session.step_kind":"agent",
                            "native.session.part_index":0,
                            "native.session.occurred_at":"2026-10-17T00:00:00Z",
                        },
                        "idempotency_key": format!("nss3:{SERVER}:{AGENT}:p1"),
                    }),
                ))
                .await
                .unwrap();
            assert_ne!(foreign["result"]["isError"], true, "{foreign}");
            let ours = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "our body");
            rig.store.freeze_spool(&ours, AGENT).unwrap();
            let action = rig
                .writer()
                .send_next(AGENT, SERVER, &cursor())
                .await
                .unwrap();
            assert_eq!(
                action,
                SendAction::ConflictResolved {
                    adopted: true,
                    alignment_required: true
                }
            );
            let cp = rig.store.load_checkpoint(AGENT).unwrap();
            assert_eq!(cp.head_pos, Some(1));
            assert_eq!(cp.head_cid.as_deref(), Some(cid.as_str()));
            assert!(cp.needs_realign, "adoption always requires alignment");
            assert!(rig.store.load_spool(AGENT).unwrap().is_none());
            // A later send refuses outright until alignment runs.
            let next = freeze_at(&rig.store, &id.folder_id, 2, &cid, "next");
            rig.store.freeze_spool(&next, AGENT).unwrap();
            let err = rig
                .writer()
                .send_next(AGENT, SERVER, &cursor())
                .await
                .expect_err("alignment required");
            assert!(format!("{err:?}").contains("alignment"));
        }

        impl Rig {
            /// A direct engine call under another caller (test setup only:
            /// models a second account acting on the same database).
            async fn call_as(&self, account: &str, arguments: Value) -> Value {
                let server = ExecutorPrototypeStdioServer::new(
                    self.registry.clone(),
                    self.hosted.db.clone(),
                    McpCaller::authenticated(account),
                    None,
                )
                .await
                .unwrap();
                server
                    .handle_message(call("records_write", "create_record", arguments))
                    .await
                    .unwrap()
            }

            async fn bind_account(&self, account: &str, name: &str) -> String {
                let person = uuid::Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id,persistence)
                     VALUES (?,'Entity','person',?,?,?,'enduring')",
                )
                .bind(&person)
                .bind(name)
                .bind(crate::schema::UNFILED_RECORD_ID)
                .bind(crate::schema::ROOT_RECORD_ID)
                .execute(self.hosted.db.write_pool())
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                     VALUES (?, 'account', ?, 1)",
                )
                .bind(&person)
                .bind(account)
                .execute(self.hosted.db.write_pool())
                .await
                .unwrap();
                person
            }
        }

        #[tokio::test]
        async fn foreign_matching_folder_and_session_refuse() {
            let rig = Rig::new().await;
            let ours = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            // A second account with a real binding creates a lookalike
            // folder carrying our exact host/agent facets, plus a record.
            rig.bind_account("acct-b", "Owner B").await;
            let lookalike = rig
                .call_as(
                    "acct-b",
                    json!({
                        "type":"Collection","kind":"folder","name":"lookalike","reason":"fixture",
                        "facets":{
                            "native.session.host_id": SERVER,
                            "native.session.agent_id": AGENT,
                        },
                    }),
                )
                .await;
            let lookalike_id = lookalike["result"]["structuredContent"]["id"]
                .as_str()
                .unwrap()
                .to_owned();
            rig.call_as(
                "acct-b",
                json!({
                    "type":"Document","kind":"agent-session","home_id": lookalike_id,
                    "name":"lookalike record","body":"x","reason":"fixture",
                }),
            )
            .await;
            // Two matching folders now exist: discovery refuses rather than
            // picking one, and nothing is written.
            let outcome = rig
                .writer()
                .ensure_session(
                    AGENT,
                    SERVER,
                    "Saved sessions — owner",
                    "t",
                    "h",
                    "p",
                    "boot-1",
                    "2026-10-17T00:00:00Z",
                )
                .await;
            let err = outcome.expect_err("ambiguous foreign lookalike must refuse");
            assert!(
                format!("{err:?}").contains("several session folders"),
                "{err:?}"
            );
            // Our own identity is untouched.
            assert_eq!(
                rig.sink
                    .find_session_record(&ours.folder_id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(ours.record_id.as_str())
            );
            // And the lookalike's owner is not our person.
            let row = rig.sink.read_row(&lookalike_id).await.unwrap();
            assert_ne!(row.owner_id.as_deref(), Some(PERSON));
        }

        #[tokio::test]
        async fn broadened_root_policy_refuses_before_any_write() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_id = rig.store.load_checkpoint(AGENT).unwrap().root_id.unwrap();
            // The owner opens the root to members: privacy is gone.
            // The owner grants a second person view: the root is no longer
            // account-only.
            let person_b = rig.bind_account("acct-b", "Owner B").await;
            let granted = rig
                .hosted
                .server
                .handle_message(call(
                    "access_admin",
                    "manage_record_policy.grant",
                    json!({
                        "record_id":root_id,
                        "subject":{"kind":"person","person_record_id":person_b},
                        "capability":"view","reason":"fixture",
                    }),
                ))
                .await
                .unwrap();
            assert_ne!(granted["result"]["isError"], true, "{granted}");
            // Consequential policy writes are plan-required: execute the
            // returned plan (never a second prepare).
            let plan = granted["result"]["structuredContent"]["next_call"]["arguments"].clone();
            let executed = rig
                .hosted
                .server
                .handle_message(json!({
                    "jsonrpc":"2.0","id":901,"method":"tools/call",
                    "params":{"name":"access_admin","arguments":{
                        "operation":"manage_record_policy.grant",
                        "plan_id": plan["plan_id"],
                        "target": plan["target"],
                        "effect_summary": plan["effect_summary"],
                        "format":"json",
                    }},
                }))
                .await
                .unwrap();
            assert_ne!(executed["result"]["isError"], true, "{executed}");
            // The grant is live: the root now has two entries.
            let view = rig.sink.read_policy(&root_id).await.unwrap();
            assert_eq!(view.entries.len(), 2, "{view:?}");
            let received_before = rig.hosted.received.lock().unwrap().len();
            let err = rig
                .writer()
                .ensure_session(
                    AGENT,
                    SERVER,
                    "Saved sessions — owner",
                    "t",
                    "h",
                    "p",
                    "boot-1",
                    "2026-10-17T00:00:00Z",
                )
                .await
                .expect_err("broadened root must refuse");
            assert!(
                format!("{err:?}").contains("more than our account"),
                "{err:?}"
            );
            // Refused before any hosted payload write.
            let wrote_after = rig
                .hosted
                .received
                .lock()
                .unwrap()
                .iter()
                .skip(received_before)
                .any(|body| {
                    body.pointer("/params/name").and_then(Value::as_str) == Some("call_executor")
                });
            assert!(!wrote_after, "refusal must precede payload writes");
            // The existing identity is unchanged.
            assert_eq!(
                rig.sink
                    .find_session_record(&id.folder_id)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(id.record_id.as_str())
            );
        }

        #[tokio::test]
        async fn owner_shared_folder_is_accepted_unchanged() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            // The owner shares the session by moving the folder into a
            // private channel: its anchor becomes the channel, not the
            // Saved-sessions root.
            let channel = rig
                .hosted
                .server
                .handle_message(call(
                    "records_write",
                    "create_record",
                    json!({
                        "type":"Collection","kind":"folder","name":"#channel","reason":"fixture",
                        "access_policy":"account_only",
                    }),
                ))
                .await
                .unwrap();
            let channel_id = channel["result"]["structuredContent"]["id"]
                .as_str()
                .unwrap()
                .to_owned();
            rig.hosted
                .server
                .handle_message(call(
                    "records_write",
                    "update_record",
                    json!({
                        "id": id.folder_id, "home_id": channel_id, "reason":"fixture",
                    }),
                ))
                .await
                .unwrap();
            // The shared folder now inherits the channel anchor.
            let policy = rig.sink.read_policy(&id.folder_id).await.unwrap();
            assert_eq!(policy.mode, "inherit");
            assert_eq!(policy.anchor_id, channel_id);
            // Ensure accepts the existing identity unchanged: same folder,
            // same record, still homed in the channel.
            let outcome = rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await;
            match outcome {
                EnsureOutcome::Existing(id2) => {
                    assert_eq!(id2.folder_id, id.folder_id);
                    assert_eq!(id2.record_id, id.record_id);
                }
                EnsureOutcome::Created(_) => panic!("must not create a second identity"),
            }
            let row = rig.sink.read_row(&id.folder_id).await.unwrap();
            assert_eq!(row.home_id.as_deref(), Some(channel_id.as_str()));
            assert_eq!(
                rig.sink
                    .find_session_folder(SERVER, AGENT)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(id.folder_id.as_str()),
                "the shared folder was not duplicated or re-homed"
            );
        }

        #[tokio::test]
        async fn transport_faults_stop_without_losing_the_spool() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            let req = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "hello");
            rig.store.freeze_spool(&req, AGENT).unwrap();
            // Auth refusal stops all writes and keeps the spool; no failover.
            rig.fault(Fault::Auth);
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::StoppedAuth
            );
            assert!(rig.store.load_spool(AGENT).unwrap().is_some());
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::StoppedAuth
            );
            // Read-only is a truthful pause, never a quarantine.
            rig.fault(Fault::ReadOnly);
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::RetryLater
            );
            assert!(!rig.store.load_checkpoint(AGENT).unwrap().needs_realign);
            // A gateway outage is retryable.
            rig.fault(Fault::Gateway);
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::RetryLater
            );
            // Recovery commits the same frozen bytes.
            rig.reset();
            assert_eq!(
                rig.writer()
                    .send_next(AGENT, SERVER, &cursor())
                    .await
                    .unwrap(),
                SendAction::Advanced { pos: 1 }
            );
            let steps = rig.sink.query_steps(&id.folder_id, 0).await.unwrap().steps;
            assert_eq!(steps.len(), 1);
        }

        #[tokio::test]
        async fn binding_and_server_fence_precede_every_send() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            let req = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "hello");
            rig.store.freeze_spool(&req, AGENT).unwrap();
            let received_before = rig.hosted.received.lock().unwrap().len();
            // A reset daemon home is a new host: refuse before sending.
            let err = rig
                .writer()
                .send_next(AGENT, "srv-reset", &cursor())
                .await
                .expect_err("server fence");
            assert!(format!("{err:?}").contains("server-id changed"));
            // A foreign account in the same store refuses too.
            let rogue = Writer::new(&rig.store, &rig.sink, SERVER, "acct-b", DB, "inst-1");
            assert!(rogue.send_next(AGENT, SERVER, &cursor()).await.is_err());
            assert_eq!(rig.hosted.received.lock().unwrap().len(), received_before);
            assert!(rig.store.load_spool(AGENT).unwrap().is_some());
        }

        #[tokio::test]
        async fn transport_reads_parse_engine_shapes() {
            let rig = Rig::new().await;
            let id = match rig.ensure("t", "boot-1", "2026-10-17T00:00:00Z").await {
                EnsureOutcome::Created(id) | EnsureOutcome::Existing(id) => id,
            };
            let root_cid = chain_root(SERVER, AGENT).unwrap();
            let req = freeze_at(&rig.store, &id.folder_id, 1, &root_cid, "hello");
            rig.store.freeze_spool(&req, AGENT).unwrap();
            rig.writer()
                .send_next(AGENT, SERVER, &cursor())
                .await
                .unwrap();
            // Query → hydrate → strict step parse, through the real sink.
            let steps = rig.sink.query_steps(&id.folder_id, 0).await.unwrap().steps;
            assert_eq!(steps.len(), 1);
            let found = &steps[0];
            assert_eq!(found.pos, 1);
            assert_eq!(found.body, "hello");
            assert_eq!(found.cid, req.facets.cid);
            assert_eq!(found.parent_cid, root_cid);
            assert_eq!(found.part_index, 0);
            assert!(!found.owner_id.is_empty());
            // Full-detail history: create evidence by our credential.
            let events = rig.sink.step_history(&found.record_id).await.unwrap();
            assert_eq!(events[0].etype, "record.created");
            assert_eq!(events[0].actor.as_deref(), Some(ACCOUNT));
            assert_eq!(
                events[0].payload.get("body").and_then(Value::as_str),
                Some("hello")
            );
            // Policy parse retains every authority field.
            let root_id = rig.store.load_checkpoint(AGENT).unwrap().root_id.unwrap();
            let view = rig.sink.read_policy(&root_id).await.unwrap();
            assert_eq!(view.record_id, root_id);
            assert_eq!(view.target_id, root_id);
            assert_eq!(view.anchor_id, root_id);
            assert!(view.policy_administration_authorized);
            assert!(view.entries[0].person_id.is_some());
        }
    }
}
