//! `manage_alpha_tabs` — personal alpha tab installs (task `26ba75a`,
//! design `docs/alpha-tab-install-state.md`).
//!
//! One projection row per installed tab per account (`alpha_tab_installs`),
//! folded from the canonical control log (`alpha_tab.installed | disabled |
//! restored | removed` under aggregate kind `alpha_tab`; see
//! `crate::control`). Writes go through `append_control_event_in` inside the
//! tool's write transaction, so a persisted event without its projection is
//! unrepresentable.
//!
//! Patterns reused (precedent only — the K3 `surface_binding` links are not
//! extended, design §8):
//! - `src/mcp/tools/surface_bindings.rs`: `artifact_status_in` live
//!   Document kind:artifact check, `expected_target_id` CAS shape,
//!   View-on-target at bind time with honest degradation on the read path.
//! - `src/mcp/tools/instructions.rs`: `append_authored` control append,
//!   `prior_event` same-key idempotent retry, `caller.credential()` as the
//!   database-local account.
//!
//! Honesty boundary: list/inspect never return a launch URL and keep
//! `resolves:false`. The explicit `launch` action checks adoption, authority,
//! exact source event, and digest, then issues pinned sample-only HTML bytes.
//! The explicit `live_read` action runs the one consented host read and
//! returns live rows to the tool caller only (top-level `records` shim;
//! `inputs.items` stays empty, effects unwired); no live bytes reach the
//! frame. See the launch-ticket doc.
//!
//! Launch-bind slice 2 (`docs/alpha-tab-install-slice2.md`) adds the exact
//! canonical digest (`alpha-tab-digest.v1`), the portable source-revision
//! identity, and a read-only `launch_binding` verdict on every entry. The
//! verdict evaluates the full gate chain and fails closed with named
//! reasons; it mints no frame ticket and changes no existing field.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use turso_parser::ast::{
    Cmd, Expr, JoinConstraint, JoinOperator, JoinType, OneSelect, ResultColumn, SelectTable, Stmt,
};
use turso_parser::parser::Parser;
use uuid::Uuid;

use crate::act::ActAllocation;
use crate::authorization::Capability;
use crate::control::{
    alpha_tab_aggregate_id, alpha_tab_order_aggregate_id, append_control_event_in,
    AlphaTabAdoptPayload, AlphaTabOrderPayload, AlphaTabStatePayload, ControlEventPayload,
    NewControlEvent, ALPHA_TAB_ADOPTION_SHELL_AUTO, ALPHA_TAB_ADOPTION_VERIFIED,
    ALPHA_TAB_AUTHORED_FIELD_MAX_CHARS, ALPHA_TAB_ORDER_MAX_ENTRIES, ALPHA_TAB_REQUEST_MAX_CHARS,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::generated::kinds::CoreKind;
use crate::need_metrics::{PullKind, VmWorkObserver};
use crate::need_subscriptions::{
    params_digest, ConnectionToken, SubscribeRefusal, SubscriptionId, SurfaceBinding,
};
use crate::query::sql::SqlResult;
use crate::query::sql_contract::QuerySqlRequest;
use crate::query::QueryPrincipal;
use crate::realtime::RealtimeHub;

use super::super::registry::{Caller, ToolRegistry, VerifiedAlphaTabPreview};
use super::super::ToolKind;
use super::effect_admission::{
    AdmissionRefusal, InactiveState, PinMismatchKind, ScopeUnsupportedReason,
    SourceUnresolvedReason, TargetUnavailableReason, UnconsentedReason,
};
use super::{echo_act, parse_args, require_nonblank_reason};

// Trusted-host services; generic tool actions do not offer feature authority.
#[doc(hidden)]
pub mod adoption_intent;
mod batch_read;
mod gate_cache;
pub use batch_read::LiveReadItem;
#[doc(hidden)]
pub mod hosted_producer;
#[doc(hidden)]
pub use gate_cache::holds as gate_cache_holds;

const TOOL: &str = "manage_alpha_tabs";

/// The stored-digest launch honesty marker: every entry carries it so no
/// caller can mistake a stored pin for an enforced one.
const DIGEST_BINDING: &str = "stored-not-enforced";

/// Canonical digest version for alpha-tab launch binding (task
/// `26ba75a`, `docs/alpha-tab-install-slice2.md` §1):
/// `alpha-tab-digest.v1` binds bundle bytes + declared needs/effects +
/// runtime. Every `launch_binding` verdict names it so no caller can
/// mistake which algorithm a receipt was recomputed under.
pub const ALPHA_TAB_DIGEST_VERSION: &str = "alpha-tab-digest.v1";

/// Default alpha tab-strip order (task `c5d3820`): the shell built-ins in
/// strip order. The shell owns tab labels; the backend owns this default
/// sequence, returned by `list`/`inspect` until the account stores its own
/// order with the `reorder` action. Built-ins and installs interleave freely
/// in a stored order — there is no built-ins-first rule once the viewer (or
/// an agent on their behalf) has chosen an order.
pub const ALPHA_TAB_DEFAULT_ORDER: [&str; 4] = ["agents", "folders", "tasks", "graph"];

/// Installed tabs address as `pending:<package>` inside a stored order, the
/// same id space the shell uses for its trailing tab registry.
pub const ALPHA_TAB_PENDING_PREFIX: &str = "pending:";

/// The single consented live-read need this slice executes (task `26ba75a`,
/// `docs/alpha-tab-live-read-revocation-design.md` §2). It is a semantic need
/// string from the install's consented declaration — not a port name and not
/// an existing query API. Any install whose consented `needs` omits it
/// refuses `live_read` with `undeclared_need`.
pub const ATTENTION_QUERY_NEED: &str = "attention.query.v1";

/// Declared on-request read: governed full-text search (task `1044bb6`,
/// candidate primitive P2 in `73a9513`). Host-named, so any package may
/// declare it and no package holds a search-only privilege. The host runs
/// the ordinary `search` tool handler under the viewer's authority, so the
/// frame sees exactly what the viewer's own search would show.
pub const RECORDS_SEARCH_NEED: &str = "records.search.v1";

/// Declared on-request read: resolve one typed record reference (short hex
/// or full id) through the ordinary `get_record` handler, returning display
/// fields only — never a body, children, or links.
pub const RECORDS_RESOLVE_REFERENCE_NEED: &str = "records.resolve_reference.v1";

/// Push-only inbound reveal opt-in (task `fb8564c`, design `e839b03` §3): a
/// plain string need an install consents to so the host may reveal one
/// already viewer-authorized record to the frame. It is never readable via
/// `live_read`: an explicit read of it refuses `undeclared_need` even when
/// consented, before any parameter parsing. Admission runs only through the
/// `admit_reveal_target` action, which returns the canonical target id with
/// pin provenance and grants nothing.
pub const SURFACE_REVEAL_NEED: &str = "surface.reveal.v1";

/// Needs that are consent-gated but never readable. Membership-only; the
/// shared `declared_need_gates_in` stays untouched and this list is checked
/// by the string-need read path after membership, before parameters.
const PUSH_ONLY_NEEDS: &[&str] = &[SURFACE_REVEAL_NEED];

/// The need names `parse_sql_need_entry` refuses as SQL keys. A read of one
/// of them can never address a SQL need, so `do_declared_read` gates it on
/// the read-only pool; any other name gates on the governed pool its SQL
/// would run on.
const HOST_READ_NEEDS: [&str; 6] = [
    ATTENTION_QUERY_NEED,
    RECORDS_SEARCH_NEED,
    RECORDS_RESOLVE_REFERENCE_NEED,
    CANVAS_SCENE_NEED,
    RECORD_CHANGES_NEED,
    ARTIFACT_RENDER_NEED,
];

/// Bounds on `records.search.v1` parameters. The limit matches alpha's shell
/// search, so the package cannot page further than the shell does.
pub const SEARCH_QUERY_MAX_CHARS: usize = 200;
pub const SEARCH_LIMIT_MAX: i64 = 30;

/// Bound on `records.resolve_reference.v1`'s reference parameter.
pub const REFERENCE_MAX_CHARS: usize = 128;

/// Declared on-request read: one bounded page of an existing Canvas v1 scene
/// (task `ab9463e`, design `638bc12` slice 1). Host-named and read-only. The
/// host runs the ordinary `read_canvas.get_scene` read under the viewer's
/// authority, windowed, so geometry, `z`, `parent`, kinds and record-card
/// redaction are exactly what the viewer's own `get_scene` would show.
/// Canvas presence is not part of it, and no effect writes through it.
pub const CANVAS_SCENE_NEED: &str = "canvas.scene.v1";

/// Bounds on `canvas.scene.v1` parameters. A scene holds at most 5,000 live
/// objects; a page holds at most this many, and `truncated` says honestly
/// when more remain.
pub const CANVAS_SCENE_LIMIT_MAX: i64 = 500;
pub const CANVAS_ID_MAX_CHARS: usize = 128;

/// Size budget for one whole `canvas.scene.v1` page, in the frame bridge's
/// own measure: `JSON.stringify(...).length`, which is UTF-16 code units of
/// the ECMAScript serialisation. The bridge answers any read whose answer
/// passes 1,048,576 of those with `too_large` (`html.rs` `settleRead`), so a
/// page stops early, flagged `truncated`, before it passes this. The
/// remaining quarter covers the host's wrapper around the page.
pub const CANVAS_SCENE_PAGE_MAX_CHARS: usize = 768 * 1024;

/// Declared on-request read: one bounded page of one record's changes,
/// newest first (task `68b48e5`, slice A). Host-named and read-only. The
/// host reads the record's history as `get_history {detail: metadata}` does
/// under the viewer's authority, so visibility, the actor rule and
/// `changed_fields` are exactly the viewer's own; it adds bounded scalar
/// before/after values and body sizes, and never a payload or a sequence.
pub const RECORD_CHANGES_NEED: &str = "records.changes.v1";

/// Bounds on `records.changes.v1` parameters. A page holds at most this many
/// events, and `complete` says honestly whether older ones remain.
pub const RECORD_CHANGES_LIMIT_MAX: i64 = 50;
pub const RECORD_ID_MAX_CHARS: usize = 128;

/// Size budget for one whole `records.changes.v1` page, in the bridge's
/// measure, as [`CANVAS_SCENE_PAGE_MAX_CHARS`]. Every value on a page is
/// already bounded, so this only ever shortens a page, flagged incomplete.
pub const RECORD_CHANGES_PAGE_MAX_CHARS: usize = 768 * 1024;

/// Declared on-request read: the server-rendered safe tree of one MDX
/// artifact (task `51e8571`, slice A). Host-named and read-only. The host
/// runs the ordinary live `render_artifact` under the viewer's authority,
/// never `as_of`, so the tree, the bound records in it and any refusal are
/// exactly what the viewer's own render would show. Only `native.mdx.v1`
/// and `native.mdx.v2` artifacts render; HTML tab packages, boards and every
/// other record refuse. The answer is display-only: interaction
/// declarations, CAS tokens, editability and the input envelope never reach
/// the frame.
pub const ARTIFACT_RENDER_NEED: &str = "artifact.render.v1";

/// Size budget for one whole `artifact.render.v1` answer, in the bridge's
/// measure, as [`CANVAS_SCENE_PAGE_MAX_CHARS`]. A render that would pass it
/// is refused `too_large` rather than cut, because half a document is not a
/// document.
pub const ARTIFACT_RENDER_RESULT_MAX_CHARS: usize = 768 * 1024;

/// Where a `records.changes.v1` page resumes, sealed.
///
/// The cursor is the id of the last event a page carried, sealed with
/// XChaCha20-Poly1305 under a process key used for nothing else, with a
/// fresh random 24-byte nonce, and with the need, the install generation and
/// the record as associated data: `hex(nonce || ciphertext || tag)`. A tab
/// can only hand back a cursor a page of the same record and install gave
/// it. Anything else, whatever event it names and whether or not that event
/// exists, fails authentication and is refused identically; the plaintext
/// is read only after authentication succeeds. A cursor only ever names an
/// event the tab was shown, so confidentiality is not what the seal is for;
/// it is kept because a vetted AEAD is the simplest way to be opaque and
/// unforgeable at once. No sequence is inside. The key is random per
/// process, so a cursor from before a restart is refused and the tab reads
/// from the top.
pub struct RecordChangesCursor;

impl RecordChangesCursor {
    const NONCE_BYTES: usize = 24;
    const TAG_BYTES: usize = 16;
    const MAX_EVENT_ID_BYTES: usize = 128;
    /// Longest cursor string a page hands out, in hex characters.
    pub const MAX_CHARS: usize =
        2 * (Self::NONCE_BYTES + Self::MAX_EVENT_ID_BYTES + Self::TAG_BYTES);

    /// Whether `cursor` has a sealed cursor's shape. Pure, so parameter
    /// parsing can refuse garbage before any gate runs; it says nothing
    /// about whether the cursor opens.
    fn well_formed(cursor: &str) -> bool {
        cursor.len() > 2 * (Self::NONCE_BYTES + Self::TAG_BYTES)
            && cursor.len() <= Self::MAX_CHARS
            && cursor.len().is_multiple_of(2)
            && cursor.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    /// The cursor key: random per process, and separate from the canvas
    /// revision key so the two constructions never share key material.
    fn cipher() -> &'static chacha20poly1305::XChaCha20Poly1305 {
        use chacha20poly1305::KeyInit;
        static CIPHER: OnceLock<chacha20poly1305::XChaCha20Poly1305> = OnceLock::new();
        CIPHER.get_or_init(|| {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            chacha20poly1305::XChaCha20Poly1305::new((&key).into())
        })
    }

    fn associated_data(install_event_id: &str, record_id: &str) -> Vec<u8> {
        json!([RECORD_CHANGES_NEED, "cursor", install_event_id, record_id])
            .to_string()
            .into_bytes()
    }

    fn seal(install_event_id: &str, record_id: &str, event_id: &str) -> String {
        use chacha20poly1305::aead::{Aead, Payload};
        use rand::RngCore;
        let mut nonce = [0u8; Self::NONCE_BYTES];
        rand::rng().fill_bytes(&mut nonce);
        let sealed = Self::cipher()
            .encrypt(
                &chacha20poly1305::XNonce::from(nonce),
                Payload {
                    msg: event_id.as_bytes(),
                    aad: &Self::associated_data(install_event_id, record_id),
                },
            )
            .expect("XChaCha20-Poly1305 encryption of a short message cannot fail");
        format!("{}{}", hex::encode(nonce), hex::encode(sealed))
    }

    /// The event id inside a cursor this install sealed for this record, or
    /// `None` for anything else.
    fn open(cursor: &str, install_event_id: &str, record_id: &str) -> Option<String> {
        use chacha20poly1305::aead::{Aead, Payload};
        if !Self::well_formed(cursor) {
            return None;
        }
        let bytes = hex::decode(cursor).ok()?;
        let (nonce, sealed) = bytes.split_at(Self::NONCE_BYTES);
        let nonce: [u8; Self::NONCE_BYTES] = nonce.try_into().ok()?;
        let plaintext = Self::cipher()
            .decrypt(
                &chacha20poly1305::XNonce::from(nonce),
                Payload {
                    msg: sealed,
                    aad: &Self::associated_data(install_event_id, record_id),
                },
            )
            .ok()?;
        // Authenticated: the plaintext is one this process sealed.
        String::from_utf8(plaintext).ok()
    }
}

/// Declared snapshot SQL need: a package-pinned fixed read-only statement
/// executed on every snapshot `live_read` through the ordinary `query_sql`
/// handler under the viewer's authority.
pub const SQL_SNAPSHOT_NEED: &str = "sql.snapshot.v1";

/// Bounds on `sql.snapshot.v1` declaration entries.
pub const SQL_SNAPSHOT_MAX_NEEDS: usize = 8;
pub const SQL_SNAPSHOT_KEY_MAX_CHARS: usize = 40;
pub const SQL_SNAPSHOT_LABEL_MAX_CHARS: usize = 120;
pub const SQL_SNAPSHOT_SQL_MAX_BYTES: usize = 4096;

/// Per-need row cap for one snapshot SQL execution. Truncation (not refusal):
/// the delivered result carries `truncated: true` plus the ordinary
/// `truncation_hint`, so a lane that grows past the cap stays available and
/// parity with a direct `query_sql` call holds for every result within the
/// cap. Refusal would turn data growth into an outage and force a reinstall.
pub const SQL_SNAPSHOT_ROW_CAP: usize = 200;

/// The fields of one delivered `sql.snapshot.v1` result, in the order
/// [`execute_sql_need`] emits them. The kit mirrors this list
/// (`limits.json` `reads.sql_result_fields`) so an authored package and its
/// lint agree on what a result carries. `truncated` says the delivered rows
/// are not all the rows; `row_count_complete` says whether `row_count` is
/// the true total (false exactly when `query_sql` itself stopped at its own
/// row bound, so `row_count` is a floor). A package that shows rows must
/// surface both, never "of N" when `row_count_complete` is false.
pub const SQL_NEED_RESULT_FIELDS: &[&str] = &[
    "label",
    "columns",
    "rows",
    "row_count",
    "row_count_complete",
    "truncated",
    "truncation_hint",
    "now_ms_ms",
    "time_dependent",
    "assumed_order",
];

/// Bounds on `sql.snapshot.v1` parameter declarations.
pub const SQL_SNAPSHOT_MAX_PARAMS: usize = 8;
pub const SQL_PARAM_TEXT_DEFAULT_MAX_LEN: usize = 256;
pub const SQL_PARAM_TEXT_HARD_CAP: usize = 1024;

/// One declared SQL parameter. The ordered `params` array defines the
/// positional `?N` binding (`params[0]` binds `?1`): `query_sql` admits only
/// positional placeholders, so names are consent/schema labels, not SQL
/// syntax. `max_len` is resolved (default 256) for `text`; `required`
/// defaults to true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlParam {
    pub name: String,
    pub param_type: SqlParamType,
    pub max_len: usize,
    pub required: bool,
}

/// Declared SQL parameter type: `text`, `integer`, or `timestamp_ms`.
/// `timestamp_ms` is a JSON integer of UTC epoch millis and binds as an
/// integer (decimal string), matching the `*_ms` integer companions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlParamType {
    Text,
    Integer,
    TimestampMs,
}

impl SqlParamType {
    fn as_str(&self) -> &'static str {
        match self {
            SqlParamType::Text => "text",
            SqlParamType::Integer => "integer",
            SqlParamType::TimestampMs => "timestamp_ms",
        }
    }

    fn parse(value: &str) -> Option<SqlParamType> {
        match value {
            "text" => Some(SqlParamType::Text),
            "integer" => Some(SqlParamType::Integer),
            "timestamp_ms" => Some(SqlParamType::TimestampMs),
            _ => None,
        }
    }
}

/// One declared snapshot SQL need, already bounded and install-validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlNeed {
    pub key: String,
    pub label: String,
    pub sql: String,
    pub params: Vec<SqlParam>,
    /// Logical tables observed by the same authoritative SQL validator used
    /// at install. Scheduling only; never a viewer-visible dirty signal.
    pub relations: std::collections::BTreeSet<String>,
}

/// Key shape `^[a-z][a-z0-9_.]{0,39}$`: lowercase start, then lowercase
/// alphanumerics, underscore or dot, at most 40 characters total.
/// `pub(crate)` so the `effect_bounds` seam shares the one definition.
pub(crate) fn valid_sql_need_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > SQL_SNAPSHOT_KEY_MAX_CHARS {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'.'
    })
}

/// Param name shape `^[a-z][a-z0-9_]{0,31}$`: lowercase start, then
/// lowercase alphanumerics or underscore, at most 32 characters total.
fn valid_sql_param_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Parse and bound one declared SQL parameter. Pure. Every refusal names
/// `invalid_sql_need`.
fn parse_sql_param_entry(entry: &Value) -> std::result::Result<SqlParam, String> {
    let object = entry
        .as_object()
        .ok_or_else(|| format!("{TOOL}: sql param entry must be an object [invalid_sql_need]"))?;
    let has_max_len = object.contains_key("max_len");
    let has_required = object.contains_key("required");
    let allowed = 2 + usize::from(has_max_len) + usize::from(has_required);
    if object.len() != allowed || !object.contains_key("name") || !object.contains_key("type") {
        return Err(format!(
            "{TOOL}: sql param entry must hold exactly 'name', 'type' with optional 'max_len' and 'required' [invalid_sql_need]"
        ));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql param 'name' must be a string [invalid_sql_need]"))?;
    if !valid_sql_param_name(name) {
        return Err(format!(
            "{TOOL}: sql param 'name' must match ^[a-z][a-z0-9_]{{0,31}}$ [invalid_sql_need]"
        ));
    }
    let type_str = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql param 'type' must be a string [invalid_sql_need]"))?;
    let param_type = SqlParamType::parse(type_str).ok_or_else(|| {
        format!("{TOOL}: sql param 'type' must be one of text, integer, timestamp_ms [invalid_sql_need]")
    })?;
    let max_len = match object.get("max_len") {
        None => SQL_PARAM_TEXT_DEFAULT_MAX_LEN,
        Some(value) => {
            let raw = value.as_u64().ok_or_else(|| {
                format!("{TOOL}: sql param 'max_len' must be an integer [invalid_sql_need]")
            })?;
            // Bound before narrowing: `as usize` truncates on sub-64-bit
            // targets, so an over-cap input must refuse here on the `u64`,
            // not after the cast.
            if raw == 0 || raw > SQL_PARAM_TEXT_HARD_CAP as u64 {
                return Err(format!(
                    "{TOOL}: sql param 'max_len' must be 1..=1024 [invalid_sql_need]"
                ));
            }
            raw as usize
        }
    };
    if param_type != SqlParamType::Text && has_max_len {
        return Err(format!(
            "{TOOL}: sql param 'max_len' applies only to text params [invalid_sql_need]"
        ));
    }
    let required = match object.get("required") {
        None => true,
        Some(Value::Bool(required)) => *required,
        Some(_) => {
            return Err(format!(
                "{TOOL}: sql param 'required' must be a boolean [invalid_sql_need]"
            ));
        }
    };
    Ok(SqlParam {
        name: name.to_string(),
        param_type,
        max_len,
        required,
    })
}

// Inert authoring/digest vocabulary only. These constants are deliberately
// absent from host string-need registries and declared-read dispatch.
pub(crate) const BODY_READ_NEED: &str = "records.body.read.v1";
pub(crate) const BODY_READ_SCOPE: &str = "viewer-visible-current-bodies";

enum DeclarationNeed<'a> {
    Name(&'a str),
    Sql(SqlNeed),
    BodyRead,
}

fn classify_declaration_need(entry: &Value) -> std::result::Result<DeclarationNeed<'_>, String> {
    if let Some(name) = entry.as_str() {
        return Ok(DeclarationNeed::Name(name));
    }
    if entry.get("need").and_then(Value::as_str) == Some(BODY_READ_NEED) {
        let valid = entry.as_object().is_some_and(|object| {
            object.len() == 2
                && object.get("scope").and_then(Value::as_str) == Some(BODY_READ_SCOPE)
        });
        if !valid {
            return Err(format!(
                "{TOOL}: body read descriptor must hold exactly 'need' and 'scope' with scope '{BODY_READ_SCOPE}' [invalid_body_read_need]"
            ));
        }
        return Ok(DeclarationNeed::BodyRead);
    }
    parse_sql_need_entry(entry).map(DeclarationNeed::Sql)
}

/// Check only the newly introduced descriptor constraints. With no descriptor,
/// standalone digest inputs retain their historical acceptance semantics.
pub(crate) fn body_read_descriptor_in(declaration: &Value) -> std::result::Result<bool, String> {
    let Some(entries) = declaration.get("needs").and_then(Value::as_array) else {
        return Ok(false);
    };
    if !entries
        .iter()
        .any(|entry| entry.get("need").and_then(Value::as_str) == Some(BODY_READ_NEED))
    {
        return Ok(false);
    }
    if entries.len() > 64 {
        return Err(format!(
            "{TOOL}: declaration 'needs' holds at most 64 entries [invalid_body_read_need]"
        ));
    }
    let mut count = 0;
    for entry in entries {
        match classify_declaration_need(entry)? {
            DeclarationNeed::BodyRead => count += 1,
            DeclarationNeed::Name(BODY_READ_NEED) => {
                return Err(format!(
                "{TOOL}: body read descriptor duplicates a string need [invalid_body_read_need]"
            ))
            }
            DeclarationNeed::Sql(need) if need.key == BODY_READ_NEED => {
                return Err(format!(
                    "{TOOL}: body read descriptor duplicates an SQL key [invalid_body_read_need]"
                ))
            }
            _ => {}
        }
    }
    if count != 1 {
        return Err(format!(
            "{TOOL}: declaration holds at most one body read descriptor [invalid_body_read_need]"
        ));
    }
    Ok(true)
}

/// Pure heterogeneous target scan. A descriptor never becomes an effect target.
pub(crate) fn parse_effect_target_need(
    entry: &Value,
) -> std::result::Result<Option<SqlNeed>, String> {
    match classify_declaration_need(entry)? {
        DeclarationNeed::Sql(need) => Ok(Some(need)),
        DeclarationNeed::BodyRead | DeclarationNeed::Name(_) => Ok(None),
    }
}

/// Parse and bound one `sql.snapshot.v1` declaration entry. Pure, so the
/// bounds are unit-testable without a database. Every refusal names
/// `invalid_sql_need`.
pub(crate) fn parse_sql_need_entry(entry: &Value) -> std::result::Result<SqlNeed, String> {
    let object = entry.as_object().ok_or_else(|| {
        format!("{TOOL}: declaration 'needs' sql entry must be an object [invalid_sql_need]")
    })?;
    let has_params = object.contains_key("params");
    let allowed = 4 + usize::from(has_params);
    if object.len() != allowed
        || object.get("need").and_then(Value::as_str) != Some(SQL_SNAPSHOT_NEED)
        || !object.contains_key("key")
        || !object.contains_key("label")
        || !object.contains_key("sql")
    {
        return Err(format!(
            "{TOOL}: declaration 'needs' sql entry must hold exactly 'need', 'key', 'label' and 'sql' with optional 'params' [invalid_sql_need]"
        ));
    }
    let key = object
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql need 'key' must be a string [invalid_sql_need]"))?;
    if !valid_sql_need_key(key) {
        return Err(format!(
            "{TOOL}: sql need 'key' must match ^[a-z][a-z0-9_.]{{0,39}}$ [invalid_sql_need]"
        ));
    }
    // SQL keys share the `live_read` need namespace with the string needs,
    // so a key that collides with an on-request/host need name would make
    // dispatch ambiguous. Refuse at install; the digest fails closed too.
    if key == ATTENTION_QUERY_NEED
        || key == RECORDS_SEARCH_NEED
        || key == RECORDS_RESOLVE_REFERENCE_NEED
        || key == CANVAS_SCENE_NEED
        || key == RECORD_CHANGES_NEED
        || key == ARTIFACT_RENDER_NEED
    {
        return Err(format!(
            "{TOOL}: sql need 'key' must not collide with a host need name [invalid_sql_need]"
        ));
    }
    let label = object
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql need 'label' must be a string [invalid_sql_need]"))?;
    if label.is_empty() || label.chars().count() > SQL_SNAPSHOT_LABEL_MAX_CHARS {
        return Err(format!(
            "{TOOL}: sql need 'label' must be 1..=120 characters [invalid_sql_need]"
        ));
    }
    let sql = object
        .get("sql")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{TOOL}: sql need 'sql' must be a string [invalid_sql_need]"))?;
    if sql.is_empty() || sql.len() > SQL_SNAPSHOT_SQL_MAX_BYTES {
        return Err(format!(
            "{TOOL}: sql need 'sql' must be 1..=4096 bytes [invalid_sql_need]"
        ));
    }
    let params = match object.get("params") {
        None => Vec::new(),
        Some(Value::Array(entries)) => {
            if entries.len() > SQL_SNAPSHOT_MAX_PARAMS {
                return Err(format!(
                    "{TOOL}: sql need '{key}' holds at most 8 params [invalid_sql_need]"
                ));
            }
            let mut parsed: Vec<SqlParam> = Vec::with_capacity(entries.len());
            for entry in entries {
                parsed.push(parse_sql_param_entry(entry)?);
            }
            let mut names: Vec<&str> = parsed.iter().map(|param| param.name.as_str()).collect();
            names.sort_unstable();
            for window in names.windows(2) {
                if window[0] == window[1] {
                    return Err(format!(
                        "{TOOL}: sql need '{key}' param '{}' is duplicated [invalid_sql_need]",
                        window[0]
                    ));
                }
            }
            parsed
        }
        Some(_) => {
            return Err(format!(
                "{TOOL}: sql need 'params' must be an array [invalid_sql_need]"
            ));
        }
    };
    // `crate::query::sql::validate` is the same validator the ordinary
    // `query_sql` path runs (single read-only statement over the public
    // relations); it executes nothing. The ordered `params` array defines
    // the positional `?N` binding (`params[0]` binds `?1`), so the exact-set
    // check enforces both directions: no undeclared placeholder, and no
    // declared-but-unused param.
    // E2: an unordered top-level LIMIT still refuses, but names the exact
    // default the ad-hoc path would apply.
    crate::query::sql::validate(sql).map_err(|error| {
        let mut refusal = format!(
            "{TOOL}: sql need '{key}' is not an admitted read-only query: {error} [invalid_sql_need]"
        );
        if error.to_string().contains("LIMIT without ORDER BY") {
            if let Some(repair) = crate::query::sql::default_order_repair(sql) {
                refusal.push_str(&format!("; {repair}"));
            }
        }
        refusal
    })?;
    crate::query::sql_contract::check_positional_arguments(
        crate::query::sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
        params.len(),
    )
    .map_err(|error| {
        if params.is_empty() {
            format!(
                "{TOOL}: sql need '{key}' must not contain placeholders: {error} [invalid_sql_need]"
            )
        } else {
            format!(
                "{TOOL}: sql need '{key}' placeholders must match declared params exactly: {error} [invalid_sql_need]"
            )
        }
    })?;
    // Fail fast on statements admission accepts but execution never can:
    // `query_sql` admits at most 64 output columns at runtime, so a wider
    // statement would refuse every `live_read` instead of installing.
    let columns = crate::query::sql::validated_output_columns(sql).map_err(|error| {
        format!("{TOOL}: sql need '{key}' output is not readable: {error} [invalid_sql_need]")
    })?;
    if columns.len() > crate::query::sql_contract::MAX_COLUMNS {
        return Err(format!(
            "{TOOL}: sql need '{key}' returns {} columns, at most {} [invalid_sql_need]",
            columns.len(),
            crate::query::sql_contract::MAX_COLUMNS,
        ));
    }
    let relations = if crate::keyed_freshness::is_keyed_read_key(key) {
        crate::query::sql::validated_relation_dependencies(sql).map_err(|error| {
            format!(
                "{TOOL}: sql need '{key}' dependencies are unavailable: {error} [invalid_sql_need]"
            )
        })?
    } else {
        std::collections::BTreeSet::new()
    };
    Ok(SqlNeed {
        key: key.to_string(),
        label: label.to_string(),
        sql: sql.to_string(),
        params,
        relations,
    })
}

/// Validate on-request values against a parameterised SQL need's declared
/// schema and bind them positionally for `query_sql` (never string
/// interpolation). Pure, so the bounds are unit-testable without a
/// database. Refusal codes: `unknown_sql_param` (undeclared name),
/// `missing_sql_param` (absent required param), `invalid_sql_param`
/// (mistyped, over `max_len`, or a non-object `params` envelope).
fn bind_sql_params(
    need: &SqlNeed,
    params: Option<&Value>,
) -> std::result::Result<Vec<crate::query::sql_contract::QuerySqlParameter>, &'static str> {
    use crate::query::sql_contract::QuerySqlParameter;
    let empty = serde_json::Map::new();
    let supplied = match params {
        None => &empty,
        Some(Value::Object(object)) => object,
        Some(_) => return Err("invalid_sql_param"),
    };
    for name in supplied.keys() {
        if !need.params.iter().any(|param| param.name == *name) {
            return Err("unknown_sql_param");
        }
    }
    let mut bound: Vec<QuerySqlParameter> = Vec::with_capacity(need.params.len());
    for param in &need.params {
        match supplied.get(&param.name) {
            None if !param.required => bound.push(match param.param_type {
                SqlParamType::Text => QuerySqlParameter::Text { value: None },
                SqlParamType::Integer | SqlParamType::TimestampMs => {
                    QuerySqlParameter::Integer { value: None }
                }
            }),
            None => return Err("missing_sql_param"),
            Some(value) => bound.push(match param.param_type {
                SqlParamType::Text => {
                    let text = value.as_str().ok_or("invalid_sql_param")?;
                    if text.chars().count() > param.max_len {
                        return Err("invalid_sql_param");
                    }
                    QuerySqlParameter::Text {
                        value: Some(text.to_string()),
                    }
                }
                SqlParamType::Integer => {
                    let number = value.as_i64().ok_or("invalid_sql_param")?;
                    QuerySqlParameter::Integer {
                        value: Some(number.to_string()),
                    }
                }
                SqlParamType::TimestampMs => {
                    let millis = value.as_i64().ok_or("invalid_sql_param")?;
                    QuerySqlParameter::Integer {
                        value: Some(millis.to_string()),
                    }
                }
            }),
        }
    }
    Ok(bound)
}

/// One declared on-request read, with parameters already bounded.
#[derive(Debug, PartialEq, Eq)]
pub enum DeclaredRead {
    Search {
        query: String,
        limit: i64,
    },
    ResolveReference {
        reference: String,
    },
    CanvasScene {
        canvas_id: String,
        limit: i64,
        cursor: Option<String>,
    },
    RecordChanges {
        record_id: String,
        limit: i64,
        cursor: Option<String>,
    },
    ArtifactRender {
        artifact_id: String,
    },
}

/// Parse and bound the parameters of an on-request need. Pure, so the
/// bounds are unit-testable without a database. `unknown_need` names a need
/// the host does not execute on request; `invalid_params` covers missing,
/// extra, mistyped and out-of-bound parameters alike.
pub fn parse_declared_read(
    need: &str,
    params: Option<&Value>,
) -> std::result::Result<DeclaredRead, &'static str> {
    let empty = serde_json::Map::new();
    let params = match params {
        None => &empty,
        Some(Value::Object(object)) => object,
        Some(_) => return Err("invalid_params"),
    };
    let only = |allowed: &[&str]| params.keys().all(|key| allowed.contains(&key.as_str()));
    match need {
        RECORDS_SEARCH_NEED => {
            if !only(&["query", "limit"]) {
                return Err("invalid_params");
            }
            let query = params
                .get("query")
                .and_then(Value::as_str)
                .map(str::trim)
                .ok_or("invalid_params")?;
            if query.is_empty() || query.chars().count() > SEARCH_QUERY_MAX_CHARS {
                return Err("invalid_params");
            }
            let limit = match params.get("limit") {
                None => SEARCH_LIMIT_MAX,
                Some(value) => value.as_i64().ok_or("invalid_params")?,
            };
            if !(1..=SEARCH_LIMIT_MAX).contains(&limit) {
                return Err("invalid_params");
            }
            Ok(DeclaredRead::Search {
                query: query.to_string(),
                limit,
            })
        }
        RECORDS_RESOLVE_REFERENCE_NEED => {
            if !only(&["reference"]) {
                return Err("invalid_params");
            }
            let reference = params
                .get("reference")
                .and_then(Value::as_str)
                .map(str::trim)
                .ok_or("invalid_params")?;
            if reference.is_empty() || reference.chars().count() > REFERENCE_MAX_CHARS {
                return Err("invalid_params");
            }
            Ok(DeclaredRead::ResolveReference {
                reference: reference.to_string(),
            })
        }
        CANVAS_SCENE_NEED => {
            if !only(&["canvas_id", "limit", "cursor"]) {
                return Err("invalid_params");
            }
            let canvas_id = params
                .get("canvas_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .ok_or("invalid_params")?;
            if canvas_id.is_empty() || canvas_id.chars().count() > CANVAS_ID_MAX_CHARS {
                return Err("invalid_params");
            }
            let limit = match params.get("limit") {
                None => CANVAS_SCENE_LIMIT_MAX,
                Some(value) => value.as_i64().ok_or("invalid_params")?,
            };
            if !(1..=CANVAS_SCENE_LIMIT_MAX).contains(&limit) {
                return Err("invalid_params");
            }
            // Only a cursor a previous page handed out resumes a page.
            let cursor = match params.get("cursor") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let cursor = value.as_str().ok_or("invalid_params")?;
                    super::canvas::SceneCursor::decode(cursor).ok_or("invalid_params")?;
                    Some(cursor.to_string())
                }
            };
            Ok(DeclaredRead::CanvasScene {
                canvas_id: canvas_id.to_string(),
                limit,
                cursor,
            })
        }
        RECORD_CHANGES_NEED => {
            if !only(&["record_id", "limit", "cursor"]) {
                return Err("invalid_params");
            }
            let record_id = params
                .get("record_id")
                .and_then(Value::as_str)
                .map(str::trim)
                .ok_or("invalid_params")?;
            if record_id.is_empty() || record_id.chars().count() > RECORD_ID_MAX_CHARS {
                return Err("invalid_params");
            }
            let limit = match params.get("limit") {
                None => RECORD_CHANGES_LIMIT_MAX,
                Some(value) => value.as_i64().ok_or("invalid_params")?,
            };
            if !(1..=RECORD_CHANGES_LIMIT_MAX).contains(&limit) {
                return Err("invalid_params");
            }
            // Only a cursor a page of this same record and install handed
            // out resumes; that is checked after the gates, in the read.
            let cursor = match params.get("cursor") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let cursor = value.as_str().ok_or("invalid_params")?;
                    if !RecordChangesCursor::well_formed(cursor) {
                        return Err("invalid_params");
                    }
                    Some(cursor.to_string())
                }
            };
            Ok(DeclaredRead::RecordChanges {
                record_id: record_id.to_string(),
                limit,
                cursor,
            })
        }
        ARTIFACT_RENDER_NEED => {
            if !only(&["artifact_id"]) {
                return Err("invalid_params");
            }
            // A full record id only, in its canonical lowercase hyphenated
            // form: no short reference is resolved, so the frame cannot use
            // this read to probe prefixes.
            let artifact_id = params
                .get("artifact_id")
                .and_then(Value::as_str)
                .ok_or("invalid_params")?;
            let canonical = Uuid::parse_str(artifact_id)
                .map_err(|_| "invalid_params")?
                .hyphenated()
                .to_string();
            if canonical != artifact_id {
                return Err("invalid_params");
            }
            Ok(DeclaredRead::ArtifactRender {
                artifact_id: canonical,
            })
        }
        _ => Err("unknown_need"),
    }
}

/// The consented write-effect names the guarded paths execute (triage, task
/// `26ba75a`; Tasks lifecycle, task `21f44fc`). Each is a semantic effect
/// string from the install's consented declaration — not a manifest entry id
/// and not a bundle hash. A guarded `invoke_artifact_interaction` refuses
/// with `alpha_guard_effect_unconsented` unless the install's consented
/// `effects` include the entry's arm value. A declared v2 manifest
/// interaction alone, or a matching bundle digest alone, is never consent.
///
/// Canonical home moved to [`super::tab_effect_catalogue`] (D1 slice 2);
/// re-exported here so existing paths keep resolving. Values unchanged.
pub use super::tab_effect_catalogue::{
    ALPHA_GUARD_FACET, ALPHA_TRIAGE_SET_EFFECT, BODY_SET_EFFECT, BODY_SET_MAX_BODY_BYTES,
    COMMENT_CREATE_EFFECT, COMMENT_CREATE_MAX_BODY_BYTES, FACET_SET_EFFECT, MESSAGE_REACT_EFFECT,
    TASKS_LIFECYCLE_FACET, TASKS_LIFECYCLE_SET_EFFECT, TASKS_LIFECYCLE_SOURCE,
    TASKS_LIFECYCLE_TARGET, TITLE_SET_EFFECT,
};

/// Named-input port the `attention.query.v1` read is declared against.
/// Mirrors the existing HTML named-input declaration shape
/// (`crates/artifact-html/src/html.rs` `valid_input_declaration` /
/// `parse_named_declaration`): envelope `native.collection-envelope.v1`,
/// `required: true`, `expose_to_root: true`, with exactly one `input.read`
/// capability request scoping that port. The preview fixture's `items` port
/// (`tests/tools/alpha_tabs.rs` `named_input_preview_body`) already uses
/// this shape for sample input.
///
/// Declared, not bound: this slice delivers rows at the top-level `records`
/// shim (see `alpha_tab_attention_port_mapping`), so `inputs.items` stays
/// empty. No fake collection id is minted to make the envelope look bound.
pub const ATTENTION_LIVE_PORT: &str = "items";

/// Row cap for one `attention.query.v1` execution: at most this many
/// viewer-authorized rows are returned. Host-bounded so one tab cannot page
/// the database through repeated reads; larger needs are a later slice with
/// pagination, not silent growth here.
pub const ATTENTION_LIVE_LIMIT: i64 = 50;

/// Superseded by the visible-first window: `do_live_read` now joins
/// `temp._query_sql_visible_records` before ordering/limiting to
/// `ATTENTION_LIVE_LIMIT`, so no bounded raw scan is needed. Retained for
/// provenance; new code must not bind it.
pub const ATTENTION_CANDIDATE_SCAN_CAP: i64 = 500;

/// Pinned `attention.query.v1` row semantics, v1 (task `26ba75a`).
///
/// Live `WorkItem`/`task` rows only: `deleted_at IS NULL`, hidden rows
/// excluded via the shared `not_hidden` predicate, no `archived` facet,
/// `lifecycle IS NOT NULL` and not a known-terminal token
/// (`completed`, `closed`). Unknown lifecycle tokens stay included (attention,
/// like the dashboard buckets, must not drop open work over a vocabulary
/// gap). Viewer `View` is selected inside SQL by joining the governed
/// `temp._query_sql_visible_records` view (same authority as the
/// `can_record_in` the launch gate uses) BEFORE `ORDER BY`/`LIMIT 50`,
/// so inaccessible newer tasks cannot push visible rows out of the
/// window; a per-row `can_record_in` stays as a fail-closed second check.
/// Stable order: `last_activity_at DESC`, `id ASC`.
/// This pins the task subset; full vocabulary-driven terminality stays with
/// the dashboard interpreter and is explicitly not reimplemented here.
///
/// L2 limit (stated, not deferred silently): returned rows carry the
/// display fields only (`id`, `type`, `kind`, `name`, `lifecycle`,
/// `last_activity_at`) — no facet prior values and no per-record CAS token
/// (`event_seq` / observed facet version) for a later reversible triage
/// action. The L2 slice must extend the row shape or re-read the target
/// through a governed CAS path (`prepareFacetIntent`-equivalent
/// observed-CAS + `reversalCandidate`); nothing here may be treated as the
/// observed prior for a write.
pub const ATTENTION_QUERY_SEMANTICS: &str =
    "attention.query.v1=v1:live WorkItem/task,lifecycle not completed/closed,first 50 viewer-authorized,last_activity_at DESC,id ASC,display-fields-only,no-facet-prior-no-cas";

/// The declared port for `attention.query.v1`, as the package manifest must
/// declare it to be eligible for the live read. Returned verbatim by
/// `live_read` (as `declared_port`) so callers can verify the mapping
/// without re-deriving it.
///
/// Honesty boundary: `status` is `declared-not-bound` and `delivery` is
/// `top-level-records-shim`. Rows ride at top-level `input.records` — the
/// exact positions the sample input uses, so preview/frame shape
/// compatibility holds — and `input.inputs` stays `{}`. A valid
/// `native.collection-envelope.v1` `inputs.items` requires a real bound
/// Collection (with its id, kind, and binding event seq); this slice has no
/// such binding and mints no fake collection id to pretend otherwise. That
/// bound-port delivery is a later slice; until it lands, no consumer may
/// read live rows from `inputs.items`.
pub fn alpha_tab_attention_port_mapping() -> Value {
    json!({
        "need": ATTENTION_QUERY_NEED,
        "port": ATTENTION_LIVE_PORT,
        "status": "declared-not-bound",
        "delivery": "top-level-records-shim",
        "declaration": {
            "envelope": "native.collection-envelope.v1",
            "required": true,
            "expose_to_root": true,
        },
        "capability_requests": [
            { "capability": "input.read", "scope": { "port": ATTENTION_LIVE_PORT } }
        ],
        "semantics": ATTENTION_QUERY_SEMANTICS,
    })
}

/// Adoption values the backend accepts as verified shell preview/adopt
/// gestures. Exactly the cookie+Origin adopt-confirm producer's value
/// (`26ba75a-adopt-gesture`): every stored install that is still
/// `caller_asserted` refuses launch with `adoption_unverified`, while a
/// verified install proceeds to the authority and digest gates. The control
/// tier rejects any other value on write, so caller-supplied install arguments
/// cannot self-assert verification.
const VERIFIED_ALPHA_TAB_ADOPTIONS: &[&str] =
    &[ALPHA_TAB_ADOPTION_VERIFIED, ALPHA_TAB_ADOPTION_SHELL_AUTO];

/// List/inspect never mint a reusable URL. A verified row can request a
/// one-use launch with its current install event token.
pub(crate) const ALPHA_TAB_LAUNCH_REQUEST_REQUIRED: &str = "launch_request_required";

/// Server-held preview-receipt time-to-live: ~15 minutes
/// (`slice3-adopt-gesture.md` §4). Receipts are single-use and bound to the
/// exact account plus the full pin; see `verify_alpha_tab_adopt_confirm`.
pub const ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS: i64 = 15 * 60;

/// Canonical alpha-tab bundle digest: lowercase hex SHA-256 over the exact
/// artifact source body bytes. Equals the HTML manifest `body_digest`
/// (and the MDX `source_sha256`) for the same bytes.
pub fn alpha_tab_bundle_digest(source_body: &str) -> String {
    hex::encode(Sha256::digest(source_body.as_bytes()))
}

/// Canonical parameter form: `{name, type, required}` plus `max_len` for
/// `text` only, in declared order. Declared order is consent: it defines
/// the positional `?N` binding, so reordering params is a different digest.
fn canonical_sql_params(params: &[SqlParam]) -> Value {
    Value::Array(
        params
            .iter()
            .map(|param| {
                if param.param_type == SqlParamType::Text {
                    json!({
                        "name": param.name,
                        "type": param.param_type.as_str(),
                        "max_len": param.max_len,
                        "required": param.required,
                    })
                } else {
                    json!({
                        "name": param.name,
                        "type": param.param_type.as_str(),
                        "required": param.required,
                    })
                }
            })
            .collect(),
    )
}

/// Declared app read scope (`reads.v1`, task `c2ca43a`): normalized
/// relation + column grants with optional type/kind scope. Schema,
/// catalog validation, semantic inclusion and digest binding only — no
/// runtime admission, no authorizer change, no UI in this slice. Pure, so
/// the bounds are unit-testable without a database. Every refusal names
/// `invalid_reads`.
pub const READS_DECLARATION_KEY: &str = "reads";

/// Sanity bounds on a `reads.v1` declaration. The catalog itself is the
/// real bound (unknown relations/columns are refused); these caps only
/// stop degenerate payloads.
pub const READS_MAX_RELATIONS: usize = 64;
pub const READS_MAX_COLUMNS_PER_RELATION: usize = 128;
pub const READS_MAX_SCOPES: usize = 32;
pub const READS_SCOPE_TYPE_MAX_CHARS: usize = 128;
pub const READS_SCOPE_KIND_MAX_CHARS: usize = 128;

/// One normalized relation grant: lowercase relation name with sorted,
/// deduplicated lowercase columns, all validated against the logical
/// catalog (`LOGICAL_RELATIONS`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadGrant {
    pub relation: String,
    pub columns: Vec<String>,
}

/// One optional type/kind scope entry. Record types are case-sensitive
/// (`WorkItem`, not `workitem`), so type (and kind, when present) is
/// stored verbatim. There is no static catalog for types/kinds — they are
/// open — so validation here is shape-only; admission resolves them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadScope {
    pub type_name: String,
    pub kind: Option<String>,
}

/// A parsed `reads.v1` declaration: grants sorted by relation, scopes
/// sorted and deduplicated (inclusion and the digest treat them as a set;
/// digest order is normalized separately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadsDeclaration {
    pub grants: Vec<ReadGrant>,
    pub scopes: Vec<ReadScope>,
}

/// Catalog columns for one relation name (already lowercased), or `None`
/// when the name is not a logical relation.
fn reads_catalog_columns(relation_lower: &str) -> Option<&'static [&'static str]> {
    crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .find(|relation| relation.name == relation_lower)
        .map(|relation| relation.columns)
}

/// Parse and validate a `reads.v1` declaration value (the `reads` key of
/// an app declaration). Pure. Fail-closed: unknown relations or columns,
/// empty column lists, malformed scope entries and unknown top-level keys
/// are all refused with `invalid_reads`, never normalized to absent.
pub fn parse_reads_declaration(value: &Value) -> std::result::Result<ReadsDeclaration, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{TOOL}: declaration 'reads' must be an object [invalid_reads]"))?;
    let has_scope = object.contains_key("scope");
    if !(object.len() == 1 || (object.len() == 2 && has_scope)) || !object.contains_key("relations")
    {
        return Err(format!(
            "{TOOL}: declaration 'reads' must hold exactly 'relations' with optional 'scope' [invalid_reads]"
        ));
    }
    let relations = object
        .get("relations")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            format!("{TOOL}: declaration 'reads.relations' must be an object [invalid_reads]")
        })?;
    if relations.len() > READS_MAX_RELATIONS {
        return Err(format!(
            "{TOOL}: declaration 'reads.relations' holds at most 64 relations [invalid_reads]"
        ));
    }
    let mut grants = Vec::with_capacity(relations.len());
    for (name, columns) in relations {
        let relation = name.to_ascii_lowercase();
        let catalog = reads_catalog_columns(&relation).ok_or_else(|| {
            format!("{TOOL}: declaration 'reads' names unknown relation '{name}' [invalid_reads]")
        })?;
        let list = columns.as_array().ok_or_else(|| {
            format!(
                "{TOOL}: declaration 'reads' relation '{name}' must hold an array of columns [invalid_reads]"
            )
        })?;
        if list.is_empty() || list.len() > READS_MAX_COLUMNS_PER_RELATION {
            return Err(format!(
                "{TOOL}: declaration 'reads' relation '{name}' must hold 1..=128 columns [invalid_reads]"
            ));
        }
        let mut grant_columns = Vec::with_capacity(list.len());
        for column in list {
            let text = column.as_str().ok_or_else(|| {
                format!(
                    "{TOOL}: declaration 'reads' relation '{name}' columns must be strings [invalid_reads]"
                )
            })?;
            let normalized = text.to_ascii_lowercase();
            if !catalog.contains(&normalized.as_str()) {
                return Err(format!(
                    "{TOOL}: declaration 'reads' relation '{name}' names unknown column '{text}' [invalid_reads]"
                ));
            }
            grant_columns.push(normalized);
        }
        grant_columns.sort();
        grant_columns.dedup();
        grants.push(ReadGrant {
            relation,
            columns: grant_columns,
        });
    }
    grants.sort_by(|left, right| left.relation.cmp(&right.relation));
    // Case-normalized duplicates (`Records` plus `records`) would otherwise
    // emit two grants for one relation: the canonical map would silently
    // keep the last while coverage reads the first. Refuse instead, so the
    // author writes one entry.
    for window in grants.windows(2) {
        if window[0].relation == window[1].relation {
            return Err(format!(
                "{TOOL}: declaration 'reads' names relation '{}' more than once [invalid_reads]",
                window[0].relation
            ));
        }
    }
    let mut scopes = Vec::new();
    if has_scope {
        let list = object
            .get("scope")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!("{TOOL}: declaration 'reads.scope' must be an array [invalid_reads]")
            })?;
        if list.is_empty() || list.len() > READS_MAX_SCOPES {
            return Err(format!(
                "{TOOL}: declaration 'reads.scope' must hold 1..=32 entries [invalid_reads]"
            ));
        }
        for entry in list {
            let scope_object = entry.as_object().ok_or_else(|| {
                format!("{TOOL}: declaration 'reads.scope' entries must be objects [invalid_reads]")
            })?;
            let has_kind = scope_object.contains_key("kind");
            if !(scope_object.len() == 1 || (scope_object.len() == 2 && has_kind))
                || !scope_object.contains_key("type")
            {
                return Err(format!(
                    "{TOOL}: declaration 'reads.scope' entries must hold exactly 'type' with optional 'kind' [invalid_reads]"
                ));
            }
            let type_name = scope_object
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "{TOOL}: declaration 'reads.scope' entry 'type' must be a string [invalid_reads]"
                    )
                })?;
            if type_name.is_empty() || type_name.len() > READS_SCOPE_TYPE_MAX_CHARS {
                return Err(format!(
                    "{TOOL}: declaration 'reads.scope' entry 'type' must be 1..=128 characters [invalid_reads]"
                ));
            }
            let kind = if has_kind {
                let text = scope_object
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        format!(
                            "{TOOL}: declaration 'reads.scope' entry 'kind' must be a string [invalid_reads]"
                        )
                    })?;
                if text.is_empty() || text.len() > READS_SCOPE_KIND_MAX_CHARS {
                    return Err(format!(
                        "{TOOL}: declaration 'reads.scope' entry 'kind' must be 1..=128 characters [invalid_reads]"
                    ));
                }
                Some(text.to_string())
            } else {
                None
            };
            scopes.push(ReadScope {
                type_name: type_name.to_string(),
                kind,
            });
        }
        // Exact-duplicate scope entries are provably safe to drop: every
        // consumer (coverage, canonical digest order) treats scopes as a
        // set, so dedup changes neither admission nor the pin.
        scopes.sort_by(|left, right| {
            (&left.type_name, &left.kind).cmp(&(&right.type_name, &right.kind))
        });
        scopes.dedup();
    }
    Ok(ReadsDeclaration { grants, scopes })
}

/// Canonical `reads.v1` form: `{"relations": {relation: [columns]}}` with
/// relations ascending and columns sorted, plus `scope` only when the
/// declaration narrows by scope (scope entries digest-ordered). Key order
/// is irrelevant (JCS); array order is normalized here for the same reason
/// the needs/effects sets are: consent covers the grant set, not the
/// author's ordering.
pub fn canonical_reads_declaration(reads: &ReadsDeclaration) -> Value {
    let mut relations = serde_json::Map::with_capacity(reads.grants.len());
    for grant in &reads.grants {
        relations.insert(
            grant.relation.clone(),
            Value::Array(grant.columns.iter().cloned().map(Value::String).collect()),
        );
    }
    if reads.scopes.is_empty() {
        return json!({"relations": Value::Object(relations)});
    }
    let mut scopes: Vec<Value> = reads
        .scopes
        .iter()
        .map(|scope| match &scope.kind {
            Some(kind) => json!({"type": scope.type_name, "kind": kind}),
            None => json!({"type": scope.type_name}),
        })
        .collect();
    scopes.sort_by_cached_key(crate::canonical_json::digest_json);
    json!({"relations": Value::Object(relations), "scope": scopes})
}

/// Semantic grant coverage: `haystack` covers `needle` iff every needle
/// relation is present with a superset of its columns, and every needle
/// scope entry is covered by a haystack entry. An absent scope list is
/// viewer-wide, so a scopeless haystack covers any needle scope, while a
/// scopeless needle needs a scopeless haystack. Scope entries cover by
/// exact type, with an absent kind covering any kind of that type.
pub fn reads_covers_grant(haystack: &ReadsDeclaration, needle: &ReadsDeclaration) -> bool {
    for need in &needle.grants {
        let Some(have) = haystack
            .grants
            .iter()
            .find(|grant| grant.relation == need.relation)
        else {
            return false;
        };
        if !need
            .columns
            .iter()
            .all(|column| have.columns.contains(column))
        {
            return false;
        }
    }
    if haystack.scopes.is_empty() {
        return true;
    }
    if needle.scopes.is_empty() {
        return false;
    }
    needle.scopes.iter().all(|need| {
        haystack.scopes.iter().any(|have| {
            have.type_name == need.type_name && (have.kind.is_none() || have.kind == need.kind)
        })
    })
}

/// Widening check for the install/update change note: `new` widens `old`
/// iff the old grants do not cover it. Equal and narrowed declarations
/// report no widening.
pub fn reads_widens(old: &ReadsDeclaration, new: &ReadsDeclaration) -> bool {
    !reads_covers_grant(old, new)
}

/// Per-viewer message-state relations in the logical catalog: grants on
/// these read queue state only the viewer can see. Catalog discovery (no
/// invented relations): `messages_awaiting_reply` is the one
/// caller-relative message-state relation; there is no `messages` relation
/// and no message-body column anywhere in the catalog.
pub const APP_READ_PRIVATE_MESSAGE_RELATIONS: &[&str] = &["messages_awaiting_reply"];

/// Full record-text columns that merit the quiet broad badge even under a
/// narrowed scope. Both records.body and the reassemblable body_blocks.text
/// chunks disclose record text; records.summary and links.note are short
/// annotations and do not qualify.
pub const APP_READ_BROAD_COLUMNS: &[(&str, &str)] = &[("records", "body"), ("body_blocks", "text")];

/// Relations whose rows belong to the exact record set narrowed inside the
/// viewer fence. Chunks, task markers and typed times use their owner record's type/kind. Other
/// relations need explicit reference and metadata semantics before admission.
const APP_READ_SCOPED_RELATIONS: &[&str] =
    &["records", "body_blocks", "body_task_items", "facet_times"];

/// One relation's read-info for host rendering: the exact declared columns
/// in plain language, never a runnable-support claim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppReadRelationInfo {
    pub relation: String,
    pub columns: Vec<String>,
    pub summary: String,
    pub only_you_see_this: bool,
    pub counters_included: Vec<String>,
}

/// Shared read-info display model from a normalized [`ReadsDeclaration`]:
/// stable typed metadata for host rendering, not prose parsed from SQL.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppReadInfo {
    pub relations: Vec<AppReadRelationInfo>,
    pub scope_description: Option<String>,
    pub broad_access: bool,
    pub capability_notes: Vec<String>,
}

/// Plain-language summary of one grant, e.g. "reads id from records".
fn app_read_grant_summary(relation: &str, columns: &[String]) -> String {
    match columns {
        [] => format!("touches {relation} without reading columns"),
        [one] => format!("reads {one} from {relation}"),
        [first, second] => format!("reads {first} and {second} from {relation}"),
        [first, second, rest @ ..] => format!(
            "reads {first}, {second} and {} more from {relation}",
            rest.len()
        ),
    }
}

/// Describe normalized app reads for host rendering: exact declared
/// grants (including currently forbidden counters — reported, never hidden),
/// an optional scope description, the quiet broad badge (viewer-wide scope
/// or full record text), and current capability limits as metadata.
pub fn describe_app_reads(reads: &ReadsDeclaration) -> AppReadInfo {
    let mut capability_notes = Vec::new();
    if !reads.scopes.is_empty()
        && reads
            .grants
            .iter()
            .any(|grant| !APP_READ_SCOPED_RELATIONS.contains(&grant.relation.as_str()))
    {
        capability_notes.push(
            "Type/kind-scoped app reads currently support only records, body_blocks, body_task_items and facet_times; other scoped relations are refused."
                .to_string(),
        );
    }
    let mut relations = Vec::with_capacity(reads.grants.len());
    for grant in &reads.grants {
        let counters: Vec<String> = grant
            .columns
            .iter()
            .filter(|column| {
                APP_READ_FORBIDDEN_COUNTERS.contains(&(grant.relation.as_str(), column.as_str()))
            })
            .cloned()
            .collect();
        if !counters.is_empty() {
            capability_notes.push(format!(
                "'{}.{}' exposes workspace counters that app execution currently refuses",
                grant.relation,
                counters.join(", ")
            ));
        }
        relations.push(AppReadRelationInfo {
            summary: app_read_grant_summary(&grant.relation, &grant.columns),
            only_you_see_this: APP_READ_PRIVATE_MESSAGE_RELATIONS
                .contains(&grant.relation.as_str()),
            counters_included: counters,
            relation: grant.relation.clone(),
            columns: grant.columns.clone(),
        });
    }
    // Empty grants access nothing, so the badge stays off even scopeless.
    let broad_access = !reads.grants.is_empty()
        && (reads.scopes.is_empty()
            || reads.grants.iter().any(|grant| {
                grant.columns.iter().any(|column| {
                    APP_READ_BROAD_COLUMNS.contains(&(grant.relation.as_str(), column.as_str()))
                })
            }));
    let scope_description = if reads.scopes.is_empty() {
        None
    } else {
        Some(
            reads
                .scopes
                .iter()
                .map(|scope| match &scope.kind {
                    Some(kind) => format!("declares type '{}' kind '{kind}'", scope.type_name),
                    None => format!("declares type '{}'", scope.type_name),
                })
                .collect::<Vec<_>>()
                .join("; "),
        )
    };
    AppReadInfo {
        relations,
        scope_description,
        broad_access,
        capability_notes,
    }
}

/// Semantic widening note between normalized grants using [`reads_widens`]:
/// `None` for equal or narrowed declarations, `Some` prose when the new
/// declaration widens — produced without prompting.
pub fn app_reads_widening_note(old: &ReadsDeclaration, new: &ReadsDeclaration) -> Option<String> {
    if !reads_widens(old, new) {
        return None;
    }
    let mut parts = Vec::new();
    for grant in &new.grants {
        match old
            .grants
            .iter()
            .find(|have| have.relation == grant.relation)
        {
            None => parts.push(format!("new relation '{}'", grant.relation)),
            Some(have) => {
                let added: Vec<&str> = grant
                    .columns
                    .iter()
                    .map(String::as_str)
                    .filter(|column| !have.columns.iter().any(|held| held == column))
                    .collect();
                if !added.is_empty() {
                    parts.push(format!("'{}' gains {}", grant.relation, added.join(", ")));
                }
            }
        }
    }
    // Scope broadening is compared independently, never inferred from
    // whole-declaration widening: sharing the new grants makes the grant
    // half of coverage trivially true, so any failure is the scope half
    // alone.
    let probe = ReadsDeclaration {
        grants: new.grants.clone(),
        scopes: old.scopes.clone(),
    };
    if !reads_covers_grant(&probe, new) {
        parts.push("broader type/kind scope".to_string());
    }
    Some(format!(
        "This update widens app reads: {}.",
        parts.join("; ")
    ))
}

/// Flat SELECT read-dependency analyzer (task `c2ca43a`, slice 2): pure,
/// engine-neutral, fail-closed.
///
/// Admits exactly two shapes over logical catalog relations
/// (`LOGICAL_RELATIONS`). First, the flat single-table query: `SELECT
/// [DISTINCT | ALL] <explicit exprs> FROM <relation> [AS alias] [WHERE
/// <expr>] [ORDER BY ...] [LIMIT ...]`; unqualified names bind to the single
/// table, and qualified names must use the table name — or its alias when
/// one is declared, which hides the table name as SQLite resolves. Second, a
/// chain of INNER and LEFT joins (`JOIN`, `INNER JOIN` or `LEFT JOIN`, each
/// with `ON`): bare table names and explicit aliases both establish visible
/// labels, and duplicate labels are refused. Unqualified columns resolve iff
/// exactly one scope table contains the column — ambiguity counts scope
/// entries, so a self-join never resolves unqualified names. Each `ON`
/// resolves against its prefix scope only (the left side plus the new right
/// side); forward references are refused. `*` expands to every column of
/// every base relation and `alias.*` to every column of the named scope
/// relation; `count(*)` is a relation-level read (only its `FILTER`, if any,
/// adds columns). The result is one grant per relation, so
/// `reads_covers_grant` can later check it against a declared `reads.v1`
/// without any wiring in this slice.
/// GROUP BY expressions and HAVING (including aggregate FILTER terms) use
/// the same full table scope as the projection. Output aliases that are not
/// catalog columns remain unsupported; backend determinism gates still apply.
///
/// Everything else is refused with `invalid_sql`, never normalized to fewer
/// columns: other `f(*)` spellings, other joins (right, full, cross, comma,
/// `NATURAL`, `USING`, missing `ON`, duplicate labels), ambiguous or unknown
/// column names, subqueries (in `FROM` or any expression), CTEs, compounds, `VALUES`, `WINDOW`,
/// unknown relations or columns, qualifier mismatches, doubly-qualified
/// names, multi-statements and unparseable text.
pub fn analyze_flat_select_reads(sql: &str) -> std::result::Result<ReadsDeclaration, String> {
    let invalid = |detail: &str| format!("{TOOL}: sql {detail} [invalid_sql]");
    let mut parser = Parser::new(sql.as_bytes());
    let first = parser
        .next()
        .transpose()
        .map_err(|error| invalid(&error.to_string()))?
        .ok_or_else(|| invalid("is empty"))?;
    if parser.next().is_some() {
        return Err(invalid("holds more than one statement"));
    }
    let select = match first {
        Cmd::Stmt(Stmt::Select(select)) => select,
        _ => return Err(invalid("is not a SELECT statement")),
    };
    if select.with.is_some() {
        return Err(invalid("WITH/CTE queries are unsupported"));
    }
    if !select.body.compounds.is_empty() {
        return Err(invalid("compound SELECTs are unsupported"));
    }
    let OneSelect::Select {
        columns,
        from,
        where_clause,
        group_by,
        window_clause,
        ..
    } = &select.body.select
    else {
        return Err(invalid("VALUES is unsupported"));
    };
    if !window_clause.is_empty() {
        return Err(invalid("WINDOW clauses are unsupported"));
    }
    let from = from
        .as_ref()
        .ok_or_else(|| invalid("needs a FROM clause"))?;
    // FROM scope: one table or a chain of INNER/LEFT joins with ON. Each
    // ON resolves against its prefix scope only (no forward references).
    // Bare table names and explicit aliases both establish visible labels;
    // duplicate labels are refused.
    let mut tables = vec![flat_from_table(&from.select)?];
    let mut on_scopes: Vec<(&Expr, usize)> = Vec::new();
    for join in &from.joins {
        match join.operator {
            JoinOperator::TypedJoin(None) => {}
            JoinOperator::TypedJoin(Some(kind)) if kind == JoinType::INNER => {}
            JoinOperator::TypedJoin(Some(kind)) if kind == JoinType::LEFT | JoinType::OUTER => {}
            _ => return Err(invalid("only INNER and LEFT JOIN are supported")),
        }
        let constraint = join
            .constraint
            .as_ref()
            .ok_or_else(|| invalid("JOIN needs an ON clause"))?;
        match constraint {
            JoinConstraint::On(expr) => {
                tables.push(flat_from_table(&join.table)?);
                on_scopes.push((expr, tables.len()));
            }
            JoinConstraint::Using(_) => return Err(invalid("JOIN ... USING is unsupported")),
        }
    }
    let mut labels: Vec<&str> = tables.iter().map(|table| table.1.as_str()).collect();
    labels.sort();
    labels.dedup();
    if labels.len() != tables.len() {
        return Err(invalid("JOIN scope has duplicate table labels"));
    }
    let mut refs = Vec::new();
    for column in columns {
        match column {
            ResultColumn::Expr(expr, _) => collect_flat_refs(expr, &mut refs)?,
            ResultColumn::Star => {
                // Unqualified `*` reads every column of every base relation.
                for table in &tables {
                    let catalog =
                        reads_catalog_columns(&table.0).expect("relation validated above");
                    for name in catalog {
                        refs.push((Some(table.1.clone()), (*name).to_string()));
                    }
                }
            }
            ResultColumn::TableStar(name) => {
                // `alias.*` reads every column of the named scope relation;
                // unknown or hidden (aliased-away) names are refused.
                let qualifier = name.as_str().to_ascii_lowercase();
                let table = tables
                    .iter()
                    .find(|table| table.1 == qualifier)
                    .ok_or_else(|| invalid("names an unknown table qualifier"))?;
                let catalog = reads_catalog_columns(&table.0).expect("relation validated above");
                for column_name in catalog {
                    refs.push((Some(table.1.clone()), (*column_name).to_string()));
                }
            }
        }
    }
    if let Some(filter) = where_clause.as_ref() {
        collect_flat_refs(filter, &mut refs)?;
    }
    if let Some(group) = group_by.as_ref() {
        for expression in &group.exprs {
            collect_flat_refs(expression, &mut refs)?;
        }
        if let Some(having) = group.having.as_ref() {
            collect_flat_refs(having, &mut refs)?;
        }
    }
    for sorted in &select.order_by {
        collect_flat_refs(&sorted.expr, &mut refs)?;
    }
    if let Some(limit) = select.limit.as_ref() {
        collect_flat_refs(&limit.expr, &mut refs)?;
        if let Some(offset) = limit.offset.as_ref() {
            collect_flat_refs(offset, &mut refs)?;
        }
    }
    let scope_all = tables.len();
    let mut scoped: Vec<(Option<String>, String, usize)> = refs
        .into_iter()
        .map(|(qualifier, column)| (qualifier, column, scope_all))
        .collect();
    for (on, prefix) in on_scopes {
        let mut on_refs = Vec::new();
        collect_flat_refs(on, &mut on_refs)?;
        scoped.extend(
            on_refs
                .into_iter()
                .map(|(qualifier, column)| (qualifier, column, prefix)),
        );
    }
    let mut resolved: Vec<(String, String)> = Vec::with_capacity(scoped.len());
    for (qualifier, column, visible) in scoped {
        let visible = &tables[..visible];
        match qualifier {
            Some(qualifier) => {
                let table = visible
                    .iter()
                    .find(|table| table.1 == qualifier)
                    .ok_or_else(|| invalid("names an unknown table qualifier"))?;
                let catalog = reads_catalog_columns(&table.0).expect("relation validated above");
                if !catalog.contains(&column.as_str()) {
                    return Err(invalid("names an unknown column"));
                }
                resolved.push((table.0.clone(), column));
            }
            None => {
                // Unqualified names resolve iff exactly one visible scope
                // table contains the column. Ambiguity counts scope entries,
                // so a self-join never resolves unqualified names.
                let mut owners = visible.iter().filter(|table| {
                    reads_catalog_columns(&table.0)
                        .expect("relation validated above")
                        .contains(&column.as_str())
                });
                match (owners.next(), owners.next()) {
                    (Some(one), None) => resolved.push((one.0.clone(), column)),
                    (Some(_), Some(_)) => return Err(invalid("names an ambiguous column")),
                    (None, _) => return Err(invalid("names an unknown column")),
                }
            }
        }
    }
    resolved.sort();
    resolved.dedup();
    // Seed one grant per base relation — even with zero referenced columns
    // (`SELECT 1 FROM records`, constant `ON 1 = 1`): admission must see
    // every touched relation, and a missing grant would read as no access.
    // A self-join merges into one grant. Empty analyzer columns never relax
    // the declaration parser, which still requires 1..=128 columns.
    let mut relations: Vec<String> = tables.iter().map(|table| table.0.clone()).collect();
    relations.sort();
    relations.dedup();
    let mut grants: Vec<ReadGrant> = relations
        .into_iter()
        .map(|relation| ReadGrant {
            relation,
            columns: Vec::new(),
        })
        .collect();
    for (relation, column) in resolved {
        let grant = grants
            .iter_mut()
            .find(|grant| grant.relation == relation)
            .expect("grant seeded per base relation");
        grant.columns.push(column);
    }
    Ok(ReadsDeclaration {
        grants,
        scopes: Vec::new(),
    })
}

/// One FROM table as `(relation, label, aliased)`: the relation is
/// catalog-validated; the label is the explicit alias when one is declared
/// (which hides the table name, as SQLite resolves) and the table name
/// otherwise. A legacy `QualifiedName` alias must agree with the `AS` alias.
fn flat_from_table(table: &SelectTable) -> std::result::Result<(String, String, bool), String> {
    let invalid = |detail: &str| format!("{TOOL}: sql {detail} [invalid_sql]");
    match table {
        SelectTable::Table(name, alias, _) => {
            if name.db_name.is_some() {
                return Err(invalid("database-qualified tables are unsupported"));
            }
            let relation = name.name.as_str().to_ascii_lowercase();
            reads_catalog_columns(&relation).ok_or_else(|| invalid("names an unknown relation"))?;
            let mut label = relation.clone();
            let mut aliased = false;
            if let Some(alias) = alias {
                label = alias.name().as_str().to_ascii_lowercase();
                aliased = true;
            }
            if let Some(legacy) = name.alias.as_ref() {
                let legacy = legacy.as_str().to_ascii_lowercase();
                if legacy != label {
                    return Err(invalid("has conflicting table aliases"));
                }
                label = legacy;
            }
            Ok((relation, label, aliased))
        }
        SelectTable::TableCall(..) => Err(invalid("table functions are unsupported")),
        SelectTable::Select(..) | SelectTable::Sub(..) => {
            Err(invalid("subqueries in FROM are unsupported"))
        }
    }
}

/// Stable refusal codes for [`admit_app_sql_reads`], the shared enforcement
/// predicate the app runtime path will call. Codes are the stable surface;
/// details name only catalog relations/columns, never SQL text or database
/// state.
pub const APP_READ_UNSUPPORTED_SQL: &str = "unsupported_sql";
pub const APP_READ_UNDECLARED_RELATION: &str = "undeclared_relation";
pub const APP_READ_UNDECLARED_COLUMN: &str = "undeclared_column";
pub const APP_READ_UNSUPPORTED_SCOPE: &str = "unsupported_read_scope";
pub const APP_READ_WORKSPACE_COUNTER: &str = "workspace_counter_forbidden";

/// Global workspace-sequence columns no app read may touch: exact
/// (relation, column) pairs, never a `*seq*` heuristic. `local_seq` orders
/// the whole content log and `event_seq` the whole observation log —
/// exposing either lets an app track workspace activity beyond its visible
/// rows (order/filter becomes a side channel), so analysis never strips
/// them and admission refuses them even when declared. Per-row clocks
/// (`created_at_ms`, `observed_at_ms`, …) are row-scoped, not global, and
/// stay admissible; `runs`, `run_intents` and `facet_times` carry upstream
/// test-pinned no-global-sequence assertions, so no other pair qualifies.
pub const APP_READ_FORBIDDEN_COUNTERS: &[(&str, &str)] = &[
    ("content_events", "local_seq"),
    ("facet_observations", "event_seq"),
];

/// Why [`admit_app_sql_reads`] refused a statement. Pure data: no SQL text,
/// no row contents, no database handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppReadAdmissionError {
    /// The statement is outside the analyzer's admitted SELECT shape.
    UnsupportedSql,
    /// The statement reads a relation the declaration does not grant —
    /// even when no column of it is referenced (presence matters).
    UndeclaredRelation { relation: String },
    /// The statement reads a column the declaration does not grant.
    UndeclaredColumn { relation: String, column: String },
    /// The declaration narrows by type/kind scope on a relation without
    /// defined row-scope enforcement. Fails closed rather than stripping it.
    UnsupportedReadScope,
    /// The statement touches a global workspace-sequence column
    /// ([`APP_READ_FORBIDDEN_COUNTERS`]) — in the projection, a predicate,
    /// ordering, an aggregate filter, under an alias, or via `*` expansion.
    /// Refused even when the declaration grants the column: order/filter
    /// over a global counter is a workspace-activity side channel.
    WorkspaceCounterForbidden { relation: String, column: String },
}

impl AppReadAdmissionError {
    /// Stable machine-readable code for this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedSql => APP_READ_UNSUPPORTED_SQL,
            Self::UndeclaredRelation { .. } => APP_READ_UNDECLARED_RELATION,
            Self::UndeclaredColumn { .. } => APP_READ_UNDECLARED_COLUMN,
            Self::UnsupportedReadScope => APP_READ_UNSUPPORTED_SCOPE,
            Self::WorkspaceCounterForbidden { .. } => APP_READ_WORKSPACE_COUNTER,
        }
    }

    /// Human-readable reason naming only catalog relations/columns — the
    /// root-error mapping pairs it with [`Self::code`], so it never
    /// carries SQL text or database state on its own either.
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::UnsupportedSql => "statement is outside the admitted read shape".to_string(),
            Self::UndeclaredRelation { relation } => format!("'{relation}' is not granted"),
            Self::UndeclaredColumn { relation, column } => {
                format!("'{relation}.{column}' is not granted")
            }
            Self::UnsupportedReadScope => {
                "type/kind scopes currently support only records, body_blocks, body_task_items and facet_times".to_string()
            }
            Self::WorkspaceCounterForbidden { relation, column } => {
                format!("'{relation}.{column}' exposes a workspace counter")
            }
        }
    }
}

impl std::fmt::Display for AppReadAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.detail())
    }
}

impl std::error::Error for AppReadAdmissionError {}

/// Shared app-SQL enforcement predicate (task `c2ca43a`, slice 2): admit a
/// SQL read against a declared `reads.v1` scope. Pure and engine-neutral —
/// the later app runtime path calls this before executing. Fail-closed: the
/// statement is analyzed, then every analyzed relation must be granted
/// (presence alone admits column-less reads, so they still need their
/// relation) and every analyzed column must be granted. Type/kind scopes
/// are supported only for the explicit owner-record relation allowlist and carried forward
/// for row enforcement by the app executor, never inferred from SQL.
/// Global workspace-sequence columns ([`APP_READ_FORBIDDEN_COUNTERS`]) are
/// refused even when granted. Returns the exact admitted grant set on
/// success.
pub fn admit_app_sql_reads(
    declared: &ReadsDeclaration,
    sql: &str,
) -> std::result::Result<ReadsDeclaration, AppReadAdmissionError> {
    if !declared.scopes.is_empty()
        && declared
            .grants
            .iter()
            .any(|grant| !APP_READ_SCOPED_RELATIONS.contains(&grant.relation.as_str()))
    {
        return Err(AppReadAdmissionError::UnsupportedReadScope);
    }
    let mut analyzed =
        analyze_flat_select_reads(sql).map_err(|_| AppReadAdmissionError::UnsupportedSql)?;
    // Global counters fail closed before coverage: a granted column never
    // bypasses this, and analysis is never asked to strip the reference.
    for grant in &analyzed.grants {
        for column in &grant.columns {
            if APP_READ_FORBIDDEN_COUNTERS.contains(&(grant.relation.as_str(), column.as_str())) {
                return Err(AppReadAdmissionError::WorkspaceCounterForbidden {
                    relation: grant.relation.clone(),
                    column: column.clone(),
                });
            }
        }
    }
    for grant in &analyzed.grants {
        let have = declared
            .grants
            .iter()
            .find(|have| have.relation == grant.relation)
            .ok_or_else(|| AppReadAdmissionError::UndeclaredRelation {
                relation: grant.relation.clone(),
            })?;
        for column in &grant.columns {
            if !have.columns.contains(column) {
                return Err(AppReadAdmissionError::UndeclaredColumn {
                    relation: grant.relation.clone(),
                    column: column.clone(),
                });
            }
        }
    }
    analyzed.scopes = declared.scopes.clone();
    Ok(analyzed)
}

/// Crate-internal SQLite transaction seam for governed app SQL reads (task
/// `c2ca43a`, slice 2): the only app route to the portable executor. Takes
/// a trusted engine-resolved declaration (a parsed [`ReadsDeclaration` —
/// never declaration text or external arguments), an authenticated
/// [`QueryPrincipal`](crate::query::QueryPrincipal), and a
/// [`QuerySqlRequest`](crate::query::sql_contract::QuerySqlRequest).
/// [`admit_app_sql_reads`] runs before any query execution: undeclared or
/// out-of-shape SQL maps to a stable `app_sql [<code>]` root error and the
/// executor is never reached. Admitted statements delegate to the shared
/// caller-transaction executor with the explicit app row cap
/// ([`SQL_SNAPSHOT_ROW_CAP`]) and no ad-hoc implicit ordering — the bare
/// `query_sql` entry is never used as an app route. No lifecycle rows, no
/// package state, no public tool: the internal
/// [`SqlResult`](crate::query::sql::SqlResult) (observation stripped) is
/// returned for a later host wrapper to shape. Still not externally
/// exposed: crate-internal only, no public tool.
///
/// This transaction seam is verified only against primary SQLite. It does
/// not carry a [`Db`]'s source footing: a future trusted host route must
/// derive that context and preserve profile-specific availability before
/// calling it. In particular, the member-copy query surface refuses body
/// chunks and task markers even when declared. Do not use this seam to
/// bypass those refusals or infer package authority from request fields.
#[allow(
    dead_code,
    reason = "no production caller until the app runtime path lands"
)]
pub(crate) async fn execute_app_sql_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    declared: &ReadsDeclaration,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<SqlResult> {
    let admitted = admit_app_sql_reads(declared, &request.sql).map_err(|error| {
        Error::engine(format!("app_sql [{}]: {}", error.code(), error.detail()))
    })?;
    let columns = crate::query::sql::validate_app_sql_dependencies(&request.sql, &admitted)?;
    let (mut result, _observation) = crate::query::sql::query_app_sql_request_in_with_row_limit(
        transaction,
        principal,
        request,
        SQL_SNAPSHOT_ROW_CAP as i64,
        &admitted.scopes,
    )
    .await
    .map_err(project_app_sql_execution_error)?;
    // The shared executor discovers labels from its first row. An empty app
    // read still has a schema, verified by the same prepare above.
    if result.rows.is_empty() {
        result.columns = columns;
    }
    Ok(result)
}

/// Shared executor diagnostics can name stored records or values outside an
/// app's column grants. Only a closed category and static detail may cross
/// this seam. Direct SQL retains its ordinary diagnostic behavior.
fn project_app_sql_execution_error(error: Error) -> Error {
    use crate::query::sql_contract::{QuerySqlErrorCategory, ERROR_CATEGORIES};
    let category = match &error {
        Error::Engine(message) => ERROR_CATEGORIES
            .iter()
            .copied()
            .find(|category| message.starts_with(&format!("query_sql [{}]: ", category.as_str())))
            .unwrap_or(QuerySqlErrorCategory::Engine),
        _ => QuerySqlErrorCategory::Engine,
    };
    let detail = match category {
        QuerySqlErrorCategory::InvalidArguments => "app read arguments are invalid",
        QuerySqlErrorCategory::UnsafeStatement => "app read violates portable SQL rules",
        QuerySqlErrorCategory::UnauthorizedRelation => "app read accesses an unavailable relation",
        QuerySqlErrorCategory::SyntaxOrType => "app read has an unsupported expression or value",
        QuerySqlErrorCategory::Timeout => "app read exceeded its time budget",
        QuerySqlErrorCategory::ResultTooLarge => "app read exceeded its result budget",
        QuerySqlErrorCategory::DuplicateColumns => "app read has duplicate output labels",
        QuerySqlErrorCategory::UnsupportedProfile => "app read profile is unavailable",
        QuerySqlErrorCategory::Engine => "app read could not execute",
    };
    Error::engine(format!("app_sql [{}]: {detail}", category.as_str()))
}

#[cfg(test)]
mod app_execution_error_tests {
    use super::project_app_sql_execution_error;
    use crate::query::sql_contract::ERROR_CATEGORIES;
    use crate::Error;

    #[test]
    fn app_execution_error_projection_has_a_closed_category_boundary() {
        let secret = "private-record-id 264975 bytes WHERE records.id NOT IN";
        for category in ERROR_CATEGORIES {
            let error = project_app_sql_execution_error(Error::engine(format!(
                "query_sql [{}]: {secret}",
                category.as_str()
            )))
            .to_string();
            assert!(error.starts_with(&format!("app_sql [{}]: ", category.as_str())));
            assert!(!error.contains(secret), "{error}");
        }
        for message in [
            secret.to_string(),
            format!("query_sql [unknown-{secret}]: diagnostic"),
            format!("query_sql [syntax_or_type] {secret}"),
            format!("prefix query_sql [syntax_or_type]: {secret}"),
        ] {
            assert_eq!(
                project_app_sql_execution_error(Error::engine(message)).to_string(),
                "app_sql [engine]: app read could not execute"
            );
        }
    }
}

/// Host-facing app SQL response (task `c2ca43a`, slice 2): an explicit
/// allowlist projection over the internal [`SqlResult`]. Only safe fields
/// travel — `columns`, `rows`, `truncated`, `row_count`, the derived
/// `row_count_complete`, the content `revision_token`, and statement-scoped
/// clock facts. Never `as_of_seq` (a workspace counter), observations, VM
/// counters, or anything a future `SqlResult` field might add: the manual
/// [`serde::Serialize`] impl below enumerates every emitted field, so a new
/// internal field is dropped from output by default rather than leaked.
///
/// `row_count` is the number of returned visible rows — never a workspace
/// counter. `revision_token` is an opaque digest over the caller-visible
/// response shape and content — columns, rows, truncation and counts — so
/// a complete response that later truncates to the same prefix retokens,
/// while clock-only changes (and differing `as_of_seq`) cannot fake a
/// content change. Any row change retokens.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code, reason = "no host caller until app exposure lands")]
pub(crate) struct AppSqlResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Value>,
    pub truncated: bool,
    pub row_count: usize,
    pub row_count_complete: bool,
    pub revision_token: String,
    pub now_ms_ms: Option<i64>,
    pub time_dependent: bool,
}

impl AppSqlResponse {
    /// Explicit projection the future host wrapper must call: picks only
    /// the allowlisted fields out of the internal result. Never construct
    /// this from anything but a caller-visible [`SqlResult`].
    #[allow(dead_code, reason = "no host caller until app exposure lands")]
    pub(crate) fn project(result: &SqlResult) -> Self {
        Self {
            columns: result.columns.clone(),
            rows: result.rows.clone(),
            truncated: result.truncated,
            row_count: result.row_count,
            row_count_complete: !result.truncated,
            revision_token: crate::canonical_json::digest_json(&json!({
                "columns": result.columns,
                "rows": result.rows,
                "truncated": result.truncated,
                "row_count": result.row_count,
                "row_count_complete": !result.truncated,
            })),
            now_ms_ms: result.now_ms_ms,
            time_dependent: result.time_dependent,
        }
    }
}

impl serde::Serialize for AppSqlResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("AppSqlResponse", 8)?;
        out.serialize_field("columns", &self.columns)?;
        out.serialize_field("rows", &self.rows)?;
        out.serialize_field("truncated", &self.truncated)?;
        out.serialize_field("row_count", &self.row_count)?;
        out.serialize_field("row_count_complete", &self.row_count_complete)?;
        out.serialize_field("revision_token", &self.revision_token)?;
        out.serialize_field("now_ms_ms", &self.now_ms_ms)?;
        out.serialize_field("time_dependent", &self.time_dependent)?;
        out.end()
    }
}

/// Column references under one flat-query expression as
/// `(qualifier, column)` pairs, lowercased for SQLite's case-insensitive
/// resolution. Recurses through scalar composites (operators, `CASE`, calls,
/// `LIKE`/`BETWEEN`/`IN`-list, parentheses, array/subscript, field access);
/// literals and bind variables carry no column and are admitted. `count(*)`
/// is a relation-level read (only its `FILTER` adds columns). Anything else
/// that can read outside the query's FROM scope — subqueries, table `IN`,
/// other `f(*)` spellings, windowed calls, doubly-qualified names and
/// resolved-internal nodes — is refused so the analyzer never under-reports.
fn collect_flat_refs(
    expr: &Expr,
    out: &mut Vec<(Option<String>, String)>,
) -> std::result::Result<(), String> {
    let invalid = |detail: &str| format!("{TOOL}: sql {detail} [invalid_sql]");
    let lower = |name: &turso_parser::ast::Name| name.as_str().to_ascii_lowercase();
    match expr {
        Expr::Id(name) | Expr::Name(name) => out.push((None, lower(name))),
        Expr::Qualified(table, column) => out.push((Some(lower(table)), lower(column))),
        Expr::DoublyQualified(..) => {
            return Err(invalid("database-qualified columns are unsupported"));
        }
        Expr::Exists(_)
        | Expr::InSelect { .. }
        | Expr::Subquery(_)
        | Expr::SubqueryResult { .. } => {
            return Err(invalid("subqueries are unsupported"));
        }
        Expr::InTable { .. } => return Err(invalid("table IN is unsupported")),
        Expr::FunctionCallStar { name, filter_over } => {
            // `count(*)` is a relation-level read: the seeded base grant
            // already covers it, so only FILTER columns are tracked. Every
            // other `f(*)` spelling stays refused — only `count` is proven
            // portable here (`sum(*)` et al. differ across engines).
            if lower(name) != "count" {
                return Err(invalid("'f(*)' needs explicit columns"));
            }
            if filter_over.over_clause.is_some() {
                return Err(invalid("window functions are unsupported"));
            }
            if let Some(filter) = filter_over.filter_clause.as_ref() {
                collect_flat_refs(filter, out)?;
            }
        }
        Expr::Column { .. } | Expr::RowId { .. } | Expr::Register(_) => {
            return Err(invalid("has an unsupported expression"));
        }
        Expr::Literal(_) | Expr::Variable(_) | Expr::Default => {}
        Expr::Binary(left, _, right) => {
            collect_flat_refs(left, out)?;
            collect_flat_refs(right, out)?;
        }
        Expr::Unary(_, operand)
        | Expr::IsNull(operand)
        | Expr::NotNull(operand)
        | Expr::Collate(operand, _)
        | Expr::Cast { expr: operand, .. } => {
            collect_flat_refs(operand, out)?;
        }
        Expr::Case {
            base,
            when_then_pairs,
            else_expr,
        } => {
            if let Some(base) = base {
                collect_flat_refs(base, out)?;
            }
            for (when, then) in when_then_pairs {
                collect_flat_refs(when, out)?;
                collect_flat_refs(then, out)?;
            }
            if let Some(other) = else_expr {
                collect_flat_refs(other, out)?;
            }
        }
        Expr::FunctionCall {
            args,
            order_by,
            within_group,
            filter_over,
            ..
        } => {
            if filter_over.over_clause.is_some() {
                return Err(invalid("window functions are unsupported"));
            }
            for arg in args {
                collect_flat_refs(arg, out)?;
            }
            for sorted in order_by.iter().chain(within_group.iter()) {
                collect_flat_refs(&sorted.expr, out)?;
            }
            if let Some(filter) = filter_over.filter_clause.as_ref() {
                collect_flat_refs(filter, out)?;
            }
        }
        Expr::Like {
            lhs, rhs, escape, ..
        } => {
            collect_flat_refs(lhs, out)?;
            collect_flat_refs(rhs, out)?;
            if let Some(escape) = escape {
                collect_flat_refs(escape, out)?;
            }
        }
        Expr::Between {
            lhs, start, end, ..
        } => {
            collect_flat_refs(lhs, out)?;
            collect_flat_refs(start, out)?;
            collect_flat_refs(end, out)?;
        }
        Expr::InList { lhs, rhs, .. } => {
            collect_flat_refs(lhs, out)?;
            for value in rhs {
                collect_flat_refs(value, out)?;
            }
        }
        Expr::Parenthesized(values) => {
            for value in values {
                collect_flat_refs(value, out)?;
            }
        }
        Expr::Array { elements } => {
            for element in elements {
                collect_flat_refs(element, out)?;
            }
        }
        Expr::Subscript { base, index } => {
            collect_flat_refs(base, out)?;
            collect_flat_refs(index, out)?;
        }
        Expr::FieldAccess { base, .. } => collect_flat_refs(base, out)?,
        Expr::Raise(_, operand) => {
            if let Some(operand) = operand {
                collect_flat_refs(operand, out)?;
            }
        }
    }
    Ok(())
}

/// Canonical declaration form: exactly `needs` + `effects`, each sorted
/// ascending by UTF-8 bytes with duplicates preserved, plus — only when the
/// declaration holds at least one `sql.snapshot.v1` entry — a `sql_needs`
/// array of the canonical `{key, label, need, sql}` objects (plus `params`
/// in declared order when the entry declares any) sorted by `key`
/// (then `sql` to keep duplicates adjacent). Object key order is irrelevant
/// (JCS); array order is normalized here because consent covers the declared
/// set, not the author's ordering. Param-less entries canonicalize exactly
/// as before, so their digests are byte-identical.
///
/// Facet-set object effects canonicalize with their full bounds (`effect`,
/// `key`, `target`, sorted `values`), ordered by canonical bytes after the
/// sorted strings. Comment.create objects canonicalize with their full
/// bounds (`effect`, sorted `positions`, `target`, `max_body_bytes`) in the
/// same global byte order. A string-only declaration takes the historical
/// shape exactly, so its digest is unchanged by either slice.
///
/// Fail-closed: a non-string `needs` entry must parse as a well-formed
/// `sql.snapshot.v1` entry (`invalid_sql_need`), never digest as absent.
/// Two declarations differing only by an invalid entry must not digest
/// identically; install rejects them, and the digest refuses too, so the
/// guarantee does not depend on the install path having run.
///
/// Compatibility: a string-only declaration canonicalizes to exactly
/// `{"needs": [...], "effects": [...]}` as before, so its digest is
/// unchanged by this slice.
///
/// `reads.v1` (task `c2ca43a`) binds into the same digest: a declaration
/// carrying `reads` canonicalizes with a normalized `reads` object, while
/// a declaration without `reads` keeps the historical shape exactly, so
/// legacy digests are unchanged.
pub fn alpha_tab_canonical_declaration(declaration: &Value) -> Result<Value> {
    // Direct digest callers must validate the whole Body list, including needs.
    parse_body_set_bounds(declaration).map_err(Error::engine)?;
    let names = |key: &str| -> Vec<String> {
        let mut out: Vec<String> = declaration
            .get(key)
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        out
    };
    let body_read = body_read_descriptor_in(declaration).map_err(Error::engine)?;
    let mut sql_needs: Vec<Value> = Vec::new();
    if let Some(entries) = declaration.get("needs").and_then(Value::as_array) {
        for entry in entries {
            if entry.is_string() {
                continue;
            }
            let parsed = match classify_declaration_need(entry).map_err(Error::engine)? {
                DeclarationNeed::Sql(need) => need,
                DeclarationNeed::Name(_) | DeclarationNeed::BodyRead => continue,
            };
            if parsed.params.is_empty() {
                sql_needs.push(json!({
                    "key": parsed.key,
                    "label": parsed.label,
                    "need": SQL_SNAPSHOT_NEED,
                    "sql": parsed.sql,
                }));
            } else {
                sql_needs.push(json!({
                    "key": parsed.key,
                    "label": parsed.label,
                    "need": SQL_SNAPSHOT_NEED,
                    "sql": parsed.sql,
                    "params": canonical_sql_params(&parsed.params),
                }));
            }
        }
    }
    sql_needs.sort_by(|left, right| {
        let key = |value: &Value| {
            (
                value
                    .get("key")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                value
                    .get("sql")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            )
        };
        key(left).cmp(&key(right))
    });
    // Facet-set, comment.create and message.react objects canonicalize
    // with their full bounds together, sorted by canonical bytes; strings
    // keep the historical sorted order. With no comment or react objects
    // the facet group keeps its exact historical order, so those digests
    // are byte-identical. Fail-closed like SQL needs: an invalid object
    // never digests as absent.
    let mut effect_objects: Vec<Value> = Vec::new();
    if let Some(entries) = declaration.get("effects").and_then(Value::as_array) {
        for entry in entries {
            if entry.is_string() {
                continue;
            }
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(COMMENT_CREATE_EFFECT)
            {
                let bound = parse_comment_create_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": COMMENT_CREATE_EFFECT,
                    "positions": bound.positions,
                    "target": { "need": bound.need },
                    "max_body_bytes": bound.max_body_bytes,
                }));
                continue;
            }
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(MESSAGE_REACT_EFFECT)
            {
                let bound = parse_message_react_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": MESSAGE_REACT_EFFECT,
                    "emoji": bound.emoji,
                    "target": { "need": bound.need },
                }));
                continue;
            }
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(TITLE_SET_EFFECT)
            {
                let bound = parse_title_set_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": TITLE_SET_EFFECT,
                    "target": { "need": bound.need },
                }));
                continue;
            }
            if entry.get("effect").and_then(Value::as_str) == Some(BODY_SET_EFFECT) {
                let bound = parse_body_set_bound(entry).map_err(Error::engine)?;
                effect_objects.push(json!({
                    "effect": BODY_SET_EFFECT,
                    "max_body_bytes": bound.max_body_bytes,
                    "target": { "need": bound.need },
                }));
                continue;
            }
            let bound = parse_facet_set_bound(entry).map_err(Error::engine)?;
            effect_objects.push(json!({
                "effect": FACET_SET_EFFECT,
                "key": bound.key,
                "target": { "need": bound.need },
                "values": bound.values,
            }));
        }
    }
    effect_objects.sort_by_cached_key(crate::canonical_json::digest_json);
    let mut effects: Vec<Value> = names("effects").into_iter().map(Value::String).collect();
    effects.extend(effect_objects);
    // `reads.v1` binds into the same digest: a declaration without `reads`
    // canonicalizes exactly as before (no `reads` key), so legacy digests
    // are byte-identical. A present `reads` fails closed here too, so the
    // pin never depends on the install path having run.
    let reads = match declaration.get(READS_DECLARATION_KEY) {
        None => None,
        Some(value) => Some(canonical_reads_declaration(
            &parse_reads_declaration(value).map_err(Error::engine)?,
        )),
    };
    let mut canonical = match (sql_needs.is_empty(), reads) {
        (true, None) => json!({"needs": names("needs"), "effects": effects}),
        (false, None) => {
            json!({"needs": names("needs"), "effects": effects, "sql_needs": sql_needs})
        }
        (true, Some(reads)) => json!({"needs": names("needs"), "effects": effects, "reads": reads}),
        (false, Some(reads)) => {
            json!({"needs": names("needs"), "effects": effects, "sql_needs": sql_needs, "reads": reads})
        }
    };
    // Optional `sessions` is bound iff present, so a declaration without it
    // canonicalises byte-identically to before this slice.
    if declaration.get("sessions").is_some() {
        let sessions = crate::alpha_tab_sessions::canonical_sessions(declaration.get("sessions"))
            .map_err(Error::engine)?;
        if let (Some(object), Some(list)) = (canonical.as_object_mut(), sessions) {
            object.insert("sessions".to_string(), Value::Array(list));
        }
    }
    if body_read {
        canonical
            .as_object_mut()
            .expect("canonical declaration object")
            .insert(
                "body_read_needs".into(),
                json!([{ "need": BODY_READ_NEED, "scope": BODY_READ_SCOPE }]),
            );
    }
    Ok(canonical)
}

/// Canonical declaration digest: hex SHA-256 over the JCS bytes of the
/// canonical form. No `sha256:` prefix (matches the stored
/// `declaration_digest` hex convention); deliberately NOT the install-time
/// raw hash, which is order-sensitive storage rather than proof input.
/// Fails closed on malformed SQL or body descriptors rather than digesting
/// them as absent. Body descriptor digest support grants no public admission.
pub fn alpha_tab_declaration_digest(declaration: &Value) -> Result<String> {
    Ok(crate::canonical_json::digest_json(
        &alpha_tab_canonical_declaration(declaration)?,
    ))
}

/// Canonical alpha-tab digest `alpha-tab-digest.v1`: `sha256:` plus hex
/// SHA-256 over the JCS bytes of
/// `{bundle_sha256, declaration_digest, runtime}`. Key order is fixed by
/// JCS; all three inputs are exact strings (lowercase hex digests, exact
/// runtime facet value).
pub fn alpha_tab_digest(
    bundle_sha256_hex: &str,
    declaration_digest_hex: &str,
    runtime: &str,
) -> String {
    let input = json!({
        "bundle_sha256": bundle_sha256_hex,
        "declaration_digest": declaration_digest_hex,
        "runtime": runtime,
    });
    format!("sha256:{}", crate::canonical_json::digest_json(&input))
}

/// Install-intrinsic plus authority launch gates (no I/O): status, then
/// verified adoption, then target liveness and viewer View. First refusal
/// wins, in the fixed precedence of
/// `docs/alpha-tab-install-slice2.md` §3.
pub(crate) fn evaluate_alpha_tab_install_gates(
    status: &str,
    adoption: &str,
    target: TargetState,
    can_view: bool,
) -> std::result::Result<(), &'static str> {
    if status == "removed" {
        return Err("removed");
    }
    if status == "disabled" {
        return Err("disabled");
    }
    if !VERIFIED_ALPHA_TAB_ADOPTIONS.contains(&adoption) {
        return Err("adoption_unverified");
    }
    match target {
        TargetState::Missing => Err("missing"),
        TargetState::Archived => Err("archived"),
        TargetState::WrongRecordType => Err("wrong_record_type"),
        TargetState::Resolvable if !can_view => Err("unauthorized"),
        TargetState::Resolvable => Ok(()),
    }
}

/// Source plus digest launch gates over already-resolved material: runtime
/// presence, §2 source resolution, §1 digest recomputation match. Evaluated
/// only after the install gates pass, so refused installs cost no I/O.
pub(crate) fn evaluate_alpha_tab_source_gates(
    runtime_present: bool,
    source_resolved: bool,
    digest_matches: bool,
) -> std::result::Result<(), &'static str> {
    if !runtime_present {
        return Err("not_renderable");
    }
    if !source_resolved {
        return Err("source_revision_unresolved");
    }
    if !digest_matches {
        return Err("digest_mismatch");
    }
    Ok(())
}

/// Inspection never issues a ticket; an explicit launch call is required.
pub(crate) fn evaluate_alpha_tab_ticket_gate() -> std::result::Result<(), &'static str> {
    Err(ALPHA_TAB_LAUNCH_REQUEST_REQUIRED)
}

/// In-transaction exact personal-install guard for one
/// `invoke_artifact_interaction` facet write (task `26ba75a` L2 backend
/// slice).
///
/// Checked inside the write transaction that will append, against the same
/// account's install (`caller.credential()`), so a host inspect→invoke race
/// after `disable`/`remove`/reinstall cannot slip between the check and the
/// append: both the control transition and this write hold `BEGIN IMMEDIATE`,
/// so they serialize.
///
/// Reuses the launch-gate helpers rather than duplicating them:
/// `evaluate_alpha_tab_install_gates` for status → verified `shell_adopt.v1`
/// adoption → target liveness + viewer `View`, then
/// `evaluate_alpha_tab_source_gates` for runtime presence → exact
/// body-carrying source event → `alpha-tab-digest.v1` recomputation. Exact
/// pin equality (package generation CAS, artifact, source revision, version,
/// digest, declaration digest) plus invocation binding
/// (`guard.artifact_id == invocation.artifact_id`,
/// `invocation.source_digest == consented bundle`) is checked alongside.
///
/// Effect consent is install-side only: the install's consented
/// `effects` must include the effect the entry's arm requires —
/// [`ALPHA_TRIAGE_SET_EFFECT`] for the triage pair,
/// [`TASKS_LIFECYCLE_SET_EFFECT`] for the tasks lifecycle arm. A declared
/// v2 manifest interaction alone, or a matching bundle digest alone, is
/// never consent. The guard envelope carries no effect name; the arm is
/// derived from the actual parsed manifest entry, never caller text.
///
/// Scope is entry-side: even with effect consent, only the declared triage
/// `facet.set` / `facet.unset` pair on [`ALPHA_GUARD_FACET`] or the tasks
/// `facet.set` arm on [`TASKS_LIFECYCLE_FACET`] with a declared literal
/// [`TASKS_LIFECYCLE_TARGET`] value may commit.
/// Checked against the actual parsed manifest `entry` — never caller text —
/// so consent to either effect cannot authorize `record.create`, another
/// facet, or another lifecycle value. Guarded writes additionally require
/// `native.html.v1`, matching the alpha launch path.
///
/// Returns `Ok(None)` when the guard passes, `Ok(Some((code, message)))`
/// when it refuses. A refusal names the personal install only — it never
/// claims the artifact is globally disabled for other Workbench use.
///
/// N2 b2 retains this pair API for tests; the forward dispatcher resolves
/// through `resolve_alpha_declaring_package_in` with no second install
/// read. Comment/react/title dispatchers keep their own pair APIs until
/// the later comment increment.
#[allow(dead_code)]
pub(crate) async fn check_alpha_install_guard_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
) -> Result<Option<(String, String)>> {
    check_install_guard_core_in(
        tx,
        caller,
        guard,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        GuardScope::Facet,
    )
    .await
}

/// Scope policy for the install-guard core below: which arm family one
/// check admits. The public facet entry point keeps `Facet` behavior
/// exactly; the canonical hosted comment path uses `Comment`; the
/// canonical hosted reaction path uses `React`; the canonical hosted
/// title path uses `Title`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuardScope<'a> {
    /// Legacy facet arms (triage pair, tasks lifecycle, generic facet.set),
    /// including refusal of comment entries — byte-identical behavior.
    Facet,
    /// Comment posting with a fixed validated thread position. Used by
    /// the canonical hosted comment write path.
    Comment { position: &'a str },
    /// Message reaction with a fixed invocation emoji. Used by the
    /// canonical hosted reaction write path.
    React { emoji: &'a str },
    /// Title rename with no invocation discriminator. Used by the
    /// canonical hosted title write path.
    Title,
    /// Dormant static Body admission only; no operational consumer.
    #[allow(dead_code)]
    Body,
}

/// Comment install guard for the canonical hosted comment write path.
/// Same install/account/status/adoption/generation/source pins,
/// declaration, runtime-HTML, source-hash and View checks as the facet
/// guard, plus comment object admission for the fixed validated position.
/// Refusal-shape only; the kernel re-proves binding and need membership on
/// the same transaction before any replay. N2b2 migrated the comment kernel
/// to [`resolve_alpha_declaring_package_in`] with the same scope and row
/// core, so this pair API is retained for unmigrated callers and tests only
/// — byte-identical, no second install read on the migrated path.
#[allow(dead_code)]
pub(crate) async fn check_comment_install_guard_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    position: &str,
) -> Result<Option<(String, String)>> {
    check_install_guard_core_in(
        tx,
        caller,
        guard,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        GuardScope::Comment { position },
    )
    .await
}

/// React install guard for the canonical hosted reaction write path.
/// Same install/account/status/adoption/generation/source pins,
/// declaration, runtime-HTML, source-hash and View checks as the facet
/// guard, plus react object admission for the invocation emoji.
/// Refusal-shape only; the kernel re-proves binding and need membership on
/// the same transaction before any replay. N2c1 migrated the reaction kernel
/// to [`resolve_alpha_declaring_package_in`] with the same scope and row
/// core, so this pair API is retained for unmigrated callers and tests only
/// — byte-identical, no second install read on the migrated path.
#[allow(dead_code)]
pub(crate) async fn check_react_install_guard_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    emoji: &str,
) -> Result<Option<(String, String)>> {
    check_install_guard_core_in(
        tx,
        caller,
        guard,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        GuardScope::React { emoji },
    )
    .await
}

/// Title install guard for the canonical hosted title write path.
/// Same install/account/status/adoption/generation/source pins,
/// declaration, runtime-HTML, source-hash and View checks as the facet
/// guard, plus title object admission. Refusal-shape only; the kernel
/// re-proves binding and need membership on the same transaction before
/// any replay. N2c2 migrated the title kernel to
/// [`resolve_alpha_declaring_package_in`] with the same scope and row core,
/// so this pair API is retained for unmigrated callers and tests only —
/// byte-identical, no second install read on the migrated path.
#[allow(dead_code)]
pub(crate) async fn check_title_install_guard_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
) -> Result<Option<(String, String)>> {
    check_install_guard_core_in(
        tx,
        caller,
        guard,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        GuardScope::Title,
    )
    .await
}

/// The one install row and the static decision made from its declaration.
struct AdmittedInstallRow {
    row: InstallRow,
    admitted: super::effect_bounds::Admitted,
}

/// Common guard core: screen scope before I/O, check generation/full pins,
/// admit static consent, then gate target/View/status/adoption and source.
/// Carry the same row and decision only on complete success. The pair and
/// package-only compatibility APIs may discard the decision until N3c.
async fn check_install_guard_core_row_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    scope: GuardScope<'_>,
) -> Result<std::result::Result<AdmittedInstallRow, AdmissionRefusal>> {
    // Scope first, before any install I/O: the actual parsed entry decides,
    // never caller text. Consent to triage-set authorizes only the triage
    // facet.set/unset pair.
    if scope == GuardScope::Facet
        && entry.effect == native_artifact_runtime::mdx_v2::InteractionEffect::CommentCreate
    {
        // A facet-scoped guard cannot authorize a comment effect.
        // Refuse before any install I/O so a comment entry cannot
        // reach the facet consent checks.
        return Ok(Err(AdmissionRefusal::ScopeUnsupported {
            reason: ScopeUnsupportedReason::CommentUnderFacet,
        }));
    }
    if scope == GuardScope::Facet
        && !matches!(
            entry.effect,
            native_artifact_runtime::mdx_v2::InteractionEffect::FacetSet
                | native_artifact_runtime::mdx_v2::InteractionEffect::FacetUnset
        )
    {
        return Ok(Err(AdmissionRefusal::ScopeUnsupported {
            reason: ScopeUnsupportedReason::NonPairUnderFacet,
        }));
    }
    // Catalogue scope check: the actual parsed entry decides, never caller
    // text. Triage and lifecycle arms keep the same admission, code and
    // wording as before; ordinary facet.set entries additionally reach the
    // object-bound consent stage below (legacy string-only installs keep
    // this exact refusal there). Comment scope skips this facet wording
    // entirely — its consent check below is object-only.
    if scope == GuardScope::Facet && super::tab_effect_catalogue::match_arm(entry).is_none() {
        return Ok(Err(AdmissionRefusal::Unconsented {
            reason: UnconsentedReason::FacetCatalogueMiss {
                entry_id: entry.id.clone(),
                facet: entry.facet.clone(),
            },
        }));
    }
    if let GuardScope::Comment { position } = scope {
        // Comment scope admits only an actual parsed comment.create entry
        // carrying its envelope, and the supplied position must equal the
        // entry's own validated position — a forged position diverges here,
        // before any install I/O, like the facet scope above.
        if entry.effect != native_artifact_runtime::mdx_v2::InteractionEffect::CommentCreate {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonCommentEntry,
            }));
        }
        let Some(envelope) = &entry.comment else {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonCommentEntry,
            }));
        };
        let actual = match envelope.position {
            native_artifact_runtime::mdx_v2::CommentPosition::Root => "root",
            native_artifact_runtime::mdx_v2::CommentPosition::Reply => "reply",
        };
        if position != actual {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::PositionDiverge {
                    expected: position.to_owned(),
                    actual: actual.to_owned(),
                },
            }));
        }
    }
    if let GuardScope::React { emoji } = scope {
        // React scope admits only an actual parsed message.react entry
        // carrying its envelope, and the supplied invocation emoji must
        // sit inside the entry's own validated manifest subset — a forged
        // emoji diverges here, before any install I/O, like the comment
        // scope above. Consent-subset admission runs below against the
        // stored declaration.
        if entry.effect != native_artifact_runtime::mdx_v2::InteractionEffect::MessageReact {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonReactEntry,
            }));
        }
        let Some(envelope) = &entry.react else {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonReactEntry,
            }));
        };
        if !envelope.emoji.iter().any(|allowed| allowed == emoji) {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::EmojiOutsideSubset,
            }));
        }
    }
    if scope == GuardScope::Title {
        // Title scope admits only an actual parsed title.set entry
        // carrying its envelope. There is no invocation discriminator to
        // compare — the title value is free text — so this only proves the
        // entry shape here, before any install I/O. Consent admission runs
        // below against the stored declaration.
        if entry.effect != native_artifact_runtime::mdx_v2::InteractionEffect::TitleSet
            || entry.title.is_none()
        {
            return Ok(Err(AdmissionRefusal::ScopeUnsupported {
                reason: ScopeUnsupportedReason::NonTitleEntry,
            }));
        }
    }
    if scope == GuardScope::Body
        && (entry.effect != native_artifact_runtime::mdx_v2::InteractionEffect::BodySet
            || !entry
                .body
                .as_ref()
                .is_some_and(|body| (1..=BODY_SET_MAX_BODY_BYTES).contains(&body.max_bytes))
            || !entry.facet.is_empty()
            || entry.value.is_some()
            || entry.create.is_some()
            || entry.comment.is_some()
            || entry.react.is_some()
            || entry.title.is_some())
    {
        return Ok(Err(AdmissionRefusal::ScopeUnsupported {
            reason: ScopeUnsupportedReason::NonBodyEntry,
        }));
    }
    let account_id = caller.credential().trim().to_string();
    if account_id.is_empty() {
        return Ok(Err(AdmissionRefusal::NoPackage));
    }
    if guard.artifact_id != invocation_artifact_id {
        return Ok(Err(AdmissionRefusal::PinMismatch {
            kind: PinMismatchKind::ArtifactVsInvocation,
        }));
    }
    let Some(row) = install_row_in(tx, &account_id, &guard.package).await? else {
        return Ok(Err(AdmissionRefusal::PackageMissing {
            package: guard.package.clone(),
        }));
    };
    if guard.expected_install_event_id != row.event_id {
        return Ok(Err(AdmissionRefusal::Stale {
            expected: guard.expected_install_event_id.clone(),
            current: row.event_id.clone(),
        }));
    }
    if guard.artifact_id != row.artifact_id
        || guard.source_revision != row.consented_source_revision
        || guard.version != row.version
        || guard.digest != row.digest
        || guard.declaration_digest != row.declaration_digest
    {
        return Ok(Err(AdmissionRefusal::PinMismatch {
            kind: PinMismatchKind::GuardVsStored,
        }));
    }
    // Static consent stays after generation/full pins and before any later
    // target/View/status/adoption/runtime/declaration/source I/O. Dynamic
    // need/binding gates remain after replay in the consuming kernels.
    // Facet screening guarantees a match; unknown facet entries retain
    // their historical pre-I/O refusal. Object scopes select their validated
    // effect directly, preserving the old scope-first consent choice even
    // for an entry whose incidental facet field matches the triage row.
    use super::tab_effect_catalogue::TabEffectArm;
    let arm = match scope {
        GuardScope::Facet => super::tab_effect_catalogue::match_arm(entry)
            .expect("validated facet scope has a catalogue row"),
        GuardScope::Comment { .. } => TabEffectArm::CommentCreate,
        GuardScope::React { .. } => TabEffectArm::MessageReact,
        GuardScope::Title => TabEffectArm::TitleSet,
        GuardScope::Body => TabEffectArm::BodySet,
    };
    let ctx = super::effect_bounds::AdmissionContext {
        source: super::effect_admission::AdmissionSource::AlphaTabInstall,
        package: &row.package,
        position: match scope {
            GuardScope::Comment { position } => Some(position),
            _ => None,
        },
        emoji: match scope {
            GuardScope::React { emoji } => Some(emoji),
            _ => None,
        },
    };
    let admitted = match super::effect_bounds::admit(arm, &row.consented_declaration, entry, &ctx) {
        Ok(admitted) => admitted,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let target = target_state_in(tx, &row.artifact_id).await?;
    let can_view = if target == TargetState::Resolvable {
        super::can_record_in(tx, caller, &row.artifact_id, Capability::View).await?
    } else {
        false
    };
    if let Err(reason) =
        evaluate_alpha_tab_install_gates(&row.status, &row.adoption, target, can_view)
    {
        let refusal = match reason {
            "removed" => AdmissionRefusal::Inactive {
                state: InactiveState::Removed,
                package: row.package.clone(),
            },
            "disabled" => AdmissionRefusal::Inactive {
                state: InactiveState::Disabled,
                package: row.package.clone(),
            },
            "adoption_unverified" => AdmissionRefusal::AdoptionUnverified {
                package: row.package.clone(),
            },
            "missing" => AdmissionRefusal::TargetUnavailable {
                reason: TargetUnavailableReason::Missing,
                package: row.package.clone(),
                artifact_id: row.artifact_id.clone(),
            },
            "archived" => AdmissionRefusal::TargetUnavailable {
                reason: TargetUnavailableReason::Archived,
                package: row.package.clone(),
                artifact_id: row.artifact_id.clone(),
            },
            "wrong_record_type" => AdmissionRefusal::TargetUnavailable {
                reason: TargetUnavailableReason::WrongRecordType,
                package: row.package.clone(),
                artifact_id: row.artifact_id.clone(),
            },
            _ => AdmissionRefusal::TargetUnavailable {
                reason: TargetUnavailableReason::Unauthorized,
                package: row.package.clone(),
                artifact_id: row.artifact_id.clone(),
            },
        };
        return Ok(Err(refusal));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&row.artifact_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let declaration_digest = alpha_tab_declaration_digest(&row.consented_declaration)?;
    if declaration_digest != row.declaration_digest {
        return Ok(Err(AdmissionRefusal::DeclarationMismatch));
    }
    let source =
        resolve_alpha_tab_source_in(tx, &row.artifact_id, &row.consented_source_revision).await?;
    let digest_matches = match (&runtime, &source) {
        (Some(runtime), Some(source)) => {
            alpha_tab_digest(
                &alpha_tab_bundle_digest(&source.body),
                &declaration_digest,
                runtime,
            ) == row.digest
        }
        _ => false,
    };
    // Guarded writes require native.html.v1, matching the alpha launch path
    // (which admits HTML only). The same source-gate helper is reused with
    // the HTML-only set; an MDX artifact with a guard refuses here, before
    // any write, even with an otherwise valid pin.
    let runtime_present = runtime.as_deref() == Some("native.html.v1");
    if let Err(reason) =
        evaluate_alpha_tab_source_gates(runtime_present, source.is_some(), digest_matches)
    {
        let refusal = match reason {
            "not_renderable" => AdmissionRefusal::SourceUnresolved {
                reason: SourceUnresolvedReason::NotRenderable,
            },
            "source_revision_unresolved" => AdmissionRefusal::SourceUnresolved {
                reason: SourceUnresolvedReason::RevisionUnresolved,
            },
            _ => AdmissionRefusal::SourceUnresolved {
                reason: SourceUnresolvedReason::DigestMismatch,
            },
        };
        return Ok(Err(refusal));
    }
    let source = source.expect("source gate passed");
    let bundle_sha256 = alpha_tab_bundle_digest(&source.body);
    if bundle_sha256 != invocation_source_digest {
        return Ok(Err(AdmissionRefusal::InvocationSourceMismatch));
    }
    Ok(Ok(AdmittedInstallRow { row, admitted }))
}

/// Historical pair API over [`check_install_guard_core_row_in`]: today's
/// callers keep their signatures and refusal shapes unchanged — the row is
/// rendered back to the historical `(code, message)` pair.
async fn check_install_guard_core_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    scope: GuardScope<'_>,
) -> Result<Option<(String, String)>> {
    match check_install_guard_core_row_in(
        tx,
        caller,
        guard,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        scope,
    )
    .await?
    {
        Ok(_) => Ok(None),
        Err(refusal) => Ok(Some(super::effect_admission::render_refusal(
            super::effect_admission::AdmissionSource::AlphaTabInstall,
            &refusal,
        ))),
    }
}

/// Neutral resolution for later consumers: static consent and the package
/// come from the same install row, and neither escapes before all gates pass.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedAlphaAdmission {
    pub package: super::effect_admission::DeclaringPackage,
    pub admitted: super::effect_bounds::Admitted,
}

/// Historical package-only compatibility API; production consumes admission.
#[allow(dead_code)] // Retained for compatibility and literal resolver oracles.
pub(crate) async fn resolve_alpha_declaring_package_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    claim: super::effect_admission::PackageClaim<'_>,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    scope: GuardScope<'_>,
) -> Result<std::result::Result<super::effect_admission::DeclaringPackage, AdmissionRefusal>> {
    Ok(resolve_alpha_admission_in(
        tx,
        caller,
        claim,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        scope,
    )
    .await?
    .map(|resolved| resolved.package))
}

/// Preserve guard staging and carry the already-read row's admission.
pub(crate) async fn resolve_alpha_admission_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    claim: super::effect_admission::PackageClaim<'_>,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    scope: GuardScope<'_>,
) -> Result<std::result::Result<ResolvedAlphaAdmission, super::effect_admission::AdmissionRefusal>>
{
    use super::effect_admission::{
        alpha_consent_for_adoption, AdmissionRefusal, AdmissionSource, DeclaringPackage,
    };
    if claim.source != AdmissionSource::AlphaTabInstall {
        // Fail closed at runtime (not just debug_assert): only alpha claims
        // resolve against the install table. No install I/O on this path, so
        // a misrouted claim can never become an alpha-resolved package, in
        // release as in debug. The crate-visible claim fields make this a
        // genuine boundary, not a type-level one.
        return Ok(Err(AdmissionRefusal::NoPackage));
    }
    let AdmittedInstallRow { row, admitted } = match check_install_guard_core_row_in(
        tx,
        caller,
        claim.pin,
        invocation_artifact_id,
        invocation_source_digest,
        entry,
        scope,
    )
    .await?
    {
        Ok(row) => row,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // The core passes only verified adoption, mirroring the existing
    // `expect("source gate passed")` style for an invariant the gates above
    // just established.
    let consent =
        alpha_consent_for_adoption(&row.adoption).expect("guard passes only verified adoption");
    Ok(Ok(ResolvedAlphaAdmission {
        package: DeclaringPackage {
            source: claim.source,
            consent,
            package: row.package,
            generation: row.event_id,
            artifact_id: row.artifact_id,
            source_revision: row.consented_source_revision,
            declaration: row.consented_declaration,
            declaration_digest: row.declaration_digest,
        },
        admitted,
    }))
}

/// Hosted HTTP authority gate for preview-receipt issue and adopt confirm
/// (slice 3 §2, §4).
///
/// Both operations mint or consume server-stamped adoption authority, so
/// they require the same narrow first-party proof as the verified-human
/// precedent (`mutate_human_awareness/presented` in `held/hosting`): a
/// cookie-authenticated session (`source == Cookie`) plus a trusted-Origin
/// same-origin POST. Bearer is refused outright — `session_credential`
/// prefers an explicit `Authorization` header, so agents holding a Bearer
/// credential can never pick up this authority by attaching a session
/// cookie beside it — and a missing Origin is refused because there is no
/// same-origin proof to check against the configured trusted origin.
///
/// The 3b shell producer wires it at the hosted HTTP boundary for both
/// issue and confirm; `held/hosting/src/http.rs` enforces it for the
/// `preview` action before dispatch so Bearer agents never receive a
/// receipt. Pure so it is unit-testable without a server.
pub fn alpha_adopt_authority_gate(
    is_bearer: bool,
    origin_present: bool,
) -> std::result::Result<(), &'static str> {
    if is_bearer {
        return Err("bearer_refused");
    }
    if !origin_present {
        return Err("origin_missing");
    }
    Ok(())
}

/// Build the hosted preview attestation for one exact pin, canonicalizing
/// the declaration exactly the way `do_preview` verifies it (sorted
/// needs/effects plus their canonical digest). The hosted plain-JSON
/// adapter calls this after cookie-session plus trusted-Origin checks and
/// attaches the result to the caller; `do_preview` then requires a
/// field-for-field match. Malformed pins simply produce an attestation the
/// tool's own shape validation rejects first — minting never grants
/// anything by itself.
pub fn alpha_tab_preview_authority_for(
    account_id: &str,
    package: &str,
    version: &str,
    digest: &str,
    artifact_id: &str,
    source_revision: &str,
    declaration: &Value,
) -> Option<VerifiedAlphaTabPreview> {
    // Fail closed: a malformed SQL entry mints no authority at all, so the
    // preview path refuses before any pin comparison.
    let canonical = alpha_tab_canonical_declaration(declaration).ok()?;
    let mut needs: Vec<String> = canonical
        .get("needs")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    // Name lists stay names: strings verbatim plus each object bound's
    // effect name. The digest binds the bounds; an invalid object never
    // reaches this list because canonicalization above fails closed first.
    let mut effects: Vec<String> = canonical
        .get("effects")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    entry.as_str().map(str::to_owned).or_else(|| {
                        entry
                            .get("effect")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    needs.sort();
    effects.sort();
    Some(VerifiedAlphaTabPreview::for_pin(
        account_id,
        package,
        version,
        digest,
        artifact_id,
        source_revision,
        alpha_tab_declaration_digest(declaration).ok()?,
        needs,
        effects,
    ))
}

/// Server-held preview receipt (slice 3 §4): authorizes exactly one thing —
/// rendering the pinned bundle bytes against host-supplied sample data, with
/// no governed reads and no intents. Bound to the exact caller account plus
/// the full pin (package, version, digest, artifact, source revision,
/// declaration digest and canonical needs/effects) and the preview session;
/// short expiry (~15 min) and single use.
///
/// Stored in the process-local preview-receipt store below (the same
/// server-held pattern as the HTML launch-ticket store): `do_preview` mints
/// and holds it, the future adopt-confirm path consumes it. No
/// caller-supplied token or field can self-assert that a preview happened
/// or that a receipt exists.
///
/// Process-local limits (see `preview_receipt_store`): the store is
/// per-process memory with expiry eviction and count caps — it is not
/// replicated, not durable across restarts/redeploys, and a receipt minted
/// on one replica is unknown on every other. The adopt-confirm slice must
/// therefore run against the same process (or replace this store with a
/// shared one); cross-instance confirmation is explicitly not claimed.
#[derive(Debug, Clone, PartialEq)]
pub struct AlphaTabPreviewReceipt {
    pub receipt_id: String,
    pub nonce: String,
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub source_revision: String,
    pub declaration_digest: String,
    pub needs: Vec<String>,
    pub effects: Vec<String>,
    pub preview_session: String,
    /// Last durable update observed during preview; never supplied by a client.
    pub last_update_event_id: Option<String>,
    pub issued_at_secs: i64,
    pub expires_at_secs: i64,
}

/// Host-owned representative sample input for preview rendering.
///
/// Static fixture bytes owned by the host — never a governed named-input
/// read, never live record content. The frame receives only this plus the
/// pinned bundle bytes: no viewer authority, no session credential, no live
/// record reaches the frame during preview. `mode: "sample"` plus
/// `sample_preview: true` lets the shell and the frame distinguish preview
/// input from live input without trusting package bytes.
pub fn alpha_tab_sample_input() -> Value {
    json!({
        "version": "native.artifact-input.v1",
        "mode": "sample",
        "sample_preview": true,
        "records": [
            {"id": "sample:attention-1", "type": "Task", "name": "Sample attention item 1",
             "summary": "Host-owned preview fixture — not live data."},
            {"id": "sample:attention-2", "type": "Task", "name": "Sample attention item 2",
             "summary": "Host-owned preview fixture — not live data."}
        ],
        "inputs": {}
    })
}

/// Digest over the exact sample-input JSON bytes (lowercase hex SHA-256),
/// so the preview response binds which sample the frame received.
pub fn alpha_tab_sample_input_digest(sample: &Value) -> String {
    let bytes = serde_json::to_vec(sample).expect("sample input is JSON");
    hex::encode(Sha256::digest(&bytes))
}

/// Process-wide cap on held preview receipts. Preview issuance is
/// shell-driven (one receipt per preview open), so this is many orders of
/// magnitude above honest use; it exists only so a malfunctioning or hostile
/// caller that could reach issuance cannot grow process memory without
/// bound. Expiry eviction runs on every issue before the caps apply.
pub const ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT: usize = 512;

/// Per-account cap on held preview receipts. Keeps one account's preview
/// loop from evicting every other account's live receipts under the global
/// cap above.
pub const ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT: usize = 32;

/// Process-local preview-receipt store. A NEW checked feature preview also
/// stores private generation/scope provenance; legacy receipts carry None.
///
/// Same server-held pattern as the HTML launch-ticket store, with the same
/// honesty boundary, stated plainly because receipts authorize adoption:
/// entries live in this process's memory only. They are not replicated to
/// other replicas, not persisted across restarts or redeploys, and expiry is
/// enforced lazily (swept on issue; reads treat expired as refused via
/// `verify_alpha_tab_adopt_confirm`). A confirm presented to a different
/// process than the one that issued the preview gets `receipt_unknown` —
/// that is a deliberate fail-closed, not a retryable hint, until a later
/// slice replaces this store with shared durable state. Do not claim
/// durable cross-instance confirmation from this slice.
#[derive(Clone)]
struct BodyPreviewBinding {
    install_event_id: String,
    scope: String,
    publication: crate::artifact_html::SamplePublicationMarker,
}
type StoredPreviewReceipt = (AlphaTabPreviewReceipt, bool, Option<BodyPreviewBinding>);

fn preview_receipt_store() -> &'static Mutex<HashMap<String, StoredPreviewReceipt>> {
    static STORE: OnceLock<Mutex<HashMap<String, StoredPreviewReceipt>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Sweep expired receipts, then evict oldest-first down to the global and
/// per-account caps. Oldest is `(issued_at_secs, receipt_id)` order, so
/// eviction is deterministic under test.
fn bound_preview_receipt_store(
    store: &mut HashMap<String, StoredPreviewReceipt>,
    account_id: &str,
    now_secs: i64,
) {
    store.retain(|_, (receipt, _, binding)| {
        receipt.expires_at_secs > now_secs
            && !binding.as_ref().is_some_and(|b| b.publication.is_invalid())
    });
    while store.len() >= ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT {
        let Some(oldest) = store
            .iter()
            .min_by_key(|(id, (receipt, _, _))| (receipt.issued_at_secs, (*id).clone()))
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        store.remove(&oldest);
    }
    while store
        .values()
        .filter(|(receipt, _, _)| receipt.account_id == account_id)
        .count()
        >= ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT
    {
        let Some(oldest) = store
            .iter()
            .filter(|(_, (receipt, _, _))| receipt.account_id == account_id)
            .min_by_key(|(id, (receipt, _, _))| (receipt.issued_at_secs, (*id).clone()))
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        store.remove(&oldest);
    }
}

fn random_hex_32() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Mint and server-hold one preview receipt bound to the exact account plus
/// the full pin and a fresh sample-preview session. Returns the stored
/// receipt; the caller returns its id/nonce/session to the shell. Single
/// use and short-lived: `consumed` starts false and the adopt-confirm path
/// flips it (confirm lands in a later slice).
///
/// Bounding: expired entries are swept on every issue, then oldest-first
/// eviction holds the store to `ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT`
/// process-wide and `ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT` per account.
/// Eviction only discards unreadable-future state — a later confirm for an
/// evicted id fails closed with `receipt_unknown`.
///
/// Process-local: the receipt is held in this process's memory, not in the
/// database and not on any other replica. A multi-replica deployment must
/// route confirm to the issuing process (or replace this store) — preview
/// and confirm on different processes will not meet, by construction.
#[allow(clippy::too_many_arguments)]
pub fn issue_alpha_tab_preview_receipt(
    account_id: &str,
    package: &str,
    version: &str,
    digest: &str,
    artifact_id: &str,
    source_revision: &str,
    declaration_digest: &str,
    needs: Vec<String>,
    effects: Vec<String>,
    last_update_event_id: Option<String>,
    now_secs: i64,
) -> AlphaTabPreviewReceipt {
    let receipt = AlphaTabPreviewReceipt {
        receipt_id: format!("preview_{}", &random_hex_32()[..16]),
        nonce: random_hex_32(),
        account_id: account_id.into(),
        package: package.into(),
        version: version.into(),
        digest: digest.into(),
        artifact_id: artifact_id.into(),
        source_revision: source_revision.into(),
        declaration_digest: declaration_digest.into(),
        needs,
        effects,
        preview_session: format!("sess_{}", &random_hex_32()[..16]),
        last_update_event_id,
        issued_at_secs: now_secs,
        expires_at_secs: now_secs + ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
    };
    let mut store = preview_receipt_store()
        .lock()
        .expect("preview receipt store poisoned");
    bound_preview_receipt_store(&mut store, &receipt.account_id, now_secs);
    store.insert(receipt.receipt_id.clone(), (receipt.clone(), false, None));
    receipt
}

/// Look up one server-held preview receipt by id. Returns the receipt plus
/// its consumed flag; `None` is unknown or a new-feature receipt not Published.
/// Read-only: consumption is
/// the adopt-confirm slice's write.
pub fn find_alpha_tab_preview_receipt(receipt_id: &str) -> Option<(AlphaTabPreviewReceipt, bool)> {
    preview_receipt_store()
        .lock()
        .expect("preview receipt store poisoned")
        .get(receipt_id)
        .filter(|(_, _, binding)| {
            binding
                .as_ref()
                .is_none_or(|b| b.publication.is_published())
        })
        .map(|(receipt, consumed, _)| (receipt.clone(), *consumed))
}

/// Caller-presented adopt confirm: the receipt id/nonce plus the full pin
/// echoed field-for-field, the CAS token, and a 1..1024 reason. Every pin
/// field is compared against the stored receipt; any mismatch is a named
/// refusal with no state change.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub struct AlphaTabAdoptConfirm {
    pub receipt_id: String,
    pub nonce: String,
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub source_revision: String,
    pub declaration_digest: String,
    pub needs: Vec<String>,
    pub effects: Vec<String>,
    pub preview_session: String,
    pub reason: String,
    pub expected_install_event_id: String,
    pub current_event_id: String,
}

/// Confirm-side verification for `adopt` (slice 3 §4). Check order is fixed
/// and first-refusal-wins: authority (Bearer/Origin) → receipt
/// liveness (known, unexpired, unconsumed) → account binding → full pin
/// match → reason shape → CAS. Any mismatch is a named refusal with no
/// state change; on success the caller appends the `alpha_tab.adopted`
/// control event (3b), flips adoption to `ALPHA_TAB_ADOPTION_VERIFIED`,
/// and marks the receipt consumed (single use).
///
/// `stored` is the server-held receipt (`None` = unknown id);
/// `already_consumed` is the store's consumed flag for that id. Pure so the
/// full receipt matrix is unit-testable without a server or a store.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn verify_alpha_tab_adopt_confirm(
    stored: Option<&AlphaTabPreviewReceipt>,
    confirm: &AlphaTabAdoptConfirm,
    now_secs: i64,
    already_consumed: bool,
    is_bearer: bool,
    origin_present: bool,
) -> std::result::Result<(), &'static str> {
    alpha_adopt_authority_gate(is_bearer, origin_present)?;
    let stored = match stored {
        Some(stored) => stored,
        None => return Err("receipt_unknown"),
    };
    if now_secs < stored.issued_at_secs || now_secs >= stored.expires_at_secs {
        return Err("receipt_expired");
    }
    if already_consumed {
        return Err("receipt_consumed");
    }
    if confirm.account_id != stored.account_id {
        return Err("account_mismatch");
    }
    if confirm.receipt_id != stored.receipt_id
        || confirm.nonce != stored.nonce
        || confirm.preview_session != stored.preview_session
        || confirm.package != stored.package
        || confirm.version != stored.version
        || confirm.digest != stored.digest
        || confirm.artifact_id != stored.artifact_id
        || confirm.source_revision != stored.source_revision
        || confirm.declaration_digest != stored.declaration_digest
        || confirm.needs != stored.needs
        || confirm.effects != stored.effects
    {
        return Err("pin_mismatch");
    }
    if confirm.reason.is_empty() || confirm.reason.len() > 1024 {
        return Err("reason_invalid");
    }
    if confirm.expected_install_event_id != confirm.current_event_id {
        return Err("cas_mismatch");
    }
    Ok(())
}

/// Arguments accepted by `manage_alpha_tabs`. Personal scope only: the
/// caller's own `account_id` rows. No workspace scope, no `trusted` mode.
/// M2 subscribe request on `live_read` (design `ee12faf` §2.2): `stream` is
/// the opaque connection token from the `stream` frame, passed back verbatim.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct LiveReadSubscribe {
    pub stream: String,
}

/// Host-only association of a keyed read with its already open snapshot pin.
/// Package code still calls the ordinary `host.read(key, params)` API.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveReadWatch {
    pub stream: String,
    pub subscription: String,
}

struct LiveReadOptions {
    subscribe: Option<LiveReadSubscribe>,
    if_revision: Option<String>,
    watch: Option<LiveReadWatch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub enum ManageAlphaTabsArgs {
    Inspect {
        package: String,
    },
    List {},
    Launch {
        package: String,
        expected_install_event_id: String,
    },
    LiveRead {
        package: String,
        expected_install_event_id: String,
        /// Omitted means `attention.query.v1`, the original snapshot read.
        #[serde(default)]
        need: Option<String>,
        #[serde(default)]
        params: Option<Value>,
        /// M2 subscribe mode (design `ee12faf` §2.2): open a need
        /// subscription on the SSE connection announced by its `stream`
        /// frame. Snapshot reads only; on-request needs refuse with
        /// `invalid_params` (they carry no revision fence).
        #[serde(default)]
        subscribe: Option<LiveReadSubscribe>,
        /// Resync fence (design §2.2): when equal to the evaluated
        /// `revision_digest` (pin included, so a pin change is never
        /// `unchanged`), the read returns `{unchanged: true}` with pin and
        /// revision but no rows. Snapshot reads only.
        #[serde(default)]
        if_revision: Option<String>,
        #[serde(default)]
        watch: Option<LiveReadWatch>,
        /// Batched on-request reads (`batch_read`): several needs answered
        /// in one call, under one gate per pool. Excludes `need`, `params`,
        /// `subscribe`, `if_revision` and `watch`. Host-facing, like `watch`,
        /// so it is not in the published tool schema.
        #[serde(default)]
        reads: Option<Vec<LiveReadItem>>,
    },
    LiveUnsubscribe {
        /// Opaque connection token from the `stream` frame, passed back
        /// verbatim. Unknown or closed tokens succeed with no effect.
        stream: String,
        /// Opaque subscription id from an earlier `subscription` result.
        /// Unknown ids succeed with no effect and can never affect another
        /// connection's subscriptions.
        subscription: String,
    },
    AdmitRevealTarget {
        package: String,
        expected_install_event_id: String,
        record_id: String,
    },
    Preview {
        package: String,
        version: String,
        digest: String,
        artifact_id: String,
        source_revision: String,
        declaration: Value,
        reason: String,
    },
    Adopt {
        package: String,
        version: String,
        digest: String,
        artifact_id: String,
        source_revision: String,
        declaration: Value,
        receipt_id: String,
        nonce: String,
        preview_session: String,
        expected_install_event_id: String,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    AdoptAuthored {
        package: String,
        version: String,
        digest: String,
        artifact_id: String,
        source_revision: String,
        declaration: Value,
        expected_install_event_id: String,
        reason: String,
        /// Opaque launch handle from the desktop shell (E1). Client-asserted
        /// provenance, never verified; bounded length.
        #[serde(default)]
        launch_id: Option<String>,
        /// Run key of the pane agent that authored the adopted revision
        /// (E1). Client-asserted provenance, never verified; bounded length.
        /// Pane binding is enforced by the desktop app (plan `100d273`).
        #[serde(default)]
        authored_run_key: Option<String>,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Install {
        package: String,
        version: String,
        digest: String,
        artifact_id: String,
        source_revision: String,
        declaration: Value,
        reason: String,
        #[serde(default)]
        request: Option<String>,
        #[serde(default)]
        idempotency_key: Option<String>,
        #[serde(default)]
        expected_install_event_id: Option<String>,
    },
    Update {
        package: String,
        version: String,
        digest: String,
        artifact_id: String,
        source_revision: String,
        declaration: Value,
        expected_install_event_id: String,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
        #[serde(default)]
        request: Option<String>,
    },
    Disable {
        package: String,
        expected_install_event_id: String,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Restore {
        package: String,
        expected_install_event_id: String,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Remove {
        package: String,
        expected_install_event_id: String,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Reorder {
        tab_order: Vec<String>,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
}
fn require_reason(tool: &str, reason: &str) -> Result<()> {
    require_nonblank_reason(tool, reason)?;
    if reason.len() > 1024 {
        return Err(Error::engine(format!(
            "{tool}: 'reason' must be 1..1024 bytes"
        )));
    }
    Ok(())
}

/// One client-asserted shell-auto provenance field (E1, task `f1d80b0`):
/// optional, 1..=256 characters when present. A blank string normalizes to
/// absent; an over-long value is a named refusal. The control tier enforces
/// the same bound on write.
fn require_authored_field(label: &str, value: Option<String>) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => Ok(None),
        Some(text) => {
            if text.chars().count() > ALPHA_TAB_AUTHORED_FIELD_MAX_CHARS {
                return Err(Error::engine(format!(
                    "{TOOL}: '{label}' must be 1..={} characters [{label}_too_long]",
                    ALPHA_TAB_AUTHORED_FIELD_MAX_CHARS
                )));
            }
            Ok(Some(text))
        }
    }
}

/// Display-only install request text (E3, task `f1d80b0`): optional, never
/// authority. A blank string is normalized to absent by the caller; a
/// present value must be 1..=500 characters, else a named refusal. The
/// control tier enforces the same bound on write.
fn require_request(request: Option<String>) -> Result<Option<String>> {
    match request {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => Ok(None),
        Some(text) => {
            if text.chars().count() > ALPHA_TAB_REQUEST_MAX_CHARS {
                return Err(Error::engine(format!(
                    "{TOOL}: 'request' must be 1..={} characters [request_too_long]",
                    ALPHA_TAB_REQUEST_MAX_CHARS
                )));
            }
            Ok(Some(text))
        }
    }
}

fn require_account(caller: &Caller) -> Result<String> {
    let account = caller.credential().trim().to_string();
    if account.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: no authenticated account is bound to this caller"
        )));
    }
    Ok(account)
}

/// Reverse-dns package id: dot-separated lowercase labels of alphanumerics
/// and hyphens, at least two labels (e.g. `agent.attention-cockpit`).
pub(crate) fn require_package(package: &str) -> Result<()> {
    if package.len() > 128 {
        return Err(Error::engine(format!(
            "{TOOL}: package must be 1..128 characters"
        )));
    }
    let labels: Vec<&str> = package.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 32
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(Error::engine(format!(
            "{TOOL}: package '{package}' is not a reverse-dns id"
        )));
    }
    Ok(())
}

pub(crate) fn require_version(version: &str) -> Result<()> {
    let parts: Vec<&str> = version.split('.').collect();
    if version.len() > 32
        || parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 8 || !part.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(Error::engine(format!(
            "{TOOL}: version '{version}' is not semver X.Y.Z"
        )));
    }
    Ok(())
}

fn require_digest(digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(Error::engine(format!(
            "{TOOL}: digest must start with 'sha256:'"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::engine(format!(
            "{TOOL}: digest must be 'sha256:' plus 64 lowercase hex characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) use super::effect_bounds::comment_admission;
pub(crate) use super::effect_bounds::{
    facet_set_admission, parse_comment_create_bound, parse_comment_create_bounds,
    parse_facet_set_bound, parse_facet_set_bounds,
};
// Test-only re-export: the positions const moved to `effect_bounds` with
// the parsers, and the drift guard (`alpha_tab_kit_drift`, `#[cfg(test)]`)
// still reads it as `super::COMMENT_CREATE_POSITIONS`. Unused in non-test
// builds by construction.
#[allow(unused_imports)]
pub(crate) use super::effect_bounds::COMMENT_CREATE_POSITIONS;
/// Neutral bounds (D7 §6 N1 pure move): facet-set and comment bounds live
/// in `effect_bounds`; re-exported here so every call site compiles
/// unchanged with identical names, signatures and refusal texts.
pub use super::effect_bounds::{CommentCreateBound, FacetSetBound, FACET_SET_VALUES_MAX};

use super::effect_bounds::{
    parse_body_set_bound, parse_body_set_bounds, parse_message_react_bound,
    parse_message_react_bounds, parse_title_set_bound, parse_title_set_bounds, MessageReactBound,
    TitleSetBound,
};

/// Stored comment consent for the canonical kernel: the install row's
/// consented declaration, re-read on the caller-owned write transaction
/// after the install guard passed on that same transaction. `None` when
/// the install vanished mid-flight or the caller has no account — the
/// kernel refuses, never proceeds on cached consent.
///
/// N3c consumes the already-admitted bound/need from
/// [`resolve_alpha_admission_in`], so this twin no longer has a
/// non-test caller; retained byte-identical for unmigrated callers.
#[allow(dead_code)]
pub(crate) async fn stored_comment_consent_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    package: &str,
) -> Result<Option<Value>> {
    let account_id = caller.credential().trim().to_string();
    if account_id.is_empty() {
        return Ok(None);
    }
    Ok(install_row_in(tx, &account_id, package)
        .await?
        .map(|row| row.consented_declaration))
}

/// Stored react consent for the canonical kernel: same install row,
/// same transaction discipline as the comment twin above.
///
/// N2c1 replaced the reaction kernel's call with `pkg.declaration` from
/// [`resolve_alpha_declaring_package_in`], so this twin no longer has a
/// non-test caller; retained byte-identical for unmigrated callers.
#[allow(dead_code)]
pub(crate) async fn stored_react_consent_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    package: &str,
) -> Result<Option<Value>> {
    let account_id = caller.credential().trim().to_string();
    if account_id.is_empty() {
        return Ok(None);
    }
    Ok(install_row_in(tx, &account_id, package)
        .await?
        .map(|row| row.consented_declaration))
}

/// Stored title consent for the canonical kernel: same install row,
/// same transaction discipline as the comment/react twins above.
///
/// N3c consumes the already-admitted bound/need from
/// [`resolve_alpha_admission_in`], so this twin no longer has a
/// non-test caller; retained byte-identical for unmigrated callers.
#[allow(dead_code)]
pub(crate) async fn stored_title_consent_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    package: &str,
) -> Result<Option<Value>> {
    let account_id = caller.credential().trim().to_string();
    if account_id.is_empty() {
        return Ok(None);
    }
    Ok(install_row_in(tx, &account_id, package)
        .await?
        .map(|row| row.consented_declaration))
}

/// In-transaction delivered-need membership for an admitted facet-set bound.
/// Thin wrapper over the neutral core below: signature, codes, texts,
/// ordering and truncation semantics are identical.
pub(crate) async fn check_facet_set_membership_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    bound: &FacetSetBound,
    need: &SqlNeed,
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    check_delivered_membership_in(
        tx,
        caller,
        MembershipFamily::FacetSet,
        need,
        &format!("key '{}'", bound.key),
        record_id,
    )
    .await
}

/// Delivered-need membership for an admitted comment.create bound, on the
/// caller-owned write transaction. Requires the bound's need to equal the
/// need under test before running anything: only the consented need's SQL
/// ever runs, never invocation SQL. Later kernel use only.
pub(crate) async fn check_comment_membership_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    bound: &CommentCreateBound,
    need: &SqlNeed,
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    if bound.need != need.key {
        return Ok(Some((
            "comment_need_mismatch".into(),
            format!(
                "comment.create bound targets need '{}' but membership ran need '{}'",
                bound.need, need.key
            ),
        )));
    }
    check_delivered_membership_in(
        tx,
        caller,
        MembershipFamily::CommentCreate,
        need,
        &format!("bound '{}'", bound.need),
        record_id,
    )
    .await
}

/// Delivered-need membership for an admitted message.react bound, on the
/// caller-owned write transaction. Requires the bound's need to equal the
/// need under test before running anything: only the consented need's SQL
/// ever runs, never invocation SQL. Later kernel use only.
pub(crate) async fn check_react_membership_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    bound: &MessageReactBound,
    need: &SqlNeed,
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    if bound.need != need.key {
        return Ok(Some((
            "react_need_mismatch".into(),
            format!(
                "message.react bound targets need '{}' but membership ran need '{}'",
                bound.need, need.key
            ),
        )));
    }
    check_delivered_membership_in(
        tx,
        caller,
        MembershipFamily::MessageReact,
        need,
        &format!("bound '{}'", bound.need),
        record_id,
    )
    .await
}

/// Delivered-need membership for an admitted title-set bound, on the
/// caller-owned write transaction. Requires the bound's need to equal the
/// need under test before running anything: only the consented need's SQL
/// ever runs, never invocation SQL. Later kernel use only.
pub(crate) async fn check_title_membership_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    bound: &TitleSetBound,
    need: &SqlNeed,
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    if bound.need != need.key {
        return Ok(Some((
            "title_need_mismatch".into(),
            format!(
                "title-set bound targets need '{}' but membership ran need '{}'",
                bound.need, need.key
            ),
        )));
    }
    check_delivered_membership_in(
        tx,
        caller,
        MembershipFamily::TitleSet,
        need,
        &format!("bound '{}'", bound.need),
        record_id,
    )
    .await
}

/// Dormant Body-only targeted delivery. The target is a server-bound parameter;
/// a prefix, duplicate target, malformed id or time-dependent delivery refuses.
pub(crate) async fn check_body_membership_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    bound: &super::effect_bounds::BodySetBound,
    need: &SqlNeed,
    record_id: &str,
) -> Result<Option<(String, String)>> {
    let refused = |code: &str| {
        Some((
            code.into(),
            "body target need is not a complete singleton delivery".into(),
        ))
    };
    if bound.need != need.key {
        return Ok(refused("body_need_mismatch"));
    }
    if need.params.len() != 1
        || need.params[0].name != "record_id"
        || need.params[0].param_type != SqlParamType::Text
        || !need.params[0].required
        || need.params[0].max_len != 128
    {
        return Ok(refused(MembershipFamily::BodySet.parameterized_code()));
    }
    let parameters = match bind_sql_params(need, Some(&json!({"record_id": record_id}))) {
        Ok(parameters) => parameters,
        Err(_) => return Ok(refused("body_need_parameterized")),
    };
    let (result, _) = crate::query::sql::query_sql_request_in_with_row_limit(
        &mut *tx,
        caller.into(),
        QuerySqlRequest {
            sql: need.sql.clone(),
            parameters,
        },
        2,
        crate::query::sql_contract::FunctionAllowance::Portable,
    )
    .await
    .map_err(crate::query::sql_contract::ensure_categorized)?;
    if result.time_dependent {
        return Ok(refused(MembershipFamily::BodySet.time_code()));
    }
    if result.truncated
        || result.rows.len() != 1
        || result.row_count != 1
        || result
            .columns
            .iter()
            .filter(|column| column.as_str() == "id")
            .count()
            != 1
        || result.rows[0].get("id").and_then(Value::as_str) != Some(record_id)
    {
        return Ok(refused("record_outside_need"));
    }
    Ok(None)
}

/// Exact explicit Body port, sharing ordinary source attestation/input grants.
pub(crate) async fn check_body_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    scope: &[(String, String, String)],
    record_id: &str,
) -> Result<Option<(String, String)>> {
    if !matches!(scope, [(port, _, _)] if !port.is_empty() && port != "default") {
        return Ok(Some((
            "named_input_unbound".into(),
            "body binding requires one explicit input port".into(),
        )));
    }
    check_current_binding_in(
        tx,
        caller,
        artifact_id,
        source_event_id,
        source_sha256,
        scope,
        Some(record_id),
    )
    .await
}

#[cfg(test)]
mod body_targeted_membership_tests {
    use super::*;

    async fn fixture() -> (Db, String, Vec<String>) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tools = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut tools).unwrap();
        let mut ids = Vec::new();
        for name in ["target", "s3b outsider", "s3b outsider", "s3b outsider"] {
            let row = tools.call(db.clone(), Caller::local(), "create_record",
                json!({"type":"Document","kind":"note","name":name,"reason":"Body need fixture"})).await.unwrap();
            ids.push(row["id"].as_str().unwrap().to_owned());
        }
        (db, ids[0].clone(), ids[1..].to_vec())
    }

    fn need(sql: &str) -> SqlNeed {
        SqlNeed {
            key: "docs.body".into(),
            label: "Body".into(),
            sql: sql.into(),
            params: vec![SqlParam {
                name: "record_id".into(),
                param_type: SqlParamType::Text,
                max_len: 128,
                required: true,
            }],
            relations: std::collections::BTreeSet::from(["records".into()]),
        }
    }

    fn bound() -> super::super::effect_bounds::BodySetBound {
        super::super::effect_bounds::BodySetBound {
            need: "docs.body".into(),
            max_body_bytes: 32768,
        }
    }

    #[tokio::test]
    async fn body_targeted_governed_singleton_and_parameter_shape() {
        let (db, target, _) = fixture().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let good = need("SELECT id FROM records WHERE id=?1 AND deleted_at IS NULL");
        assert_eq!(
            check_body_membership_in(&mut tx, &Caller::local(), &bound(), &good, &target)
                .await
                .unwrap(),
            None
        );
        for change in 0..5 {
            let mut bad = good.clone();
            match change {
                0 => bad.params[0].max_len = 127,
                1 => bad.params[0].required = false,
                2 => bad.params[0].param_type = SqlParamType::Integer,
                3 => bad.params.push(bad.params[0].clone()),
                _ => bad.params[0].name = "client_target".into(),
            }
            assert_eq!(
                check_body_membership_in(&mut tx, &Caller::local(), &bound(), &bad, &target)
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
                "body_need_parameterized"
            );
        }
        let mut mismatched = bound();
        mismatched.need = "other".into();
        assert_eq!(
            check_body_membership_in(&mut tx, &Caller::local(), &mismatched, &good, &target)
                .await
                .unwrap()
                .unwrap()
                .0,
            "body_need_mismatch"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn body_targeted_duplicate_truncated_malformed_missing_and_time_refuse() {
        let (db, target, outsiders) = fixture().await;
        let cases = vec![
            "SELECT id FROM records WHERE id=?1 AND name='absent'".to_owned(),
            "SELECT 17 AS id FROM records WHERE id=?1".to_owned(),
            format!("SELECT r.id FROM records r CROSS JOIN records x WHERE r.id=?1 AND x.id IN ('{}','{}')",outsiders[0],outsiders[1]),
            "SELECT r.id FROM records r CROSS JOIN records x WHERE r.id=?1 AND x.name='s3b outsider'".to_owned(),
        ];
        for sql in cases {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            assert_eq!(
                check_body_membership_in(&mut tx, &Caller::local(), &bound(), &need(&sql), &target)
                    .await
                    .unwrap()
                    .unwrap()
                    .0,
                "record_outside_need"
            );
            tx.rollback().await.unwrap();
        }
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        assert_eq!(
            check_body_membership_in(
                &mut tx,
                &Caller::local(),
                &bound(),
                &need("SELECT id,now_ms() AS clock FROM records WHERE id=?1"),
                &target
            )
            .await
            .unwrap()
            .unwrap()
            .0,
            "body_need_time_dependent"
        );
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn body_binding_rejects_default_empty_and_mixed_scope_before_source_lookup() {
        let (db, target, _) = fixture().await;
        for scope in [
            vec![],
            vec![("default".into(), "absent".into(), "query".into())],
            vec![
                ("orders".into(), "absent".into(), "query".into()),
                ("other".into(), "absent".into(), "query".into()),
            ],
        ] {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            assert_eq!(
                check_body_binding_in(
                    &mut tx,
                    &Caller::local(),
                    "absent",
                    "absent",
                    "absent",
                    &scope,
                    &target
                )
                .await
                .unwrap()
                .unwrap()
                .0,
                "named_input_unbound"
            );
            tx.rollback().await.unwrap();
        }
    }
}

/// Membership wording family: which effect's refusal codes and copy the
/// shared delivered-membership call uses. The governed call itself —
/// helper, signature, defaults, cap, TEMP handling — is identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MembershipFamily {
    FacetSet,
    CommentCreate,
    MessageReact,
    TitleSet,
    BodySet,
}

impl MembershipFamily {
    fn effect_label(self) -> &'static str {
        match self {
            Self::FacetSet => "facet-set",
            Self::CommentCreate => "comment.create",
            Self::MessageReact => "message.react",
            Self::TitleSet => "title-set",
            Self::BodySet => "body-set",
        }
    }

    fn parameterized_code(self) -> &'static str {
        match self {
            Self::FacetSet => "facet_need_parameterized",
            Self::CommentCreate => "comment_need_parameterized",
            Self::MessageReact => "react_need_parameterized",
            Self::TitleSet => "title_need_parameterized",
            Self::BodySet => "body_need_parameterized",
        }
    }

    fn time_code(self) -> &'static str {
        match self {
            Self::FacetSet => "facet_need_time_dependent",
            Self::CommentCreate => "comment_need_time_dependent",
            Self::MessageReact => "react_need_time_dependent",
            Self::TitleSet => "title_need_time_dependent",
            Self::BodySet => "body_need_time_dependent",
        }
    }
}

/// Neutral delivered-need core behind both arms. Re-runs the consented
/// static need SQL on the write transaction through the governed seam
/// (viewer TEMP views, torn down before return) with the 200-row delivery
/// cap; the target must occur among the delivered rows with a string `id`.
/// Never queries beyond the first 200: a truncated need still admits
/// targets it delivered. Comments additionally admit a single required text
/// `record_id` parameter, filled from the authoritative invocation target,
/// never from frame-supplied query parameters. Binding membership is checked
/// separately on the same transaction. Other parameterized and all
/// time-dependent needs refuse. Only row ids are read.
async fn check_delivered_membership_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    family: MembershipFamily,
    need: &SqlNeed,
    scope_detail: &str,
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    let targeted_comment = family == MembershipFamily::CommentCreate
        && need.params.len() == 1
        && need.params[0].name == "record_id"
        && need.params[0].param_type == SqlParamType::Text
        && need.params[0].required;
    if !need.params.is_empty() && !targeted_comment {
        return Ok(Some((
            family.parameterized_code().into(),
            format!(
                "{} target need '{}' has unsupported parameters; comments admit only a single required text record_id parameter",
                family.effect_label(),
                need.key
            ),
        )));
    }
    let parameters = if targeted_comment {
        let Some(target) = record_id else {
            return Ok(Some((
                "record_outside_need".into(),
                "comment target is unresolved".into(),
            )));
        };
        match bind_sql_params(need, Some(&json!({"record_id": target}))) {
            Ok(parameters) => parameters,
            Err(code) => {
                return Ok(Some((
                    code.into(),
                    "comment target does not match the consented parameter schema".into(),
                )))
            }
        }
    } else {
        Vec::new()
    };
    let (result, _observation) = crate::query::sql::query_sql_request_in_with_row_limit(
        &mut *tx,
        caller.into(),
        crate::query::sql_contract::QuerySqlRequest {
            sql: need.sql.clone(),
            parameters,
        },
        SQL_SNAPSHOT_ROW_CAP as i64,
        crate::query::sql_contract::FunctionAllowance::Portable,
    )
    .await
    .map_err(crate::query::sql_contract::ensure_categorized)?;
    if result.time_dependent {
        return Ok(Some((
            family.time_code().into(),
            format!(
                "{} target need '{}' is time-dependent; the first slice admits static needs only",
                family.effect_label(),
                need.key
            ),
        )));
    }
    let admitted = record_id.is_some_and(|target| {
        result
            .rows
            .iter()
            .any(|row| row.get("id").and_then(Value::as_str) == Some(target))
    });
    if !admitted {
        return Ok(Some((
            "record_outside_need".into(),
            format!(
                "record {} is not among the delivered rows of need '{}' ({})",
                record_id.unwrap_or("unresolved"),
                need.key,
                scope_detail,
            ),
        )));
    }
    Ok(None)
}

/// Current-binding proof for the facet-set arm, on the write transaction.
/// Thin wrapper over the neutral core below: signature, behavior, codes,
/// texts and ordering are identical; only the name is arm-specific.
async fn check_facet_set_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    scope: &[(String, String, String)],
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    check_current_binding_in(
        tx,
        caller,
        artifact_id,
        source_event_id,
        source_sha256,
        scope,
        record_id,
    )
    .await
}

/// Current-binding proof for the canonical hosted comment write path.
/// Requires exactly the entry's one explicit bound-input port scope —
/// nonempty, singleton, never the default port — then re-proves it through
/// the neutral core below. No port is ever inferred: a missing, default,
/// or multi-port scope refuses before any binding I/O. The kernel supplies
/// the scope derived from the exact parsed entry and source.
pub(crate) async fn check_comment_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    scope: &[(String, String, String)],
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    let [(port, _, _)] = scope else {
        return Ok(Some((
            "named_input_unbound".into(),
            "comment binding scope must hold exactly the entry's one bound_input port".into(),
        )));
    };
    if port.as_str() == "default" {
        return Ok(Some((
            "named_input_unbound".into(),
            "comment binding scope must name the entry's explicit bound_input port, never the default port"
                .into(),
        )));
    }
    check_current_binding_in(
        tx,
        caller,
        artifact_id,
        source_event_id,
        source_sha256,
        scope,
        record_id,
    )
    .await
}

/// Current-binding proof for the canonical hosted reaction write path.
/// Same singleton explicit-port scope discipline as the comment twin.
pub(crate) async fn check_react_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    scope: &[(String, String, String)],
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    let [(port, _, _)] = scope else {
        return Ok(Some((
            "named_input_unbound".into(),
            "react binding scope must hold exactly the entry's one bound_input port".into(),
        )));
    };
    if port.as_str() == "default" {
        return Ok(Some((
            "named_input_unbound".into(),
            "react binding scope must name the entry's explicit bound_input port, never the default port"
                .into(),
        )));
    }
    check_current_binding_in(
        tx,
        caller,
        artifact_id,
        source_event_id,
        source_sha256,
        scope,
        record_id,
    )
    .await
}

/// Current-binding proof for the canonical hosted title write path.
/// Same singleton explicit-port scope discipline as the comment/react twins.
pub(crate) async fn check_title_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    scope: &[(String, String, String)],
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    let [(port, _, _)] = scope else {
        return Ok(Some((
            "named_input_unbound".into(),
            "title binding scope must hold exactly the entry's one bound_input port".into(),
        )));
    };
    if port.as_str() == "default" {
        return Ok(Some((
            "named_input_unbound".into(),
            "title binding scope must name the entry's explicit bound_input port, never the default port"
                .into(),
        )));
    }
    check_current_binding_in(
        tx,
        caller,
        artifact_id,
        source_event_id,
        source_sha256,
        scope,
        record_id,
    )
    .await
}

/// Neutral current-binding core behind both arms, on the write transaction.
/// The pre-transaction scope only proves the binding as of the read
/// snapshot; a concurrent rebind, grant revocation, kind change or access
/// loss could move it before the append. Here the admitted scope is
/// re-proved on this snapshot with the same gates as port resolution —
/// source attestation triplet, port→collection mapping, live Collection
/// kind re-read (never the stale preflight kind), viewer View, and the
/// exact input.read grant through its transaction twin — and the target is
/// re-resolved inside those collections through the existing
/// transaction-capable collection resolver. No new executor, no duplicated
/// TEMP internals. Refusal codes mirror the pre-transaction diagnostics
/// where the situation matches; `binding_changed` names genuine
/// in-transaction divergence.
async fn check_current_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    scope: &[(String, String, String)],
    record_id: Option<&str>,
) -> Result<Option<(String, String)>> {
    use crate::authorization::Capability;
    let changed = || {
        (
            "binding_changed".into(),
            format!(
                "the artifact input binding moved; re-read the tab and retry \
                 (artifact {artifact_id})"
            ),
        )
    };
    // Source attestation triplet, exactly as port resolution pins it: a
    // revoked or replaced attestation stops the write here.
    let attestation_event_id: Option<String> = sqlx::query_scalar(
        "SELECT attestation_event_id FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=? AND source_sha256=?",
    )
    .bind(artifact_id)
    .bind(source_event_id)
    .bind(source_sha256)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(attestation_event_id) = attestation_event_id else {
        return Ok(Some((
            "artifact_source_unattested".into(),
            "the exact artifact source attestation is unavailable".into(),
        )));
    };
    let current: std::collections::BTreeMap<String, String> = sqlx::query(
        "SELECT port_name,collection_id FROM artifact_inputs
          WHERE artifact_id=? AND artifact_source_attestation_event_id=?
            AND artifact_source_event_id=? AND artifact_source_sha256=?",
    )
    .bind(artifact_id)
    .bind(&attestation_event_id)
    .bind(source_event_id)
    .bind(source_sha256)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("port_name")?,
            row.try_get::<String, _>("collection_id")?,
        ))
    })
    .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let renders: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id=? AND relationship='renders' ORDER BY target_id",
    )
    .bind(artifact_id)
    .fetch_all(&mut **tx)
    .await?;
    if renders.len() > 1 {
        return Ok(Some(changed()));
    }
    for (port, collection_id, _kind) in scope {
        // The default port is not a stored row: it resolves from the renders
        // link exactly as the pre-transaction derivation does.
        if port == "default" {
            if renders.first().map(String::as_str) != Some(collection_id.as_str()) {
                return Ok(Some(changed()));
            }
            continue;
        }
        if current.get(port.as_str()) != Some(collection_id) {
            return Ok(Some(changed()));
        }
    }
    let mut in_binding = std::collections::BTreeSet::new();
    for (port, collection_id, _kind) in scope {
        // Live kind re-read on this snapshot: a collection whose kind (or
        // liveness) changed since the preflight no longer admits the write
        // through the stale kind.
        let live_kind: Option<String> =
            sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
                .bind(collection_id)
                .fetch_optional(&mut **tx)
                .await?
                .and_then(|row| {
                    // NULL deleted_at is live; unreadable values, a deleted
                    // row, or a non-Collection row fail closed with no kind.
                    let deleted: Option<String> = row.try_get("deleted_at").ok()?;
                    let live =
                        deleted.is_none() && row.try_get::<String, _>("type").ok()? == "Collection";
                    live.then(|| row.try_get::<String, _>("kind").ok())
                        .flatten()
                });
        let Some(live_kind) = live_kind else {
            return Ok(Some(changed()));
        };
        if !super::can_record_in(tx, caller, collection_id, Capability::View).await? {
            return Ok(Some((
                "binding_unavailable".into(),
                "artifact input binding is unavailable".into(),
            )));
        }
        if port != "default"
            && !super::artifacts::artifact_source_holds_input_read_in(
                tx,
                artifact_id,
                &attestation_event_id,
                source_event_id,
                source_sha256,
                port,
            )
            .await?
        {
            return Ok(Some((
                "module_capability_denied".into(),
                format!(
                    "input port '{port}' is not exposed to the artifact root with an exact input.read grant"
                ),
            )));
        }
        match super::artifacts::resolve_collection_in(tx, caller, collection_id, &live_kind).await {
            Ok(records) => in_binding.extend(records.into_iter().map(|record| record.id)),
            Err(error) => {
                return Ok(Some(("input_resolution_failed".into(), error.to_string())));
            }
        }
    }
    let inside = record_id.is_some_and(|target| in_binding.contains(target));
    if !inside {
        return Ok(Some((
            "record_outside_binding".into(),
            format!(
                "record {} is not inside this artifact's current bound input",
                record_id.unwrap_or("unresolved")
            ),
        )));
    }
    Ok(None)
}

/// Post-replay dynamic gates for the facet-set arm, on the write
/// transaction and before CAS/append. Static consent (bound admission) and
/// install/consent revocation already passed in the guard above, and
/// permission precedes the replay branch, so a replay keeps every static
/// gate while skipping these mutable ones: a replay commits nothing, and a
/// target that has since left the need must still settle its prior receipt.
/// Re-admission is deterministic on this snapshot (same inputs as the
/// guard), so it cannot disagree with the consent decision above.
///
/// N2 b2 retains this row-reading twin for unmigrated callers (none in the
/// forward dispatcher after this slice); the forward path uses
/// [`check_facet_set_post_replay_with_admission_in`] with no second install
/// read. Kept byte-identical until full N2 acceptance removes it.
#[allow(clippy::too_many_arguments)] // Keep the transaction and pinned admission inputs explicit.
#[allow(dead_code)]
pub(crate) async fn check_facet_set_post_replay_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    package: &str,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
    record_id: Option<&str>,
    scope: &[(String, String, String)],
) -> Result<Option<(String, String)>> {
    let account_id = caller.credential().trim().to_string();
    let Some(row) = install_row_in(tx, &account_id, package).await? else {
        return Ok(Some((
            "alpha_guard_missing_install".into(),
            format!(
                "package {package} is not installed for this account; other Workbench use of the artifact is unaffected"
            ),
        )));
    };
    let (bound, need) = match facet_set_admission(&row.consented_declaration, entry) {
        Ok(context) => context,
        Err((code, message)) => return Ok(Some((code, message))),
    };
    if let Some((code, message)) = check_facet_set_binding_in(
        tx,
        caller,
        artifact_id,
        source_event_id,
        source_sha256,
        scope,
        record_id,
    )
    .await?
    {
        return Ok(Some((code, message)));
    }
    if let Some((code, message)) =
        check_facet_set_membership_in(tx, caller, &bound, &need, record_id).await?
    {
        return Ok(Some((code, message)));
    }
    Ok(None)
}

/// Post-replay dynamic facet gates using the fresh same-TX package and
/// already-admitted bound/need. No second install read or consent parse.
#[allow(clippy::too_many_arguments)] // Keep the transaction and pinned package inputs explicit.
pub(crate) async fn check_facet_set_post_replay_with_admission_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    resolved: &ResolvedAlphaAdmission,
    source_event_id: &str,
    source_sha256: &str,
    record_id: Option<&str>,
    scope: &[(String, String, String)],
) -> Result<Option<(String, String)>> {
    let super::effect_bounds::Admitted::FacetSet { bound, need } = &resolved.admitted else {
        unreachable!("facet scope resolved a facet-set admission");
    };
    if let Some((code, message)) = check_facet_set_binding_in(
        tx,
        caller,
        &resolved.package.artifact_id,
        source_event_id,
        source_sha256,
        scope,
        record_id,
    )
    .await?
    {
        return Ok(Some((code, message)));
    }
    if let Some((code, message)) =
        check_facet_set_membership_in(tx, caller, bound, need, record_id).await?
    {
        return Ok(Some((code, message)));
    }
    Ok(None)
}

/// The host-rule declaration: an object with `needs` and `effects` arrays.
/// `effects` entries are strings, except narrowed facet writes which are
/// `{effect, key, values, target}` objects; `needs` entries are either
/// strings or `sql.snapshot.v1` objects (`{need, key, label, sql}`). The
/// shape is pinned so the consent digest covers declared bytes.
#[derive(Debug)]
struct ParsedDeclaration {
    needs: Vec<String>,
    effects: Vec<String>,
}

fn require_declaration(declaration: &Value) -> Result<ParsedDeclaration> {
    require_declaration_for_adoption(declaration, false)
}

// Only the private fresh-adoption branch admits the descriptor structurally.
// All current SQL/effect/session admission below remains shared.
fn require_declaration_for_adoption(
    declaration: &Value,
    body_feature: bool,
) -> Result<ParsedDeclaration> {
    let object = declaration
        .as_object()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration must be an object")))?;
    // Parsing and digest support for reads.v1 are groundwork only. Do not
    // allow tab adoption to store an app read grant before the host can show
    // it and the app-scoped engine path can enforce it; the shared allowlist
    // therefore names only needs/effects plus the optional sessions shape.
    for key in object.keys() {
        if !crate::alpha_tab_sessions::DECLARATION_KEYS.contains(&key.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: declaration holds unknown key '{key}'"
            )));
        }
    }
    if !object.contains_key("needs") || !object.contains_key("effects") {
        return Err(Error::engine(format!(
            "{TOOL}: declaration must hold 'needs' and 'effects' (and optional 'sessions')"
        )));
    }
    let effect_entries = object["effects"]
        .as_array()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration 'effects' must be an array")))?;
    if effect_entries.len() > 64 {
        return Err(Error::engine(format!(
            "{TOOL}: declaration 'effects' holds at most 64 entries"
        )));
    }
    let mut effects = Vec::new();
    for entry in effect_entries {
        if let Some(name) = entry.as_str() {
            if name == FACET_SET_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'records.facet-set.v1' consents to no key, values or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == COMMENT_CREATE_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'comment.create.v1' consents to no positions, cap or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == MESSAGE_REACT_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'message.react.v1' consents to no emoji or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == BODY_SET_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'records.body-set.v1' consents to no cap or need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name == TITLE_SET_EFFECT {
                return Err(Error::engine(format!(
                    "{TOOL}: bare 'records.title-set.v1' consents to no need; declare the object bound instead [invalid_effect]"
                )));
            }
            if name.trim().is_empty() || name.len() > 128 {
                return Err(Error::engine(format!(
                    "{TOOL}: declaration 'effects' entries must be 1..128 characters"
                )));
            }
            effects.push(name.to_string());
        } else if entry.is_object() {
            // Comment, react and title bounds parse through their own
            // parsers; anything else stays on the facet parser, which
            // refuses unknown objects.
            if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(COMMENT_CREATE_EFFECT)
            {
                parse_comment_create_bound(entry).map_err(Error::engine)?;
                effects.push(COMMENT_CREATE_EFFECT.to_string());
            } else if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(MESSAGE_REACT_EFFECT)
            {
                parse_message_react_bound(entry).map_err(Error::engine)?;
                effects.push(MESSAGE_REACT_EFFECT.to_string());
            } else if entry
                .as_object()
                .and_then(|object| object.get("effect"))
                .and_then(Value::as_str)
                == Some(TITLE_SET_EFFECT)
            {
                parse_title_set_bound(entry).map_err(Error::engine)?;
                effects.push(TITLE_SET_EFFECT.to_string());
            } else if entry.get("effect").and_then(Value::as_str) == Some(BODY_SET_EFFECT) {
                parse_body_set_bound(entry).map_err(Error::engine)?;
                effects.push(BODY_SET_EFFECT.to_string());
            } else {
                parse_facet_set_bound(entry).map_err(Error::engine)?;
                effects.push(FACET_SET_EFFECT.to_string());
            }
        } else {
            return Err(Error::engine(format!(
                "{TOOL}: declaration 'effects' entries must be strings or facet-set objects"
            )));
        }
    }
    // Duplicate keys and the target-need cross-check live in the shared
    // bound parser below so install and guard read identical bounds.
    let facet_sets = parse_facet_set_bounds(declaration).map_err(Error::engine)?;
    // Position overlap (including duplicate identical objects) and the
    // target-need cross-check live in the shared comment parser below.
    let comment_bounds = parse_comment_create_bounds(declaration).map_err(Error::engine)?;
    // Emoji overlap (including duplicate identical objects) and the
    // target-need cross-check live in the shared react parser below.
    let react_bounds = parse_message_react_bounds(declaration).map_err(Error::engine)?;
    // Singularity (at most one bound) and the target-need cross-check live
    // in the shared title parser below.
    let title_bounds = parse_title_set_bounds(declaration).map_err(Error::engine)?;
    parse_body_set_bounds(declaration).map_err(Error::engine)?;
    let need_entries = object["needs"]
        .as_array()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration 'needs' must be an array")))?;
    if need_entries.len() > 64 {
        return Err(Error::engine(format!(
            "{TOOL}: declaration 'needs' holds at most 64 entries"
        )));
    }
    let mut needs = Vec::new();
    let mut sql_needs = Vec::new();
    for entry in need_entries {
        if let Some(name) = entry.as_str() {
            if name.trim().is_empty() || name.len() > 128 {
                return Err(Error::engine(format!(
                    "{TOOL}: declaration 'needs' entries must be 1..128 characters"
                )));
            }
            needs.push(name.to_string());
        } else if entry.is_object() {
            match classify_declaration_need(entry).map_err(Error::engine)? {
                DeclarationNeed::Sql(need) => sql_needs.push(need),
                DeclarationNeed::BodyRead => {
                    if !body_feature {
                        return Err(Error::engine(format!(
                            "{TOOL}: body read descriptor admission is unavailable [body_admission_unavailable]"
                        )));
                    }
                    // Descriptor commitment is not a bare host-need offering.
                }
                DeclarationNeed::Name(_) => unreachable!("object need"),
            }
        } else {
            return Err(Error::engine(format!(
                "{TOOL}: declaration 'needs' entries must be strings or sql.snapshot.v1 objects"
            )));
        }
    }
    if sql_needs.len() > SQL_SNAPSHOT_MAX_NEEDS {
        return Err(Error::engine(format!(
            "{TOOL}: declaration holds at most 8 sql.snapshot.v1 needs [invalid_sql_need]"
        )));
    }
    let mut keys: Vec<&str> = sql_needs.iter().map(|need| need.key.as_str()).collect();
    keys.sort_unstable();
    for window in keys.windows(2) {
        if window[0] == window[1] {
            return Err(Error::engine(format!(
                "{TOOL}: sql need key '{}' is duplicated [invalid_sql_need]",
                window[0]
            )));
        }
    }
    // Cross-namespace duplicate: a string need and an SQL key with the same
    // name would make on-request dispatch silently prefer the SQL need and
    // leave the string need as dead config. Refuse at install.
    for key in &keys {
        if needs.iter().any(|name| name == key) {
            return Err(Error::engine(format!(
                "{TOOL}: sql need key '{key}' duplicates a string need [invalid_sql_need]"
            )));
        }
    }
    sql_needs.sort_by(|left, right| left.key.cmp(&right.key));
    // A bound may only target a declared static need: the membership check
    // re-runs that need's SQL in the write transaction.
    for bound in &facet_sets {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: facet-set bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    for bound in &comment_bounds {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: comment.create bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    for bound in &react_bounds {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: message.react bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    for bound in &title_bounds {
        if !sql_needs.iter().any(|need| need.key == bound.need) {
            return Err(Error::engine(format!(
                "{TOOL}: title-set bound targets undeclared need '{}' [invalid_effect]",
                bound.need
            )));
        }
    }
    // Optional `sessions` entries are validated by the shared descriptor
    // module (also consumed by control-event consent validation). No cap is
    // imposed: the contract specifies none.
    crate::alpha_tab_sessions::parse_sessions(object.get("sessions")).map_err(Error::engine)?;
    // `facet_sets` stays a local: it validates the need cross-check here,
    // while production consent reads bounds from the stored declaration
    // through `parse_facet_set_bounds`, so nothing stores the parsed form.
    Ok(ParsedDeclaration { needs, effects })
}
/// One projection row in tuple form, as `do_list` reads it before folding
/// into [`InstallRow`].
type InstallRowTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    i64,
);

/// One projection row as the tool sees it.
struct InstallRow {
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    consented_source_revision: String,
    declaration_digest: String,
    consented_declaration: Value,
    adoption: String,
    adoption_provenance: Option<String>,
    /// Display-only install request text (E3); `None` when the install
    /// carries none. Surfaced verbatim in list/inspect, never authority.
    request: Option<String>,
    status: String,
    event_id: String,
    event_seq: i64,
}

async fn install_row_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account_id: &str,
    package: &str,
) -> Result<Option<InstallRow>> {
    let row = sqlx::query(
        "SELECT package,version,digest,artifact_id,consented_source_revision,
                declaration_digest,consented_declaration,adoption,adoption_provenance,request,status,event_id,event_seq
           FROM alpha_tab_installs WHERE account_id=? AND package=?",
    )
    .bind(account_id)
    .bind(package)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(InstallRow {
            package: row.try_get("package")?,
            version: row.try_get("version")?,
            digest: row.try_get("digest")?,
            artifact_id: row.try_get("artifact_id")?,
            consented_source_revision: row.try_get("consented_source_revision")?,
            declaration_digest: row.try_get("declaration_digest")?,
            consented_declaration: serde_json::from_str(
                &row.try_get::<String, _>("consented_declaration")?,
            )?,
            adoption: row.try_get("adoption")?,
            adoption_provenance: row.try_get("adoption_provenance")?,
            request: row.try_get("request")?,
            status: row.try_get("status")?,
            event_id: row.try_get("event_id")?,
            event_seq: row.try_get("event_seq")?,
        })
    })
    .transpose()
}

/// The target's live record shape, mirroring
/// `surface_bindings.rs::artifact_status_in`: a live Document kind:artifact
/// the viewer may view, else a named refusal. Unknown-field tolerance and
/// reserved-relationship guards do not apply here — installs key no links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetState {
    Resolvable,
    Missing,
    Archived,
    WrongRecordType,
}

async fn target_state_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    target: &str,
) -> Result<TargetState> {
    let predicate = CoreKind::DocumentArtifact.sql_matches("r");
    let row = sqlx::query(&format!(
        "SELECT r.deleted_at, \
                EXISTS (SELECT 1 FROM facet_values av WHERE av.record_id = r.id AND av.key = ?) AS archived, \
                {predicate} AS is_artifact \
         FROM records r WHERE r.id = ?"
    ))
    .bind(crate::schema::ARCHIVED_FACET_KEY)
    .bind(target)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(TargetState::Missing);
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(TargetState::Missing);
    }
    if row.try_get::<i64, _>("is_artifact")? == 0 {
        return Ok(TargetState::WrongRecordType);
    }
    if row.try_get::<i64, _>("archived")? != 0 {
        return Ok(TargetState::Archived);
    }
    Ok(TargetState::Resolvable)
}

fn target_state_name(state: TargetState) -> &'static str {
    match state {
        TargetState::Resolvable => "resolvable",
        TargetState::Missing => "missing",
        TargetState::Archived => "archived",
        TargetState::WrongRecordType => "wrong_record_type",
    }
}
/// One §2-resolved source: the body-carrying content event id plus its
/// exact bytes. The identity is portable because content event ids are
/// stable across event import while local content sequence numbers may
/// remap.
struct AlphaTabSource {
    #[allow(dead_code)]
    event_id: String,
    body: String,
}

/// Resolve `(artifact_id, consented_source_revision)` to its body-carrying
/// content event — the same body-source rule `resolve_artifact` uses.
/// `None` when the revision names no such event for this artifact:
/// opaque strings, pruned histories, and cross-record ids all refuse
/// identically with `source_revision_unresolved`. The caller verifies the
/// resolved bytes by §1 recomputation; resolution alone proves nothing.
async fn resolve_alpha_tab_source_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    artifact_id: &str,
    source_revision: &str,
) -> Result<Option<AlphaTabSource>> {
    let row = sqlx::query(
        "SELECT id, json_extract(payload,'$.body') AS body FROM content_events
          WHERE record_id=? AND id=?
            AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(payload,'$.body') IS NOT NULL",
    )
    .bind(artifact_id)
    .bind(source_revision)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(AlphaTabSource {
            event_id: row.try_get("id")?,
            body: row.try_get("body")?,
        })
    })
    .transpose()
}

/// Read-only launch verdict for one install row (`launch_binding` on the
/// entry). Fail-closed with the named reasons of
/// `docs/alpha-tab-install-slice2.md` §3 plus the terminal
/// `launch_request_required` refusal; mints no frame ticket and performs the
/// source/digest I/O only when the install and authority gates already pass.
async fn launch_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    row: &InstallRow,
    target: TargetState,
    can_view: bool,
) -> Result<Value> {
    let refused = |reason: &'static str| {
        json!({
            "digest_version": ALPHA_TAB_DIGEST_VERSION,
            "verdict": "refused",
            "reason": reason,
            "receipt": Value::Null,
        })
    };
    if let Err(reason) =
        evaluate_alpha_tab_install_gates(&row.status, &row.adoption, target, can_view)
    {
        return Ok(refused(reason));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&row.artifact_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let runtime_present = runtime.as_deref() == Some("native.html.v1");
    let source =
        resolve_alpha_tab_source_in(tx, &row.artifact_id, &row.consented_source_revision).await?;
    // Fail closed: a stored declaration the canonical form refuses can never
    // match its pin. Refuse explicitly with `digest_mismatch` (the code a
    // non-matching pin produces) rather than comparing against a default
    // that is only safe because `""` is never a real digest.
    let Ok(recomputed_declaration_digest) =
        alpha_tab_declaration_digest(&row.consented_declaration)
    else {
        return Ok(refused("digest_mismatch"));
    };
    let digest_matches = match (&runtime, &source) {
        (Some(runtime), Some(source))
            if row.declaration_digest == recomputed_declaration_digest =>
        {
            alpha_tab_digest(
                &alpha_tab_bundle_digest(&source.body),
                &recomputed_declaration_digest,
                runtime,
            ) == row.digest
        }
        _ => false,
    };
    if let Err(reason) =
        evaluate_alpha_tab_source_gates(runtime_present, source.is_some(), digest_matches)
    {
        return Ok(refused(reason));
    }
    // Inspection never mints a ticket, even when every earlier gate passes.
    if let Err(reason) = evaluate_alpha_tab_ticket_gate() {
        return Ok(refused(reason));
    }
    unreachable!("the ticket gate refuses every call in this slice");
}
/// Preview continuity fence, scoped to this account/package in this database.
async fn last_alpha_update_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account: &str,
    package: &str,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT id FROM control_events WHERE aggregate_kind='alpha_tab' AND aggregate_id=? AND type='alpha_tab.updated' ORDER BY seq DESC LIMIT 1")
        .bind(alpha_tab_aggregate_id(account, package)).fetch_optional(&mut **tx).await?)
}

/// One list/inspect entry with its read-gate verdicts, split in two so no
/// caller can mistake install-state readiness for permission to execute.
///
/// - `target_resolves` / `target_skip_reason`: install-state plus authority
///   readiness only — status installed, a live artifact target, viewer View.
/// - `resolves` / `skip_reason`: list/inspect never carry a reusable ticket;
///   `resolves` stays false and the skip reason names the first gate refusal
///   or `launch_request_required` for a fully verified row. The shell calls
///   `launch` with the current event token to get a one-use sample URL.
///
/// `launch_binding` carries the same gates plus source-revision resolution
/// and digest recomputation, but never a ticket. After all gates pass it
/// reports `launch_request_required`; see the launch-ticket doc.
fn entry_json(
    row: &InstallRow,
    target: TargetState,
    can_view: bool,
    launch_binding: Value,
) -> Value {
    // Provenance is display-only: launch/admission reads never parse it.
    let provenance = row
        .adoption_provenance
        .as_deref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(Value::is_object)
        .map(|mut value| {
            let object = value.as_object_mut().expect("filtered object");
            object.remove("launch_id");
            object.remove("authored_run_key");
            value
        });
    let target_skip_reason: Option<&str> = match row.status.as_str() {
        "disabled" => Some("disabled"),
        "removed" => Some("removed"),
        _ => match target {
            TargetState::Resolvable if can_view => None,
            TargetState::Resolvable => Some("unauthorized"),
            TargetState::Missing => Some("missing"),
            TargetState::Archived => Some("archived"),
            TargetState::WrongRecordType => Some("wrong_record_type"),
        },
    };
    let skip_reason: Option<&str> = target_skip_reason.or_else(|| {
        if VERIFIED_ALPHA_TAB_ADOPTIONS.contains(&row.adoption.as_str()) {
            launch_binding["reason"].as_str()
        } else {
            Some("digest_unverified")
        }
    });
    json!({
        "package": row.package,
        "version": row.version,
        "digest": row.digest,
        "artifact_id": row.artifact_id,
        "consented_source_revision": row.consented_source_revision,
        "declaration_digest": row.declaration_digest,
        "consented_declaration": row.consented_declaration,
        "adoption": row.adoption,
        "adoption_basis": match provenance.as_ref() {
            Some(p) if p["carried_from_event_id"].is_string() => Some("carried"),
            Some(_) => Some("direct"),
            None if row.adoption == crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED => Some("requires_adoption"),
            None => None,
        },
        "adoption_provenance": provenance,
        "request": row.request,
        "status": row.status,
        "event_id": row.event_id,
        "event_seq": row.event_seq,
        "target_resolves": target_skip_reason.is_none(),
        "target_skip_reason": target_skip_reason,
        "resolves": false,
        "skip_reason": skip_reason,
        "digest_binding": DIGEST_BINDING,
        "launch_binding": launch_binding,
    })
}

/// Read-gate verdict for one row inside the caller's transaction: live
/// target shape plus viewer View, computed per request and never cached.
async fn entry_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    row: &InstallRow,
) -> Result<Value> {
    let target = target_state_in(tx, &row.artifact_id).await?;
    let can_view = if target == TargetState::Resolvable {
        super::can_record_in(tx, caller, &row.artifact_id, Capability::View).await?
    } else {
        false
    };
    let launch_binding = launch_binding_in(tx, row, target, can_view).await?;
    Ok(entry_json(row, target, can_view, launch_binding))
}
/// Same-key retry: `instructions.rs::prior_event` precedent. When the caller
/// repeats an idempotency key whose canonical intent matches field for field,
/// re-append the identical payload so the control tier converges on the
/// original event (`changed: false`); any difference is a visible reuse error.
async fn prior_alpha_event(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    key: &str,
) -> Result<Option<(String, String, String, String, AlphaTabStatePayload)>> {
    let row = sqlx::query(
        "SELECT type,aggregate_id,actor,reason,payload FROM control_events WHERE idempotency_key=?",
    )
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let raw: String = row.try_get("payload")?;
        Ok((
            row.try_get("type")?,
            row.try_get("aggregate_id")?,
            row.try_get("actor")?,
            row.try_get("reason")?,
            serde_json::from_str(&raw)?,
        ))
    })
    .transpose()
}

async fn append_alpha_event(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    key: String,
    aggregate_id: String,
    reason: String,
    payload: ControlEventPayload,
    act_alloc: &mut ActAllocation,
) -> Result<String> {
    let event = append_control_event_in(
        tx,
        NewControlEvent::authored(
            key,
            aggregate_id,
            caller.actor(),
            caller.run_key().map(str::to_owned),
            reason,
            payload,
        )?,
        act_alloc,
    )
    .await?;
    Ok(event.id)
}
#[allow(clippy::too_many_arguments)]
fn install_payload(
    account_id: &str,
    package: &str,
    version: &str,
    digest: &str,
    artifact_id: &str,
    source_revision: &str,
    declaration_digest: &str,
    declaration: &Value,
    request: Option<String>,
    previous_event_id: Option<String>,
) -> AlphaTabStatePayload {
    AlphaTabStatePayload {
        account_id: account_id.into(),
        package: package.into(),
        version: version.into(),
        digest: digest.into(),
        artifact_id: artifact_id.into(),
        consented_source_revision: source_revision.into(),
        declaration_digest: declaration_digest.into(),
        consented_declaration: declaration.clone(),
        // Server-stamped, never caller-supplied: this slice has no verified
        // shell preview/adopt gesture, so every install is recorded exactly
        // as what it is — asserted by the calling credential. See the
        // adoption boundary in docs/alpha-tab-install-slice1.md.
        adoption: crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into(),
        request,
        previous_event_id,
    }
}

#[allow(clippy::too_many_arguments)]
async fn do_install(
    db: &Db,
    caller: &Caller,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration: Value,
    reason: String,
    request: Option<String>,
    idempotency_key: Option<String>,
    expected_install_event_id: Option<String>,
) -> Result<Value> {
    require_package(&package)?;
    require_version(&version)?;
    require_digest(&digest)?;
    require_declaration(&declaration)?;
    require_reason(TOOL, &reason)?;
    let request = require_request(request)?;
    if artifact_id.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: artifact_id must not be blank"
        )));
    }
    if source_revision.trim().is_empty() || source_revision.len() > 256 {
        return Err(Error::engine(format!(
            "{TOOL}: source_revision must be 1..256 characters"
        )));
    }
    let account_id = require_account(caller)?;
    // The canonical (sorted) digest, the same one adopt, launch and live_read
    // recompute. Digesting the raw declaration made any unsorted multi-entry
    // declaration install cleanly and then fail every later pin check.
    let declaration_digest = alpha_tab_declaration_digest(&declaration)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = ActAllocation::new();
    let key = idempotency_key
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| {
            // The default key names the CAS generation it chains from (or genesis
            // for a fresh chain): remove + reinstall of the same version/digest
            // is a new chain over the tombstone token, never a replay of the
            // first install, so sharing the first install's key would collide.
            format!(
                "alpha-tab-install:{account_id}:{package}:{version}:{digest}:{}",
                expected_install_event_id.as_deref().unwrap_or("genesis")
            )
        });
    let aggregate_id = alpha_tab_aggregate_id(&account_id, &package);
    let payload = install_payload(
        &account_id,
        &package,
        &version,
        &digest,
        &artifact_id,
        &source_revision,
        &declaration_digest,
        &declaration,
        request,
        expected_install_event_id.clone(),
    );
    if let Some((kind, aggregate, actor, prior_reason, prior)) =
        prior_alpha_event(&mut tx, &key).await?
    {
        if kind != "alpha_tab.installed"
            || aggregate != aggregate_id
            || actor != caller.actor()
            || prior_reason != reason
            || prior != payload
        {
            return Err(Error::engine(format!(
                "{TOOL}: idempotency_key was reused for different intent"
            )));
        }
        append_alpha_event(
            &mut tx,
            caller,
            key,
            aggregate_id,
            reason,
            ControlEventPayload::AlphaTabInstalled(payload),
            &mut act_alloc,
        )
        .await?;
        let row = install_row_in(&mut tx, &account_id, &package)
            .await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: install did not fold")))?;
        let entry = entry_in(&mut tx, caller, &row).await?;
        db.commit_control(tx).await?;
        return echo_act(
            json!({"package": package, "changed": false, "idempotent_retry": true, "install": entry}),
            act_alloc.get(),
        );
    }
    // Bind-time target gate (`surface_bindings.rs` set precedent): the target
    // must be a live Document kind:artifact the caller may view, refused here
    // where the installer is present to be told.
    match target_state_in(&mut tx, &artifact_id).await? {
        TargetState::Resolvable => {}
        other => {
            return Err(Error::engine(format!(
                "{TOOL}: target {artifact_id} is {}",
                target_state_name(other)
            )));
        }
    }
    super::require_record_in(&mut tx, caller, TOOL, &artifact_id, Capability::View).await?;
    match install_row_in(&mut tx, &account_id, &package).await? {
        Some(row) if row.status != "removed" => {
            return Err(Error::engine(format!(
                "{TOOL}: package {package} is already {}; disable or remove it first",
                row.status
            )));
        }
        Some(row) if Some(row.event_id.as_str()) != expected_install_event_id.as_deref() => {
            return Err(Error::engine(format!(
                "{TOOL}: installation changed; expected current event {} but found {}",
                expected_install_event_id.as_deref().unwrap_or("none"),
                row.event_id
            )));
        }
        _ => {}
    }
    append_alpha_event(
        &mut tx,
        caller,
        key,
        aggregate_id,
        reason,
        ControlEventPayload::AlphaTabInstalled(payload),
        &mut act_alloc,
    )
    .await?;
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: install did not fold")))?;
    let entry = entry_in(&mut tx, caller, &row).await?;
    db.commit_control(tx).await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
        act_alloc.get(),
    )
}

/// Atomic replacement. Consent fields come exclusively from the control fold's
/// shared calculation; retries never append or evaluate the stale CAS token.
#[allow(clippy::too_many_arguments)]
async fn do_update(
    db: &Db,
    caller: &Caller,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration: Value,
    expected_install_event_id: String,
    reason: String,
    idempotency_key: Option<String>,
    request: Option<String>,
) -> Result<Value> {
    require_package(&package)?;
    require_version(&version)?;
    require_digest(&digest)?;
    require_declaration(&declaration)?;
    require_reason(TOOL, &reason)?;
    let request = require_request(request)?;
    if artifact_id.trim().is_empty()
        || source_revision.trim().is_empty()
        || source_revision.len() > 256
        || expected_install_event_id.trim().is_empty()
    {
        return Err(Error::engine(format!(
            "{TOOL}: artifact, source revision and expected install event must be nonblank"
        )));
    }
    let account_id = require_account(caller)?;
    let declaration_digest = alpha_tab_declaration_digest(&declaration)?;
    let command_digest = crate::canonical_json::digest_json(&json!({
        "operation": "manage_alpha_tabs.update", "account_id": account_id,
        "actor": caller.actor(), "package": package, "version": version,
        "digest": digest, "artifact_id": artifact_id, "source_revision": source_revision,
        "declaration": declaration, "expected_install_event_id": expected_install_event_id,
        "reason": reason, "request": request,
    }));
    let key = idempotency_key
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| format!("alpha-tab-update:{command_digest}"));
    let aggregate_id = alpha_tab_aggregate_id(&account_id, &package);
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if let Some(prior) = sqlx::query("SELECT id,seq,type,aggregate_id,actor,reason,payload FROM control_events WHERE idempotency_key=?")
        .bind(&key).fetch_optional(&mut *tx).await? {
        let raw: Value = serde_json::from_str(&prior.try_get::<String, _>("payload")?)?;
        if prior.try_get::<String, _>("type")? != "alpha_tab.updated"
            || prior.try_get::<String, _>("aggregate_id")? != aggregate_id
            || prior.try_get::<String, _>("actor")? != caller.actor()
            || prior.try_get::<String, _>("reason")? != reason
            || raw["command_digest"] != command_digest {
            return Err(Error::engine(format!("{TOOL}: idempotency_key was reused for different intent")));
        }
        let payload: crate::control::AlphaTabUpdatePayload = serde_json::from_value(raw)?;
        super::require_record_in(&mut tx, caller, TOOL, &artifact_id, Capability::View).await?;
        let receipt = InstallRow {
            package: payload.package.clone(), version: payload.version.clone(), digest: payload.digest.clone(),
            artifact_id: payload.artifact_id.clone(), consented_source_revision: payload.consented_source_revision.clone(),
            declaration_digest: payload.declaration_digest.clone(), consented_declaration: payload.consented_declaration.clone(),
            adoption: payload.adoption.clone(), adoption_provenance: payload.adoption_provenance.as_ref().map(serde_json::to_string).transpose()?,
            request: payload.request.clone(), status: payload.status.clone(),
            event_id: prior.try_get("id")?, event_seq: prior.try_get("seq")?,
        };
        let install = entry_in(&mut tx, caller, &receipt).await?;
        let current = install_row_in(&mut tx, &account_id, &package).await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: update projection missing")))?;
        let current_install = entry_in(&mut tx, caller, &current).await?;
        tx.rollback().await?;
        return Ok(json!({"changed": false, "idempotent_retry": true,
            "update_event_id": receipt.event_id, "previous_install_event_id": payload.previous_event_id,
            "adoption_carried": payload.adoption_basis == "carried",
            "adoption_required": payload.adoption_basis == "requires_adoption",
            "install": install, "current_install": current_install}));
    }
    let previous = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: package {package} is not installed [missing_install]"
            ))
        })?;
    if !matches!(previous.status.as_str(), "installed" | "disabled") {
        return Err(Error::engine(format!(
            "{TOOL}: update requires installed or disabled status"
        )));
    }
    if previous.event_id != expected_install_event_id {
        return Err(Error::engine(format!(
            "{TOOL}: installation changed [cas_mismatch]"
        )));
    }
    if request
        .as_ref()
        .is_some_and(|value| previous.request.as_ref() != Some(value))
    {
        return Err(Error::engine(format!(
            "{TOOL}: update must preserve the install request"
        )));
    }
    let target = target_state_in(&mut tx, &artifact_id).await?;
    if target != TargetState::Resolvable {
        return Err(Error::engine(format!(
            "{TOOL}: target {artifact_id} is {}",
            target_state_name(target)
        )));
    }
    super::require_record_in(&mut tx, caller, TOOL, &artifact_id, Capability::View).await?;
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&artifact_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    if runtime.as_deref() != Some("native.html.v1") {
        return Err(Error::engine(format!(
            "{TOOL}: update refused [runtime_mismatch]"
        )));
    }
    let source = resolve_alpha_tab_source_in(&mut tx, &artifact_id, &source_revision)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: update refused [source_unresolved]")))?;
    let manifest = crate::artifact_html::validate_cached(&source.body)
        .map_err(|failure| Error::engine(format!("{TOOL}: update refused [{}]", failure.code)))?;
    let bundle_digest = alpha_tab_bundle_digest(&source.body);
    if manifest.body_digest != bundle_digest
        || alpha_tab_digest(&bundle_digest, &declaration_digest, "native.html.v1") != digest
    {
        return Err(Error::engine(format!(
            "{TOOL}: update refused [digest_mismatch]"
        )));
    }
    let mut payload = crate::control::AlphaTabUpdatePayload {
        account_id,
        package: package.clone(),
        version,
        digest,
        artifact_id,
        consented_source_revision: source_revision,
        declaration_digest,
        consented_declaration: declaration,
        previous_event_id: expected_install_event_id.clone(),
        previous_pin_digest: String::new(),
        status: previous.status,
        request: previous.request,
        command_digest,
        adoption: String::new(),
        adoption_basis: String::new(),
        adoption_provenance: None,
    };
    crate::control::complete_alpha_tab_update_in(&mut tx, &mut payload).await?;
    let carried = payload.adoption_basis == "carried";
    let required = payload.adoption_basis == "requires_adoption";
    let account_id = payload.account_id.clone();
    let mut act_alloc = ActAllocation::new();
    let event_id = append_alpha_event(
        &mut tx,
        caller,
        key,
        aggregate_id,
        reason,
        ControlEventPayload::AlphaTabUpdated(Box::new(payload)),
        &mut act_alloc,
    )
    .await?;
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: update did not fold")))?;
    let install = entry_in(&mut tx, caller, &row).await?;
    db.commit_control(tx).await?;
    echo_act(
        json!({"changed": true, "idempotent_retry": false, "update_event_id": event_id,
        "previous_install_event_id": expected_install_event_id, "adoption_carried": carried,
        "adoption_required": required, "install": install}),
        act_alloc.get(),
    )
}

async fn do_transition(
    db: &Db,
    caller: &Caller,
    event_type: &'static str,
    package: String,
    expected_install_event_id: String,
    reason: String,
    idempotency_key: Option<String>,
) -> Result<Value> {
    require_package(&package)?;
    require_reason(TOOL, &reason)?;
    let account_id = require_account(caller)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = ActAllocation::new();
    let key = idempotency_key
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| {
            format!("alpha-tab-{event_type}:{account_id}:{package}:{expected_install_event_id}")
        });
    let aggregate_id = alpha_tab_aggregate_id(&account_id, &package);
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: package {package} is not installed")))?;
    let payload = install_payload(
        &account_id,
        &row.package,
        &row.version,
        &row.digest,
        &row.artifact_id,
        &row.consented_source_revision,
        &row.declaration_digest,
        &row.consented_declaration,
        row.request.clone(),
        Some(expected_install_event_id.clone()),
    );
    let control_payload = match event_type {
        "alpha_tab.disabled" => ControlEventPayload::AlphaTabDisabled(payload),
        "alpha_tab.restored" => ControlEventPayload::AlphaTabRestored(payload),
        "alpha_tab.removed" => ControlEventPayload::AlphaTabRemoved(payload),
        _ => return Err(Error::engine(format!("{TOOL}: unknown transition"))),
    };
    if let Some((kind, aggregate, actor, prior_reason, prior)) =
        prior_alpha_event(&mut tx, &key).await?
    {
        let expected_kind = event_type;
        if kind != expected_kind
            || aggregate != aggregate_id
            || actor != caller.actor()
            || prior_reason != reason
            || prior
                != match &control_payload {
                    ControlEventPayload::AlphaTabDisabled(value)
                    | ControlEventPayload::AlphaTabRestored(value)
                    | ControlEventPayload::AlphaTabRemoved(value) => value.clone(),
                    _ => unreachable!("transition payload"),
                }
        {
            return Err(Error::engine(format!(
                "{TOOL}: idempotency_key was reused for different intent"
            )));
        }
        append_alpha_event(
            &mut tx,
            caller,
            key,
            aggregate_id,
            reason,
            control_payload,
            &mut act_alloc,
        )
        .await?;
        let row = install_row_in(&mut tx, &account_id, &package)
            .await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: transition did not fold")))?;
        let entry = entry_in(&mut tx, caller, &row).await?;
        db.commit_control(tx).await?;
        return echo_act(
            json!({"package": package, "changed": false, "idempotent_retry": true, "install": entry}),
            act_alloc.get(),
        );
    }
    if row.event_id != expected_install_event_id {
        return Err(Error::engine(format!(
            "{TOOL}: installation changed; expected current event {expected_install_event_id} but found {}",
            row.event_id
        )));
    }
    let allowed = matches!(
        (event_type, row.status.as_str()),
        ("alpha_tab.disabled", "installed")
            | ("alpha_tab.restored", "disabled")
            | ("alpha_tab.removed", "installed" | "disabled")
    );
    if !allowed {
        return Err(Error::engine(format!(
            "{TOOL}: package {package} with status {} cannot transition via {event_type}",
            row.status
        )));
    }
    // Restore re-validates the pinned target before moving state: a removed
    // artifact or lost View refuses the transition with a named reason
    // rather than folding an unresolvable row. Remove deliberately does not:
    // cleanup must stay possible after the target is gone or authority is
    // lost — the tombstone it folds is already unresolvable by construction.
    if event_type == "alpha_tab.restored" {
        match target_state_in(&mut tx, &row.artifact_id).await? {
            TargetState::Resolvable => {}
            other => {
                return Err(Error::engine(format!(
                    "{TOOL}: target {} is {}",
                    row.artifact_id,
                    target_state_name(other)
                )));
            }
        }
        super::require_record_in(&mut tx, caller, TOOL, &row.artifact_id, Capability::View).await?;
    }
    append_alpha_event(
        &mut tx,
        caller,
        key,
        aggregate_id,
        reason,
        control_payload,
        &mut act_alloc,
    )
    .await?;
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: transition did not fold")))?;
    let entry = entry_in(&mut tx, caller, &row).await?;
    db.commit_control(tx).await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
        act_alloc.get(),
    )
}
/// The account's stored tab order, if the viewer (or an agent) ever stored
/// one with `reorder`. Malformed JSON here is engine corruption, not a shell
/// problem: only validated `alpha_tab.order_set` events write this row, so a
/// parse failure is an error rather than a silent fallback.
async fn stored_tab_order_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account_id: &str,
) -> Result<Option<Vec<String>>> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT tab_order FROM alpha_tab_orders WHERE account_id=?")
            .bind(account_id)
            .fetch_optional(&mut **tx)
            .await?;
    raw.map(|raw| {
        serde_json::from_str(&raw)
            .map_err(|_| Error::engine(format!("{TOOL}: stored tab order is corrupt")))
    })
    .transpose()
}

/// Packages with a live tab slot: `installed` or `disabled` rows. `removed`
/// rows keep no slot — the shell renders no tab for them — and unknown
/// packages never had one.
async fn slotted_packages_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account_id: &str,
) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT package FROM alpha_tab_installs
          WHERE account_id=? AND status IN ('installed','disabled') ORDER BY package",
    )
    .bind(account_id)
    .fetch_all(&mut **tx)
    .await?)
}

/// Resolve the order the shell renders from a stored order plus the live
/// slots: the stored array (or the default when none was stored, or the
/// stored one was reset to empty), deduped, minus entries for
/// removed-or-unknown packages, plus every missing built-in and then every
/// missing slotted package, appended in order.
///
/// Pure so the normalization is unit-coverable without a database. The
/// `reorder` gate keeps tool-written orders clean, but a directly appended
/// control event only faces the tier's shape check — so a malformed yet
/// shaped order (duplicates, unknown ids, missing built-ins) still
/// normalizes here instead of reaching the strip. Mirrors the shell's
/// `applyTabOrder`.
fn resolve_effective_tab_order(stored: Option<&[String]>, slotted: &[String]) -> Vec<String> {
    let base: Vec<String> = match stored {
        Some(stored) if !stored.is_empty() => stored.to_vec(),
        _ => ALPHA_TAB_DEFAULT_ORDER
            .iter()
            .map(|tab| tab.to_string())
            .chain(
                slotted
                    .iter()
                    .map(|package| format!("{ALPHA_TAB_PENDING_PREFIX}{package}")),
            )
            .collect(),
    };
    let mut seen = std::collections::HashSet::new();
    let mut order = Vec::new();
    for entry in &base {
        if !seen.insert(entry.as_str()) {
            continue;
        }
        if ALPHA_TAB_DEFAULT_ORDER.contains(&entry.as_str()) {
            order.push(entry.clone());
        } else if let Some(package) = entry.strip_prefix(ALPHA_TAB_PENDING_PREFIX) {
            if slotted.iter().any(|slotted| slotted == package) {
                order.push(entry.clone());
            }
        }
    }
    for builtin in ALPHA_TAB_DEFAULT_ORDER {
        if !order.iter().any(|entry| entry == builtin) {
            order.push(builtin.to_string());
        }
    }
    for package in slotted {
        let id = format!("{ALPHA_TAB_PENDING_PREFIX}{package}");
        if !order.contains(&id) {
            order.push(id);
        }
    }
    order
}

/// The order the shell should render: the stored order (or the default when
/// none was stored, or the stored one was reset to empty), normalized by
/// [`resolve_effective_tab_order`].
///
/// The append rule is what makes new installs land at the end without an
/// explicit reorder, and what keeps a stored entry for a removed-then-
/// reinstalled package meaningful: removal only hides the tab (it drops out
/// here), while its stored position survives, so a reinstall slots back
/// where it was until the next reorder says otherwise.
async fn effective_tab_order_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account_id: &str,
) -> Result<Vec<String>> {
    let stored = stored_tab_order_in(tx, account_id).await?;
    let slotted = slotted_packages_in(tx, account_id).await?;
    Ok(resolve_effective_tab_order(stored.as_deref(), &slotted))
}

/// Vocabulary gate for `reorder` (task `c5d3820`). An empty order is a reset
/// to the default and needs no further check. Otherwise every entry must be
/// a known built-in or a `pending:<package>` with a live slot
/// (installed-or-disabled), exactly once. Removed, never-installed, and
/// unknown ids are refused with a named tab so the agent can `list` and
/// retry — they are never silently dropped, because a silent drop would
/// reorder other tabs under a misunderstanding.
async fn require_reorderable_order_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account_id: &str,
    order: &[String],
) -> Result<()> {
    if order.len() > ALPHA_TAB_ORDER_MAX_ENTRIES {
        return Err(Error::engine(format!(
            "{TOOL}: tab_order holds {} entries (max {ALPHA_TAB_ORDER_MAX_ENTRIES})",
            order.len()
        )));
    }
    let slotted = slotted_packages_in(tx, account_id).await?;
    let mut seen = std::collections::HashSet::new();
    for entry in order {
        if !seen.insert(entry) {
            return Err(Error::engine(format!(
                "{TOOL}: tab_order names tab '{entry}' twice"
            )));
        }
        if let Some(package) = entry.strip_prefix(ALPHA_TAB_PENDING_PREFIX) {
            require_package(package).map_err(|_| {
                Error::engine(format!("{TOOL}: tab_order names unknown tab '{entry}'"))
            })?;
            if !slotted.iter().any(|slotted| slotted == package) {
                return Err(Error::engine(format!(
                    "{TOOL}: tab_order names tab '{entry}' with no installed package"
                )));
            }
        } else if !ALPHA_TAB_DEFAULT_ORDER.contains(&entry.as_str()) {
            return Err(Error::engine(format!(
                "{TOOL}: tab_order names unknown tab '{entry}'"
            )));
        }
    }
    // Tabs are arranged, never hidden: every built-in stays on the strip.
    // (Omitted installs are the forgiving case — they append at the end in
    // the effective order — but a missing built-in is almost certainly a
    // caller working from a stale list, so it refuses loudly. An empty
    // order is a reset to the default and needs no further check.)
    if !order.is_empty() {
        for builtin in ALPHA_TAB_DEFAULT_ORDER {
            if !seen.iter().any(|entry| entry.as_str() == builtin) {
                return Err(Error::engine(format!(
                    "{TOOL}: tab_order omits built-in tab '{builtin}'"
                )));
            }
        }
    }
    Ok(())
}

/// Same-key retry for orders: the `instructions.rs::prior_event` precedent
/// specialised to `AlphaTabOrderPayload`. A repeated key with a
/// field-for-field identical intent re-appends convergently (`changed:
/// false`); any difference is a visible reuse error.
async fn prior_alpha_order_event(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    key: &str,
) -> Result<Option<(String, String, String, String, AlphaTabOrderPayload)>> {
    let row = sqlx::query(
        "SELECT type,aggregate_id,actor,reason,payload FROM control_events WHERE idempotency_key=?",
    )
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let raw: String = row.try_get("payload")?;
        Ok((
            row.try_get("type")?,
            row.try_get("aggregate_id")?,
            row.try_get("actor")?,
            row.try_get("reason")?,
            serde_json::from_str(&raw)?,
        ))
    })
    .transpose()
}

/// Store the viewer's full tab-strip order (task `c5d3820`).
///
/// Complete-state write through `alpha_tab.order_set`: concurrent reorders
/// serialize in the write transaction and the later one stands (last writer
/// wins — documented on the payload), so callers that care list first and
/// reorder from what they saw. The response carries the effective order
/// (stored, normalised as `list` reports it), not just the stored array.
///
/// Idempotency has two layers. An explicit key dedupes retries before
/// anything else: a repeated key with an identical intent converges
/// (`changed: false`); any difference is a visible reuse error. Without a
/// key, every call mints a fresh one — a content-derived default would
/// collide across time (A→B→A reuses A's first key and leaves B projected
/// while reporting convergence). Reordering to the already-stored order is
/// a state-aware no-op (`changed: false`) that appends nothing, so a shell
/// persisting on every drag-end cannot spam the log.
async fn do_reorder(
    db: &Db,
    caller: &Caller,
    tab_order: Vec<String>,
    reason: String,
    idempotency_key: Option<String>,
) -> Result<Value> {
    require_reason(TOOL, &reason)?;
    let account_id = require_account(caller)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = ActAllocation::new();
    require_reorderable_order_in(&mut tx, &account_id, &tab_order).await?;
    let payload = AlphaTabOrderPayload {
        account_id: account_id.clone(),
        tab_order: tab_order.clone(),
    };
    let aggregate_id = alpha_tab_order_aggregate_id(&account_id);
    let explicit_key = idempotency_key.filter(|key| !key.trim().is_empty());
    if let Some(key) = explicit_key.clone() {
        if let Some((kind, aggregate, actor, prior_reason, prior)) =
            prior_alpha_order_event(&mut tx, &key).await?
        {
            if kind != "alpha_tab.order_set"
                || aggregate != aggregate_id
                || actor != caller.actor()
                || prior_reason != reason
                || prior != payload
            {
                return Err(Error::engine(format!(
                    "{TOOL}: idempotency_key was reused for different intent"
                )));
            }
            append_alpha_event(
                &mut tx,
                caller,
                key,
                aggregate_id,
                reason,
                ControlEventPayload::AlphaTabOrderSet(payload),
                &mut act_alloc,
            )
            .await?;
            let order = effective_tab_order_in(&mut tx, &account_id).await?;
            db.commit_control(tx).await?;
            return echo_act(
                json!({"changed": false, "idempotent_retry": true, "tab_order": order}),
                act_alloc.get(),
            );
        }
    }
    let stored = stored_tab_order_in(&mut tx, &account_id).await?;
    let is_noop = match &stored {
        Some(stored) => *stored == tab_order,
        None => {
            tab_order.is_empty()
                || tab_order
                    == ALPHA_TAB_DEFAULT_ORDER
                        .iter()
                        .map(|tab| tab.to_string())
                        .collect::<Vec<_>>()
        }
    };
    if is_noop {
        let order = effective_tab_order_in(&mut tx, &account_id).await?;
        tx.rollback().await?;
        return echo_act(
            json!({"changed": false, "tab_order": order}),
            act_alloc.get(),
        );
    }
    let key = explicit_key
        .unwrap_or_else(|| format!("alpha-tab-order-set:{account_id}:{}", Uuid::new_v4()));
    append_alpha_event(
        &mut tx,
        caller,
        key,
        aggregate_id,
        reason,
        ControlEventPayload::AlphaTabOrderSet(payload),
        &mut act_alloc,
    )
    .await?;
    let order = effective_tab_order_in(&mut tx, &account_id).await?;
    db.commit_control(tx).await?;
    echo_act(
        json!({"changed": true, "tab_order": order}),
        act_alloc.get(),
    )
}

async fn do_list(db: &Db, caller: &Caller) -> Result<Value> {
    let account_id = require_account(caller)?;
    let mut tx = db.pool().begin().await?;
    let rows: Vec<InstallRowTuple> = sqlx::query_as(
        "SELECT package,version,digest,artifact_id,consented_source_revision,
                    declaration_digest,consented_declaration,adoption,adoption_provenance,request,status,event_id,event_seq
               FROM alpha_tab_installs WHERE account_id=? ORDER BY package",
    )
    .bind(&account_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut installs = Vec::new();
    for (
        package,
        version,
        digest,
        artifact_id,
        consented_source_revision,
        declaration_digest,
        consented_declaration,
        adoption,
        adoption_provenance,
        request,
        status,
        event_id,
        event_seq,
    ) in rows
    {
        let row = InstallRow {
            package,
            version,
            digest,
            artifact_id,
            consented_source_revision,
            declaration_digest,
            consented_declaration: serde_json::from_str(&consented_declaration)?,
            adoption,
            adoption_provenance,
            request,
            status,
            event_id,
            event_seq,
        };
        installs.push(entry_in(&mut tx, caller, &row).await?);
    }
    let tab_order = effective_tab_order_in(&mut tx, &account_id).await?;
    tx.rollback().await?;
    Ok(json!({"account_id": account_id, "installs": installs, "tab_order": tab_order}))
}

async fn do_inspect(db: &Db, caller: &Caller, package: String) -> Result<Value> {
    require_package(&package)?;
    let account_id = require_account(caller)?;
    let mut tx = db.pool().begin().await?;
    let tab_order = effective_tab_order_in(&mut tx, &account_id).await?;
    let result = match install_row_in(&mut tx, &account_id, &package).await? {
        Some(row) => {
            let entry = entry_in(&mut tx, caller, &row).await?;
            json!({"package": package, "installed": true, "install": entry, "tab_order": tab_order})
        }
        None => json!({"package": package, "installed": false, "tab_order": tab_order}),
    };
    tx.rollback().await?;
    Ok(result)
}

/// Issue a one-use HTML ticket from the exact consented source event. The
/// write transaction serializes source, install, and authority checks with
/// concurrent control transitions; no URL is returned before the post-issue
/// provenance check. Delivery is sample-only until the named-input host lands.
async fn do_launch(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
) -> Result<Value> {
    require_package(&package)?;
    if expected_install_event_id.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: expected_install_event_id must not be blank"
        )));
    }
    let account_id = require_account(caller)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: package {package} is not installed [missing_install]"
            ))
        })?;
    if row.event_id != expected_install_event_id {
        return Err(Error::engine(format!(
            "{TOOL}: installation changed [cas_mismatch]"
        )));
    }
    let target = target_state_in(&mut tx, &row.artifact_id).await?;
    let can_view = target == TargetState::Resolvable
        && super::can_record_in(&mut tx, caller, &row.artifact_id, Capability::View).await?;
    if let Err(reason) =
        evaluate_alpha_tab_install_gates(&row.status, &row.adoption, target, can_view)
    {
        return Err(Error::engine(format!("{TOOL}: launch refused [{reason}]")));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&row.artifact_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    let source =
        resolve_alpha_tab_source_in(&mut tx, &row.artifact_id, &row.consented_source_revision)
            .await?;
    let declaration_digest = alpha_tab_declaration_digest(&row.consented_declaration)?;
    if declaration_digest != row.declaration_digest {
        return Err(Error::engine(format!(
            "{TOOL}: launch refused [declaration_mismatch]"
        )));
    }
    let digest_matches = match (&runtime, &source) {
        (Some(runtime), Some(source)) => {
            alpha_tab_digest(
                &alpha_tab_bundle_digest(&source.body),
                &declaration_digest,
                runtime,
            ) == row.digest
        }
        _ => false,
    };
    if let Err(reason) = evaluate_alpha_tab_source_gates(
        runtime.as_deref() == Some("native.html.v1"),
        source.is_some(),
        digest_matches,
    ) {
        return Err(Error::engine(format!("{TOOL}: launch refused [{reason}]")));
    }
    let source = source.expect("source gate passed");
    let manifest = crate::artifact_html::validate_cached(&source.body)
        .map_err(|failure| Error::engine(format!("{TOOL}: launch refused [{}]", failure.code)))?;
    let bundle_sha256 = alpha_tab_bundle_digest(&source.body);
    if manifest.body_digest != bundle_sha256 {
        return Err(Error::engine(format!(
            "{TOOL}: launch refused [body_digest_mismatch]"
        )));
    }
    let principal = caller.hosting_principal().unwrap_or(account_id.as_str());
    let launch = crate::artifact_html::issue_launch(
        &source.body,
        &manifest,
        principal,
        caller.hosting_database(),
        &row.artifact_id,
    )
    .map_err(|failure| Error::engine(format!("{TOOL}: launch refused [{}]", failure.code)))?;
    // Post-issue bind: a returned ticket must describe the same event and
    // install state observed before issuance. Under SQLite's write lock these
    // cannot change concurrently, but keep the check explicit as provenance.
    let current = install_row_in(&mut tx, &account_id, &package).await?;
    let current_source =
        resolve_alpha_tab_source_in(&mut tx, &row.artifact_id, &row.consented_source_revision)
            .await?;
    if current.as_ref().is_none_or(|current| {
        current.event_id != row.event_id
            || current.digest != row.digest
            || current.version != row.version
            || current.artifact_id != row.artifact_id
            || current.consented_source_revision != row.consented_source_revision
            || current.declaration_digest != row.declaration_digest
            || current.adoption != row.adoption
            || current.status != row.status
    }) || current_source.as_ref().is_none_or(|current| {
        current.event_id != source.event_id
            || alpha_tab_bundle_digest(&current.body) != bundle_sha256
    }) {
        // The unreturned ticket expires unused; it grants no caller access.
        return Err(Error::engine(format!(
            "{TOOL}: launch refused [provenance_changed]"
        )));
    }
    tx.rollback().await?;
    let sample_input = alpha_tab_sample_input();
    let sample_input_digest = alpha_tab_sample_input_digest(&sample_input);
    Ok(json!({
        "package": package,
        "install_event_id": row.event_id,
        "pin": {
            "package": row.package,
            "version": row.version,
            "digest": row.digest,
            "artifact_id": row.artifact_id,
            "source_revision": row.consented_source_revision,
            "declaration_digest": row.declaration_digest,
        },
        "source": {
            "event_id": source.event_id,
            "bundle_sha256": bundle_sha256,
            "body_digest": manifest.body_digest,
            "runtime": runtime,
        },
        "launch": {
            "url": launch.url,
            "expires_in_ms": launch.expires_in_ms,
            "bridge_version": crate::artifact_html::BRIDGE_VERSION,
        },
        "sandbox": {
            "sandbox": "allow-scripts",
            "referrerPolicy": "no-referrer",
            "allow": "",
            "bridge_version": crate::artifact_html::BRIDGE_VERSION,
        },
        "input": sample_input,
        "input_digest": sample_input_digest,
        "live_reads": false,
        "effects_wired": false,
    }))
}

/// Host-executed governed live read for one adopted tab (task `26ba75a`,
/// bounded backend/data slice).
///
/// Gate order mirrors `do_launch` exactly, then adds the consented-need
/// check: CAS on `expected_install_event_id` → install gates (status, then
/// verified adoption (`shell_adopt.v1` or `shell_auto.v1`), then target
/// liveness + viewer View) →
/// source/digest gates (runtime `native.html.v1`, exact body-carrying source
/// event, `alpha-tab-digest.v1` recomputation) → consented `needs` contains
/// `attention.query.v1` (else `undeclared_need`). First refusal wins, no live
/// rows leave the host on any refusal.
///
/// On success the host — never the frame — executes `attention.query.v1`
/// under the current viewer's authority (internal bounded newest-first scan
/// with per-row `can_record_in`, the same API the launch gate uses), shapes
/// the rows as the HTML bridge input (`native.artifact-input.v1`,
/// `mode: "live"`, top-level `records` shim per
/// `alpha_tab_attention_port_mapping`), and returns the rows with
/// `input_digest` plus a viewer-scoped staleness token
/// `revision { revision_digest, rows_sha256 }` and the install pin as
/// provenance. Launch and preview stay sample-only; this response goes to
/// the tool caller (the host), never to the frame.
///
/// Noninterference by construction: the token derives ONLY from data this
/// viewer may see (the returned rows) plus the install generation (the pin
/// plus `install_event_id`). No global content-event id/seq and no
/// authorization epoch leave the host — those would leak the existence and
/// recency of records this viewer may not read — and no scan
/// counters/completeness leave either (those would reveal the density of
/// inaccessible tasks). The bounded scan stays internal; the public
/// response carries only the static `window { bounded_window: true }`
/// marker.
///
/// Exact limits: the token fences the delivered display fields only. It
/// moves when the returned row set changes (proven by test for visible row
/// and access changes) and deliberately does NOT move for unrelated writes
/// — including writes to inaccessible tasks (proven by the noninterference
/// test). Revocation is gated per request by re-running the full gate chain
/// on every `live_read` call, not by comparing this token. This is
/// explicitly NOT `native.artifact-input-bundle-receipt.v1`: no per-port
/// digests, no `meta_sha256`, no `input_abi` are claimed.
/// `expires_in_ms` is deliberately absent: ticket TTL bounds redemption of
/// an issued URL only, never display staleness.
///
/// With `need` set to an on-request need ([`RECORDS_SEARCH_NEED`],
/// [`RECORDS_RESOLVE_REFERENCE_NEED`], [`CANVAS_SCENE_NEED`], [`RECORD_CHANGES_NEED`]) the same
/// gate chain runs, then the
/// consented-need check names that need, then [`parse_declared_read`] bounds
/// the parameters (`unknown_need`, `invalid_params`). The read itself is the
/// ordinary tool handler under the viewer's `Caller`, so its results and
/// access semantics are the viewer's own by construction. On-request reads
/// carry no revision fence: they answer one request and are not a snapshot.
/// Snapshot SQL needs as stored in a consented declaration, sorted by `key`.
/// Strict: the same [`parse_sql_need_entry`] parser admission uses (bounds,
/// key shape, statement validity, no placeholders), plus key uniqueness and
/// the count bound. A corrupt or legacy stored declaration fails here with a
/// named refusal instead of executing half-parsed: duplicate keys would
/// otherwise collapse in the keyed input (last wins) while consent covered
/// two entries. The gate chain's digest recomputation usually refuses first;
/// this is the second layer for a stored declaration whose digest was
/// corrupted consistently with its body.
fn sql_needs_in(declaration: &Value) -> Result<Vec<SqlNeed>> {
    body_read_descriptor_in(declaration).map_err(Error::engine)?;
    let mut out: Vec<SqlNeed> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    if let Some(entries) = declaration.get("needs").and_then(Value::as_array) {
        for entry in entries {
            if let Some(name) = entry.as_str() {
                names.push(name);
                continue;
            }
            match classify_declaration_need(entry).map_err(Error::engine)? {
                DeclarationNeed::Sql(need) => out.push(need),
                DeclarationNeed::Name(_) | DeclarationNeed::BodyRead => {}
            }
        }
    }
    if out.len() > SQL_SNAPSHOT_MAX_NEEDS {
        return Err(Error::engine(format!(
            "{TOOL}: snapshot holds at most 8 sql.snapshot.v1 needs [sql_need_failed]"
        )));
    }
    out.sort_by(|left, right| left.key.cmp(&right.key));
    for window in out.windows(2) {
        if window[0].key == window[1].key {
            return Err(Error::engine(format!(
                "{TOOL}: snapshot sql need key '{}' is duplicated [sql_need_failed]",
                window[0].key
            )));
        }
    }
    // Cross-namespace duplicate, mirroring the install-time refusal: a
    // string need shadowed by an SQL key would dispatch to SQL silently.
    for need in &out {
        if names.iter().any(|name| *name == need.key) {
            return Err(Error::engine(format!(
                "{TOOL}: snapshot sql need key '{}' duplicates a string need [sql_need_failed]",
                need.key
            )));
        }
    }
    Ok(out)
}

/// Execute one declared SQL need through the ordinary `query_sql`
/// handler under the viewer's `Caller`, so rows and access semantics match
/// the viewer's own `query_sql` call with the same text by construction.
/// Strips the handler's `as_of_seq` (a global content-event seq that must
/// never leave the host in this response) and truncates the delivered rows
/// to [`SQL_SNAPSHOT_ROW_CAP`] with an explicit `truncated` flag, while the
/// digest covers the FULL rows `query_sql` returned plus `truncated` — so
/// tail growth past the cap still moves `revision_digest` while the
/// delivered prefix is unchanged. Any failure maps to a named
/// `sql_need_failed` refusal: the snapshot returns no partial input.
/// Parameters bind positionally via `query_sql`'s `parameters` mechanism,
/// never string interpolation, so a value can never widen what the viewer
/// sees beyond their own authority.
///
/// Completeness: `row_count` is the count `query_sql` returned, which is
/// itself capped at that path's runtime row bound (`MAX_ROWS`, 1,000).
/// `row_count_complete` is false exactly when `query_sql` reported its own
/// truncation, so `row_count` is then a floor ("more than 1,000"), never a
/// total a package may print as "of N". It is independent of the snapshot
/// cap: 205 rows deliver 200 with `truncated: true` and
/// `row_count_complete: true`.
///
/// Staleness caveat: the digest covers what `query_sql` returned plus
/// `row_count_complete`, so crossing `query_sql`'s own cap moves
/// `revision_digest` even when the returned 1,000-row prefix is unchanged.
/// Growth further beyond that cap is invisible here, exactly as it is to a
/// direct `query_sql` caller.
struct SnapshotSqlNeed {
    /// Frame input: rows capped at [`SQL_SNAPSHOT_ROW_CAP`] with `row_count`
    /// reporting the full returned count and `row_count_complete` saying
    /// whether that count is the true total, so a package can show "200 of
    /// N" only when it is true. Fields are [`SQL_NEED_RESULT_FIELDS`].
    input: Value,
    /// Digest material: `{columns, rows, truncated, row_count_complete}`
    /// over the full returned rows, before the snapshot cap.
    digest: Value,
    /// Statement-fixed clock from the `query_sql` engine (M1 slice 1): the
    /// single value bound for every `now_ms()` use in this need's statement,
    /// or `None` when the statement is clock-free. Preserved per need
    /// because sequential snapshot evaluation gives each statement its own
    /// clock; the snapshot-level `as_of_ms` is only the maximum of these,
    /// never any one need's exact bind value.
    now_ms_ms: Option<i64>,
    /// Genuinely server-detected time dependence: the engine's own
    /// `time_dependent` flag for this need's statement.
    time_dependent: bool,
}

/// Pure SnapshotSqlNeed projection shared by the owned and caller-transaction
/// SQL paths: snapshot cap, digest inputs, and clock metadata from one engine
/// result envelope. Declared needs execute inside the caller-owned data
/// transaction (`execute_sql_need_in`); the former owned-executor wrappers
/// were removed with the snapshot/on-request rewiring so only one executor
/// remains. Paging's row_count_complete is computed here, shared: engine
/// full-result completeness, distinct from our delivered-200 truncation.
fn project_snapshot_need(need: &SqlNeed, raw: &Value) -> Result<SnapshotSqlNeed> {
    let columns = raw.get("columns").cloned().unwrap_or(Value::Null);
    let full_rows: Vec<Value> = raw
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let full_count = full_rows.len();
    // `query_sql`'s own truncation, before the snapshot cap touches it. A
    // missing flag is not evidence of completeness: fail closed to a floor.
    let query_truncated = raw
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let row_count_complete = !query_truncated;
    let mut truncated = query_truncated;
    let mut truncation_hint = raw.get("truncation_hint").cloned().unwrap_or(Value::Null);
    let mut delivered = full_rows.clone();
    if delivered.len() > SQL_SNAPSHOT_ROW_CAP {
        delivered.truncate(SQL_SNAPSHOT_ROW_CAP);
        truncated = true;
        truncation_hint = json!(crate::query::sql_contract::truncation_hint_for(true));
    }
    // M1 slice 1: carry the engine's own clock metadata beside the rows.
    // `time_dependent` is the statement's genuine server-detected flag, not
    // a text scan at this layer; `now_ms_ms` is its statement-fixed clock.
    // Neither enters the digest below, so a clock-only reevaluation keeps
    // the same `revision_digest` and a quiet tick delivers nothing. The
    // engine always emits both fields together (`time_dependent` exactly
    // when `now_ms_ms` is present); anything else is an internal skew,
    // failed closed rather than reported as a confident `false` — a silent
    // `false` would drop the subscription from the M1 clock recheck.
    let now_ms_ms = raw.get("now_ms_ms").and_then(Value::as_i64);
    let time_dependent = raw.get("time_dependent").and_then(Value::as_bool);
    if !matches!(
        (time_dependent, now_ms_ms),
        (Some(true), Some(_)) | (Some(false), None)
    ) {
        return Err(Error::engine(format!(
            "{TOOL}: sql need '{}' returned inconsistent clock metadata [clock_metadata_mismatch]",
            need.key
        )));
    }
    let time_dependent = time_dependent == Some(true);
    Ok(SnapshotSqlNeed {
        input: json!({
            "label": need.label,
            "columns": columns,
            "rows": delivered,
            "row_count": full_count,
            "row_count_complete": row_count_complete,
            "truncated": truncated,
            "truncation_hint": truncation_hint,
            "now_ms_ms": now_ms_ms,
            "time_dependent": time_dependent,
            // Declared needs always carry ORDER BY, so the server never
            // assumes an order here; the key stays null for shape
            // consistency with ad-hoc `query_sql`.
            "assumed_order": null,
        }),
        digest: json!({
            "columns": columns,
            "rows": full_rows,
            "truncated": truncated,
            "row_count_complete": row_count_complete,
        }),
        now_ms_ms,
        time_dependent,
    })
}

/// One declared SQL need inside the caller's data transaction: same snapshot
/// as the gates, same rows as the viewer's own `query_sql`. The engine runs
/// under the ordinary owned ad-hoc contract (Portable, MAX_ROWS); the
/// snapshot cap stays in the shared projection. No `as_of_seq` enters the
/// envelope: it is stripped by construction here, not just unread later.
/// Only execution failures carry `sql_need_failed`; gate and parameter
/// refusals are raised before this runs and keep their own codes.
async fn execute_sql_need_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    principal: crate::query::QueryPrincipal,
    need: &SqlNeed,
    parameters: Vec<crate::query::sql_contract::QuerySqlParameter>,
    vm_callbacks: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    replay_clock: Option<i64>,
) -> Result<SnapshotSqlNeed> {
    let request = crate::query::sql_contract::QuerySqlRequest {
        sql: need.sql.clone(),
        parameters,
    };
    let (result, _) = crate::query::sql::query_sql_request_in_with_row_limit_observed(
        tx,
        principal,
        request,
        crate::query::sql_contract::MAX_ROWS as i64,
        crate::query::sql_contract::FunctionAllowance::Portable,
        replay_clock,
        vm_callbacks,
        // Declared needs always carry ORDER BY (admission refuses
        // otherwise); the ad-hoc default never applies here. The field
        // list below stays the pinned package shape.
        false,
    )
    .await
    .map_err(|error| {
        Error::engine(format!(
            "{TOOL}: sql need '{}' failed: {error} [sql_need_failed]",
            need.key
        ))
    })?;
    project_snapshot_need(
        need,
        &json!({
            "columns": result.columns,
            "rows": result.rows,
            "row_count": result.row_count,
            "truncated": result.truncated,
            "truncation_hint": result.truncation_hint,
            "now_ms_ms": result.now_ms_ms,
            "time_dependent": result.time_dependent,
        }),
    )
}

/// Fail-closed parity gate for the attention window. Candidates already
/// passed the governed visible view under the same authority, so a denial
/// by `can_record_in` is an authority mismatch: refuse the whole read with
/// an internal error before any `records`/digest is emitted. Identical in
/// debug and release — authorization control flow must not diverge by
/// profile. A mismatch is stop-and-report, never a reason to broaden
/// rights — and never a silent skip, which would shrink the window and
/// recreate the pre-LIMIT boundary the join fixed. The error carries no
/// row identity.
fn attention_parity_gate(allowed: bool) -> Result<()> {
    if !allowed {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [authority_mismatch]"
        )));
    }
    Ok(())
}

/// Outcome of resolving a `subscribe` request against the hub registry.
/// A refusal still evaluates the ordinary read in the same call; the refusal
/// code rides alongside the result so the host polls that need instead.
enum SubscribeOutcome {
    Absent,
    Pending(PendingSubscription),
    Refused(SubscribeRefusal),
}

struct PendingSubscription {
    hub: Arc<RealtimeHub>,
    token: ConnectionToken,
    id: crate::need_subscriptions::SubscriptionId,
}

/// The immediate subscribe catch-up owns this marker across its awaited
/// snapshot. Cancellation cannot leave an unannounced active subscription
/// with an old clean baseline: dropping an incomplete guard removes it.
struct CatchupProbeGuard {
    hub: Arc<RealtimeHub>,
    token: ConnectionToken,
    id: crate::need_subscriptions::SubscriptionId,
    completed: bool,
}

impl CatchupProbeGuard {
    fn new(pending: &PendingSubscription) -> Self {
        Self {
            hub: Arc::clone(&pending.hub),
            token: pending.token.clone(),
            id: pending.id.clone(),
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .finish_catchup(&self.token, &self.id);
        self.completed = true;
    }
}

impl Drop for CatchupProbeGuard {
    fn drop(&mut self) {
        if !self.completed {
            // A failed/cancelled request never gave the host this id. Its
            // catch-up result cannot establish a baseline, so retire it.
            self.hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .unsubscribe(&self.token, &self.id);
        }
    }
}

/// Step 1 of the §2.2 atomic subscribe: register as pending before any
/// evaluation, so a trigger firing mid-read sets the dirty flag instead of
/// slipping between evaluation and registration. The token's account and
/// database must match the tool call's (`Caller` credential and database
/// identity); otherwise `stream_unknown`, same as closed/unknown tokens.
async fn resolve_subscribe_request(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    subscribe: Option<LiveReadSubscribe>,
    need: &str,
    params: &Option<Value>,
) -> Result<SubscribeOutcome> {
    let Some(request) = subscribe else {
        return Ok(SubscribeOutcome::Absent);
    };
    let resolved = match (
        ConnectionToken::from_hex(request.stream.trim()),
        RealtimeHub::for_database(db),
    ) {
        (Some(token), Some(hub)) => {
            let database_id = crate::identity::database_id(db).await?;
            let digest = params_digest(params.as_ref());
            let binding = SurfaceBinding::alpha_tab(package, expected_install_event_id);
            let subscribed = hub
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .subscribe_pending(
                    &token,
                    caller.credential(),
                    &database_id,
                    binding,
                    need,
                    &digest,
                );
            match subscribed {
                Ok(id) => SubscribeOutcome::Pending(PendingSubscription { hub, token, id }),
                Err(refusal) => SubscribeOutcome::Refused(refusal),
            }
        }
        _ => SubscribeOutcome::Refused(SubscribeRefusal::StreamUnknown),
    };
    Ok(resolved)
}

/// Measure the synchronous snapshot work without adding fields to the
/// viewer's tool result. The push scheduler calls the underlying evaluator
/// directly and retains its own delivery and quiet accounting.
struct PullVmWorkObservation {
    hub: Option<std::sync::Arc<RealtimeHub>>,
    kind: PullKind,
    sql_attempted: bool,
    completed: bool,
    vm_work: VmWorkObserver,
}

impl Drop for PullVmWorkObservation {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(hub) = &self.hub {
                hub.need_metrics()
                    .lock()
                    .expect("need metrics poisoned")
                    .note_cancelled_pull(ATTENTION_QUERY_NEED, self.sql_attempted);
            }
        }
    }
}

async fn measured_pull_snapshot(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    kind: PullKind,
) -> Result<(Value, crate::need_subscriptions::GateSnapshot, bool)> {
    let started = std::time::Instant::now();
    let mut observation = PullVmWorkObservation {
        hub: db.realtime_hub(),
        kind,
        sql_attempted: false,
        completed: false,
        vm_work: VmWorkObserver::default(),
    };
    let result = evaluate_snapshot_live_read(
        db,
        caller,
        package,
        expected_install_event_id,
        Some(&mut observation.sql_attempted),
        Some(&observation.vm_work),
    )
    .await;
    let duration = started.elapsed();
    if let Some(hub) = &observation.hub {
        let output_rows = result.as_ref().ok().map(|(value, _, _)| {
            let input = &value["input"];
            let records = input["records"].as_array().map_or(0, Vec::len);
            let sql = input["sql"].as_object().map_or(0, |needs| {
                needs
                    .values()
                    .map(|need| need["rows"].as_array().map_or(0, Vec::len))
                    .sum::<usize>()
            });
            records + sql
        });
        hub.need_metrics()
            .lock()
            .expect("need metrics poisoned")
            .note_pull(
                ATTENTION_QUERY_NEED,
                observation.kind,
                duration,
                observation.sql_attempted,
                output_rows,
                observation.vm_work.sample(),
            );
    }
    observation.completed = true;
    result
}

/// M2 `live_read` entry point: on-request needs fan out to the declared
/// read; the snapshot evaluates, then applies the §2.2 atomic subscribe
/// (pending → evaluate → install baseline → one immediate re-run if
/// dirtied) and the `if_revision` resync fence. A refused evaluation
/// releases its pending entry. A refused re-run unsubscribes (the closest
/// available analogue of `need-closed`: with no sink yet there is no frame
/// to carry the reason) and returns the refusal. Scheduler wake sources and
/// the push sink are wired by the `/events` handler.
async fn do_live_read(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    need: Option<String>,
    params: Option<Value>,
    options: LiveReadOptions,
) -> Result<Value> {
    let resolved_need = need.unwrap_or_else(|| ATTENTION_QUERY_NEED.to_string());
    if resolved_need != ATTENTION_QUERY_NEED {
        // Boxed: the declared read embeds whole tool handlers, which would
        // otherwise inflate every `manage_alpha_tabs` future on the stack.
        return Box::pin(do_declared_read(
            db,
            caller,
            package,
            expected_install_event_id,
            resolved_need,
            params,
            options,
        ))
        .await;
    }
    let LiveReadOptions {
        subscribe,
        if_revision,
        watch,
    } = options;
    if watch.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [invalid_params]"
        )));
    }
    let pull_kind = match (subscribe.is_some(), if_revision.is_some()) {
        (false, false) => PullKind::Plain,
        (true, false) => PullKind::Subscribe,
        (false, true) => PullKind::Resync,
        (true, true) => PullKind::Resubscribe,
    };
    if params.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [invalid_params]"
        )));
    }
    let outcome = resolve_subscribe_request(
        db,
        caller,
        &package,
        &expected_install_event_id,
        subscribe,
        &resolved_need,
        &params,
    )
    .await?;
    let (mut response, mut clock_replay_safe) = match measured_pull_snapshot(
        db,
        caller,
        package.clone(),
        expected_install_event_id.clone(),
        pull_kind,
    )
    .await
    {
        Ok((response, _gate, clock_replay_safe)) => (response, clock_replay_safe),
        Err(error) => {
            if let SubscribeOutcome::Pending(pending) = &outcome {
                pending
                    .hub
                    .need_registry()
                    .lock()
                    .expect("need registry poisoned")
                    .remove_pending(&pending.token, &pending.id);
            }
            return Err(error);
        }
    };
    let mut subscription_field = None;
    let mut refused_code = None;
    if let SubscribeOutcome::Pending(pending) = &outcome {
        let digest = response
            .get("revision")
            .and_then(|revision| revision.get("revision_digest"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let time_dependent = response
            .get("time_dependent")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (activated, catchup_act_drops) = {
            let mut registry = pending
                .hub
                .need_registry()
                .lock()
                .expect("need registry poisoned");
            let activated = registry.activate_with_probe_safety(
                &pending.token,
                &pending.id,
                &digest,
                time_dependent,
                snapshot_clock_bindings(&response),
                clock_replay_safe,
            );
            // The immediate subscribe catch-up is a tool-handler evaluation,
            // outside the measured push scheduler. Consume its acts at this
            // boundary; a write during the await below stays pending for the
            // scheduler instead of being charged to a later unrelated run.
            let dropped = if activated == Some(true) {
                registry
                    .clear_dirty_for_catchup(&pending.token, &pending.id)
                    .map_or(0, |dirty| {
                        dirty.content_acts.len() as u64 + u64::from(dirty.unknown_act)
                    })
            } else {
                0
            };
            (activated, dropped)
        };
        if catchup_act_drops > 0 {
            pending
                .hub
                .need_metrics()
                .lock()
                .expect("need metrics poisoned")
                .note_subscribe_catchup_association_drops(catchup_act_drops);
        }
        if let Some(dirtied) = activated {
            if dirtied {
                let mut catchup_guard = CatchupProbeGuard::new(pending);
                response = match measured_pull_snapshot(
                    db,
                    caller,
                    package,
                    expected_install_event_id,
                    PullKind::Catchup,
                )
                .await
                {
                    Ok((rerun, _gate, rerun_clock_replay_safe)) => {
                        clock_replay_safe = rerun_clock_replay_safe;
                        let fresh = rerun
                            .get("revision")
                            .and_then(|revision| revision.get("revision_digest"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        let time_dependent = rerun
                            .get("time_dependent")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let reactivated = {
                            let mut registry = pending
                                .hub
                                .need_registry()
                                .lock()
                                .expect("need registry poisoned");
                            let reactivated = registry.activate_with_probe_safety(
                                &pending.token,
                                &pending.id,
                                &fresh,
                                time_dependent,
                                snapshot_clock_bindings(&rerun),
                                clock_replay_safe,
                            );
                            // A second trigger during this one immediate re-run
                            // must remain queued for the scheduler. The wake may
                            // already have queued it; enqueue is idempotent.
                            // Force this atomic-subscribe catch-up even if the
                            // trigger was content, so no intervening write
                            // waits for the ordinary debounce.
                            if reactivated == Some(true) {
                                registry.enqueue_dirty_with_trigger(
                                    &pending.token,
                                    &pending.id,
                                    true,
                                    crate::need_metrics::Trigger::Subscribe,
                                );
                            }
                            reactivated
                        };
                        if reactivated.is_none() {
                            refused_code =
                                Some(SubscribeRefusal::StreamUnknown.as_code().to_string());
                        }
                        catchup_guard.complete();
                        rerun
                    }
                    Err(error) => return Err(error),
                };
            }
            if refused_code.is_none() {
                // M1 slice 1: the subscription reports the snapshot's own
                // server-detected time dependence, evaluated above — true
                // when any evaluated snapshot need uses `now_ms()`.
                let time_dependent = response
                    .get("time_dependent")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                subscription_field =
                    Some(json!({"id": pending.id.as_str(), "time_dependent": time_dependent}));
            }
        } else {
            // The stream was removed while the ordinary read evaluated.
            refused_code = Some(SubscribeRefusal::StreamUnknown.as_code().to_string());
        }
    } else if let SubscribeOutcome::Refused(refusal) = &outcome {
        refused_code = Some(refusal.as_code().to_string());
    }
    if let Some(held) = if_revision.as_deref() {
        let current = response
            .get("revision")
            .and_then(|revision| revision.get("revision_digest"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if held == current {
            // M1 slice 1: an unchanged resync intentionally carries no fresh
            // `as_of_ms`. The snapshot above was freshly evaluated, but
            // equality means the held rows and revision are still valid, so
            // the response suppresses the body and the new stamp with it —
            // the held digest stays covered by the stamp of the delivery
            // that set the baseline. The subscription flag still reports
            // the snapshot's time dependence, which is a property of the
            // declaration, not of this call.
            let mut unchanged = json!({
                "package": response.get("package").cloned().unwrap_or(Value::Null),
                "install_event_id": response.get("install_event_id").cloned().unwrap_or(Value::Null),
                "pin": response.get("pin").cloned().unwrap_or(Value::Null),
                "revision": response.get("revision").cloned().unwrap_or(Value::Null),
                "unchanged": true,
            });
            if let Some(field) = subscription_field {
                unchanged["subscription"] = field;
            }
            if let Some(code) = refused_code {
                unchanged["subscribe_refused"] = Value::String(code);
            }
            return Ok(unchanged);
        }
    }
    if let Some(field) = subscription_field {
        response["subscription"] = field;
    }
    if let Some(code) = refused_code {
        response["subscribe_refused"] = Value::String(code);
    }
    Ok(response)
}

/// Scheduler re-run (design `ee12faf` §2.3): a full `live_read` evaluation
/// under the viewer's *current* authority — the same pre-check, gates and
/// per-row View check as the tool call, with no subscribe/if_revision
/// shaping. Returns the result, its `revision_digest`, and the surface-gate
/// pin the emit gate re-checks. A refusal means `need-closed` (mapped by the
/// scheduler through the shared refusal table).
pub(crate) async fn rerun_snapshot_for_scheduler(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    sql_attempted: &mut bool,
    vm_work: Option<&VmWorkObserver>,
) -> Result<(Value, String, crate::need_subscriptions::GateSnapshot, bool)> {
    let (response, gate, clock_replay_safe) = evaluate_snapshot_live_read(
        db,
        caller,
        package.to_string(),
        expected_install_event_id.to_string(),
        Some(sql_attempted),
        vm_work,
    )
    .await?;
    let digest = response
        .get("revision")
        .and_then(|revision| revision.get("revision_digest"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok((response, digest, gate, clock_replay_safe))
}

/// Independent server-only replay at the exact hidden clock binds of the
/// baseline evaluation. No clock value comes from a viewer request.
pub(crate) async fn replay_snapshot_for_probe(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    clocks: &std::collections::BTreeMap<String, i64>,
) -> Result<(Value, String, crate::need_subscriptions::GateSnapshot)> {
    let (response, gate, clock_replay_safe) = evaluate_snapshot_live_read_with_clocks(
        db,
        caller,
        package.to_string(),
        expected_install_event_id.to_string(),
        None,
        None,
        Some(clocks),
    )
    .await?;
    if !clock_replay_safe {
        return Err(Error::engine(
            "live need clock replay has execution-clock relations",
        ));
    }
    let digest = response["revision"]["revision_digest"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    Ok((response, digest, gate))
}

/// Exact server-derived statement clocks for private replay. A malformed
/// snapshot is ineligible for sampling; this never changes its delivery.
pub(crate) fn snapshot_clock_bindings(
    result: &Value,
) -> Option<std::collections::BTreeMap<String, i64>> {
    if result["time_dependent"] != Value::Bool(true) {
        return None;
    }
    let sql = result["input"]["sql"].as_object()?;
    if sql.len() > SQL_SNAPSHOT_MAX_NEEDS {
        return None;
    }
    let mut clocks = std::collections::BTreeMap::new();
    for (key, need) in sql {
        match need["time_dependent"].as_bool()? {
            true => {
                clocks.insert(key.clone(), need["now_ms_ms"].as_i64()?);
            }
            false if !need["now_ms_ms"].is_null() => return None,
            false => {}
        }
    }
    (!clocks.is_empty()).then_some(clocks)
}

/// Both activity relations use the independent execution-owned
/// `_query_sql_principal.observed_at` clock for admission/inference. Holding
/// `now_ms()` binds alone cannot replay them faithfully. Use the same strict
/// SQLite authorizer dependency analyzer as governed SQL; names in comments,
/// literals, and same-named CTEs do not cause a false exclusion.
fn clock_probe_safe_sql_needs(needs: &[SqlNeed]) -> bool {
    needs
        .iter()
        .filter(|need| need.params.is_empty())
        .all(|need| {
            crate::query::sql::validated_relation_dependencies(&need.sql).is_ok_and(|relations| {
                !relations.contains("agent_activity")
                    && !relations.contains("agent_activity_claims")
            })
        })
}

/// Emit-gate re-check (design `ee12faf` §2.3): the surface-level gates
/// without the row reads — install CAS, install gates, declaration digest
/// and source gates. Compared against the re-run's pin; any drift closes
/// the subscription and the value is never emitted.
pub(crate) async fn snapshot_surface_gates(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
) -> Result<crate::need_subscriptions::GateSnapshot> {
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    // The read-only pool: the gate chain only reads, and every push re-run
    // passes through here, so it must not queue behind (or hold up) writers.
    let mut tx = db.pool().begin().await?;
    let LiveReadGate {
        row,
        source,
        runtime,
        bundle_sha256,
        ..
    } = live_read_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
    )
    .await?;
    tx.rollback().await?;
    Ok(crate::need_subscriptions::GateSnapshot {
        install_event_id: row.event_id,
        status: row.status,
        adoption: row.adoption,
        declaration_digest: row.declaration_digest,
        bundle_sha256,
        source_event_id: source.event_id,
        source_revision: row.consented_source_revision,
        runtime,
    })
}

/// Snapshot evaluation: the `attention.query.v1` read plus param-less SQL
/// needs, exactly as `live_read` always ran it. Called with the need already
/// resolved to the snapshot and `params` already refused; returns the full
/// read result (no `subscription`/`unchanged` shaping — the caller applies
/// it) plus the surface-gate pin for the M2 emit gate: the install and
/// source values this evaluation read, re-checked without row reads before
/// any `need` frame (design `ee12faf` §2.3).
async fn evaluate_snapshot_live_read(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    sql_attempted: Option<&mut bool>,
    vm_work: Option<&VmWorkObserver>,
) -> Result<(Value, crate::need_subscriptions::GateSnapshot, bool)> {
    evaluate_snapshot_live_read_with_clocks(
        db,
        caller,
        package,
        expected_install_event_id,
        sql_attempted,
        vm_work,
        None,
    )
    .await
}

async fn evaluate_snapshot_live_read_with_clocks(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    mut sql_attempted: Option<&mut bool>,
    vm_work: Option<&VmWorkObserver>,
    replay_clocks: Option<&std::collections::BTreeMap<String, i64>>,
) -> Result<(Value, crate::need_subscriptions::GateSnapshot, bool)> {
    let account_id = live_read_precheck(caller, &package, &expected_install_event_id)?;
    // Deferred governed-pool data transaction: gates, attention, and every
    // SQL need below share one snapshot. Ordinary write-pool SQL content
    // never contends here; the pool release hook still sanitizes the
    // connection when cancellation drops this future before rollback.
    let mut tx = db.governed_pool().begin().await?;
    let LiveReadGate {
        row,
        source,
        runtime,
        bundle_sha256,
        needs,
        verified,
    } = live_read_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        &package,
        &expected_install_event_id,
    )
    .await?;
    let sql_needs = verified.sql_needs()?;
    let has_attention = needs.iter().any(|need| need == ATTENTION_QUERY_NEED);
    if !has_attention && sql_needs.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [undeclared_need]"
        )));
    }
    // Pinned visible-first window for `attention.query.v1` v1 semantics
    // (see `ATTENTION_QUERY_SEMANTICS`). Visibility is joined BEFORE
    // ordering/limiting, so an unreadable-only write cannot push a visible
    // row out of the window and move `records`/`revision_digest`. The
    // view is installed on this gate transaction (same snapshot as the
    // gates) under a narrowly constructed principal matching the existing
    // `can_record_in` authority exactly — `Principal::bound(credential,
    // is_host_member)` or trusted-local bypass only under
    // `is_legacy_local` — never the hosted activity roster carried by
    // `From<&Caller>`. The per-row `can_record_in` below stays as a
    // fail-closed second check; a row the viewer may not see never leaves.
    let not_hidden = crate::query::not_hidden_predicate("r");
    let candidate_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.lifecycle, r.last_activity_at \
           FROM main.records r \
           JOIN temp._query_sql_visible_records AS visible ON visible.id = r.id \
          WHERE r.deleted_at IS NULL AND {not_hidden} \
            AND r.type='WorkItem' AND r.kind='task' \
            AND r.lifecycle IS NOT NULL \
            AND r.lifecycle NOT IN ('completed','closed') \
            AND NOT EXISTS (SELECT 1 FROM main.facet_values av \
                              WHERE av.record_id=r.id AND av.key='archived') \
          ORDER BY r.last_activity_at DESC, r.id ASC LIMIT ?"
    );
    // Snapshot SQL-only installs skip the attention scan: rows for an
    // undeclared need must never be computed, let alone returned.
    let candidates = if has_attention {
        let query_principal = if super::is_legacy_local(caller) {
            // SAFETY: same predicate as `super::principal`/`can_record_in`:
            // trusted-local with no hosting route. No roster is carried.
            unsafe { crate::query::QueryPrincipal::trusted_local_unchecked(caller.credential()) }
        } else {
            crate::query::QueryPrincipal::authenticated(
                caller.credential(),
                caller.is_host_member(),
            )
        };
        if let Some(attempted) = sql_attempted.as_mut() {
            **attempted = true;
        }
        crate::query::sql::install_visible_records_in(&mut tx, query_principal).await?;
        // The attention candidate SELECT has its own cost phase. TEMP view
        // setup and the per-row parity gate remain outside this count. The
        // write-pool release hook also removes the handler if cancellation
        // interrupts this await before the explicit cleanup below.
        if let Some(vm_work) = vm_work {
            let callbacks = vm_work.attention_counter();
            let mut handle = tx.lock_handle().await?;
            handle.set_progress_handler(crate::query::sql::PROGRESS_OPS, move || {
                callbacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                true
            });
        }
        let candidate_result = sqlx::query(&candidate_sql)
            .bind(ATTENTION_LIVE_LIMIT)
            .fetch_all(&mut *tx)
            .await;
        let cleanup_result: Result<()> = async {
            if vm_work.is_some() {
                let mut handle = tx.lock_handle().await?;
                handle.remove_progress_handler();
            }
            Ok(())
        }
        .await;
        let candidates = candidate_result?;
        cleanup_result?;
        candidates
    } else {
        Vec::new()
    };
    let mut records = Vec::new();
    for candidate in &candidates {
        if records.len() as i64 >= ATTENTION_LIVE_LIMIT {
            break;
        }
        let id: String = candidate.try_get("id")?;
        attention_parity_gate(super::can_record_in(&mut tx, caller, &id, Capability::View).await?)?;
        records.push(json!({
            "id": id,
            "type": candidate.try_get::<String, _>("type")?,
            "kind": candidate.try_get::<Option<String>, _>("kind")?,
            "name": candidate.try_get::<String, _>("name")?,
            "lifecycle": candidate.try_get::<Option<String>, _>("lifecycle")?,
            "last_activity_at": candidate.try_get::<Option<String>, _>("last_activity_at")?,
        }));
    }
    // Capture the install generation for the token before ending the
    // transaction; everything after this point is pure digest computation
    // over viewer-visible data.
    let pin = json!({
        "package": row.package,
        "version": row.version,
        "digest": row.digest,
        "artifact_id": row.artifact_id,
        "source_revision": row.consented_source_revision,
        "declaration_digest": row.declaration_digest,
        "install_event_id": row.event_id,
    });
    // Declared snapshot SQL needs run inside the same gate transaction,
    // through the caller-transaction engine under the viewer's authority.
    // The transaction stays open until every need below finishes. Any
    // failure refuses the whole snapshot (`sql_need_failed`): no partial
    // input ever leaves the host. Parameterised needs carry no values here,
    // so the snapshot skips them: they run on-request only.
    let mut sql_input = serde_json::Map::new();
    let mut sql_digest = serde_json::Map::new();
    // M1 slice 1: snapshot-level clock metadata. Each evaluated need keeps
    // its exact statement-fixed clock at `input.sql[key].now_ms_ms`; the
    // top-level `as_of_ms` is the maximum of those per-need clocks — an
    // upper bound no statement clock exceeds, not any one need's exact bind
    // value and not the snapshot's completion time. `None` when no evaluated
    // snapshot need uses `now_ms()`. `time_dependent` is true when any
    // evaluated snapshot need is.
    let mut snapshot_time_dependent = false;
    let mut snapshot_as_of_ms: Option<i64> = None;
    for need in &sql_needs {
        if !need.params.is_empty() {
            continue;
        }
        if let Some(attempted) = sql_attempted.as_mut() {
            **attempted = true;
        }
        let replay_clock = replay_clocks
            .and_then(|clocks| clocks.get(&need.key))
            .copied();
        let principal: crate::query::QueryPrincipal = caller.into();
        let result = execute_sql_need_in(
            &mut tx,
            principal,
            need,
            Vec::new(),
            vm_work.map(VmWorkObserver::declared_sql_counter),
            replay_clock,
        )
        .await?;
        if replay_clocks.is_some() && result.time_dependent != replay_clock.is_some() {
            return Err(Error::engine("live need clock replay metadata mismatch"));
        }
        if result.time_dependent {
            snapshot_time_dependent = true;
            snapshot_as_of_ms = match (snapshot_as_of_ms, result.now_ms_ms) {
                (Some(seen), Some(stamp)) => Some(seen.max(stamp)),
                (seen, stamp) => seen.or(stamp),
            };
        }
        sql_digest.insert(need.key.clone(), result.digest);
        sql_input.insert(need.key.clone(), result.input);
    }
    if let Some(clocks) = replay_clocks {
        let observed = sql_input
            .iter()
            .filter_map(|(key, value)| {
                value["time_dependent"]
                    .as_bool()
                    .filter(|v| *v)
                    .map(|_| key)
            })
            .count();
        if observed != clocks.len() {
            return Err(Error::engine("live need clock replay key mismatch"));
        }
    }
    // Read-only data transaction ends here, after every SQL read finished;
    // everything below is pure digest computation over viewer-visible data.
    tx.rollback().await?;
    let clock_replay_safe = clock_probe_safe_sql_needs(&sql_needs);
    // Viewer-scoped staleness token: canonical digest over the returned
    // rows plus the install pin/generation. Derived ONLY from data this
    // viewer may see — no global content-event id/seq, no authorization
    // epoch, no scan counters. It fences the delivered display fields
    // only; revocation is enforced by re-running the gate chain per
    // request, and unrelated writes (including inaccessible-task writes)
    // deliberately leave it unchanged. With snapshot SQL needs the token
    // additionally covers every SQL row `query_sql` returned (before the
    // snapshot cap) plus `truncated`, so it moves exactly when something
    // the viewer can see moves — including tail growth past the cap.
    let records_value = Value::Array(records);
    let rows_sha256 = crate::canonical_json::digest_json(&records_value);
    let revision_digest = if sql_digest.is_empty() {
        crate::canonical_json::digest_json(&json!({
            "rows": records_value,
            "pin": pin,
        }))
    } else {
        crate::canonical_json::digest_json(&json!({
            "rows": records_value,
            "sql": sql_digest,
            "pin": pin,
        }))
    };
    let mut live_input = json!({
        "version": "native.artifact-input.v1",
        "mode": "live",
        "sample_preview": false,
        "records": records_value,
        "records_sha256": rows_sha256,
        "inputs": {},
    });
    if !sql_input.is_empty() {
        live_input["sql"] = Value::Object(sql_input);
    }
    let input_digest = alpha_tab_sample_input_digest(&live_input);
    // Pin the surface gates this evaluation read, before the response moves
    // them: the scheduler re-checks exactly these without row reads.
    let gate = crate::need_subscriptions::GateSnapshot {
        install_event_id: row.event_id.clone(),
        status: row.status.clone(),
        adoption: row.adoption.clone(),
        declaration_digest: row.declaration_digest.clone(),
        bundle_sha256: bundle_sha256.clone(),
        source_event_id: source.event_id.clone(),
        source_revision: row.consented_source_revision.clone(),
        runtime: runtime.clone(),
    };
    Ok((
        json!({
            "package": package,
            "install_event_id": pin["install_event_id"],
            "pin": {
                "package": pin["package"],
                "version": pin["version"],
                "digest": pin["digest"],
                "artifact_id": pin["artifact_id"],
                "source_revision": pin["source_revision"],
                "declaration_digest": pin["declaration_digest"],
            },
            "source": {
                "event_id": source.event_id,
                "bundle_sha256": bundle_sha256,
                "runtime": runtime,
            },
            "need": ATTENTION_QUERY_NEED,
            "declared_port": alpha_tab_attention_port_mapping(),
            "input": live_input,
            "input_digest": input_digest,
            "rows_sha256": rows_sha256,
            // M1 slice 1: evaluation stamp and time dependence. Both ride
            // beside the digest, never inside it: `revision_digest` above
            // covers rows plus pin only, so a stamp-only change is a quiet
            // re-run and never a `need` frame on its own. `as_of_ms` is the
            // maximum of the evaluated needs' statement-fixed clocks (an
            // upper bound on those clocks, not a completion timestamp);
            // per-need exact clocks stay at `input.sql[key].now_ms_ms`.
            "as_of_ms": snapshot_as_of_ms,
            "time_dependent": snapshot_time_dependent,
            "revision": {
                "revision_digest": revision_digest,
                "rows_sha256": rows_sha256,
            },
            "window": {
                "bounded_window": true,
            },
            "live_reads": true,
            "effects_wired": false,
        }),
        gate,
        clock_replay_safe,
    ))
}

/// Dispatch note: the read calls the `search` / `get_record` handlers
/// directly, with the registry's record-reference expansion run first, rather
/// than re-entering the registry. Both are core read tools on the SQLite
/// engine this tool runs on. If the registry ever adds another pre-handler
/// step for them (admission, capture), route through it here too.
/// `canvas.scene.v1` calls the `read_canvas.get_scene` read through its
/// windowed wrapper, `canvas::read_scene_page`, for the same reason.
///
/// One on-request declared read for an adopted tab (task `1044bb6`, plus
/// parameterised `sql.snapshot.v1` needs by key). Same gate chain as the
/// attention snapshot; then the need must be in the consented declaration
/// (`undeclared_need`) and its parameters in bounds (`unknown_need`,
/// `invalid_params` for the host needs; `unknown_sql_param`,
/// `missing_sql_param`, `invalid_sql_param` for SQL keys). For a host need
/// the gate transaction ends before the read runs, because the read is an
/// ordinary tool handler that opens its own and enforces the viewer's
/// authority itself. A SQL need gates once, on the governed transaction its
/// statement then runs on. On-request SQL reads carry no revision fence:
/// they answer one request and are not a snapshot.
async fn do_declared_read(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    need: String,
    params: Option<Value>,
    options: LiveReadOptions,
) -> Result<Value> {
    // On-request reads keep their existing pull contract. The optional
    // host-only watch associates one Graph result with an existing snapshot
    // subscription; it creates no new subscription or package capability.
    if options.subscribe.is_some() || options.if_revision.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [invalid_params]"
        )));
    }
    let account_id = live_read_precheck(caller, &package, &expected_install_event_id)?;
    // A host need gates on the read-only pool: the gate chain only reads,
    // and each host read re-runs it on its own snapshot. Any other name may
    // be a SQL key, so it gates on a governed-pool data transaction, where
    // the gate, the declaration, the bound params and the data read share
    // one snapshot. The gate runs once either way.
    let host_read = HOST_READ_NEEDS.contains(&need.as_str());
    let mut tx = if host_read {
        db.pool().begin().await?
    } else {
        db.governed_pool().begin().await?
    };
    let LiveReadGate {
        row,
        source,
        runtime,
        bundle_sha256,
        needs,
        verified,
    } = live_read_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        &package,
        &expected_install_event_id,
    )
    .await?;
    // Parameterised SQL needs run on-request only, addressed by key: the
    // install-time key-collision refusal keeps this namespace disjoint from
    // the string needs below, so a key match is unambiguous.
    let sql_need = verified
        .sql_needs()?
        .into_iter()
        .find(|candidate| candidate.key == need);
    if let Some(sql_need) = sql_need {
        if host_read {
            // Install refuses a SQL key named like a host need
            // (`host_read_needs_are_never_sql_keys`), so this cannot happen.
            // Fail closed rather than run SQL on a read-only-pool transaction.
            return Err(Error::engine(format!(
                "{TOOL}: live read refused [undeclared_need]"
            )));
        }
        let mut data_tx = tx;
        let echo = params.clone().unwrap_or(json!({}));
        let bound = bind_sql_params(&sql_need, params.as_ref())
            .map_err(|code| Error::engine(format!("{TOOL}: live read refused [{code}]")))?;
        let principal: crate::query::QueryPrincipal = caller.into();
        let executed =
            execute_sql_need_in(&mut data_tx, principal, &sql_need, bound, None, None).await?;
        data_tx.rollback().await?;
        let keyed_revision = sql_keyed_revision(&row, &sql_need, &executed.digest);
        let mut response = declared_read_body(
            &package,
            &row,
            &source,
            &runtime,
            &bundle_sha256,
            &need,
            echo.clone(),
            executed.input,
        );
        if let Some(revision) = keyed_revision {
            response["revision"] = json!({"revision_digest": revision});
            if let Some(watch) = options.watch {
                let params_digest = crate::canonical_json::digest_json(&echo);
                let variant = crate::keyed_freshness::variant_handle(&sql_need.key, &params_digest);
                let admitted = match (
                    ConnectionToken::from_hex(watch.stream.trim()),
                    RealtimeHub::for_database(db),
                ) {
                    (Some(token), Some(hub)) => {
                        let database_id = crate::identity::database_id(db).await?;
                        hub.need_registry()
                            .lock()
                            .expect("need registry poisoned")
                            .admit_keyed_read(
                                &token,
                                &crate::need_subscriptions::SubscriptionId::from_wire(
                                    watch.subscription,
                                ),
                                caller.credential(),
                                &database_id,
                                &package,
                                &expected_install_event_id,
                                crate::keyed_freshness::KeyedFingerprint {
                                    key: sql_need.key.clone(),
                                    params_digest,
                                    params: echo,
                                    revision,
                                    relations: sql_need.relations.clone(),
                                },
                            )
                    }
                    _ => None,
                };
                if let Some(evicted) = admitted {
                    response["keyed_freshness"] = json!({
                        "variant": variant,
                        "evicted": if evicted { vec![sql_need.key.clone()] } else { vec![] }
                    });
                }
            }
        }
        return Ok(response);
    }
    tx.rollback().await?;
    if !needs.iter().any(|declared| declared == &need) {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [undeclared_need]"
        )));
    }
    // Push-only needs (task `fb8564c`): consented but never readable. The
    // exclusion sits after the full gate chain plus declaration membership
    // and before parameter parsing, so even a well-formed read — and any
    // malformed one — refuses `undeclared_need`. It never applies to the
    // `admit_reveal_target` action, which succeeds for a consented reveal.
    if PUSH_ONLY_NEEDS.iter().any(|only| *only == need) {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [undeclared_need]"
        )));
    }
    let read = parse_declared_read(&need, params.as_ref())
        .map_err(|code| Error::engine(format!("{TOOL}: live read refused [{code}]")))?;
    let (echo, result) = match read {
        DeclaredRead::Search { query, limit } => {
            let echo = json!({"query": query, "limit": limit});
            let result = search_read(
                db,
                caller,
                &package,
                &expected_install_event_id,
                &query,
                limit,
            )
            .await?;
            (echo, result)
        }
        DeclaredRead::ResolveReference { reference } => {
            let echo = json!({"reference": reference});
            let result = resolve_reference_read(
                db,
                caller,
                &package,
                &expected_install_event_id,
                &reference,
            )
            .await?;
            (echo, result)
        }
        DeclaredRead::CanvasScene {
            canvas_id,
            limit,
            cursor,
        } => {
            let echo = json!({"canvas_id": canvas_id, "limit": limit, "cursor": cursor});
            let result = canvas_scene_read(
                db,
                caller,
                &package,
                &expected_install_event_id,
                &canvas_id,
                limit,
                cursor.as_deref(),
            )
            .await?;
            (echo, result)
        }
        DeclaredRead::RecordChanges {
            record_id,
            limit,
            cursor,
        } => {
            let echo = json!({"record_id": record_id, "limit": limit, "cursor": cursor});
            let result = record_changes_read(
                db,
                caller,
                &package,
                &expected_install_event_id,
                &record_id,
                limit,
                cursor.as_deref(),
            )
            .await?;
            (echo, result)
        }
        DeclaredRead::ArtifactRender { artifact_id } => {
            let echo = json!({"artifact_id": artifact_id});
            let result = artifact_render_read(
                db,
                caller,
                &package,
                &expected_install_event_id,
                &artifact_id,
            )
            .await?;
            (echo, result)
        }
    };
    Ok(declared_read_body(
        &package,
        &row,
        &source,
        &runtime,
        &bundle_sha256,
        &need,
        echo,
        result,
    ))
}

/// The body of one on-request declared read, as a single `live_read`
/// answers it and as each successful item of a batched read carries it.
#[allow(clippy::too_many_arguments)]
fn declared_read_body(
    package: &str,
    row: &InstallRow,
    source: &LiveReadSource,
    runtime: &Option<String>,
    bundle_sha256: &str,
    need: &str,
    echo: Value,
    result: Value,
) -> Value {
    json!({
        "package": package,
        "install_event_id": row.event_id,
        "pin": {
            "package": row.package,
            "version": row.version,
            "digest": row.digest,
            "artifact_id": row.artifact_id,
            "source_revision": row.consented_source_revision,
            "declaration_digest": row.declaration_digest,
        },
        "source": {
            "event_id": source.event_id,
            "bundle_sha256": bundle_sha256,
            "runtime": runtime,
        },
        "need": need,
        "params": echo,
        "result": result,
        "live_reads": true,
        "effects_wired": false,
    })
}

/// The keyed revision of one SQL need's result, for keyed-read keys only.
/// The digest is over precisely this viewer's governed result and the
/// install pin. It contains no content sequence, table touch, or hidden
/// row. A later keyed hint must name this same digest so the host can
/// verify it against its own on-request re-read.
fn sql_keyed_revision(
    row: &InstallRow,
    sql_need: &SqlNeed,
    result_digest: &Value,
) -> Option<String> {
    crate::keyed_freshness::is_keyed_read_key(&sql_need.key).then(|| {
        crate::canonical_json::digest_json(&json!({
            "pin": {
                "package": row.package,
                "version": row.version,
                "digest": row.digest,
                "artifact_id": row.artifact_id,
                "source_revision": row.consented_source_revision,
                "declaration_digest": row.declaration_digest,
            },
            "result": result_digest,
        }))
    })
}

/// Re-evaluate one retained keyed variant through the identical gate chain
/// as the package's on-request read. The returned digest is the exact
/// `revision.revision_digest` the package's next re-read will carry.
pub(crate) async fn rerun_keyed_for_scheduler(
    db: &Db,
    caller: &Caller,
    package: &str,
    install_event_id: &str,
    key: &str,
    params: Value,
) -> Result<String> {
    let result = do_declared_read(
        db,
        caller,
        package.to_string(),
        install_event_id.to_string(),
        key.to_string(),
        Some(params),
        LiveReadOptions {
            subscribe: None,
            if_revision: None,
            watch: None,
        },
    )
    .await?;
    result["revision"]["revision_digest"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: keyed read has no revision [keyed_revision_missing]"
            ))
        })
}

/// `records.search.v1`: re-check the tab's consent and the viewer's access on
/// the read's own transaction, then run the ordinary search core through
/// that same snapshot — match, near misses, siblings, parent redaction,
/// paths and succession. The frame sees exactly what the viewer's own
/// search would show, for the installation that holds in the snapshot.
///
/// Public only so an integration test can call it without the outer gate
/// in front of it, and show that it refuses a stale or withdrawn install on
/// its own. Hosts reach it through `manage_alpha_tabs.live_read`.
#[doc(hidden)]
pub async fn search_read(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    query: &str,
    limit: i64,
) -> Result<Value> {
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    // A read-only-pool transaction: the gates and every result-controlling
    // read share one snapshot, and the read neither waits on nor holds a
    // writer's connection.
    let mut tx = db.pool().begin().await?;
    let _gate = declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        RECORDS_SEARCH_NEED,
    )
    .await?;
    let result = super::querying::search_in(&mut tx, caller, query, None, Some(limit), false).await;
    let cleanup = tx.rollback().await;
    match result {
        Ok(value) => {
            cleanup?;
            Ok(value)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

/// `records.resolve_reference.v1`: re-check the tab's consent and the viewer's access on
/// the read's own transaction, then resolve the reference and read display
/// fields from that same snapshot. Mirrors alpha's shell search: a found
/// record, the candidates of an ambiguous short reference, or nothing.
///
/// Public only so an integration test can call it without the outer gate
/// in front of it, and show that it refuses a stale or withdrawn install on
/// its own. Hosts reach it through `manage_alpha_tabs.live_read`.
#[doc(hidden)]
pub async fn resolve_reference_read(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    reference: &str,
) -> Result<Value> {
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    // A read-only-pool transaction: the gates and the reference share one
    // snapshot, and the read neither waits on nor holds a writer's
    // connection.
    let mut tx = db.pool().begin().await?;
    let _gate = declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        RECORDS_RESOLVE_REFERENCE_NEED,
    )
    .await?;
    let display = resolve_reference_in(&mut tx, caller, reference).await;
    tx.rollback().await?;
    display
}

/// The body of `records.resolve_reference.v1` on a transaction whose gate
/// has already passed.
async fn resolve_reference_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    reference: &str,
) -> Result<Value> {
    // The registry expands short references before any handler runs; the
    // in-snapshot resolver runs the same expansion first, over View-visible
    // candidates only. An ambiguous prefix is refused there.
    let arguments = {
        let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
        crate::mcp::record_ref::resolve_record_ids_in(
            &mut executor,
            caller,
            "get_record",
            json!({"ids": [reference], "children_limit": 0, "links_limit": 0}),
        )
        .await
    };
    let arguments = match arguments {
        Ok(arguments) => arguments,
        Err(error) => return ambiguous_display_or_unavailable(error),
    };
    let id = arguments
        .get("ids")
        .and_then(|ids| ids.get(0))
        .and_then(Value::as_str)
        .unwrap_or(reference)
        .to_string();
    // `get_record` answers a read the viewer may not make as `not_found`,
    // never as an error, so nothing about hidden records leaks. Display
    // fields only: no body, children, links, or annotation pass, and no
    // pooled read hides behind the gate.
    let display = if super::can_record_in(tx, caller, &id, Capability::View).await? {
        match record_display_in(tx, &id).await? {
            Some(record) => json!({"status": "found", "record": record}),
            None => json!({"status": "not_found"}),
        }
    } else {
        json!({"status": "not_found"})
    };
    Ok(display)
}

/// Display fields for one record id from the caller's snapshot, or `None`
/// when the row is absent. Authorization stays with the caller: only call
/// this after `can_record_in` has refused hidden rows as `not_found`.
async fn record_display_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
) -> Result<Option<Value>> {
    let row = sqlx::query("SELECT id, type, kind, name FROM records WHERE id=?")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(|row| {
        // `kind` is nullable: historical rows may carry NULL, and `get_record`
        // projects those as `kind: null`. A `String` read would error on a
        // record the viewer may plainly see.
        Ok(json!({
            "id": row.try_get::<String, _>("id")?,
            "type": row.try_get::<String, _>("type")?,
            "kind": row.try_get::<Option<String>, _>("kind")?,
            "name": row.try_get::<String, _>("name")?,
        }))
    })
    .transpose()
}

/// An ambiguous-prefix refusal carries its View-visible candidates; anything
/// else is a failed read, not an absent record, so the host answers
/// `unavailable` rather than claiming there is none.
fn ambiguous_display_or_unavailable(error: Error) -> Result<Value> {
    let message = error.to_string();
    let candidates = ambiguous_reference_candidates(&message);
    if message.contains("ambiguous") && candidates.len() > 1 {
        Ok(json!({"status": "ambiguous", "candidates": candidates}))
    } else {
        Err(error)
    }
}

/// Full record ids named in an ambiguous-reference refusal, in order,
/// without duplicates.
fn ambiguous_reference_candidates(message: &str) -> Vec<String> {
    let bytes = message.as_bytes();
    let mut out: Vec<String> = Vec::new();
    let mut index = 0;
    while index + 36 <= bytes.len() {
        let window = &bytes[index..index + 36];
        let shaped = window.iter().enumerate().all(|(at, byte)| match at {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
        if shaped {
            // Every byte is ASCII, so this cannot fail.
            let id = String::from_utf8_lossy(window).to_ascii_lowercase();
            if !out.contains(&id) {
                out.push(id);
            }
            index += 36;
        } else {
            index += 1;
        }
    }
    out
}

/// Exact persisted-id shape for a reveal target (task `fb8564c`, design
/// `e839b03` §2): `1..=128` bytes over `[A-Za-z0-9._:-]`. Shape alone admits
/// any well-formed string — including UUID prefixes and bare hex — and
/// rejects only what cannot be a persisted id. Prefixes are refused not by
/// this gate but by the exact-row existence plus `View` check below: a
/// prefix is never an exact row, so it lands in `not_visible` alongside
/// missing ids, with no resolver and no candidate enumeration.
fn valid_reveal_target_shape(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    id.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// `surface.reveal.v1`: admit one exact already-visible record id to a
/// consented installed surface (task `fb8564c`, design `e839b03` §4).
///
/// One deferred transaction: the unchanged full `live_read` gate chain plus
/// the consented-need check for `surface.reveal.v1` via the shared
/// `declared_need_gates_in` (membership-only, untouched), then the bounded
/// id shape, then exact-row existence plus the ordinary `can_record_in`
/// `View` check in the SAME snapshot; the transaction rolls back. Gate
/// precedes declaration precedes target parameters: stale/withdrawn/
/// disabled installs and undeclared needs refuse before any shape or
/// visibility verdict, and a malformed id refuses `invalid_params` before
/// any existence probe.
///
/// Hidden, missing and ineligible ids share one `not_visible` refusal that
/// echoes nothing — no name, body, ancestor or candidate. The receipt
/// carries only the minimal canonical target id plus the current
/// install/pin provenance in the existing `live_read` pin shape: no rows
/// and no global content sequence. (`pin.version` stays exactly the
/// install's existing opaque version string — part of the pin provenance
/// contract, not disclosed target content.) It grants no data or effect
/// authority beyond the receipt consent and the viewer's ordinary `View`.
///
/// Public only so an integration test can call it without the outer action
/// dispatch in front of it, and show that it refuses a stale or withdrawn
/// install on its own. Hosts reach it through
/// `manage_alpha_tabs.admit_reveal_target`.
#[doc(hidden)]
pub async fn admit_reveal_target(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    record_id: &str,
) -> Result<Value> {
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    // A deferred transaction, as `get_scene` opens: the gates, the shape
    // check input, the existence probe and the visibility check share one
    // snapshot, and no writer waits on a tab's admission.
    let mut tx = db.write_pool().begin().await?;
    let gate = declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        SURFACE_REVEAL_NEED,
    )
    .await?;
    if !valid_reveal_target_shape(record_id) {
        tx.rollback().await?;
        return Err(Error::engine(format!(
            "{TOOL}: reveal refused [invalid_params]"
        )));
    }
    // Exact persisted equality only: no prefix/reference resolver, no
    // UUID-only assumption — and the pre-handler resolver is exempted for
    // this action (`record_ref::admits_exact_target_ids_only`), so the value
    // arrives exactly as written. `can_record_in` reuses the record-read
    // visibility semantics (deleted/archived/ineligible fail closed), and
    // the row probe keeps absent ids indistinguishable from hidden ones.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await?;
    let visible = exists.is_some()
        && super::can_record_in(&mut tx, caller, record_id, Capability::View).await?;
    tx.rollback().await?;
    if !visible {
        return Err(Error::engine(format!(
            "{TOOL}: reveal refused [not_visible]"
        )));
    }
    Ok(json!({
        "package": package,
        "install_event_id": gate.row.event_id,
        "pin": {
            "package": gate.row.package,
            "version": gate.row.version,
            "digest": gate.row.digest,
            "artifact_id": gate.row.artifact_id,
            "source_revision": gate.row.consented_source_revision,
            "declaration_digest": gate.row.declaration_digest,
        },
        "target": { "record_id": record_id },
    }))
}

/// The argument checks that need no database, run before the transaction
/// opens (as they did before the gate chain was shared). Returns the
/// caller's account.
fn live_read_precheck(
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
) -> Result<String> {
    require_package(package)?;
    if expected_install_event_id.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: expected_install_event_id must not be blank"
        )));
    }
    require_account(caller)
}

/// What the shared `live_read` gate chain yields once every gate passed.
struct LiveReadGate {
    row: InstallRow,
    source: LiveReadSource,
    runtime: Option<String>,
    bundle_sha256: String,
    needs: Vec<String>,
    /// The verified immutable gate work for this pin, shared with the
    /// per-process cache (`gate_cache`).
    verified: Arc<gate_cache::VerifiedInstall>,
}

/// The resolved source as the gate reports it. The bytes are verified inside
/// the gate and never leave it.
struct LiveReadSource {
    event_id: String,
}

/// The plain-string needs of a consented declaration.
fn declared_need_names(declaration: &Value) -> Vec<String> {
    declaration
        .get("needs")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The `live_read` gate chain shared by every need: CAS on the install
/// event, install gates, source/digest gates and declaration digest. First
/// refusal wins; nothing is read for the frame until all pass.
///
/// The source and declaration checks are verified in full once per install
/// event and pin, then served from `gate_cache`; everything else runs on
/// `tx` every time.
async fn live_read_gates_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    account_id: &str,
    package: &str,
    expected_install_event_id: &str,
) -> Result<LiveReadGate> {
    let row = install_row_in(tx, account_id, package)
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: package {package} is not installed [missing_install]"
            ))
        })?;
    if row.event_id != expected_install_event_id {
        return Err(Error::engine(format!(
            "{TOOL}: installation changed [cas_mismatch]"
        )));
    }
    let target = target_state_in(tx, &row.artifact_id).await?;
    let can_view = target == TargetState::Resolvable
        && super::can_record_in(tx, caller, &row.artifact_id, Capability::View).await?;
    if let Err(reason) =
        evaluate_alpha_tab_install_gates(&row.status, &row.adoption, target, can_view)
    {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [{reason}]"
        )));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&row.artifact_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    if let Some(verified) = gate_cache::lookup(db.handle_id(), account_id, package, &row) {
        // The source bytes and the declaration were verified for exactly
        // this pin. Only the runtime and the source event's presence are
        // left to check, in the same order as below.
        let source_present = gate_cache::source_event_present_in(
            tx,
            &row.artifact_id,
            &row.consented_source_revision,
        )
        .await?;
        let digest_matches =
            source_present && verified.pin_digest_matches(runtime.as_deref(), &row.digest);
        if let Err(reason) = evaluate_alpha_tab_source_gates(
            runtime.as_deref() == Some("native.html.v1"),
            source_present,
            digest_matches,
        ) {
            return Err(Error::engine(format!(
                "{TOOL}: live read refused [{reason}]"
            )));
        }
        return Ok(LiveReadGate {
            source: LiveReadSource {
                event_id: row.consented_source_revision.clone(),
            },
            bundle_sha256: verified.bundle_sha256.clone(),
            needs: declared_need_names(&row.consented_declaration),
            row,
            runtime,
            verified,
        });
    }
    let source =
        resolve_alpha_tab_source_in(tx, &row.artifact_id, &row.consented_source_revision).await?;
    let declaration_digest = alpha_tab_declaration_digest(&row.consented_declaration)?;
    if declaration_digest != row.declaration_digest {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [declaration_mismatch]"
        )));
    }
    let digest_matches = match (&runtime, &source) {
        (Some(runtime), Some(source)) => {
            alpha_tab_digest(
                &alpha_tab_bundle_digest(&source.body),
                &declaration_digest,
                runtime,
            ) == row.digest
        }
        _ => false,
    };
    if let Err(reason) = evaluate_alpha_tab_source_gates(
        runtime.as_deref() == Some("native.html.v1"),
        source.is_some(),
        digest_matches,
    ) {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [{reason}]"
        )));
    }
    let source = source.expect("source gate passed");
    let bundle_sha256 = alpha_tab_bundle_digest(&source.body);
    let verified = Arc::new(gate_cache::VerifiedInstall::new(
        &row,
        bundle_sha256.clone(),
    ));
    gate_cache::remember(
        db.handle_id(),
        account_id,
        package,
        &row.event_id,
        Arc::clone(&verified),
    );
    let needs = declared_need_names(&row.consented_declaration);
    Ok(LiveReadGate {
        row,
        source: LiveReadSource {
            event_id: source.event_id,
        },
        runtime,
        bundle_sha256,
        needs,
        verified,
    })
}

/// The whole `live_read` gate chain plus the consented-need check, on a
/// transaction the caller goes on to read through.
///
/// An on-request read normally runs after the gate transaction has ended, so
/// between the two the install can be disabled, replaced or removed, or the
/// viewer can lose the artifact. The read's own View checks catch lost
/// access to what it reads, but not to the tab. A read that calls this on
/// its own transaction before reading answers only for the installation,
/// pin, artifact access and declaration that hold in the snapshot it reads
/// from. Search, reference resolution, canvas scene and record change
/// (`records.changes.v1`) reads use this gate before reading through the
/// same transaction.
async fn declared_need_gates_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    account_id: &str,
    package: &str,
    expected_install_event_id: &str,
    need: &str,
) -> Result<LiveReadGate> {
    let gate = live_read_gates_in(
        db,
        tx,
        caller,
        account_id,
        package,
        expected_install_event_id,
    )
    .await?;
    if !gate.needs.iter().any(|declared| declared == need) {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [undeclared_need]"
        )));
    }
    Ok(gate)
}

/// Process-wide key for the opaque revision tokens on tab reads. It is
/// random per process, as the interaction-token keys are: Native has no
/// persistent secret to derive it from (task `a5804e8`). A restart therefore
/// changes every token once, which a tab reads as "changed" and answers by
/// reading again. That costs a re-read and discloses nothing.
fn tab_revision_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        use rand::RngCore;
        let mut key = [0; 32];
        rand::rng().fill_bytes(&mut key);
        key
    })
}

/// One opaque `canvas.scene.v1` revision token. It is keyed by the process
/// key and bound to the install generation, the canvas and the subject (the
/// scene, one object's geometry or content, or one card's record), so equal
/// tokens mean an unchanged revision for this install. They cannot be
/// ordered, subtracted, compared across subjects or viewers, or inverted to
/// the sequence behind them.
fn seal_scene_revision(
    install_event_id: &str,
    canvas_id: &str,
    subject: &str,
    value: &str,
) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(tab_revision_key()).expect("HMAC accepts any key length");
    mac.update(
        json!([
            CANVAS_SCENE_NEED,
            install_event_id,
            canvas_id,
            subject,
            value
        ])
        .to_string()
        .as_bytes(),
    );
    let digest = mac.finalize().into_bytes();
    format!("t:{}", hex::encode(&digest[..16]))
}

/// `canvas.scene.v1`: re-check the tab's consent and the viewer's access on
/// the read's own transaction, then read one sealed page of the scene from
/// that same snapshot.
///
/// Public only so an integration test can call it without the outer gate
/// in front of it, and show that it refuses a stale or withdrawn install on
/// its own. Hosts reach it through `manage_alpha_tabs.live_read`.
#[doc(hidden)]
pub async fn canvas_scene_read(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    canvas_id: &str,
    limit: i64,
    cursor: Option<&str>,
) -> Result<Value> {
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    let invalid = || Error::engine(format!("{TOOL}: live read refused [invalid_params]"));
    if !(1..=CANVAS_SCENE_LIMIT_MAX).contains(&limit) {
        return Err(invalid());
    }
    let after = match cursor {
        None => None,
        Some(cursor) => Some(super::canvas::SceneCursor::decode(cursor).ok_or_else(invalid)?),
    };
    // A read-only-pool transaction: the gates and the scene are read from
    // one snapshot, and the read neither waits on nor holds a writer's
    // connection.
    let mut tx = db.pool().begin().await?;
    let gate = declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        CANVAS_SCENE_NEED,
    )
    .await?;
    let page =
        canvas_scene_in(&mut tx, caller, &gate.row.event_id, canvas_id, limit, after).await?;
    tx.rollback().await?;
    Ok(page)
}

/// The body of `canvas.scene.v1` on a transaction whose gate has already
/// passed for `install_event_id`, with the parameters already bounded.
async fn canvas_scene_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    install_event_id: &str,
    canvas_id: &str,
    limit: i64,
    after: Option<super::canvas::SceneCursor>,
) -> Result<Value> {
    let seal = |subject: &str, value: &str| {
        seal_scene_revision(install_event_id, canvas_id, subject, value)
    };
    super::canvas::tab_scene_page_in(
        tx,
        caller,
        canvas_id,
        after,
        limit as usize,
        CANVAS_SCENE_PAGE_MAX_CHARS,
        &seal,
    )
    .await
}

/// `records.changes.v1`: re-check the tab's consent and the viewer's access
/// on the read's own transaction, then read one page of the record's
/// changes from that same snapshot.
///
/// Refusals come in a fixed order, so none says more than the one before
/// it: parameters (shape only), then the tab's gates, then the viewer's
/// View on the record (with `get_history`'s own message), and only then the
/// cursor. A cursor that this install did not seal for this record is
/// refused as `invalid_params` whatever event it names, so a tab cannot
/// learn whether an event exists or belongs to a record, and without View
/// it learns nothing past "does not exist".
///
/// The page is [`super::history::tab_record_changes_in`] in an envelope
/// that fits the bridge. `complete` is false, with a `next_cursor`, when
/// older events may remain. No sequence reaches the tab.
///
/// Public only so an integration test can call it without the outer gate
/// in front of it, and show that it refuses a stale or withdrawn install on
/// its own. Hosts reach it through `manage_alpha_tabs.live_read`.
#[doc(hidden)]
pub async fn record_changes_read(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    record_id: &str,
    limit: i64,
    cursor: Option<&str>,
) -> Result<Value> {
    record_changes_read_with_budget(
        db,
        caller,
        package,
        expected_install_event_id,
        record_id,
        limit,
        cursor,
        super::history::TabChangeBudget::DEFAULT,
    )
    .await
}

/// [`record_changes_read`] with its work bounds set by the caller, so a test
/// can run a budget out on a small fixture. Hosts always get
/// [`super::history::TabChangeBudget::DEFAULT`].
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn record_changes_read_with_budget(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    record_id: &str,
    limit: i64,
    cursor: Option<&str>,
    budget: super::history::TabChangeBudget,
) -> Result<Value> {
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    let invalid = || Error::engine(format!("{TOOL}: live read refused [invalid_params]"));
    if !(1..=RECORD_CHANGES_LIMIT_MAX).contains(&limit)
        || cursor.is_some_and(|cursor| !RecordChangesCursor::well_formed(cursor))
    {
        return Err(invalid());
    }
    // A deferred transaction: the gates and the history are read from one
    // snapshot, and no writer waits on the read. It stays on the write pool,
    // unlike the other declared reads, because the walk arms a deadline
    // progress handler on the connection. The normal path removes it, but a
    // read cancelled mid-walk leaves it armed, and only the write pool's
    // release hook (`sanitize_released_write_connection`) clears it; on a
    // read-pool connection it would interrupt unrelated later reads.
    let mut tx = db.write_pool().begin().await?;
    let gate = declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        RECORD_CHANGES_NEED,
    )
    .await?;
    let install_event_id = gate.row.event_id.clone();
    let result = async {
        super::history::require_tab_history_record_in(&mut tx, caller, record_id).await?;
        let position = match cursor {
            None => None,
            Some(cursor) => {
                let event_id = RecordChangesCursor::open(cursor, &install_event_id, record_id)
                    .ok_or_else(invalid)?;
                Some(
                    super::history::record_event_position_in(&mut tx, record_id, &event_id)
                        .await?
                        .ok_or_else(invalid)?,
                )
            }
        };
        let page = super::history::tab_record_changes_in(
            &mut tx,
            caller,
            record_id,
            position,
            limit as usize,
            budget,
        )
        .await?;
        let seal =
            |event_id: &str| RecordChangesCursor::seal(&install_event_id, record_id, event_id);
        Ok::<_, Error>(record_changes_envelope(
            record_id,
            limit,
            page,
            RECORD_CHANGES_PAGE_MAX_CHARS,
            &seal,
        ))
    }
    .await;
    tx.rollback().await?;
    result
}

/// Shape one `records.changes.v1` page so that the whole of it, envelope
/// included, is at most `max_chars` long as the frame bridge measures it.
///
/// Events are taken newest first. One that does not fit what is left but
/// would fit a page of its own ends the page early, to lead the next one.
/// One that could never fit, the first included, becomes a bounded
/// `{event_id, type, created_at, oversized: true}` placeholder (or, should
/// even that not fit, `{oversized: true}`), as `canvas.scene.v1` does, so
/// paging always moves past it. `next_cursor` is sealed by `seal`.
fn record_changes_envelope(
    record_id: &str,
    limit: i64,
    page: super::history::TabRecordChangesPage,
    max_chars: usize,
    seal: &dyn Fn(&str) -> String,
) -> Value {
    let envelope = |events: Vec<Value>, next_cursor: Option<String>| {
        json!({
            "version": RECORD_CHANGES_NEED,
            "record_id": record_id,
            "order": "newest_first",
            "events": events,
            "limit": limit,
            "complete": next_cursor.is_none(),
            "next_cursor": next_cursor,
        })
    };
    // Charge the envelope first, with the longest cursor it could carry, so
    // the events get exactly what is left of the page.
    let longest_cursor = "f".repeat(RecordChangesCursor::MAX_CHARS);
    let empty = super::canvas::es_json_len(&envelope(Vec::new(), Some(longest_cursor)));
    let mut used = empty;
    let mut kept: Vec<Value> = Vec::with_capacity(page.events.len());
    let mut consumed: Option<String> = None;
    let mut cut = false;
    for (event_id, event) in page.events {
        // One more event costs its own length and a separating comma.
        let chars = super::canvas::es_json_len(&event) + 1;
        if used + chars <= max_chars {
            used += chars;
            kept.push(event);
        } else if empty + chars <= max_chars {
            cut = true;
            break;
        } else {
            let placeholder = json!({
                "event_id": event["event_id"],
                "type": event["type"],
                "created_at": event["created_at"],
                "oversized": true,
            });
            let placeholder_chars = super::canvas::es_json_len(&placeholder) + 1;
            if used + placeholder_chars <= max_chars {
                used += placeholder_chars;
                kept.push(placeholder);
            } else if kept.is_empty() {
                used += super::canvas::es_json_len(&json!({"oversized": true})) + 1;
                kept.push(json!({"oversized": true}));
            } else {
                cut = true;
                break;
            }
        }
        consumed = Some(event_id);
    }
    let resume_after = if cut { consumed } else { page.resume_after };
    envelope(kept, resume_after.map(|event_id| seal(&event_id)))
}

/// `artifact.render.v1`: the server-rendered safe tree of one MDX artifact,
/// rendered as the viewer.
///
/// Every outcome but a rendered tree is an ordinary `live read refused
/// [code]`, which the host relays to the frame as a refused read, and no
/// error from the render or its snapshots ever reaches the frame raw. In
/// order, so no refusal says more than the one before it: the tab's gates
/// and consent, then the viewer's View on the record (`not_found`, the same
/// answer for a record that does not exist), then its shape
/// (`not_mdx_artifact` for anything but a live `Document kind:artifact`
/// whose runtime is exactly `native.mdx.v1` or `native.mdx.v2`). Those
/// checks share one read-only snapshot with the gates. After the render the
/// gates run again and win over everything below them; then a render that
/// did not produce an MDX safe tree, for whatever reason, settles through
/// [`artifact_render_failure_code`] (`not_found` if the viewer can no
/// longer see the artifact, `render_failed` otherwise), and one too large
/// for the bridge refuses `too_large`.
///
/// The render itself is the ordinary live `render_artifact` under the
/// viewer's `Caller`. It opens its own transactions and re-checks View on
/// the artifact, every module subject and every bound Collection, and the
/// artifact's own input bindings and exact-source grants apply exactly as
/// they do in the workbench; the tab adds no authority and gains none. The
/// answer is projected by [`artifact_render_envelope`].
///
/// Public only so an integration test can call it without the outer gate
/// in front of it, and show that it refuses a stale or withdrawn install on
/// its own. Hosts reach it through `manage_alpha_tabs.live_read`.
#[doc(hidden)]
pub async fn artifact_render_read(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    artifact_id: &str,
) -> Result<Value> {
    artifact_render_read_with(
        db,
        caller,
        package,
        expected_install_event_id,
        artifact_id,
        || async {},
    )
    .await
}

/// [`artifact_render_read`] with `between` run after admission and before
/// the render, so a test can change the world in exactly that window.
/// Hosts always run nothing there.
#[doc(hidden)]
pub async fn artifact_render_read_with<F, Fut>(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_install_event_id: &str,
    artifact_id: &str,
    between: F,
) -> Result<Value>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let refused = |code: &str| Error::engine(format!("{TOOL}: live read refused [{code}]"));
    let account_id = live_read_precheck(caller, package, expected_install_event_id)?;
    let mut tx = db.pool().begin().await?;
    declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        ARTIFACT_RENDER_NEED,
    )
    .await?;
    let admitted = async {
        if !super::can_record_in(&mut tx, caller, artifact_id, Capability::View).await? {
            return Ok::<_, Error>(Err("not_found"));
        }
        // The snapshot runtime is only the pre-flight gate; the answer's
        // runtime comes from the render itself.
        Ok(super::artifacts::live_mdx_runtime_in(&mut tx, artifact_id)
            .await?
            .map(|_| ())
            .ok_or("not_mdx_artifact"))
    }
    .await;
    let cleanup = tx.rollback().await;
    // A snapshot that could not answer is a failed render, never a raw error.
    match (admitted, cleanup) {
        (Ok(admitted), Ok(())) => admitted.map_err(refused)?,
        _ => return Err(refused("render_failed")),
    }
    between().await;
    let rendered = super::artifacts::render_live_as_viewer(db, caller, artifact_id).await;
    let mut tx = db.pool().begin().await?;
    let regated = declared_need_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        package,
        expected_install_event_id,
        ARTIFACT_RENDER_NEED,
    )
    .await;
    let cleanup = tx.rollback().await;
    regated?;
    if cleanup.is_err() {
        return Err(refused("render_failed"));
    }
    match settle_artifact_render(artifact_id, rendered, ARTIFACT_RENDER_RESULT_MAX_CHARS) {
        Ok(answer) => Ok(answer),
        Err("render_failed") => Err(refused(
            artifact_render_failure_code(db, caller, artifact_id).await,
        )),
        Err(code) => Err(refused(code)),
    }
}

/// Settle one render outcome without looking at its error: any `Err` from
/// `render_artifact`, whatever it says, is `render_failed`, as is any
/// answer [`artifact_render_envelope`] does not accept.
fn settle_artifact_render(
    artifact_id: &str,
    rendered: Result<Value>,
    max_chars: usize,
) -> std::result::Result<Value, &'static str> {
    let rendered = rendered.map_err(|_| "render_failed")?;
    artifact_render_envelope(artifact_id, &rendered, max_chars)
}

/// The code for a render that failed: `not_found` when the viewer cannot
/// see the artifact in a fresh snapshot (revoked or deleted while it
/// rendered, the same answer for both), `render_failed` otherwise,
/// including when the check itself cannot run. Decided from authority,
/// never from the render's error text.
async fn artifact_render_failure_code(db: &Db, caller: &Caller, artifact_id: &str) -> &'static str {
    let visible = async {
        let mut tx = db.pool().begin().await?;
        let visible = super::can_record_in(&mut tx, caller, artifact_id, Capability::View).await;
        let cleanup = tx.rollback().await;
        let visible = visible?;
        cleanup?;
        Ok::<_, Error>(visible)
    }
    .await;
    match visible {
        Ok(false) => "not_found",
        _ => "render_failed",
    }
}

/// The provenance fields an `artifact.render.v1` answer keeps: enough to
/// say which source and content boundary the tree came from and to compare
/// two renders, and nothing that identifies the viewer (`caller_sha256` and
/// the revalidation token carry the viewer's principal fingerprint) or
/// describes the input envelope.
const ARTIFACT_RENDER_PROVENANCE_FIELDS: [&str; 7] = [
    "record_id",
    "source_event_id",
    "event_seq",
    "snapshot_event_id",
    "snapshot_event_seq",
    "body_sha256",
    "render_sha256",
];

/// Project one live `render_artifact` answer into the display-only
/// `artifact.render.v1` shape, at most `max_chars` long as the bridge
/// measures it, or name the refusal.
///
/// A rendered safe tree keeps `tree`, the stylesheet's `digest` and `flags`
/// (its `href` is an authenticated host URL the frame cannot use), and the
/// provenance fields above. Interaction declarations, `observed` CAS
/// tokens, `interaction_availability`, the input envelope, cache state,
/// timing and write diagnostics are withheld: the frame displays the tree
/// and has no way to act on it. `runtime.id` is the render's own, and must
/// be `native.mdx.v1` or `native.mdx.v2`. Any other answer, a diagnostic
/// included, is `render_failed`; none of the diagnostic crosses. An answer that would
/// not fit is `too_large`, never cut.
fn artifact_render_envelope(
    artifact_id: &str,
    rendered: &Value,
    max_chars: usize,
) -> std::result::Result<Value, &'static str> {
    let plan = &rendered["plan"];
    if rendered["status"] != "rendered"
        || rendered.get("unchanged").is_some()
        || plan["kind"] != "safe_tree"
        || !plan["tree"].is_object()
    {
        return Err("render_failed");
    }
    let runtime = match rendered["runtime"]["id"].as_str() {
        Some(runtime @ ("native.mdx.v1" | "native.mdx.v2")) => runtime,
        _ => return Err("render_failed"),
    };
    let mut projected = serde_json::Map::new();
    projected.insert("kind".into(), json!("safe_tree"));
    projected.insert("version".into(), plan["version"].clone());
    projected.insert("tree".into(), plan["tree"].clone());
    if let Some(styles) = plan.get("styles").filter(|styles| styles.is_object()) {
        projected.insert(
            "styles".into(),
            json!({"digest": styles["digest"], "flags": styles["flags"]}),
        );
    }
    let provenance: serde_json::Map<String, Value> = ARTIFACT_RENDER_PROVENANCE_FIELDS
        .iter()
        .filter_map(|field| {
            plan["provenance"]
                .get(*field)
                .filter(|value| !value.is_null())
                .map(|value| ((*field).to_string(), value.clone()))
        })
        .collect();
    projected.insert("provenance".into(), Value::Object(provenance));
    let answer = json!({
        "version": ARTIFACT_RENDER_NEED,
        "status": "rendered",
        "artifact_id": artifact_id,
        "runtime": {"id": runtime},
        "plan": projected,
    });
    if super::canvas::es_json_len(&answer) > max_chars {
        return Err("too_large");
    }
    Ok(answer)
}

/// Sample-only preview of one exact artifact/package pin (task `26ba75a`
/// preview-producer slice).
///
/// What it does, in order:
/// 0. Hosted preview authority: the caller must carry a
///    `VerifiedAlphaTabPreview` attestation matching the requested pin
///    field-for-field. Only the hosted plain-JSON adapter mints it, after
///    cookie-session plus trusted-Origin checks; the MCP router, Bearer
///    callers, and tool arguments have no representation for it, so the
///    preview response (receipt id/nonce plus sample launch) can never
///    reach an agent. The observed [`Channel`] is deliberately not
///    consulted — Bearer HTTP calls are `Channel::Web` too.
/// 1. Viewer authority: the caller must hold View on the artifact. This is
///    the only governed read — the artifact's live named-input bindings,
///    collections, and interaction/interaction-availability paths are never
///    touched, so no live record content can reach the frame.
/// 2. Pin verification: the exact `(artifact_id, source_revision)` content
///    event must resolve to body-carrying bytes (§2 portable identity);
///    the runtime facet must be present; the canonical
///    `alpha-tab-digest.v1` recomputed over the resolved bytes plus the
///    canonical declaration and runtime must equal the caller-supplied
///    `digest`. Any mismatch fails closed with a named reason and mints no
///    receipt.
/// 3. HTML validation: the resolved bytes must validate as `native.html.v1`
///    (the opaque-sandbox runtime). Broken packages fail closed.
/// 4. Sample-only launch: the pinned bytes are issued through the existing
///    opaque launch-ticket path (`sandbox="allow-scripts"`, no credential,
///    no network via `connect-src 'none'`) and paired with the static
///    host-owned sample input — never live bindings.
/// 5. Server-held receipt: a short-lived single-use receipt bound to the
///    exact account plus the full pin and a fresh sample-preview session is
///    minted, held server-side (process-local; see `preview_receipt_store`),
///    and returned alongside the launch. Step 0 is what keeps it out of
///    agents' hands: without hosted preview authority the tool refuses
///    before any verification work, on every transport including MCP.
///    No install state changes, no control event, no verified adoption,
///    no executable tab: `resolves` semantics are untouched.
#[allow(clippy::too_many_arguments)]
async fn do_preview(
    db: &Db,
    caller: &Caller,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration: Value,
    reason: String,
) -> Result<Value> {
    require_package(&package)?;
    require_version(&version)?;
    require_digest(&digest)?;
    let (needs, effects) = require_declaration(&declaration).map(|parsed| {
        let mut needs = parsed.needs;
        let mut effects = parsed.effects;
        needs.sort();
        effects.sort();
        (needs, effects)
    })?;
    require_reason(TOOL, &reason)?;
    if artifact_id.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: artifact_id must not be blank"
        )));
    }
    if source_revision.trim().is_empty() || source_revision.len() > 256 {
        return Err(Error::engine(format!(
            "{TOOL}: source_revision must be 1..256 characters"
        )));
    }
    let account_id = require_account(caller)?;
    // Hosted preview authority first: no attestation, no preview response —
    // on any transport, including MCP and Bearer HTTP. The attestation must
    // match the requested pin field-for-field (account plus the full pin the
    // canonical digest was recomputed over), so one preview's authority can
    // never authorize a different pin.
    let authority = caller.verified_alpha_tab_preview().ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: preview requires hosted cookie-session preview authority [preview_authority_missing]"
        ))
    })?;
    let declaration_digest = alpha_tab_declaration_digest(&declaration)?;
    if authority.account_id != account_id
        || authority.package != package
        || authority.version != version
        || authority.digest != digest
        || authority.artifact_id != artifact_id
        || authority.source_revision != source_revision
        || authority.declaration_digest != declaration_digest
        || authority.needs != needs
        || authority.effects != effects
    {
        return Err(Error::engine(format!(
            "{TOOL}: preview authority does not match the requested pin [preview_pin_mismatch]"
        )));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    // Viewer authority on the exact pin target — the single governed read.
    // Target liveness is checked first so missing/archived/wrong-type pins
    // name themselves; View loss names `unauthorized`.
    match target_state_in(&mut tx, &artifact_id).await? {
        TargetState::Resolvable => {}
        other => {
            let _ = tx.rollback().await;
            return Err(Error::engine(format!(
                "{TOOL}: preview target {} is {}",
                artifact_id,
                target_state_name(other)
            )));
        }
    }
    super::require_record_in(&mut tx, caller, TOOL, &artifact_id, Capability::View)
        .await
        .map_err(|_| {
            Error::engine(format!(
                "{TOOL}: preview target {artifact_id} is unauthorized"
            ))
        })?;
    // Exact source-revision resolution: the body-carrying content event id.
    let source = match resolve_alpha_tab_source_in(&mut tx, &artifact_id, &source_revision).await? {
        Some(source) => source,
        None => {
            let _ = tx.rollback().await;
            return Err(Error::engine(format!(
                "{TOOL}: preview source_revision is unresolved [source_revision_unresolved]"
            )));
        }
    };
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&artifact_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    let Some(runtime) = runtime.filter(|runtime| !runtime.trim().is_empty()) else {
        let _ = tx.rollback().await;
        return Err(Error::engine(format!(
            "{TOOL}: preview target is not renderable [not_renderable]"
        )));
    };
    // Canonical pin recomputation over the resolved bytes (never the
    // caller-asserted digest on trust). A declaration the canonical form
    // refuses mismatches the pin explicitly rather than comparing against a
    // default that is only safe because `""` is never a real digest.
    let Ok(declaration_digest) = alpha_tab_declaration_digest(&declaration) else {
        let _ = tx.rollback().await;
        return Err(Error::engine(format!(
            "{TOOL}: preview pin does not match the resolved source [digest_mismatch]"
        )));
    };
    let recomputed = alpha_tab_digest(
        &alpha_tab_bundle_digest(&source.body),
        &declaration_digest,
        &runtime,
    );
    if recomputed != digest {
        let _ = tx.rollback().await;
        return Err(Error::engine(format!(
            "{TOOL}: preview pin does not match the resolved source [digest_mismatch]"
        )));
    }
    let manifest = match crate::artifact_html::validate_cached(&source.body) {
        Ok(manifest) => manifest,
        Err(failure) => {
            let _ = tx.rollback().await;
            return Err(Error::engine(format!(
                "{TOOL}: preview body is not valid HTML [{}]",
                failure.code
            )));
        }
    };
    let last_update_event_id = last_alpha_update_in(&mut tx, &account_id, &package).await?;
    let _ = tx.rollback().await;
    // Sample-only input: host-owned static fixture, no live reads. This is
    // constructed after the rollback on purpose — it touches no database
    // state at all.
    let sample_input = alpha_tab_sample_input();
    let sample_input_digest = alpha_tab_sample_input_digest(&sample_input);
    let principal = caller.hosting_principal().unwrap_or(account_id.as_str());
    let launch = crate::artifact_html::issue_launch(
        &source.body,
        &manifest,
        principal,
        caller.hosting_database(),
        &artifact_id,
    )
    .map_err(|failure| {
        Error::engine(format!("{TOOL}: preview launch failed [{}]", failure.code))
    })?;
    let now_secs = chrono::Utc::now().timestamp();
    let receipt = issue_alpha_tab_preview_receipt(
        &account_id,
        &package,
        &version,
        &digest,
        &artifact_id,
        &source_revision,
        &declaration_digest,
        needs,
        effects,
        last_update_event_id,
        now_secs,
    );
    let act_alloc = ActAllocation::new();
    echo_act(
        json!({
            "package": package,
            "preview": {
                "artifact_id": artifact_id,
                "source_revision": source_revision,
                "source_event_id": source.event_id,
                "bundle_sha256": alpha_tab_bundle_digest(&source.body),
                "declaration_digest": declaration_digest,
                "digest": digest,
                "digest_version": ALPHA_TAB_DIGEST_VERSION,
                "runtime": runtime,
                "body_digest": manifest.body_digest,
                "sample_input": sample_input,
                "sample_input_digest": sample_input_digest,
                "sandbox": {
                    "sandbox": "allow-scripts",
                    "referrerPolicy": "no-referrer",
                    "allow": "",
                    "bridge_version": crate::artifact_html::BRIDGE_VERSION
                },
                "launch": {
                    "url": launch.url,
                    "expires_in_ms": launch.expires_in_ms,
                    "bridge_version": crate::artifact_html::BRIDGE_VERSION
                },
                "live_reads": false,
                "effects_wired": false
            },
            "receipt": {
                "receipt_id": receipt.receipt_id,
                "nonce": receipt.nonce,
                "preview_session": receipt.preview_session,
                "account_id": receipt.account_id,
                "expires_at_secs": receipt.expires_at_secs,
                "ttl_secs": ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS
            }
        }),
        act_alloc.get(),
    )
}

/// Same-key retry lookup for `adopt`: the control row plus the typed
/// adopt payload, so a retried confirm converges on its first durable
/// event while a reused key for different intent fails visibly.
async fn prior_alpha_adopt_event(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    key: &str,
) -> Result<Option<(String, String, String, String, AlphaTabAdoptPayload)>> {
    let row = sqlx::query(
        "SELECT type,aggregate_id,actor,reason,payload FROM control_events WHERE idempotency_key=?",
    )
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let raw: String = row.try_get("payload")?;
        Ok((
            row.try_get("type")?,
            row.try_get("aggregate_id")?,
            row.try_get("actor")?,
            row.try_get("reason")?,
            serde_json::from_str(&raw)?,
        ))
    })
    .transpose()
}

/// Adopt-confirm for one installed tab (task `26ba75a` adopt-confirm
/// slice): flips a `caller_asserted` install to verified adoption on the
/// strength of a live server-held preview receipt, nothing else.
///
/// In order:
/// 0. Hosted adopt authority: the caller must carry a
///    `VerifiedAlphaTabPreview` attestation on the adopt field matching the
///    requested pin field-for-field. Only the hosted plain-JSON adapter
///    mints it, after cookie-session plus trusted-Origin checks; the MCP
///    router, Bearer callers, and tool arguments have no representation
///    for it, so direct registry/MCP calls refuse with
///    `adopt_authority_missing` before any verification work, and a
///    cross-pin or cross-account attestation refuses with
///    `adopt_pin_mismatch`.
/// 1. Install row plus CAS: the package must be installed and
///    `expected_install_event_id` must name its current event, or the
///    confirm refuses without touching the receipt.
/// 2. Receipt verification plus single-use consume: the pure
///    `verify_alpha_tab_adopt_confirm` matrix (unknown / expired /
///    consumed-replay / account mismatch / pin mismatch / reason shape /
///    CAS) runs under the receipt-store lock, and a passing receipt is
///    marked consumed before any await — so a concurrent double-confirm
///    sees `receipt_consumed` rather than racing the commit.
/// 3. Control append plus projection: the `alpha_tab.adopted` event pins
///    the exact account, full pin, verified adoption, CAS token, and
///    receipt id; the projector flips adoption only when the stored row's
///    pin still matches field-for-field (`require_one`).
///
/// Crash order (honest limitation): the receipt is consumed before the
/// database commits, so a crash or commit failure between the two leaves
/// the receipt spent with no adoption — the user re-previews. The
/// process-local receipt store is the same server-held pattern as the
/// HTML launch-ticket store: preview and confirm must meet on the same
/// process, and a confirm presented elsewhere fails closed with
/// `receipt_unknown`. Multi-replica shared receipt state is a named
/// follow-up, not claimed here.
///
/// `resolves` semantics are untouched: a verified install's launch verdict
/// proceeds past adoption to the authority, digest, and terminal ticket
/// gates; inspect/list still refuse `launch_request_required` after them.
#[allow(clippy::too_many_arguments)]
async fn do_adopt(
    db: &Db,
    caller: &Caller,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration: Value,
    receipt_id: String,
    nonce: String,
    preview_session: String,
    expected_install_event_id: String,
    reason: String,
    idempotency_key: Option<String>,
) -> Result<Value> {
    require_package(&package)?;
    require_version(&version)?;
    require_digest(&digest)?;
    let (needs, effects) = require_declaration(&declaration).map(|parsed| {
        let mut needs = parsed.needs;
        let mut effects = parsed.effects;
        needs.sort();
        effects.sort();
        (needs, effects)
    })?;
    require_reason(TOOL, &reason)?;
    if artifact_id.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: artifact_id must not be blank"
        )));
    }
    if source_revision.trim().is_empty() || source_revision.len() > 256 {
        return Err(Error::engine(format!(
            "{TOOL}: source_revision must be 1..256 characters"
        )));
    }
    for (label, value) in [
        ("receipt_id", receipt_id.as_str()),
        ("nonce", nonce.as_str()),
        ("preview_session", preview_session.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(Error::engine(format!("{TOOL}: {label} must not be blank")));
        }
    }
    let account_id = require_account(caller)?;
    // Hosted adopt authority first: no attestation, no confirm — on any
    // transport, including MCP and Bearer HTTP. The attestation must match
    // the requested pin field-for-field, so one adopt's authority can never
    // authorize a different pin, and no caller-supplied token or field can
    // self-assert consent.
    let authority = caller.verified_alpha_tab_adopt().ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: adopt requires hosted cookie-session adopt authority [adopt_authority_missing]"
        ))
    })?;
    let declaration_digest = alpha_tab_declaration_digest(&declaration)?;
    if authority.account_id != account_id
        || authority.package != package
        || authority.version != version
        || authority.digest != digest
        || authority.artifact_id != artifact_id
        || authority.source_revision != source_revision
        || authority.declaration_digest != declaration_digest
        || authority.needs != needs
        || authority.effects != effects
    {
        return Err(Error::engine(format!(
            "{TOOL}: adopt authority does not match the requested pin [adopt_pin_mismatch]"
        )));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = ActAllocation::new();
    let key = idempotency_key
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| {
            format!("alpha-tab-adopted:{account_id}:{package}:{expected_install_event_id}")
        });
    let aggregate_id = alpha_tab_aggregate_id(&account_id, &package);
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: package {package} is not installed")))?;
    let payload = AlphaTabAdoptPayload {
        account_id: account_id.clone(),
        package: package.clone(),
        version: version.clone(),
        digest: digest.clone(),
        artifact_id: artifact_id.clone(),
        consented_source_revision: source_revision.clone(),
        declaration_digest: declaration_digest.clone(),
        consented_declaration: declaration.clone(),
        adoption: ALPHA_TAB_ADOPTION_VERIFIED.into(),
        previous_event_id: expected_install_event_id.clone(),
        receipt_id: Some(receipt_id.clone()),
        preview_session: Some(preview_session.clone()),
        launch_id: None,
        authored_run_key: None,
        request: None,
    };
    // Same-key retry converges on the first durable event without touching
    // the receipt: the re-appended identical payload dedups in the control
    // tier, so a retried adopt after success reports `changed: false`
    // instead of spending a second receipt.
    if let Some((kind, aggregate, actor, prior_reason, prior)) =
        prior_alpha_adopt_event(&mut tx, &key).await?
    {
        if kind != "alpha_tab.adopted"
            || aggregate != aggregate_id
            || actor != caller.actor()
            || prior_reason != reason
            || prior != payload
        {
            return Err(Error::engine(format!(
                "{TOOL}: idempotency_key was reused for different intent"
            )));
        }
        append_alpha_event(
            &mut tx,
            caller,
            key,
            aggregate_id,
            reason,
            ControlEventPayload::AlphaTabAdopted(payload),
            &mut act_alloc,
        )
        .await?;
        let row = install_row_in(&mut tx, &account_id, &package)
            .await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: adopt did not fold")))?;
        let entry = entry_in(&mut tx, caller, &row).await?;
        db.commit_control(tx).await?;
        return echo_act(
            json!({"package": package, "changed": false, "idempotent_retry": true, "install": entry}),
            act_alloc.get(),
        );
    }
    // CAS before receipt: a stale generation refuses without consuming the
    // receipt, so the caller can re-read the current event and retry with
    // the same live receipt.
    if row.event_id != expected_install_event_id {
        return Err(Error::engine(format!(
            "{TOOL}: installation changed; expected current event {expected_install_event_id} but found {}",
            row.event_id
        )));
    }
    if row.status != "installed" {
        return Err(Error::engine(format!(
            "{TOOL}: package {package} with status {} cannot adopt; restore it first",
            row.status
        )));
    }
    // Install-pin binding: the receipt authorizes exactly the previewed
    // pin, so the stored install must still carry that pin field-for-field
    // (the digest covers the canonical needs/effects). An upgrade or a
    // revision drift needs a fresh install plus a fresh preview, never an
    // adopt across pins. Refused before the receipt is consumed, so the
    // caller keeps its live receipt for the corrected retry.
    if row.version != version
        || row.digest != digest
        || row.artifact_id != artifact_id
        || row.consented_source_revision != source_revision
        || row.declaration_digest != declaration_digest
    {
        return Err(Error::engine(format!(
            "{TOOL}: adopt pin does not match the installed pin [install_pin_mismatch]"
        )));
    }
    let last_update_event_id = last_alpha_update_in(&mut tx, &account_id, &package).await?;
    // Receipt verification plus single-use consume under one store lock
    // with no await inside: a passing receipt is spent before the control
    // append, so a concurrent double-confirm fails closed with
    // `receipt_consumed`. Authority here is already proven by the hosted
    // attestation above, so the pure check runs with the boundary flags
    // that attestation stands for (cookie, Origin present).
    {
        let mut store = preview_receipt_store()
            .lock()
            .expect("preview receipt store poisoned");
        let owned = store.get(&receipt_id).cloned();
        if owned
            .as_ref()
            .and_then(|(_, _, b)| b.as_ref())
            .is_some_and(|b| !b.publication.is_published())
        {
            return Err(Error::engine("preview receipt publication unavailable"));
        }
        let (stored, consumed) = match &owned {
            Some((receipt, consumed, _)) => (Some(receipt), *consumed),
            None => (None, false),
        };
        let confirm = AlphaTabAdoptConfirm {
            receipt_id: receipt_id.clone(),
            nonce: nonce.clone(),
            account_id: account_id.clone(),
            package: package.clone(),
            version: version.clone(),
            digest: digest.clone(),
            artifact_id: artifact_id.clone(),
            source_revision: source_revision.clone(),
            declaration_digest: declaration_digest.clone(),
            needs: needs.clone(),
            effects: effects.clone(),
            preview_session: preview_session.clone(),
            reason: reason.clone(),
            expected_install_event_id: expected_install_event_id.clone(),
            current_event_id: row.event_id.clone(),
        };
        verify_alpha_tab_adopt_confirm(
            stored,
            &confirm,
            chrono::Utc::now().timestamp(),
            consumed,
            false,
            true,
        )
        .map_err(|code| Error::engine(format!("{TOOL}: adopt confirm refused [{code}]")))?;
        if stored.is_some_and(|receipt| receipt.last_update_event_id != last_update_event_id) {
            return Err(Error::engine(format!(
                "{TOOL}: adopt confirm refused [receipt_generation_changed]"
            )));
        }
        if let Some((_, consumed, _)) = store.get_mut(&receipt_id) {
            *consumed = true;
        }
    }
    append_alpha_event(
        &mut tx,
        caller,
        key,
        aggregate_id,
        reason,
        ControlEventPayload::AlphaTabAdopted(payload),
        &mut act_alloc,
    )
    .await?;
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: adopt did not fold")))?;
    let entry = entry_in(&mut tx, caller, &row).await?;
    db.commit_control(tx).await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
        act_alloc.get(),
    )
}

/// Authored-adopt for one installed tab (plan `100d273` E1, task `f1d80b0`):
/// flips a `caller_asserted` install to `shell_auto.v1` adoption on the
/// strength of hosted cookie-session plus trusted-Origin authority alone —
/// no preview receipt exists and none is spent.
///
/// In order:
/// 0. Hosted authored-adopt authority: the caller must carry a
///    `VerifiedAlphaTabPreview` attestation on the authored field matching
///    the requested pin field-for-field. Only the hosted plain-JSON adapter
///    mints it, after cookie-session plus trusted-Origin checks; the MCP
///    router, Bearer callers, and tool arguments have no representation for
///    it, so direct registry/MCP calls refuse with
///    `adopt_authored_authority_missing` before any verification work, and a
///    cross-pin or cross-account attestation refuses with
///    `adopt_authored_pin_mismatch`. A preview or adopt attestation is never
///    consulted here — each action carries its own field.
/// 1. Install row plus CAS: the package must be installed and
///    `expected_install_event_id` must name its current event.
/// 2. Install-pin binding: the requested pin must equal the stored install
///    pin field-for-field, exactly as `do_adopt`.
/// 3. Control append plus projection: the `alpha_tab.adopted` event pins
///    the exact account, full pin, `shell_auto.v1` adoption, CAS token, the
///    install's request echo, and the client-asserted launch provenance
///    (no receipt fields); the projector flips adoption only when the
///    stored row's pin still matches field-for-field (`require_one`).
///
/// Pane binding — that the install really came from the shell's own pane
/// agent — is enforced by the desktop app, not the engine (plan `100d273`
/// decision 1). `launch_id` / `authored_run_key` are recorded provenance,
/// labelled asserted.
#[allow(clippy::too_many_arguments)]
async fn do_adopt_authored(
    db: &Db,
    caller: &Caller,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration: Value,
    expected_install_event_id: String,
    reason: String,
    launch_id: Option<String>,
    authored_run_key: Option<String>,
    idempotency_key: Option<String>,
) -> Result<Value> {
    require_package(&package)?;
    require_version(&version)?;
    require_digest(&digest)?;
    let (needs, effects) = require_declaration(&declaration).map(|parsed| {
        let mut needs = parsed.needs;
        let mut effects = parsed.effects;
        needs.sort();
        effects.sort();
        (needs, effects)
    })?;
    require_reason(TOOL, &reason)?;
    let launch_id = require_authored_field("launch_id", launch_id)?;
    let authored_run_key = require_authored_field("authored_run_key", authored_run_key)?;
    if artifact_id.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: artifact_id must not be blank"
        )));
    }
    if source_revision.trim().is_empty() || source_revision.len() > 256 {
        return Err(Error::engine(format!(
            "{TOOL}: source_revision must be 1..256 characters"
        )));
    }
    let account_id = require_account(caller)?;
    // Hosted authored-adopt authority first: no attestation, no confirm —
    // on any transport, including MCP and Bearer HTTP. The attestation must
    // match the requested pin field-for-field, so one request's authority
    // can never authorize a different pin, and no caller-supplied token or
    // field can self-assert consent.
    let authority = caller.verified_alpha_tab_adopt_authored().ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: adopt_authored requires hosted cookie-session adopt authority [adopt_authored_authority_missing]"
        ))
    })?;
    let declaration_digest = alpha_tab_declaration_digest(&declaration)?;
    if authority.account_id != account_id
        || authority.package != package
        || authority.version != version
        || authority.digest != digest
        || authority.artifact_id != artifact_id
        || authority.source_revision != source_revision
        || authority.declaration_digest != declaration_digest
        || authority.needs != needs
        || authority.effects != effects
    {
        return Err(Error::engine(format!(
            "{TOOL}: adopt_authored authority does not match the requested pin [adopt_authored_pin_mismatch]"
        )));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = ActAllocation::new();
    let key = idempotency_key
        .filter(|key| !key.trim().is_empty())
        .unwrap_or_else(|| {
            format!("alpha-tab-adopt-authored:{account_id}:{package}:{expected_install_event_id}")
        });
    let aggregate_id = alpha_tab_aggregate_id(&account_id, &package);
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: package {package} is not installed")))?;
    let payload = AlphaTabAdoptPayload {
        account_id: account_id.clone(),
        package: package.clone(),
        version: version.clone(),
        digest: digest.clone(),
        artifact_id: artifact_id.clone(),
        consented_source_revision: source_revision.clone(),
        declaration_digest: declaration_digest.clone(),
        consented_declaration: declaration.clone(),
        adoption: ALPHA_TAB_ADOPTION_SHELL_AUTO.into(),
        previous_event_id: expected_install_event_id.clone(),
        receipt_id: None,
        preview_session: None,
        launch_id: launch_id.clone(),
        authored_run_key: authored_run_key.clone(),
        request: row.request.clone(),
    };
    // Same-key retry converges on the first durable event: the re-appended
    // identical payload dedups in the control tier, so a retried
    // adopt_authored after success reports `changed: false`.
    if let Some((kind, aggregate, actor, prior_reason, prior)) =
        prior_alpha_adopt_event(&mut tx, &key).await?
    {
        if kind != "alpha_tab.adopted"
            || aggregate != aggregate_id
            || actor != caller.actor()
            || prior_reason != reason
            || prior != payload
        {
            return Err(Error::engine(format!(
                "{TOOL}: idempotency_key was reused for different intent"
            )));
        }
        append_alpha_event(
            &mut tx,
            caller,
            key,
            aggregate_id,
            reason,
            ControlEventPayload::AlphaTabAdopted(payload),
            &mut act_alloc,
        )
        .await?;
        let row = install_row_in(&mut tx, &account_id, &package)
            .await?
            .ok_or_else(|| Error::engine(format!("{TOOL}: adopt_authored did not fold")))?;
        let entry = entry_in(&mut tx, caller, &row).await?;
        db.commit_control(tx).await?;
        return echo_act(
            json!({"package": package, "changed": false, "idempotent_retry": true, "install": entry}),
            act_alloc.get(),
        );
    }
    // CAS before pin: a stale generation refuses without consuming anything
    // (there is no receipt to protect here), so the caller can re-read the
    // current event and retry.
    if row.event_id != expected_install_event_id {
        return Err(Error::engine(format!(
            "{TOOL}: installation changed; expected current event {expected_install_event_id} but found {}",
            row.event_id
        )));
    }
    if row.status != "installed" {
        return Err(Error::engine(format!(
            "{TOOL}: package {package} with status {} cannot adopt; restore it first",
            row.status
        )));
    }
    // Install-pin binding: the authority names exactly the requested pin, so
    // the stored install must still carry that pin field-for-field (the
    // digest covers the canonical needs/effects). An upgrade or a revision
    // drift needs a fresh install, never an adopt across pins.
    if row.version != version
        || row.digest != digest
        || row.artifact_id != artifact_id
        || row.consented_source_revision != source_revision
        || row.declaration_digest != declaration_digest
    {
        return Err(Error::engine(format!(
            "{TOOL}: adopt_authored pin does not match the installed pin [install_pin_mismatch]"
        )));
    }
    append_alpha_event(
        &mut tx,
        caller,
        key,
        aggregate_id,
        reason,
        ControlEventPayload::AlphaTabAdopted(payload),
        &mut act_alloc,
    )
    .await?;
    let row = install_row_in(&mut tx, &account_id, &package)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: adopt_authored did not fold")))?;
    let entry = entry_in(&mut tx, caller, &row).await?;
    db.commit_control(tx).await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
        act_alloc.get(),
    )
}

/// M2 `live_unsubscribe` (design `ee12faf` §2.2): idempotent and resolved
/// only within the given connection. Unknown, closed or malformed tokens —
/// and unknown ids, including another connection's — all succeed with no
/// effect. Always answers `{subscription, unsubscribed: true}`.
async fn do_live_unsubscribe(db: &Db, stream: String, subscription: String) -> Result<Value> {
    if let (Some(token), Some(hub)) = (
        ConnectionToken::from_hex(stream.trim()),
        RealtimeHub::for_database(db),
    ) {
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .unsubscribe(&token, &SubscriptionId::from_wire(&subscription));
    }
    Ok(json!({"subscription": subscription, "unsubscribed": true}))
}

// Keep the selected action future's construction and storage out of the
// dispatcher poll frame; it still runs in this task under the same scopes.
#[inline(never)]
fn alpha_action_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

async fn manage_alpha_tabs(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ManageAlphaTabsArgs = parse_args(TOOL, arguments)?;
    match args {
        ManageAlphaTabsArgs::Inspect { package } => {
            alpha_action_future(|| do_inspect(&db, &caller, package)).await
        }
        ManageAlphaTabsArgs::List {} => alpha_action_future(|| do_list(&db, &caller)).await,
        ManageAlphaTabsArgs::Launch {
            package,
            expected_install_event_id,
        } => {
            alpha_action_future(|| do_launch(&db, &caller, package, expected_install_event_id))
                .await
        }
        ManageAlphaTabsArgs::LiveRead {
            package,
            expected_install_event_id,
            need,
            params,
            subscribe,
            if_revision,
            watch,
            reads: Some(reads),
        } => {
            if need.is_some()
                || params.is_some()
                || subscribe.is_some()
                || if_revision.is_some()
                || watch.is_some()
            {
                return Err(Error::engine(format!(
                    "{TOOL}: live read refused: reads excludes need, params, subscribe, if_revision and watch [invalid_params]"
                )));
            }
            alpha_action_future(|| {
                batch_read::do_batch_read(&db, &caller, package, expected_install_event_id, reads)
            })
            .await
        }
        ManageAlphaTabsArgs::LiveRead {
            package,
            expected_install_event_id,
            need,
            params,
            subscribe,
            if_revision,
            watch,
            reads: None,
        } => {
            alpha_action_future(|| {
                do_live_read(
                    &db,
                    &caller,
                    package,
                    expected_install_event_id,
                    need,
                    params,
                    LiveReadOptions {
                        subscribe,
                        if_revision,
                        watch,
                    },
                )
            })
            .await
        }
        ManageAlphaTabsArgs::LiveUnsubscribe {
            stream,
            subscription,
        } => alpha_action_future(|| do_live_unsubscribe(&db, stream, subscription)).await,
        ManageAlphaTabsArgs::AdmitRevealTarget {
            package,
            expected_install_event_id,
            record_id,
        } => {
            alpha_action_future(|| {
                admit_reveal_target(
                    &db,
                    &caller,
                    &package,
                    &expected_install_event_id,
                    &record_id,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Preview {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            reason,
        } => {
            alpha_action_future(|| {
                do_preview(
                    &db,
                    &caller,
                    package,
                    version,
                    digest,
                    artifact_id,
                    source_revision,
                    declaration,
                    reason,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Adopt {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            receipt_id,
            nonce,
            preview_session,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            alpha_action_future(|| {
                do_adopt(
                    &db,
                    &caller,
                    package,
                    version,
                    digest,
                    artifact_id,
                    source_revision,
                    declaration,
                    receipt_id,
                    nonce,
                    preview_session,
                    expected_install_event_id,
                    reason,
                    idempotency_key,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::AdoptAuthored {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            expected_install_event_id,
            reason,
            launch_id,
            authored_run_key,
            idempotency_key,
        } => {
            alpha_action_future(|| {
                do_adopt_authored(
                    &db,
                    &caller,
                    package,
                    version,
                    digest,
                    artifact_id,
                    source_revision,
                    declaration,
                    expected_install_event_id,
                    reason,
                    launch_id,
                    authored_run_key,
                    idempotency_key,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Install {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            reason,
            request,
            idempotency_key,
            expected_install_event_id,
        } => {
            alpha_action_future(|| {
                do_install(
                    &db,
                    &caller,
                    package,
                    version,
                    digest,
                    artifact_id,
                    source_revision,
                    declaration,
                    reason,
                    request,
                    idempotency_key,
                    expected_install_event_id,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Update {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            expected_install_event_id,
            reason,
            idempotency_key,
            request,
        } => {
            alpha_action_future(|| {
                do_update(
                    &db,
                    &caller,
                    package,
                    version,
                    digest,
                    artifact_id,
                    source_revision,
                    declaration,
                    expected_install_event_id,
                    reason,
                    idempotency_key,
                    request,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Disable {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            alpha_action_future(|| {
                do_transition(
                    &db,
                    &caller,
                    "alpha_tab.disabled",
                    package,
                    expected_install_event_id,
                    reason,
                    idempotency_key,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Restore {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            alpha_action_future(|| {
                do_transition(
                    &db,
                    &caller,
                    "alpha_tab.restored",
                    package,
                    expected_install_event_id,
                    reason,
                    idempotency_key,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Remove {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            alpha_action_future(|| {
                do_transition(
                    &db,
                    &caller,
                    "alpha_tab.removed",
                    package,
                    expected_install_event_id,
                    reason,
                    idempotency_key,
                )
            })
            .await
        }
        ManageAlphaTabsArgs::Reorder {
            tab_order,
            reason,
            idempotency_key,
        } => {
            alpha_action_future(|| do_reorder(&db, &caller, tab_order, reason, idempotency_key))
                .await
        }
    }
}

/// Register `manage_alpha_tabs`.
pub fn register_alpha_tab_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageAlphaTabs,
        "Personal alpha tabs pin package/version/digest, viewable live Document kind:artifact, \
         source revision and consented needs/effects. Install: caller_asserted. Update: \
         exact bytes/digest, event CAS, unchanged status/request; proven adoption carries for \
         unchanged canonical declarations, else Preview -> Adopt. Keyed retry: original \
         receipt + current_install no reapply. disable/restore/remove use event CAS; \
         disabled/removed tabs stop reads/actions. resolves fails closed; see target_resolves. \
         tab_order uses reorder, else agents/folders/tasks/graph/installs. Reorder: full strip; omitted \
         installs append; unknown/removed/duplicate refuse; last writer wins, list first. \
         Preview: exact source/digest, pinned sample HTML, expiring \
         account/pin/session receipt; no writes. Preview/adopt/adopt_authored require hosted \
         cookie+trusted-Origin, never Bearer. Adopt checks receipt/pin/event/attestation. Launch: \
         adoption/event/View/source; one-use sample-only URL, no live rows. live_read: \
         caller-only authorized consented input, staleness/pins: attention.query.v1 \
         at input.records; 8 sql.snapshot.v1 SELECT/WITH needs max, 200 rows each \
         at input.sql[key]; params[0] binds ?1, optional omitted=NULL. subscribe {stream}: \
         connection-bound, if_revision resync; {id,time_dependent}, now_ms() uses as_of_ms. \
         subscribe_refused includes read. live_unsubscribe: idempotent, connection-scoped. \
         admit_reveal_target: consented surface.reveal.v1, one visible canonical id/pins; \
         push-only, never live_read.",
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "inspect" },
                        "package": { "type": "string" }
                    },
                    "required": ["action", "package"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": { "action": { "const": "list" } },
                    "required": ["action"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "launch" },
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" }
                    },
                    "required": ["action", "package", "expected_install_event_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "live_read" },
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "need": {
                            "type": "string",
                            "description": "Consented need to execute. Omitted: snapshot (attention.query.v1 and param-less SQL needs). On request: records.search.v1 (params {query, limit<=30}), records.resolve_reference.v1 (params {reference}), or an SQL need by key (params per its declared schema)."
                        },
                        "params": { "type": "object" },
                        "subscribe": {
                            "type": "object",
                            "properties": {
                                "stream": {
                                    "type": "string",
                                    "description": "Connection token from the stream frame; snapshot reads only."
                                }
                            },
                            "required": ["stream"],
                            "additionalProperties": false,
                            "description": "Open a connection-bound need subscription; refusal still returns the read."
                        },
                        "if_revision": {
                            "type": "string",
                            "description": "When equal to revision_digest, returns unchanged:true with pin and revision, without rows; snapshot reads only."
                        }
                    },
                    "required": ["action", "package", "expected_install_event_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "admit_reveal_target" },
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "record_id": {
                            "type": "string",
                            "description": "Exact persisted record id to reveal (full id or reserved id such as native:root); prefixes are refused."
                        }
                    },
                    "required": ["action", "package", "expected_install_event_id", "record_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "live_unsubscribe" },
                        "stream": { "type": "string" },
                        "subscription": { "type": "string" }
                    },
                    "required": ["action", "stream", "subscription"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "preview" },
                        "package": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "declaration": { "type": "object" },
                        "reason": { "type": "string" }
                    },
                    "required": ["action", "package", "version", "digest", "artifact_id", "source_revision", "declaration", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "adopt" },
                        "package": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "declaration": { "type": "object" },
                        "receipt_id": { "type": "string" },
                        "nonce": { "type": "string" },
                        "preview_session": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "reason": { "type": "string" },
                        "idempotency_key": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "version", "digest", "artifact_id", "source_revision", "declaration", "receipt_id", "nonce", "preview_session", "expected_install_event_id", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "adopt_authored" },
                        "package": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "declaration": { "type": "object" },
                        "expected_install_event_id": { "type": "string" },
                        "reason": { "type": "string" },
                        "launch_id": { "type": ["string", "null"] },
                        "authored_run_key": { "type": ["string", "null"] },
                        "idempotency_key": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "version", "digest", "artifact_id", "source_revision", "declaration", "expected_install_event_id", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "install" },
                        "package": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "declaration": { "type": "object" },
                        "reason": { "type": "string" },
                        "request": { "type": ["string", "null"], "description": "Display-only request text." },
                        "idempotency_key": { "type": ["string", "null"] },
                        "expected_install_event_id": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "version", "digest", "artifact_id", "source_revision", "declaration", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "update" },
                        "package": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "declaration": { "type": "object" },
                        "reason": { "type": "string" },
                        "request": { "type": ["string", "null"], "description": "Display-only request text." },
                        "idempotency_key": { "type": ["string", "null"] },
                        "expected_install_event_id": { "type": "string" }
                    },
                    "required": ["action", "package", "version", "digest", "artifact_id", "source_revision", "declaration", "reason", "expected_install_event_id"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "disable" },
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "reason": { "type": "string" },
                        "idempotency_key": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "expected_install_event_id", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "restore" },
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "reason": { "type": "string" },
                        "idempotency_key": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "expected_install_event_id", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "remove" },
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "reason": { "type": "string" },
                        "idempotency_key": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "expected_install_event_id", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": { "const": "reorder" },
                        "tab_order": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Full tab-strip order: all four built-ins (agents, folders, tasks, graph) freely interleaved with pending:<package> for installed-or-disabled tabs. Empty resets to the default."
                        },
                        "reason": { "type": "string" },
                        "idempotency_key": { "type": ["string", "null"] }
                    },
                    "required": ["action", "tab_order", "reason"],
                    "additionalProperties": false
                }
            ]
        }),
        manage_alpha_tabs,
    )?;
    Ok(())
}

#[cfg(test)]
mod order_tests {
    //! Tab-order normalization vectors (task `c5d3820`): a directly
    //! appended control event faces only the tier's shape check, so a
    //! malformed yet shaped stored order still normalizes instead of
    //! reaching the strip.

    use super::resolve_effective_tab_order;

    fn tabs(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn malformed_stored_order_normalizes_like_the_shell() {
        let slotted = tabs(&["agent.attention-cockpit", "agent.team-pulse"]);
        let stored = tabs(&[
            "agents",
            "agents",
            "pending:agent.ghost",
            "pending:agent.team-pulse",
            "nope",
            "pending:agent.attention-cockpit",
        ]);
        // Duplicates collapse, unknown and unslotted entries drop, missing
        // built-ins append before missing installs, kept positions stand.
        assert_eq!(
            resolve_effective_tab_order(Some(&stored), &slotted),
            tabs(&[
                "agents",
                "pending:agent.team-pulse",
                "pending:agent.attention-cockpit",
                "folders",
                "tasks",
                "graph",
            ])
        );
    }

    #[test]
    fn missing_and_empty_orders_fall_back_to_default() {
        let slotted = tabs(&["agent.team-pulse"]);
        let default = tabs(&[
            "agents",
            "folders",
            "tasks",
            "graph",
            "pending:agent.team-pulse",
        ]);
        assert_eq!(resolve_effective_tab_order(None, &slotted), default);
        assert_eq!(resolve_effective_tab_order(Some(&[]), &slotted), default);
        assert_eq!(
            resolve_effective_tab_order(None, &[]),
            tabs(&["agents", "folders", "tasks", "graph"])
        );
    }

    #[test]
    fn clean_stored_order_survives_verbatim() {
        let slotted = tabs(&["agent.attention-cockpit", "agent.team-pulse"]);
        let stored = tabs(&[
            "graph",
            "pending:agent.team-pulse",
            "agents",
            "folders",
            "tasks",
            "pending:agent.attention-cockpit",
        ]);
        assert_eq!(resolve_effective_tab_order(Some(&stored), &slotted), stored);
    }
}

#[cfg(test)]
mod launch_tests {
    //! Slice-2 launch binding: canonical digest vectors, gate precedence,
    //! and the portable source-revision SQL
    //! (`docs/alpha-tab-install-slice2.md`).

    use super::{
        alpha_tab_bundle_digest, alpha_tab_canonical_declaration, alpha_tab_declaration_digest,
        alpha_tab_digest, alpha_tab_preview_authority_for, evaluate_alpha_tab_install_gates,
        evaluate_alpha_tab_source_gates, resolve_alpha_tab_source_in, TargetState,
        ALPHA_TAB_DIGEST_VERSION,
    };
    use serde_json::json;

    const FIXTURE_BODY: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Fixture</title></head><body><main><h1>Fixture</h1></main></body></html>";

    #[test]
    fn alpha_tab_digest_vectors() {
        // Worked vector from docs/alpha-tab-install-slice2.md §1, locked
        // byte-exact: any normalization or JCS drift changes these.
        assert_eq!(
            alpha_tab_bundle_digest(FIXTURE_BODY),
            "44a905b57d7957f3d8411ac4ce8fcedd5dcd202454cfbed87ec84cfda75efda0"
        );
        let declaration =
            json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]});
        assert_eq!(
            alpha_tab_declaration_digest(&declaration).unwrap(),
            "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15"
        );
        assert_eq!(
            alpha_tab_digest(
                "44a905b57d7957f3d8411ac4ce8fcedd5dcd202454cfbed87ec84cfda75efda0",
                "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15",
                "native.html.v1",
            ),
            "sha256:abd4e377416d6cecec1afff72b4281ee5ffde53d8649b6a7b9530a94dc3b0f40"
        );
        assert_eq!(ALPHA_TAB_DIGEST_VERSION, "alpha-tab-digest.v1");
    }

    #[test]
    fn alpha_tab_declaration_normalization() {
        // Consent covers the declared set, not author ordering: key order
        // and array order never move the canonical digest.
        let ordered = json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]});
        let shuffled = json!({"effects": ["task.triage-set.v1"], "needs": ["attention.query.v1"]});
        assert_eq!(
            alpha_tab_canonical_declaration(&ordered).unwrap(),
            alpha_tab_canonical_declaration(&shuffled).unwrap()
        );
        let multi_a = json!({"needs": ["b.read", "a.read"], "effects": ["x.act", "a.act"]});
        let multi_b = json!({"needs": ["a.read", "b.read"], "effects": ["a.act", "x.act"]});
        assert_eq!(
            alpha_tab_declaration_digest(&multi_a).unwrap(),
            alpha_tab_declaration_digest(&multi_b).unwrap()
        );
        assert_eq!(
            alpha_tab_canonical_declaration(&multi_a).unwrap(),
            json!({"needs": ["a.read", "b.read"], "effects": ["a.act", "x.act"]})
        );
        // A narrower declaration is a different digest, never a silent
        // subset: widening/narrowing inside a pinned version is decided by
        // the K1 rule, not by hash collision.
        let narrowed = json!({"needs": ["attention.query.v1"], "effects": []});
        assert_ne!(
            alpha_tab_declaration_digest(&ordered).unwrap(),
            alpha_tab_declaration_digest(&narrowed).unwrap()
        );
    }

    #[test]
    fn malformed_sql_entries_fail_the_digest_closed() {
        // Two declarations differing only by an invalid SQL entry must not
        // digest identically: the canonical form refuses instead of
        // digesting the invalid entry as absent.
        let clean = json!({"needs": ["attention.query.v1"], "effects": []});
        assert!(alpha_tab_declaration_digest(&clean).is_ok());
        for invalid in [
            json!({"needs": ["attention.query.v1",
                {"need": "sql.snapshot.v1", "key": "Bad", "label": "L", "sql": "SELECT id FROM records"}],
                "effects": []}),
            json!({"needs": ["attention.query.v1",
                {"need": "sql.snapshot.v1", "key": "ok", "label": "L", "sql": "DELETE FROM records"}],
                "effects": []}),
            json!({"needs": ["attention.query.v1", {"need": "other.need.v1", "key": "ok"}],
                "effects": []}),
        ] {
            let error = alpha_tab_canonical_declaration(&invalid)
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_sql_need"), "{invalid}: {error}");
            let error = alpha_tab_declaration_digest(&invalid)
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_sql_need"), "{invalid}: {error}");
            assert!(alpha_tab_preview_authority_for(
                "alice", "pkg", "0.1.0", "digest", "artifact", "rev", &invalid,
            )
            .is_none());
        }
    }

    #[test]
    fn alpha_tab_launch_verdict_matrix() {
        use TargetState::{Archived, Missing, Resolvable, WrongRecordType};
        let install = |status: &str, adoption: &str, target: TargetState, can_view: bool| {
            evaluate_alpha_tab_install_gates(status, adoption, target, can_view)
        };
        // Status gates first, in order.
        assert_eq!(
            install("removed", "caller_asserted", Resolvable, true),
            Err("removed")
        );
        assert_eq!(
            install("disabled", "caller_asserted", Resolvable, true),
            Err("disabled")
        );
        // Every unattested adoption refuses: only the verified value the
        // adopt-confirm slice stamps passes the adoption gate. A forged
        // stronger-looking value refuses identically — no caller-asserted
        // string is proof.
        assert_eq!(
            install("installed", "caller_asserted", Resolvable, true),
            Err("adoption_unverified")
        );
        assert_eq!(
            install("installed", "verified_gesture: forged", Resolvable, true),
            Err("adoption_unverified")
        );
        assert_eq!(
            install("installed", "", Resolvable, true),
            Err("adoption_unverified")
        );
        // Adoption precedes target and authority: even a missing target or a
        // lost View still names the stronger install-intrinsic reason.
        assert_eq!(
            install("installed", "caller_asserted", Missing, true),
            Err("adoption_unverified")
        );
        assert_eq!(
            install("installed", "caller_asserted", Archived, true),
            Err("adoption_unverified")
        );
        assert_eq!(
            install("installed", "caller_asserted", WrongRecordType, true),
            Err("adoption_unverified")
        );
        assert_eq!(
            install("installed", "caller_asserted", Resolvable, false),
            Err("adoption_unverified")
        );
        // Source gates, in order. Fully covered: the resolver and the
        // recomputation feed these booleans once verified adoption exists.
        let source = evaluate_alpha_tab_source_gates;
        assert_eq!(source(false, true, true), Err("not_renderable"));
        assert_eq!(source(true, false, true), Err("source_revision_unresolved"));
        assert_eq!(source(true, true, false), Err("digest_mismatch"));
        assert_eq!(source(true, true, true), Ok(()));
        // NOTE (coverage, stated): the install-gate target arms past
        // verified adoption (`missing`, `archived`, `wrong_record_type`,
        // `unauthorized`) are unit-covered above through the admitted
        // verified value, and DB-backed tool tests exercise them through
        // real verified installs; the terminal ticket arm refuses every
        // call by construction. See docs/alpha-tab-install-slice2.md §6.
    }

    const SOURCE_ARTIFACT: &str = "d1d00000-0000-4000-8000-000000000001";
    const SOURCE_EVENT: &str = "e1d00000-0000-4000-8000-000000000001";
    const BODYLESS_EVENT: &str = "e1d00000-0000-4000-8000-000000000002";

    async fn source_fixture_db() -> crate::Db {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, payload) in [
            (SOURCE_EVENT, json!({"body": FIXTURE_BODY}).to_string()),
            (BODYLESS_EVENT, json!({"note": "no body here"}).to_string()),
        ] {
            sqlx::query(
                "INSERT INTO content_events
                     (id, record_id, type, payload, causal_envelope_version, causal_status)
                 VALUES (?,?,?,?,1,'complete')",
            )
            .bind(id)
            .bind(SOURCE_ARTIFACT)
            .bind("record.updated")
            .bind(payload)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn alpha_tab_source_resolution() {
        let db = source_fixture_db().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // The body-carrying event resolves to its exact bytes.
        let source = resolve_alpha_tab_source_in(&mut tx, SOURCE_ARTIFACT, SOURCE_EVENT)
            .await
            .unwrap()
            .expect("body-carrying event resolves");
        assert_eq!(source.event_id, SOURCE_EVENT);
        assert_eq!(source.body, FIXTURE_BODY);
        assert_eq!(
            alpha_tab_bundle_digest(&source.body),
            "44a905b57d7957f3d8411ac4ce8fcedd5dcd202454cfbed87ec84cfda75efda0"
        );
        // Opaque revisions, body-less events, and other records refuse
        // identically: resolution proves nothing by itself.
        for (artifact, revision) in [
            (SOURCE_ARTIFACT, "rev-1"),
            (SOURCE_ARTIFACT, "00000000-0000-4000-8000-000000000000"),
            (SOURCE_ARTIFACT, BODYLESS_EVENT),
            ("d1d00000-0000-4000-8000-000000000009", SOURCE_EVENT),
        ] {
            assert!(
                resolve_alpha_tab_source_in(&mut tx, artifact, revision)
                    .await
                    .unwrap()
                    .is_none(),
                "unresolvable source must be None for {artifact} @ {revision}"
            );
        }
        tx.rollback().await.unwrap();
    }
}

#[cfg(test)]
mod adopt_gate_tests {
    //! Slice-3a verified-adoption gate: the closed-vocabulary verified value
    //! stays unadmitted, the hosted authority gate refuses Bearer and missing
    //! Origin, the receipt matrix names every mismatch, and the terminal
    //! inspection arm keeps launch URLs out of list/inspect
    //! (`docs/alpha-tab-install-slice3a-adopt-gate.md`).

    use super::TargetState;
    use super::{
        alpha_adopt_authority_gate, evaluate_alpha_tab_install_gates,
        evaluate_alpha_tab_ticket_gate, verify_alpha_tab_adopt_confirm, AlphaTabAdoptConfirm,
        AlphaTabPreviewReceipt, ALPHA_TAB_ADOPTION_SHELL_AUTO, ALPHA_TAB_ADOPTION_VERIFIED,
        ALPHA_TAB_LAUNCH_REQUEST_REQUIRED, ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
        VERIFIED_ALPHA_TAB_ADOPTIONS,
    };

    fn stored_receipt() -> AlphaTabPreviewReceipt {
        AlphaTabPreviewReceipt {
            receipt_id: "rcpt_01".into(),
            nonce: "nonce_01".into(),
            account_id: "alice".into(),
            package: "agent.attention-cockpit".into(),
            version: "0.1.0".into(),
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            artifact_id: "a1d00000-0000-4000-8000-000000000001".into(),
            source_revision: "e1d00000-0000-4000-8000-000000000001".into(),
            declaration_digest: "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15"
                .into(),
            needs: vec!["attention.query.v1".into()],
            effects: vec!["task.triage-set.v1".into()],
            preview_session: "sess_01".into(),
            last_update_event_id: None,
            issued_at_secs: 1_000_000,
            expires_at_secs: 1_000_000 + ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
        }
    }

    fn matching_confirm() -> AlphaTabAdoptConfirm {
        let stored = stored_receipt();
        AlphaTabAdoptConfirm {
            receipt_id: stored.receipt_id,
            nonce: stored.nonce,
            account_id: stored.account_id,
            package: stored.package,
            version: stored.version,
            digest: stored.digest,
            artifact_id: stored.artifact_id,
            source_revision: stored.source_revision,
            declaration_digest: stored.declaration_digest,
            needs: stored.needs,
            effects: stored.effects,
            preview_session: stored.preview_session,
            reason: "Adopt the previewed attention cockpit.".into(),
            expected_install_event_id: "evt_cur".into(),
            current_event_id: "evt_cur".into(),
        }
    }

    fn verify(
        stored: Option<&AlphaTabPreviewReceipt>,
        confirm: &AlphaTabAdoptConfirm,
        now: i64,
        consumed: bool,
        bearer: bool,
        origin: bool,
    ) -> std::result::Result<(), &'static str> {
        verify_alpha_tab_adopt_confirm(stored, confirm, now, consumed, bearer, origin)
    }

    #[test]
    fn verified_value_is_defined_and_admitted() {
        // The closed vocabulary names exactly two verified values, and the
        // adopt-confirm slice admits both: a verified install passes the
        // adoption gate, while every other adoption — including forged
        // stronger-looking strings — still refuses `adoption_unverified`.
        // Admission does not make anything executable: the terminal ticket
        // gate still refuses every verified install below.
        assert_eq!(ALPHA_TAB_ADOPTION_VERIFIED, "shell_adopt.v1");
        assert_eq!(ALPHA_TAB_ADOPTION_SHELL_AUTO, "shell_auto.v1");
        assert_eq!(
            VERIFIED_ALPHA_TAB_ADOPTIONS,
            &["shell_adopt.v1", "shell_auto.v1"]
        );
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "installed",
                ALPHA_TAB_ADOPTION_VERIFIED,
                TargetState::Resolvable,
                true
            ),
            Ok(())
        );
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "installed",
                ALPHA_TAB_ADOPTION_SHELL_AUTO,
                TargetState::Resolvable,
                true
            ),
            Ok(())
        );
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "installed",
                "caller_asserted",
                TargetState::Resolvable,
                true
            ),
            Err("adoption_unverified")
        );
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "installed",
                "verified_gesture: forged",
                TargetState::Resolvable,
                true
            ),
            Err("adoption_unverified")
        );
        // Adoption still precedes target and authority: a verified install
        // with a missing target or a lost View names its own reason, and
        // status gates still come first.
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "disabled",
                ALPHA_TAB_ADOPTION_VERIFIED,
                TargetState::Resolvable,
                true
            ),
            Err("disabled")
        );
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "installed",
                ALPHA_TAB_ADOPTION_VERIFIED,
                TargetState::Missing,
                true
            ),
            Err("missing")
        );
        assert_eq!(
            evaluate_alpha_tab_install_gates(
                "installed",
                ALPHA_TAB_ADOPTION_VERIFIED,
                TargetState::Resolvable,
                false
            ),
            Err("unauthorized")
        );
    }

    #[test]
    fn adopt_authority_gate_refuses_bearer_and_missing_origin() {
        // Cookie + trusted Origin is the only issuance/confirm authority.
        // Bearer wins in `session_credential`, so agents can never pick this
        // up; a missing Origin carries no same-origin proof.
        assert_eq!(
            alpha_adopt_authority_gate(true, true),
            Err("bearer_refused")
        );
        assert_eq!(
            alpha_adopt_authority_gate(true, false),
            Err("bearer_refused")
        );
        assert_eq!(
            alpha_adopt_authority_gate(false, false),
            Err("origin_missing")
        );
        assert_eq!(alpha_adopt_authority_gate(false, true), Ok(()));
    }

    #[test]
    fn adopt_confirm_receipt_matrix() {
        let stored = stored_receipt();
        let confirm = matching_confirm();
        let live = 1_000_100;
        // The happy path verifies — but produces no state change here: the
        // caller still needs the 3b control event + receipt-consume store.
        assert_eq!(
            verify(Some(&stored), &confirm, live, false, false, true),
            Ok(())
        );
        // Authority first: Bearer issuance+confirm and missing Origin.
        assert_eq!(
            verify(Some(&stored), &confirm, live, false, true, true),
            Err("bearer_refused")
        );
        assert_eq!(
            verify(Some(&stored), &confirm, live, false, false, false),
            Err("origin_missing")
        );
        // Receipt liveness: unknown, expired, consumed-replay.
        assert_eq!(
            verify(None, &confirm, live, false, false, true),
            Err("receipt_unknown")
        );
        assert_eq!(
            verify(
                Some(&stored),
                &confirm,
                stored.expires_at_secs,
                false,
                false,
                true
            ),
            Err("receipt_expired")
        );
        assert_eq!(
            verify(Some(&stored), &confirm, live, true, false, true),
            Err("receipt_consumed")
        );
        // Account binding.
        let mut account = confirm.clone();
        account.account_id = "bea".into();
        assert_eq!(
            verify(Some(&stored), &account, live, false, false, true),
            Err("account_mismatch")
        );
        // Each pin field mismatches identically: no caller-supplied field can
        // self-assert a preview or a receipt.
        fn mutated(
            base: &AlphaTabAdoptConfirm,
            f: impl Fn(&mut AlphaTabAdoptConfirm),
        ) -> AlphaTabAdoptConfirm {
            let mut c = base.clone();
            f(&mut c);
            c
        }
        let pins = [
            mutated(&confirm, |c| c.package = "agent.other-tab".into()),
            mutated(&confirm, |c| c.version = "0.2.0".into()),
            mutated(&confirm, |c| {
                c.digest =
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()
            }),
            mutated(&confirm, |c| {
                c.artifact_id = "a1d00000-0000-4000-8000-000000000002".into()
            }),
            mutated(&confirm, |c| {
                c.source_revision = "e1d00000-0000-4000-8000-000000000009".into()
            }),
            mutated(&confirm, |c| {
                c.declaration_digest =
                    "0000000000000000000000000000000000000000000000000000000000000000".into()
            }),
            mutated(&confirm, |c| c.needs = vec!["other.read.v1".into()]),
            mutated(&confirm, |c| c.effects = vec![]),
            mutated(&confirm, |c| c.receipt_id = "rcpt_02".into()),
            mutated(&confirm, |c| c.nonce = "nonce_02".into()),
            mutated(&confirm, |c| c.preview_session = "sess_02".into()),
        ];
        for pin in &pins {
            assert_eq!(
                verify(Some(&stored), pin, live, false, false, true),
                Err("pin_mismatch"),
                "pin field mismatch must refuse without state change"
            );
        }
        // Reason shape and CAS.
        let mut reason = confirm.clone();
        reason.reason = String::new();
        assert_eq!(
            verify(Some(&stored), &reason, live, false, false, true),
            Err("reason_invalid")
        );
        let mut cas = confirm.clone();
        cas.expected_install_event_id = "evt_stale".into();
        assert_eq!(
            verify(Some(&stored), &cas, live, false, false, true),
            Err("cas_mismatch")
        );
    }

    #[test]
    fn inspection_requires_explicit_launch() {
        assert_eq!(ALPHA_TAB_LAUNCH_REQUEST_REQUIRED, "launch_request_required");
        assert_eq!(
            evaluate_alpha_tab_ticket_gate(),
            Err("launch_request_required")
        );
    }
}

#[cfg(test)]
mod preview_store_bounds_tests {
    //! Preview-receipt store bounds: expiry sweep plus global and
    //! per-account oldest-first eviction (`preview_receipt_store`).

    use super::{
        find_alpha_tab_preview_receipt, issue_alpha_tab_preview_receipt,
        ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT, ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT,
        ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
    };

    fn issue_for(account: &str, package: &str, now: i64) -> String {
        issue_alpha_tab_preview_receipt(
            account,
            package,
            "0.1.0",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "a1d00000-0000-4000-8000-000000000001",
            "e1d00000-0000-4000-8000-000000000001",
            "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15",
            vec!["attention.query.v1".into()],
            vec!["task.triage-set.v1".into()],
            None,
            now,
        )
        .receipt_id
    }

    #[test]
    fn preview_receipt_store_sweeps_expiry_and_holds_both_caps() {
        // One sequential test, not three: the store is process-global and
        // lib tests run in parallel threads, so independent bound tests
        // could evict each other's receipts. Phases run oldest-first below.
        let now = 2_000_000;
        let stale = issue_for("store-bounds-sweep", "agent.stale-tab", now);
        // Fresh issue far past the stale receipt's expiry sweeps it: the
        // later confirm for the swept id fails closed with `receipt_unknown`
        // instead of resurrecting expired authority.
        issue_for(
            "store-bounds-sweep",
            "agent.fresh-tab",
            now + ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS + 1,
        );
        assert!(
            find_alpha_tab_preview_receipt(&stale).is_none(),
            "expired preview receipt must be swept on issue"
        );

        let now = 3_000_000;
        let mut ids = Vec::new();
        for index in 0..=ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT {
            ids.push(issue_for(
                "store-bounds-per-account",
                &format!("agent.tab-{index:03}"),
                now + index as i64,
            ));
        }
        assert_eq!(ids.len(), ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT + 1);
        // The oldest issue is evicted; everything newer is still held.
        assert!(
            find_alpha_tab_preview_receipt(&ids[0]).is_none(),
            "oldest per-account receipt must be evicted past the cap"
        );
        for id in ids.iter().skip(1) {
            assert!(
                find_alpha_tab_preview_receipt(id).is_some(),
                "newer per-account receipts must survive their own cap"
            );
        }

        // Global flood last: distinct accounts so only the global cap —
        // never the per-account one — applies here.
        let now = 4_000_000;
        let first = issue_for("store-bounds-global-000000", "agent.tab-000", now);
        for index in 1..=ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT {
            issue_for(
                &format!("store-bounds-global-{index:06}"),
                &format!("agent.tab-{index:03}"),
                now + index as i64,
            );
        }
        assert!(
            find_alpha_tab_preview_receipt(&first).is_none(),
            "oldest global receipt must be evicted past the cap"
        );
    }
}

#[cfg(test)]
mod declared_read_tests {
    //! Parameter bounds for on-request declared reads (task `1044bb6`).

    use super::{
        ambiguous_reference_candidates, parse_declared_read, DeclaredRead, RecordChangesCursor,
        CANVAS_SCENE_NEED, RECORDS_RESOLVE_REFERENCE_NEED, RECORDS_SEARCH_NEED,
        RECORD_CHANGES_NEED,
    };
    use serde_json::json;

    /// `do_declared_read` gates these names on the read-only pool because no
    /// declaration can hold a SQL need keyed by one of them.
    #[test]
    fn host_read_needs_are_never_sql_keys() {
        for name in super::HOST_READ_NEEDS {
            let entry =
                json!({"need": "sql.snapshot.v1", "key": name, "label": "L", "sql": "SELECT 1"});
            let refusal = super::parse_sql_need_entry(&entry).unwrap_err();
            assert!(
                refusal.contains("must not collide with a host need name"),
                "{name}: {refusal}"
            );
        }
    }

    #[test]
    fn artifact_render_takes_one_canonical_full_record_id() {
        let id = "a7710000-0000-4000-8000-000000000033";
        assert_eq!(
            parse_declared_read(
                super::ARTIFACT_RENDER_NEED,
                Some(&json!({"artifact_id": id}))
            ),
            Ok(DeclaredRead::ArtifactRender {
                artifact_id: id.into()
            })
        );
        for params in [
            json!({}),
            json!({"artifact_id": ""}),
            json!({"artifact_id": 7}),
            json!({"artifact_id": "a771000"}),
            json!({"artifact_id": format!(" {id} ")}),
            json!({"artifact_id": id.to_uppercase()}),
            json!({"artifact_id": id.replace('-', "")}),
            json!({"artifact_id": format!("{{{id}}}")}),
            json!({"artifact_id": format!("urn:uuid:{id}")}),
            json!({"artifact_id": id, "as_of": {"event_id": "e1"}}),
            json!({"artifact_id": id, "revalidate": {}}),
            json!({"artifact_id": id, "include_timing": true}),
            json!([id]),
        ] {
            assert_eq!(
                parse_declared_read(super::ARTIFACT_RENDER_NEED, Some(&params)),
                Err("invalid_params"),
                "{params}"
            );
        }
        assert_eq!(
            parse_declared_read(super::ARTIFACT_RENDER_NEED, None),
            Err("invalid_params")
        );
    }

    /// A live v2 render answer as `render_artifact` gives it, trimmed to the
    /// members the projection must keep or withhold.
    fn rendered_v2(tree: serde_json::Value) -> serde_json::Value {
        json!({
            "status": "rendered",
            "artifact_id": "a1",
            "runtime": {"id": "native.mdx.v2", "compiler": {"version": "1.0.4"}},
            "input": {"version": "native.named-artifact-input.v1", "mode": "named", "inputs": {"items": {"records": [{"id": "hidden-from-tree"}]}}},
            "write_diagnostics": [{"code": "w"}],
            "plan": {
                "kind": "safe_tree",
                "version": "1",
                "tree": tree,
                "interactions": [{"id": "move"}],
                "observed": {"r1": {"lifecycle": "cas"}},
                "interaction_availability": {"editable_records": ["r1"]},
                "styles": {"digest": "d", "href": "/api/artifact-styles/d.css", "flags": []},
                "cache": {"state": "miss", "key": "k"},
                "timing": {"phases": {}},
                "provenance": {
                    "record_id": "a1",
                    "source_event_id": "e1",
                    "event_seq": 4,
                    "snapshot_event_id": "e9",
                    "snapshot_event_seq": 9,
                    "body_sha256": "b",
                    "render_sha256": "r",
                    "caller_sha256": "viewer",
                    "revalidation": {"caller_sha256": "viewer"},
                    "input_bundle": {"ports": {}},
                    "dependency_closure_sha256": "c",
                    "module_releases": [],
                },
            },
        })
    }

    #[test]
    fn an_artifact_render_answer_is_display_only() {
        let tree = json!({"type": "h1", "props": {}, "children": ["Hello"]});
        let answer = super::artifact_render_envelope(
            "a1",
            &rendered_v2(tree.clone()),
            super::ARTIFACT_RENDER_RESULT_MAX_CHARS,
        );
        assert_eq!(
            answer,
            Ok(json!({
                "version": "artifact.render.v1",
                "status": "rendered",
                "artifact_id": "a1",
                "runtime": {"id": "native.mdx.v2"},
                "plan": {
                    "kind": "safe_tree",
                    "version": "1",
                    "tree": tree,
                    "styles": {"digest": "d", "flags": []},
                    "provenance": {
                        "record_id": "a1",
                        "source_event_id": "e1",
                        "event_seq": 4,
                        "snapshot_event_id": "e9",
                        "snapshot_event_seq": 9,
                        "body_sha256": "b",
                        "render_sha256": "r",
                    },
                },
            }))
        );
    }

    #[test]
    fn anything_but_a_rendered_safe_tree_is_render_failed() {
        let max = super::ARTIFACT_RENDER_RESULT_MAX_CHARS;
        let failed = json!({
            "status": "error",
            "diagnostic": {
                "format": "native.artifact-diagnostic.v1",
                "code": "mdx_policy_violation",
                "message": "secret source",
                "details": {"line": 3},
            },
        });
        let mut unchanged = rendered_v2(json!({"type": "p", "props": {}, "children": []}));
        unchanged["unchanged"] = json!(true);
        let mut treeless = rendered_v2(json!(null));
        treeless["plan"].as_object_mut().unwrap().remove("tree");
        // The runtime is the render's own and must be an MDX runtime.
        let tree = json!({"type": "p", "props": {}, "children": []});
        let mut html_runtime = rendered_v2(tree.clone());
        html_runtime["runtime"]["id"] = json!("native.html.v1");
        let mut revision_runtime = rendered_v2(tree.clone());
        revision_runtime["runtime"]["id"] = json!("native.mdx.v2@3");
        let mut no_runtime = rendered_v2(tree);
        no_runtime.as_object_mut().unwrap().remove("runtime");
        for rendered in [
            failed,
            unchanged,
            treeless,
            html_runtime,
            revision_runtime,
            no_runtime,
            json!({"status": "rendered", "plan": {"kind": "isolated_html"}}),
            json!({"status": "rendered", "plan": {"kind": "board", "lanes": []}}),
            json!(null),
        ] {
            assert_eq!(
                super::artifact_render_envelope("a1", &rendered, max),
                Err("render_failed"),
                "{rendered}"
            );
        }
    }

    #[test]
    fn any_render_error_settles_as_render_failed_without_its_text() {
        let max = super::ARTIFACT_RENDER_RESULT_MAX_CHARS;
        for error in [
            crate::error::Error::engine(
                "render_artifact: record ae000000-0000-4000-8000-000000000005 not found [not_found]",
            ),
            crate::error::Error::engine("database is locked"),
        ] {
            assert_eq!(
                super::settle_artifact_render("a1", Err(error), max),
                Err("render_failed")
            );
        }
        let tree = json!({"type": "p", "props": {}, "children": []});
        assert_eq!(
            super::settle_artifact_render("a1", Ok(rendered_v2(tree.clone())), max).unwrap()
                ["runtime"],
            json!({"id": "native.mdx.v2"})
        );
        let mut v1 = rendered_v2(tree);
        v1["runtime"]["id"] = json!("native.mdx.v1");
        assert_eq!(
            super::settle_artifact_render("a1", Ok(v1), max).unwrap()["runtime"],
            json!({"id": "native.mdx.v1"})
        );
    }

    #[test]
    fn an_artifact_render_over_the_bridge_budget_is_refused_whole() {
        let rendered =
            rendered_v2(json!({"type": "p", "props": {}, "children": ["x".repeat(4000)]}));
        let fits = super::artifact_render_envelope("a1", &rendered, 8000).unwrap();
        assert!(crate::mcp::tools::canvas::es_json_len(&fits) <= 8000);
        assert_eq!(
            super::artifact_render_envelope("a1", &rendered, 4000),
            Err("too_large")
        );
    }

    #[test]
    fn canvas_scene_params_are_bounded_and_default_to_the_page_cap() {
        assert_eq!(
            parse_declared_read(CANVAS_SCENE_NEED, Some(&json!({"canvas_id": " c1 "}))),
            Ok(DeclaredRead::CanvasScene {
                canvas_id: "c1".into(),
                limit: 500,
                cursor: None
            })
        );
        // The shape a page hands out: hex over the JSON `[z, id]` pair.
        let cursor = hex::encode(json!(["a0", "n1"]).to_string());
        assert_eq!(
            parse_declared_read(
                CANVAS_SCENE_NEED,
                Some(&json!({"canvas_id": "c1", "limit": 1, "cursor": cursor}))
            ),
            Ok(DeclaredRead::CanvasScene {
                canvas_id: "c1".into(),
                limit: 1,
                cursor: Some(cursor.clone())
            })
        );
        assert_eq!(
            parse_declared_read(
                CANVAS_SCENE_NEED,
                Some(&json!({"canvas_id": "c1", "cursor": null}))
            ),
            Ok(DeclaredRead::CanvasScene {
                canvas_id: "c1".into(),
                limit: 500,
                cursor: None
            })
        );
        for params in [
            json!({}),
            json!({"canvas_id": ""}),
            json!({"canvas_id": 7}),
            json!({"canvas_id": "c".repeat(129)}),
            json!({"canvas_id": "c1", "limit": 0}),
            json!({"canvas_id": "c1", "limit": 501}),
            json!({"canvas_id": "c1", "limit": "10"}),
            json!({"canvas_id": "c1", "cursor": "not-hex"}),
            json!({"canvas_id": "c1", "cursor": hex::encode("[\"a\"]")}),
            json!({"canvas_id": "c1", "cursor": hex::encode(json!(["", "n1"]).to_string())}),
            json!({"canvas_id": "c1", "cursor": 3}),
            json!({"canvas_id": "c1", "port": "board"}),
            json!({"canvas_id": "c1", "ops": []}),
            json!(["c1"]),
        ] {
            assert_eq!(
                parse_declared_read(CANVAS_SCENE_NEED, Some(&params)),
                Err("invalid_params"),
                "{params}"
            );
        }
        assert_eq!(
            parse_declared_read(CANVAS_SCENE_NEED, None),
            Err("invalid_params")
        );
    }

    #[test]
    fn record_changes_params_are_bounded_and_the_cursor_only_shape_checked() {
        assert_eq!(
            parse_declared_read(RECORD_CHANGES_NEED, Some(&json!({"record_id": " r1 "}))),
            Ok(DeclaredRead::RecordChanges {
                record_id: "r1".into(),
                limit: 50,
                cursor: None
            })
        );
        // Whether a cursor opens depends on the install, which parsing does
        // not know; parsing only refuses what could never be a cursor.
        let cursor = RecordChangesCursor::seal("install-1", "r1", "e1");
        assert_eq!(
            parse_declared_read(
                RECORD_CHANGES_NEED,
                Some(&json!({"record_id": "r1", "limit": 1, "cursor": cursor}))
            ),
            Ok(DeclaredRead::RecordChanges {
                record_id: "r1".into(),
                limit: 1,
                cursor: Some(cursor.clone())
            })
        );
        assert_eq!(
            parse_declared_read(
                RECORD_CHANGES_NEED,
                Some(&json!({"record_id": "r1", "cursor": null}))
            ),
            Ok(DeclaredRead::RecordChanges {
                record_id: "r1".into(),
                limit: 50,
                cursor: None
            })
        );
        for params in [
            json!({}),
            json!({"record_id": ""}),
            json!({"record_id": 7}),
            json!({"record_id": "r".repeat(129)}),
            json!({"record_id": "r1", "limit": 0}),
            json!({"record_id": "r1", "limit": 51}),
            json!({"record_id": "r1", "limit": "10"}),
            json!({"record_id": "r1", "cursor": "not-hex"}),
            json!({"record_id": "r1", "cursor": 3}),
            json!({"record_id": "r1", "cursor": "ab".repeat(40)}),
            json!({"record_id": "r1", "cursor": "abc".repeat(27)}),
            json!({"record_id": "r1", "cursor": "f".repeat(RecordChangesCursor::MAX_CHARS + 2)}),
            // No positional or payload escape hatch.
            json!({"record_id": "r1", "after_local_seq": 5}),
            json!({"record_id": "r1", "detail": "full"}),
            json!(["r1"]),
        ] {
            assert_eq!(
                parse_declared_read(RECORD_CHANGES_NEED, Some(&params)),
                Err("invalid_params"),
                "{params}"
            );
        }
        assert_eq!(
            parse_declared_read(RECORD_CHANGES_NEED, None),
            Err("invalid_params")
        );
    }

    #[test]
    fn a_record_changes_cursor_opens_only_for_its_install_and_record() {
        let event_id = "0b9f3c2e-1a2b-4c3d-8e9f-0123456789ab";
        let cursor = RecordChangesCursor::seal("install-1", "r1", event_id);
        assert!(cursor.len() <= RecordChangesCursor::MAX_CHARS);
        assert!(
            !cursor.contains(&hex::encode(event_id)),
            "the id is not in clear"
        );
        assert!(!cursor.contains("0b9f3c2e"));
        assert_eq!(
            RecordChangesCursor::open(&cursor, "install-1", "r1").as_deref(),
            Some(event_id)
        );
        assert_eq!(RecordChangesCursor::open(&cursor, "install-2", "r1"), None);
        assert_eq!(RecordChangesCursor::open(&cursor, "install-1", "r2"), None);
        // Any flipped bit, in the tag or the sealed id, refuses.
        for index in [0, 31, 32, cursor.len() - 1] {
            let mut tampered = cursor.clone().into_bytes();
            tampered[index] = if tampered[index] == b'0' { b'1' } else { b'0' };
            let tampered = String::from_utf8(tampered).unwrap();
            assert_eq!(
                RecordChangesCursor::open(&tampered, "install-1", "r1"),
                None
            );
        }
        // A forged cursor naming a real id in clear does not open.
        let forged = format!(
            "{}{}{}",
            "00".repeat(24),
            hex::encode(event_id),
            "00".repeat(16)
        );
        assert_eq!(RecordChangesCursor::open(&forged, "install-1", "r1"), None);
        // A fresh nonce every time: two seals of one event differ, both open.
        let again = RecordChangesCursor::seal("install-1", "r1", event_id);
        assert_ne!(again, cursor);
        assert_eq!(
            RecordChangesCursor::open(&again, "install-1", "r1").as_deref(),
            Some(event_id)
        );
    }

    fn synthetic_event(id: &str, padding: usize) -> (String, serde_json::Value) {
        (
            id.to_string(),
            json!({
                "event_id": id, "type": "record.updated", "created_at": "2026-09-28T00:00:00.000Z",
                "reason": "\u{1}".repeat(padding),
            }),
        )
    }

    fn envelope_of(
        events: Vec<(String, serde_json::Value)>,
        resume_after: Option<&str>,
        max_chars: usize,
    ) -> serde_json::Value {
        super::record_changes_envelope(
            "r1",
            50,
            crate::mcp::tools::history::TabRecordChangesPage {
                events,
                resume_after: resume_after.map(str::to_string),
            },
            max_chars,
            &|event_id: &str| format!("sealed:{event_id}"),
        )
    }

    fn bridge_len(value: &serde_json::Value) -> usize {
        crate::mcp::tools::canvas::es_json_len(value)
    }

    #[test]
    fn a_record_changes_page_stops_before_the_budget_and_resumes_after_its_last_event() {
        // Fifty events of about 24,000 bridge characters each: far past the
        // real budget, so the page is cut well short of its limit.
        let events: Vec<_> = (0..50)
            .map(|index| synthetic_event(&format!("e{index}"), 4_000))
            .collect();
        let page = envelope_of(events, Some("e49"), super::RECORD_CHANGES_PAGE_MAX_CHARS);
        let kept = page["events"].as_array().unwrap();
        assert!(kept.len() < 50 && !kept.is_empty(), "{}", kept.len());
        assert!(bridge_len(&page) <= super::RECORD_CHANGES_PAGE_MAX_CHARS);
        assert_eq!(page["complete"], false);
        let last = kept.last().unwrap()["event_id"].as_str().unwrap();
        assert_eq!(page["next_cursor"], format!("sealed:{last}"));
        assert!(kept.iter().all(|event| event.get("oversized").is_none()));
    }

    #[test]
    fn an_event_that_can_never_fit_becomes_a_placeholder_even_first() {
        let budget = 4_000;
        // First event alone is too big for any page: a placeholder, and the
        // page goes on to the events after it.
        let page = envelope_of(
            vec![synthetic_event("big", 2_000), synthetic_event("small", 10)],
            None,
            budget,
        );
        assert!(bridge_len(&page) <= budget);
        assert_eq!(
            page["events"][0],
            json!({"event_id": "big", "type": "record.updated",
                   "created_at": "2026-09-28T00:00:00.000Z", "oversized": true})
        );
        assert_eq!(page["events"][1]["event_id"], "small");
        assert_eq!(page["complete"], true);

        // After an event that fits, a later one that fits a page of its own
        // leads the next page instead of being cut down.
        let page = envelope_of(
            vec![
                synthetic_event("a", 300),
                synthetic_event("b", 300),
                synthetic_event("c", 300),
            ],
            None,
            3_000,
        );
        assert!(bridge_len(&page) <= 3_000);
        let kept: Vec<_> = page["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["event_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(kept, ["a"]);
        assert_eq!(page["next_cursor"], "sealed:a");
        assert_eq!(page["complete"], false);
    }

    #[test]
    fn search_params_are_trimmed_bounded_and_default_to_the_shell_limit() {
        assert_eq!(
            parse_declared_read(RECORDS_SEARCH_NEED, Some(&json!({"query": " zebra "}))),
            Ok(DeclaredRead::Search {
                query: "zebra".into(),
                limit: 30
            })
        );
        assert_eq!(
            parse_declared_read(
                RECORDS_SEARCH_NEED,
                Some(&json!({"query": "é".repeat(200), "limit": 1}))
            ),
            Ok(DeclaredRead::Search {
                query: "é".repeat(200),
                limit: 1
            })
        );
        for params in [
            json!({}),
            json!({"query": ""}),
            json!({"query": "x".repeat(201)}),
            json!({"query": "zebra", "limit": 31}),
            json!({"query": "zebra", "limit": "30"}),
            json!({"query": "zebra", "limit": 1.5}),
            json!({"query": "zebra", "scope": "root"}),
            json!(["zebra"]),
        ] {
            assert_eq!(
                parse_declared_read(RECORDS_SEARCH_NEED, Some(&params)),
                Err("invalid_params"),
                "{params}"
            );
        }
        assert_eq!(
            parse_declared_read(RECORDS_SEARCH_NEED, None),
            Err("invalid_params")
        );
    }

    #[test]
    fn reference_params_are_bounded_and_unknown_needs_are_named() {
        assert_eq!(
            parse_declared_read(
                RECORDS_RESOLVE_REFERENCE_NEED,
                Some(&json!({"reference": "e233602"}))
            ),
            Ok(DeclaredRead::ResolveReference {
                reference: "e233602".into()
            })
        );
        for params in [
            json!({}),
            json!({"reference": "x".repeat(129)}),
            json!({"reference": "e233602", "links_limit": 5}),
        ] {
            assert_eq!(
                parse_declared_read(RECORDS_RESOLVE_REFERENCE_NEED, Some(&params)),
                Err("invalid_params")
            );
        }
        assert_eq!(
            parse_declared_read("attention.query.v1", None),
            Err("unknown_need")
        );
        assert_eq!(
            parse_declared_read("other.need.v1", Some(&json!({}))),
            Err("unknown_need")
        );
    }

    #[test]
    fn ambiguous_candidates_are_full_ids_in_order_without_duplicates() {
        let message = "get_record: reference 'c1d0' is ambiguous: C1D00000-0000-4000-8000-000000000031, \
                       c1d00000-0000-4000-8000-000000000032 — é c1d00000-0000-4000-8000-000000000031";
        assert_eq!(
            ambiguous_reference_candidates(message),
            vec![
                "c1d00000-0000-4000-8000-000000000031".to_string(),
                "c1d00000-0000-4000-8000-000000000032".to_string(),
            ]
        );
        assert!(ambiguous_reference_candidates("no ids — é").is_empty());
    }
}

#[cfg(test)]
mod reads_declaration_tests {
    //! Declared app read scope `reads.v1` (task `c2ca43a`, slice 1):
    //! normalization, catalog refusal, semantic inclusion and digest
    //! compatibility. Nothing here executes a read.

    use super::{
        alpha_tab_canonical_declaration, alpha_tab_declaration_digest, canonical_reads_declaration,
        parse_reads_declaration, reads_covers_grant, reads_widens, require_declaration,
        ReadsDeclaration,
    };
    use serde_json::{json, Value};

    fn parse(relations: Value) -> ReadsDeclaration {
        parse_reads_declaration(&json!({"relations": relations})).expect("valid reads")
    }

    fn scoped(relations: Value, scope: Value) -> ReadsDeclaration {
        parse_reads_declaration(&json!({"relations": relations, "scope": scope}))
            .expect("valid reads")
    }

    #[test]
    fn normalization_sorts_lowercases_and_dedups() {
        let reads = parse_reads_declaration(&json!({"relations": {
            "Records": ["name", "ID", "name", "body"],
            "facet_values": ["value", "key"],
        }}))
        .expect("valid reads");
        assert_eq!(
            canonical_reads_declaration(&reads),
            json!({"relations": {
                "facet_values": ["key", "value"],
                "records": ["body", "id", "name"],
            }})
        );
    }

    #[test]
    fn scope_ordering_is_not_consent() {
        let first = scoped(
            json!({"records": ["id"]}),
            json!([{"type": "WorkItem", "kind": "task"}, {"type": "WorkItem"}]),
        );
        let second = scoped(
            json!({"records": ["id"]}),
            json!([{"type": "WorkItem"}, {"type": "WorkItem", "kind": "task"}]),
        );
        assert_eq!(
            alpha_tab_declaration_digest(&json!({"needs": [], "effects": [],
                "reads": canonical_reads_declaration(&first)}))
            .unwrap(),
            alpha_tab_declaration_digest(&json!({"needs": [], "effects": [],
                "reads": canonical_reads_declaration(&second)}))
            .unwrap()
        );
    }

    #[test]
    fn unknown_relations_and_columns_are_refused() {
        for relations in [
            json!({"no_such_relation": ["id"]}),
            json!({"records": ["no_such_column"]}),
            json!({"records": []}),
            json!({"records": "id"}),
        ] {
            let error =
                parse_reads_declaration(&json!({"relations": relations})).expect_err("refused");
            assert!(error.contains("[invalid_reads]"), "{error}");
        }
        for reads in [
            json!("records"),
            json!({"scope": []}),
            json!({"relations": {"records": ["id"]}, "scope": []}),
            json!({"relations": {"records": ["id"]}, "scope": [{"kind": "task"}]}),
            json!({"relations": {"records": ["id"]}, "extra": 1}),
        ] {
            let error = parse_reads_declaration(&reads).expect_err("refused");
            assert!(error.contains("[invalid_reads]"), "{error}");
        }
    }

    #[test]
    fn case_normalized_duplicate_relations_are_refused() {
        // `Records` and `records` normalize to one relation: emitting two
        // grants would let the canonical map keep the last while coverage
        // reads the first, so parse refuses instead of merging.
        let error = parse_reads_declaration(&json!({"relations": {
            "Records": ["id"],
            "records": ["name"],
        }}))
        .expect_err("duplicate normalized relation refused");
        assert!(error.contains("[invalid_reads]"), "{error}");
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn duplicate_scope_entries_dedup() {
        let single = scoped(
            json!({"records": ["id"]}),
            json!([{"type": "WorkItem", "kind": "task"}]),
        );
        let doubled = scoped(
            json!({"records": ["id"]}),
            json!([
                {"type": "WorkItem", "kind": "task"},
                {"type": "WorkItem", "kind": "task"},
            ]),
        );
        assert_eq!(single, doubled);
        assert_eq!(
            canonical_reads_declaration(&single),
            canonical_reads_declaration(&doubled)
        );
    }

    #[test]
    fn inclusion_distinguishes_narrowing_from_widening() {
        let base = parse(json!({"records": ["id", "name"]}));
        // Equal and narrowed grants are covered.
        assert!(reads_covers_grant(&base, &base));
        assert!(reads_covers_grant(
            &base,
            &parse(json!({"records": ["id"]}))
        ));
        assert!(!reads_widens(&base, &parse(json!({"records": ["id"]}))));
        // Added columns and relations widen.
        assert!(reads_widens(
            &base,
            &parse(json!({"records": ["id", "name", "body"]}))
        ));
        assert!(reads_widens(
            &base,
            &parse(json!({"records": ["id"], "links": ["id"]}))
        ));
        // Scope: a scopeless old grant covers scoped new ones (narrowing),
        // but a scoped old grant never covers a scopeless new one.
        let scoped_new = scoped(
            json!({"records": ["id"]}),
            json!([{"type": "WorkItem", "kind": "task"}]),
        );
        assert!(reads_covers_grant(&base, &scoped_new));
        let scoped_old = scoped(
            json!({"records": ["id", "name"]}),
            json!([{"type": "WorkItem", "kind": "task"}]),
        );
        assert!(!reads_covers_grant(&scoped_old, &base));
        assert!(reads_widens(&scoped_old, &base));
        // Narrowing a scope entry (adding a kind) is not widening;
        // broadening one (dropping a kind, adding a type) is.
        let kinded = scoped(
            json!({"records": ["id"]}),
            json!([{"type": "WorkItem", "kind": "task"}]),
        );
        let unkinded = scoped(json!({"records": ["id"]}), json!([{"type": "WorkItem"}]));
        assert!(reads_covers_grant(&unkinded, &kinded));
        assert!(!reads_widens(&unkinded, &kinded));
        assert!(reads_widens(&kinded, &unkinded));
        let wider_scope = scoped(
            json!({"records": ["id"]}),
            json!([{"type": "WorkItem", "kind": "task"}, {"type": "Entity"}]),
        );
        assert!(reads_widens(&kinded, &wider_scope));
    }

    #[test]
    fn legacy_declarations_keep_their_digests() {
        // Golden vectors from `sql_snapshot_tests`: no `reads` key means
        // the canonical form — and therefore the digest — is untouched.
        let string_only =
            json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]});
        assert_eq!(
            alpha_tab_declaration_digest(&string_only).unwrap(),
            "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15"
        );
        let param_less = json!({"needs": ["attention.query.v1",
            {"need": "sql.snapshot.v1", "key": "lane.a", "label": "A",
                "sql": "SELECT id FROM records"}], "effects": []});
        assert_eq!(
            alpha_tab_declaration_digest(&param_less).unwrap(),
            "bc0b2a5c9e4f8caa8e5fb7bd3a31268a72e93ba976eba4a5061bdaf81c30b989"
        );
    }

    #[test]
    fn reads_participates_in_the_digest() {
        let without = json!({"needs": ["attention.query.v1"], "effects": []});
        let plain = alpha_tab_declaration_digest(&without).unwrap();
        let with_reads = json!({"needs": ["attention.query.v1"], "effects": [],
            "reads": {"relations": {"records": ["id", "name"]}}});
        let read_digest = alpha_tab_declaration_digest(&with_reads).unwrap();
        assert_ne!(plain, read_digest);
        // Reordered grants digest identically; widened ones do not.
        let reordered = json!({"needs": ["attention.query.v1"], "effects": [],
            "reads": {"relations": {"records": ["name", "id"]}}});
        assert_eq!(
            read_digest,
            alpha_tab_declaration_digest(&reordered).unwrap()
        );
        let widened = json!({"needs": ["attention.query.v1"], "effects": [],
            "reads": {"relations": {"records": ["body", "id", "name"]}}});
        assert_ne!(read_digest, alpha_tab_declaration_digest(&widened).unwrap());
        // An invalid `reads` fails closed at digest time, never as absent.
        let invalid = json!({"needs": ["attention.query.v1"], "effects": [],
            "reads": {"relations": {"records": ["no_such_column"]}}});
        let error = alpha_tab_canonical_declaration(&invalid).expect_err("refused");
        assert!(error.to_string().contains("[invalid_reads]"));
    }

    #[test]
    fn install_defers_reads_until_display_and_admission_exist() {
        let valid = json!({"needs": ["attention.query.v1"], "effects": [],
            "reads": {"relations": {"records": ["id"]}}});
        require_declaration(&valid).expect_err("app reads must not enter the tab install path");
        let unknown_key = json!({"needs": ["attention.query.v1"], "effects": [],
            "reads": {"relations": {"records": ["id"]}}, "extra": 1});
        require_declaration(&unknown_key).expect_err("unknown key refused");
        let legacy = json!({"needs": ["attention.query.v1"], "effects": []});
        require_declaration(&legacy).expect("legacy tab declarations still work");
    }
}

#[cfg(test)]
mod flat_select_analyzer_tests {
    //! Flat single-table SELECT analyzer (task `c2ca43a`, slice 2, first
    //! increment): admitted dependencies and fail-closed refusals. Pure —
    //! no database, no admission wiring.

    use super::{analyze_flat_select_reads, reads_covers_grant};
    use serde_json::json;

    fn columns(sql: &str) -> Vec<String> {
        let analyzed = analyze_flat_select_reads(sql).expect("admitted");
        assert!(analyzed.scopes.is_empty(), "analyzer emits no scopes");
        assert_eq!(analyzed.grants.len(), 1, "analyzer emits one grant");
        assert_eq!(analyzed.grants[0].relation, "records");
        analyzed.grants[0].columns.clone()
    }

    fn refused(sql: &str) -> String {
        let error = analyze_flat_select_reads(sql).expect_err("refused");
        assert!(error.contains("[invalid_sql]"), "{error}");
        error
    }

    #[test]
    fn projected_and_where_columns_are_tracked() {
        assert_eq!(
            columns("SELECT id, name FROM records WHERE lifecycle = 'open'"),
            vec!["id", "lifecycle", "name"],
        );
    }

    #[test]
    fn app_grouped_clauses_track_all_dependencies() {
        assert_eq!(
            columns("SELECT count(*) FROM records GROUP BY kind HAVING count(*) FILTER (WHERE lifecycle = 'open') > 0"),
            vec!["kind", "lifecycle"],
        );
        assert_eq!(
            columns("SELECT 1 FROM records GROUP BY name HAVING count(*) > 0"),
            vec!["name"],
        );
        let reads = analyze_flat_select_reads(
            "SELECT r.type, count(*) FROM records r JOIN links l ON r.id = l.source_id GROUP BY r.type HAVING count(*) FILTER (WHERE l.note IS NOT NULL) > 0 ORDER BY r.type",
        ).unwrap();
        assert_eq!(reads.grants[0].relation, "links");
        assert_eq!(reads.grants[0].columns, vec!["note", "source_id"]);
        assert_eq!(reads.grants[1].relation, "records");
        assert_eq!(reads.grants[1].columns, vec!["id", "type"]);
    }

    #[test]
    fn app_grouped_clauses_refuse_unresolved_and_nested_reads() {
        for sql in [
            "SELECT count(*) FROM records GROUP BY unknown_column",
            "SELECT count(*) FROM records GROUP BY kind HAVING unknown_column > 0",
            "SELECT count(*) AS total FROM records GROUP BY kind HAVING total > 0",
            "SELECT count(*) FROM records a JOIN records b ON a.id = b.id GROUP BY kind",
            "SELECT count(*) FROM records GROUP BY (SELECT max(local_seq) FROM content_events)",
            "SELECT count(*) FROM records GROUP BY kind HAVING count(*) > (SELECT count(*) FROM links)",
        ] {
            refused(sql);
        }
    }

    #[test]
    fn aliases_and_expressions_resolve() {
        // Alias prefixes resolve; expression columns (upper, ||, CASE,
        // ORDER BY) are tracked; case folds; duplicates collapse.
        assert_eq!(
            columns(
                "SELECT r.id, upper(r.name) || r.body AS label \
                 FROM records AS r \
                 WHERE CASE WHEN r.lifecycle = 'open' THEN 1 ELSE 0 END = 1 \
                 ORDER BY r.created_at_ms DESC LIMIT 10"
            ),
            vec!["body", "created_at_ms", "id", "lifecycle", "name"],
        );
    }

    #[test]
    fn analyzed_reads_fit_declared_grants() {
        let analyzed = analyze_flat_select_reads("SELECT id FROM records").expect("admitted");
        let declared = super::parse_reads_declaration(&json!({"relations": {
            "records": ["id", "name"],
        }}))
        .expect("valid reads");
        assert!(reads_covers_grant(&declared, &analyzed));
        assert!(!reads_covers_grant(&analyzed, &declared));
    }

    #[test]
    fn constant_query_keeps_its_relation_grant() {
        // No column is referenced, but the relation is still read: the
        // grant is seeded with empty columns, never dropped.
        assert_eq!(columns("SELECT 1 FROM records"), Vec::<String>::new());
        assert_eq!(
            columns("SELECT 'x', 2 + 2 FROM records WHERE 1 = 1 LIMIT 1"),
            Vec::<String>::new(),
        );
    }

    #[test]
    fn joins_and_subqueries_are_refused() {
        refused("SELECT id FROM records, links");
        refused("SELECT id FROM records WHERE id IN (SELECT record_id FROM links)");
        refused("SELECT id FROM (SELECT id FROM records)");
        refused("SELECT (SELECT max(local_seq) FROM content_events) FROM records");
        refused("SELECT sum(*) FROM records");
    }

    #[test]
    fn star_expands_to_the_full_sorted_column_set() {
        // Exact catalog expansion for `records`: sorted, deduplicated.
        assert_eq!(
            columns("SELECT * FROM records"),
            vec![
                "archived",
                "body",
                "created_at",
                "created_at_ms",
                "deleted_at",
                "deleted_at_ms",
                "home_id",
                "id",
                "is_current",
                "kind",
                "last_activity_at",
                "last_activity_at_ms",
                "lifecycle",
                "maturity",
                "name",
                "persistence",
                "successor_count",
                "summary",
                "type",
                "updated_at",
                "updated_at_ms",
            ],
        );
        // Star plus explicit columns dedups; qualified star resolves the alias.
        assert_eq!(
            columns("SELECT *, r.id, r.name FROM records AS r"),
            columns("SELECT r.* FROM records AS r"),
        );
        // A hidden table name and an unknown alias stay refused.
        refused("SELECT records.* FROM records AS r");
        refused("SELECT q.* FROM records AS r");
    }

    #[test]
    fn count_star_is_a_relation_read_with_tracked_filters() {
        // No columns beyond the seeded relation grant ...
        assert_eq!(
            columns("SELECT count(*) FROM records"),
            Vec::<String>::new()
        );
        // ... but WHERE and FILTER columns are tracked.
        assert_eq!(
            columns("SELECT count(*) FROM records WHERE lifecycle = 'open'"),
            vec!["lifecycle"],
        );
        assert_eq!(
            columns("SELECT count(*) FILTER (WHERE lifecycle = 'open') FROM records"),
            vec!["lifecycle"],
        );
    }

    #[test]
    fn unknown_names_and_hidden_qualifiers_are_refused() {
        refused("SELECT no_such_column FROM records");
        refused("SELECT id FROM no_such_relation");
        refused("SELECT links.id FROM records");
        // An alias hides the table name, as SQLite resolves it.
        refused("SELECT records.id FROM records AS r");
        refused("SELECT main.records.id FROM records");
        refused("WITH open AS (SELECT id FROM records) SELECT id FROM open");
        refused("SELECT id FROM records UNION SELECT id FROM records");
        refused("SELECT id, name FROM records; SELECT id FROM links");
        refused("DELETE FROM records");
        refused("");
    }
}

#[cfg(test)]
mod inner_join_analyzer_tests {
    //! Ordinary INNER JOIN unit (task `c2ca43a`, slice 2): exactly two
    //! distinctly-aliased tables, qualified references only. Pure.

    use super::{analyze_flat_select_reads, parse_reads_declaration, reads_covers_grant};
    use super::{ReadGrant, ReadsDeclaration};
    use serde_json::json;

    fn analyzed(sql: &str) -> ReadsDeclaration {
        analyze_flat_select_reads(sql).expect("admitted")
    }

    fn refused(sql: &str) -> String {
        let error = analyze_flat_select_reads(sql).expect_err("refused");
        assert!(error.contains("[invalid_sql]"), "{error}");
        error
    }

    #[test]
    fn inner_join_tracks_both_relations() {
        assert_eq!(
            analyzed(
                "SELECT a.id, b.source_id FROM records AS a \
                 INNER JOIN links AS b ON a.id = b.source_id \
                 WHERE a.lifecycle = 'open' ORDER BY b.created_at_ms LIMIT 5"
            ),
            ReadsDeclaration {
                grants: vec![
                    ReadGrant {
                        relation: "links".to_string(),
                        columns: vec!["created_at_ms".to_string(), "source_id".to_string()],
                    },
                    ReadGrant {
                        relation: "records".to_string(),
                        columns: vec!["id".to_string(), "lifecycle".to_string()],
                    },
                ],
                scopes: Vec::new(),
            }
        );
        // Bare JOIN is the same inner join; ON may carry extra predicates.
        assert_eq!(
            analyzed(
                "SELECT a.id, b.target_id FROM records AS a \
                 JOIN links AS b ON a.id = b.source_id AND b.relationship = 'part_of'"
            )
            .grants[0]
                .columns,
            vec![
                "relationship".to_string(),
                "source_id".to_string(),
                "target_id".to_string()
            ],
        );
    }

    #[test]
    fn join_shape_violations_are_refused() {
        refused("SELECT a.id, b.source_id FROM records AS a JOIN links AS b USING (id)");
        refused("SELECT a.id, b.source_id FROM records AS a JOIN links AS b");
        refused("SELECT a.id, b.source_id FROM records AS a, links AS b");
        refused("SELECT a.id FROM records AS a JOIN links AS a ON a.id = a.id");
        refused("SELECT id, b.source_id FROM records AS a JOIN links AS b ON a.id = b.source_id");
        refused("SELECT records.id, b.source_id FROM records AS a JOIN links AS b ON a.id = b.source_id");
        refused("SELECT a.id, b.source_id FROM records AS a JOIN links AS b ON a.id IN (SELECT record_id FROM facet_values)");
        refused("SELECT sum(*) FROM records AS a JOIN links AS b ON a.id = b.source_id");
        refused(
            "SELECT a.id, b.no_such_column FROM records AS a JOIN links AS b ON a.id = b.source_id",
        );
        refused("WITH x AS (SELECT id FROM records) SELECT x.id, b.source_id FROM x JOIN links AS b ON x.id = b.source_id");
    }

    #[test]
    fn constant_join_keeps_both_relation_grants() {
        // A constant ON reads no columns but still reads both relations:
        // dropping either grant would bypass undeclared-relation admission.
        assert_eq!(
            analyzed("SELECT 1 FROM records AS a JOIN links AS b ON 1 = 1"),
            ReadsDeclaration {
                grants: vec![
                    ReadGrant {
                        relation: "links".to_string(),
                        columns: Vec::new(),
                    },
                    ReadGrant {
                        relation: "records".to_string(),
                        columns: Vec::new(),
                    },
                ],
                scopes: Vec::new(),
            }
        );
    }

    #[test]
    fn self_join_merges_into_one_grant() {
        let merged = analyzed(
            "SELECT a.id, b.name FROM records AS a \
             JOIN records AS b ON a.home_id = b.id",
        );
        assert_eq!(merged.grants.len(), 1, "self-join merges grants");
        assert_eq!(merged.grants[0].relation, "records");
        assert_eq!(merged.grants[0].columns, vec!["home_id", "id", "name"]);
    }

    #[test]
    fn coverage_denies_undeclared_relations_with_empty_columns() {
        let declared = parse_reads_declaration(&json!({"relations": {
            "records": ["id"],
        }}))
        .expect("valid reads");
        let constant_join = analyzed("SELECT 1 FROM records AS a JOIN links AS b ON 1 = 1");
        // The empty-column links grant is still an undeclared relation.
        assert!(!reads_covers_grant(&declared, &constant_join));
        let widened = parse_reads_declaration(&json!({"relations": {
            "records": ["id"],
            "links": ["id"],
        }}))
        .expect("valid reads");
        assert!(reads_covers_grant(&widened, &constant_join));
    }

    #[test]
    fn join_star_expands_each_side_and_merges_self_joins() {
        let expanded = analyzed(
            "SELECT *, b.note FROM records AS a \
             JOIN links AS b ON a.id = b.source_id",
        );
        assert_eq!(expanded.grants.len(), 2);
        assert_eq!(expanded.grants[0].relation, "links");
        assert_eq!(
            expanded.grants[0].columns,
            vec![
                "created_at",
                "created_at_ms",
                "id",
                "note",
                "relationship",
                "source_id",
                "target_id",
            ],
        );
        assert_eq!(expanded.grants[1].relation, "records");
        assert_eq!(expanded.grants[1].columns.len(), 21, "full records set");
        // Scoped stars expand only their own side (records keeps just the ON column).
        let scoped = analyzed("SELECT b.* FROM records AS a JOIN links AS b ON a.id = b.source_id");
        assert_eq!(scoped.grants[1].columns, vec!["id".to_string()]);
        assert_eq!(scoped.grants[0].columns.len(), 7, "full links set");
        // ... and merge on a self-join.
        let merged = analyzed("SELECT * FROM records AS a JOIN records AS b ON a.home_id = b.id");
        assert_eq!(merged.grants.len(), 1, "self-join star merges");
        assert_eq!(merged.grants[0].columns.len(), 21, "full records set");
    }

    #[test]
    fn star_and_count_coverage_is_exact() {
        let full = parse_reads_declaration(&json!({"relations": {
            "records": ["archived", "body", "created_at", "created_at_ms", "deleted_at",
                "deleted_at_ms", "home_id", "id", "is_current", "kind",
                "last_activity_at", "last_activity_at_ms", "lifecycle", "maturity",
                "name", "persistence", "successor_count", "summary", "type",
                "updated_at", "updated_at_ms"],
        }}))
        .expect("valid reads");
        assert!(reads_covers_grant(
            &full,
            &analyzed("SELECT * FROM records")
        ));
        // One missing expanded column denies coverage.
        let missing = parse_reads_declaration(&json!({"relations": {
            "records": ["archived", "body", "created_at", "created_at_ms", "deleted_at",
                "deleted_at_ms", "home_id", "id", "is_current", "kind",
                "last_activity_at", "last_activity_at_ms", "lifecycle", "maturity",
                "name", "persistence", "successor_count", "summary", "type",
                "updated_at"],
        }}))
        .expect("valid reads");
        assert!(!reads_covers_grant(
            &missing,
            &analyzed("SELECT * FROM records")
        ));
        // count(*) over a join is denied when the joined relation is undeclared.
        let records_only = parse_reads_declaration(&json!({"relations": {
            "records": ["id"],
        }}))
        .expect("valid reads");
        assert!(!reads_covers_grant(
            &records_only,
            &analyzed("SELECT count(*) FROM records AS a JOIN links AS b ON a.id = b.source_id"),
        ));
        // count(*) with a WHERE tracks the filter column.
        let filtered = analyzed(
            "SELECT a.id, count(*) FROM records AS a \
             JOIN links AS b ON a.id = b.source_id WHERE b.relationship = 'part_of'",
        );
        assert_eq!(
            filtered.grants[0].columns,
            vec!["relationship", "source_id"]
        );
    }

    #[test]
    fn left_and_three_table_chains_are_tracked() {
        // LEFT JOIN admits missing right sides; the read shape is unchanged.
        let left = analyzed(
            "SELECT a.id, b.source_id FROM records AS a \
             LEFT JOIN links AS b ON a.id = b.source_id WHERE b.relationship = 'part_of'",
        );
        assert_eq!(left.grants[0].columns, vec!["relationship", "source_id"]);
        assert_eq!(left.grants[1].columns, vec!["id"]);
        // Three-table INNER chain across three relations.
        let chain = analyzed(
            "SELECT a.name, c.value FROM records AS a \
             JOIN links AS b ON a.id = b.source_id \
             JOIN facet_values AS c ON c.record_id = b.target_id",
        );
        assert_eq!(chain.grants.len(), 3);
        assert_eq!(chain.grants[0].relation, "facet_values");
        assert_eq!(chain.grants[0].columns, vec!["record_id", "value"]);
        assert_eq!(chain.grants[1].relation, "links");
        assert_eq!(chain.grants[1].columns, vec!["source_id", "target_id"]);
        assert_eq!(chain.grants[2].relation, "records");
        assert_eq!(chain.grants[2].columns, vec!["id", "name"]);
        // Bare table names establish labels too.
        let bare = analyzed(
            "SELECT records.id, links.source_id FROM records \
             JOIN links ON records.id = links.source_id",
        );
        assert_eq!(bare.grants[0].columns, vec!["source_id"]);
        assert_eq!(bare.grants[1].columns, vec!["id"]);
        // Unprojected ON/filter columns are tracked; untouched sides seed empty.
        let side = analyzed(
            "SELECT 1 FROM records AS a \
             LEFT JOIN links AS b ON b.source_id = b.target_id WHERE b.relationship = 'x'",
        );
        assert_eq!(
            side.grants[0].columns,
            vec!["relationship", "source_id", "target_id"]
        );
        assert_eq!(side.grants[1].columns, Vec::<String>::new());
    }

    #[test]
    fn unqualified_names_resolve_only_when_unique() {
        // `lifecycle` lives only in records; `id` lives in both.
        let unique = analyzed(
            "SELECT lifecycle, b.source_id FROM records AS a \
             JOIN links AS b ON a.id = b.source_id",
        );
        assert_eq!(unique.grants[1].columns, vec!["id", "lifecycle"]);
        refused(
            "SELECT id, b.source_id FROM records AS a \
             JOIN links AS b ON a.id = b.source_id",
        );
        // Self-join ambiguity counts scope entries, not base relations.
        refused("SELECT id FROM records AS a JOIN records AS b ON a.home_id = b.id");
        refused("SELECT * FROM records JOIN records ON records.id = records.id");
        // Duplicate labels (bare or aliased) are refused outright.
        refused("SELECT a.id FROM records AS a JOIN links AS a ON a.id = a.id");
    }

    #[test]
    fn on_clauses_see_only_their_prefix_scope() {
        // The first ON may use the left side and the new right side ...
        analyzed(
            "SELECT a.id FROM records AS a \
             JOIN links AS b ON a.id = b.source_id \
             JOIN facet_values AS c ON c.record_id = a.id",
        );
        // ... but never a table joined later (forward reference).
        refused(
            "SELECT a.id FROM records AS a \
             JOIN links AS b ON a.id = c.record_id \
             JOIN facet_values AS c ON c.record_id = b.target_id",
        );
        // Unqualified ON columns resolve within the prefix scope.
        refused(
            "SELECT a.id FROM records AS a \
             JOIN links AS b ON id = b.source_id \
             JOIN facet_values AS c ON c.record_id = b.target_id",
        );
    }
}

#[cfg(test)]
mod app_sql_admission_tests {
    //! Shared enforcement predicate (task `c2ca43a`, slice 2): pure admit
    //! checks of SQL against declared `reads.v1`. No execution, no wiring.

    use super::{admit_app_sql_reads, parse_reads_declaration, ReadsDeclaration};
    use serde_json::json;

    fn declared(relations: serde_json::Value) -> ReadsDeclaration {
        parse_reads_declaration(&json!({"relations": relations})).expect("valid reads")
    }

    #[test]
    fn exact_grants_are_admitted() {
        let scope = declared(json!({"records": ["id", "lifecycle"], "links": ["source_id"]}));
        let admitted = admit_app_sql_reads(
            &scope,
            "SELECT a.id FROM records AS a JOIN links AS b ON a.id = b.source_id \
             WHERE a.lifecycle = 'open'",
        )
        .expect("admitted");
        assert_eq!(admitted.grants.len(), 2);
        // Column-less reads need only their relation.
        admit_app_sql_reads(&scope, "SELECT 1 FROM records").expect("constant admitted");
        admit_app_sql_reads(&scope, "SELECT count(*) FROM records").expect("count admitted");
    }

    #[test]
    fn undeclared_relations_are_named_without_leaks() {
        let scope = declared(json!({"records": ["id"]}));
        let error = admit_app_sql_reads(
            &scope,
            "SELECT a.id, b.source_id FROM records AS a \
             JOIN links AS b ON a.id = b.source_id",
        )
        .expect_err("refused");
        assert_eq!(error.code(), "undeclared_relation");
        assert_eq!(
            error.to_string(),
            "undeclared_relation: 'links' is not granted"
        );
        assert!(!error.to_string().contains("SELECT"), "no SQL text leaks");
    }

    #[test]
    fn undeclared_columns_are_named_per_clause() {
        let scope = declared(json!({
            "records": ["id"],
            "links": ["source_id", "target_id"],
        }));
        for sql in [
            "SELECT a.id, a.name FROM records AS a",
            "SELECT a.id FROM records AS a WHERE a.lifecycle = 'open'",
            "SELECT a.id FROM records AS a JOIN links AS b \
             ON a.id = b.source_id AND b.relationship = 'part_of'",
            "SELECT a.id FROM records AS a JOIN links AS b \
             ON a.id = b.source_id ORDER BY b.created_at_ms",
            "SELECT a.id, count(*) FILTER (WHERE a.lifecycle = 'open') FROM records AS a",
            "SELECT count(*) FROM records GROUP BY kind",
            "SELECT count(*) FROM records GROUP BY id HAVING count(*) FILTER (WHERE lifecycle = 'open') > 0",
            "SELECT * FROM records",
        ] {
            let error = admit_app_sql_reads(&scope, sql).expect_err("refused");
            assert_eq!(error.code(), "undeclared_column", "{sql}");
        }
    }

    #[test]
    fn stars_expand_under_matching_grants() {
        let links = declared(json!({"links": [
            "created_at", "created_at_ms", "id", "note", "relationship", "source_id",
            "target_id",
        ]}));
        let admitted = admit_app_sql_reads(&links, "SELECT * FROM links").expect("star admitted");
        assert_eq!(admitted.grants[0].columns.len(), 7);
        let both = declared(json!({
            "records": ["id"],
            "links": ["created_at", "created_at_ms", "id", "note", "relationship",
                "source_id", "target_id"],
        }));
        admit_app_sql_reads(
            &both,
            "SELECT a.id, b.* FROM records AS a JOIN links AS b ON a.id = b.source_id",
        )
        .expect("scoped star admitted");
    }

    #[test]
    fn unsupported_shapes_and_scopes_fail_closed() {
        let scope = declared(json!({"records": ["id"]}));
        for sql in [
            "WITH x AS (SELECT id FROM records) SELECT id FROM x",
            "SELECT id FROM records WHERE id IN (SELECT record_id FROM links)",
            "SELECT id, name FROM records; SELECT id FROM records",
        ] {
            assert_eq!(
                admit_app_sql_reads(&scope, sql)
                    .expect_err("refused")
                    .code(),
                "unsupported_sql"
            );
        }
        // Admission preserves the scope even without a WHERE predicate.
        // Only the app executor's row fence establishes the restriction.
        let scoped = parse_reads_declaration(&json!({
            "relations": {"records": ["id"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .expect("valid reads");
        let admitted = admit_app_sql_reads(&scoped, "SELECT id FROM records").unwrap();
        assert_eq!(admitted.scopes, scoped.scopes);
        let chunks = parse_reads_declaration(&json!({
            "relations": {"body_blocks": ["text"]},
            "scope": [{"type": "WorkItem", "kind": "task"}],
        }))
        .unwrap();
        let admitted = admit_app_sql_reads(&chunks, "SELECT text FROM body_blocks").unwrap();
        assert_eq!(admitted.scopes, chunks.scopes);
        for (relation, column) in [
            ("body_task_items", "checked"),
            ("facet_times", "start_date"),
        ] {
            let owner_projection = parse_reads_declaration(&json!({
                "relations": {relation: [column]},
                "scope": [{"type": "Document", "kind": "note"}],
            }))
            .unwrap();
            let admitted = admit_app_sql_reads(
                &owner_projection,
                &format!("SELECT {column} FROM {relation}"),
            )
            .unwrap();
            assert_eq!(admitted.scopes, owner_projection.scopes);
        }
        let unsupported = parse_reads_declaration(&json!({
            "relations": {"records": ["id"], "links": ["id"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .unwrap();
        let error =
            admit_app_sql_reads(&unsupported, "SELECT id FROM records").expect_err("refused");
        assert_eq!(error.code(), "unsupported_read_scope");
    }

    #[test]
    fn workspace_counters_are_forbidden_even_when_granted() {
        // The declaration grants both counters outright: admission must
        // still refuse every reference shape, since order/filter over a
        // global counter is a workspace-activity side channel.
        let granted = declared(json!({
            "content_events": ["local_seq", "id", "record_id"],
            "facet_observations": ["event_seq", "id", "record_id"],
        }));
        for sql in [
            "SELECT local_seq FROM content_events",
            "SELECT e.local_seq FROM content_events AS e",
            "SELECT id FROM content_events WHERE local_seq > 10",
            "SELECT id FROM content_events ORDER BY local_seq LIMIT 5",
            "SELECT count(*) FILTER (WHERE local_seq > 10) FROM content_events",
            "SELECT count(*) FROM content_events GROUP BY local_seq",
            "SELECT * FROM content_events",
            "SELECT event_seq FROM facet_observations",
            "SELECT o.event_seq FROM facet_observations AS o WHERE o.event_seq > 1",
            "SELECT count(*) FROM facet_observations GROUP BY id HAVING max(event_seq) > 0",
        ] {
            let error = admit_app_sql_reads(&granted, sql).expect_err("refused");
            assert_eq!(error.code(), "workspace_counter_forbidden", "{sql}");
        }
        // Ordinary non-counter reads stay admissible under coverage.
        let admitted = admit_app_sql_reads(
            &granted,
            "SELECT id, record_id FROM content_events ORDER BY id LIMIT 10",
        )
        .expect("non-counter read admitted");
        assert_eq!(admitted.grants[0].relation, "content_events");
    }

    #[test]
    fn response_projection_hides_counters_and_tokens_content() {
        use crate::query::sql::SqlResult;

        fn result_with(as_of_seq: i64, rows: serde_json::Value) -> SqlResult {
            SqlResult {
                columns: vec!["id".to_string()],
                rows: rows.as_array().unwrap().clone(),
                row_count: 1,
                truncated: false,
                truncation_hint: None,
                as_of_seq,
                now_ms_ms: None,
                time_dependent: false,
                assumed_order: None,
            }
        }
        fn keys(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, nested) in map {
                        out.push(key.clone());
                        keys(nested, out);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        keys(item, out);
                    }
                }
                _ => {}
            }
        }

        let rows = json!([{"id": "abc"}]);
        let first = super::AppSqlResponse::project(&result_with(11, rows.clone()));
        let second = super::AppSqlResponse::project(&result_with(12, rows.clone()));
        // Recursive metadata check: no counters, observations, or VM state.
        let mut found = Vec::new();
        keys(&serde_json::to_value(&first).unwrap(), &mut found);
        for banned in [
            "as_of_seq",
            "observation",
            "vm_",
            "truncation_hint",
            "assumed_order",
        ] {
            assert!(
                found.iter().all(|key| !key.contains(banned)),
                "metadata leaks {banned}: {found:?}"
            );
        }
        // Same visible data under a different workspace counter: same token.
        assert_eq!(first.revision_token, second.revision_token);
        // Clock-only changes cannot fake a content change either.
        let clocked = SqlResult {
            now_ms_ms: Some(1_700_000_000_000),
            time_dependent: true,
            ..result_with(99, rows.clone())
        };
        assert_eq!(
            first.revision_token,
            super::AppSqlResponse::project(&clocked).revision_token
        );
        // Changed rows retoken ...
        let changed = super::AppSqlResponse::project(&result_with(11, json!([{"id": "abd"}])));
        assert_ne!(first.revision_token, changed.revision_token);
        // ... and so does the same prefix going complete -> truncated: the
        // response meaning changed even though the visible rows did not.
        let cut = SqlResult {
            truncated: true,
            ..result_with(11, rows.clone())
        };
        assert_ne!(
            first.revision_token,
            super::AppSqlResponse::project(&cut).revision_token
        );
        assert!(first.row_count_complete);
        assert_eq!(
            first.row_count, 1,
            "visible rows, never a workspace counter"
        );
    }
}

#[cfg(test)]
mod app_read_info_tests {
    //! Read-info display model (task `c2ca43a`, slice 2): shared metadata
    //! from normalized declarations. No execution, no rendering.

    use super::{app_reads_widening_note, describe_app_reads, parse_reads_declaration};
    use serde_json::json;

    fn described(
        relations: serde_json::Value,
        scope: Option<serde_json::Value>,
    ) -> super::AppReadInfo {
        let mut value = json!({"relations": relations});
        if let Some(scope) = scope {
            value["scope"] = scope;
        }
        describe_app_reads(&parse_reads_declaration(&value).expect("valid reads"))
    }

    #[test]
    fn summaries_scopes_and_private_state() {
        let info = described(json!({"records": ["id", "name"]}), None);
        assert_eq!(info.relations[0].summary, "reads id and name from records");
        assert_eq!(info.scope_description, None);
        assert!(!info.relations[0].only_you_see_this);
        let single = described(json!({"records": ["id"]}), None);
        assert_eq!(single.relations[0].summary, "reads id from records");
        let many = described(json!({"links": ["id", "source_id", "target_id"]}), None);
        assert_eq!(
            many.relations[0].summary,
            "reads id, source_id and 1 more from links"
        );
        let scoped = described(
            json!({"records": ["id"]}),
            Some(json!([{"type": "WorkItem", "kind": "task"}])),
        );
        assert_eq!(
            scoped.scope_description,
            Some("declares type 'WorkItem' kind 'task'".to_string())
        );
        let queued = described(json!({"messages_awaiting_reply": ["message_id"]}), None);
        assert!(queued.relations[0].only_you_see_this);
    }

    #[test]
    fn broad_badge_needs_scope_or_record_text() {
        // Viewer-wide scope is broad even with narrow columns ...
        assert!(described(json!({"records": ["id"]}), None).broad_access);
        // ... a narrowed scope without record text is not ...
        let narrow = described(
            json!({"records": ["id"]}),
            Some(json!([{"type": "WorkItem"}])),
        );
        assert!(!narrow.broad_access);
        // ... but full body text, directly or in reassemblable chunks, is.
        let textual = described(
            json!({"records": ["body", "id"]}),
            Some(json!([{"type": "WorkItem"}])),
        );
        assert!(textual.broad_access);
        let chunks = described(
            json!({"body_blocks": ["record_id", "text"]}),
            Some(json!([{"type": "WorkItem"}])),
        );
        assert!(chunks.broad_access);
        // Empty grants access nothing: no badge even when scopeless.
        let empty = super::describe_app_reads(&super::ReadsDeclaration {
            grants: Vec::new(),
            scopes: Vec::new(),
        });
        assert!(!empty.broad_access);
    }

    #[test]
    fn forbidden_counters_are_reported_not_hidden() {
        let info = described(json!({"content_events": ["id", "local_seq"]}), None);
        assert_eq!(info.relations[0].counters_included, vec!["local_seq"]);
        assert_eq!(
            info.relations[0].summary,
            "reads id and local_seq from content_events"
        );
        assert_eq!(info.capability_notes.len(), 1);
        assert!(info.capability_notes[0].contains("currently refuses"));
        let scoped = described(
            json!({"records": ["id"]}),
            Some(json!([{"type": "WorkItem"}])),
        );
        assert!(scoped.capability_notes.is_empty());
        let chunks = described(
            json!({"body_blocks": ["record_id", "text"]}),
            Some(json!([{"type": "WorkItem"}])),
        );
        assert!(chunks.capability_notes.is_empty());
        assert!(chunks.broad_access);
        for (relation, column) in [
            ("body_task_items", "checked"),
            ("facet_times", "start_date"),
        ] {
            let owner_projection = described(
                json!({relation: [column]}),
                Some(json!([{"type": "Document", "kind": "note"}])),
            );
            assert!(owner_projection.capability_notes.is_empty());
            assert!(!owner_projection.broad_access);
        }
        let unsupported = described(
            json!({"links": ["id"]}),
            Some(json!([{"type": "WorkItem"}])),
        );
        assert_eq!(unsupported.capability_notes.len(), 1);
        assert!(unsupported.capability_notes[0].contains("support only records"));
    }

    #[test]
    fn widening_note_only_fires_on_widening() {
        let base = parse_reads_declaration(&json!({"relations": {"records": ["id"]}})).unwrap();
        assert_eq!(app_reads_widening_note(&base, &base), None);
        let wider_cols =
            parse_reads_declaration(&json!({"relations": {"records": ["body", "id"]}})).unwrap();
        assert_eq!(app_reads_widening_note(&wider_cols, &base), None);
        assert_eq!(
            app_reads_widening_note(&base, &wider_cols),
            Some("This update widens app reads: 'records' gains body.".to_string())
        );
        let wider_rel =
            parse_reads_declaration(&json!({"relations": {"records": ["id"], "links": ["id"]}}))
                .unwrap();
        assert_eq!(
            app_reads_widening_note(&base, &wider_rel),
            Some("This update widens app reads: new relation 'links'.".to_string())
        );
        let scoped = parse_reads_declaration(&json!({
            "relations": {"records": ["id"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .unwrap();
        assert_eq!(
            app_reads_widening_note(&scoped, &base),
            Some("This update widens app reads: broader type/kind scope.".to_string())
        );
        // Simultaneous column and scope widening mentions both ...
        let scoped_cols = parse_reads_declaration(&json!({
            "relations": {"records": ["id"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .unwrap();
        let wide_cols = parse_reads_declaration(&json!({
            "relations": {"records": ["body", "id"]},
        }))
        .unwrap();
        assert_eq!(
            app_reads_widening_note(&scoped_cols, &wide_cols),
            Some(
                "This update widens app reads: 'records' gains body; \
                 broader type/kind scope."
                    .to_string()
            )
        );
        // ... while equal or narrowed scopes with widened columns stay silent
        // about scope.
        let scoped_same = parse_reads_declaration(&json!({
            "relations": {"records": ["body", "id"]},
            "scope": [{"type": "WorkItem"}],
        }))
        .unwrap();
        assert_eq!(
            app_reads_widening_note(&scoped_cols, &scoped_same),
            Some("This update widens app reads: 'records' gains body.".to_string())
        );
        let narrowed_scope = parse_reads_declaration(&json!({
            "relations": {"records": ["body", "id"]},
            "scope": [{"type": "WorkItem", "kind": "task"}],
        }))
        .unwrap();
        assert_eq!(
            app_reads_widening_note(&scoped_cols, &narrowed_scope),
            Some("This update widens app reads: 'records' gains body.".to_string())
        );
        // New relations broaden scope the same independent way.
        let wide_rel = parse_reads_declaration(&json!({
            "relations": {"records": ["id"], "links": ["id"]},
        }))
        .unwrap();
        assert_eq!(
            app_reads_widening_note(&scoped_cols, &wide_rel),
            Some(
                "This update widens app reads: new relation 'links'; \
                 broader type/kind scope."
                    .to_string()
            )
        );
    }

    #[test]
    fn info_serializes_with_stable_keys() {
        let info = described(json!({"records": ["id"]}), None);
        let value = serde_json::to_value(&info).unwrap();
        let mut top: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        top.sort();
        assert_eq!(
            top,
            vec![
                "broad_access",
                "capability_notes",
                "relations",
                "scope_description"
            ]
        );
        let mut rel: Vec<&str> = value["relations"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        rel.sort();
        assert_eq!(
            rel,
            vec![
                "columns",
                "counters_included",
                "only_you_see_this",
                "relation",
                "summary"
            ]
        );
    }
}

#[cfg(test)]
mod sql_snapshot_tests {
    //! Bounds for package-declared fixed SQL snapshot needs (task `421f867`).

    use super::{
        alpha_tab_canonical_declaration, alpha_tab_declaration_digest, bind_sql_params,
        clock_probe_safe_sql_needs, parse_sql_need_entry, require_declaration, sql_needs_in,
        valid_sql_need_key, ATTENTION_QUERY_NEED, RECORDS_RESOLVE_REFERENCE_NEED,
        RECORDS_SEARCH_NEED, SQL_SNAPSHOT_NEED,
    };
    use serde_json::json;

    fn entry(key: &str, label: &str, sql: &str) -> serde_json::Value {
        json!({"need": SQL_SNAPSHOT_NEED, "key": key, "label": label, "sql": sql})
    }

    #[test]
    fn unordered_limit_need_refusal_names_the_exact_default() {
        // E2: an unordered top-level LIMIT need still refuses, but names the
        // default the ad-hoc path would apply. A nested-only unordered LIMIT
        // refuses without it.
        let error = parse_sql_need_entry(&entry(
            "lane.records",
            "Records",
            "SELECT id, name FROM records LIMIT 2",
        ))
        .unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
        assert!(
            error.contains("the ad-hoc default would order by (id, name): add ORDER BY 1, 2"),
            "{error}"
        );
        let nested = parse_sql_need_entry(&entry(
            "lane.records",
            "Records",
            "SELECT * FROM (SELECT id FROM records LIMIT 1) s ORDER BY id",
        ))
        .unwrap_err();
        assert!(!nested.contains("ad-hoc default"), "{nested}");
        // Top-level unordered over an unordered nest: the default would not
        // cure it, so no repair suffix either.
        let combo = parse_sql_need_entry(&entry(
            "lane.records",
            "Records",
            "SELECT * FROM (SELECT id FROM records LIMIT 1) s LIMIT 2",
        ))
        .unwrap_err();
        assert!(combo.contains("LIMIT without ORDER BY"), "{combo}");
        assert!(!combo.contains("ad-hoc default"), "{combo}");
    }

    #[test]
    fn clock_probe_excludes_both_execution_clock_activity_relations() {
        for relation in ["agent_activity", "agent_activity_claims"] {
            let key = if relation == "agent_activity" {
                "lane.activity"
            } else {
                "lane.claims"
            };
            let column = if relation == "agent_activity" {
                "activity_id"
            } else {
                "claim_id"
            };
            let sql = format!("SELECT {column} FROM {relation} WHERE now_ms() > 0");
            let need = parse_sql_need_entry(&entry(key, "Clock", &sql)).unwrap();
            assert!(!clock_probe_safe_sql_needs(&[need]), "{relation}");
        }
        let ordinary = parse_sql_need_entry(&entry(
            "lane.records",
            "Clock",
            "SELECT id FROM records WHERE now_ms() > 0 AND name = 'agent_activity'",
        ))
        .unwrap();
        assert!(clock_probe_safe_sql_needs(&[ordinary]));
    }

    #[test]
    fn string_only_declarations_digest_exactly_as_before() {
        // Fixed vector from `launch_tests::alpha_tab_digest_vectors`: the
        // canonical form must not gain a `sql_needs` key when no well-formed
        // SQL entry is present.
        let declaration =
            json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]});
        assert_eq!(
            alpha_tab_canonical_declaration(&declaration).unwrap(),
            json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]})
        );
        assert_eq!(
            alpha_tab_declaration_digest(&declaration).unwrap(),
            "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15"
        );
    }

    #[test]
    fn param_less_sql_declarations_keep_their_pre_params_digest() {
        // Golden vector computed from the pre-params code at `origin/main`:
        // a param-less SQL entry must canonicalize and digest exactly as it
        // did before `params` existed, so old installs keep their pins.
        let declaration = json!({"needs": ["attention.query.v1",
            entry("lane.a", "A", "SELECT id FROM records")], "effects": []});
        assert_eq!(
            alpha_tab_canonical_declaration(&declaration).unwrap(),
            json!({"needs": ["attention.query.v1"], "effects": [],
                "sql_needs": [{"key": "lane.a", "label": "A",
                    "need": "sql.snapshot.v1", "sql": "SELECT id FROM records"}]})
        );
        assert_eq!(
            alpha_tab_declaration_digest(&declaration).unwrap(),
            "bc0b2a5c9e4f8caa8e5fb7bd3a31268a72e93ba976eba4a5061bdaf81c30b989"
        );
    }

    #[test]
    fn key_shape_matches_the_pinned_pattern() {
        for key in ["a", "ready.unblocked", "lane_1", "a.b_c9", "x"] {
            assert!(valid_sql_need_key(key), "{key}");
        }
        for key in [
            "",
            "A",
            "1a",
            "_a",
            ".a",
            "a-b",
            "a b",
            "é",
            &"a".repeat(41),
        ] {
            assert!(!valid_sql_need_key(key), "{key}");
        }
        assert!(valid_sql_need_key(&"a".repeat(40)));
    }

    #[test]
    fn sql_entries_accept_reads_and_refuse_writes_placeholders_and_bad_shapes() {
        assert!(parse_sql_need_entry(&entry(
            "ready.unblocked",
            "Unblocked",
            "SELECT id FROM records"
        ))
        .is_ok());
        for bad in [
            entry("Bad", "Label", "SELECT id FROM records"),
            entry("ok", "", "SELECT id FROM records"),
            entry("ok", &"l".repeat(121), "SELECT id FROM records"),
            entry("ok", "Label", ""),
            entry("ok", "Label", "DELETE FROM records WHERE id = 'x'"),
            entry("ok", "Label", "SELECT id FROM records WHERE id = ?1"),
            entry("ok", "Label", "SELECT id FROM nope_not_a_relation"),
            json!({"need": SQL_SNAPSHOT_NEED, "key": "ok", "label": "L"}),
            json!({"need": "other.need.v1", "key": "ok", "label": "L", "sql": "SELECT 1"}),
            json!("records.search.v1"),
        ] {
            let error = parse_sql_need_entry(&bad).unwrap_err();
            assert!(error.contains("invalid_sql_need"), "{bad}: {error}");
        }
        let oversize = format!("SELECT '{}'", "x".repeat(4096));
        let error = parse_sql_need_entry(&entry("ok", "Label", &oversize)).unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
        // 65 output columns prepare cleanly but exceed the 64-column runtime
        // bound, so admission refuses instead of failing every live_read.
        let wide: String = (0..65)
            .map(|index| index.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let error =
            parse_sql_need_entry(&entry("ok", "Label", &format!("SELECT {wide}"))).unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
    }

    #[test]
    fn stored_sql_needs_sort_by_key_and_ignore_string_entries() {
        let declaration = json!({"needs": [
            "attention.query.v1",
            entry("ready.stalled", "Stalled", "SELECT id FROM records"),
            entry("ready.unblocked", "Unblocked", "SELECT id FROM records"),
        ], "effects": []});
        let keys: Vec<String> = sql_needs_in(&declaration)
            .unwrap()
            .iter()
            .map(|need| need.key.clone())
            .collect();
        assert_eq!(
            keys,
            vec!["ready.stalled".to_string(), "ready.unblocked".to_string()]
        );
        let canonical = alpha_tab_canonical_declaration(&declaration).unwrap();
        assert_eq!(canonical["needs"], json!(["attention.query.v1"]));
        let sql_keys: Vec<String> = canonical["sql_needs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|need| need["key"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            sql_keys,
            vec!["ready.stalled".to_string(), "ready.unblocked".to_string()]
        );
    }

    #[test]
    fn stored_sql_needs_refuse_malformed_entries_and_duplicate_keys() {
        let dup = entry("lane.dup", "Dup", "SELECT id FROM records");
        let duplicated = json!({"needs": [dup.clone(), dup.clone()], "effects": []});
        let error = sql_needs_in(&duplicated).unwrap_err().to_string();
        assert!(error.contains("sql_need_failed"), "{error}");
        assert!(error.contains("lane.dup"), "{error}");
        let malformed = json!({"needs": [
            entry("lane.ok", "Ok", "SELECT id FROM records"),
            {"need": "sql.snapshot.v1", "key": "Bad", "label": "L", "sql": "SELECT id FROM records"},
        ], "effects": []});
        let error = sql_needs_in(&malformed).unwrap_err().to_string();
        assert!(error.contains("invalid_sql_need"), "{error}");
    }

    fn param_entry(key: &str, sql: &str, params: serde_json::Value) -> serde_json::Value {
        json!({"need": SQL_SNAPSHOT_NEED, "key": key, "label": "L", "sql": sql, "params": params})
    }

    #[test]
    fn param_less_entries_keep_byte_identical_digests() {
        // A param-less entry canonicalizes with no `params` key, so a
        // declaration written before params existed digests unchanged.
        let declaration = json!({"needs": [
            entry("lane.a", "A", "SELECT id FROM records"),
        ], "effects": []});
        let canonical = alpha_tab_canonical_declaration(&declaration).unwrap();
        assert_eq!(
            canonical["sql_needs"],
            json!([{"key": "lane.a", "label": "A",
                    "need": "sql.snapshot.v1", "sql": "SELECT id FROM records"}])
        );
        assert!(canonical["sql_needs"][0].get("params").is_none());
    }

    #[test]
    fn param_entries_accept_matching_placeholders_and_refuse_mismatches() {
        let text_param = json!([{"name": "lifecycle", "type": "text"}]);
        let ok = param_entry(
            "lane.ok",
            "SELECT id FROM records WHERE lifecycle = ?1",
            text_param,
        );
        let parsed = parse_sql_need_entry(&ok).unwrap();
        assert_eq!(parsed.params.len(), 1);
        assert_eq!(parsed.params[0].name, "lifecycle");
        assert_eq!(parsed.params[0].max_len, 256);
        assert!(parsed.params[0].required);
        // Undeclared placeholder: param-less SQL with `?1`.
        let error = parse_sql_need_entry(&entry(
            "lane.bare",
            "Bare",
            "SELECT id FROM records WHERE lifecycle = ?1",
        ))
        .unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
        // Declared-but-unused param: params declared, SQL has no placeholder.
        let unused = param_entry(
            "lane.unused",
            "SELECT id FROM records",
            json!([{"name": "lifecycle", "type": "text"}]),
        );
        let error = parse_sql_need_entry(&unused).unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
        // Count mismatch in the other direction: two placeholders, one param.
        let short = param_entry(
            "lane.short",
            "SELECT id FROM records WHERE lifecycle = ?1 AND id = ?2",
            json!([{"name": "lifecycle", "type": "text"}]),
        );
        let error = parse_sql_need_entry(&short).unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
    }

    #[test]
    fn param_entries_bound_names_types_counts_and_duplicates() {
        let sql = "SELECT id FROM records WHERE lifecycle = ?1";
        for bad_params in [
            json!([{"name": "Bad", "type": "text"}]),
            json!([{"name": "1abc", "type": "text"}]),
            json!([{"name": "ok", "type": "bytes"}]),
            json!([{"name": "ok", "type": "text", "max_len": 0}]),
            json!([{"name": "ok", "type": "text", "max_len": 1025}]),
            json!([{"name": "ok", "type": "integer", "max_len": 10}]),
            json!([{"name": "ok", "type": "text", "required": "yes"}]),
            json!([
                {"name": "dup", "type": "text"},
                {"name": "dup", "type": "text"},
            ]),
        ] {
            // Two params need two placeholders; pad the SQL for the dup case.
            let statement = if bad_params.as_array().unwrap().len() == 2 {
                "SELECT id FROM records WHERE lifecycle = ?1 AND id = ?2"
            } else {
                sql
            };
            let bad = param_entry("lane.bad", statement, bad_params.clone());
            let error = parse_sql_need_entry(&bad).unwrap_err();
            assert!(error.contains("invalid_sql_need"), "{bad_params}: {error}");
        }
        // Nine params exceed the per-need bound.
        let many: Vec<serde_json::Value> = (0..9)
            .map(|index| json!({"name": format!("p{index}"), "type": "text"}))
            .collect();
        let placeholders: Vec<String> = (1..=9).map(|index| format!("?{index}")).collect();
        let wide_sql = format!(
            "SELECT id FROM records WHERE id IN ({})",
            placeholders.join(", ")
        );
        let bad = param_entry("lane.many", &wide_sql, json!(many));
        let error = parse_sql_need_entry(&bad).unwrap_err();
        assert!(error.contains("invalid_sql_need"), "{error}");
    }

    #[test]
    fn param_declarations_digest_canonical_params_and_order() {
        // Defaults resolve into the digest: explicit defaults digest the
        // same as omitted ones, and param order moves the digest because it
        // defines the `?N` binding.
        let omitted = param_entry(
            "lane.p",
            "SELECT id FROM records WHERE lifecycle = ?1",
            json!([{"name": "lifecycle", "type": "text"}]),
        );
        let explicit = param_entry(
            "lane.p",
            "SELECT id FROM records WHERE lifecycle = ?1",
            json!([{"name": "lifecycle", "type": "text",
                    "max_len": 256, "required": true}]),
        );
        let decl_omitted = json!({"needs": [omitted], "effects": []});
        let decl_explicit = json!({"needs": [explicit], "effects": []});
        assert_eq!(
            alpha_tab_declaration_digest(&decl_omitted).unwrap(),
            alpha_tab_declaration_digest(&decl_explicit).unwrap()
        );
        let canonical = alpha_tab_canonical_declaration(&decl_omitted).unwrap();
        assert_eq!(
            canonical["sql_needs"][0]["params"],
            json!([{"name": "lifecycle", "type": "text",
                    "max_len": 256, "required": true}])
        );
        let swapped = param_entry(
            "lane.q",
            "SELECT id FROM records WHERE lifecycle = ?1 AND id = ?2",
            json!([
                {"name": "a_param", "type": "text"},
                {"name": "b_param", "type": "text"},
            ]),
        );
        let unswapped = param_entry(
            "lane.q",
            "SELECT id FROM records WHERE lifecycle = ?1 AND id = ?2",
            json!([
                {"name": "b_param", "type": "text"},
                {"name": "a_param", "type": "text"},
            ]),
        );
        assert_ne!(
            alpha_tab_declaration_digest(&json!({"needs": [swapped], "effects": []})).unwrap(),
            alpha_tab_declaration_digest(&json!({"needs": [unswapped], "effects": []})).unwrap()
        );
    }

    fn bound_need() -> super::SqlNeed {
        parse_sql_need_entry(&param_entry(
            "lane.bound",
            "SELECT id FROM records WHERE lifecycle = ?1 AND created_at_ms > ?2",
            json!([
                {"name": "lifecycle", "type": "text", "max_len": 32},
                {"name": "since_ms", "type": "timestamp_ms"},
            ]),
        ))
        .unwrap()
    }

    #[test]
    fn sql_param_values_bind_positionally_with_named_refusals() {
        use crate::query::sql_contract::QuerySqlParameter;
        let need = bound_need();
        let bound = bind_sql_params(
            &need,
            Some(&json!({"lifecycle": "open", "since_ms": 1700000000000i64})),
        )
        .unwrap();
        assert_eq!(bound.len(), 2);
        assert!(matches!(
            bound[0],
            QuerySqlParameter::Text { value: Some(ref text) } if text == "open"
        ));
        assert!(matches!(
            bound[1],
            QuerySqlParameter::Integer { value: Some(ref text) } if text == "1700000000000"
        ));
        // Unknown name.
        assert_eq!(
            bind_sql_params(
                &need,
                Some(&json!({"lifecycle": "open", "since_ms": 1, "extra": 1}))
            )
            .unwrap_err(),
            "unknown_sql_param"
        );
        // Missing required.
        assert_eq!(
            bind_sql_params(&need, Some(&json!({"lifecycle": "open"}))).unwrap_err(),
            "missing_sql_param"
        );
        assert_eq!(
            bind_sql_params(&need, None).unwrap_err(),
            "missing_sql_param"
        );
        // Wrong types and over max_len.
        assert_eq!(
            bind_sql_params(&need, Some(&json!({"lifecycle": 7, "since_ms": 1}))).unwrap_err(),
            "invalid_sql_param"
        );
        assert_eq!(
            bind_sql_params(
                &need,
                Some(&json!({"lifecycle": "way-too-long-lifecycle-value-over-cap", "since_ms": 1}))
            )
            .unwrap_err(),
            "invalid_sql_param"
        );
        assert_eq!(
            bind_sql_params(
                &need,
                Some(&json!({"lifecycle": "open", "since_ms": "yesterday"}))
            )
            .unwrap_err(),
            "invalid_sql_param"
        );
        assert_eq!(
            bind_sql_params(&need, Some(&json!("lifecycle"))).unwrap_err(),
            "invalid_sql_param"
        );
        // An injection-shaped text value is data, not syntax: it binds as a
        // plain text parameter and validates cleanly here.
        let bound = bind_sql_params(
            &need,
            Some(&json!({"lifecycle": "' OR '1'='1", "since_ms": 1})),
        )
        .unwrap();
        assert!(matches!(
            bound[0],
            QuerySqlParameter::Text { value: Some(ref text) } if text == "' OR '1'='1"
        ));
    }

    #[test]
    fn optional_params_bind_typed_null_when_absent() {
        use crate::query::sql_contract::QuerySqlParameter;
        let need = parse_sql_need_entry(&param_entry(
            "lane.opt",
            "SELECT id FROM records WHERE lifecycle = ?1",
            json!([{"name": "lifecycle", "type": "text", "required": false}]),
        ))
        .unwrap();
        let bound = bind_sql_params(&need, None).unwrap();
        assert!(matches!(bound[0], QuerySqlParameter::Text { value: None }));
    }

    #[test]
    fn sql_keys_colliding_with_host_needs_refuse() {
        // SQL keys share the `live_read` need namespace with the host
        // on-request needs; a colliding key would shadow the host handler
        // at dispatch, so the parser refuses all three names.
        for host in [
            ATTENTION_QUERY_NEED,
            RECORDS_SEARCH_NEED,
            RECORDS_RESOLVE_REFERENCE_NEED,
        ] {
            let error =
                parse_sql_need_entry(&entry(host, "Host", "SELECT id FROM records")).unwrap_err();
            assert!(error.contains("invalid_sql_need"), "{host}: {error}");
            let declaration = json!({"needs": [entry(host, "Host", "SELECT id FROM records")],
                "effects": []});
            let error = require_declaration(&declaration).unwrap_err().to_string();
            assert!(error.contains("invalid_sql_need"), "{host}: {error}");
        }
    }

    #[test]
    fn cross_namespace_duplicates_refuse_at_install_and_execution() {
        // A string need shadowed by an SQL key with the same name would
        // dispatch to SQL silently, leaving dead config behind.
        let declaration = json!({"needs": ["lane.x",
            entry("lane.x", "X", "SELECT id FROM records")], "effects": []});
        let error = require_declaration(&declaration).unwrap_err().to_string();
        assert!(error.contains("invalid_sql_need"), "{error}");
        assert!(error.contains("lane.x"), "{error}");
        let error = sql_needs_in(&declaration).unwrap_err().to_string();
        assert!(error.contains("sql_need_failed"), "{error}");
        assert!(error.contains("lane.x"), "{error}");
    }
}

#[cfg(test)]
mod sql_inner_executor_tests {
    //! The caller-transaction need executor against a governed-pool data
    //! transaction: projection parity with the owned path, server replay
    //! pinning, authored-only VM accounting, and clock-free override ignore.
    //! No install rows are needed: the need runs directly under a principal.

    use super::{execute_sql_need_in, SqlNeed};
    use sqlx::Acquire as _;
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

    const HEAVY_SQL: &str = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000) SELECT sum(x) AS n FROM n";
    // Heavy AND time-dependent: enough VM work to trip the progress counter
    // (a trivial SELECT never reaches PROGRESS_OPS) plus a genuine now_ms
    // bind for the replay clock to pin.
    const CLOCK_SQL: &str = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000) SELECT sum(x) AS n FROM n WHERE now_ms() > 0";

    fn lane_need(sql: &str) -> SqlNeed {
        SqlNeed {
            key: "lane.t".to_string(),
            label: "T".to_string(),
            sql: sql.to_string(),
            params: Vec::new(),
            relations: Default::default(),
        }
    }

    #[tokio::test]
    async fn in_tx_projection_matches_owned_and_pins_replay_clock() {
        let db = crate::create_database(":memory:").await.unwrap();
        let principal = crate::query::QueryPrincipal::authenticated("alice", false);
        let request = crate::query::sql_contract::QuerySqlRequest {
            sql: CLOCK_SQL.to_string(),
            parameters: Vec::new(),
        };
        let owned = crate::query::sql::query_sql_request_owned_replay(
            db.clone(),
            principal.clone(),
            request,
            1_234_567,
        )
        .await
        .unwrap();
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let callbacks = Arc::new(AtomicU64::new(0));
        let executed = execute_sql_need_in(
            &mut tx,
            principal,
            &lane_need(CLOCK_SQL),
            Vec::new(),
            Some(Arc::clone(&callbacks)),
            Some(1_234_567),
        )
        .await
        .unwrap();
        assert_eq!(
            executed.input["rows"],
            serde_json::Value::Array(owned.rows.clone())
        );
        assert_eq!(
            executed.input["row_count"],
            serde_json::json!(owned.row_count)
        );
        assert_eq!(executed.now_ms_ms, Some(1_234_567));
        assert!(executed.time_dependent);
        assert!(callbacks.load(Ordering::Relaxed) > 0);
        // No global sequence in the frame input.
        assert!(executed.input.get("as_of_seq").is_none());
        tx.rollback().await.unwrap();
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn in_tx_clock_free_need_ignores_replay_override() {
        let db = crate::create_database(":memory:").await.unwrap();
        let principal = crate::query::QueryPrincipal::authenticated("alice", false);
        let mut connection = db.governed_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let executed = execute_sql_need_in(
            &mut tx,
            principal,
            &lane_need(HEAVY_SQL),
            Vec::new(),
            None,
            Some(1_234_567),
        )
        .await
        .unwrap();
        assert_eq!(executed.now_ms_ms, None);
        assert!(!executed.time_dependent);
        assert_eq!(executed.input["truncated"], serde_json::json!(false));
        tx.rollback().await.unwrap();
        drop(connection);
        db.close().await;
    }
}

#[cfg(test)]
mod catchup_probe_tests {
    use super::{CatchupProbeGuard, PendingSubscription};
    use crate::need_subscriptions::{params_digest, SurfaceBinding};
    use crate::realtime::RealtimeHub;
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn held_catchup_excludes_probe_without_clearing_scheduler_run_and_cancel_retires_id() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (_db, hub) = RealtimeHub::attach(db, None).await.unwrap();
        let (token, id) = {
            let mut needs = hub.need_registry().lock().unwrap();
            let token = needs.register_connection("alice", "db-1", true);
            let id = needs
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    SurfaceBinding::alpha_tab("agent.clock", "event-1"),
                    "attention.query.v1",
                    &params_digest(None),
                )
                .unwrap();
            needs.activate_with_evaluation(
                &token,
                &id,
                "held",
                true,
                Some(BTreeMap::from([("lane.clock".to_string(), 10)])),
            );
            needs.mark_dirty(&token, &id);
            needs.clear_dirty_for_catchup(&token, &id).unwrap();
            (token, id)
        };
        let pending = PendingSubscription {
            hub: hub.clone(),
            token: token.clone(),
            id: id.clone(),
        };
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let held = tokio::spawn(async move {
            let mut guard = CatchupProbeGuard::new(&pending);
            entered_tx.send(()).unwrap();
            release_rx.await.unwrap();
            guard.complete();
        });
        entered_rx.await.unwrap();
        {
            let needs = hub.need_registry().lock().unwrap();
            assert_eq!(needs.probe_clock_eligible_count(), 0);
            let state = needs.subscription_state(&token, &id).unwrap();
            assert!(state.catchup_in_flight);
            assert!(!state.in_flight);
        }
        let mut scheduler = crate::mcp::tools::live_scheduler::NeedScheduler::new(hub.clone());
        scheduler.probe_clock_once_for_tests().await;
        assert_eq!(hub.need_clock_probe_totals_for_tests().2[0], 1);
        // A push run may overlap the handler; neither owner may clear
        // the other's exclusion marker.
        hub.need_registry()
            .lock()
            .unwrap()
            .clear_dirty(&token, &id)
            .unwrap();
        release_tx.send(()).unwrap();
        held.await.unwrap();
        {
            let mut needs = hub.need_registry().lock().unwrap();
            let state = needs.subscription_state(&token, &id).unwrap();
            assert!(!state.catchup_in_flight);
            assert!(state.in_flight);
            assert_eq!(needs.probe_clock_eligible_count(), 0);
            needs.finish_rerun(&token, &id);
            assert_eq!(needs.probe_clock_eligible_count(), 1);
            needs.clear_dirty_for_catchup(&token, &id).unwrap();
        }
        let pending = PendingSubscription {
            hub: hub.clone(),
            token: token.clone(),
            id: id.clone(),
        };
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let cancelled = tokio::spawn(async move {
            let _guard = CatchupProbeGuard::new(&pending);
            entered_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        entered_rx.await.unwrap();
        cancelled.abort();
        assert!(cancelled.await.is_err());
        assert!(hub
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &id)
            .is_none());
    }
}

#[cfg(test)]
mod attention_parity_tests {
    //! The post-LIMIT parity guard must refuse the read on mismatch, in
    //! release as well as debug: silently skipping would shrink the window
    //! and recreate the pre-LIMIT boundary the visible join fixed.
    //!
    //! A genuine view-vs-check divergence is not constructible through the
    //! public tool surface (writes validate policy shape, so realistic
    //! fixtures always agree — see the integration parity test), so this
    //! pins the refusal contract on the guard itself: agreement passes,
    //! mismatch refuses with an internal error carrying no row identity.

    use super::attention_parity_gate;

    #[test]
    fn agreement_passes_and_mismatch_refuses_without_row_identity() {
        assert!(attention_parity_gate(true).is_ok());
        let error = attention_parity_gate(false).unwrap_err().to_string();
        assert_eq!(
            error,
            "manage_alpha_tabs: live read refused [authority_mismatch]"
        );
    }
}

/// Facet-set object bounds (task `81372d1`): parse, canonical digest and
/// preview names. Legacy string-only declarations must canonicalize and
/// digest exactly as before; every bound participates in the digest.
#[cfg(test)]
mod facet_set_declaration_tests {
    use super::{
        alpha_tab_canonical_declaration, alpha_tab_declaration_digest,
        alpha_tab_preview_authority_for, parse_facet_set_bound, parse_facet_set_bounds,
        require_declaration, FACET_SET_EFFECT,
    };
    use serde_json::{json, Value};

    fn bound(key: &str, values: Value, need: &str) -> Value {
        json!({"effect": FACET_SET_EFFECT, "key": key, "values": values, "target": {"need": need}})
    }

    fn grid_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "grid.items", "label": "Grid",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40"})
    }

    fn declaration(effects: Value) -> Value {
        json!({"needs": ["attention.query.v1", grid_need()], "effects": effects})
    }

    #[test]
    fn valid_bound_parses_with_sorted_values() {
        let parsed = parse_facet_set_bound(&bound(
            "priority",
            json!(["medium", "low", "high"]),
            "grid.items",
        ))
        .unwrap();
        assert_eq!(parsed.key, "priority");
        assert_eq!(parsed.values, vec!["high", "low", "medium"]);
        assert_eq!(parsed.need, "grid.items");
        let declaration = declaration(json!([bound(
            "priority",
            json!(["low", "high"]),
            "grid.items"
        )]));
        let parsed = require_declaration(&declaration).unwrap();
        assert_eq!(parsed.effects, vec![FACET_SET_EFFECT.to_string()]);
        // Bounds are exercised directly, never stored on the declaration:
        // the guard re-parses them from the stored consent.
        let bounds = parse_facet_set_bounds(&declaration).unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].key, "priority");
    }

    #[test]
    fn bare_facet_set_string_and_malformed_bounds_refuse() {
        for effects in [
            json!([FACET_SET_EFFECT]),
            json!([bound("priority", json!([]), "grid.items")]),
            json!([bound("priority", json!(["low", "low"]), "grid.items")]),
            json!([bound("", json!(["low"]), "grid.items")]),
            json!([bound("priority", json!(["low"]), "Missing.Key")]),
            json!([{"effect": "records.other.v1", "key": "priority",
                "values": ["low"], "target": {"need": "grid.items"}}]),
            json!([bound("name", json!(["x"]), "grid.items")]),
            json!([bound("body", json!(["x"]), "grid.items")]),
            json!([bound("lifecycle", json!(["open"]), "grid.items")]),
            json!([bound("owner", json!(["a"]), "grid.items")]),
            json!([bound("maturity", json!(["m"]), "grid.items")]),
            json!([bound("archived", json!(["x"]), "grid.items")]),
            json!([bound("runtime", json!(["x"]), "grid.items")]),
            json!([bound("triage", json!(["x"]), "grid.items")]),
            json!([{"effect": FACET_SET_EFFECT, "key": "priority",
                "values": ["low"], "target": {"need": "grid.items"}, "extra": 1}]),
            json!([{"effect": FACET_SET_EFFECT, "key": "priority",
                "values": ["low"], "target": {"need": "grid.items", "other": 1}}]),
        ] {
            let error = require_declaration(&declaration(effects))
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_effect"), "{error}");
        }
        // A non-string, non-object entry keeps the legacy refusal text and
        // behavior: it predates object bounds and is a malformed old shape,
        // not a bound error.
        let error = require_declaration(&declaration(json!([42])))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("declaration 'effects' entries must be strings or facet-set objects"),
            "{error}"
        );
        assert!(!error.contains("invalid_effect"), "{error}");
        // Duplicate keys across two bounds refuse.
        let error = require_declaration(&declaration(json!([
            bound("priority", json!(["low"]), "grid.items"),
            bound("priority", json!(["high"]), "grid.items"),
        ])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("duplicated"), "{error}");
        // A bound targeting an undeclared need refuses.
        let error = require_declaration(&declaration(json!([bound(
            "priority",
            json!(["low"]),
            "grid.absent"
        ),])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("undeclared need"), "{error}");
    }

    #[test]
    fn generic_matcher_claims_only_ordinary_facet_sets() {
        use crate::mcp::tools::tab_effect_catalogue::{match_arm, TabEffectArm};
        use native_artifact_runtime::mdx_v2::{InteractionEffect, InteractionEntry, ValueSource};
        use std::collections::BTreeMap;
        let entry = |facet: &str, value: Value| InteractionEntry {
            id: "probe".into(),
            label: "Probe".into(),
            effect: InteractionEffect::FacetSet,
            slots: BTreeMap::new(),
            facet: facet.into(),
            value: Some(ValueSource::Literal { value }),
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        // Non-Start lifecycle entries match no arm: the legacy scope refusal
        // (not the generic consent path) still owns them.
        assert_eq!(match_arm(&entry("lifecycle", json!("bogus_state"))), None);
        assert_eq!(
            match_arm(&entry("triage", json!("triaged"))),
            Some(TabEffectArm::Triage)
        );
        assert_eq!(match_arm(&entry("owner", json!("acct:x"))), None);
        // An ordinary facet routes generic.
        assert_eq!(
            match_arm(&entry("effort", json!("large"))),
            Some(TabEffectArm::FacetSet)
        );
        // A comment.create entry matches only the comment arm, after the
        // existing rows: dispatch refuses it before any write.
        let comment_entry = InteractionEntry {
            id: "post".into(),
            label: "Post".into(),
            effect: InteractionEffect::CommentCreate,
            slots: BTreeMap::new(),
            facet: String::new(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        assert_eq!(match_arm(&comment_entry), Some(TabEffectArm::CommentCreate));
    }

    #[test]
    fn string_only_canonical_form_is_unchanged() {
        let legacy = json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]});
        let canonical = alpha_tab_canonical_declaration(&legacy).unwrap();
        assert_eq!(
            canonical,
            json!({"needs": ["attention.query.v1"], "effects": ["task.triage-set.v1"]})
        );
    }

    #[test]
    fn widening_values_changes_the_digest() {
        let base = declaration(json!([bound(
            "priority",
            json!(["low", "high"]),
            "grid.items"
        )]));
        let reordered = declaration(json!([bound(
            "priority",
            json!(["high", "low"]),
            "grid.items"
        )]));
        let wide = declaration(json!([bound(
            "priority",
            json!(["low", "high", "urgent"]),
            "grid.items"
        )]));
        let base_digest = alpha_tab_declaration_digest(&base).unwrap();
        assert_eq!(base_digest, alpha_tab_declaration_digest(&base).unwrap());
        assert_ne!(base_digest, alpha_tab_declaration_digest(&wide).unwrap());
        // Author ordering is not consent: reordered values digest identically.
        assert_eq!(
            base_digest,
            alpha_tab_declaration_digest(&reordered).unwrap()
        );
    }

    #[test]
    fn preview_name_list_keeps_object_effect_names() {
        let authority = alpha_tab_preview_authority_for(
            "alice",
            "agent.grid",
            "0.1.0",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "artifact",
            "revision",
            &declaration(json!([
                "task.triage-set.v1",
                bound("priority", json!(["low"]), "grid.items"),
            ])),
        )
        .expect("well-formed declaration mints preview authority");
        assert!(authority
            .effects
            .contains(&"task.triage-set.v1".to_string()));
        assert!(authority.effects.contains(&FACET_SET_EFFECT.to_string()));
    }
}

/// Comment.create consent bounds (task `b9fb9fd` family 1): object parsing,
/// position-overlap refusal, canonical participation and declaration
/// admission. Nothing here executes a write; dispatch refuses first.
#[cfg(test)]
mod comment_create_declaration_tests {
    use super::{
        alpha_tab_canonical_declaration, alpha_tab_declaration_digest, comment_admission,
        parse_comment_create_bound, parse_comment_create_bounds, require_declaration,
        COMMENT_CREATE_EFFECT,
    };
    use serde_json::{json, Value};

    fn bound(positions: Value, max_body_bytes: Value, need: &str) -> Value {
        json!({"effect": COMMENT_CREATE_EFFECT, "positions": positions,
            "max_body_bytes": max_body_bytes, "target": {"need": need}})
    }

    fn grid_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40"})
    }

    fn declaration(effects: Value) -> Value {
        json!({"needs": ["attention.query.v1", grid_need()], "effects": effects})
    }

    #[test]
    fn valid_bound_parses_with_sorted_positions() {
        let parsed = parse_comment_create_bound(&bound(
            json!(["reply", "root"]),
            json!(4096),
            "thread.items",
        ))
        .unwrap();
        assert_eq!(parsed.positions, vec!["reply", "root"]);
        assert_eq!(parsed.max_body_bytes, 4096);
        assert_eq!(parsed.need, "thread.items");
        let bound_declaration =
            declaration(json!([bound(json!(["root"]), json!(100), "thread.items")]));
        let parsed = require_declaration(&bound_declaration).unwrap();
        assert_eq!(parsed.effects, vec![COMMENT_CREATE_EFFECT.to_string()]);
        let bounds = parse_comment_create_bounds(&bound_declaration).unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].positions, vec!["root"]);
        // Whole-value float spellings agree with the integer form, matching
        // the manifest bound parser; the canonical digest is identical.
        let float_form =
            parse_comment_create_bound(&bound(json!(["root"]), json!(100.0), "thread.items"))
                .unwrap();
        assert_eq!(float_form.max_body_bytes, 100);
        let raw: Value = serde_json::from_str(
            r#"{"effect": "comment.create.v1", "positions": ["root"],
                "max_body_bytes": 1e2, "target": {"need": "thread.items"}}"#,
        )
        .unwrap();
        assert_eq!(
            parse_comment_create_bound(&raw).unwrap().max_body_bytes,
            100
        );
        let float_decl = declaration(json!([bound(
            json!(["root"]),
            json!(100.0),
            "thread.items"
        )]));
        assert_eq!(
            alpha_tab_declaration_digest(&declaration(json!([bound(
                json!(["root"]),
                json!(100),
                "thread.items"
            )])))
            .unwrap(),
            alpha_tab_declaration_digest(&float_decl).unwrap(),
        );
    }

    #[test]
    fn bare_string_and_malformed_bounds_refuse() {
        for effects in [
            json!([COMMENT_CREATE_EFFECT]),
            json!([bound(json!([]), json!(100), "thread.items")]),
            json!([bound(json!(["root", "root"]), json!(100), "thread.items")]),
            json!([bound(json!(["pinned"]), json!(100), "thread.items")]),
            json!([bound(json!(["root"]), json!(0), "thread.items")]),
            json!([bound(json!(["root"]), json!(4097), "thread.items")]),
            json!([bound(json!(["root"]), json!(100.5), "thread.items")]),
            json!([bound(json!(["root"]), json!(-4), "thread.items")]),
            json!([bound(json!(["root"]), json!(true), "thread.items")]),
            json!([bound(json!(["root"]), json!("lots"), "thread.items")]),
            json!([bound(json!(["root"]), json!(100), "Missing.Key")]),
            json!([{"effect": COMMENT_CREATE_EFFECT, "positions": ["root"],
                "max_body_bytes": 100, "target": {"need": "thread.items"}, "extra": 1}]),
            json!([{"effect": COMMENT_CREATE_EFFECT, "positions": ["root"],
                "max_body_bytes": 100, "target": {"need": "thread.items", "other": 1}}]),
        ] {
            let error = require_declaration(&declaration(effects))
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_effect"), "{error}");
        }
        // A bound targeting an undeclared need refuses.
        let error = require_declaration(&declaration(json!([bound(
            json!(["root"]),
            json!(100),
            "thread.absent"
        )])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("undeclared need"), "{error}");
    }

    #[test]
    fn overlapping_positions_refuse_regardless_of_need_or_cap() {
        // Duplicate identical objects refuse.
        let error = require_declaration(&declaration(json!([
            bound(json!(["root"]), json!(100), "thread.items"),
            bound(json!(["root"]), json!(100), "thread.items"),
        ])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("more than one bound"), "{error}");
        // Overlapping positions refuse even with different needs/caps.
        let other_need = || {
            json!({"need": "sql.snapshot.v1", "key": "other.items", "label": "Other",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4"})
        };
        let declaration = json!({"needs": ["attention.query.v1", grid_need(), other_need()],
        "effects": [
            bound(json!(["root", "reply"]), json!(100), "thread.items"),
            bound(json!(["reply"]), json!(200), "other.items"),
        ]});
        let error = require_declaration(&declaration).unwrap_err().to_string();
        assert!(error.contains("more than one bound"), "{error}");
        // Distinct root-only and reply-only bounds on different needs pass.
        let declaration = json!({"needs": ["attention.query.v1", grid_need(), other_need()],
        "effects": [
            bound(json!(["root"]), json!(100), "thread.items"),
            bound(json!(["reply"]), json!(200), "other.items"),
        ]});
        let bounds = parse_comment_create_bounds(&declaration).unwrap();
        assert_eq!(bounds.len(), 2);
    }

    #[test]
    fn comment_cap_participates_in_the_digest() {
        let base = declaration(json!([bound(json!(["root"]), json!(100), "thread.items")]));
        let wide = declaration(json!([bound(json!(["root"]), json!(200), "thread.items")]));
        let base_digest = alpha_tab_declaration_digest(&base).unwrap();
        assert_ne!(base_digest, alpha_tab_declaration_digest(&wide).unwrap());
        let canonical = alpha_tab_canonical_declaration(&base).unwrap();
        assert_eq!(
            canonical["effects"][0],
            json!({"effect": COMMENT_CREATE_EFFECT, "positions": ["root"],
                "target": {"need": "thread.items"}, "max_body_bytes": 100}),
        );
    }

    #[test]
    fn admission_selects_position_bound_and_declared_need() {
        // Root-only and reply-only bounds on different needs admit their
        // own position with their own cap and need.
        let split = declaration(json!([
            bound(json!(["root"]), json!(100), "thread.items"),
            bound(json!(["reply"]), json!(200), "other.items"),
        ]));
        // The second need must be declared for the split to install.
        let other = json!({"need": "sql.snapshot.v1", "key": "other.items", "label": "Other",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4"});
        let split = json!({"needs": ["attention.query.v1", grid_need(), other],
            "effects": split["effects"]});
        require_declaration(&split).unwrap();
        let (root_bound, root_need) = comment_admission(&split, "post", "root").unwrap();
        assert_eq!(root_bound.positions, vec!["root"]);
        assert_eq!(root_bound.max_body_bytes, 100);
        assert_eq!(root_need.key, "thread.items");
        let (reply_bound, reply_need) = comment_admission(&split, "post", "reply").unwrap();
        assert_eq!(reply_bound.positions, vec!["reply"]);
        assert_eq!(reply_bound.max_body_bytes, 200);
        assert_eq!(reply_need.key, "other.items");
        // A combined bound admits either position under one cap and need.
        let both = declaration(json!([bound(
            json!(["reply", "root"]),
            json!(300),
            "thread.items"
        )]));
        let (admitted, need) = comment_admission(&both, "post", "reply").unwrap();
        assert_eq!(admitted.positions, vec!["reply", "root"]);
        assert_eq!(admitted.max_body_bytes, 300);
        assert_eq!(need.key, "thread.items");
        // Consent cap travels unclamped: the kernel takes min(manifest,
        // consent) later, so a manifest cap above consent stays admissible.
        let (admitted, _) = comment_admission(&both, "post", "root").unwrap();
        assert_eq!(admitted.max_body_bytes, 300);
    }

    #[test]
    fn admission_refuses_wrong_position_missing_consent_and_missing_need() {
        let root_only = declaration(json!([bound(json!(["root"]), json!(100), "thread.items")]));
        // Wrong position: no bound contains it.
        let (code, message) = comment_admission(&root_only, "post", "reply").unwrap_err();
        assert_eq!(code, "alpha_guard_effect_unconsented");
        assert!(message.contains("position 'reply'"), "{message}");
        assert!(message.contains("'post'"), "{message}");
        // Unknown positions match nothing either.
        let (code, _) = comment_admission(&root_only, "post", "pinned").unwrap_err();
        assert_eq!(code, "alpha_guard_effect_unconsented");
        // String-only declarations hold no bound: the position lookup
        // finds nothing, with the same code as every other unconsented
        // position.
        let bare = json!({"needs": ["attention.query.v1", grid_need()],
            "effects": ["task.triage-set.v1"]});
        let (code, message) = comment_admission(&bare, "post", "root").unwrap_err();
        assert_eq!(code, "alpha_guard_effect_unconsented");
        assert!(
            message.contains("does not consent to a comment.create bound"),
            "{message}"
        );
        // A bound targeting an undeclared need refuses.
        let dangling = declaration(json!([bound(json!(["root"]), json!(100), "thread.absent")]));
        let (code, message) = comment_admission(&dangling, "post", "root").unwrap_err();
        assert_eq!(code, "alpha_guard_effect_unconsented");
        assert!(message.contains("need 'thread.absent'"), "{message}");
    }
}

/// Declaration-only consent for `message.react.v1` (task `07ae879` I1).
/// Nothing here executes a write; dispatch refuses first.
#[cfg(test)]
mod message_react_declaration_tests {
    use super::super::effect_bounds::{parse_message_react_bound, parse_message_react_bounds};
    use super::{
        alpha_tab_canonical_declaration, alpha_tab_declaration_digest, require_declaration,
        MESSAGE_REACT_EFFECT,
    };
    use serde_json::{json, Value};

    fn bound(emoji: Value, need: &str) -> Value {
        json!({"effect": MESSAGE_REACT_EFFECT, "emoji": emoji,
            "target": {"need": need}})
    }

    fn channel_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "messages.channel", "label": "Channel",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40"})
    }

    fn declaration(effects: Value) -> Value {
        json!({"needs": ["attention.query.v1", channel_need()], "effects": effects})
    }

    #[test]
    fn valid_bound_parses_with_sorted_emoji() {
        let parsed =
            parse_message_react_bound(&bound(json!(["🎉", "👍"]), "messages.channel")).unwrap();
        assert_eq!(parsed.emoji, vec!["🎉".to_string(), "👍".to_string()]);
        assert_eq!(parsed.need, "messages.channel");
        let bound_declaration = declaration(json!([bound(json!(["👍"]), "messages.channel")]));
        let parsed = require_declaration(&bound_declaration).unwrap();
        assert_eq!(parsed.effects, vec![MESSAGE_REACT_EFFECT.to_string()]);
        let bounds = parse_message_react_bounds(&bound_declaration).unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].emoji, vec!["👍"]);
    }

    #[test]
    fn bare_string_and_malformed_bounds_refuse() {
        for effects in [
            json!([MESSAGE_REACT_EFFECT]),
            json!([bound(json!([]), "messages.channel")]),
            json!([bound(json!(["👍", "👍"]), "messages.channel")]),
            json!([bound(json!(["nope"]), "messages.channel")]),
            json!([bound(json!(["👍", 1]), "messages.channel")]),
            json!([bound(json!(["👍"]), "Missing.Key")]),
            json!([{"effect": MESSAGE_REACT_EFFECT, "emoji": ["👍"],
                "target": {"need": "messages.channel"}, "extra": 1}]),
            json!([{"effect": MESSAGE_REACT_EFFECT, "emoji": ["👍"],
                "target": {"need": "messages.channel", "other": 1}}]),
        ] {
            let error = require_declaration(&declaration(effects))
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_effect"), "{error}");
        }
        // A bound targeting an undeclared need refuses.
        let error = require_declaration(&declaration(json!([bound(
            json!(["👍"]),
            "messages.absent"
        )])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("undeclared need"), "{error}");
    }

    #[test]
    fn overlapping_emoji_refuse_regardless_of_need() {
        // Duplicate identical objects refuse.
        let error = require_declaration(&declaration(json!([
            bound(json!(["👍"]), "messages.channel"),
            bound(json!(["👍"]), "messages.channel"),
        ])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("more than one bound"), "{error}");
        // Overlapping emoji refuse even with different needs.
        let other_need = || {
            json!({"need": "sql.snapshot.v1", "key": "other.channel", "label": "Other",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4"})
        };
        let declaration = json!({"needs": ["attention.query.v1", channel_need(), other_need()],
        "effects": [
            bound(json!(["👍", "🎉"]), "messages.channel"),
            bound(json!(["🎉"]), "other.channel"),
        ]});
        let error = require_declaration(&declaration).unwrap_err().to_string();
        assert!(error.contains("more than one bound"), "{error}");
        // Distinct disjoint emoji subsets on different needs pass.
        let declaration = json!({"needs": ["attention.query.v1", channel_need(), other_need()],
        "effects": [
            bound(json!(["👍"]), "messages.channel"),
            bound(json!(["🎉"]), "other.channel"),
        ]});
        let bounds = parse_message_react_bounds(&declaration).unwrap();
        assert_eq!(bounds.len(), 2);
    }

    #[test]
    fn react_emoji_widening_changes_the_digest() {
        let base = declaration(json!([bound(json!(["👍"]), "messages.channel")]));
        let wide = declaration(json!([bound(json!(["👍", "🎉"]), "messages.channel")]));
        let base_digest = alpha_tab_declaration_digest(&base).unwrap();
        assert_ne!(base_digest, alpha_tab_declaration_digest(&wide).unwrap());
        let canonical = alpha_tab_canonical_declaration(&base).unwrap();
        assert_eq!(
            canonical["effects"][0],
            json!({"effect": MESSAGE_REACT_EFFECT, "emoji": ["👍"],
                "target": {"need": "messages.channel"}}),
        );
    }

    #[test]
    fn declared_sessions_bind_the_digest_and_leave_legacy_bytes_untouched() {
        let legacy = json!({"needs": ["attention.query.v1"], "effects": []});
        assert_eq!(
            alpha_tab_canonical_declaration(&legacy).unwrap(),
            json!({"needs": ["attention.query.v1"], "effects": []})
        );
        let legacy_digest = alpha_tab_declaration_digest(&legacy).unwrap();
        // Golden baseline: a declaration without `sessions` is unchanged.
        assert_eq!(
            legacy_digest,
            "6c4e683e490845b811e3393d4e17f44b229ba60cdb5ad75bb5818fcee8c33acb"
        );

        let session = json!({"session": "session.body.v1", "key": "doc",
            "scope": {"type": "Document", "kind": "note"}, "mode": "edit", "presence": true});
        let declared =
            json!({"needs": ["attention.query.v1"], "effects": [], "sessions": [session.clone()]});
        let canonical = alpha_tab_canonical_declaration(&declared).unwrap();
        assert_eq!(canonical["sessions"], json!([session.clone()]));
        assert_ne!(
            alpha_tab_declaration_digest(&declared).unwrap(),
            legacy_digest
        );

        // `*` kind, view mode and presence=false are valid (no invented enums).
        assert!(
            require_declaration(&json!({"needs": [], "effects": [], "sessions": [
            {"session": "session.body.v1", "key": "k", "scope": {"type": "T", "kind": "*"},
             "mode": "view", "presence": false}]}))
            .is_ok()
        );

        // Malformed descriptors refuse whole, and never digest as absent.
        for bad in [
            json!({"session": "session.other.v1", "key": "doc", "scope": {"type": "Document", "kind": "note"}, "mode": "edit", "presence": true}),
            json!({"session": "session.body.v1", "key": "", "scope": {"type": "Document", "kind": "note"}, "mode": "edit", "presence": true}),
            json!({"session": "session.body.v1", "key": "doc", "scope": {"type": "Document", "kind": "note"}, "mode": "write", "presence": true}),
            json!({"session": "session.body.v1", "key": "doc", "scope": {"type": "Document", "kind": "note"}, "mode": "edit", "presence": "yes"}),
            json!({"session": "session.body.v1", "key": "doc", "scope": {"type": "Document", "kind": "note"}, "mode": "edit", "presence": true, "extra": 1}),
        ] {
            let declaration =
                json!({"needs": ["attention.query.v1"], "effects": [], "sessions": [bad]});
            assert!(require_declaration(&declaration).is_err());
            assert!(alpha_tab_declaration_digest(&declaration).is_err());
        }
        assert!(
            require_declaration(&json!({"needs": [], "effects": [], "sessions": "no"})).is_err()
        );
        assert!(require_declaration(&json!({"needs": [], "effects": [], "other": []})).is_err());
    }

    #[test]
    fn react_arm_matches_only_react_entries() {
        use crate::mcp::tools::tab_effect_catalogue::{match_arm, TabEffectArm};
        use native_artifact_runtime::mdx_v2::{InteractionEffect, InteractionEntry};
        use std::collections::BTreeMap;
        let entry = InteractionEntry {
            id: "react".into(),
            label: "React".into(),
            effect: InteractionEffect::MessageReact,
            slots: BTreeMap::new(),
            facet: String::new(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        assert_eq!(match_arm(&entry), Some(TabEffectArm::MessageReact));
    }
}

/// Dormant Body declaration, canonical and static-scope oracles only.
#[cfg(test)]
mod body_set_declaration_tests {
    use super::*;
    fn bound() -> Value {
        json!({"effect":BODY_SET_EFFECT,"max_body_bytes":32768,"target":{"need":"docs.body"}})
    }
    fn need() -> Value {
        json!({"need":SQL_SNAPSHOT_NEED,"key":"docs.body","label":"Body",
            "sql":"SELECT id, body FROM records WHERE deleted_at IS NULL ORDER BY id LIMIT 1"})
    }
    fn declaration() -> Value {
        json!({"needs":[need()],"effects":[bound()]})
    }

    #[tokio::test]
    async fn body_scope_refuses_wrong_entry_before_install_lookup() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let guard = native_artifact_runtime::artifact_intents::AlphaTabInstallGuard {
            package: "agent.absent-body-test".into(),
            expected_install_event_id: "absent".into(),
            artifact_id: "absent".into(),
            source_revision: "absent".into(),
            version: "0.1.0".into(),
            digest: "absent".into(),
            declaration_digest: "absent".into(),
        };
        for raw in [
            json!({"id":"save","label":"Save","effect":"title.set","title":{}}),
            json!({"id":"save","label":"Save","effect":"body.set"}),
            json!({"id":"save","label":"Save","effect":"body.set","body":{"max_bytes":0}}),
            json!({"id":"save","label":"Save","effect":"body.set","body":{"max_bytes":1},"title":{}}),
        ] {
            let entry = serde_json::from_value(raw).unwrap();
            let result = check_install_guard_core_row_in(
                &mut tx,
                &Caller::local(),
                &guard,
                "absent",
                "absent",
                &entry,
                GuardScope::Body,
            )
            .await
            .unwrap();
            assert!(
                matches!(
                    result,
                    Err(AdmissionRefusal::ScopeUnsupported {
                        reason: ScopeUnsupportedReason::NonBodyEntry,
                    })
                ),
                "Scope must refuse before missing install or account"
            );
        }
        tx.rollback().await.unwrap();
    }

    #[test]
    fn body_bound_canonical_cap_and_target_are_pinned() {
        let base = declaration();
        assert_eq!(
            require_declaration(&base).unwrap().effects,
            vec![BODY_SET_EFFECT.to_owned()]
        );
        let canonical = alpha_tab_canonical_declaration(&base).unwrap();
        assert_eq!(canonical["effects"], json!([bound()]));
        let mut smaller = base.clone();
        smaller["effects"][0]["max_body_bytes"] = json!(1);
        assert_ne!(
            alpha_tab_declaration_digest(&base).unwrap(),
            alpha_tab_declaration_digest(&smaller).unwrap()
        );
        let mut other = base.clone();
        other["needs"][0]["key"] = json!("docs.other");
        other["effects"][0]["target"]["need"] = json!("docs.other");
        assert_ne!(
            alpha_tab_declaration_digest(&base).unwrap(),
            alpha_tab_declaration_digest(&other).unwrap()
        );
    }

    #[test]
    fn body_direct_canonical_and_install_reject_invalid_lists_and_needs() {
        let mut maximum = declaration();
        maximum["effects"][0]["max_body_bytes"] = json!(BODY_SET_MAX_BODY_BYTES);
        assert!(require_declaration(&maximum).is_ok());
        assert!(alpha_tab_canonical_declaration(&maximum).is_ok());
        let mut cases = Vec::new();
        for cap in [
            json!(0),
            json!(-1),
            json!(BODY_SET_MAX_BODY_BYTES + 1),
            json!(1.5),
            json!(true),
            json!("32"),
        ] {
            let mut d = declaration();
            d["effects"][0]["max_body_bytes"] = cap;
            cases.push(d);
        }
        for effects in [
            json!([BODY_SET_EFFECT]),
            json!(BODY_SET_EFFECT),
            bound(),
            json!([bound(), bound()]),
            json!([{"effect":BODY_SET_EFFECT}]),
            json!([{"effect":BODY_SET_EFFECT,"max_body_bytes":1,"target":{"need":"docs.body","extra":1}}]),
        ] {
            let mut d = declaration();
            d["effects"] = effects;
            cases.push(d);
        }
        let mut extra = declaration();
        extra["effects"][0]["extra"] = json!(1);
        cases.push(extra);
        let mut missing = declaration();
        missing["needs"] = json!([]);
        cases.push(missing);
        let mut non_sql = declaration();
        non_sql["needs"] = json!(["docs.body"]);
        cases.push(non_sql);
        let mut duplicate = declaration();
        duplicate["needs"] = json!([need(), need()]);
        cases.push(duplicate);
        let mut shadowed = declaration();
        shadowed["needs"] = json!(["docs.body", need()]);
        cases.push(shadowed);
        let mut wrong = declaration();
        wrong["needs"][0]["need"] = json!("records.search.v1");
        cases.push(wrong);
        let mut malformed = declaration();
        malformed["needs"] = json!({});
        cases.push(malformed);
        for d in cases {
            assert!(require_declaration(&d).is_err(), "install {d}");
            assert!(
                alpha_tab_canonical_declaration(&d).is_err(),
                "direct canonical {d}"
            );
        }
    }

    #[test]
    fn body_absence_preserves_fixed_legacy_bytes_and_digest() {
        let legacy = json!({"needs":["attention.query.v1"],"effects":["task.triage-set.v1"]});
        assert_eq!(
            serde_jcs::to_vec(&alpha_tab_canonical_declaration(&legacy).unwrap()).unwrap(),
            br#"{"effects":["task.triage-set.v1"],"needs":["attention.query.v1"]}"#
        );
        assert_eq!(
            alpha_tab_declaration_digest(&legacy).unwrap(),
            "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15"
        );
        // Historical malformed no-Body canonical default remains unchanged.
        let malformed = json!({"needs":[],"effects":{}});
        assert_eq!(
            alpha_tab_canonical_declaration(&malformed).unwrap(),
            json!({"needs":[],"effects":[]})
        );
    }
}

/// Declaration-only consent for `records.title-set.v1` (task `da148be`).
/// Nothing here executes a write; dispatch owns the path.
#[cfg(test)]
mod title_set_declaration_tests {
    use super::super::effect_bounds::{parse_title_set_bound, parse_title_set_bounds};
    use super::{
        alpha_tab_canonical_declaration, alpha_tab_declaration_digest, require_declaration,
        TITLE_SET_EFFECT,
    };
    use serde_json::{json, Value};

    fn bound(need: &str) -> Value {
        json!({"effect": TITLE_SET_EFFECT, "target": {"need": need}})
    }

    fn grid_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "grid.items", "label": "Grid",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40"})
    }

    fn declaration(effects: Value) -> Value {
        json!({"needs": ["attention.query.v1", grid_need()], "effects": effects})
    }

    #[test]
    fn valid_bound_parses() {
        let parsed = parse_title_set_bound(&bound("grid.items")).unwrap();
        assert_eq!(parsed.need, "grid.items");
        let bound_declaration = declaration(json!([bound("grid.items")]));
        let parsed = require_declaration(&bound_declaration).unwrap();
        assert_eq!(parsed.effects, vec![TITLE_SET_EFFECT.to_string()]);
        let bounds = parse_title_set_bounds(&bound_declaration).unwrap();
        assert_eq!(bounds.len(), 1);
    }

    #[test]
    fn bare_string_and_malformed_bounds_refuse() {
        for effects in [
            json!([TITLE_SET_EFFECT]),
            json!([{"effect": TITLE_SET_EFFECT, "target": {"need": "Missing.Key"}}]),
            json!([{"effect": TITLE_SET_EFFECT, "target": {"need": "grid.items"}, "extra": 1}]),
            json!([{"effect": TITLE_SET_EFFECT, "target": {"need": "grid.items", "other": 1}}]),
            json!([{"effect": TITLE_SET_EFFECT}]),
            json!([{"effect": "records.other.v1", "target": {"need": "grid.items"}}]),
        ] {
            let error = require_declaration(&declaration(effects))
                .unwrap_err()
                .to_string();
            assert!(error.contains("invalid_effect"), "{error}");
        }
        // A bound targeting an undeclared need refuses.
        let error = require_declaration(&declaration(json!([bound("grid.absent")])))
            .unwrap_err()
            .to_string();
        assert!(error.contains("undeclared need"), "{error}");
    }

    #[test]
    fn second_bound_refuses() {
        let error = require_declaration(&declaration(json!([
            bound("grid.items"),
            bound("grid.items"),
        ])))
        .unwrap_err()
        .to_string();
        assert!(error.contains("more than once"), "{error}");
    }

    #[test]
    fn title_need_widening_changes_the_digest() {
        let base = declaration(json!([bound("grid.items")]));
        let other_need = json!({"need": "sql.snapshot.v1", "key": "other.items", "label": "Other",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 4"});
        let wide = json!({"needs": ["attention.query.v1", grid_need(), other_need],
            "effects": [bound("other.items")]});
        require_declaration(&wide).unwrap();
        let base_digest = alpha_tab_declaration_digest(&base).unwrap();
        assert_ne!(base_digest, alpha_tab_declaration_digest(&wide).unwrap());
        let canonical = alpha_tab_canonical_declaration(&base).unwrap();
        assert_eq!(
            canonical["effects"][0],
            json!({"effect": TITLE_SET_EFFECT, "target": {"need": "grid.items"}}),
        );
    }

    #[test]
    fn title_arm_matches_only_title_entries() {
        use crate::mcp::tools::tab_effect_catalogue::{match_arm, TabEffectArm};
        use native_artifact_runtime::mdx_v2::{InteractionEffect, InteractionEntry};
        use std::collections::BTreeMap;
        let entry = InteractionEntry {
            id: "rename".into(),
            label: "Rename".into(),
            effect: InteractionEffect::TitleSet,
            slots: BTreeMap::new(),
            facet: String::new(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        assert_eq!(match_arm(&entry), Some(TabEffectArm::TitleSet));
    }
}

/// In-transaction binding proof (task `81372d1`): a stale preflight scope
/// and a revoked grant refuse on the write snapshot. These call the helper
/// directly with stale state — no interleaving hook needed — which is what
/// distinguishes the transaction check from the pre-transaction derivation.
#[cfg(test)]
mod facet_set_binding_tests {
    use super::{check_comment_binding_in, check_facet_set_binding_in};
    use crate::authorization::{AllowEntry, Capability};
    use crate::mcp::{Caller, ToolRegistry};
    use serde_json::json;

    const BINDING_ARTIFACT: &str = "0b5e0000-0000-4000-8000-000000000001";
    const BINDING_COLLECTION: &str = "0b5e0000-0000-4000-8000-000000000002";
    const BINDING_OTHER: &str = "0b5e0000-0000-4000-8000-000000000003";
    const BINDING_MEMBER: &str = "0b5e0000-0000-4000-8000-000000000004";
    const BINDING_SOURCE_EVENT: &str = "0c5e0000-0000-4000-8000-000000000001";
    const BINDING_SOURCE_SHA: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BINDING_ATTESTATION: &str = "0d5e0000-0000-4000-8000-000000000001";

    async fn binding_fixture() -> (crate::db::Db, ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        for (id, type_, kind, name) in [
            (BINDING_ARTIFACT, "Document", "note", "Tab"),
            (BINDING_COLLECTION, "Collection", "selection", "Grid"),
            (BINDING_OTHER, "Collection", "selection", "Elsewhere"),
            (BINDING_MEMBER, "WorkItem", "task", "Row"),
        ] {
            let created = registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "create_record",
                    json!({"id": id, "type": type_, "kind": kind,
                        "name": name, "reason": "Binding proof fixture."}),
                )
                .await
                .unwrap();
            assert!(created.get("error").is_none(), "{created:#}");
        }
        registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_links",
                json!({"action": "add", "source_id": BINDING_MEMBER,
                    "target_id": BINDING_COLLECTION, "relationship": "member_of"}),
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO artifact_source_attestations
                (attestation_event_id, artifact_id, source_event_id, source_sha256,
                 descriptor, attestation_sha256, event_seq, created_at)
             VALUES(?,?,?,?,?,?,?,?)",
        )
        .bind(BINDING_ATTESTATION)
        .bind(BINDING_ARTIFACT)
        .bind(BINDING_SOURCE_EVENT)
        .bind(BINDING_SOURCE_SHA)
        .bind("{}")
        .bind(BINDING_SOURCE_SHA)
        .bind(0_i64)
        .bind("2026-01-01T00:00:00Z")
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO artifact_inputs
                (artifact_id, port_name, collection_id,
                 artifact_source_attestation_event_id, artifact_source_event_id,
                 artifact_source_sha256, event_seq)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(BINDING_ARTIFACT)
        .bind("orders")
        .bind(BINDING_COLLECTION)
        .bind(BINDING_ATTESTATION)
        .bind(BINDING_SOURCE_EVENT)
        .bind(BINDING_SOURCE_SHA)
        .bind(0_i64)
        .execute(db.write_pool())
        .await
        .unwrap();
        // Grant seeded directly, like the attestation and binding rows above:
        // this fixture proves the helper's reads, not the grant tool's
        // artifact validation (which correctly refuses the note anchor).
        let scope_sha256 = crate::mcp::tools::artifacts::mdx_sha256_for_projection(
            &json!({"artifact_port": "orders"}),
        );
        sqlx::query(
            "INSERT INTO artifact_module_grants
                (artifact_id, subject_kind, subject_record_id, subject_event_id,
                 source_sha256, artifact_source_attestation_event_id,
                 artifact_source_event_id, artifact_source_sha256, capability,
                 scope_sha256, scope, event_seq)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(BINDING_ARTIFACT)
        .bind("artifact_source")
        .bind(BINDING_ARTIFACT)
        .bind(BINDING_SOURCE_EVENT)
        .bind(BINDING_SOURCE_SHA)
        .bind(BINDING_ATTESTATION)
        .bind(BINDING_SOURCE_EVENT)
        .bind(BINDING_SOURCE_SHA)
        .bind("input.read")
        .bind(&scope_sha256)
        .bind("{\"artifact_port\":\"orders\"}")
        .bind(0_i64)
        .execute(db.write_pool())
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            BINDING_COLLECTION,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        (db, registry)
    }

    #[tokio::test]
    async fn current_mapping_grant_and_view_admit() {
        // Positive preconditions first: with current mapping, grant and
        // View, the helper admits — so the refusals below prove their own
        // gate rather than fixture breakage.
        let (db, _registry) = binding_fixture().await;
        let scope = vec![(
            "orders".to_string(),
            BINDING_COLLECTION.to_string(),
            "selection".to_string(),
        )];
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let admitted = check_facet_set_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &scope,
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap();
        assert!(admitted.is_none(), "{admitted:?}");
    }

    #[tokio::test]
    async fn stale_scope_mapping_refuses_as_binding_changed() {
        // The preflight admitted orders→Elsewhere, but the transaction sees
        // orders→Grid: the binding moved, so the write stops here.
        let (db, _registry) = binding_fixture().await;
        let stale_scope = vec![(
            "orders".to_string(),
            BINDING_OTHER.to_string(),
            "selection".to_string(),
        )];
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let refusal = check_facet_set_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &stale_scope,
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap();
        let (code, _) = refusal.expect("stale mapping must refuse");
        assert_eq!(code, "binding_changed");
    }

    #[tokio::test]
    async fn revoked_grant_refuses_as_capability_denied() {
        // Mapping, kind and View all still pass; only the exact input.read
        // grant is gone, so the port is no longer exposed to the root.
        let (db, _registry) = binding_fixture().await;
        sqlx::query(
            "DELETE FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
        )
        .bind(BINDING_ARTIFACT)
        .execute(db.write_pool())
        .await
        .unwrap();
        let scope = vec![(
            "orders".to_string(),
            BINDING_COLLECTION.to_string(),
            "selection".to_string(),
        )];
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let refusal = check_facet_set_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &scope,
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap();
        let (code, _) = refusal.expect("revoked grant must refuse");
        assert_eq!(code, "module_capability_denied");
    }

    /// Comment binding wrapper over the same core, reusing the honest
    /// seeded fixture as a helper-read test: the positive proves the
    /// singleton explicit-port scope, and each refusal proves its own
    /// gate rather than fixture breakage.
    fn comment_scope() -> Vec<(String, String, String)> {
        vec![(
            "orders".to_string(),
            BINDING_COLLECTION.to_string(),
            "selection".to_string(),
        )]
    }

    #[tokio::test]
    async fn comment_singleton_scope_passes_and_target_resolves() {
        let (db, _registry) = binding_fixture().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let admitted = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &comment_scope(),
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap();
        assert!(admitted.is_none(), "{admitted:?}");
    }

    #[tokio::test]
    async fn comment_scope_shape_refuses_before_binding_io() {
        let (db, _registry) = binding_fixture().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Empty scope names no port.
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &[],
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap()
        .expect("empty scope must refuse");
        assert_eq!(code, "named_input_unbound");
        // Two ports refuse rather than inferring one.
        let scope = vec![
            (
                "orders".to_string(),
                BINDING_COLLECTION.to_string(),
                "selection".to_string(),
            ),
            (
                "other".to_string(),
                BINDING_OTHER.to_string(),
                "selection".to_string(),
            ),
        ];
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &scope,
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap()
        .expect("multi-port scope must refuse");
        assert_eq!(code, "named_input_unbound");
        // The default port is never the entry's explicit port.
        let scope = vec![(
            "default".to_string(),
            BINDING_COLLECTION.to_string(),
            "selection".to_string(),
        )];
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &scope,
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap()
        .expect("default scope must refuse");
        assert_eq!(code, "named_input_unbound");
    }

    #[tokio::test]
    async fn comment_binding_rechecks_attestation_mapping_grant_and_target() {
        // Revoked attestation stops the write here.
        let (db, _registry) = binding_fixture().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            "stale-source-sha",
            &comment_scope(),
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap()
        .expect("revoked attestation must refuse");
        assert_eq!(code, "artifact_source_unattested");
        // Stale mapping refuses as divergence.
        let stale_scope = vec![(
            "orders".to_string(),
            BINDING_OTHER.to_string(),
            "selection".to_string(),
        )];
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &stale_scope,
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap()
        .expect("stale mapping must refuse");
        assert_eq!(code, "binding_changed");
        // Revoked grant refuses as capability denial. The delete runs on
        // the same held write transaction — a second pool writer here
        // could block or fail locked under BEGIN IMMEDIATE.
        sqlx::query(
            "DELETE FROM artifact_module_grants WHERE artifact_id=? AND capability='input.read'",
        )
        .bind(BINDING_ARTIFACT)
        .execute(&mut *tx)
        .await
        .unwrap();
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &comment_scope(),
            Some(BINDING_MEMBER),
        )
        .await
        .unwrap()
        .expect("revoked grant must refuse");
        assert_eq!(code, "module_capability_denied");
    }

    #[tokio::test]
    async fn comment_target_outside_port_refuses() {
        let (db, _registry) = binding_fixture().await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let (code, _) = check_comment_binding_in(
            &mut tx,
            &Caller::authenticated("alice"),
            BINDING_ARTIFACT,
            BINDING_SOURCE_EVENT,
            BINDING_SOURCE_SHA,
            &comment_scope(),
            Some(BINDING_OTHER),
        )
        .await
        .unwrap()
        .expect("outside target must refuse");
        assert_eq!(code, "record_outside_binding");
    }
}

/// Comment install guard (task `b9fb9fd` family 1): the future kernel's
/// wrapper over real installs. Positive pin plus wrong-position, bare
/// consent, disabled/unverified/stale/mismatched and legacy-public legs.
/// Nothing here posts or advertises a comment.
#[cfg(test)]
mod comment_guard_tests {
    use super::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
        alpha_tab_preview_authority_for, check_alpha_install_guard_in,
        check_comment_install_guard_in,
    };
    use crate::authorization::{AllowEntry, Capability};
    use crate::mcp::{Caller, ToolRegistry};
    use native_artifact_runtime::artifact_intents::AlphaTabInstallGuard;
    use native_artifact_runtime::mdx_v2::{
        CommentBodyDecl, CommentCreateDecl, CommentPosition, InteractionEffect, InteractionEntry,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    const GUARD_ARTIFACT: &str = "77777777-7777-4777-8777-777777777777";
    const GUARD_ACCOUNT: &str = "alice";
    const GUARD_BODY: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Comments</title></head><body><main><h1>Comments</h1></main></body></html>";

    fn configure_preview_launch() {
        // Sample-only preview launch tickets need the HTML runtime origins;
        // the values are test-local and idempotent across parallel tests in
        // this binary (mirrors tests/tools/alpha_tabs.rs).
        crate::artifact_html::configure(
            crate::artifact_html::RuntimeConfig::new(
                "http://localhost:8080",
                "http://artifact.localhost:8080",
            )
            .expect("preview test HTML runtime configuration"),
        );
    }

    fn thread_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40"})
    }

    fn comment_bound(positions: Value) -> Value {
        json!({"effect": "comment.create.v1", "positions": positions,
            "max_body_bytes": 100, "target": {"need": "thread.items"}})
    }

    fn guard_declaration(effects: Value) -> Value {
        json!({"needs": ["attention.query.v1", thread_need()], "effects": effects})
    }

    fn comment_entry(id: &str, position: CommentPosition) -> InteractionEntry {
        InteractionEntry {
            id: id.into(),
            label: "Post".into(),
            effect: InteractionEffect::CommentCreate,
            slots: BTreeMap::new(),
            facet: String::new(),
            value: None,
            create: None,
            comment: Some(CommentCreateDecl {
                position,
                body: CommentBodyDecl {
                    input: "text".into(),
                    max_bytes: 100,
                },
            }),
            react: None,
            title: None,
            body: None,
        }
    }

    struct InstalledGuard {
        db: crate::db::Db,
        registry: ToolRegistry,
        guard: AlphaTabInstallGuard,
        body_digest: String,
    }

    /// Real install (+ adopt unless declined) through the registry: source
    /// attestation, pin digests and verified adoption all come from the
    /// flow itself, never seeds.
    async fn install_comment_package(
        declaration: Value,
        package: &str,
        adopt: bool,
    ) -> InstalledGuard {
        configure_preview_launch();
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": GUARD_ARTIFACT, "type": "Document", "kind": "artifact",
                    "name": "Comments", "body": GUARD_BODY,
                    "facets": { "runtime": "native.html.v1" },
                    "reason": "Comment guard fixture artifact.",
                }),
            )
            .await
            .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            GUARD_ARTIFACT,
            vec![AllowEntry::account(GUARD_ACCOUNT, Capability::View)],
        )
        .await
        .unwrap();
        let source_revision: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(GUARD_ARTIFACT)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let declaration_digest = alpha_tab_declaration_digest(&declaration).unwrap();
        let digest = alpha_tab_digest(
            &alpha_tab_bundle_digest(GUARD_BODY),
            &declaration_digest,
            "native.html.v1",
        );
        let base_args = json!({
            "package": package, "version": "0.1.0", "digest": digest,
            "artifact_id": GUARD_ARTIFACT, "source_revision": source_revision,
            "declaration": declaration,
        });
        let mut install_args = base_args.as_object().cloned().unwrap();
        install_args.insert("action".into(), json!("install"));
        install_args.insert("reason".into(), json!("Install comment guard fixture."));
        let installed = registry
            .call(
                db.clone(),
                Caller::authenticated(GUARD_ACCOUNT),
                "manage_alpha_tabs",
                Value::Object(install_args),
            )
            .await
            .unwrap();
        let install_event = installed["install"]["event_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut verified_event = install_event.clone();
        if adopt {
            let field = |key: &str| {
                base_args
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            let mut preview_args = base_args.as_object().cloned().unwrap();
            preview_args.insert("action".into(), json!("preview"));
            preview_args.insert("reason".into(), json!("Preview comment guard fixture."));
            let preview_caller = Caller::authenticated(GUARD_ACCOUNT)
                .with_verified_alpha_tab_preview(
                    alpha_tab_preview_authority_for(
                        GUARD_ACCOUNT,
                        &field("package"),
                        &field("version"),
                        &field("digest"),
                        &field("artifact_id"),
                        &field("source_revision"),
                        &declaration,
                    )
                    .expect("fixture declaration is well-formed"),
                );
            let preview = registry
                .call(
                    db.clone(),
                    preview_caller,
                    "manage_alpha_tabs",
                    Value::Object(preview_args),
                )
                .await
                .unwrap();
            let mut adopt_args = base_args.as_object().cloned().unwrap();
            adopt_args.insert("action".into(), json!("adopt"));
            adopt_args.insert(
                "receipt_id".into(),
                preview["receipt"]["receipt_id"].clone(),
            );
            adopt_args.insert("nonce".into(), preview["receipt"]["nonce"].clone());
            adopt_args.insert(
                "preview_session".into(),
                preview["receipt"]["preview_session"].clone(),
            );
            adopt_args.insert("expected_install_event_id".into(), json!(install_event));
            adopt_args.insert("reason".into(), json!("Adopt comment guard fixture."));
            let adopt_caller = Caller::authenticated(GUARD_ACCOUNT).with_verified_alpha_tab_adopt(
                alpha_tab_preview_authority_for(
                    GUARD_ACCOUNT,
                    &field("package"),
                    &field("version"),
                    &field("digest"),
                    &field("artifact_id"),
                    &field("source_revision"),
                    &declaration,
                )
                .expect("fixture declaration is well-formed"),
            );
            let adopted = registry
                .call(
                    db.clone(),
                    adopt_caller,
                    "manage_alpha_tabs",
                    Value::Object(adopt_args),
                )
                .await
                .unwrap();
            assert_eq!(
                adopted["install"]["adoption"], "shell_adopt.v1",
                "{adopted:#}"
            );
            verified_event = adopted["install"]["event_id"].as_str().unwrap().to_string();
        }
        let guard = AlphaTabInstallGuard {
            package: package.to_string(),
            expected_install_event_id: verified_event,
            artifact_id: GUARD_ARTIFACT.to_string(),
            source_revision,
            version: "0.1.0".to_string(),
            digest,
            declaration_digest,
        };
        let body_digest = alpha_tab_bundle_digest(GUARD_BODY);
        InstalledGuard {
            db,
            registry,
            guard,
            body_digest,
        }
    }

    async fn guard_check(
        installed: &InstalledGuard,
        guard: &AlphaTabInstallGuard,
        entry: &InteractionEntry,
        position: &str,
        source_digest: &str,
    ) -> Option<(String, String)> {
        let mut tx = crate::db::begin_write(installed.db.write_pool())
            .await
            .unwrap();
        check_comment_install_guard_in(
            &mut tx,
            &Caller::authenticated(GUARD_ACCOUNT),
            guard,
            GUARD_ARTIFACT,
            source_digest,
            entry,
            position,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn comment_guard_passes_pin_and_wrong_position_refuses() {
        let root_only = guard_declaration(json!([comment_bound(json!(["root"]))]));
        let installed = install_comment_package(root_only, "agent.comment-guard-a", true).await;
        let entry = comment_entry("post", CommentPosition::Root);
        let passed = guard_check(
            &installed,
            &installed.guard,
            &entry,
            "root",
            &installed.body_digest,
        )
        .await;
        assert!(passed.is_none(), "{passed:?}");
        // Same install, genuine reply entry: no bound contains the reply
        // position under root-only consent.
        let reply_entry = comment_entry("post", CommentPosition::Reply);
        let (code, message) = guard_check(
            &installed,
            &installed.guard,
            &reply_entry,
            "reply",
            &installed.body_digest,
        )
        .await
        .expect("wrong position must refuse");
        assert_eq!(code, "alpha_guard_effect_unconsented");
        assert!(message.contains("position 'reply'"), "{message}");
        // Forged position diverges from the entry's own position: refused
        // before consent, with the scope refusal shape.
        let (code, message) = guard_check(
            &installed,
            &installed.guard,
            &entry,
            "reply",
            &installed.body_digest,
        )
        .await
        .expect("forged position must refuse");
        assert_eq!(code, "alpha_guard_unsupported_effect");
        assert!(message.contains("diverges"), "{message}");
    }

    #[tokio::test]
    async fn comment_guard_refuses_bare_disabled_stale_and_mismatches() {
        // Bare consent: no comment bound to admit.
        let bare = guard_declaration(json!(["task.triage-set.v1"]));
        let installed = install_comment_package(bare, "agent.comment-guard-b", true).await;
        let entry = comment_entry("post", CommentPosition::Root);
        let (code, message) = guard_check(
            &installed,
            &installed.guard,
            &entry,
            "root",
            &installed.body_digest,
        )
        .await
        .expect("bare consent must refuse");
        assert_eq!(code, "alpha_guard_effect_unconsented");
        assert!(
            message.contains("does not consent to a comment.create bound"),
            "{message}"
        );
        // Adopted comment install for the pin legs below.
        let root_only = guard_declaration(json!([comment_bound(json!(["root"]))]));
        let installed = install_comment_package(root_only, "agent.comment-guard-d", true).await;
        // Stale generation refuses before pins.
        let mut stale = installed.guard.clone();
        stale.expected_install_event_id = "stale-token".into();
        let (code, _) = guard_check(&installed, &stale, &entry, "root", &installed.body_digest)
            .await
            .expect("stale generation must refuse");
        assert_eq!(code, "alpha_guard_cas_mismatch");
        // Wrong digest refuses as a pin mismatch.
        let mut repinned = installed.guard.clone();
        repinned.digest = format!("sha256:{}", "0".repeat(64));
        let (code, _) = guard_check(
            &installed,
            &repinned,
            &entry,
            "root",
            &installed.body_digest,
        )
        .await
        .expect("pin mismatch must refuse");
        assert_eq!(code, "alpha_guard_pin_mismatch");
        // Wrong invocation source refuses after the source gates pass.
        let (code, _) = guard_check(
            &installed,
            &installed.guard,
            &entry,
            "root",
            &"0".repeat(64),
        )
        .await
        .expect("source mismatch must refuse");
        assert_eq!(code, "alpha_guard_source_mismatch");
        // Unknown package refuses as a missing install.
        let mut relocated = installed.guard.clone();
        relocated.package = "agent.comment-guard-absent".into();
        let (code, _) = guard_check(
            &installed,
            &relocated,
            &entry,
            "root",
            &installed.body_digest,
        )
        .await
        .expect("missing install must refuse");
        assert_eq!(code, "alpha_guard_missing_install");
        // Unadopted install refuses adoption before source reads.
        let unadopted = install_comment_package(
            guard_declaration(json!([comment_bound(json!(["root"]))])),
            "agent.comment-guard-e",
            false,
        )
        .await;
        let (code, _) = guard_check(
            &unadopted,
            &unadopted.guard,
            &entry,
            "root",
            &unadopted.body_digest,
        )
        .await
        .expect("unverified adoption must refuse");
        assert_eq!(code, "alpha_guard_adoption_unverified");
        // Disabled install refuses with its generation pin.
        let installed = install_comment_package(
            guard_declaration(json!([comment_bound(json!(["root"]))])),
            "agent.comment-guard-g",
            true,
        )
        .await;
        let disabled = installed
            .registry
            .call(
                installed.db.clone(),
                Caller::authenticated(GUARD_ACCOUNT),
                "manage_alpha_tabs",
                json!({
                    "action": "disable", "package": "agent.comment-guard-g",
                    "expected_install_event_id": installed.guard.expected_install_event_id,
                    "reason": "Disable comment guard fixture.",
                }),
            )
            .await
            .unwrap();
        let disabled_event = disabled["install"]["event_id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut disabled_guard = installed.guard.clone();
        disabled_guard.expected_install_event_id = disabled_event;
        let (code, _) = guard_check(
            &installed,
            &disabled_guard,
            &entry,
            "root",
            &installed.body_digest,
        )
        .await
        .expect("disabled install must refuse");
        assert_eq!(code, "alpha_guard_disabled");
    }

    #[tokio::test]
    async fn alpha_resolver_yields_package_with_generation_and_declaration() {
        use super::resolve_alpha_declaring_package_in;
        use super::GuardScope;
        use crate::mcp::tools::effect_admission::{AdmissionSource, ConsentMode, PackageClaim};
        let root_only = guard_declaration(json!([comment_bound(json!(["root"]))]));
        let installed = install_comment_package(root_only, "agent.comment-resolver-a", true).await;
        let entry = comment_entry("post", CommentPosition::Root);
        let mut tx = crate::db::begin_write(installed.db.write_pool())
            .await
            .unwrap();
        let pkg = resolve_alpha_declaring_package_in(
            &mut tx,
            &Caller::authenticated(GUARD_ACCOUNT),
            PackageClaim::alpha(&installed.guard),
            GUARD_ARTIFACT,
            &installed.body_digest,
            &entry,
            GuardScope::Comment { position: "root" },
        )
        .await
        .unwrap()
        .expect("adopted install must resolve to a package");
        assert_eq!(pkg.source, AdmissionSource::AlphaTabInstall);
        assert_eq!(pkg.consent.reads, ConsentMode::Adopted);
        assert_eq!(pkg.consent.effects, ConsentMode::Adopted);
        assert_eq!(pkg.package, "agent.comment-resolver-a");
        assert_eq!(pkg.generation, installed.guard.expected_install_event_id);
        assert_eq!(pkg.artifact_id, GUARD_ARTIFACT);
        assert_eq!(pkg.source_revision, installed.guard.source_revision);
        assert_eq!(pkg.declaration_digest, installed.guard.declaration_digest);
        let stored: String = sqlx::query_scalar(
            "SELECT consented_declaration FROM alpha_tab_installs WHERE account_id=? AND package=?",
        )
        .bind(GUARD_ACCOUNT)
        .bind("agent.comment-resolver-a")
        .fetch_one(installed.db.pool())
        .await
        .unwrap();
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(pkg.declaration, stored);
        let stored_event: String = sqlx::query_scalar(
            "SELECT event_id FROM alpha_tab_installs WHERE account_id=? AND package=?",
        )
        .bind(GUARD_ACCOUNT)
        .bind("agent.comment-resolver-a")
        .fetch_one(installed.db.pool())
        .await
        .unwrap();
        assert_eq!(pkg.generation, stored_event);
    }

    #[tokio::test]
    async fn alpha_resolver_refuses_wrong_source_before_any_install_read() {
        use super::resolve_alpha_declaring_package_in;
        use super::GuardScope;
        use crate::mcp::tools::effect_admission::{
            render_refusal, AdmissionRefusal, AdmissionSource, PackageClaim,
        };
        // No install row exists anywhere in this fresh database: the
        // misrouted claim must fail with NoPackage (not PackageMissing),
        // proving the source check precedes install I/O — no second install
        // read, and no read at all, on this path.
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let guard = AlphaTabInstallGuard {
            package: "agent.absent".into(),
            expected_install_event_id: "event".into(),
            artifact_id: "artifact".into(),
            source_revision: "revision".into(),
            version: "0.1.0".into(),
            digest: "digest".into(),
            declaration_digest: "declaration".into(),
        };
        let claim = PackageClaim {
            source: AdmissionSource::AppDeclaration,
            pin: &guard,
        };
        let entry = native_artifact_runtime::mdx_v2::InteractionEntry {
            id: "mark".into(),
            label: "Mark".into(),
            effect: native_artifact_runtime::mdx_v2::InteractionEffect::FacetSet,
            slots: BTreeMap::new(),
            facet: "triage".into(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        let refusal = resolve_alpha_declaring_package_in(
            &mut tx,
            &Caller::authenticated(GUARD_ACCOUNT),
            claim,
            "artifact",
            &"0".repeat(64),
            &entry,
            GuardScope::Facet,
        )
        .await
        .unwrap()
        .expect_err("misrouted claim must fail closed");
        assert_eq!(refusal, AdmissionRefusal::NoPackage);
        let (code, message) = render_refusal(AdmissionSource::AppDeclaration, &refusal);
        assert_eq!(code, "alpha_guard_no_account");
        assert!(message.contains("no authenticated account"), "{message}");
    }

    #[tokio::test]
    async fn alpha_resolver_doubly_invalid_precedence_matches_main() {
        use super::resolve_alpha_declaring_package_in;
        use super::GuardScope;
        use crate::mcp::tools::effect_admission::{render_refusal, AdmissionSource, PackageClaim};
        // Main-literal oracles: origin/main's exact refusal code and text for
        // these states, written out here rather than read back from the
        // converted core. Consent precedes target/View/status gates, and pins
        // precede consent, so every doubly-invalid install below keeps its
        // pre-consent (or pre-gate) refusal.
        const UNCONSENTED_CODE: &str = "alpha_guard_effect_unconsented";
        const UNCONSENTED_MESSAGE: &str = "the personal alpha install does not consent to a comment.create bound for entry 'post' (position 'reply'); a declared interaction alone is never effect consent";
        async fn resolve_reply(
            installed: &InstalledGuard,
            guard: &AlphaTabInstallGuard,
        ) -> (String, String) {
            let entry = comment_entry("post", CommentPosition::Reply);
            let mut tx = crate::db::begin_write(installed.db.write_pool())
                .await
                .unwrap();
            let refusal = resolve_alpha_declaring_package_in(
                &mut tx,
                &Caller::authenticated(GUARD_ACCOUNT),
                PackageClaim::alpha(guard),
                GUARD_ARTIFACT,
                &installed.body_digest,
                &entry,
                GuardScope::Comment { position: "reply" },
            )
            .await
            .unwrap()
            .expect_err("doubly-invalid install must refuse");
            let rendered = render_refusal(AdmissionSource::AlphaTabInstall, &refusal);
            drop(tx);
            rendered
        }
        let root_only = || guard_declaration(json!([comment_bound(json!(["root"]))]));
        // Unconsented + disabled: consent wins over the status gate.
        let installed =
            install_comment_package(root_only(), "agent.comment-precedence-a", true).await;
        let disabled = installed
            .registry
            .call(
                installed.db.clone(),
                Caller::authenticated(GUARD_ACCOUNT),
                "manage_alpha_tabs",
                json!({
                    "action": "disable", "package": "agent.comment-precedence-a",
                    "expected_install_event_id": installed.guard.expected_install_event_id,
                    "reason": "Disable precedence fixture.",
                }),
            )
            .await
            .unwrap();
        let mut disabled_guard = installed.guard.clone();
        disabled_guard.expected_install_event_id = disabled["install"]["event_id"]
            .as_str()
            .unwrap()
            .to_string();
        let (code, message) = resolve_reply(&installed, &disabled_guard).await;
        assert_eq!(code, UNCONSENTED_CODE);
        assert_eq!(message, UNCONSENTED_MESSAGE);
        // Unconsented + removed: consent wins over the status gate.
        let installed =
            install_comment_package(root_only(), "agent.comment-precedence-b", true).await;
        let removed = installed
            .registry
            .call(
                installed.db.clone(),
                Caller::authenticated(GUARD_ACCOUNT),
                "manage_alpha_tabs",
                json!({
                    "action": "remove", "package": "agent.comment-precedence-b",
                    "expected_install_event_id": installed.guard.expected_install_event_id,
                    "reason": "Remove precedence fixture.",
                }),
            )
            .await
            .unwrap();
        let mut removed_guard = installed.guard.clone();
        removed_guard.expected_install_event_id =
            removed["install"]["event_id"].as_str().unwrap().to_string();
        let (code, message) = resolve_reply(&installed, &removed_guard).await;
        assert_eq!(code, UNCONSENTED_CODE);
        assert_eq!(message, UNCONSENTED_MESSAGE);
        // Unconsented + missing target: consent wins over the target gate.
        let installed =
            install_comment_package(root_only(), "agent.comment-precedence-c", true).await;
        let mut tx = crate::db::begin_write(installed.db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE records SET deleted_at=? WHERE id=?")
            .bind("2026-09-30T00:00:00Z")
            .bind(GUARD_ARTIFACT)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let (code, message) = resolve_reply(&installed, &installed.guard).await;
        assert_eq!(code, UNCONSENTED_CODE);
        assert_eq!(message, UNCONSENTED_MESSAGE);
        // Unconsented + revoked View: consent wins over the visibility gate.
        let installed =
            install_comment_package(root_only(), "agent.comment-precedence-d", true).await;
        crate::authorization::replace_explicit_policy(
            &installed.db,
            "test:policy",
            GUARD_ARTIFACT,
            vec![],
        )
        .await
        .unwrap();
        let (code, message) = resolve_reply(&installed, &installed.guard).await;
        assert_eq!(code, UNCONSENTED_CODE);
        assert_eq!(message, UNCONSENTED_MESSAGE);
        // Unconsented + stale generation: the pin wins over consent.
        let installed =
            install_comment_package(root_only(), "agent.comment-precedence-e", true).await;
        let mut stale = installed.guard.clone();
        stale.expected_install_event_id = "stale-token".into();
        let (code, message) = resolve_reply(&installed, &stale).await;
        assert_eq!(code, "alpha_guard_cas_mismatch");
        assert_eq!(
            message,
            format!(
                "installation changed; the guarded generation stale-token is stale (current {})",
                installed.guard.expected_install_event_id
            )
        );
    }

    #[tokio::test]
    async fn alpha_admission_generic_facet_malformed_and_empty_keep_literal_stage_refusal() {
        use crate::mcp::tools::effect_admission::{render_refusal, AdmissionSource, PackageClaim};
        use native_artifact_runtime::mdx_v2::ValueSource;
        // Corrupt stored consent after a real install while retaining the
        // matching guard/row pins. Missing target and declaration mismatch
        // are also present: the literal facet refusal must precede both.
        for effects in [json!([]), json!([{"effect": "records.facet-set.v1"}])] {
            let installed = install_comment_package(
                guard_declaration(json!([comment_bound(json!(["root"]))])),
                "agent.facet-stage",
                true,
            )
            .await;
            let declaration = guard_declaration(effects);
            let mut tx = crate::db::begin_write(installed.db.write_pool())
                .await
                .unwrap();
            sqlx::query("UPDATE alpha_tab_installs SET consented_declaration=? WHERE account_id=? AND package=?")
                .bind(declaration.to_string())
                .bind(GUARD_ACCOUNT).bind(&installed.guard.package).execute(&mut *tx).await.unwrap();
            sqlx::query("UPDATE records SET deleted_at=? WHERE id=?")
                .bind("2026-09-30T00:00:00Z")
                .bind(GUARD_ARTIFACT)
                .execute(&mut *tx)
                .await
                .unwrap();
            let entry = InteractionEntry {
                id: "mark".into(),
                label: "Mark".into(),
                effect: InteractionEffect::FacetSet,
                slots: BTreeMap::new(),
                facet: "priority".into(),
                value: Some(ValueSource::Literal {
                    value: json!("high"),
                }),
                create: None,
                comment: None,
                react: None,
                title: None,
                body: None,
            };
            let refusal = super::resolve_alpha_admission_in(
                &mut tx,
                &Caller::authenticated(GUARD_ACCOUNT),
                PackageClaim::alpha(&installed.guard),
                GUARD_ARTIFACT,
                &installed.body_digest,
                &entry,
                super::GuardScope::Facet,
            )
            .await
            .unwrap()
            .expect_err("facet consent must refuse before later gates");
            let (code, message) = render_refusal(AdmissionSource::AlphaTabInstall, &refusal);
            assert_eq!(code, "alpha_guard_facet_unconsented");
            assert_eq!(message, "the personal-install guard consents only to facet 'triage' or the tasks lifecycle arm; entry 'mark' targets 'priority'");
        }
    }

    #[tokio::test]
    async fn alpha_admission_carries_same_transaction_comment_bound_and_need() {
        use crate::mcp::tools::effect_admission::{ConsentMode, PackageClaim};
        use crate::mcp::tools::effect_bounds::Admitted;
        let installed = install_comment_package(
            guard_declaration(json!([comment_bound(json!(["root"]))])),
            "agent.comment-carry",
            true,
        )
        .await;
        let mut entry = comment_entry("post", CommentPosition::Root);
        // The old comment scope chose object consent before catalogue facet
        // matching. Incidental triage text must not change that selection.
        entry.facet = "triage".into();
        let mut tx = crate::db::begin_write(installed.db.write_pool())
            .await
            .unwrap();
        let resolved = super::resolve_alpha_admission_in(
            &mut tx,
            &Caller::authenticated(GUARD_ACCOUNT),
            PackageClaim::alpha(&installed.guard),
            GUARD_ARTIFACT,
            &installed.body_digest,
            &entry,
            super::GuardScope::Comment { position: "root" },
        )
        .await
        .unwrap()
        .expect("verified install must carry static admission");
        assert_eq!(resolved.package.package, "agent.comment-carry");
        assert_eq!(
            resolved.package.generation,
            installed.guard.expected_install_event_id
        );
        assert_eq!(
            resolved.package.declaration,
            guard_declaration(json!([comment_bound(json!(["root"]))]))
        );
        assert_eq!(resolved.package.consent.effects, ConsentMode::Adopted);
        let Admitted::Comment { bound, need } = resolved.admitted else {
            panic!("comment scope must carry a comment bound");
        };
        assert_eq!(bound.positions, vec!["root"]);
        assert_eq!(bound.max_body_bytes, 100);
        assert_eq!(bound.need, "thread.items");
        assert_eq!(need.key, "thread.items");
        assert_eq!(
            need.sql,
            "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40"
        );
    }

    #[tokio::test]
    async fn alpha_resolver_refusals_match_guard_byte_for_byte() {
        use super::resolve_alpha_declaring_package_in;
        use super::GuardScope;
        use crate::mcp::tools::effect_admission::{
            render_refusal, AdmissionRefusal, AdmissionSource, PackageClaim,
        };
        let root_only = guard_declaration(json!([comment_bound(json!(["root"]))]));
        let installed = install_comment_package(root_only, "agent.comment-resolver-b", true).await;
        let entry = comment_entry("post", CommentPosition::Root);
        // A stale generation and a pin mismatch: both must refuse exactly as
        // the existing guard does — same structured variant, same code and
        // same text — proving the resolver adds no second interpretation.
        let mut stale = installed.guard.clone();
        stale.expected_install_event_id = "stale-token".into();
        let mut repinned = installed.guard.clone();
        repinned.digest = format!("sha256:{}", "0".repeat(64));
        // Doubly-invalid precedence (D7 §4C.2 step 3–4): an unconsented entry
        // on a stale generation keeps the generation refusal, not the
        // consent refusal.
        let reply_entry = comment_entry("post", CommentPosition::Reply);
        for (bad, probe) in [
            (&stale, &entry),
            (&repinned, &entry),
            (&stale, &reply_entry),
        ] {
            let position = match probe.comment.as_ref().unwrap().position {
                CommentPosition::Root => "root",
                CommentPosition::Reply => "reply",
            };
            // guard_check opens and drops its own write transaction; the
            // resolver's tx2 below begins only after that await resolves, so
            // the two never hold the write pool at once.
            let (code, message) =
                guard_check(&installed, bad, probe, position, &installed.body_digest)
                    .await
                    .expect("bad pin must refuse");
            let mut tx2 = crate::db::begin_write(installed.db.write_pool())
                .await
                .unwrap();
            let refusal = resolve_alpha_declaring_package_in(
                &mut tx2,
                &Caller::authenticated(GUARD_ACCOUNT),
                PackageClaim::alpha(bad),
                GUARD_ARTIFACT,
                &installed.body_digest,
                probe,
                GuardScope::Comment { position },
            )
            .await
            .unwrap()
            .expect_err("bad pin must refuse through the resolver");
            let (rendered_code, rendered_message) =
                render_refusal(AdmissionSource::AlphaTabInstall, &refusal);
            assert_eq!(rendered_code, code);
            assert_eq!(rendered_message, message);
        }
        // The stale leg resolves to the structured `Stale` variant carrying
        // the guarded and current generations.
        let mut tx3 = crate::db::begin_write(installed.db.write_pool())
            .await
            .unwrap();
        let refusal = resolve_alpha_declaring_package_in(
            &mut tx3,
            &Caller::authenticated(GUARD_ACCOUNT),
            PackageClaim::alpha(&stale),
            GUARD_ARTIFACT,
            &installed.body_digest,
            &entry,
            GuardScope::Comment { position: "root" },
        )
        .await
        .unwrap()
        .expect_err("stale generation must refuse");
        match &refusal {
            AdmissionRefusal::Stale { expected, current } => {
                assert_eq!(expected, "stale-token");
                assert_eq!(current, &installed.guard.expected_install_event_id);
            }
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn legacy_public_guard_still_refuses_comment_entries() {
        // No install rows anywhere: every leg refuses before install I/O,
        // proving scope rather than fixture breakage.
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let entry = comment_entry("post", CommentPosition::Root);
        let (code, message) = check_alpha_install_guard_in(
            &mut tx,
            &Caller::authenticated(GUARD_ACCOUNT),
            &AlphaTabInstallGuard {
                package: "agent.comment-guard-a".into(),
                expected_install_event_id: "event".into(),
                artifact_id: "artifact".into(),
                source_revision: "revision".into(),
                version: "0.1.0".into(),
                digest: "digest".into(),
                declaration_digest: "declaration".into(),
            },
            "artifact",
            &"0".repeat(64),
            &entry,
        )
        .await
        .unwrap()
        .expect("public guard must refuse comment entries");
        assert_eq!(code, "alpha_guard_unsupported_effect");
        assert!(message.contains("facet-scoped guard"), "{message}");
        // The comment wrapper refuses non-comment entries, missing
        // envelopes and bad positions before any install I/O either.
        let facet_entry = native_artifact_runtime::mdx_v2::InteractionEntry {
            id: "mark".into(),
            label: "Mark".into(),
            effect: native_artifact_runtime::mdx_v2::InteractionEffect::FacetSet,
            slots: BTreeMap::new(),
            facet: "triage".into(),
            value: None,
            create: None,
            comment: None,
            react: None,
            title: None,
            body: None,
        };
        let guard = AlphaTabInstallGuard {
            package: "agent.comment-guard-a".into(),
            expected_install_event_id: "event".into(),
            artifact_id: "artifact".into(),
            source_revision: "revision".into(),
            version: "0.1.0".into(),
            digest: "digest".into(),
            declaration_digest: "declaration".into(),
        };
        for (entry, position) in [
            (&facet_entry, "root"),
            (
                &native_artifact_runtime::mdx_v2::InteractionEntry {
                    comment: None,
                    ..comment_entry("post", CommentPosition::Root)
                },
                "root",
            ),
            (&entry, "pinned"),
        ] {
            let (code, _) = check_comment_install_guard_in(
                &mut tx,
                &Caller::authenticated(GUARD_ACCOUNT),
                &guard,
                "artifact",
                &"0".repeat(64),
                entry,
                position,
            )
            .await
            .unwrap()
            .expect("comment scope violations must refuse");
            assert_eq!(code, "alpha_guard_unsupported_effect");
        }
    }
}

/// Comment delivered-need membership (task `b9fb9fd` family 1): the shared
/// core over real caller transactions and viewer-authorized rows. The
/// truncated-need leg proves the FIRST200 cap admits delivered rows while
/// refusing later ones; the TEMP leg proves ordinary reads and writes work
/// after membership on the same connection.
#[cfg(test)]
mod comment_membership_tests {
    use super::{
        check_comment_membership_in, check_facet_set_membership_in, parse_sql_need_entry,
        CommentCreateBound, FacetSetBound,
    };
    use crate::mcp::{Caller, ToolRegistry};
    use serde_json::{json, Value};

    fn thread_need() -> Value {
        json!({"need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'row-%' ORDER BY id ASC LIMIT 300"})
    }

    fn comment_bound() -> CommentCreateBound {
        CommentCreateBound {
            positions: vec!["root".to_string()],
            max_body_bytes: 100,
            need: "thread.items".to_string(),
        }
    }

    /// 205 ordered records on a fresh database: the static need delivers
    /// the first 200 and truncates. Fixed v4 UUIDs keep `ORDER BY id` ==
    /// creation order regardless of engine seeds.
    async fn many_row_fixture() -> (crate::db::Db, ToolRegistry, Vec<String>) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        let mut ids = Vec::with_capacity(205);
        for index in 0..205 {
            let id = format!("{index:08x}-0000-4000-8000-{index:012x}");
            registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "create_record",
                    json!({
                        "id": id, "type": "Document", "kind": "note",
                        "name": format!("row-{index:03}"),
                        "reason": "Comment membership truncation fixture.",
                    }),
                )
                .await
                .unwrap();
            ids.push(id);
        }
        (db, registry, ids)
    }

    #[tokio::test]
    async fn truncated_need_admits_delivered_and_refuses_late_rows() {
        let (db, registry, ids) = many_row_fixture().await;
        let need = parse_sql_need_entry(&thread_need()).unwrap();
        let bound = comment_bound();
        let caller = Caller::local();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Exact delivery boundary: row 199 of 205 admits, row 200 refuses.
        let admitted =
            check_comment_membership_in(&mut tx, &caller, &bound, &need, Some(&ids[199]))
                .await
                .unwrap();
        assert!(admitted.is_none(), "{admitted:?}");
        let (code, message) =
            check_comment_membership_in(&mut tx, &caller, &bound, &need, Some(&ids[200]))
                .await
                .unwrap()
                .expect("boundary row must refuse");
        assert_eq!(code, "record_outside_need");
        assert!(message.contains("thread.items"), "{message}");
        assert!(message.contains("bound 'thread.items'"), "{message}");
        // Further late row refuses with the paired positive retained above.
        let (code, _) =
            check_comment_membership_in(&mut tx, &caller, &bound, &need, Some(&ids[203]))
                .await
                .unwrap()
                .expect("late row must refuse");
        assert_eq!(code, "record_outside_need");
        // No target refuses without leaking rows.
        let (code, message) = check_comment_membership_in(&mut tx, &caller, &bound, &need, None)
            .await
            .unwrap()
            .expect("missing target must refuse");
        assert_eq!(code, "record_outside_need");
        assert!(message.contains("unresolved"), "{message}");
        // Same-transaction governed SQL still reads through the seam after
        // membership: TEMP setup and cleanup are per-call, so the held
        // write transaction stays usable for ordinary work.
        let (reread, _) = crate::query::sql::query_sql_request_in_with_row_limit(
            &mut tx,
            (&caller).into(),
            crate::query::sql_contract::QuerySqlRequest {
                sql: "SELECT id FROM records WHERE deleted_at IS NULL AND name LIKE 'row-%' ORDER BY id ASC LIMIT 5"
                    .to_string(),
                parameters: Vec::new(),
            },
            super::SQL_SNAPSHOT_ROW_CAP as i64,
            crate::query::sql_contract::FunctionAllowance::Portable,
        )
        .await
        .unwrap();
        assert_eq!(reread.rows.len(), 5);
        assert_eq!(reread.rows[0]["id"], json!(&ids[0]));
        // Same-transaction store append projects: the fixture row's
        // governed name changes and reads back on this snapshot. Cleanup
        // and projection proof only — not comment authority.
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::store::append_in(
            &db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: ids[5].clone(),
                event_type: "record.updated".into(),
                payload: json!({"name": "row-renamed"}),
                actor: Some(caller.actor().to_string()),
            },
            &mut act_alloc,
        )
        .await
        .unwrap();
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id=?")
            .bind(&ids[5])
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(name, "row-renamed");
        tx.commit().await.unwrap();
        // Ordinary reads and writes work after membership on this stack.
        let created = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note", "name": "after",
                    "reason": "Comment membership TEMP cleanup proof.",
                }),
            )
            .await
            .unwrap();
        let read = registry
            .call(
                db.clone(),
                Caller::local(),
                "get_record",
                json!({ "ids": [created["id"]] }),
            )
            .await
            .unwrap();
        assert_eq!(read["records"][0]["name"], "after");
    }

    #[tokio::test]
    async fn parameterized_time_and_mismatched_needs_refuse() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        let _ = &registry;
        let caller = Caller::local();
        let bound = comment_bound();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Parameterized needs refuse before running SQL.
        let param_need = parse_sql_need_entry(&json!({
            "need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread",
            "sql": "SELECT id FROM records WHERE lifecycle = ?1",
            "params": [{"name": "lifecycle", "type": "text"}],
        }))
        .unwrap();
        let (code, message) =
            check_comment_membership_in(&mut tx, &caller, &bound, &param_need, Some("row"))
                .await
                .unwrap()
                .expect("parameterized need must refuse");
        assert_eq!(code, "comment_need_parameterized");
        assert!(message.contains("thread.items"), "{message}");
        // Time-dependent needs refuse after running SQL.
        let time_need = parse_sql_need_entry(&json!({
            "need": "sql.snapshot.v1", "key": "thread.items", "label": "Thread",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL AND now_ms() > 0 ORDER BY id ASC LIMIT 40",
        }))
        .unwrap();
        let (code, message) =
            check_comment_membership_in(&mut tx, &caller, &bound, &time_need, Some("row"))
                .await
                .unwrap()
                .expect("time-dependent need must refuse");
        assert_eq!(code, "comment_need_time_dependent");
        assert!(message.contains("thread.items"), "{message}");
        // Bound need must equal the need under test: no SQL runs.
        let other_need = parse_sql_need_entry(&json!({
            "need": "sql.snapshot.v1", "key": "other.items", "label": "Other",
            "sql": "SELECT id FROM records WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 40",
        }))
        .unwrap();
        let (code, message) =
            check_comment_membership_in(&mut tx, &caller, &bound, &other_need, Some("row"))
                .await
                .unwrap()
                .expect("mismatched need must refuse");
        assert_eq!(code, "comment_need_mismatch");
        assert!(message.contains("thread.items"), "{message}");
        assert!(message.contains("other.items"), "{message}");
        // The facet wrapper keeps its exact historical copy.
        let facet_bound = FacetSetBound {
            key: "priority".to_string(),
            values: vec!["low".to_string()],
            need: "thread.items".to_string(),
        };
        let need = parse_sql_need_entry(&thread_need()).unwrap();
        let (code, message) =
            check_facet_set_membership_in(&mut tx, &caller, &facet_bound, &need, Some("row"))
                .await
                .unwrap()
                .expect("facet wrapper must refuse outside rows");
        assert_eq!(code, "record_outside_need");
        assert!(message.contains("(key 'priority')"), "{message}");
    }

    #[tokio::test]
    async fn targeted_comment_admits_old_document_but_not_a_missing_or_excluded_target() {
        let (db, _registry, ids) = many_row_fixture().await;
        let caller = Caller::local();
        let bound = comment_bound();
        let need = parse_sql_need_entry(&json!({
            "need": "sql.snapshot.v1", "key": "thread.items", "label": "One document",
            "sql": "SELECT id FROM records WHERE id = ?1 AND type = 'Document' AND deleted_at IS NULL AND name <> 'row-203' ORDER BY id LIMIT 1",
            "params": [{"name": "record_id", "type": "text", "max_len": 128}],
        })).unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        // Beyond the old static 200-row boundary; the host binds the target.
        assert!(
            check_comment_membership_in(&mut tx, &caller, &bound, &need, Some(&ids[204]))
                .await
                .unwrap()
                .is_none()
        );
        for target in [Some(ids[203].as_str()), Some("missing"), None] {
            let (code, _) = check_comment_membership_in(&mut tx, &caller, &bound, &need, target)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(code, "record_outside_need");
        }
        let mut short = need.clone();
        short.params[0].max_len = 1;
        assert_eq!(
            check_comment_membership_in(&mut tx, &caller, &bound, &short, Some(&ids[204]))
                .await
                .unwrap()
                .unwrap()
                .0,
            "invalid_sql_param"
        );
        // The new path is specific to comments; other effect families retain
        // their delivered static-need semantics.
        assert_eq!(
            super::check_delivered_membership_in(
                &mut tx,
                &caller,
                super::MembershipFamily::FacetSet,
                &need,
                "test",
                Some(&ids[204])
            )
            .await
            .unwrap()
            .unwrap()
            .0,
            "facet_need_parameterized"
        );
        tx.rollback().await.unwrap();
    }
}

/// Drift guard for `packages/alpha-tab-kit`, which mirrors this module's
/// install rules for packages checked outside this repository.
#[cfg(test)]
#[path = "alpha_tab_kit_drift.rs"]
mod alpha_tab_kit_drift;

#[cfg(test)]
mod inert_body_read_descriptor_tests {
    use super::*;
    use crate::mcp::tools::effect_bounds::{react_admission, title_admission};

    fn body() -> Value {
        json!({"need": BODY_READ_NEED, "scope": BODY_READ_SCOPE})
    }
    fn sql(key: &str) -> Value {
        json!({"need": SQL_SNAPSHOT_NEED, "key": key, "label": "Rows", "sql": "SELECT id FROM records ORDER BY id LIMIT 1"})
    }
    fn declaration(needs: Vec<Value>) -> Value {
        json!({"needs": needs, "effects": []})
    }

    #[test]
    fn body_descriptor_canonicalization_is_inert_and_distinct_from_bare_names() {
        let candidate = declaration(vec![body()]);
        assert_eq!(
            alpha_tab_canonical_declaration(&candidate).unwrap(),
            json!({
                "needs": [], "effects": [], "body_read_needs": [body()]
            })
        );
        assert!(require_declaration(&candidate)
            .unwrap_err()
            .to_string()
            .contains("body_admission_unavailable"));
        assert!(sql_needs_in(&candidate).unwrap().is_empty());
        let bare = declaration(vec![json!(BODY_READ_NEED)]);
        assert_eq!(alpha_tab_canonical_declaration(&bare).unwrap(), bare);
        assert!(require_declaration(&bare).is_ok());
        assert_ne!(
            alpha_tab_declaration_digest(&bare).unwrap(),
            alpha_tab_declaration_digest(&candidate).unwrap()
        );
        // Standalone historic digest acceptance is deliberately wider than
        // install acceptance. Do not retroactively reject duplicate SQL keys.
        let historic = declaration(vec![sql(BODY_READ_NEED), sql(BODY_READ_NEED)]);
        assert!(alpha_tab_declaration_digest(&historic).is_ok());
        assert!(require_declaration(&declaration(vec![sql(BODY_READ_NEED)])).is_ok());
    }

    #[test]
    fn body_descriptor_rejects_malformed_and_cross_kind_collisions() {
        let invalid = [
            json!({"need": BODY_READ_NEED}),
            json!({"need": BODY_READ_NEED, "scope": null}),
            json!({"need": BODY_READ_NEED, "scope": " viewer-visible-current-bodies"}),
            json!({"need": BODY_READ_NEED, "scope": BODY_READ_SCOPE, "label": "Read"}),
            json!({"need": "records.body.read.v2", "scope": BODY_READ_SCOPE}),
        ];
        for item in invalid {
            let candidate = declaration(vec![item]);
            assert!(alpha_tab_declaration_digest(&candidate).is_err());
            assert!(sql_needs_in(&candidate).is_err());
            assert!(require_declaration(&candidate).is_err());
        }
        for other in [body(), json!(BODY_READ_NEED), sql(BODY_READ_NEED)] {
            for needs in [vec![body(), other.clone()], vec![other.clone(), body()]] {
                let candidate = declaration(needs);
                assert!(alpha_tab_declaration_digest(&candidate).is_err());
                assert!(sql_needs_in(&candidate).is_err());
                assert!(require_declaration(&candidate).is_err());
            }
        }
    }

    #[test]
    fn body_descriptor_counts_toward_total_but_not_sql_limit() {
        let mut needs: Vec<Value> = (0..8).map(|i| sql(&format!("rows.{i}"))).collect();
        needs.push(body());
        assert_eq!(sql_needs_in(&declaration(needs.clone())).unwrap().len(), 8);
        needs.push(sql("rows.ninth"));
        assert!(sql_needs_in(&declaration(needs)).is_err());
        let mut needs = vec![body()];
        needs.extend((0..63).map(|i| json!(format!("unknown.{i}"))));
        assert!(alpha_tab_declaration_digest(&declaration(needs.clone())).is_ok());
        needs.push(json!("unknown.extra"));
        assert!(alpha_tab_declaration_digest(&declaration(needs.clone())).is_err());
        assert!(sql_needs_in(&declaration(needs)).is_err());
    }

    #[test]
    fn body_descriptor_is_skipped_by_sql_effect_target_scans() {
        let effects = json!([
            {"effect": TITLE_SET_EFFECT, "target": {"need": "rows.target"}},
            {"effect": MESSAGE_REACT_EFFECT, "target": {"need": "rows.target"}, "emoji": ["👍"]}
        ]);
        for needs in [
            vec![body(), sql("rows.target")],
            vec![sql("rows.target"), body()],
        ] {
            let candidate = json!({"needs": needs, "effects": effects});
            assert_eq!(
                title_admission(&candidate, "entry").unwrap().1.key,
                "rows.target"
            );
            assert_eq!(
                react_admission(&candidate, "entry", "👍").unwrap().1.key,
                "rows.target"
            );
            assert!(require_declaration(&candidate).is_err());
        }
        let effects = json!([
            {"effect": TITLE_SET_EFFECT, "target": {"need": BODY_READ_NEED}},
            {"effect": MESSAGE_REACT_EFFECT, "target": {"need": BODY_READ_NEED}, "emoji": ["👍"]}
        ]);
        let candidate = json!({"needs": [body()], "effects": effects});
        assert!(title_admission(&candidate, "entry").is_err());
        assert!(react_admission(&candidate, "entry", "👍").is_err());
        // The same spelling remains a genuine legacy SQL target without a
        // descriptor: never change the historical SQL reserved-name set.
        let legacy = json!({"needs": [sql(BODY_READ_NEED)], "effects": effects});
        assert!(require_declaration(&legacy).is_ok());
        assert_eq!(
            title_admission(&legacy, "entry").unwrap().1.key,
            BODY_READ_NEED
        );
        assert_eq!(
            react_admission(&legacy, "entry", "👍").unwrap().1.key,
            BODY_READ_NEED
        );
    }
}
