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

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::act::ActAllocation;
use crate::authorization::Capability;
use crate::control::{
    alpha_tab_aggregate_id, append_control_event_in, AlphaTabAdoptPayload, AlphaTabStatePayload,
    ControlEventPayload, NewControlEvent, ALPHA_TAB_ADOPTION_VERIFIED,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::generated::kinds::CoreKind;

use super::super::registry::{Caller, ToolRegistry, VerifiedAlphaTabPreview};
use super::super::ToolKind;
use super::{echo_act, parse_args, require_nonblank_reason};

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

/// Bounds on `records.search.v1` parameters. The limit matches alpha's shell
/// search, so the package cannot page further than the shell does.
pub const SEARCH_QUERY_MAX_CHARS: usize = 200;
pub const SEARCH_LIMIT_MAX: i64 = 30;

/// Bound on `records.resolve_reference.v1`'s reference parameter.
pub const REFERENCE_MAX_CHARS: usize = 128;

/// One declared on-request read, with parameters already bounded.
#[derive(Debug, PartialEq, Eq)]
pub enum DeclaredRead {
    Search { query: String, limit: i64 },
    ResolveReference { reference: String },
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
        _ => Err("unknown_need"),
    }
}

/// The single consented write effect the L2 guarded facet path executes
/// (task `26ba75a`). Provisional vocabulary: a semantic effect string from
/// the install's consented declaration — not a manifest entry id and not a
/// bundle hash. A guarded `invoke_artifact_interaction` refuses with
/// `alpha_guard_effect_unconsented` unless the install's consented
/// `effects` include exactly this value. A declared v2 manifest interaction
/// alone, or a matching bundle digest alone, is never effect consent.
///
/// The guard envelope carries no effect name in this slice, so there is no
/// effect vocabulary to validate on the envelope itself. If a future slice
/// adds an effect name to the guard, it must accept only this value.
pub const ALPHA_TRIAGE_SET_EFFECT: &str = "task.triage-set.v1";

/// The single facet the L2 guarded path may move (task `26ba75a`).
/// Provisional scope: consent to [`ALPHA_TRIAGE_SET_EFFECT`] authorizes only
/// the declared triage `facet.set` / `facet.unset` pair — never
/// `record.create`, never another facet. Checked against the actual parsed
/// manifest entry inside the write transaction, never against caller text.
pub const ALPHA_GUARD_FACET: &str = "triage";

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

/// Internal candidate scan cap for one `attention.query.v1` execution: at
/// most this many newest-first attention-shaped candidates are examined for
/// viewer authorization. Together with `ATTENTION_LIVE_LIMIT` this bounds
/// the read to one ordered SQL query plus at most this many per-row `View`
/// checks. Internal only: the public response never discloses the scanned
/// count or whether the window ran out (those would reveal the density of
/// inaccessible tasks), it only carries the static `bounded_window: true`
/// marker.
pub const ATTENTION_CANDIDATE_SCAN_CAP: i64 = 500;

/// Pinned `attention.query.v1` row semantics, v1 (task `26ba75a`).
///
/// Live `WorkItem`/`task` rows only: `deleted_at IS NULL`, hidden rows
/// excluded via the shared `not_hidden` predicate, no `archived` facet,
/// `lifecycle IS NOT NULL` and not a known-terminal token
/// (`completed`, `closed`). Unknown lifecycle tokens stay included (attention,
/// like the dashboard buckets, must not drop open work over a vocabulary
/// gap). Viewer `View` is enforced per row in host code under the same
/// `can_record_in` the launch gate uses — but AFTER an internal bounded
/// scan, not after a bare `LIMIT 50`: the executor scans newest-first
/// candidates and keeps the first `ATTENTION_LIVE_LIMIT` authorized rows,
/// so inaccessible newer tasks cannot starve visible older ones within the
/// window. Stable order: `last_activity_at DESC`, `id ASC`.
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
const VERIFIED_ALPHA_TAB_ADOPTIONS: &[&str] = &[ALPHA_TAB_ADOPTION_VERIFIED];

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

/// Canonical declaration form: exactly `needs` + `effects`, each sorted
/// ascending by UTF-8 bytes with duplicates preserved. Object key order is
/// irrelevant (JCS); array order is normalized here because consent covers
/// the declared set, not the author's ordering. Total: anything that is
/// not the validated shape folds to empty arrays rather than failing.
pub fn alpha_tab_canonical_declaration(declaration: &Value) -> Value {
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
    json!({"needs": names("needs"), "effects": names("effects")})
}

/// Canonical declaration digest: hex SHA-256 over the JCS bytes of the
/// canonical form. No `sha256:` prefix (matches the stored
/// `declaration_digest` hex convention); deliberately NOT the install-time
/// raw hash, which is order-sensitive storage rather than proof input.
pub fn alpha_tab_declaration_digest(declaration: &Value) -> String {
    crate::canonical_json::digest_json(&alpha_tab_canonical_declaration(declaration))
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
/// `effects` must include [`ALPHA_TRIAGE_SET_EFFECT`]. A declared v2
/// manifest interaction alone, or a matching bundle digest alone, is never
/// consent. The guard envelope carries no effect name in this slice; if a
/// future slice adds one, it must accept only [`ALPHA_TRIAGE_SET_EFFECT`].
///
/// Scope is entry-side: even with effect consent, only the declared triage
/// `facet.set` / `facet.unset` pair on [`ALPHA_GUARD_FACET`] may commit.
/// Checked against the actual parsed manifest `entry` — never caller text —
/// so consent to triage-set cannot authorize `record.create` or another
/// facet. Guarded writes additionally require `native.html.v1`, matching the
/// alpha launch path.
///
/// Returns `Ok(None)` when the guard passes, `Ok(Some((code, message)))`
/// when it refuses. A refusal names the personal install only — it never
/// claims the artifact is globally disabled for other Workbench use.
pub(crate) async fn check_alpha_install_guard_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    guard: &native_artifact_runtime::artifact_intents::AlphaTabInstallGuard,
    invocation_artifact_id: &str,
    invocation_source_digest: &str,
    entry: &native_artifact_runtime::mdx_v2::InteractionEntry,
) -> Result<Option<(String, String)>> {
    // Scope first, before any install I/O: the actual parsed entry decides,
    // never caller text. Consent to triage-set authorizes only the triage
    // facet.set/unset pair.
    if !matches!(
        entry.effect,
        native_artifact_runtime::mdx_v2::InteractionEffect::FacetSet
            | native_artifact_runtime::mdx_v2::InteractionEffect::FacetUnset
    ) {
        return Ok(Some((
            "alpha_guard_unsupported_effect".into(),
            "the personal-install guard applies only to the declared triage facet.set/facet.unset pair; record.create with a guard is refused".into(),
        )));
    }
    if entry.facet != ALPHA_GUARD_FACET {
        return Ok(Some((
            "alpha_guard_facet_unconsented".into(),
            format!(
                "the personal-install guard consents only to facet '{ALPHA_GUARD_FACET}'; entry '{}' targets '{entry_facet}'",
                entry.id,
                entry_facet = entry.facet,
            ),
        )));
    }
    let account_id = caller.credential().trim().to_string();
    if account_id.is_empty() {
        return Ok(Some((
            "alpha_guard_no_account".into(),
            "no authenticated account is bound to this caller; the personal-install guard cannot be checked".into(),
        )));
    }
    if guard.artifact_id != invocation_artifact_id {
        return Ok(Some((
            "alpha_guard_artifact_mismatch".into(),
            "the install guard names a different artifact than the invocation; re-read the consented install and retry".into(),
        )));
    }
    let Some(row) = install_row_in(tx, &account_id, &guard.package).await? else {
        return Ok(Some((
            "alpha_guard_missing_install".into(),
            format!(
                "package {} is not installed for this account; other Workbench use of the artifact is unaffected",
                guard.package
            ),
        )));
    };
    if guard.expected_install_event_id != row.event_id {
        return Ok(Some((
            "alpha_guard_cas_mismatch".into(),
            format!(
                "installation changed; the guarded generation {} is stale (current {})",
                guard.expected_install_event_id, row.event_id
            ),
        )));
    }
    if guard.artifact_id != row.artifact_id
        || guard.source_revision != row.consented_source_revision
        || guard.version != row.version
        || guard.digest != row.digest
        || guard.declaration_digest != row.declaration_digest
    {
        return Ok(Some((
            "alpha_guard_pin_mismatch".into(),
            "the install guard does not match the installed pin field-for-field; re-read the install and retry".into(),
        )));
    }
    // Effect consent: the install must declare the provisional triage-set
    // effect. Pure check over the stored declaration — no I/O — so it runs
    // before target/source reads. A manifest entry or bundle digest alone is
    // never consent.
    let consented_effects: Vec<String> = row
        .consented_declaration
        .get("effects")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if !consented_effects
        .iter()
        .any(|effect| effect == ALPHA_TRIAGE_SET_EFFECT)
    {
        return Ok(Some((
            "alpha_guard_effect_unconsented".into(),
            format!(
                "the personal alpha install {} does not consent to {ALPHA_TRIAGE_SET_EFFECT}; a declared interaction alone is never effect consent",
                row.package
            ),
        )));
    }
    let target = target_state_in(tx, &row.artifact_id).await?;
    let can_view = if target == TargetState::Resolvable {
        super::can_record_in(tx, caller, &row.artifact_id, Capability::View).await?
    } else {
        false
    };
    if let Err(reason) =
        evaluate_alpha_tab_install_gates(&row.status, &row.adoption, target, can_view)
    {
        let (code, message) = match reason {
            "removed" => (
                "alpha_guard_removed",
                format!(
                    "the personal alpha install {} was removed; the guarded invocation is refused but other Workbench use of the artifact is unaffected",
                    row.package
                ),
            ),
            "disabled" => (
                "alpha_guard_disabled",
                format!(
                    "the personal alpha install {} is disabled; the guarded invocation is refused but other Workbench use of the artifact is unaffected",
                    row.package
                ),
            ),
            "adoption_unverified" => (
                "alpha_guard_adoption_unverified",
                format!(
                    "the personal alpha install {} is not verified (shell_adopt.v1); the guarded invocation is refused",
                    row.package
                ),
            ),
            "missing" => (
                "alpha_guard_target_missing",
                format!(
                    "the personal alpha install {} target {} is missing",
                    row.package, row.artifact_id
                ),
            ),
            "archived" => (
                "alpha_guard_target_archived",
                format!(
                    "the personal alpha install {} target {} is archived",
                    row.package, row.artifact_id
                ),
            ),
            "wrong_record_type" => (
                "alpha_guard_target_wrong_type",
                format!(
                    "the personal alpha install {} target {} is not an artifact",
                    row.package, row.artifact_id
                ),
            ),
            _ => (
                "alpha_guard_unauthorized",
                format!(
                    "the viewer may not view the personal alpha install {} target {}",
                    row.package, row.artifact_id
                ),
            ),
        };
        return Ok(Some((code.into(), message)));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&row.artifact_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten();
    let declaration_digest = alpha_tab_declaration_digest(&row.consented_declaration);
    if declaration_digest != row.declaration_digest {
        return Ok(Some((
            "alpha_guard_declaration_mismatch".into(),
            "the installed declaration digest does not match the consented declaration".into(),
        )));
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
        let (code, message) = match reason {
            "not_renderable" => (
                "alpha_guard_not_renderable",
                "the guarded install target is not renderable".to_string(),
            ),
            "source_revision_unresolved" => (
                "alpha_guard_source_unresolved",
                "the guarded install source revision resolves to no body-carrying event".to_string(),
            ),
            _ => (
                "alpha_guard_digest_mismatch",
                "the guarded install digest does not match the consented source; re-read the install and retry".to_string(),
            ),
        };
        return Ok(Some((code.into(), message)));
    }
    let source = source.expect("source gate passed");
    let bundle_sha256 = alpha_tab_bundle_digest(&source.body);
    if bundle_sha256 != invocation_source_digest {
        return Ok(Some((
            "alpha_guard_source_mismatch".into(),
            "the invocation source digest is not the consented source revision; re-render from the consented revision and retry".into(),
        )));
    }
    Ok(None)
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
) -> VerifiedAlphaTabPreview {
    let canonical = alpha_tab_canonical_declaration(declaration);
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
    let mut effects: Vec<String> = canonical
        .get("effects")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    needs.sort();
    effects.sort();
    VerifiedAlphaTabPreview::for_pin(
        account_id,
        package,
        version,
        digest,
        artifact_id,
        source_revision,
        alpha_tab_declaration_digest(declaration),
        needs,
        effects,
    )
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

/// Process-local preview-receipt store: `receipt_id -> (receipt, consumed)`.
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
fn preview_receipt_store() -> &'static Mutex<HashMap<String, (AlphaTabPreviewReceipt, bool)>> {
    static STORE: OnceLock<Mutex<HashMap<String, (AlphaTabPreviewReceipt, bool)>>> =
        OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Sweep expired receipts, then evict oldest-first down to the global and
/// per-account caps. Oldest is `(issued_at_secs, receipt_id)` order, so
/// eviction is deterministic under test.
fn bound_preview_receipt_store(
    store: &mut HashMap<String, (AlphaTabPreviewReceipt, bool)>,
    account_id: &str,
    now_secs: i64,
) {
    store.retain(|_, (receipt, _)| receipt.expires_at_secs > now_secs);
    while store.len() >= ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT {
        let Some(oldest) = store
            .iter()
            .min_by_key(|(id, (receipt, _))| (receipt.issued_at_secs, (*id).clone()))
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        store.remove(&oldest);
    }
    while store
        .values()
        .filter(|(receipt, _)| receipt.account_id == account_id)
        .count()
        >= ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT
    {
        let Some(oldest) = store
            .iter()
            .filter(|(_, (receipt, _))| receipt.account_id == account_id)
            .min_by_key(|(id, (receipt, _))| (receipt.issued_at_secs, (*id).clone()))
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
        issued_at_secs: now_secs,
        expires_at_secs: now_secs + ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
    };
    let mut store = preview_receipt_store()
        .lock()
        .expect("preview receipt store poisoned");
    bound_preview_receipt_store(&mut store, &receipt.account_id, now_secs);
    store.insert(receipt.receipt_id.clone(), (receipt.clone(), false));
    receipt
}

/// Look up one server-held preview receipt by id. Returns the receipt plus
/// its consumed flag; `None` is an unknown id. Read-only: consumption is
/// the adopt-confirm slice's write.
pub fn find_alpha_tab_preview_receipt(receipt_id: &str) -> Option<(AlphaTabPreviewReceipt, bool)> {
    preview_receipt_store()
        .lock()
        .expect("preview receipt store poisoned")
        .get(receipt_id)
        .cloned()
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
    Install {
        package: String,
        version: String,
        digest: String,
        artifact_id: String,
        source_revision: String,
        declaration: Value,
        reason: String,
        #[serde(default)]
        idempotency_key: Option<String>,
        #[serde(default)]
        expected_install_event_id: Option<String>,
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
fn require_package(package: &str) -> Result<()> {
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

fn require_version(version: &str) -> Result<()> {
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

/// The host-rule declaration: an object with `needs` and `effects` string
/// arrays. Deeper admission (which needs/effects exist) is a later slice;
/// here the shape is pinned so the consent digest covers declared bytes.
fn require_declaration(declaration: &Value) -> Result<(Vec<String>, Vec<String>)> {
    let object = declaration
        .as_object()
        .ok_or_else(|| Error::engine(format!("{TOOL}: declaration must be an object")))?;
    if object.len() != 2 || !object.contains_key("needs") || !object.contains_key("effects") {
        return Err(Error::engine(format!(
            "{TOOL}: declaration must hold exactly 'needs' and 'effects'"
        )));
    }
    let mut out = Vec::new();
    for key in ["needs", "effects"] {
        let entries = object[key].as_array().ok_or_else(|| {
            Error::engine(format!("{TOOL}: declaration '{key}' must be an array"))
        })?;
        if entries.len() > 64 {
            return Err(Error::engine(format!(
                "{TOOL}: declaration '{key}' holds at most 64 entries"
            )));
        }
        let mut names = Vec::new();
        for entry in entries {
            let name = entry.as_str().ok_or_else(|| {
                Error::engine(format!(
                    "{TOOL}: declaration '{key}' entries must be strings"
                ))
            })?;
            if name.trim().is_empty() || name.len() > 128 {
                return Err(Error::engine(format!(
                    "{TOOL}: declaration '{key}' entries must be 1..128 characters"
                )));
            }
            names.push(name.to_string());
        }
        out.push(names);
    }
    Ok((out.remove(0), out.remove(0)))
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
                declaration_digest,consented_declaration,adoption,status,event_id,event_seq
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
    let digest_matches = match (&runtime, &source) {
        (Some(runtime), Some(source))
            if row.declaration_digest
                == alpha_tab_declaration_digest(&row.consented_declaration) =>
        {
            alpha_tab_digest(
                &alpha_tab_bundle_digest(&source.body),
                &alpha_tab_declaration_digest(&row.consented_declaration),
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
        if row.adoption == ALPHA_TAB_ADOPTION_VERIFIED {
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
    idempotency_key: Option<String>,
    expected_install_event_id: Option<String>,
) -> Result<Value> {
    require_package(&package)?;
    require_version(&version)?;
    require_digest(&digest)?;
    require_declaration(&declaration)?;
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
    // The canonical (sorted) digest, the same one adopt, launch and live_read
    // recompute. Digesting the raw declaration made any unsorted multi-entry
    // declaration install cleanly and then fail every later pin check.
    let declaration_digest = alpha_tab_declaration_digest(&declaration);
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
        tx.commit().await?;
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
    tx.commit().await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
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
        tx.commit().await?;
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
    tx.commit().await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
        act_alloc.get(),
    )
}
async fn do_list(db: &Db, caller: &Caller) -> Result<Value> {
    let account_id = require_account(caller)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let rows: Vec<InstallRowTuple> = sqlx::query_as(
        "SELECT package,version,digest,artifact_id,consented_source_revision,
                    declaration_digest,consented_declaration,adoption,status,event_id,event_seq
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
            status,
            event_id,
            event_seq,
        };
        installs.push(entry_in(&mut tx, caller, &row).await?);
    }
    tx.rollback().await?;
    Ok(json!({"account_id": account_id, "installs": installs}))
}

async fn do_inspect(db: &Db, caller: &Caller, package: String) -> Result<Value> {
    require_package(&package)?;
    let account_id = require_account(caller)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let result = match install_row_in(&mut tx, &account_id, &package).await? {
        Some(row) => {
            let entry = entry_in(&mut tx, caller, &row).await?;
            json!({"package": package, "installed": true, "install": entry})
        }
        None => json!({"package": package, "installed": false}),
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
    let declaration_digest = alpha_tab_declaration_digest(&row.consented_declaration);
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
/// verified `shell_adopt.v1` adoption, then target liveness + viewer View) →
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
/// [`RECORDS_RESOLVE_REFERENCE_NEED`]) the same gate chain runs, then the
/// consented-need check names that need, then [`parse_declared_read`] bounds
/// the parameters (`unknown_need`, `invalid_params`). The read itself is the
/// ordinary tool handler under the viewer's `Caller`, so its results and
/// access semantics are the viewer's own by construction. On-request reads
/// carry no revision fence: they answer one request and are not a snapshot.
async fn do_live_read(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    need: Option<String>,
    params: Option<Value>,
) -> Result<Value> {
    let need = need.unwrap_or_else(|| ATTENTION_QUERY_NEED.to_string());
    if need != ATTENTION_QUERY_NEED {
        // Boxed: the declared read embeds whole tool handlers, which would
        // otherwise inflate every `manage_alpha_tabs` future on the stack.
        return Box::pin(do_declared_read(
            db,
            caller,
            package,
            expected_install_event_id,
            need,
            params,
        ))
        .await;
    }
    if params.is_some() {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [invalid_params]"
        )));
    }
    let account_id = live_read_precheck(caller, &package, &expected_install_event_id)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let LiveReadGate {
        row,
        source,
        runtime,
        bundle_sha256,
        needs,
    } = live_read_gates_in(
        &mut tx,
        caller,
        &account_id,
        &package,
        &expected_install_event_id,
    )
    .await?;
    if !needs.iter().any(|need| need == ATTENTION_QUERY_NEED) {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [undeclared_need]"
        )));
    }
    // Pinned candidate scan for `attention.query.v1` v1 semantics (see
    // `ATTENTION_QUERY_SEMANTICS`). SQL proposes attention-shaped candidates
    // newest-first; host code disposes per row via the existing
    // `can_record_in` API, keeping the first `ATTENTION_LIVE_LIMIT`
    // authorized rows out of at most `ATTENTION_CANDIDATE_SCAN_CAP`
    // candidates. A bare `LIMIT 50` before the authority check would let
    // inaccessible newer tasks starve visible older ones; the bounded scan
    // fills the page from what the viewer may actually see. A row the viewer
    // may not see never leaves this function.
    let not_hidden = crate::query::not_hidden_predicate("r");
    let candidate_sql = format!(
        "SELECT r.id, r.type, r.kind, r.name, r.lifecycle, r.last_activity_at \
           FROM records r \
          WHERE r.deleted_at IS NULL AND {not_hidden} \
            AND r.type='WorkItem' AND r.kind='task' \
            AND r.lifecycle IS NOT NULL \
            AND r.lifecycle NOT IN ('completed','closed') \
            AND NOT EXISTS (SELECT 1 FROM facet_values av \
                              WHERE av.record_id=r.id AND av.key='archived') \
          ORDER BY r.last_activity_at DESC, r.id ASC LIMIT ?"
    );
    let candidates = sqlx::query(&candidate_sql)
        .bind(ATTENTION_CANDIDATE_SCAN_CAP)
        .fetch_all(&mut *tx)
        .await?;
    let mut records = Vec::new();
    for candidate in &candidates {
        if records.len() as i64 >= ATTENTION_LIVE_LIMIT {
            break;
        }
        let id: String = candidate.try_get("id")?;
        if !super::can_record_in(&mut tx, caller, &id, Capability::View).await? {
            continue;
        }
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
    tx.rollback().await?;
    // Viewer-scoped staleness token: canonical digest over the returned
    // rows plus the install pin/generation. Derived ONLY from data this
    // viewer may see — no global content-event id/seq, no authorization
    // epoch, no scan counters. It fences the delivered display fields
    // only; revocation is enforced by re-running the gate chain per
    // request, and unrelated writes (including inaccessible-task writes)
    // deliberately leave it unchanged.
    let records_value = Value::Array(records);
    let rows_sha256 = crate::canonical_json::digest_json(&records_value);
    let revision_digest = crate::canonical_json::digest_json(&json!({
        "rows": records_value,
        "pin": pin,
    }));
    let live_input = json!({
        "version": "native.artifact-input.v1",
        "mode": "live",
        "sample_preview": false,
        "records": records_value,
        "records_sha256": rows_sha256,
        "inputs": {},
    });
    let input_digest = alpha_tab_sample_input_digest(&live_input);
    Ok(json!({
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
        "revision": {
            "revision_digest": revision_digest,
            "rows_sha256": rows_sha256,
        },
        "window": {
            "bounded_window": true,
        },
        "live_reads": true,
        "effects_wired": false,
    }))
}

/// Dispatch note: the read calls the `search` / `get_record` handlers
/// directly, with the registry's record-reference expansion run first, rather
/// than re-entering the registry. Both are core read tools on the SQLite
/// engine this tool runs on. If the registry ever adds another pre-handler
/// step for them (admission, capture), route through it here too.
///
/// One on-request declared read for an adopted tab (task `1044bb6`). Same
/// gate chain as the attention snapshot; then the need must be in the
/// consented declaration (`undeclared_need`) and its parameters in bounds
/// (`unknown_need`, `invalid_params`). The gate transaction ends before the
/// read runs, because the read is an ordinary tool handler that opens its
/// own and enforces the viewer's authority itself.
async fn do_declared_read(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    need: String,
    params: Option<Value>,
) -> Result<Value> {
    let account_id = live_read_precheck(caller, &package, &expected_install_event_id)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let LiveReadGate {
        row,
        source,
        runtime,
        bundle_sha256,
        needs,
    } = live_read_gates_in(
        &mut tx,
        caller,
        &account_id,
        &package,
        &expected_install_event_id,
    )
    .await?;
    tx.rollback().await?;
    if !needs.iter().any(|declared| declared == &need) {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused [undeclared_need]"
        )));
    }
    let read = parse_declared_read(&need, params.as_ref())
        .map_err(|code| Error::engine(format!("{TOOL}: live read refused [{code}]")))?;
    let (echo, result) = match read {
        DeclaredRead::Search { query, limit } => {
            let echo = json!({"query": query, "limit": limit});
            let result = super::querying::search(db.clone(), caller.clone(), echo.clone()).await?;
            (echo, result)
        }
        DeclaredRead::ResolveReference { reference } => {
            let echo = json!({"reference": reference});
            let result = resolve_reference_display(db, caller, &reference).await?;
            (echo, result)
        }
    };
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
            "runtime": runtime,
        },
        "need": need,
        "params": echo,
        "result": result,
        "live_reads": true,
        "effects_wired": false,
    }))
}

/// `records.resolve_reference.v1`: resolve through the ordinary `get_record`
/// handler and return display fields only. Mirrors alpha's shell search: a
/// found record, the candidates of an ambiguous short reference, or nothing.
async fn resolve_reference_display(db: &Db, caller: &Caller, reference: &str) -> Result<Value> {
    // The registry expands short references before any handler runs; this
    // calls the handler directly, so it runs the same expansion first. An
    // ambiguous prefix is refused there, over View-visible candidates only.
    let arguments = crate::mcp::record_ref::resolve_record_ids(
        &super::super::registry::EngineHandle::Sqlite(db.clone()),
        caller,
        "get_record",
        json!({"ids": [reference], "children_limit": 0, "links_limit": 0}),
    )
    .await;
    let resolved = match arguments {
        Ok(arguments) => super::lifecycle::get_record(db.clone(), caller.clone(), arguments).await,
        Err(error) => Err(error),
    };
    Ok(match resolved {
        Ok(value) => match value.get("records").and_then(|records| records.get(0)) {
            Some(record) if record.get("status").and_then(Value::as_str) == Some("found") => {
                json!({
                    "status": "found",
                    "record": {
                        "id": record.get("id"),
                        "type": record.get("type"),
                        "kind": record.get("kind"),
                        "name": record.get("name"),
                    },
                })
            }
            _ => json!({"status": "not_found"}),
        },
        Err(error) => {
            let message = error.to_string();
            let candidates = ambiguous_reference_candidates(&message);
            if message.contains("ambiguous") && candidates.len() > 1 {
                json!({"status": "ambiguous", "candidates": candidates})
            } else {
                // A failed read is not an absent record: let the host
                // answer `unavailable` rather than claim there is none.
                return Err(error);
            }
        }
    })
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
    source: AlphaTabSource,
    runtime: Option<String>,
    bundle_sha256: String,
    needs: Vec<String>,
}

/// The `live_read` gate chain shared by every need: CAS on the install
/// event, install gates, source/digest gates and declaration digest. First
/// refusal wins; nothing is read for the frame until all pass.
async fn live_read_gates_in(
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
    let source =
        resolve_alpha_tab_source_in(tx, &row.artifact_id, &row.consented_source_revision).await?;
    let declaration_digest = alpha_tab_declaration_digest(&row.consented_declaration);
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
    let needs: Vec<String> = row
        .consented_declaration
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
    Ok(LiveReadGate {
        row,
        source,
        runtime,
        bundle_sha256,
        needs,
    })
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
    let (needs, effects) = require_declaration(&declaration).map(|(needs, effects)| {
        let mut needs = needs;
        let mut effects = effects;
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
    let declaration_digest = alpha_tab_declaration_digest(&declaration);
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
    // caller-asserted digest on trust).
    let recomputed = alpha_tab_digest(
        &alpha_tab_bundle_digest(&source.body),
        &alpha_tab_declaration_digest(&declaration),
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
    let (needs, effects) = require_declaration(&declaration).map(|(needs, effects)| {
        let mut needs = needs;
        let mut effects = effects;
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
    let declaration_digest = alpha_tab_declaration_digest(&declaration);
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
        receipt_id: receipt_id.clone(),
        preview_session: preview_session.clone(),
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
        tx.commit().await?;
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
        let (stored, consumed) = match &owned {
            Some((receipt, consumed)) => (Some(receipt), *consumed),
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
        if let Some((_, consumed)) = store.get_mut(&receipt_id) {
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
    tx.commit().await?;
    echo_act(
        json!({"package": package, "changed": true, "install": entry}),
        act_alloc.get(),
    )
}

async fn manage_alpha_tabs(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ManageAlphaTabsArgs = parse_args(TOOL, arguments)?;
    match args {
        ManageAlphaTabsArgs::Inspect { package } => do_inspect(&db, &caller, package).await,
        ManageAlphaTabsArgs::List {} => do_list(&db, &caller).await,
        ManageAlphaTabsArgs::Launch {
            package,
            expected_install_event_id,
        } => do_launch(&db, &caller, package, expected_install_event_id).await,
        ManageAlphaTabsArgs::LiveRead {
            package,
            expected_install_event_id,
            need,
            params,
        } => {
            do_live_read(
                &db,
                &caller,
                package,
                expected_install_event_id,
                need,
                params,
            )
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
            idempotency_key,
            expected_install_event_id,
        } => {
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
                idempotency_key,
                expected_install_event_id,
            )
            .await
        }
        ManageAlphaTabsArgs::Disable {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            do_transition(
                &db,
                &caller,
                "alpha_tab.disabled",
                package,
                expected_install_event_id,
                reason,
                idempotency_key,
            )
            .await
        }
        ManageAlphaTabsArgs::Restore {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            do_transition(
                &db,
                &caller,
                "alpha_tab.restored",
                package,
                expected_install_event_id,
                reason,
                idempotency_key,
            )
            .await
        }
        ManageAlphaTabsArgs::Remove {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            do_transition(
                &db,
                &caller,
                "alpha_tab.removed",
                package,
                expected_install_event_id,
                reason,
                idempotency_key,
            )
            .await
        }
    }
}

/// Register `manage_alpha_tabs`.
pub fn register_alpha_tab_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageAlphaTabs,
        "Inspect, list, launch, live_read, install, disable, restore, or remove a personal alpha tab install, \
         or preview one exact artifact/package pin against host-owned sample input only. \
         An install pins (package, version, digest) plus the artifact record, its source \
         revision, and the consented needs/effects declaration; the target must be a live \
         Document kind:artifact the caller may view. disable/restore/remove compare-and-set \
         on expected_install_event_id (the install's current event token). Disabled and \
         removed tabs stop reads and actions; the host renders fallback with the named \
         skip_reason. `resolves` is fail-closed in this slice: even a healthy install \
         reports `resolves: false` with a named skip reason (see \
         `target_resolves` for install-state plus authority readiness) \
         — use the explicit launch action to obtain a one-use sample-only URL. \
         Preview verifies the exact source revision and canonical alpha-tab-digest.v1, \
         renders the pinned HTML bytes in the opaque sandbox against host-owned sample \
         input only (no governed named-input reads, no effect path), and mints a \
         short-lived server-held preview receipt bound to account plus full pin plus \
         sample-preview session. Preview changes no install state and grants no \
         adoption. Adoption boundary: a direct install records caller-asserted adoption only \
         (\"adoption\": \"caller_asserted\"); preview receipts are cookie+trusted-Origin \
          only at the hosted boundary (Bearer is refused there), so agents never receive one. \
          Adopt confirms a previewed install against its live server-held receipt plus the exact pin \
          and the install's current event token, flipping adoption to the verified value; adopt is \
          likewise cookie+trusted-Origin only at the hosted boundary with a per-action attestation. \
           Launch checks the stored pin, verified adoption, current event token, live View and exact \
           content-event bytes, then returns one-use sandbox URL plus host-owned sample input only; \
           launch and preview never return live rows. Live_read executes the single consented \
           attention.query.v1 host read under viewer authority for an adopted tab and returns \
           live rows at top-level input.records (shim delivery; inputs.items stays empty) with \
           a staleness fence plus pin provenance to the tool caller only (never to the frame); \
           effects remain unwired. With need records.search.v1 or records.resolve_reference.v1 \
           it runs that consented on-request read through the ordinary search/get_record \
           handler under viewer authority, with bounded params, and returns the result.",
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
                            "description": "Consented need to execute. Omitted: attention.query.v1 (snapshot rows). On request: records.search.v1 (params {query, limit<=30}) or records.resolve_reference.v1 (params {reference})."
                        },
                        "params": { "type": "object" }
                    },
                    "required": ["action", "package", "expected_install_event_id"],
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
                        "action": { "const": "install" },
                        "package": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "declaration": { "type": "object" },
                        "reason": { "type": "string" },
                        "idempotency_key": { "type": ["string", "null"] },
                        "expected_install_event_id": { "type": ["string", "null"] }
                    },
                    "required": ["action", "package", "version", "digest", "artifact_id", "source_revision", "declaration", "reason"],
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
                }
            ]
        }),
        manage_alpha_tabs,
    )?;
    Ok(())
}

#[cfg(test)]
mod launch_tests {
    //! Slice-2 launch binding: canonical digest vectors, gate precedence,
    //! and the portable source-revision SQL
    //! (`docs/alpha-tab-install-slice2.md`).

    use super::{
        alpha_tab_bundle_digest, alpha_tab_canonical_declaration, alpha_tab_declaration_digest,
        alpha_tab_digest, evaluate_alpha_tab_install_gates, evaluate_alpha_tab_source_gates,
        resolve_alpha_tab_source_in, TargetState, ALPHA_TAB_DIGEST_VERSION,
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
            alpha_tab_declaration_digest(&declaration),
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
            alpha_tab_canonical_declaration(&ordered),
            alpha_tab_canonical_declaration(&shuffled)
        );
        let multi_a = json!({"needs": ["b.read", "a.read"], "effects": ["x.act", "a.act"]});
        let multi_b = json!({"needs": ["a.read", "b.read"], "effects": ["a.act", "x.act"]});
        assert_eq!(
            alpha_tab_declaration_digest(&multi_a),
            alpha_tab_declaration_digest(&multi_b)
        );
        assert_eq!(
            alpha_tab_canonical_declaration(&multi_a),
            json!({"needs": ["a.read", "b.read"], "effects": ["a.act", "x.act"]})
        );
        // A narrower declaration is a different digest, never a silent
        // subset: widening/narrowing inside a pinned version is decided by
        // the K1 rule, not by hash collision.
        let narrowed = json!({"needs": ["attention.query.v1"], "effects": []});
        assert_ne!(
            alpha_tab_declaration_digest(&ordered),
            alpha_tab_declaration_digest(&narrowed)
        );
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
        AlphaTabPreviewReceipt, ALPHA_TAB_ADOPTION_VERIFIED, ALPHA_TAB_LAUNCH_REQUEST_REQUIRED,
        ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS, VERIFIED_ALPHA_TAB_ADOPTIONS,
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
        // The closed vocabulary names exactly one verified value, and the
        // adopt-confirm slice admits it: a verified install passes the
        // adoption gate, while every other adoption — including forged
        // stronger-looking strings — still refuses `adoption_unverified`.
        // Admission does not make anything executable: the terminal ticket
        // gate still refuses every verified install below.
        assert_eq!(ALPHA_TAB_ADOPTION_VERIFIED, "shell_adopt.v1");
        assert_eq!(VERIFIED_ALPHA_TAB_ADOPTIONS, &["shell_adopt.v1"]);
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
        ambiguous_reference_candidates, parse_declared_read, DeclaredRead,
        RECORDS_RESOLVE_REFERENCE_NEED, RECORDS_SEARCH_NEED,
    };
    use serde_json::json;

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
