//! S3a durable saver state: checkpoint, spool, chain ids and pure outcomes.
//!
//! Bounded S3a slice of design `f38936b` §§6.1–6.4 (plus §5.4 identities).
//! This module owns **local durability only** and performs no hosted writes,
//! no daemon I/O and no runtime saving enablement. S3b wires the hosted gate
//! (`no_hold`, binding/lease/adoption/alignment); S3c owns provider goldens.
//!
//! ## Layout (`<socket_directory>/sessions/`, dir 0700, files 0600)
//!
//! - `binding.json`: versioned `{server_id, account_id, db_id,
//!   saved_sessions_folder_id?}`. Design §6.2 names only `server_id` plus the
//!   folder; the full triple is stored because S1 F4 (carried into the S3 task
//!   anchor) requires account/db/server binding before any canonical session
//!   write, with server-id fencing. **Recorded gap:** design §6.2
//!   under-specifies the binding; this module enforces the triple and rejects
//!   any mismatch rather than treating server alone as sufficient.
//! - `<agent>.json`: atomic checkpoint carrying `head {pos, cid}`, the
//!   source-equivalent `E` (as fingerprint hex list), the daemon source cursor
//!   `{epoch, seq_end}`, `alignment_gen` and `needs_realign` **in one
//!   fsync'd file replace**. Identity fields (`label_value`, `folder_id`,
//!   `session_record_id`, `writer_generation`, `state_seq`) ride along so a
//!   restart never applies a head under a different binding.
//! - `<agent>.spool/p<pos>.json`: the single frozen step request for the next
//!   position. The file stores the **envelope** (local validation metadata:
//!   version, position, key, type/kind plus the frozen arguments). The actual
//!   hosted `create_record` arguments are derived deterministically via
//!   [`FrozenStepRequest::wire_request`]; [`FrozenStepRequest::wire_bytes`]
//!   is what S3b sends verbatim on every attempt, and retries resend those
//!   identical wire bytes under the identical position key.
//!
//! ## Chain ids (§5.4) — exact byte encoding (defined here)
//!
//! Design states `cid_n = sha256(cid_{n-1} ‖ fp_n)` and
//! `cid_0 = sha256("nss3" ‖ server_id ‖ agent_id)` without fixing the byte
//! encoding of `‖`. The encoding below is normative for this implementation
//! and is covered by byte-stability tests:
//!
//! ```text
//! field(x)  = BE64(len(x)) || x
//! cid_0     = hex(sha256(field("nss3") || field(server_id) || field(agent_id)))
//! cid_n     = hex(sha256(field(parent_raw) || field(fp_raw)))   for n >= 1
//! ```
//!
//! where `server_id`/`agent_id` are UTF-8, and `parent_raw`/`fp_raw` are the
//! 32 raw bytes hex-decoded from the parent `cid` / step `fp`. Length
//! prefixes make `"ab"+"c"` and `"a"+"bc"` hash differently; without them the
//! design formula is ambiguous. Content fingerprints themselves reuse the
//! merged S2 implementation
//! ([`crate::node::session_projection::fingerprint_step`]); this module never
//! re-derives that encoding.
//!
//! ## Exactly-once scope (honest)
//!
//! Local state alone provides **at-most-one in-flight spool per agent plus
//! idempotent retry under a stable position key**. End-to-end exactly-once
//! across writers still needs hosted admission (position-key uniqueness,
//! conflict validation, §6.3/§6.5), which is S3b. Nothing here claims that a
//! durable spool by itself prevents a foreign writer from admitting the same
//! position first.
//!
//! ## Pre-S3 hosted-write obligations (tracked, not implemented here)
//!
//! Snapshot/live projection adapter contract (wakeup-only stream, fetch
//! projected pages, drain-before-epoch-switch), account/db/host label
//! filtering and server-id fencing are required before any canonical write.
//! They are **not** satisfied by this module; S3b must enforce them at the
//! hosted gate. This module only guarantees that local state *records* the
//! binding it was built under so S3b can compare it.
//!
//! ## Crash ordering
//!
//! `needs_realign` is set durably **before** a foreign head is adopted or a
//! stale spool is quarantined. While the flag is set, any surviving rejected
//! spool entry is ignored (deleting it is not a precondition for recovery).
//! A restart with the flag set, or with an unverified head, must run full
//! alignment first and must never replay the stale mapping. The API enforces
//! this: [`SessionStore::adopt_foreign_head`] and
//! [`SessionStore::quarantine_spool`] refuse unless the on-disk checkpoint
//! already carries `needs_realign = true`.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Versioned envelope versions. Bump only for a change an older reader could
/// misread; new optional fields stay defaulted at version 1.
pub const BINDING_VERSION: u32 = 1;
/// Checkpoint envelope version.
pub const CHECKPOINT_VERSION: u32 = 1;
/// Spool envelope version.
pub const SPOOL_VERSION: u32 = 1;
/// Frozen reason byte, stable across restarts and re-enrolment (§6.1).
pub const REASON_STEP: &str = "Saved agent session step";
/// Proposed `Document` type/kind for step creates (names only; S3a performs
/// no vocabulary write and no hosted call).
pub const STEP_TYPE: &str = "Document";
/// Proposed step kind (design §5.2).
pub const STEP_KIND: &str = "agent-session-step";
/// Default pending bound (§6.2): 64 MiB pauses curation, drops nothing.
pub const DEFAULT_PENDING_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// Spool positions are `u64`; file names are `p<pos>.json`.
pub const MAX_SPOOL_BYTES: u64 = 4 * 1024 * 1024;
/// Checkpoint size bound (heavy session E ≤ ~1,000 fps plus cursors).
pub const MAX_CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024;
/// One pending lease or state mutation, including its exact keyed arguments.
pub const MAX_PROPOSAL_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    Lease,
    State,
    Retire,
    Transition,
}

/// A single unresolved mutation. A new proposal cannot replace an uncertain
/// one. The writer rechecks the hosted lease before settling a replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenStateProposal {
    pub version: u32,
    pub binding: Binding,
    pub agent_id: String,
    pub record_id: String,
    pub kind: ProposalKind,
    pub generation: u64,
    pub writer: String,
    pub key: String,
    pub arguments: serde_json::Value,
}

impl FrozenStateProposal {
    fn validate(&self, binding: &Binding, agent_id: &str) -> Result<()> {
        use serde_json::json;
        if self.version != 1 || !self.binding.matches(binding) || self.agent_id != agent_id {
            return Err(Error::engine("frozen state proposal identity mismatch"));
        }
        self.binding.validate()?;
        let args = &self.arguments;
        if self.record_id.is_empty()
            || self.writer.is_empty()
            || args.get("ids") != Some(&json!([self.record_id]))
            || args.get("idempotency_key").and_then(|v| v.as_str()) != Some(&self.key)
            || args
                .get("reason")
                .and_then(|v| v.as_str())
                .is_none_or(|s| s.trim().is_empty())
            || !args
                .get("facets")
                .is_some_and(|v| v.as_object().is_some_and(|m| !m.is_empty()))
        {
            return Err(Error::engine("invalid frozen state proposal arguments"));
        }
        let guard = args
            .get("if_facets")
            .ok_or_else(|| Error::engine("proposal lacks guard"))?;
        let valid = match self.kind {
            ProposalKind::Lease => {
                let prior = guard
                    .get("native.session.writer_generation")
                    .and_then(|v| v.as_u64());
                prior.and_then(|g| g.checked_add(1)) == Some(self.generation)
                    && guard
                        .get("native.session.writer")
                        .is_some_and(|v| v.is_string())
                    && guard
                        .get("native.session.last_seen_at")
                        .is_some_and(|v| v.is_string())
                    && args["facets"]["native.session.writer_generation"] == json!(self.generation)
                    && args["facets"]["native.session.writer"] == json!(self.writer)
                    && self.key == format!("nss3:lease:{}:g{}", self.record_id, self.generation)
            }
            ProposalKind::Retire => {
                let prior = guard
                    .get("native.session.writer_generation")
                    .and_then(|v| v.as_u64());
                prior.and_then(|g| g.checked_add(1)) == Some(self.generation)
                    && guard
                        .get("native.session.writer")
                        .is_some_and(|v| v.is_string())
                    && guard
                        .get("native.session.last_seen_at")
                        .is_some_and(|v| v.is_string())
                    && args["facets"]["native.session.writer_generation"] == json!(self.generation)
                    && args["facets"]["native.session.writer"] == json!(self.writer)
                    && args["facets"]["native.session.state"] == json!("ended")
                    && args["lifecycle"] == json!("closed")
                    && args["facets"].as_object().is_some_and(|f| {
                        f.len() == 4 && f.contains_key("native.session.last_seen_at")
                    })
                    && args.as_object().is_some_and(|a| {
                        a.keys().all(|k| {
                            matches!(
                                k.as_str(),
                                "ids"
                                    | "reason"
                                    | "facets"
                                    | "if_facets"
                                    | "idempotency_key"
                                    | "lifecycle"
                            )
                        })
                    })
                    && self.key == format!("nss3:retire:{}:g{}", self.record_id, self.generation)
            }
            ProposalKind::Transition => {
                let prior = guard
                    .get("native.session.writer_generation")
                    .and_then(|v| v.as_u64());
                let state = args["facets"]["native.session.state"].as_str();
                prior.and_then(|g| g.checked_add(1)) == Some(self.generation)
                    && guard
                        .get("native.session.writer")
                        .is_some_and(|v| v.is_string())
                    && guard
                        .get("native.session.last_seen_at")
                        .is_some_and(|v| v.is_string())
                    && args["facets"]["native.session.writer_generation"] == json!(self.generation)
                    && args["facets"]["native.session.writer"] == json!(self.writer)
                    && matches!(state, Some("paused" | "stopped" | "ended" | "error"))
                    && if state == Some("ended") {
                        args["lifecycle"] == json!("closed")
                    } else {
                        args.get("lifecycle").is_none()
                    }
                    && args["facets"].as_object().is_some_and(|f| {
                        f.keys().all(|k| {
                            matches!(
                                k.as_str(),
                                "native.session.writer_generation"
                                    | "native.session.writer"
                                    | "native.session.last_seen_at"
                                    | "native.session.state"
                                    | "native.session.paused_reason"
                            )
                        })
                    })
                    && args.as_object().is_some_and(|a| {
                        a.keys().all(|k| {
                            matches!(
                                k.as_str(),
                                "ids"
                                    | "reason"
                                    | "facets"
                                    | "if_facets"
                                    | "idempotency_key"
                                    | "lifecycle"
                            )
                        })
                    })
                    && self.key
                        == format!("nss3:transition:{}:g{}", self.record_id, self.generation)
            }
            ProposalKind::State => {
                guard.get("native.session.writer_generation") == Some(&json!(self.generation))
                    && guard.get("native.session.writer") == Some(&json!(self.writer))
                    && self
                        .key
                        .strip_prefix(&format!(
                            "nss3:state:{}:g{}:s",
                            self.record_id, self.generation
                        ))
                        .is_some_and(|s| s.parse::<u64>().is_ok())
                    && args["facets"]
                        .get("native.session.writer_generation")
                        .is_none()
                    && args["facets"].get("native.session.writer").is_none()
            }
        };
        if !valid {
            return Err(Error::engine(
                "frozen state proposal key or lease guard mismatch",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// Which hosted database (and folder) this local state may be used with.
///
/// Stored at `<state_dir>/binding.json`. The triple is the S1 F4 obligation;
/// design §6.2's two-field sketch is insufficient on its own (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Envelope version; must equal [`BINDING_VERSION`].
    pub version: u32,
    /// Execution-host identity scoping the position keys.
    pub server_id: String,
    /// Hosting account the saver credential belongs to.
    pub account_id: String,
    /// Hosting database the saver writes to.
    pub db_id: String,
    /// Hosted Saved-sessions folder id once created; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_sessions_folder_id: Option<String>,
}

impl Binding {
    /// New binding; rejects empty ids (an empty id would silently widen the
    /// scope the keys are supposed to fence).
    pub fn new(
        server_id: &str,
        account_id: &str,
        db_id: &str,
        saved_sessions_folder_id: Option<&str>,
    ) -> Result<Self> {
        for (name, value) in [
            ("server_id", server_id),
            ("account_id", account_id),
            ("db_id", db_id),
        ] {
            if value.trim().is_empty() {
                return Err(Error::engine(format!("saver binding {name} is empty")));
            }
            // Only server_id enters a delimited position key. Account and
            // database are separate binding fields and Desktop explicitly
            // permits ':' in their tokens.
            if name == "server_id" && value.contains([':', '/', '\\']) {
                return Err(Error::engine(format!(
                    "saver binding {name} must not contain key or path separators"
                )));
            }
        }
        Ok(Self {
            version: BINDING_VERSION,
            server_id: server_id.to_owned(),
            account_id: account_id.to_owned(),
            db_id: db_id.to_owned(),
            saved_sessions_folder_id: saved_sessions_folder_id.map(str::to_owned),
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.version != BINDING_VERSION {
            return Err(Error::engine(format!(
                "unsupported saver binding version {}",
                self.version
            )));
        }
        // Reuse the constructor's shape checks (empty/`:`) on load so a
        // hand-edited file cannot widen scope.
        Self::new(
            &self.server_id,
            &self.account_id,
            &self.db_id,
            self.saved_sessions_folder_id.as_deref(),
        )?;
        Ok(())
    }

    /// Full-triple match. Any field mismatch refuses: local state built under
    /// one (server, account, db) must never be replayed under another.
    pub fn matches(&self, other: &Binding) -> bool {
        self.server_id == other.server_id
            && self.account_id == other.account_id
            && self.db_id == other.db_id
    }
}

// ---------------------------------------------------------------------------
// Chain ids and position keys (§5.4)
// ---------------------------------------------------------------------------

fn field(bytes: &[u8], hasher: &mut Sha256) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn decode_32(hex_str: &str, what: &str) -> Result<[u8; 32]> {
    let raw =
        hex::decode(hex_str).map_err(|_| Error::engine(format!("saver {what} is not hex")))?;
    if raw.len() != 32 {
        return Err(Error::engine(format!("saver {what} is not 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// `cid_0` for a (server, agent) pair. See module docs for the exact encoding.
pub fn chain_root(server_id: &str, agent_id: &str) -> Result<String> {
    if server_id.is_empty() || agent_id.is_empty() {
        return Err(Error::engine("saver chain root needs nonempty ids"));
    }
    let mut hasher = Sha256::new();
    field(b"nss3", &mut hasher);
    field(server_id.as_bytes(), &mut hasher);
    field(agent_id.as_bytes(), &mut hasher);
    Ok(hex::encode(hasher.finalize()))
}

/// `cid_n` from the parent cid hex and the step fingerprint hex.
pub fn chain_next(parent_cid_hex: &str, fp_hex: &str) -> Result<String> {
    let parent = decode_32(parent_cid_hex, "parent cid")?;
    let fp = decode_32(fp_hex, "fingerprint")?;
    let mut hasher = Sha256::new();
    field(&parent, &mut hasher);
    field(&fp, &mut hasher);
    Ok(hex::encode(hasher.finalize()))
}

/// Admission identity for a step position (§5.4): `nss3:<server>:<agent>:p<pos>`.
pub fn position_key(server_id: &str, agent_id: &str, pos: u64) -> Result<String> {
    if server_id.is_empty() || agent_id.is_empty() {
        return Err(Error::engine("saver position key needs nonempty ids"));
    }
    for (name, value) in [("server_id", server_id), ("agent_id", agent_id)] {
        if value.contains(':') || value.contains('/') || value.contains('\\') {
            return Err(Error::engine(format!(
                "saver {name} must not contain ':' or path separators"
            )));
        }
    }
    Ok(format!("nss3:{server_id}:{agent_id}:p{pos}"))
}

// ---------------------------------------------------------------------------
// Frozen step request (§6.1)
// ---------------------------------------------------------------------------

/// Facets frozen into the step create. `BTreeMap` keeps retry serialization
/// byte-stable under a fixed serializer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepFacets {
    /// Position, mirrored in the key.
    pub pos: u64,
    /// Chain id of this step.
    pub cid: String,
    /// Parent chain id (the head this step extends).
    pub parent_cid: String,
    /// Content fingerprint (S2 encoding).
    pub fp: String,
    /// Curated step kind string (`user`/`agent`/`tools`/`error`/`compacted`).
    pub step_kind: String,
    /// Split part index (0-based).
    pub part_index: u32,
    /// Marker base length; present on `rewound`/`resync` markers only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_len: Option<u64>,
    /// Durable rewind identity, on markers from branch-aware hosts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_no: Option<u64>,
    /// Frozen at freeze time; preserved verbatim on retry.
    pub occurred_at: String,
}

/// The full frozen create: local envelope plus frozen arguments. No run key,
/// no intent. [`FrozenStepRequest::retry_bytes`] serializes this envelope
/// (what the spool file holds); [`FrozenStepRequest::wire_bytes`] derives the
/// deterministic hosted `create_record` arguments S3b sends verbatim (§6.1).
/// The ingress must not inject a run or intent into either.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenStepRequest {
    /// Envelope version; must equal [`SPOOL_VERSION`].
    pub version: u32,
    /// Position this request creates.
    pub pos: u64,
    /// Idempotency key (`nss3:<server>:<agent>:p<pos>`).
    pub key: String,
    /// Record type (`Document`).
    pub rtype: String,
    /// Record kind (`agent-session-step`).
    pub kind: String,
    /// Session folder id (home).
    pub home_id: String,
    /// Step title (derived deterministically at freeze time).
    pub name: String,
    /// Curated step body.
    pub body: String,
    /// Step facets.
    pub facets: StepFacets,
    /// Constant [`REASON_STEP`].
    pub reason: String,
}

impl FrozenStepRequest {
    /// Freeze one step create. `occurred_at` is caller-supplied (RFC3339) so
    /// tests can fix it; production passes "now". Byte-stability across retry
    /// comes from freezing here, once, and never recomputing.
    #[allow(clippy::too_many_arguments)]
    pub fn freeze(
        binding: &Binding,
        agent_id: &str,
        home_id: &str,
        name: &str,
        body: &str,
        step_kind: &str,
        part_index: u32,
        base_len: Option<u64>,
        parent_cid_hex: &str,
        fp_hex: &str,
        pos: u64,
        occurred_at: &str,
    ) -> Result<Self> {
        if home_id.trim().is_empty() {
            return Err(Error::engine("saver frozen request needs a home_id"));
        }
        if step_kind.trim().is_empty() {
            return Err(Error::engine("saver frozen request needs a step_kind"));
        }
        if occurred_at.trim().is_empty() {
            return Err(Error::engine("saver frozen request needs occurred_at"));
        }
        // Fingerprint/chain inputs must be well-formed now, not at send time.
        decode_32(fp_hex, "fingerprint")?;
        let cid = chain_next(parent_cid_hex, fp_hex)?;
        let key = position_key(&binding.server_id, agent_id, pos)?;
        let request = Self {
            version: SPOOL_VERSION,
            pos,
            key,
            rtype: STEP_TYPE.to_owned(),
            kind: STEP_KIND.to_owned(),
            home_id: home_id.to_owned(),
            name: name.to_owned(),
            body: body.to_owned(),
            facets: StepFacets {
                pos,
                cid,
                parent_cid: parent_cid_hex.to_owned(),
                fp: fp_hex.to_owned(),
                step_kind: step_kind.to_owned(),
                part_index,
                base_len,
                branch_no: None,
                occurred_at: occurred_at.to_owned(),
            },
            reason: REASON_STEP.to_owned(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validate the frozen content before persistence and before any retry.
    /// Parsing JSON alone cannot detect a changed body or inconsistent facets.
    fn validate(&self) -> Result<()> {
        use crate::node::session_projection::{fingerprint_step, StepKind};
        let kind = match self.facets.step_kind.as_str() {
            "user" => StepKind::User,
            "agent" => StepKind::Agent,
            "tools" => StepKind::Tools,
            "error" => StepKind::Error,
            "compacted" => StepKind::Compacted,
            "rewound" => StepKind::Rewound,
            "resync" => StepKind::Resync,
            _ => return Err(Error::engine("unknown saver step kind")),
        };
        let marker = matches!(kind, StepKind::Rewound | StepKind::Resync);
        if self.version != SPOOL_VERSION
            || self.rtype != STEP_TYPE
            || self.kind != STEP_KIND
            || self.reason != REASON_STEP
            || self.pos == 0
            || self.pos != self.facets.pos
            || self.home_id.trim().is_empty()
            || self.body.len() > 64 * 1024
            || self.facets.base_len.is_some() != marker
            || (!marker && self.facets.branch_no.is_some())
            || chrono::DateTime::parse_from_rfc3339(&self.facets.occurred_at).is_err()
        {
            return Err(Error::engine("invalid saver frozen request shape"));
        }
        let fp = fingerprint_step(kind, self.facets.part_index, &self.body);
        if self.facets.fp != fp || self.facets.cid != chain_next(&self.facets.parent_cid, &fp)? {
            return Err(Error::engine("saver frozen content checksum mismatch"));
        }
        Ok(())
    }

    /// Envelope bytes as stored in the spool file: deterministic for a fixed
    /// value (`serde_json::to_vec` over field-ordered structs). These are
    /// the local record of *what* to send; [`FrozenStepRequest::wire_bytes`]
    /// is the derived hosted request S3b actually sends.
    pub fn retry_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| Error::engine(format!("saver frozen request encode: {e}")))
    }

    /// Attach a branch before freezing the spool, never while retrying an
    /// already-frozen request. Older marker envelopes remain readable.
    pub fn with_marker_branch(mut self, branch: Option<u64>) -> Result<Self> {
        self.facets.branch_no = branch;
        self.validate()?;
        Ok(self)
    }

    /// Deterministic hosted `create_record` arguments for S3b: exactly
    /// `type`, `kind`, `home_id`, `name`, `body`, namespaced `facets`, the
    /// frozen `reason` and the position `idempotency_key` — and nothing else.
    /// In particular there is no run key and no intent surface here (§6.1).
    /// Facet keys use the `native.session.*` namespace the hosted readers
    /// query by (§5.4 facets `native.session.cid`/`parent_cid`, §5.5
    /// `facet_order native.session.pos`); design §6.1's short facet names are
    /// the same fields unqualified. `BTreeMap` ordering keeps the derived
    /// bytes byte-stable for a fixed request.
    pub fn wire_request(&self) -> serde_json::Value {
        let mut facets = BTreeMap::new();
        if let Some(branch) = self.facets.branch_no {
            facets.insert(
                "native.session.branch_no".to_owned(),
                serde_json::Value::from(branch),
            );
        }
        // `base_len` rides only on markers (§6.1); a marker without one is
        // malformed, so the key is omitted rather than serialized as null —
        // S3b alignment always sets it, and the hosted validator refuses an
        // unbased marker if one is ever constructed outside `freeze`.
        if let Some(base_len) = self.facets.base_len {
            facets.insert(
                "native.session.base_len".to_owned(),
                serde_json::Value::from(base_len),
            );
        }
        facets.insert(
            "native.session.cid".to_owned(),
            serde_json::Value::String(self.facets.cid.clone()),
        );
        facets.insert(
            "native.session.fp".to_owned(),
            serde_json::Value::String(self.facets.fp.clone()),
        );
        facets.insert(
            "native.session.occurred_at".to_owned(),
            serde_json::Value::String(self.facets.occurred_at.clone()),
        );
        facets.insert(
            "native.session.parent_cid".to_owned(),
            serde_json::Value::String(self.facets.parent_cid.clone()),
        );
        facets.insert(
            "native.session.part_index".to_owned(),
            serde_json::Value::from(self.facets.part_index),
        );
        facets.insert(
            "native.session.pos".to_owned(),
            serde_json::Value::from(self.facets.pos),
        );
        facets.insert(
            "native.session.step_kind".to_owned(),
            serde_json::Value::String(self.facets.step_kind.clone()),
        );
        serde_json::json!({
            "type": self.rtype,
            "kind": self.kind,
            "home_id": self.home_id,
            "name": self.name,
            "body": self.body,
            "facets": facets,
            "reason": self.reason,
            "idempotency_key": self.key,
        })
    }

    /// Deterministic bytes of [`FrozenStepRequest::wire_request`]: the exact
    /// bytes S3b sends on the first attempt and resends on every retry.
    pub fn wire_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.wire_request())
            .map_err(|e| Error::engine(format!("saver wire request encode: {e}")))
    }
}

// ---------------------------------------------------------------------------
// Checkpoint (§6.2)
// ---------------------------------------------------------------------------

/// Atomic per-agent checkpoint. `head`, `E`, the source cursor,
/// `alignment_gen` and `needs_realign` are always persisted together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Envelope version; must equal [`CHECKPOINT_VERSION`].
    pub version: u32,
    /// Agent this file belongs to (must match the file name).
    pub agent_id: String,
    /// Binding this checkpoint was built under (full triple).
    pub binding: Binding,
    /// Current daemon label value (for ack correlation; never a write key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_value: Option<String>,
    /// Local terminal request fence. It is not a claim about hosted state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_save_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_save_code: Option<String>,
    /// Prefix fully processed for quote side effects. Validated against the
    /// immutable hosted chain before recovery trusts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_scan: Option<(u64, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) quote_pending: Option<super::session_quotes::PendingQuotes>,
    /// Session folder id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    /// Session record id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_record_id: Option<String>,
    /// Writer generation (lease scope, S3b).
    #[serde(default)]
    pub writer_generation: u64,
    /// Session-record state sequence (restarts at 0 under a new generation).
    #[serde(default)]
    pub state_seq: u64,
    /// Admitted head position.
    pub head_pos: Option<u64>,
    /// Admitted head chain id.
    pub head_cid: Option<String>,
    /// Fingerprint of the admitted head, including markers excluded from E.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_fp: Option<String>,
    /// Source-equivalent sequence `E`, as fingerprint hex (markers excluded).
    #[serde(default)]
    pub source_fps: Vec<String>,
    /// Daemon cursor: epoch of the source entry behind the head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_epoch: Option<String>,
    /// Daemon cursor: `seqEnd` of the source entry behind the head.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_seq_end: Option<u64>,
    /// Alignment generation (bumped by every alignment run).
    #[serde(default)]
    pub alignment_gen: u64,
    /// While set, the spool entry (if any) is stale and must be ignored;
    /// only full alignment may clear it.
    #[serde(default)]
    pub needs_realign: bool,
    /// Last state written to the session record (opaque to S3a).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_state: Option<String>,
    /// Verified Saved-sessions root id (S3b-i). Additive and append-safe:
    /// old checkpoints load with `None`, and only identity staging writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_id: Option<String>,
    /// Guard failure is terminal for automatic state writes across restarts.
    #[serde(default)]
    pub lease_stopped: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_writer: Option<String>,
    #[serde(default)]
    pub last_hosted_write_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_proposal_key: Option<String>,
}

impl Checkpoint {
    /// Fresh checkpoint bound to an agent and binding. Headless until the
    /// first admitted step; `needs_realign` starts clear.
    pub fn fresh(agent_id: &str, binding: Binding) -> Result<Self> {
        check_agent_filename(agent_id)?;
        binding.validate()?;
        Ok(Self {
            version: CHECKPOINT_VERSION,
            agent_id: agent_id.to_owned(),
            binding,
            label_value: None,
            terminal_save_label: None,
            terminal_save_code: None,
            quote_scan: None,
            quote_pending: None,
            folder_id: None,
            session_record_id: None,
            writer_generation: 0,
            state_seq: 0,
            head_pos: None,
            head_cid: None,
            head_fp: None,
            source_fps: Vec::new(),
            cursor_epoch: None,
            cursor_seq_end: None,
            alignment_gen: 0,
            needs_realign: false,
            last_state: None,
            root_id: None,
            lease_stopped: false,
            lease_writer: None,
            last_hosted_write_ms: 0,
            settled_proposal_key: None,
        })
    }

    fn validate(&self, agent_id: &str, binding: &Binding) -> Result<()> {
        if self.version != CHECKPOINT_VERSION {
            return Err(Error::engine(format!(
                "unsupported saver checkpoint version {}",
                self.version
            )));
        }
        if self.agent_id != agent_id {
            return Err(Error::engine("saver checkpoint agent mismatch"));
        }
        self.binding.validate()?;
        // Binding-aware identity: local state built under another
        // (server, account, db) is refused, never silently adopted.
        if !self.binding.matches(binding) {
            return Err(Error::engine(
                "saver checkpoint binding mismatch: refusing foreign local state",
            ));
        }
        match (&self.head_pos, &self.head_cid) {
            (Some(_), Some(cid)) => {
                decode_32(cid, "head cid")?;
            }
            (None, None) => {}
            _ => return Err(Error::engine("saver checkpoint head is half-present")),
        }
        for fp in &self.source_fps {
            decode_32(fp, "source fp")?;
        }
        if let Some(fp) = &self.head_fp {
            decode_32(fp, "head fp")?;
            if self.head_pos.is_none() {
                return Err(Error::engine("headless checkpoint has a head fingerprint"));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure outcome reducer (§6.3, S3a half)
// ---------------------------------------------------------------------------

/// Hosted answer classes the saver distinguishes. This is the transport-level
/// outcome; conflict *validation* (reading the record at `pos` and comparing
/// immutable content) belongs to S3b — the pure layer never invents admission
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Hosted answered success for our key.
    Success,
    /// Hosted answered `idempotency_conflict`: position taken. Caller must do
    /// the verified read + immutable-content comparison before adopting.
    Conflict,
    /// Nothing was sent (connection failed before send). Spool intact.
    NotSent,
    /// The write may or may not have been applied (timeout, dropped reply).
    Lost,
    /// Outcome unknown but not credential-scoped (unparsed 2xx, odd 5xx).
    Unclear,
    /// Credentials refused. All hosted writes stop; spool kept. No failover.
    AuthRefused,
    /// Key refused by name: non-SQLite backend. Stop with actionable error.
    KeyRefused,
    /// Any other 4xx: the request itself is invalid. Quarantine, stop session.
    ValidationRefused,
}

/// What the saver must do with the spool. Pure: no I/O, no adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Confirm `pos`, advance the head (S3b persists the head move).
    AdvanceHead,
    /// The position is taken; run the verified adoption read (S3b) before
    /// touching the head or the spool. Never auto-adopt here.
    AwaitVerifiedAdoption,
    /// Resend the identical frozen bytes (same key, same body).
    ResendSameBytes,
    /// Keep the spool, back off, mark `paused:hosted_unreachable` (S3b label).
    KeepSpoolBackoff,
    /// Stop all hosted writes, keep the spool, surface `error:auth`.
    StopAuth,
    /// Stop, surface `error:unsupported_backend`. Never fall back to unkeyed.
    StopUnsupported,
    /// Quarantine the spool entry, stop the session, surface `error`.
    Quarantine,
}

/// Pure outcome table (§6.3). Pending bytes are preserved on
/// uncertain/not-sent outcomes; only success advances and only validation
/// failure quarantines. Auth stops without failover.
pub fn decide(outcome: WriteOutcome) -> Disposition {
    match outcome {
        WriteOutcome::Success => Disposition::AdvanceHead,
        WriteOutcome::Conflict => Disposition::AwaitVerifiedAdoption,
        WriteOutcome::NotSent => Disposition::KeepSpoolBackoff,
        WriteOutcome::Lost | WriteOutcome::Unclear => Disposition::ResendSameBytes,
        WriteOutcome::AuthRefused => Disposition::StopAuth,
        WriteOutcome::KeyRefused => Disposition::StopUnsupported,
        WriteOutcome::ValidationRefused => Disposition::Quarantine,
    }
}

/// Whether curation must pause under the pending bound (§6.2). At or above the
/// limit the saver stops curating, reports `paused:backlog`, and drops
/// nothing; the next alignment records a resync marker if source was lost.
pub fn should_pause_curation(pending_bytes: u64, limit_bytes: u64) -> bool {
    pending_bytes >= limit_bytes
}

// ---------------------------------------------------------------------------
// Durable store
// ---------------------------------------------------------------------------

fn check_agent_filename(agent_id: &str) -> Result<()> {
    if agent_id.is_empty() || agent_id == "." || agent_id == ".." {
        return Err(Error::engine("saver agent id is not a file name"));
    }
    if agent_id.contains('/') || agent_id.contains('\\') || agent_id.contains('\0') {
        return Err(Error::engine(
            "saver agent id must not contain path separators",
        ));
    }
    if agent_id.len() > 128 {
        return Err(Error::engine("saver agent id exceeds bound"));
    }
    Ok(())
}

/// Durable per-host saver store rooted at `<socket_directory>/sessions/`.
pub struct SessionStore {
    state_dir: PathBuf,
    binding: Binding,
    #[cfg(test)]
    fail_after: std::sync::atomic::AtomicI64,
    /// Test-only crash-window hooks (one-shot). Each simulates the process
    /// dying at that persistence phase: the operation reports failure and, as
    /// documented per hook, either leaves prior state untouched (pre-rename
    /// phases) or leaves the mutation in place without its follow-up (post
    /// phases). Production builds contain no hooks: every phase runs.
    #[cfg(test)]
    fail_after_file_sync: std::sync::atomic::AtomicBool,
    /// Fail once after the rename, before the parent-dir fsync.
    #[cfg(test)]
    fail_after_rename: std::sync::atomic::AtomicBool,
    /// Fail once after the confirm checkpoint is saved, before the spool
    /// entry is unlinked.
    #[cfg(test)]
    fail_before_spool_unlink: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl SessionStore {
    fn take_hook(flag: &std::sync::atomic::AtomicBool) -> bool {
        flag.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

impl SessionStore {
    /// Open (creating) the state dir and pin the binding. An existing
    /// `binding.json` with a different triple is refused — never overwritten.
    pub fn open(state_dir: &Path, binding: Binding) -> Result<Self> {
        binding.validate()?;
        ensure_state_dir(state_dir)?;
        let store = Self {
            state_dir: state_dir.to_owned(),
            binding,
            #[cfg(test)]
            fail_after: std::sync::atomic::AtomicI64::new(-1),
            #[cfg(test)]
            fail_after_file_sync: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_before_spool_unlink: std::sync::atomic::AtomicBool::new(false),
        };
        store.pin_binding()?;
        Ok(store)
    }

    /// Binding this store was opened under.
    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// A durable host fence survives crashes between retirement admission
    /// and local lease adoption. It never authorizes ordinary old-host sends.
    pub fn host_retired(&self) -> Result<bool> {
        let path = self.state_dir.join(".host-retired.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(Error::engine(format!(
                    "cannot inspect host retirement: {e}"
                )))
            }
            Ok(m) if !m.is_file() || m.len() > MAX_PROPOSAL_BYTES => {
                return Err(Error::engine("unsafe host retirement fence"))
            }
            _ => {}
        }
        let bytes = fs::read(path)
            .map_err(|e| Error::engine(format!("cannot read retirement fence: {e}")))?;
        let binding: Binding = serde_json::from_slice(&bytes)
            .map_err(|_| Error::engine("corrupt host retirement fence"))?;
        if !binding.matches(&self.binding) {
            return Err(Error::engine("foreign host retirement fence"));
        }
        Ok(true)
    }
    pub fn retire_host(&self) -> Result<()> {
        if self.host_retired()? {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&self.binding)
            .map_err(|_| Error::engine("cannot encode retirement fence"))?;
        self.write_file(&self.state_dir.join(".host-retired.json"), &bytes)
    }
    /// Retain an obsolete uncertain metadata proposal for diagnosis. Once
    /// retired, only the narrow ended-state proposal may be replayed.
    pub fn quarantine_fenced_proposal(&self, agent: &str) -> Result<()> {
        if !self.host_retired()? && !self.load_checkpoint(agent)?.needs_realign {
            return Err(Error::engine(
                "proposal quarantine needs a durable source fence",
            ));
        }
        let path = self.proposal_path(agent)?;
        if !path
            .try_exists()
            .map_err(|e| Error::engine(format!("cannot inspect obsolete proposal: {e}")))?
        {
            return Ok(());
        }
        let target = path.with_extension(format!("json.retired-{}", uuid::Uuid::new_v4()));
        fs::rename(path, target)
            .map_err(|e| Error::engine(format!("cannot quarantine obsolete proposal: {e}")))?;
        sync_dir(&self.state_dir)
    }
    pub fn checkpoint_agents(&self) -> Result<Vec<String>> {
        let mut agents = Vec::new();
        for entry in fs::read_dir(&self.state_dir)
            .map_err(|e| Error::engine(format!("cannot enumerate saver checkpoints: {e}")))?
        {
            let entry =
                entry.map_err(|e| Error::engine(format!("cannot read checkpoint entry: {e}")))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.starts_with('.')
                || name == "binding.json"
                || name.ends_with(".proposal.json")
                || path.extension().and_then(|x| x.to_str()) != Some("json")
            {
                continue;
            }
            let agent = path
                .file_stem()
                .and_then(|n| n.to_str())
                .ok_or_else(|| Error::engine("invalid checkpoint filename"))?;
            let cp = self.load_checkpoint(agent)?;
            if cp.session_record_id.is_some() {
                agents.push(agent.to_owned());
            }
        }
        agents.sort();
        Ok(agents)
    }

    fn binding_path(&self) -> PathBuf {
        self.state_dir.join("binding.json")
    }

    fn proposal_path(&self, agent_id: &str) -> Result<PathBuf> {
        check_agent_filename(agent_id)?;
        Ok(self.state_dir.join(format!("{agent_id}.proposal.json")))
    }

    pub fn load_proposal(&self, agent_id: &str) -> Result<Option<FrozenStateProposal>> {
        let path = self.proposal_path(agent_id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::engine(format!("cannot stat state proposal: {e}"))),
            Ok(metadata) => metadata,
        };
        if !metadata.is_file() || metadata.len() > MAX_PROPOSAL_BYTES {
            return Err(Error::engine("invalid state proposal file or size"));
        }
        let bytes =
            fs::read(path).map_err(|e| Error::engine(format!("cannot read proposal: {e}")))?;
        let proposal: FrozenStateProposal = serde_json::from_slice(&bytes)
            .map_err(|e| Error::engine(format!("corrupt state proposal: {e}")))?;
        proposal.validate(&self.binding, agent_id)?;
        Ok(Some(proposal))
    }

    pub fn freeze_proposal(&self, proposal: &FrozenStateProposal) -> Result<()> {
        proposal.validate(&self.binding, &proposal.agent_id)?;
        let checkpoint = self.load_checkpoint(&proposal.agent_id)?;
        if proposal.kind == ProposalKind::State {
            let sequence = proposal
                .key
                .rsplit_once(":s")
                .and_then(|(_, n)| n.parse::<u64>().ok());
            if checkpoint.writer_generation != proposal.generation
                || checkpoint.lease_writer.as_deref() != Some(proposal.writer.as_str())
                || sequence.is_none_or(|n| n >= checkpoint.state_seq)
            {
                return Err(Error::engine(
                    "state proposal lacks a reserved key under the held lease",
                ));
            }
        }
        if checkpoint.lease_stopped
            || checkpoint.session_record_id.as_deref() != Some(&proposal.record_id)
        {
            return Err(Error::engine(
                "state proposal has no active local session identity",
            ));
        }
        if let Some(pending) = self.load_proposal(&proposal.agent_id)? {
            return if pending == *proposal {
                Ok(())
            } else {
                Err(Error::engine(
                    "state proposal pending: settle before replacing",
                ))
            };
        }
        let bytes = serde_json::to_vec(proposal)
            .map_err(|e| Error::engine(format!("proposal encode: {e}")))?;
        if bytes.len() as u64 > MAX_PROPOSAL_BYTES {
            return Err(Error::engine("state proposal exceeds size bound"));
        }
        self.write_file(&self.proposal_path(&proposal.agent_id)?, &bytes)
    }

    /// Call only after the admitted generation or terminal stop is durable.
    pub fn drop_proposal(&self, agent_id: &str) -> Result<()> {
        if let Some(pending) = self.load_proposal(agent_id)? {
            let checkpoint = self.load_checkpoint(agent_id)?;
            if !checkpoint.lease_stopped
                && checkpoint.settled_proposal_key.as_deref() != Some(&pending.key)
            {
                return Err(Error::engine(
                    "refusing to drop an unsettled state proposal",
                ));
            }
        }
        match fs::remove_file(self.proposal_path(agent_id)?) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::engine(format!("cannot drop state proposal: {e}"))),
        }
        sync_dir(&self.state_dir)
    }

    pub fn mark_proposal_settled(
        &self,
        agent_id: &str,
        pending: &FrozenStateProposal,
        last_seen_ms: i64,
        state: Option<&str>,
    ) -> Result<()> {
        if self.load_proposal(agent_id)?.as_ref() != Some(pending) {
            return Err(Error::engine(
                "state settlement does not match the frozen proposal",
            ));
        }
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        checkpoint.settled_proposal_key = Some(pending.key.clone());
        checkpoint.last_hosted_write_ms = last_seen_ms;
        if let Some(state) = state {
            checkpoint.last_state = Some(state.to_owned());
        }
        self.save_checkpoint(&checkpoint)
    }

    pub fn latch_lease_stopped(&self, agent_id: &str) -> Result<()> {
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        checkpoint.lease_stopped = true;
        self.save_checkpoint(&checkpoint)
    }

    pub fn adopt_lease(&self, agent_id: &str, generation: u64, writer: &str) -> Result<()> {
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        if checkpoint.lease_stopped
            || generation < checkpoint.writer_generation
            || writer.is_empty()
        {
            return Err(Error::engine("refusing stale or stopped lease adoption"));
        }
        if generation == checkpoint.writer_generation {
            if checkpoint
                .lease_writer
                .as_deref()
                .is_some_and(|held| held != writer)
            {
                return Err(Error::engine("writer changed without a new generation"));
            }
        } else {
            checkpoint.writer_generation = generation;
            checkpoint.state_seq = 0;
        }
        checkpoint.lease_writer = Some(writer.to_owned());
        self.save_checkpoint(&checkpoint)
    }

    pub fn reserve_state_seq(&self, agent_id: &str, generation: u64, writer: &str) -> Result<u64> {
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        if checkpoint.lease_stopped
            || checkpoint.writer_generation != generation
            || checkpoint.lease_writer.as_deref() != Some(writer)
        {
            return Err(Error::engine(
                "state sequence requires the locally held lease",
            ));
        }
        if self.load_proposal(agent_id)?.is_some() {
            return Err(Error::engine(
                "state proposal pending before sequence reservation",
            ));
        }
        let seq = checkpoint.state_seq;
        checkpoint.state_seq = seq
            .checked_add(1)
            .ok_or_else(|| Error::engine("state sequence exhausted"))?;
        self.save_checkpoint(&checkpoint)?;
        Ok(seq)
    }

    fn checkpoint_path(&self, agent_id: &str) -> Result<PathBuf> {
        check_agent_filename(agent_id)?;
        Ok(self.state_dir.join(format!("{agent_id}.json")))
    }

    fn spool_dir(&self, agent_id: &str) -> Result<PathBuf> {
        check_agent_filename(agent_id)?;
        Ok(self.state_dir.join(format!("{agent_id}.spool")))
    }

    fn spool_path(&self, agent_id: &str, pos: u64) -> Result<PathBuf> {
        Ok(self.spool_dir(agent_id)?.join(format!("p{pos}.json")))
    }

    /// First open wins: an existing binding file must match the full triple.
    fn pin_binding(&self) -> Result<()> {
        let path = self.binding_path();
        match fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.write_file(
                    &path,
                    &serde_json::to_vec(&self.binding)
                        .map_err(|e| Error::engine(format!("saver binding encode: {e}")))?,
                )?;
                Ok(())
            }
            Err(e) => Err(Error::engine(format!("cannot read saver binding: {e}"))),
            Ok(bytes) => {
                let stored: Binding = serde_json::from_slice(&bytes)
                    .map_err(|_| Error::engine("saver binding is corrupt: refusing local state"))?;
                stored
                    .validate()
                    .map_err(|_| Error::engine("saver binding is corrupt: refusing local state"))?;
                if !stored.matches(&self.binding) {
                    return Err(Error::engine(
                        "saver binding mismatch: local state belongs to another (server, account, db)",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Load the checkpoint, validating version, agent identity and binding.
    /// Missing file yields a fresh headless checkpoint (not an error).
    pub fn load_checkpoint(&self, agent_id: &str) -> Result<Checkpoint> {
        let path = self.checkpoint_path(agent_id)?;
        let bytes = match fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Checkpoint::fresh(agent_id, self.binding.clone());
            }
            Err(e) => return Err(Error::engine(format!("cannot read checkpoint: {e}"))),
            Ok(bytes) => bytes,
        };
        if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
            return Err(Error::engine("saver checkpoint exceeds bound"));
        }
        let checkpoint: Checkpoint = serde_json::from_slice(&bytes)
            .map_err(|_| Error::engine("saver checkpoint is corrupt: refusing local state"))?;
        checkpoint.validate(agent_id, &self.binding)?;
        Ok(checkpoint)
    }

    /// Atomically replace the checkpoint (head/E/cursor/`alignment_gen`/
    /// `needs_realign` together). Tmp files never parse as checkpoints.
    pub fn save_checkpoint(&self, checkpoint: &Checkpoint) -> Result<()> {
        checkpoint.validate(&checkpoint.agent_id, &self.binding)?;
        let path = self.checkpoint_path(&checkpoint.agent_id)?;
        let bytes = serde_json::to_vec(checkpoint)
            .map_err(|e| Error::engine(format!("saver checkpoint encode: {e}")))?;
        if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
            return Err(Error::engine("saver checkpoint exceeds bound"));
        }
        self.write_file(&path, &bytes)
    }

    /// Durably set `needs_realign = true` (bumping `alignment_gen`). This is
    /// the mandatory first step before adopting a foreign head or
    /// quarantining a stale spool; the counterparts refuse without it.
    pub fn mark_needs_realign(&self, agent_id: &str) -> Result<Checkpoint> {
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        checkpoint.needs_realign = true;
        // Even an exhausted generation must remain durably fenceable.
        // Readmission, not setting the fence, refuses exhaustion below.
        checkpoint.alignment_gen = checkpoint.alignment_gen.saturating_add(1);
        self.save_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Freeze the next spool entry. At most one spool file may exist per
    /// agent, and a spooled position is never rekeyed.
    ///
    /// Restart behavior, decided explicitly: re-freezing the **byte-identical**
    /// request (same position, same bytes — e.g. a retry after a crash
    /// between freeze and send) is idempotent and returns the existing path.
    /// Any other collision — a different position while one is in flight, or
    /// different bytes for the same position — is refused; the caller must
    /// drain, confirm, or quarantine the in-flight entry first.
    pub fn freeze_spool(&self, request: &FrozenStepRequest, agent_id: &str) -> Result<PathBuf> {
        request.validate()?;
        if request.version != SPOOL_VERSION {
            return Err(Error::engine("unsupported saver spool version"));
        }
        let expected_key = position_key(&self.binding.server_id, agent_id, request.pos)?;
        if request.key != expected_key {
            return Err(Error::engine(
                "saver spool key does not match binding/position",
            ));
        }
        if request.reason != REASON_STEP {
            return Err(Error::engine("saver spool reason is not frozen"));
        }
        let new_bytes = request.retry_bytes()?;
        if new_bytes.len() as u64 > MAX_SPOOL_BYTES {
            return Err(Error::engine("saver spool entry exceeds bound"));
        }
        let dir = self.spool_dir(agent_id)?;
        ensure_state_dir(&dir)?;
        let existing = self.list_spool(agent_id)?;
        if !existing.is_empty() {
            // Idempotent same-bytes re-freeze is the only allowed collision.
            if existing.len() == 1 {
                let path = self.spool_path(agent_id, request.pos)?;
                if existing[0] == path {
                    let on_disk = fs::read(&path)
                        .map_err(|e| Error::engine(format!("cannot read spool: {e}")))?;
                    if on_disk == new_bytes {
                        return Ok(path);
                    }
                }
            }
            return Err(Error::engine(
                "saver spool already in flight: drain or resolve it first",
            ));
        }
        let path = self.spool_path(agent_id, request.pos)?;
        self.write_file(&path, &new_bytes)?;
        Ok(path)
    }

    /// Validate one spool file's bytes against its name, binding and frozen
    /// shape. Single choke point for every spool read, so the raw-byte retry
    /// path can never bypass the checks the parsed path enforces.
    fn read_spool_file(&self, agent_id: &str, path: &Path) -> Result<(FrozenStepRequest, Vec<u8>)> {
        let bytes = fs::read(path).map_err(|e| Error::engine(format!("cannot read spool: {e}")))?;
        if bytes.len() as u64 > MAX_SPOOL_BYTES {
            return Err(Error::engine("saver spool entry exceeds bound"));
        }
        let request: FrozenStepRequest = serde_json::from_slice(&bytes)
            .map_err(|_| Error::engine("saver spool is corrupt: refusing local state"))?;
        request.validate()?;
        if request.version != SPOOL_VERSION {
            return Err(Error::engine("unsupported saver spool version"));
        }
        let expected_key = position_key(&self.binding.server_id, agent_id, request.pos)?;
        if request.key != expected_key {
            return Err(Error::engine(
                "saver spool key does not match binding/position",
            ));
        }
        if request.reason != REASON_STEP {
            return Err(Error::engine("saver spool reason is not frozen"));
        }
        if spool_file_pos(path)? != request.pos {
            return Err(Error::engine(
                "saver spool file position does not match entry",
            ));
        }
        Ok((request, bytes))
    }

    /// Read the in-flight spool entry, if any. While `needs_realign` is set
    /// the entry is stale and reported as absent: alignment must run first
    /// and a restart must not replay the stale mapping.
    pub fn load_spool(&self, agent_id: &str) -> Result<Option<FrozenStepRequest>> {
        let checkpoint = self.load_checkpoint(agent_id)?;
        if checkpoint.needs_realign {
            return Ok(None);
        }
        let paths = self.list_spool(agent_id)?;
        match paths.as_slice() {
            [] => Ok(None),
            [path] => {
                let (request, _) = self.read_spool_file(agent_id, path)?;
                Ok(Some(request))
            }
            _ => Err(Error::engine(
                "saver spool has more than one in-flight entry: refusing local state",
            )),
        }
    }

    /// Exact retry bytes for the in-flight entry (byte-stable across restart).
    /// `None` when no entry is actionable (absent or hidden by the flag).
    /// Reads the raw file bytes rather than re-serializing, so the stability
    /// claim is about what is actually on disk — after passing the same
    /// [`SessionStore::read_spool_file`] validation the parsed path enforces.
    pub fn spool_retry_bytes(&self, agent_id: &str) -> Result<Option<Vec<u8>>> {
        if self.load_checkpoint(agent_id)?.needs_realign {
            return Ok(None);
        }
        let paths = self.list_spool(agent_id)?;
        match paths.as_slice() {
            [] => Ok(None),
            [path] => {
                let (_, bytes) = self.read_spool_file(agent_id, path)?;
                Ok(Some(bytes))
            }
            _ => Err(Error::engine(
                "saver spool has more than one in-flight entry: refusing local state",
            )),
        }
    }

    fn list_spool(&self, agent_id: &str) -> Result<Vec<PathBuf>> {
        let dir = self.spool_dir(agent_id)?;
        let mut out = Vec::new();
        match fs::read_dir(&dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(Error::engine(format!("cannot list spool: {e}"))),
            Ok(entries) => {
                for item in entries {
                    let path = item
                        .map_err(|e| Error::engine(format!("cannot list spool: {e}")))?
                        .path();
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_owned();
                    if name.contains(".tmp") {
                        // A freeze that never reached rename: the previous
                        // state (absent entry) is intact. Clean up lazily.
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if name.starts_with('p') && name.ends_with(".json") {
                        // Only count well-formed `p<pos>.json`; anything else
                        // (e.g. `.quarantined` sidecars) is not in flight.
                        if spool_file_pos(&path).is_ok() {
                            out.push(path);
                        }
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Adopt a foreign head after the verified S3b read. Refuses unless
    /// `needs_realign` is already durably set on disk: the flag must be
    /// written **before** adoption so a crash between observing the foreign
    /// head and refreshing the mapping restarts into alignment, never into a
    /// stale append.
    pub fn adopt_foreign_head(
        &self,
        agent_id: &str,
        pos: u64,
        cid_hex: &str,
        source_fps: Vec<String>,
    ) -> Result<Checkpoint> {
        decode_32(cid_hex, "adopted head cid")?;
        for fp in &source_fps {
            decode_32(fp, "source fp")?;
        }
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        if !checkpoint.needs_realign {
            return Err(Error::engine(
                "refusing foreign-head adoption before durable needs_realign",
            ));
        }
        checkpoint.head_pos = Some(pos);
        checkpoint.head_cid = Some(cid_hex.to_owned());
        checkpoint.head_fp = None; // Foreign admission is verified by S3b, not a local receipt.
        checkpoint.source_fps = source_fps;
        checkpoint.cursor_epoch = None;
        checkpoint.cursor_seq_end = None;
        // The flag stays set until alignment completes and clears it with a
        // verified cursor; adoption alone never clears it.
        self.save_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Move a stale spool entry aside after the flag is durably set. Refuses
    /// without the flag for the same crash-ordering reason as adoption.
    /// Quarantined bytes are preserved for inspection, never retried.
    pub fn quarantine_spool(&self, agent_id: &str) -> Result<PathBuf> {
        let checkpoint = self.load_checkpoint(agent_id)?;
        if !checkpoint.needs_realign {
            return Err(Error::engine(
                "refusing spool quarantine before durable needs_realign",
            ));
        }
        let paths = self.list_spool(agent_id)?;
        let path = paths
            .first()
            .ok_or_else(|| Error::engine("no spool entry to quarantine"))?;
        let quarantined = path.with_extension("json.quarantined");
        fs::rename(path, &quarantined)
            .map_err(|e| Error::engine(format!("cannot quarantine spool: {e}")))?;
        sync_dir(
            &self
                .spool_dir(agent_id)
                .unwrap_or_else(|_| self.state_dir.clone()),
        )?;
        Ok(quarantined)
    }

    /// Confirm the spooled position after hosted success: advance the head,
    /// extend `E`, record the source cursor, and remove the spool entry.
    /// The caller passes back exactly what hosted admitted (`pos`, `cid`,
    /// `fp`); every mismatch against the spool or the checkpoint refuses —
    /// this function never branches into a different history.
    ///
    /// Crash windows, handled explicitly:
    ///
    /// - Crash between the checkpoint save and the spool unlink: the head is
    ///   already advanced but the spool file survives. Re-confirming with the
    ///   same (`pos`, `cid`, `fp`) is idempotent — the stale spool file is
    ///   cleaned up and the checkpoint is returned **without** re-appending
    ///   `E`. Any differing triple refuses.
    /// - Crash before the checkpoint save: the spool survives, the head is
    ///   unmoved, and re-confirming advances normally.
    ///
    /// Position discipline: a headless checkpoint admits only position 1
    /// whose parent is the true [`chain_root`] for this (server, agent) —
    /// never whatever parent the spool happens to carry. A headed checkpoint
    /// admits only `head + 1` whose parent equals the head cid. Arbitrary
    /// positions and head regressions are refused.
    pub fn confirm_spooled(
        &self,
        agent_id: &str,
        pos: u64,
        cid_hex: &str,
        fp_hex: &str,
        cursor_epoch: &str,
        cursor_seq_end: u64,
    ) -> Result<Checkpoint> {
        decode_32(cid_hex, "confirmed cid")?;
        decode_32(fp_hex, "source fp")?;
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        if checkpoint.needs_realign {
            return Err(Error::engine("refusing confirm while needs_realign is set"));
        }
        let head_matches = checkpoint.head_pos == Some(pos)
            && checkpoint.head_cid.as_deref() == Some(cid_hex)
            && checkpoint.head_fp.as_deref() == Some(fp_hex);
        if head_matches {
            // Already admitted (checkpoint saved, spool unlink lost): clean up
            // the stale spool file without touching the head or `E`. The
            // post-unlink dir sync below is best-effort: if power loss
            // resurrects the file, re-confirming the same triple returns here
            // again, so resurrection can never double-advance the head.
            let path = self.spool_path(agent_id, pos)?;
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::engine(format!("cannot drop spool: {e}"))),
            }
            if let Ok(dir) = self.spool_dir(agent_id) {
                let _ = sync_dir(&dir);
            }
            return Ok(checkpoint);
        }
        let spooled = self
            .load_spool(agent_id)?
            .ok_or_else(|| Error::engine("no actionable spool entry to confirm"))?;
        // The receipt must describe exactly the frozen request.
        if spooled.pos != pos || spooled.facets.cid != cid_hex || spooled.facets.fp != fp_hex {
            return Err(Error::engine(
                "confirm triple does not match the spooled request",
            ));
        }
        // Next position and verified parent — never arbitrary, never back.
        match (&checkpoint.head_pos, &checkpoint.head_cid) {
            (None, None) => {
                if pos != 1 {
                    return Err(Error::engine("headless checkpoint admits only position 1"));
                }
                let root = chain_root(&self.binding.server_id, agent_id)?;
                if spooled.facets.parent_cid != root {
                    return Err(Error::engine("headless spool parent is not the chain root"));
                }
            }
            (Some(head_pos), Some(head_cid)) => {
                if Some(pos) != head_pos.checked_add(1) {
                    return Err(Error::engine(
                        "confirm position is not the next head position",
                    ));
                }
                if spooled.facets.parent_cid != *head_cid {
                    return Err(Error::engine(
                        "spool parent does not extend the checkpoint head",
                    ));
                }
            }
            _ => {
                return Err(Error::engine("saver checkpoint head is half-present"));
            }
        }
        // Head/CID consistency: the frozen cid must chain from the parent.
        let recomputed = chain_next(&spooled.facets.parent_cid, fp_hex)?;
        if recomputed != spooled.facets.cid {
            return Err(Error::engine("spooled cid does not chain from parent"));
        }
        checkpoint.head_pos = Some(spooled.pos);
        checkpoint.head_cid = Some(spooled.facets.cid.clone());
        checkpoint.head_fp = Some(fp_hex.to_owned());
        checkpoint.last_hosted_write_ms = chrono::Utc::now().timestamp_millis();
        if let Some(base_len) = spooled.facets.base_len {
            check_marker_base_len(base_len, checkpoint.source_fps.len())?;
            checkpoint.source_fps.truncate(base_len as usize);
        } else {
            checkpoint.source_fps.push(fp_hex.to_owned());
        }
        checkpoint.cursor_epoch = Some(cursor_epoch.to_owned());
        checkpoint.cursor_seq_end = Some(cursor_seq_end);
        self.save_checkpoint(&checkpoint)?;
        #[cfg(test)]
        if Self::take_hook(&self.fail_before_spool_unlink) {
            // Crash after the checkpoint save, before the spool unlink: the
            // head is advanced and the spool survives. Re-confirming the same
            // triple takes the idempotent path above.
            return Err(Error::engine("injected failure before spool unlink"));
        }
        let path = self.spool_path(agent_id, spooled.pos)?;
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::engine(format!("cannot drop spool: {e}"))),
        }
        if let Ok(dir) = self.spool_dir(agent_id) {
            let _ = sync_dir(&dir);
        }
        Ok(checkpoint)
    }

    /// Clear `needs_realign` once alignment has rebuilt `E` and verified the
    /// cursor. Only alignment (S3b) calls this, with fresh values. Refuses
    /// while a stale spool `.json` still survives: clearing the flag would
    /// reactivate it, so the caller must [`SessionStore::quarantine_spool`]
    /// it first.
    pub fn clear_realign(
        &self,
        agent_id: &str,
        source_fps: Vec<String>,
        cursor_epoch: &str,
        cursor_seq_end: u64,
    ) -> Result<Checkpoint> {
        for fp in &source_fps {
            decode_32(fp, "source fp")?;
        }
        if !self.list_spool(agent_id)?.is_empty() {
            return Err(Error::engine(
                "refusing to clear needs_realign with a surviving stale spool: quarantine it first",
            ));
        }
        let mut checkpoint = self.load_checkpoint(agent_id)?;
        checkpoint.source_fps = source_fps;
        checkpoint.cursor_epoch = Some(cursor_epoch.to_owned());
        checkpoint.cursor_seq_end = Some(cursor_seq_end);
        checkpoint.needs_realign = false;
        checkpoint.alignment_gen = checkpoint
            .alignment_gen
            .checked_add(1)
            .ok_or_else(|| Error::engine("saver alignment generation exhausted"))?;
        self.save_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Durable temp-file + fsync + rename + parent-dir fsync replace,
    /// following the node journal conventions (0700 dirs, 0600 files,
    /// `O_NOFOLLOW | O_CLOEXEC`, `.tmp` names that never parse as state).
    /// Every fsync error is propagated: durability is claimed only when every
    /// phase succeeds, never by swallowing a failed sync.
    /// Whether a checkpoint file exists on disk (distinct from loading,
    /// which mints a headless fresh value when absent).
    pub(crate) fn has_checkpoint(&self, agent_id: &str) -> Result<bool> {
        let path = self.checkpoint_path(agent_id)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::engine(format!("cannot stat checkpoint: {e}"))),
        }
    }

    /// Whether any spool file survives for this agent (visible or not).
    pub(crate) fn has_spool(&self, agent_id: &str) -> Result<bool> {
        Ok(!self.list_spool(agent_id)?.is_empty())
    }

    /// Stash the verified root/folder/record identity (S3b-i). Additive:
    /// nothing else in the store reads `root_id`.
    pub(crate) fn set_session_ids(
        &self,
        agent_id: &str,
        root_id: &str,
        folder_id: &str,
        record_id: &str,
    ) -> Result<Checkpoint> {
        if root_id.trim().is_empty() || folder_id.trim().is_empty() || record_id.trim().is_empty() {
            return Err(Error::engine("saver session ids are empty"));
        }
        // Identity staging must not turn checkpoint loss into a fresh session.
        // Persist the recovery fence before writing replacement identity fields.
        let mut checkpoint = if !self.has_checkpoint(agent_id)?
            && (self.has_spool(agent_id)? || self.load_proposal(agent_id)?.is_some())
        {
            self.mark_needs_realign(agent_id)?
        } else {
            self.load_checkpoint(agent_id)?
        };
        checkpoint.root_id = Some(root_id.to_owned());
        checkpoint.folder_id = Some(folder_id.to_owned());
        checkpoint.session_record_id = Some(record_id.to_owned());
        self.save_checkpoint(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Durably record the hosted Saved-sessions folder id in the binding.
    pub(crate) fn set_saved_sessions_folder(&mut self, folder_id: &str) -> Result<()> {
        if folder_id.trim().is_empty() {
            return Err(Error::engine("saver folder id is empty"));
        }
        self.binding.saved_sessions_folder_id = Some(folder_id.to_owned());
        self.binding.validate()?;
        let path = self.binding_path();
        let bytes = fs::read(&path)
            .map_err(|e| Error::engine(format!("cannot read saver binding: {e}")))?;
        let stored: Binding = serde_json::from_slice(&bytes)
            .map_err(|_| Error::engine("saver binding is corrupt: refusing local state"))?;
        stored.validate()?;
        if !stored.matches(&self.binding) {
            return Err(Error::engine(
                "saver binding mismatch: local state belongs to another (server, account, db)",
            ));
        }
        self.write_file(
            &path,
            &serde_json::to_vec(&self.binding)
                .map_err(|e| Error::engine(format!("saver binding encode: {e}")))?,
        )
    }

    fn write_file(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let left = self.fail_after.load(SeqCst);
            if left == 0 {
                self.fail_after.store(-1, SeqCst);
                return Err(Error::engine("injected saver store write failure"));
            }
            if left > 0 {
                self.fail_after.store(left - 1, SeqCst);
            }
        }
        let parent = path
            .parent()
            .ok_or_else(|| Error::engine("saver state path has no parent"))?;
        let temporary = parent.join(format!(
            ".{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
            uuid::Uuid::new_v4()
        ));
        let write_tmp = || -> std::io::Result<()> {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(bytes)?;
            output.sync_all()?;
            // Harden the mode explicitly: umask-independent 0600.
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
            Ok(())
        };
        if let Err(e) = write_tmp() {
            let _ = fs::remove_file(&temporary);
            return Err(Error::engine(format!(
                "cannot durably stage saver state: {e}"
            )));
        }
        #[cfg(test)]
        if Self::take_hook(&self.fail_after_file_sync) {
            // Crash after the file fsync, before the rename: the staged tmp
            // is swept on the next load and prior state is untouched.
            let _ = fs::remove_file(&temporary);
            return Err(Error::engine("injected failure after file sync"));
        }
        if let Err(e) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(Error::engine(format!("cannot replace saver state: {e}")));
        }
        #[cfg(test)]
        if Self::take_hook(&self.fail_after_rename) {
            // Crash after the rename, before the parent-dir fsync: the new
            // bytes are in place but the directory entry may not survive a
            // power loss. The caller sees failure and must re-read rather
            // than assume either outcome.
            return Err(Error::engine("injected failure after rename"));
        }
        if let Err(e) = sync_dir(parent) {
            return Err(Error::engine(format!("cannot fsync saver state dir: {e}")));
        }
        Ok(())
    }
}

fn spool_file_pos(path: &Path) -> Result<u64> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::engine("saver spool name is not unicode"))?;
    let stem = name
        .strip_prefix('p')
        .and_then(|s| s.strip_suffix(".json"))
        .ok_or_else(|| Error::engine("saver spool name is not p<pos>.json"))?;
    stem.parse::<u64>()
        .map_err(|_| Error::engine("saver spool position is not numeric"))
}

/// Create (0700, hardened after creation) and durability-fsync a state
/// directory. The new directory's own entry lives in its parent, so the
/// parent is fsync'd too — without that, every fsync'd file inside could
/// vanish with the entry. All sync errors propagate: this function claims
/// durability only when every phase succeeds.
fn ensure_state_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::engine(format!("cannot create saver state dir: {e}")))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::engine(format!("cannot secure saver state dir: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
            .map_err(|e| Error::engine(format!("cannot create saver state dir: {e}")))?;
    }
    // Durable entry: the parent must be on disk for this directory to survive.
    let parent = dir
        .parent()
        .ok_or_else(|| Error::engine("saver state dir has no parent"))?;
    File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| Error::engine(format!("cannot fsync saver state parent dir: {e}")))?;
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| Error::engine(format!("cannot fsync saver state dir: {e}")))?;
    Ok(())
}

/// Validate a marker `base_len` against the current `E` length (§6.4 step 4).
pub fn check_marker_base_len(base_len: u64, e_len: usize) -> Result<()> {
    if base_len <= e_len as u64 {
        Ok(())
    } else {
        Err(Error::engine("saver marker base_len exceeds E length"))
    }
}

/// Pending accounting helper: spool bytes plus already-curated-but-unsent
/// bytes against the configured limit.
pub fn pending_paused(spool_bytes: u64, curated_bytes: u64, limit_bytes: u64) -> bool {
    should_pause_curation(spool_bytes.saturating_add(curated_bytes), limit_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::session_projection;

    fn test_binding() -> Binding {
        Binding::new("srv-a", "acct-a", "db-a", None).unwrap()
    }

    fn open_store(dir: &Path) -> SessionStore {
        SessionStore::open(&dir.join("sessions"), test_binding()).unwrap()
    }

    fn state_proposal(store: &SessionStore, seq: u64) -> FrozenStateProposal {
        use serde_json::json;
        let key = format!("nss3:state:record-1:g1:s{seq}");
        FrozenStateProposal {
            version: 1,
            binding: store.binding().clone(),
            agent_id: "agent-1".into(),
            record_id: "record-1".into(),
            kind: ProposalKind::State,
            generation: 1,
            writer: "srv-a/instance/boot".into(),
            key: key.clone(),
            arguments: json!({"ids":["record-1"], "reason":"Saved session state",
                "facets":{"native.session.state":"saving"},
                "if_facets":{"native.session.writer_generation":1,"native.session.writer":"srv-a/instance/boot"},
                "idempotency_key":key}),
        }
    }

    #[test]
    fn uncertain_state_proposal_survives_restart_and_blocks_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        store
            .set_session_ids("agent-1", "root", "folder", "record-1")
            .unwrap();
        store
            .adopt_lease("agent-1", 1, "srv-a/instance/boot")
            .unwrap();
        let seq = store
            .reserve_state_seq("agent-1", 1, "srv-a/instance/boot")
            .unwrap();
        let proposal = state_proposal(&store, seq);
        store.freeze_proposal(&proposal).unwrap();
        let reopened = open_store(dir.path());
        assert_eq!(
            reopened.load_proposal("agent-1").unwrap(),
            Some(proposal.clone())
        );
        reopened.freeze_proposal(&proposal).unwrap();
        assert!(reopened
            .freeze_proposal(&state_proposal(&store, seq + 1))
            .is_err());
        assert!(reopened
            .reserve_state_seq("agent-1", 1, "srv-a/instance/boot")
            .is_err());
        // Replaying a surviving lease receipt must not reset already reserved keys.
        reopened
            .adopt_lease("agent-1", 1, "srv-a/instance/boot")
            .unwrap();
        assert!(reopened.drop_proposal("agent-1").is_err());
        reopened
            .fail_after_file_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(reopened
            .mark_proposal_settled("agent-1", &proposal, 1, Some("saving"))
            .is_err());
        assert!(reopened.drop_proposal("agent-1").is_err());
        assert_eq!(
            open_store(dir.path()).load_proposal("agent-1").unwrap(),
            Some(proposal.clone())
        );
        reopened
            .mark_proposal_settled("agent-1", &proposal, 1, Some("saving"))
            .unwrap();
        reopened.drop_proposal("agent-1").unwrap();
        assert_eq!(
            reopened
                .reserve_state_seq("agent-1", 1, "srv-a/instance/boot")
                .unwrap(),
            seq + 1
        );
        let mut corrupt = state_proposal(&store, 2);
        corrupt.arguments["if_facets"]["native.session.writer"] = serde_json::json!("other");
        fs::write(
            reopened.proposal_path("agent-1").unwrap(),
            serde_json::to_vec(&corrupt).unwrap(),
        )
        .unwrap();
        assert!(reopened.load_proposal("agent-1").is_err());
        assert!(
            reopened.freeze_proposal(&proposal).is_err(),
            "corruption must not be overwritten"
        );
    }

    #[test]
    fn superseded_state_writer_is_latched_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        store
            .adopt_lease("agent-1", 1, "srv-a/instance/boot")
            .unwrap();
        store.latch_lease_stopped("agent-1").unwrap();
        let reopened = open_store(dir.path());
        assert!(reopened
            .adopt_lease("agent-1", 2, "srv-a/instance/newboot")
            .is_err());
        assert!(reopened
            .reserve_state_seq("agent-1", 1, "srv-a/instance/boot")
            .is_err());
        assert!(reopened.load_checkpoint("agent-1").unwrap().lease_stopped);
    }

    #[test]
    fn state_sequence_exhaustion_and_failed_proposal_freeze_preserve_prior_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        store
            .set_session_ids("agent-1", "root", "folder", "record-1")
            .unwrap();
        store
            .adopt_lease("agent-1", 1, "srv-a/instance/boot")
            .unwrap();
        store
            .reserve_state_seq("agent-1", 1, "srv-a/instance/boot")
            .unwrap();
        store
            .fail_after_file_sync
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(store.freeze_proposal(&state_proposal(&store, 0)).is_err());
        assert!(store.load_proposal("agent-1").unwrap().is_none());
        let mut checkpoint = store.load_checkpoint("agent-1").unwrap();
        checkpoint.state_seq = u64::MAX;
        store.save_checkpoint(&checkpoint).unwrap();
        assert!(store
            .reserve_state_seq("agent-1", 1, "srv-a/instance/boot")
            .is_err());
        assert_eq!(
            store.load_checkpoint("agent-1").unwrap().state_seq,
            u64::MAX
        );
    }

    fn sample_fp(body: &str) -> String {
        session_projection::fingerprint_step(session_projection::StepKind::Agent, 0, body)
    }

    fn freeze_sample(
        store: &SessionStore,
        agent: &str,
        pos: u64,
        parent: &str,
        body: &str,
    ) -> FrozenStepRequest {
        let fp = sample_fp(body);
        FrozenStepRequest::freeze(
            store.binding(),
            agent,
            "folder-1",
            "step",
            body,
            "agent",
            0,
            None,
            parent,
            &fp,
            pos,
            "2026-10-17T00:00:00Z",
        )
        .unwrap()
    }

    #[test]
    fn binding_triple_mismatch_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _store = open_store(dir.path());
        // Same server, different db: must not open against existing state.
        let other = Binding::new("srv-a", "acct-a", "db-b", None).unwrap();
        assert!(SessionStore::open(&dir.path().join("sessions"), other).is_err());
        // Same server+db, different account: refused as well.
        let other = Binding::new("srv-a", "acct-z", "db-a", None).unwrap();
        assert!(SessionStore::open(&dir.path().join("sessions"), other).is_err());
    }

    #[test]
    fn corrupt_truncated_version_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        // Seed a valid checkpoint first.
        let cp = store.load_checkpoint("agent-1").unwrap();
        store.save_checkpoint(&cp).unwrap();
        let path = dir.path().join("sessions").join("agent-1.json");

        // Corrupt bytes.
        fs::write(&path, b"{not json").unwrap();
        assert!(store.load_checkpoint("agent-1").is_err());

        // Truncated valid JSON.
        let mut raw = serde_json::to_vec(&cp).unwrap();
        raw.truncate(raw.len() / 2);
        fs::write(&path, raw).unwrap();
        assert!(store.load_checkpoint("agent-1").is_err());

        // Unknown future version.
        let mut value = serde_json::to_value(&cp).unwrap();
        value["version"] = serde_json::json!(999u32);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(store.load_checkpoint("agent-1").is_err());

        // Binding file corrupt likewise refuses at open.
        let bpath = dir.path().join("sessions").join("binding.json");
        fs::write(&bpath, b"\x00\x01\x02").unwrap();
        assert!(SessionStore::open(&dir.path().join("sessions"), test_binding()).is_err());
    }

    #[test]
    fn state_files_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let cp = store.load_checkpoint("agent-1").unwrap();
        store.save_checkpoint(&cp).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join("sessions"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
            let fmode = fs::metadata(dir.path().join("sessions").join("agent-1.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(fmode, 0o600);
        }
    }

    #[test]
    fn spool_freeze_is_byte_stable_and_holds_no_run_or_intent() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        let path = store.freeze_spool(&req, "agent-1").unwrap();
        let on_disk = fs::read(&path).unwrap();
        // Retry path returns the identical bytes, not a re-serialization.
        let retry = store.spool_retry_bytes("agent-1").unwrap().unwrap();
        assert_eq!(on_disk, retry);
        assert_eq!(retry, req.retry_bytes().unwrap());
        // Frozen request carries no run/intent surface for the ingress to use.
        let text = String::from_utf8(retry).unwrap();
        assert!(!text.contains("run_key"));
        assert!(!text.contains("intent"));
        assert!(text.contains(REASON_STEP));
    }

    #[test]
    fn freeze_is_idempotent_for_identical_bytes_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let first = freeze_sample(&store, "agent-1", 1, &root, "one");
        let path = store.freeze_spool(&first, "agent-1").unwrap();
        // Byte-identical re-freeze (crash between freeze and send) is
        // idempotent and resolves to the same path.
        let again = store.freeze_spool(&first, "agent-1").unwrap();
        assert_eq!(again, path);
        // Different bytes for the same position are refused, not rekeyed.
        let other = freeze_sample(&store, "agent-1", 1, &root, "changed");
        assert!(store.freeze_spool(&other, "agent-1").is_err());
        // The surviving entry is still the original.
        let loaded = store.load_spool("agent-1").unwrap().unwrap();
        assert_eq!(loaded.retry_bytes().unwrap(), first.retry_bytes().unwrap());
    }

    #[test]
    fn spool_one_in_flight_and_never_rekeyed() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let first = freeze_sample(&store, "agent-1", 1, &root, "one");
        store.freeze_spool(&first, "agent-1").unwrap();
        // A second position while one is in flight is refused.
        let fp2 = sample_fp("two");
        let second = FrozenStepRequest::freeze(
            store.binding(),
            "agent-1",
            "folder-1",
            "step",
            "two",
            "agent",
            0,
            None,
            &root,
            &fp2,
            2,
            "2026-10-17T00:00:00Z",
        )
        .unwrap();
        assert!(store.freeze_spool(&second, "agent-1").is_err());
        // The surviving entry still resolves to position 1 with its bytes.
        let loaded = store.load_spool("agent-1").unwrap().unwrap();
        assert_eq!(loaded.pos, 1);
        assert_eq!(loaded.retry_bytes().unwrap(), first.retry_bytes().unwrap());
    }

    #[test]
    fn crash_after_spool_before_send_keeps_head_and_spool() {
        // Crash window: spool frozen, send never happened (process died).
        // Restart must find the head unmoved and the same bytes to send.
        let dir = tempfile::tempdir().unwrap();
        let before: Vec<u8>;
        {
            let store = open_store(dir.path());
            let root = chain_root("srv-a", "agent-1").unwrap();
            let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
            before = req.retry_bytes().unwrap();
            store.freeze_spool(&req, "agent-1").unwrap();
            // No confirm: drop the store without further writes (the crash).
        }
        let store = open_store(dir.path());
        let cp = store.load_checkpoint("agent-1").unwrap();
        assert_eq!(cp.head_pos, None);
        assert!(!cp.needs_realign);
        let retry = store.spool_retry_bytes("agent-1").unwrap().unwrap();
        assert_eq!(retry, before);
    }

    #[test]
    fn crash_after_send_before_receipt_resends_identical_bytes() {
        // Crash window: bytes left the process, receipt never recorded.
        // The outcome is uncertain; restart must resend the identical frozen
        // request under the identical key (Lost/Unclear disposition).
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        let key = req.key.clone();
        store.freeze_spool(&req, "agent-1").unwrap();
        // Simulated uncertain send: decide() keeps the spool for resend.
        assert_eq!(decide(WriteOutcome::Lost), Disposition::ResendSameBytes);
        assert_eq!(decide(WriteOutcome::Unclear), Disposition::ResendSameBytes);
        assert_eq!(decide(WriteOutcome::NotSent), Disposition::KeepSpoolBackoff);
        drop(store);
        let store = open_store(dir.path());
        let again = store.load_spool("agent-1").unwrap().unwrap();
        assert_eq!(again.key, key);
        assert_eq!(again.retry_bytes().unwrap(), req.retry_bytes().unwrap());
    }

    #[test]
    fn foreign_head_requires_durable_flag_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        store.freeze_spool(&req, "agent-1").unwrap();
        let foreign_cid = chain_next(&root, &sample_fp("elsewhere")).unwrap();
        // Adopting without the durable flag is refused (crash between
        // observing the foreign head and refreshing the mapping must
        // restart into alignment, not into a stale append).
        assert!(store
            .adopt_foreign_head("agent-1", 1, &foreign_cid, vec![sample_fp("elsewhere")])
            .is_err());
        assert!(store.quarantine_spool("agent-1").is_err());
        // Durable flag first, then adopt + quarantine.
        store.mark_needs_realign("agent-1").unwrap();
        // While the flag is set the stale spool is invisible to the sender.
        assert!(store.load_spool("agent-1").unwrap().is_none());
        let adopted = store
            .adopt_foreign_head("agent-1", 1, &foreign_cid, vec![sample_fp("elsewhere")])
            .unwrap();
        assert!(adopted.needs_realign);
        assert_eq!(adopted.head_cid.as_deref(), Some(foreign_cid.as_str()));
        let q = store.quarantine_spool("agent-1").unwrap();
        assert!(q.to_string_lossy().contains("quarantined"));
        // No in-flight entry remains; restart still requires alignment.
        assert!(store.load_spool("agent-1").unwrap().is_none());
        let cp = store.load_checkpoint("agent-1").unwrap();
        assert!(cp.needs_realign);
    }

    #[test]
    fn confirm_advances_head_and_reconfirm_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let body = "hello";
        let fp = sample_fp(body);
        let req = freeze_sample(&store, "agent-1", 1, &root, body);
        let cid = req.facets.cid.clone();
        store.freeze_spool(&req, "agent-1").unwrap();
        let cp = store
            .confirm_spooled("agent-1", 1, &cid, &fp, "epoch-1", 41)
            .unwrap();
        assert_eq!(cp.head_pos, Some(1));
        assert_eq!(cp.head_cid.as_deref(), Some(cid.as_str()));
        assert_eq!(cp.source_fps, vec![fp.clone()]);
        assert!(store.load_spool("agent-1").unwrap().is_none());
        // A replayed receipt after a crash between the checkpoint save and
        // the spool unlink is idempotent: same checkpoint, no `E` re-append.
        let cp2 = store
            .confirm_spooled("agent-1", 1, &cid, &fp, "epoch-1", 41)
            .unwrap();
        assert_eq!(cp2, cp);
        assert_eq!(cp2.source_fps.len(), 1);
        // A mismatched triple against an advanced head refuses.
        assert!(store
            .confirm_spooled("agent-1", 1, &cid, &sample_fp("other body"), "epoch-1", 41)
            .is_err());
    }

    #[test]
    fn confirm_rejects_skips_regression_and_wrong_parent() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        // Headless: only position 1 with the true chain root parent.
        let fp_wrong_parent = sample_fp("zero");
        let bad_parent = sample_fp("not-the-root");
        let bad = FrozenStepRequest::freeze(
            store.binding(),
            "agent-1",
            "folder-1",
            "step",
            "zero",
            "agent",
            0,
            None,
            &bad_parent,
            &fp_wrong_parent,
            1,
            "2026-10-17T00:00:00Z",
        )
        .unwrap();
        store.freeze_spool(&bad, "agent-1").unwrap();
        assert!(store
            .confirm_spooled(
                "agent-1",
                1,
                &bad.facets.cid,
                &fp_wrong_parent,
                "epoch-1",
                1
            )
            .is_err());
        // Quarantine the bad spool out of the way via the flag path, then
        // confirm the real first step.
        store.mark_needs_realign("agent-1").unwrap();
        store.quarantine_spool("agent-1").unwrap();
        store
            .clear_realign("agent-1", Vec::new(), "epoch-1", 0)
            .unwrap();
        let fp1 = sample_fp("one");
        let first = freeze_sample(&store, "agent-1", 1, &root, "one");
        let cid1 = first.facets.cid.clone();
        store.freeze_spool(&first, "agent-1").unwrap();
        store
            .confirm_spooled("agent-1", 1, &cid1, &fp1, "epoch-1", 10)
            .unwrap();
        // Skipping to position 3 is refused even with a well-formed spool.
        let fp3 = sample_fp("three");
        let head = store.load_checkpoint("agent-1").unwrap();
        let skipped = FrozenStepRequest::freeze(
            store.binding(),
            "agent-1",
            "folder-1",
            "step",
            "three",
            "agent",
            0,
            None,
            head.head_cid.as_deref().unwrap(),
            &fp3,
            3,
            "2026-10-17T00:00:00Z",
        )
        .unwrap();
        store.freeze_spool(&skipped, "agent-1").unwrap();
        assert!(store
            .confirm_spooled("agent-1", 3, &skipped.facets.cid, &fp3, "epoch-1", 30)
            .is_err());
        // Head is still at 1 with a single `E` entry: nothing branched.
        let head = store.load_checkpoint("agent-1").unwrap();
        assert_eq!(head.head_pos, Some(1));
        assert_eq!(head.source_fps.len(), 1);
    }

    #[test]
    fn injected_crash_between_checkpoint_and_unlink_reconfirms_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let fp = sample_fp("hello");
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        let cid = req.facets.cid.clone();
        store.freeze_spool(&req, "agent-1").unwrap();
        {
            use std::sync::atomic::Ordering::SeqCst;
            store.fail_before_spool_unlink.store(true, SeqCst);
        }
        // The checkpoint lands, the spool unlink never runs: caller sees
        // failure, head is advanced, spool survives.
        assert!(store
            .confirm_spooled("agent-1", 1, &cid, &fp, "epoch-1", 41)
            .is_err());
        let mid = store.load_checkpoint("agent-1").unwrap();
        assert_eq!(mid.head_pos, Some(1));
        // Re-confirming the same triple is idempotent: no `E` re-append,
        // stale spool file cleaned up.
        let cp = store
            .confirm_spooled("agent-1", 1, &cid, &fp, "epoch-1", 41)
            .unwrap();
        assert_eq!(cp.source_fps, vec![fp.clone()]);
        assert!(store.load_spool("agent-1").unwrap().is_none());
    }

    #[test]
    fn clear_realign_refuses_surviving_stale_spool() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        store.freeze_spool(&req, "agent-1").unwrap();
        store.mark_needs_realign("agent-1").unwrap();
        // Clearing the flag with the stale spool still on disk would
        // reactivate it: refused until quarantined.
        assert!(store
            .clear_realign("agent-1", Vec::new(), "epoch-2", 0)
            .is_err());
        store.quarantine_spool("agent-1").unwrap();
        let cp = store
            .clear_realign("agent-1", Vec::new(), "epoch-2", 0)
            .unwrap();
        assert!(!cp.needs_realign);
        assert!(store.load_spool("agent-1").unwrap().is_none());
    }

    #[test]
    fn alignment_generation_exhaustion_keeps_durable_realign_fence() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let mut cp = store.mark_needs_realign("agent-1").unwrap();
        cp.alignment_gen = u64::MAX;
        cp.needs_realign = false;
        cp.cursor_epoch = Some("old".into());
        cp.cursor_seq_end = Some(7);
        store.save_checkpoint(&cp).unwrap();
        let fenced = store.mark_needs_realign("agent-1").unwrap();
        assert!(fenced.needs_realign);
        assert_eq!(fenced.alignment_gen, u64::MAX);
        assert!(store
            .clear_realign("agent-1", Vec::new(), "new", 19)
            .is_err());
        let cp = open_store(dir.path()).load_checkpoint("agent-1").unwrap();
        assert!(cp.needs_realign);
        assert_eq!(cp.alignment_gen, u64::MAX);
        assert_eq!(cp.cursor_epoch.as_deref(), Some("old"));
        assert_eq!(cp.cursor_seq_end, Some(7));
    }

    #[test]
    fn injected_failure_after_file_sync_leaves_state_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let cp = store.load_checkpoint("agent-1").unwrap();
        store.save_checkpoint(&cp).unwrap();
        {
            use std::sync::atomic::Ordering::SeqCst;
            store.fail_after_file_sync.store(true, SeqCst);
        }
        let mut next = cp.clone();
        next.alignment_gen += 1;
        assert!(store.save_checkpoint(&next).is_err());
        // Prior state intact, staged tmp swept (no `.tmp` debris parses).
        let reloaded = store.load_checkpoint("agent-1").unwrap();
        assert_eq!(reloaded.alignment_gen, cp.alignment_gen);
        let has_tmp = fs::read_dir(dir.path().join("sessions"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .any(|n| n.contains(".tmp"));
        assert!(!has_tmp);
    }

    #[test]
    fn injected_failure_after_rename_reports_but_lands() {
        // Honest window documentation: after the rename the new bytes are in
        // place but the directory entry may not survive power loss, so the
        // caller sees failure and must re-read rather than assume either
        // outcome.
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let cp = store.load_checkpoint("agent-1").unwrap();
        {
            use std::sync::atomic::Ordering::SeqCst;
            store.fail_after_rename.store(true, SeqCst);
        }
        let mut next = cp.clone();
        next.alignment_gen += 1;
        assert!(store.save_checkpoint(&next).is_err());
        let reloaded = store.load_checkpoint("agent-1").unwrap();
        assert_eq!(reloaded.alignment_gen, cp.alignment_gen + 1);
    }

    #[test]
    fn wire_bytes_are_stable_shaped_and_run_free() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        store.freeze_spool(&req, "agent-1").unwrap();
        let before = req.wire_bytes().unwrap();
        // Exact hosted shape: type/kind/home/name/body/facets/reason/key.
        let wire = req.wire_request();
        let obj = wire.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "body",
                "facets",
                "home_id",
                "idempotency_key",
                "kind",
                "name",
                "reason",
                "type"
            ]
        );
        let facets = wire.pointer("/facets").unwrap().as_object().unwrap();
        let mut fkeys: Vec<&str> = facets.keys().map(String::as_str).collect();
        fkeys.sort_unstable();
        assert_eq!(
            fkeys,
            vec![
                "native.session.cid",
                "native.session.fp",
                "native.session.occurred_at",
                "native.session.parent_cid",
                "native.session.part_index",
                "native.session.pos",
                "native.session.step_kind"
            ]
        );
        assert_eq!(
            wire.pointer("/reason").unwrap(),
            &serde_json::json!(REASON_STEP)
        );
        assert_eq!(
            wire.pointer("/idempotency_key").unwrap(),
            &serde_json::json!(req.key)
        );
        // No run/intent surface anywhere in the wire bytes.
        let text = String::from_utf8(before.clone()).unwrap();
        assert!(!text.contains("run_key"));
        assert!(!text.contains("intent"));
        // Stable across a disk round-trip.
        let reloaded = store.load_spool("agent-1").unwrap().unwrap();
        assert_eq!(reloaded.wire_bytes().unwrap(), before);
    }

    #[test]
    fn outcome_table_preserves_pending_and_stops_honestly() {
        use Disposition as D;
        use WriteOutcome as O;
        assert_eq!(decide(O::Success), D::AdvanceHead);
        // Conflicts never auto-adopt in the pure layer: S3b must run the
        // verified read + immutable-content comparison first.
        assert_eq!(decide(O::Conflict), D::AwaitVerifiedAdoption);
        assert_eq!(decide(O::NotSent), D::KeepSpoolBackoff);
        assert_eq!(decide(O::Lost), D::ResendSameBytes);
        assert_eq!(decide(O::Unclear), D::ResendSameBytes);
        assert_eq!(decide(O::AuthRefused), D::StopAuth);
        assert_eq!(decide(O::KeyRefused), D::StopUnsupported);
        assert_eq!(decide(O::ValidationRefused), D::Quarantine);
    }

    #[test]
    fn pending_bound_pauses_without_dropping() {
        assert!(!should_pause_curation(0, DEFAULT_PENDING_LIMIT_BYTES));
        assert!(should_pause_curation(
            DEFAULT_PENDING_LIMIT_BYTES,
            DEFAULT_PENDING_LIMIT_BYTES
        ));
        assert!(pending_paused(u64::MAX, 0, DEFAULT_PENDING_LIMIT_BYTES));
        // Pausing drops nothing: spool survives the pause decision.
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let req = freeze_sample(&store, "agent-1", 1, &root, "hello");
        store.freeze_spool(&req, "agent-1").unwrap();
        assert!(pending_paused(
            64 * 1024 * 1024,
            1,
            DEFAULT_PENDING_LIMIT_BYTES
        ));
        assert!(store.load_spool("agent-1").unwrap().is_some());
    }

    #[test]
    fn chain_roots_bind_server_and_agent_and_chain_orders() {
        let a = chain_root("srv-a", "agent-1").unwrap();
        assert_ne!(a, chain_root("srv-b", "agent-1").unwrap());
        assert_ne!(a, chain_root("srv-a", "agent-2").unwrap());
        let fp1 = sample_fp("one");
        let fp2 = sample_fp("two");
        let c1 = chain_next(&a, &fp1).unwrap();
        let c2 = chain_next(&c1, &fp2).unwrap();
        // Order matters: swapping parent/fp must not collide.
        let swapped = chain_next(&a, &fp2).unwrap();
        assert_ne!(c1, swapped);
        let _ = (c2, swapped);
        // Malformed inputs refused, not hashed.
        assert!(chain_next("zz", &fp1).is_err());
        assert!(chain_next(&a, "short").is_err());
        // Keys scope exactly.
        assert_eq!(
            position_key("srv-a", "agent-1", 7).unwrap(),
            "nss3:srv-a:agent-1:p7"
        );
        assert!(position_key("", "agent-1", 1).is_err());
        assert!(position_key("srv:a", "agent-1", 1).is_err());
    }

    #[test]
    fn injected_store_failure_leaves_prior_checkpoint_intact() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let cp = store.load_checkpoint("agent-1").unwrap();
        store.save_checkpoint(&cp).unwrap();
        // Fail the next durable write: the caller must see the error and the
        // prior checkpoint must still load (no torn state).
        {
            use std::sync::atomic::Ordering::SeqCst;
            store.fail_after.store(0, SeqCst);
        }
        let mut next = cp.clone();
        next.alignment_gen += 1;
        assert!(store.save_checkpoint(&next).is_err());
        let reloaded = store.load_checkpoint("agent-1").unwrap();
        assert_eq!(reloaded.alignment_gen, cp.alignment_gen);
        // Tmp debris never parses as state and is swept on next list/load.
        let spool_dir = dir.path().join("sessions").join("agent-1.spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(spool_dir.join(".p9.json.abc.tmp"), b"junk").unwrap();
        assert!(store.load_spool("agent-1").unwrap().is_none());
    }

    #[test]
    fn marker_base_len_validated_against_e() {
        assert!(check_marker_base_len(0, 0).is_ok());
        assert!(check_marker_base_len(3, 5).is_ok());
        assert!(check_marker_base_len(6, 5).is_err());
    }

    #[test]
    fn marker_confirmation_truncates_source_and_survives_checkpoint_unlink_crash() {
        use session_projection::{fingerprint_step, StepKind};
        for kind in [StepKind::Rewound, StepKind::Resync] {
            let dir = tempfile::tempdir().unwrap();
            let store = open_store(dir.path());
            let mut parent = chain_root("srv-a", "agent-1").unwrap();
            for (index, body) in ["A", "B", "C"].into_iter().enumerate() {
                let pos = index as u64 + 1;
                let request = freeze_sample(&store, "agent-1", pos, &parent, body);
                store.freeze_spool(&request, "agent-1").unwrap();
                store
                    .confirm_spooled(
                        "agent-1",
                        pos,
                        &request.facets.cid,
                        &request.facets.fp,
                        "before",
                        pos,
                    )
                    .unwrap();
                parent = request.facets.cid;
            }
            let body = "History changed after source step 1";
            let fp = fingerprint_step(kind, 0, body);
            let request = FrozenStepRequest::freeze(
                store.binding(),
                "agent-1",
                "folder-1",
                "marker",
                body,
                kind.as_str(),
                0,
                Some(1),
                &parent,
                &fp,
                4,
                "2026-10-17T00:00:00Z",
            )
            .unwrap();
            store.freeze_spool(&request, "agent-1").unwrap();
            store
                .fail_before_spool_unlink
                .store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(store
                .confirm_spooled("agent-1", 4, &request.facets.cid, &fp, "after", 1)
                .is_err());
            // A process restart sees the new head plus the old spool. E has
            // already been truncated, with no marker fingerprint appended.
            let store = open_store(dir.path());
            let checkpoint = store.load_checkpoint("agent-1").unwrap();
            assert_eq!(checkpoint.source_fps, vec![sample_fp("A")]);
            assert_eq!(checkpoint.head_pos, Some(4));
            let confirmed = store
                .confirm_spooled("agent-1", 4, &request.facets.cid, &fp, "after", 1)
                .unwrap();
            assert_eq!(confirmed, checkpoint);
            assert!(store.load_spool("agent-1").unwrap().is_none());
            // Position follows the admitted history, not the shorter source E.
            let next = freeze_sample(&store, "agent-1", 5, &request.facets.cid, "D");
            store.freeze_spool(&next, "agent-1").unwrap();
            let checkpoint = store
                .confirm_spooled("agent-1", 5, &next.facets.cid, &next.facets.fp, "after", 2)
                .unwrap();
            assert_eq!(checkpoint.source_fps, vec![sample_fp("A"), sample_fp("D")]);
        }
    }

    #[test]
    fn malformed_frozen_content_is_refused_on_freeze_and_both_reload_paths() {
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let request = freeze_sample(&store, "agent-1", 1, &root, "hello");
        let mut variants = Vec::new();
        let mut bad = request.clone();
        bad.body = "changed".into();
        variants.push(bad);
        let mut bad = request.clone();
        bad.rtype = "Message".into();
        variants.push(bad);
        let mut bad = request.clone();
        bad.facets.pos = 2;
        variants.push(bad);
        let mut bad = request.clone();
        bad.facets.cid = root;
        variants.push(bad);
        let mut bad = request.clone();
        bad.facets.base_len = Some(0);
        variants.push(bad);
        let mut bad = request.clone();
        bad.facets.step_kind = "rewound".into();
        variants.push(bad);
        let mut bad = request.clone();
        bad.facets.occurred_at = "not a time".into();
        variants.push(bad);
        let path = store.freeze_spool(&request, "agent-1").unwrap();
        for bad in variants {
            assert!(store.freeze_spool(&bad, "agent-1").is_err());
            // Valid JSON with plausible metadata must still fail closed.
            fs::write(&path, bad.retry_bytes().unwrap()).unwrap();
            assert!(store.load_spool("agent-1").is_err());
            assert!(store.spool_retry_bytes("agent-1").is_err());
        }
    }

    #[test]
    fn fingerprint_reuses_merged_s2_encoding() {
        // S3a must not re-derive the content encoding: the fingerprint stored
        // in the spool equals the S2 curator output for the same bytes.
        let dir = tempfile::tempdir().unwrap();
        let store = open_store(dir.path());
        let root = chain_root("srv-a", "agent-1").unwrap();
        let body = "  hello\r\nworld  ";
        let expected =
            session_projection::fingerprint_step(session_projection::StepKind::Agent, 0, body);
        let req = freeze_sample(&store, "agent-1", 1, &root, body);
        assert_eq!(req.facets.fp, expected);
    }
}
