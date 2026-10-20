//! Saved-session step curator: pure `nss-projection.v1` projection over fetched
//! daemon PROJECTED pages (S2).
//!
//! The daemon owns chunk merging and tool-lifecycle collapse
//! (`timeline-projection.ts`); this module owns the Slack-faithful curation
//! (`activity-curator.ts`) plus the S2 step layer from reconciled design
//! `f38936b` §§5.2–5.4: step boundaries, finalization, size bounds,
//! paragraph-safe splitting and content fingerprints.
//!
//! ## Input contract (settled)
//!
//! The saver treats `agent_stream` as WAKEUP ONLY and fetches projected
//! pages as DATA. This module never consumes raw live stream items:
//!
//! - [`classify_wakeup`] reads a verbatim `agent_stream` envelope and
//!   reports [`Wakeup::TimelineActivity`] (refetch), [`Wakeup::TurnEnded`]
//!   (refetch, then [`Curator::end_turn`]) or [`Wakeup::Other`] (ignore).
//! - [`parse_fetch_page`] reads a verbatim `fetch_agent_timeline_response`
//!   payload into its `epoch` plus [`ProjectedEntry`] rows
//!   (`AgentTimelineEntryPayloadSchema` in
//!   `packages/protocol/src/messages.ts`: `{item, turnId?, timestamp,
//!   seqStart, seqEnd, sourceSeqRanges, collapsed}`).
//! - [`Curator::push_page`] merges one fetched page into the canonical
//!   snapshot and emits the newly final steps, in order.
//!
//! Item shapes mirror the real wire union `AgentTimelineItemPayloadSchema`
//! (`user_message`, `assistant_message`, `reasoning`, `tool_call` with the
//! eleven `ToolCallDetail` variants, `todo`, `error`, `notification`,
//! `compaction`, `plugin`). Parsing is tolerant: unknown item/detail types map
//! to `Ignored`/`Unknown` (excluded from output) and unknown fields are
//! dropped, so a newer daemon never breaks the saver. Nothing here invents a
//! wire shape: extra keys such as `provider`, `sourceSeqRanges` and
//! `collapsed` are accepted and ignored.
//!
//! Tool display names and summaries port `tool-call-display.ts` and the
//! curator's `formatToolCallEntry` (`activity-curator.ts:111-133`), including
//! the `Task`/`Thinking`/`Terminal` overrides and the humanize fallback. The
//! one deliberate divergence: Desktop renders a 400-char input-JSON line for
//! likely-external tools; S2 excludes external/MCP tool input JSON by design,
//! so those tools render as a bare `[Name]` (or `[Name] summary` when the
//! display model supplies one).
//!
//! ## Snapshot and upsert
//!
//! The curator keeps the canonical snapshot: entries keyed by `seqStart`
//! (stable across refreshes of one epoch; the daemon extends `seqEnd` and
//! cumulative text in place). A page entry replaces the stored one when its
//! `seqEnd` covers the stored one; a strictly older refresh is dropped, as
//! is an equal-span terminal→running tool regression (stale pages must never
//! clobber completions). Re-pushing an identical page is a no-op. An epoch
//! change clears the snapshot (S3 alignment owns cross-epoch markers and
//! gaps).
//!
//! Entry `turnId`s are parsed and carried but never drive step logic —
//! provider history rows deliberately omit them — turn boundaries enter only
//! through [`Curator::end_turn`], which the saver calls on `turn_completed`,
//! `turn_failed` and `turn_canceled` wakeups.
//!
//! ## Steps and finalization (§5.3)
//!
//! Ordered snapshot entries group into steps: one `user_message` is its own
//! `user` step; one `assistant_message` plus the tool/task/error/compaction
//! lines that follow it (up to the next assistant message, user message or
//! turn end) is one `agent` step; a run of tool lines with no assistant text
//! forms `tools` steps; marker-only runs form `tools` (`todo`), `error` or
//! `compacted` steps. Because pages arrive already merged, assistant entries
//! are always whole: arrival order in the snapshot IS display order, so an
//! `assistant → tool → assistant` page can never reorder into
//! `assistant+assistant → tool`.
//!
//! A step emits only when final, and emission is strictly in order: the
//! drain stops at the first non-final group, so a pending tool line delays
//! the user step behind it rather than letting history be written out of
//! order. A group is closed once a later group starts a new message (user-
//! or agent-led): nothing can ever join it again. Final means:
//!
//! - `user` rows are complete on arrival and emit on sight (in order);
//! - an agent group emits once closed with terminal tools: the later message
//!   proves the assistant text complete;
//! - marker-only groups (`todo`/`error`/`compaction`) emit once closed: the
//!   boundary decides their final grouping and kind, so an early marker
//!   never strands a step whose kind later changes;
//! - tool-led groups emit full bound-sized chunks of their terminal prefix
//!   as soon as the chunks are full (even while the run stays open), and
//!   flush a below-bound terminal remainder once closed. Running lines never
//!   finalize; a `running` tool (or any unknown future status,
//!   conservatively non-terminal) keeps its whole step pending. The wire tool
//!   union carries exactly those four statuses (`completed`, `failed`,
//!   `canceled` plus `running`); anything else maps to the non-terminal
//!   bucket.
//!
//! Chunk boundaries fall every 32 tool-call lines / 16 KiB from the run
//! start, so the same final line sequence always yields the same steps
//! whatever the page splits were: below-bound open content is never emitted
//! early, and closed remainders flush deterministically.
//!
//! [`Curator::end_turn`] force-emits everything still held: a tool that never
//! reported completion finalizes with its last-seen summary rather than
//! blocking later turns forever. Turn end closes the books — a completion
//! arriving afterwards updates the snapshot copy but is never re-emitted, so
//! emitted steps are append-only and never rewritten ("no mutable
//! persistence").
//!
//! ## Size bounds (§5.3)
//!
//! Tool-led runs chunk their lines at 32 tool-call lines or 16 KiB of
//! accumulated body. Chunks emit only when full and terminal, or when their
//! run closes, or at turn end — never speculatively below the bounds while
//! the run stays open. Agent-led and user groups emit atomically (an
//! assistant message stays with the tools that follow it). Any emitted step body over 64 KiB is split at paragraph (`\n\n`)
//! boundaries, greedily packed with the worst-case part label reserved up
//! front (sized from the total's digit count, refined to a fixpoint); a
//! single paragraph over the packing limit (or text with no paragraph
//! boundary) is hard-split at the largest character boundary within the
//! limit, so splitting is always UTF-8 safe and every emitted part, label
//! included, fits 64 KiB. Split parts are labelled `…(i/n)` (1-based
//! display) and carry a stable 0-based `part_index`.
//!
//! ## Included / excluded (§5.3)
//!
//! Included: user text (pass-on quote envelopes are preserved verbatim for
//! later source-link handling in S3; `>` markers are never stripped),
//! assistant text, one-line tool summaries (≤200 bytes), `[Tasks]` checklists
//! (each item line ≤500 bytes), `[Error]` lines (≤500 bytes), `[Compacted]`,
//! and `[image]` / `[attachment: name]` placeholders for prompt image/file
//! blocks when the row carries them (absent from current timeline rows; read
//! only when present, never synthesized).
//!
//! Excluded: `[Thought]` reasoning, external/MCP tool input JSON, sub-agent
//! `log` text, raw tool output and error payloads (`output`/`content`/`error`
//! fields are never read — a failed tool renders its summary exactly like a
//! completed one), the fork-variant working-directory header (never emitted),
//! `notification` and `plugin` items, and empty text.
//!
//! Byte bounds above are bytes of UTF-8, truncated only at character
//! boundaries (Desktop counts UTF-16 units; identical for ASCII, safe for the
//! rest).
//!
//! ## Fingerprint (§5.4)
//!
//! `fp = hex(sha256(input))` with the exact byte encoding
//!
//! ```text
//! input = BE64(len(V)) || V || BE64(len(K)) || K
//!       || BE64(len(P)) || P || BE64(len(B)) || B
//! V = UTF-8("nss-projection.v1")   K = UTF-8(step kind)
//! P = ASCII decimal part_index      B = UTF-8(normalized part body)
//! ```
//!
//! Normalization of `B`: trim Unicode whitespace at both ends, map `\r\n`
//! then lone `\r` to `\n`, Unicode NFC. The fingerprint covers version, kind,
//! part index and normalized body only — never provider ids (`messageId`,
//! `clientMessageId`, `providerMessageId`), timestamps, `turnId`, seq numbers
//! or display labels — so live and rebuilt daemon rows with aliased or absent
//! ids fingerprint identically.
//!
//! ## S3 adapter contract (stable finalized prefix)
//!
//! The saver (S3) subscribes to `agent_stream` for wakeup only: on
//! [`Wakeup::TimelineActivity`] it fetches projected pages and calls
//! [`Curator::push_page`] in fetch order, draining after each call; on
//! [`Wakeup::TurnEnded`] it pushes the latest page, calls
//! [`Curator::end_turn`], then drains. Drained steps are written
//! position-keyed in drain order. Live stream items are never pushed. A
//! `push_page` that switches the epoch reports it through its return value:
//! the caller must drain before switching epochs (the outbox is untouched by
//! the reset, so undrained steps from two epochs would interleave) and must
//! never feed stale-epoch pages afterwards — epochs are opaque and any new
//! epoch reads as a rebuild. Cross-epoch alignment (markers, gaps) belongs
//! to S3.
//!
//! ## Explicitly not this slice
//!
//! Chain ids (`cid_n`), admission keys (`nss3:<server>:<agent>:p<pos>`),
//! source mapping / `rewound` / `resync` markers, spool, lease, alignment,
//! binding checks and server-id fencing are S3. Provider daemon
//! live-vs-rebuild/rewind goldens are S3 acceptance; tests here assert only
//! curator-level determinism over fetched pages and must not be read as
//! provider qualification. The `F4` account/db/host binding plus server-id
//! fencing obligation from S1 review stays open pre-S3. The three new
//! `Document` kinds below are proposed names only — any live vocabulary change
//! goes through the ordinary supported workflow, never as a surprise schema
//! write from this slice.

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Projection version stamped into every fingerprint.
pub const PROJECTION_VERSION: &str = "nss-projection.v1";
/// One-line tool summary bound (§5.3), in UTF-8 bytes.
pub const MAX_TOOL_SUMMARY_CHARS: usize = 200;
/// `[Error]` line bound (§5.3), in UTF-8 bytes.
pub const MAX_ERROR_CHARS: usize = 500;
/// Each `[Tasks]` item line bound (S2 judgment within §5.3), in UTF-8 bytes.
pub const MAX_TASK_LINE_CHARS: usize = 500;
/// Tool-only step flush: at most this many tool-call lines per chunk (§5.3).
pub const TOOL_ONLY_FLUSH_LINES: usize = 32;
/// Tool-only step flush: at most this many accumulated body bytes (§5.3).
pub const TOOL_ONLY_FLUSH_BYTES: usize = 16 * 1024;
/// Step body bound including any split label (§5.3), in UTF-8 bytes.
pub const MAX_STEP_BYTES: usize = 64 * 1024;

/// Proposed `Document` kinds for saved sessions (design §5.2). Names only:
/// S2 performs no vocabulary write; proposing them is an ordinary
/// owner-driven workflow step, not a side effect of this module.
pub const KIND_AGENT_SESSION: &str = "agent-session";
/// Proposed kind for immutable curated step records (design §5.2).
pub const KIND_AGENT_SESSION_STEP: &str = "agent-session-step";
/// Proposed kind for channel share cards (design §7). Outside S2 scope.
pub const KIND_AGENT_SESSION_SHARE: &str = "agent-session-share";

/// Curated step kind (`native.session.step_kind` facet values, design §5.2).
/// `Rewound`/`Resync` markers are S3 alignment output, produced by the
/// persistence layer only — never by the curator's page drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepKind {
    User,
    Agent,
    Tools,
    Error,
    Compacted,
    /// Alignment marker, produced by the persistence layer only.
    Rewound,
    /// Alignment marker, produced by the persistence layer only.
    Resync,
}

impl StepKind {
    /// Facet string for `native.session.step_kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Agent => "agent",
            Self::Tools => "tools",
            Self::Error => "error",
            Self::Compacted => "compacted",
            Self::Rewound => "rewound",
            Self::Resync => "resync",
        }
    }
}

/// Terminality of a tool call, from the real `status` union (`running`,
/// `completed`, `failed`, `canceled`). Unknown future statuses map to the
/// non-terminal bucket so an unrecognized state can never finalize early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolStatus {
    Running,
    Completed,
    Failed,
    Canceled,
}

impl ToolStatus {
    fn terminal(self) -> bool {
        self != Self::Running
    }

    fn from_str(status: Option<&str>) -> Self {
        match status {
            Some("completed") => Self::Completed,
            Some("failed") => Self::Failed,
            Some("canceled") => Self::Canceled,
            _ => Self::Running,
        }
    }
}

/// One checklist item of a real `todo` row (`AgentTaskItem` subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskItem {
    pub text: String,
    pub completed: bool,
}

/// Prompt image/file blocks carried on a user row, using the real
/// `send_agent_message` attachment shapes. Current daemon timeline rows do
/// not carry these; they are read only when present and never synthesized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentRef {
    Image,
    NamedFile(String),
}

/// Tool detail variants mirroring `ToolCallDetailPayloadSchema` field names.
/// Only the summary-bearing fields are kept; `output`/`content` (raw tool
/// output) are never read, and `unknown.input` (external/MCP input JSON) is
/// deliberately dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolDetail {
    Shell {
        command: String,
    },
    Read {
        file_path: String,
    },
    Edit {
        file_path: String,
    },
    Write {
        file_path: String,
    },
    Search {
        query: String,
    },
    Fetch {
        url: String,
    },
    WorktreeSetup {
        branch_name: String,
    },
    SubAgent {
        kind: Option<String>,
        description: Option<String>,
    },
    PlainText {
        label: Option<String>,
    },
    Plan,
    Unknown,
}

impl ToolDetail {
    fn from_value(detail_type: &str, detail: &Value) -> Self {
        let string_field = |name: &str| {
            detail
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let optional_field = |name: &str| {
            let value = detail.get(name)?.as_str()?;
            if value.is_empty() {
                None
            } else {
                Some(value.to_owned())
            }
        };
        match detail_type {
            "shell" => Self::Shell {
                command: string_field("command"),
            },
            "read" => Self::Read {
                file_path: string_field("filePath"),
            },
            "edit" => Self::Edit {
                file_path: string_field("filePath"),
            },
            "write" => Self::Write {
                file_path: string_field("filePath"),
            },
            "search" => Self::Search {
                query: string_field("query"),
            },
            "fetch" => Self::Fetch {
                url: string_field("url"),
            },
            "worktree_setup" => Self::WorktreeSetup {
                branch_name: string_field("branchName"),
            },
            "sub_agent" => Self::SubAgent {
                kind: optional_field("subAgentType"),
                description: optional_field("description"),
            },
            "plain_text" => Self::PlainText {
                label: optional_field("label"),
            },
            "plan" => Self::Plan,
            _ => Self::Unknown,
        }
    }
}

/// One projected timeline item, mirroring `AgentTimelineItemPayloadSchema`.
/// Provider identity fields (`messageId`, `clientMessageId`) are retained for
/// documentation but never enter curated text or fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineItem {
    UserMessage {
        text: String,
        message_id: Option<String>,
        client_message_id: Option<String>,
        attachments: Vec<AttachmentRef>,
    },
    AssistantMessage {
        text: String,
        message_id: Option<String>,
    },
    Reasoning {
        text: String,
    },
    ToolCall {
        call_id: String,
        name: String,
        status: ToolStatus,
        detail: ToolDetail,
        metadata: HashMap<String, String>,
    },
    Todo {
        items: Vec<TaskItem>,
    },
    Error {
        message: String,
    },
    Notification {
        level: String,
        message: String,
    },
    Compaction {
        status: String,
    },
    Plugin {
        id: String,
        plugin_id: String,
        kind: String,
    },
    /// Unknown future item types and unparseable rows. Always excluded.
    Ignored,
}

fn optional_id(value: &Value, field: &str) -> Option<String> {
    let id = value.get(field)?.as_str()?;
    if id.is_empty() {
        None
    } else {
        Some(id.to_owned())
    }
}

fn parse_attachments(item: &Value) -> Vec<AttachmentRef> {
    let Some(attachments) = item.get("attachments").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for attachment in attachments {
        let Some(kind) = attachment.get("type").and_then(Value::as_str) else {
            continue;
        };
        if kind == "image" {
            out.push(AttachmentRef::Image);
            continue;
        }
        // Real file-ish shapes: `uploaded_file.fileName`, plus tolerant
        // `title`/`fileName`/`name` fallbacks for forward compatibility.
        let name = ["fileName", "title", "name"]
            .iter()
            .filter_map(|field| attachment.get(field)?.as_str())
            .find(|name| !name.trim().is_empty())
            .map(|name| name.trim().to_owned());
        if let Some(name) = name {
            out.push(AttachmentRef::NamedFile(name));
        }
    }
    out
}

impl TimelineItem {
    /// Lenient parser over one `AgentTimelineItemPayloadSchema` value.
    /// Unknown `type` values yield `Ignored` (excluded downstream).
    pub fn from_value(item: &Value) -> Self {
        let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
        let text_field = |name: &str| {
            item.get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        match item_type {
            "user_message" => Self::UserMessage {
                text: text_field("text"),
                message_id: optional_id(item, "messageId"),
                client_message_id: optional_id(item, "clientMessageId"),
                attachments: parse_attachments(item),
            },
            "assistant_message" => Self::AssistantMessage {
                text: text_field("text"),
                message_id: optional_id(item, "messageId"),
            },
            "reasoning" => Self::Reasoning {
                text: text_field("text"),
            },
            "tool_call" => {
                let detail_value = item.get("detail").unwrap_or(&Value::Null);
                let detail_type = detail_value
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let mut metadata = HashMap::new();
                if let Some(map) = item.get("metadata").and_then(Value::as_object) {
                    for (key, value) in map {
                        if let Some(text) = value.as_str() {
                            metadata.insert(key.clone(), text.to_owned());
                        }
                    }
                }
                Self::ToolCall {
                    call_id: text_field("callId"),
                    name: text_field("name"),
                    status: ToolStatus::from_str(item.get("status").and_then(Value::as_str)),
                    detail: ToolDetail::from_value(detail_type, detail_value),
                    metadata,
                }
            }
            "todo" => Self::Todo {
                items: item
                    .get("items")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(|entry| TaskItem {
                                text: entry
                                    .get("text")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                completed: entry
                                    .get("completed")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            "error" => Self::Error {
                message: text_field("message"),
            },
            "notification" => Self::Notification {
                level: text_field("level"),
                message: text_field("message"),
            },
            "compaction" => Self::Compaction {
                status: text_field("status"),
            },
            "plugin" => Self::Plugin {
                id: text_field("id"),
                plugin_id: text_field("pluginId"),
                kind: text_field("kind"),
            },
            _ => Self::Ignored,
        }
    }
}

/// One daemon PROJECTED row: an `AgentTimelineEntryPayloadSchema` entry.
/// Extra wire keys (`provider`, `sourceSeqRanges`, `collapsed`,
/// `providerMessageId`, …) are accepted and ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedEntry {
    pub item: TimelineItem,
    pub turn_id: Option<String>,
    pub timestamp: String,
    pub seq_start: u64,
    pub seq_end: u64,
}

impl ProjectedEntry {
    /// Policy-only preflight, without rendering ahead of the source budget.
    /// These rows need no hosted output and can retire a reserved slot.
    pub fn omitted_by_policy(&self) -> bool {
        match &self.item {
            TimelineItem::Ignored
            | TimelineItem::Reasoning { .. }
            | TimelineItem::Notification { .. }
            | TimelineItem::Plugin { .. } => true,
            TimelineItem::UserMessage {
                text, attachments, ..
            } => text.trim().is_empty() && attachments.is_empty(),
            TimelineItem::AssistantMessage { text, .. } => text.trim().is_empty(),
            TimelineItem::Error { message } => message.trim().is_empty(),
            TimelineItem::ToolCall { .. }
            | TimelineItem::Todo { .. }
            | TimelineItem::Compaction { .. } => false,
        }
    }

    /// Lenient parser over one projected entry value. `prev_seq_end` feeds
    /// the tolerant default when sequence keys are absent.
    pub fn from_value(entry: &Value, prev_seq_end: u64) -> Self {
        let seq_end = entry
            .get("seqEnd")
            .and_then(Value::as_u64)
            .unwrap_or(prev_seq_end + 1);
        let seq_start = entry
            .get("seqStart")
            .and_then(Value::as_u64)
            .unwrap_or(seq_end);
        Self {
            item: entry
                .get("item")
                .map(TimelineItem::from_value)
                .unwrap_or(TimelineItem::Ignored),
            turn_id: optional_id(entry, "turnId"),
            timestamp: entry
                .get("timestamp")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            seq_start,
            seq_end,
        }
    }
}

/// Parse a `fetch_agent_timeline_response` payload `entries` array verbatim.
pub fn parse_projected_entries(entries: &Value) -> Vec<ProjectedEntry> {
    let mut out = Vec::new();
    let mut prev_seq_end = 0;
    for entry in entries.as_array().cloned().unwrap_or_default() {
        let parsed = ProjectedEntry::from_value(&entry, prev_seq_end);
        prev_seq_end = parsed.seq_end.max(prev_seq_end);
        out.push(parsed);
    }
    out
}

/// Parse a verbatim `fetch_agent_timeline_response` payload into its epoch
/// plus projected entries. A missing epoch parses as empty (stable default,
/// never mixed: any present epoch replaces it on first push).
pub fn parse_fetch_page(payload: &Value) -> (String, Vec<ProjectedEntry>) {
    let epoch = payload
        .get("epoch")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let entries = parse_projected_entries(payload.get("entries").unwrap_or(&Value::Null));
    (epoch, entries)
}

/// What a verbatim `agent_stream` envelope asks the saver to do. The stream
/// is wakeup only: timeline events mean "refetch the projected pages", turn
/// terminations additionally close the turn. Nothing else in the stream
/// reaches the curator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wakeup {
    /// A `timeline` event arrived: refetch projected pages.
    TimelineActivity,
    /// `turn_completed`, `turn_failed` or `turn_canceled`: refetch, then
    /// [`Curator::end_turn`].
    TurnEnded,
    /// Anything else (permissions, mode changes, non-stream messages):
    /// no saver action.
    Other,
}

/// Classify a verbatim daemon message (normally an `agent_stream` envelope)
/// into saver wakeup semantics. Unknown shapes report [`Wakeup::Other`].
pub fn classify_wakeup(message: &Value) -> Wakeup {
    if message.get("type").and_then(Value::as_str) != Some("agent_stream") {
        return Wakeup::Other;
    }
    match message
        .pointer("/payload/event/type")
        .and_then(Value::as_str)
    {
        Some("timeline") => Wakeup::TimelineActivity,
        Some("turn_completed") | Some("turn_failed") | Some("turn_canceled") => Wakeup::TurnEnded,
        _ => Wakeup::Other,
    }
}

/// One finalized curated step: ready for an S3 position-keyed create.
/// `seq_start`/`seq_end` name the source span for S3 ordering diagnostics;
/// they never enter the fingerprint (live and rebuilt rows carry different
/// seqs by construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedStep {
    pub kind: StepKind,
    pub body: String,
    pub part_index: u32,
    pub fingerprint: String,
    pub seq_start: u64,
    pub seq_end: u64,
}

/// Body-free metadata retained only after validating a real curated step.
/// There is no wire deserializer or constructor from a claimed fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceStepMeta {
    pub(super) fingerprint: String,
    pub(super) kind: StepKind,
    pub(super) seq_start: u64,
    pub(super) seq_end: u64,
}

impl SourceStepMeta {
    pub fn from_step(step: &ProjectedStep) -> crate::error::Result<Self> {
        if step.seq_start > step.seq_end
            || matches!(step.kind, StepKind::Rewound | StepKind::Resync)
            || step.fingerprint != fingerprint_step(step.kind, step.part_index, &step.body)
        {
            return Err(crate::error::Error::engine("invalid curated source step"));
        }
        Ok(Self {
            fingerprint: step.fingerprint.clone(),
            kind: step.kind,
            seq_start: step.seq_start,
            seq_end: step.seq_end,
        })
    }
}

/// Ephemeral source provenance for bounded curation. Wide projected spans
/// can contain gaps: only actual row anchors count, never seqEnd - seqStart.
/// Every split part carries the whole group's anchors until all parts settle.
#[derive(Debug, Clone)]
pub struct FinalizedStep {
    pub step: ProjectedStep,
    pub source_entries: Vec<u64>,
    pub part_count: u32,
}

/// Normalize a step body for fingerprinting: trim, `\r\n`/`\r` → `\n`,
/// Unicode NFC.
pub fn normalize_body(body: &str) -> String {
    let newline_folded = body.replace("\r\n", "\n").replace('\r', "\n");
    newline_folded.trim().nfc().collect()
}

/// Fingerprint one step part: `hex(sha256(BE64‖V …))` per the module docs.
/// Provider ids and timestamps are not inputs by construction.
pub fn fingerprint_step(kind: StepKind, part_index: u32, body: &str) -> String {
    let normalized = normalize_body(body);
    let mut hasher = Sha256::new();
    for field in [
        PROJECTION_VERSION.as_bytes(),
        kind.as_str().as_bytes(),
        part_index.to_string().as_bytes(),
        normalized.as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hex::encode(hasher.finalize())
}

/// Collapse ASCII and Unicode whitespace runs to single spaces and trim.
fn single_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Truncate to at most `max` UTF-8 bytes, ending with `...` when cut.
/// Always splits at a character boundary.
fn truncate_bounded(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max.saturating_sub(3).min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn humanize_tool_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    // Namespaced/compound names are shown verbatim (matches the Desktop test
    // expectation for `paseo__create_agent`).
    if trimmed.contains([':', '.', '/']) || trimmed.contains("__") {
        return trimmed.to_owned();
    }
    let joined = trimmed
        .split(['.', '_', '-'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut chars = joined.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Display name and optional summary for one tool call, ported from
/// `tool-call-display.ts` + `formatToolCallEntry`. Never includes input JSON,
/// raw output, or sub-agent logs (S2 exclusions).
fn tool_display(
    name: &str,
    detail: &ToolDetail,
    metadata: &HashMap<String, String>,
) -> (String, Option<String>) {
    let lower_name = name.trim().to_lowercase();
    // Canonical per-detail display.
    let (canonical_name, canonical_summary): (Option<&str>, Option<String>) = match detail {
        ToolDetail::Shell { command } => (Some("Shell"), Some(command.clone())),
        ToolDetail::Read { file_path } => (Some("Read"), Some(file_path.clone())),
        ToolDetail::Edit { file_path } => (Some("Edit"), Some(file_path.clone())),
        ToolDetail::Write { file_path } => (Some("Write"), Some(file_path.clone())),
        ToolDetail::Search { query } => (Some("Search"), Some(query.clone())),
        ToolDetail::Fetch { url } => (Some("Fetch"), Some(url.clone())),
        ToolDetail::WorktreeSetup { branch_name } => {
            (Some("Worktree setup"), Some(branch_name.clone()))
        }
        ToolDetail::SubAgent { kind, description } => {
            (Some("Task"), description.clone().or_else(|| kind.clone()))
        }
        ToolDetail::PlainText { label } => (None, label.clone()),
        ToolDetail::Plan => (Some("Plan"), None),
        ToolDetail::Unknown => (None, None),
    };
    // Sub-agent display name prefers its own type label.
    let canonical_name = match detail {
        ToolDetail::SubAgent { kind, .. } => kind.as_deref().or(Some("Task")),
        _ => canonical_name,
    };
    // Unknown-detail overrides for well-known pseudo-tools.
    let (display_name, summary) = if matches!(detail, ToolDetail::Unknown) && lower_name == "task" {
        ("Task".to_owned(), metadata.get("subAgentActivity").cloned())
    } else if matches!(detail, ToolDetail::Unknown) && lower_name == "thinking" {
        ("Thinking".to_owned(), None)
    } else if lower_name == "terminal" {
        let summary = match detail {
            ToolDetail::PlainText { label } => label.clone(),
            _ => canonical_summary.clone(),
        };
        ("Terminal".to_owned(), summary)
    } else {
        (
            canonical_name
                .map(str::to_owned)
                .unwrap_or_else(|| humanize_tool_name(name)),
            canonical_summary,
        )
    };
    // Sub-agent entries keep their own type as the display name when set.
    let display_name = match detail {
        ToolDetail::SubAgent {
            kind: Some(kind), ..
        } if !kind.trim().is_empty() => kind.trim().to_owned(),
        _ => display_name,
    };
    (display_name, summary)
}

/// Render one tool-call line: `[Name] summary`, summary single-lined and
/// bounded. The line is never empty (`[Name]` at minimum).
fn format_tool_line(name: &str, detail: &ToolDetail, metadata: &HashMap<String, String>) -> String {
    let (display_name, summary) = tool_display(name, detail, metadata);
    match summary {
        Some(summary) => {
            let single = single_line(&summary);
            if single.is_empty() {
                format!("[{display_name}]")
            } else {
                format!(
                    "[{display_name}] {}",
                    truncate_bounded(&single, MAX_TOOL_SUMMARY_CHARS)
                )
            }
        }
        None => format!("[{display_name}]"),
    }
}

/// One curated line with its source span and mutability. Only non-terminal
/// tool lines are mutable; everything else is complete on arrival.
struct RenderedLine {
    text: String,
    entry_seq: u64,
    entry_seq_end: u64,
    is_tool: bool,
    mutable: bool,
}

/// Render one snapshot entry into curated lines. Entries that contribute
/// nothing (reasoning, notifications, plugins, unknown kinds, empty text)
/// yield no lines but keep their snapshot slot for ordering.
fn entry_lines(entry: &ProjectedEntry) -> Vec<RenderedLine> {
    if entry.omitted_by_policy() {
        return Vec::new();
    }
    let line = |text: String| RenderedLine {
        text,
        entry_seq: entry.seq_start,
        entry_seq_end: entry.seq_end,
        is_tool: false,
        mutable: false,
    };
    match &entry.item {
        TimelineItem::Ignored
        | TimelineItem::Reasoning { .. }
        | TimelineItem::Notification { .. }
        | TimelineItem::Plugin { .. } => Vec::new(),
        TimelineItem::UserMessage {
            text, attachments, ..
        } => {
            let mut lines = Vec::new();
            if !text.trim().is_empty() {
                // Owner quote envelopes (`> ...`) are preserved verbatim.
                lines.push(line(format!("[User] {}", text.trim())));
            }
            for attachment in attachments {
                match attachment {
                    AttachmentRef::Image => lines.push(line("[image]".to_owned())),
                    AttachmentRef::NamedFile(name) => {
                        lines.push(line(format!("[attachment: {name}]")));
                    }
                }
            }
            lines
        }
        TimelineItem::AssistantMessage { text, .. } => {
            if text.trim().is_empty() {
                Vec::new()
            } else {
                vec![line(text.trim().to_owned())]
            }
        }
        TimelineItem::ToolCall {
            name,
            status,
            detail,
            metadata,
            ..
        } => {
            vec![RenderedLine {
                text: format_tool_line(name, detail, metadata),
                entry_seq: entry.seq_start,
                entry_seq_end: entry.seq_end,
                is_tool: true,
                mutable: !status.terminal(),
            }]
        }
        TimelineItem::Todo { items } => {
            let mut lines = vec![line("[Tasks]".to_owned())];
            for item in items {
                let checkbox = if item.completed { "[x]" } else { "[ ]" };
                lines.push(line(truncate_bounded(
                    &format!("- {checkbox} {}", single_line(&item.text)),
                    MAX_TASK_LINE_CHARS,
                )));
            }
            lines
        }
        TimelineItem::Error { message } => {
            let single = single_line(message);
            if single.is_empty() {
                Vec::new()
            } else {
                vec![line(truncate_bounded(
                    &format!("[Error] {single}"),
                    MAX_ERROR_CHARS,
                ))]
            }
        }
        TimelineItem::Compaction { .. } => vec![line("[Compacted]".to_owned())],
    }
}

/// One step-shaped run of rendered lines over the ordered snapshot.
struct StepGroup {
    kind: StepKind,
    lines: Vec<RenderedLine>,
}

/// Group ordered snapshot entries into steps: a user entry closes the open
/// group and forms its own; an assistant entry closes the open group and
/// starts an agent group; tool and marker entries attach to the open group
/// (opening a marker-led one when none is open). Entries with no rendered
/// lines never affect grouping.
fn derive_groups(ordered: &[&ProjectedEntry]) -> Vec<StepGroup> {
    let mut groups: Vec<StepGroup> = Vec::new();
    let mut current: Option<StepGroup> = None;
    let flush_current = |current: &mut Option<StepGroup>, groups: &mut Vec<StepGroup>| {
        if let Some(group) = current.take() {
            if !group.lines.is_empty() {
                groups.push(group);
            }
        }
    };
    for entry in ordered {
        let lines = entry_lines(entry);
        if lines.is_empty() {
            continue;
        }
        match &entry.item {
            TimelineItem::UserMessage { .. } => {
                flush_current(&mut current, &mut groups);
                groups.push(StepGroup {
                    kind: StepKind::User,
                    lines,
                });
            }
            TimelineItem::AssistantMessage { .. } => {
                flush_current(&mut current, &mut groups);
                current = Some(StepGroup {
                    kind: StepKind::Agent,
                    lines,
                });
            }
            TimelineItem::Error { .. } => {
                attach_marker(&mut current, lines, StepKind::Error);
            }
            TimelineItem::Compaction { .. } => {
                attach_marker(&mut current, lines, StepKind::Compacted);
            }
            // Tool calls and todo lists attach to (or open) a tools-led run.
            _ => {
                attach_marker(&mut current, lines, StepKind::Tools);
            }
        }
    }
    flush_current(&mut current, &mut groups);
    groups
}

/// Attach marker/tool lines to the open group, opening a marker-led group
/// when none is open. A group holding an assistant message keeps the agent
/// kind; marker-led groups that gain tool lines become `tools`.
fn attach_marker(current: &mut Option<StepGroup>, lines: Vec<RenderedLine>, led_kind: StepKind) {
    let group = current.get_or_insert_with(|| StepGroup {
        kind: led_kind,
        lines: Vec::new(),
    });
    if lines.iter().any(|line| line.is_tool) && group.kind != StepKind::Agent {
        group.kind = StepKind::Tools;
    }
    group.lines.extend(lines);
}

/// Assistant entries that a later message already closed: a later
/// `user_message` or `assistant_message` (any ids, any turn) proves the
/// earlier message complete. Same-`seqStart` refreshes never count (they are
/// the same entry, keyed uniquely in the snapshot).
/// One bound-sized run of tool-led lines with its stability flag. Only full
/// chunks are stable across page splits: a trailing below-bound chunk may
/// still grow, so an open run holds it for the genuine boundary or turn end.
struct LineChunk<'a> {
    lines: Vec<&'a RenderedLine>,
    full: bool,
}

/// Greedily cut tool-led lines at 32 tool-call lines or 16 KiB. Every chunk
/// but possibly the last is full by construction; the last is full only when
/// it lands exactly on a bound.
fn chunk_lines<'a>(head: &[&'a RenderedLine]) -> Vec<LineChunk<'a>> {
    let mut chunks: Vec<LineChunk<'a>> = Vec::new();
    let mut chunk: Vec<&'a RenderedLine> = Vec::new();
    let mut chunk_tools = 0usize;
    let mut chunk_bytes = 0usize;
    for line in head {
        if !chunk.is_empty()
            && ((line.is_tool && chunk_tools >= TOOL_ONLY_FLUSH_LINES)
                || chunk_bytes + line.text.len() + 1 > TOOL_ONLY_FLUSH_BYTES)
        {
            chunks.push(LineChunk {
                lines: std::mem::take(&mut chunk),
                full: true,
            });
            chunk_tools = 0;
            chunk_bytes = 0;
        }
        chunk_tools += usize::from(line.is_tool);
        chunk_bytes += line.text.len() + 1;
        chunk.push(line);
    }
    if !chunk.is_empty() {
        let full = chunk_tools >= TOOL_ONLY_FLUSH_LINES || chunk_bytes >= TOOL_ONLY_FLUSH_BYTES;
        chunks.push(LineChunk { lines: chunk, full });
    }
    chunks
}

/// True when `incoming` supersedes `stored` for the same `seqStart`.
/// Coverage growth always wins; at equal coverage only a regressive
/// terminal→running tool update is refused (a stale page must never clobber
/// a completion). Everything else at equal span resolves last-wins, which
/// makes identical redelivery a natural no-op.
fn supersedes(stored: &ProjectedEntry, incoming: &ProjectedEntry) -> bool {
    if incoming.seq_end != stored.seq_end {
        return incoming.seq_end > stored.seq_end;
    }
    let stored_terminal =
        matches!(&stored.item, TimelineItem::ToolCall { status, .. } if status.terminal());
    let incoming_terminal =
        matches!(&incoming.item, TimelineItem::ToolCall { status, .. } if status.terminal());
    !(stored_terminal && !incoming_terminal)
}

/// Pure streaming curator over fetched projected pages. The snapshot is
/// working state, not persistence: emitted steps are append-only and never
/// rewritten.
pub struct Curator {
    epoch: String,
    entries: BTreeMap<u64, ProjectedEntry>,
    /// `seqStart` of the last emitted source entry. Groups at or below it
    /// are never re-emitted, even if a late refresh touches them.
    emitted_through: Option<u64>,
    outbox: VecDeque<FinalizedStep>,
}

impl Default for Curator {
    fn default() -> Self {
        Self::new()
    }
}

impl Curator {
    pub fn new() -> Self {
        Self {
            epoch: String::new(),
            entries: BTreeMap::new(),
            emitted_through: None,
            outbox: VecDeque::new(),
        }
    }

    /// Merge one fetched page, then emit the newly final steps in order.
    /// Same-`seqStart` entries upsert per [`supersedes`]: coverage growth
    /// and idempotent redelivery apply, older refreshes and equal-span
    /// terminal→running regressions are dropped. An epoch change clears the
    /// snapshot and the emission mark (S3 alignment owns cross-epoch
    /// history). Returns true when this page switched the epoch: the caller
    /// must drain before switching epochs (the outbox is untouched by the
    /// reset) and must never feed stale-epoch pages afterwards — the curator
    /// cannot order opaque epochs and treats any new epoch as a rebuild.
    pub fn push_page(&mut self, epoch: &str, entries: Vec<ProjectedEntry>) -> bool {
        let switched = epoch != self.epoch;
        if switched {
            self.epoch = epoch.to_owned();
            self.entries.clear();
            self.emitted_through = None;
        }
        for entry in entries {
            let replace = match self.entries.get(&entry.seq_start) {
                None => true,
                Some(stored) => supersedes(stored, &entry),
            };
            if replace {
                self.entries.insert(entry.seq_start, entry);
            }
        }
        self.drain_emittable(false, false);
        switched
    }

    /// Mark the turn ended: everything still held emits in order, including
    /// tools that never reported completion (they finalize with their
    /// last-seen summary rather than blocking later turns forever). Turn end
    /// closes the books — later completions update the snapshot copy but are
    /// never re-emitted.
    pub fn end_turn(&mut self) {
        self.drain_emittable(true, false);
    }

    /// Drain finalized steps in emission order. Never exposes in-flight
    /// content: the drain stops at the first non-final group.
    pub fn drain_finalized(&mut self) -> Vec<ProjectedStep> {
        self.outbox.drain(..).map(|entry| entry.step).collect()
    }

    pub fn drain_finalized_with_sources(&mut self) -> Vec<FinalizedStep> {
        self.outbox.drain(..).collect()
    }

    pub fn is_frozen(&self, anchor: u64) -> bool {
        self.emitted_through.is_some_and(|mark| anchor <= mark)
    }

    /// Release settled source bodies without changing the emitted watermark.
    /// Open groups remain intact; tool-only stable chunks need no old prefix.
    pub fn forget_settled(&mut self, anchors: &[u64]) -> crate::error::Result<()> {
        if anchors.iter().any(|anchor| {
            self.entries
                .get(anchor)
                .is_some_and(|entry| !self.is_frozen(*anchor) && !entry.omitted_by_policy())
        }) {
            return Err(crate::error::Error::engine(
                "cannot forget unfinished source row",
            ));
        }
        for anchor in anchors {
            self.entries.remove(anchor);
        }
        Ok(())
    }

    /// Earliest row not yet finalized. A fetch cursor can be beyond this
    /// row, but a durable restart cursor must remain before it. Ignored rows
    /// may keep this boundary conservative; skipping unfinished rows cannot.
    pub fn first_pending_seq(&self) -> Option<u64> {
        self.entries
            .keys()
            .copied()
            .find(|seq| self.emitted_through.is_none_or(|mark| *seq > mark))
    }

    /// A validated next-message header closes the existing group without
    /// rendering or reserving that next row. Mutable tools still block it.
    pub fn close_before_next_message(&mut self, anchor: u64) {
        // Refreshes of the current message cannot prove a later boundary.
        if self
            .entries
            .last_key_value()
            .is_some_and(|(last, _)| *last >= anchor)
            || self.is_frozen(anchor)
        {
            return;
        }
        self.drain_emittable(false, true);
    }

    fn drain_emittable(&mut self, force: bool, following_message: bool) {
        let ordered: Vec<&ProjectedEntry> = self.entries.values().collect();
        let groups = derive_groups(&ordered);
        // A group is closed once a later group starts a new message (user-
        // or agent-led): nothing can ever join it again. Open runs may still
        // grow, so they emit only full bound-sized chunks — the same final
        // line sequence always yields the same steps whatever the page
        // splits were.
        let mut closed_after = vec![false; groups.len()];
        let mut seen_message = following_message;
        for (index, group) in groups.iter().enumerate().rev() {
            closed_after[index] = seen_message;
            if matches!(group.kind, StepKind::User | StepKind::Agent) {
                seen_message = true;
            }
        }
        for (index, group) in groups.iter().enumerate() {
            // Drop already-emitted prefix lines; the remainder is a suffix by
            // construction (emission advances monotonically).
            let rest: Vec<&RenderedLine> = group
                .lines
                .iter()
                .filter(|line| {
                    self.emitted_through
                        .is_none_or(|mark| line.entry_seq > mark)
                })
                .collect();
            if rest.is_empty() {
                continue;
            }
            let closed = closed_after[index];
            match group.kind {
                StepKind::Tools => {
                    if !self.emit_tool_chunks(&rest, closed, force) {
                        break;
                    }
                }
                // User rows are complete on arrival: emit on sight.
                StepKind::User => self.emit_body(group.kind, &rest),
                // Assistant and marker groups emit once closed (or at turn
                // end): an agent step needs its message closed behind a
                // later message plus terminal tools; marker-only runs wait
                // for the boundary that decides their final grouping/kind.
                _ => {
                    if force || (closed && group_final(group)) {
                        self.emit_body(group.kind, &rest);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Emit a tool-led group's lines. Closed runs flush their terminal
    /// remainder even below the bounds; open runs emit only full bound-sized
    /// chunks of the terminal prefix, holding the below-bound remainder for
    /// the genuine boundary or turn end. A retained pending tail (mutable
    /// lines, or an open below-bound remainder) blocks later groups, keeping
    /// emission in order. Returns false when blocked. At `force`, all chunks
    /// emit.
    fn emit_tool_chunks(&mut self, rest: &[&RenderedLine], closed: bool, force: bool) -> bool {
        let mutable_from = rest.iter().position(|line| line.mutable);
        let head_len = match (mutable_from, closed, force) {
            (None, _, _) | (_, _, true) => rest.len(),
            (Some(at), _, false) => at,
        };
        if head_len == 0 && !force {
            return false;
        }
        let (head, _tail) = rest.split_at(head_len);
        let chunks = chunk_lines(head);
        let emit_count = if closed || force {
            chunks.len()
        } else {
            // Open run: only full bound-sized chunks are stable.
            chunks.iter().take_while(|chunk| chunk.full).count()
        };
        for chunk in &chunks[..emit_count] {
            self.emit_body(StepKind::Tools, &chunk.lines);
        }
        emit_count == chunks.len() && head_len == rest.len()
    }

    /// Emit one body (already known final) through the 64 KiB splitter.
    fn emit_body(&mut self, kind: StepKind, lines: &[&RenderedLine]) {
        let body = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if normalize_body(&body).is_empty() {
            return;
        }
        let min_seq = lines.iter().map(|line| line.entry_seq).min().unwrap_or(0);
        let max_seq = lines
            .iter()
            .map(|line| line.entry_seq_end)
            .max()
            .unwrap_or(0);
        let source_entries: Vec<u64> = lines
            .iter()
            .map(|line| line.entry_seq)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let parts = split_step_body(&body);
        let part_count = parts.len() as u32;
        for (part_index, part) in parts.iter().enumerate() {
            let part_index = part_index as u32;
            self.outbox.push_back(FinalizedStep {
                source_entries: source_entries.clone(),
                part_count,
                step: ProjectedStep {
                    fingerprint: fingerprint_step(kind, part_index, part),
                    kind,
                    body: part.clone(),
                    part_index,
                    seq_start: min_seq,
                    seq_end: max_seq,
                },
            });
        }
        // Deduplication keys are row starts; source spans include each full row.
        self.emitted_through = lines.iter().map(|line| line.entry_seq).max();
    }
}

/// A group with no pending assistant message is final when every line is
/// immutable (assistant, user and marker lines always are; tool lines only
/// when terminal). Assistant closure is established by the caller through
/// the group-closed rule: an agent group is only evaluated once a later
/// message began behind it.
fn group_final(group: &StepGroup) -> bool {
    group.lines.iter().all(|line| !line.mutable)
}

/// Worst-case ` …(i/n)` label bytes for `total` parts: space + `…` (3 bytes
/// UTF-8) + parens + slash + decimal digits of the largest indices.
fn label_reserve(total: usize) -> usize {
    let digits = total.to_string().len();
    7 + 2 * digits
}

/// Split an over-bound step body at paragraph boundaries with a byte-safe
/// hard-split fallback, reserving label space so every emitted part, label
/// included, fits [`MAX_STEP_BYTES`]. Short bodies return unchanged with no
/// label.
fn split_step_body(body: &str) -> Vec<String> {
    if body.len() <= MAX_STEP_BYTES {
        return vec![body.to_owned()];
    }
    let mut limit = MAX_STEP_BYTES;
    let mut parts = pack_body(body, limit);
    // Refine to a fixpoint: a smaller packing limit can only add parts, and
    // part counts are bounded by the body bytes, so this terminates; the cap
    // is pure insurance.
    for _ in 0..32 {
        if parts.len() <= 1 {
            return label_parts(parts);
        }
        let reserve = label_reserve(parts.len());
        let next = MAX_STEP_BYTES.saturating_sub(reserve).max(1024);
        if next == limit {
            return label_parts(parts);
        }
        limit = next;
        let repacked = pack_body(body, limit);
        if repacked.len() == parts.len() {
            return label_parts(repacked);
        }
        parts = repacked;
    }
    label_parts(parts)
}

fn label_parts(parts: Vec<String>) -> Vec<String> {
    if parts.len() <= 1 {
        return parts;
    }
    let total = parts.len();
    parts
        .into_iter()
        .enumerate()
        .map(|(index, part)| format!("{part} …({}/{total})", index + 1))
        .collect()
}

/// Split into paragraphs (keeping `\n\n` separators with the preceding
/// paragraph so reassembly is lossless), greedily pack paragraphs within
/// `limit`, and hard-split any paragraph over the limit.
fn pack_body(body: &str, limit: usize) -> Vec<String> {
    let mut paragraphs: Vec<&str> = Vec::new();
    let mut rest = body;
    while let Some(split_at) = rest.find("\n\n") {
        let (head, tail) = rest.split_at(split_at);
        let separator_end = tail
            .char_indices()
            .take_while(|(_, c)| *c == '\n')
            .map(|(i, c)| i + c.len_utf8())
            .last()
            .unwrap_or(0);
        let (separator, remainder) = tail.split_at(separator_end);
        paragraphs.push(&rest[..head.len() + separator.len()]);
        rest = remainder;
    }
    if !rest.is_empty() {
        paragraphs.push(rest);
    }
    if paragraphs.is_empty() {
        paragraphs.push(body);
    }
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    for paragraph in paragraphs {
        if paragraph.len() > limit {
            if !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
            parts.extend(hard_split(paragraph, limit));
            continue;
        }
        if !current.is_empty() && current.len() + paragraph.len() > limit {
            parts.push(std::mem::take(&mut current));
        }
        current.push_str(paragraph);
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Byte-safe hard split at the largest character boundary within `limit`.
/// The floor of 4 is the longest UTF-8 encoding, so a boundary always
/// exists and the loop always makes progress.
fn hard_split(text: &str, limit: usize) -> Vec<String> {
    let limit = limit.max(4);
    let mut parts = Vec::new();
    let mut rest = text;
    while rest.len() > limit {
        let mut end = limit.min(rest.len());
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            end = 4.min(rest.len());
            while !rest.is_char_boundary(end) {
                end += 1;
            }
        }
        let (head, tail) = rest.split_at(end);
        parts.push(head.to_owned());
        rest = tail;
    }
    if !rest.is_empty() {
        parts.push(rest.to_owned());
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- verbatim wire builders -------------------------------------------

    fn user_j(text: &str) -> Value {
        json!({"type": "user_message", "text": text, "clientMessageId": "client-1"})
    }

    fn user_rebuilt_j(text: &str) -> Value {
        json!({"type": "user_message", "text": text, "messageId": "prov-uuid-9"})
    }

    fn asst_j(text: &str, message_id: Option<&str>) -> Value {
        let mut item = json!({"type": "assistant_message", "text": text});
        if let Some(id) = message_id {
            item["messageId"] = json!(id);
        }
        item
    }

    fn tool_j(call_id: &str, name: &str, status: &str, detail: Value) -> Value {
        json!({
            "type": "tool_call",
            "callId": call_id,
            "name": name,
            "status": status,
            "error": null,
            "detail": detail,
            "metadata": {},
        })
    }

    fn shell_j(call_id: &str, status: &str, command: &str) -> Value {
        tool_j(
            call_id,
            "shell",
            status,
            json!({"type": "shell", "command": command}),
        )
    }

    fn read_j(call_id: &str, status: &str, path: &str) -> Value {
        tool_j(
            call_id,
            "read_file",
            status,
            json!({"type": "read", "filePath": path, "content": "raw never shown"}),
        )
    }

    /// One verbatim projected entry: provider key, turn, timestamp, seq
    /// window, source ranges and collapse markers included, extras ignored.
    fn entry_j(item: Value, turn: Option<&str>, seq_start: u64, seq_end: u64) -> Value {
        let mut entry = json!({
            "provider": "claude",
            "item": item,
            "timestamp": "2026-10-16T00:00:01.000Z",
            "seqStart": seq_start,
            "seqEnd": seq_end,
            "sourceSeqRanges": [{"startSeq": seq_start, "endSeq": seq_end}],
            "collapsed": [],
        });
        if let Some(turn) = turn {
            entry["turnId"] = json!(turn);
        }
        entry
    }

    /// One verbatim `fetch_agent_timeline_response` payload.
    fn page_j(epoch: &str, entries: Vec<Value>) -> Value {
        json!({
            "type": "fetch_agent_timeline_response",
            "payload": {
                "requestId": "r1",
                "agentId": "agent-1",
                "agent": null,
                "direction": "after",
                "projection": "projected",
                "epoch": epoch,
                "reset": false,
                "staleCursor": false,
                "gap": false,
                "window": {"minSeq": 1, "maxSeq": 10, "nextSeq": 11},
                "startCursor": null,
                "endCursor": null,
                "hasOlder": false,
                "hasNewer": false,
                "entries": entries,
                "error": null,
            },
        })
    }

    /// One verbatim `agent_stream` envelope carrying `event`.
    fn stream_j(event: Value) -> Value {
        json!({
            "type": "session",
            "message": {
                "type": "agent_stream",
                "payload": {
                    "subscriptionId": "sub-1",
                    "agentId": "agent-1",
                    "event": event,
                    "timestamp": "2026-10-16T00:00:05.000Z",
                    "seq": 42,
                    "epoch": "epoch-1",
                },
            },
        })
    }

    fn stream_inner(message: &Value) -> &Value {
        message.pointer("/message").unwrap_or(message)
    }

    struct PageDriver {
        curator: Curator,
    }

    impl PageDriver {
        fn new() -> Self {
            Self {
                curator: Curator::new(),
            }
        }

        fn push_json(&mut self, page: &Value) -> bool {
            let payload = page.pointer("/payload").unwrap_or(page);
            let (epoch, entries) = parse_fetch_page(payload);
            self.curator.push_page(&epoch, entries)
        }

        fn end_turn(&mut self) {
            self.curator.end_turn();
        }

        fn drain(&mut self) -> Vec<ProjectedStep> {
            self.curator.drain_finalized()
        }

        fn finish(mut self) -> Vec<ProjectedStep> {
            self.curator.end_turn();
            self.curator.drain_finalized()
        }
    }

    // -- fingerprint lock -------------------------------------------------

    #[test]
    fn curated_source_span_includes_the_full_projected_row_and_all_split_parts() {
        let mut driver = PageDriver::new();
        driver.push_json(&page_j("e", vec![entry_j(user_j("hello"), None, 3, 9)]));
        let steps = driver.finish();
        assert_eq!(steps.len(), 1);
        assert_eq!((steps[0].seq_start, steps[0].seq_end), (3, 9));

        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e",
            vec![entry_j(
                user_j(&"x".repeat(MAX_STEP_BYTES * 2)),
                None,
                10,
                20,
            )],
        ));
        let steps = driver.finish();
        assert!(steps.len() > 1);
        assert!(steps.iter().all(|s| (s.seq_start, s.seq_end) == (10, 20)));
    }

    #[test]
    fn fingerprint_encoding_vector() {
        // Regression lock for the documented BE64-length-prefixed encoding.
        // Independent reimplementation: python3 hashlib with
        // unicodedata.normalize("NFC", s.strip().replace("\r\n","\n").replace("\r","\n")).
        let step = ProjectedStep {
            kind: StepKind::Agent,
            body: "hello".to_owned(),
            part_index: 0,
            fingerprint: fingerprint_step(StepKind::Agent, 0, "hello"),
            seq_start: 1,
            seq_end: 1,
        };
        assert_eq!(
            step.fingerprint,
            "a09ed5c2055c6ee3bbd4be162f1faf66528422800a3ae8bd3cb5b40b3d58a0ac"
        );
    }

    #[test]
    fn unicode_normalization_feeds_fingerprint() {
        let precomposed = "caf\u{e9}";
        let decomposed = "cafe\u{301}";
        assert_eq!(normalize_body(precomposed), normalize_body(decomposed));
        assert_eq!(
            fingerprint_step(StepKind::Agent, 0, precomposed),
            fingerprint_step(StepKind::Agent, 0, decomposed)
        );
        assert_eq!(normalize_body("  a\r\nb\r"), "a\nb");
        assert_eq!(
            fingerprint_step(StepKind::User, 0, "  a\r\nb\r"),
            fingerprint_step(StepKind::User, 0, "a\nb")
        );
    }

    // -- id independence --------------------------------------------------

    #[test]
    fn user_id_aliases_fingerprint_identically() {
        let live = page_j(
            "e1",
            vec![entry_j(user_j("do the thing"), Some("t1"), 1, 1)],
        );
        let rebuilt = page_j(
            "e1",
            vec![entry_j(user_rebuilt_j("do the thing"), Some("t1"), 1, 1)],
        );
        let run = |page: &Value| {
            let mut driver = PageDriver::new();
            driver.push_json(page);
            driver.finish()
        };
        let live_steps = run(&live);
        let rebuilt_steps = run(&rebuilt);
        assert_eq!(live_steps.len(), 1);
        assert_eq!(live_steps, rebuilt_steps);
        assert_eq!(live_steps[0].body, "[User] do the thing");
    }

    #[test]
    fn assistant_id_variants_fingerprint_identically() {
        let with_id = page_j(
            "e1",
            vec![
                entry_j(asst_j("done", Some("m1")), Some("t1"), 2, 2),
                entry_j(user_j("next"), Some("t2"), 3, 3),
            ],
        );
        let without_id = page_j(
            "e1",
            vec![
                entry_j(asst_j("done", None), Some("t1"), 2, 2),
                entry_j(user_j("next"), Some("t2"), 3, 3),
            ],
        );
        let run = |page: &Value| {
            let mut driver = PageDriver::new();
            driver.push_json(page);
            driver.finish()
        };
        assert_eq!(run(&with_id), run(&without_id));
    }

    #[test]
    fn repeated_text_across_turns_stays_separate() {
        let page = page_j(
            "e1",
            vec![
                entry_j(asst_j("same answer", None), Some("t1"), 1, 1),
                entry_j(user_j("again"), Some("t2"), 2, 2),
                entry_j(asst_j("same answer", None), Some("t2"), 3, 3),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        // The trailing assistant message is still in flight: no later row.
        let interim = driver.drain();
        assert_eq!(interim.len(), 2);
        assert_eq!(interim[0].kind, StepKind::Agent);
        assert_eq!(interim[1].kind, StepKind::User);
        let tail = driver.finish();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].body, "same answer");
        assert_eq!(interim[0].fingerprint, tail[0].fingerprint);
    }

    #[test]
    fn turn_ids_ignored_by_step_logic() {
        // Provider history rows deliberately omit turnId; grouping and
        // finality must not depend on it.
        let with_turns = page_j(
            "e1",
            vec![
                entry_j(user_j("hi"), Some("t1"), 1, 1),
                entry_j(asst_j("hello", Some("m1")), Some("t1"), 2, 2),
                entry_j(read_j("r1", "completed", "f"), Some("t1"), 3, 3),
                entry_j(user_j("bye"), Some("t2"), 4, 4),
            ],
        );
        let without_turns = page_j(
            "e1",
            vec![
                entry_j(user_j("hi"), None, 1, 1),
                entry_j(asst_j("hello", Some("m1")), None, 2, 2),
                entry_j(read_j("r1", "completed", "f"), None, 3, 3),
                entry_j(user_j("bye"), None, 4, 4),
            ],
        );
        let run = |page: &Value| {
            let mut driver = PageDriver::new();
            driver.push_json(page);
            driver.finish()
        };
        assert_eq!(run(&with_turns), run(&without_turns));
    }

    // -- page upsert: overlap, extension, staleness ------------------------

    #[test]
    fn page_refresh_upserts_idempotently() {
        let partial = page_j(
            "e1",
            vec![
                entry_j(user_j("hi"), Some("t1"), 1, 1),
                entry_j(asst_j("Hello", Some("m1")), Some("t1"), 2, 2),
                entry_j(shell_j("c1", "running", "make"), Some("t1"), 3, 3),
            ],
        );
        let full = page_j(
            "e1",
            vec![
                entry_j(user_j("hi"), Some("t1"), 1, 1),
                entry_j(asst_j("Hello world", Some("m1")), Some("t1"), 2, 4),
                entry_j(shell_j("c1", "completed", "make"), Some("t1"), 3, 3),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&partial);
        // Only the user step is final: the assistant has no later message
        // and the tool is still running.
        let first = driver.drain();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].body, "[User] hi");

        driver.push_json(&full);
        // Still pending: no later message has begun, so the extended text
        // stays in flight even though the tool completed.
        assert!(driver.drain().is_empty());

        // Idempotent redelivery and stale refreshes emit nothing and change
        // nothing (the stale page must not clobber the extension).
        driver.push_json(&full);
        assert!(driver.drain().is_empty());
        driver.push_json(&partial);
        assert!(driver.drain().is_empty());

        // A later user row releases the agent step with the full text.
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(user_j("thanks"), Some("t1"), 5, 5)],
        ));
        let second = driver.drain();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].kind, StepKind::Agent);
        assert_eq!(second[0].body, "Hello world\n[Shell] make");
        assert_eq!(second[1].body, "[User] thanks");
    }

    #[test]
    fn cumulative_extension_replaces_without_duplication() {
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(asst_j("Hello", Some("m1")), Some("t1"), 5, 5)],
        ));
        assert!(driver.drain().is_empty());
        // Same seqStart, larger seqEnd, cumulative text: snapshot refresh.
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(
                asst_j("Hello brave world", Some("m1")),
                Some("t1"),
                5,
                7,
            )],
        ));
        assert!(driver.drain().is_empty());
        driver.push_json(&page_j("e1", vec![entry_j(user_j("ok"), Some("t1"), 8, 8)]));
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].body, "Hello brave world");
        assert_eq!(steps[1].body, "[User] ok");
    }

    #[test]
    fn same_span_completion_still_applies() {
        // Guard against over-tightening: a same-span running→completed
        // lifecycle update is genuine and must replace.
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(shell_j("c1", "running", "make"), Some("t1"), 5, 5)],
        ));
        assert!(driver.drain().is_empty());
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(
                shell_j("c1", "completed", "make"),
                Some("t1"),
                5,
                5,
            )],
        ));
        driver.end_turn();
        let steps = driver.drain();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[Shell] make");
    }

    #[test]
    fn older_refresh_is_dropped() {
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(
                asst_j("full text here", Some("m1")),
                Some("t1"),
                5,
                9,
            )],
        ));
        // A strictly older refresh for the same entry changes nothing.
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(asst_j("full", Some("m1")), Some("t1"), 5, 5)],
        ));
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(user_j("next"), Some("t1"), 10, 10)],
        ));
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].body, "full text here");
    }

    #[test]
    fn epoch_change_resets_snapshot() {
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "epoch-1",
            vec![entry_j(user_j("old"), Some("t1"), 1, 1)],
        ));
        assert_eq!(driver.drain().len(), 1);
        // Rebuild: seqs restart under a new epoch; the old snapshot is gone.
        driver.push_json(&page_j(
            "epoch-2",
            vec![
                entry_j(user_j("new"), Some("t9"), 1, 1),
                entry_j(asst_j("answer", None), Some("t9"), 2, 2),
            ],
        ));
        let steps = driver.drain();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[User] new");
        assert!(driver.finish().iter().any(|step| step.body == "answer"));
    }

    // -- ordering and finality ---------------------------------------------

    #[test]
    fn assistant_tool_assistant_stays_ordered() {
        // Regression: pages arrive already merged, so arrival order IS
        // display order — the curator must never fold B into A's text.
        let page = page_j(
            "e1",
            vec![
                entry_j(asst_j("alpha", None), Some("t1"), 1, 1),
                entry_j(read_j("read-1", "completed", "f"), Some("t1"), 2, 2),
                entry_j(asst_j("beta", None), Some("t1"), 3, 3),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        // The first assistant message closed behind beta; beta itself is
        // still in flight until a later row or turn end.
        let steps = driver.drain();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "alpha\n[Read] f");
        let tail = driver.finish();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].body, "beta");
    }

    #[test]
    fn assistant_step_waits_for_later_message() {
        // Conservative finality: with no later message the assistant text
        // may still grow, even beside a completed tool.
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e1",
            vec![
                entry_j(asst_j("working", Some("m1")), Some("t1"), 1, 1),
                entry_j(shell_j("c1", "completed", "make"), Some("t1"), 2, 2),
            ],
        ));
        assert!(driver.drain().is_empty());
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(user_j("thanks"), Some("t1"), 3, 3)],
        ));
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].body, "working\n[Shell] make");
        assert_eq!(steps[1].body, "[User] thanks");
    }

    #[test]
    fn pending_tool_blocks_later_groups_in_order() {
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e1",
            vec![
                entry_j(shell_j("c1", "running", "make"), Some("t1"), 5, 5),
                entry_j(user_j("later"), Some("t1"), 6, 6),
            ],
        ));
        // The user row is immutable, but emitting it first would write
        // history out of order: it waits behind the running tool.
        assert!(driver.drain().is_empty());
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(
                shell_j("c1", "completed", "make"),
                Some("t1"),
                5,
                5,
            )],
        ));
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].body, "[Shell] make");
        assert_eq!(steps[1].body, "[User] later");
    }

    // -- running-tool thresholds -------------------------------------------

    #[test]
    fn running_tools_never_flush() {
        let running: Vec<Value> = (0..32)
            .map(|i| {
                entry_j(
                    shell_j(&format!("call-{i}"), "running", "make check"),
                    Some("t1"),
                    10 + i,
                    10 + i,
                )
            })
            .collect();
        let mut driver = PageDriver::new();
        driver.push_json(&page_j("e1", running));
        // 32 running lines hit the count bound but every line is mutable:
        // nothing finalizes.
        assert!(driver.drain().is_empty());
        // Completions land in place; the bound then flushes exact steps.
        let completed: Vec<Value> = (0..32)
            .map(|i| {
                entry_j(
                    shell_j(&format!("call-{i}"), "completed", "make check"),
                    Some("t1"),
                    10 + i,
                    10 + i,
                )
            })
            .collect();
        driver.push_json(&page_j("e1", completed));
        let steps = driver.drain();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].kind, StepKind::Tools);
        assert_eq!(steps[0].body.lines().count(), 32);
        assert!(steps[0]
            .body
            .lines()
            .all(|line| line == "[Shell] make check"));
    }

    #[test]
    fn below_bound_open_run_waits_for_close() {
        // Corrected expectation (review G1): an open run below the bounds
        // emits nothing, even when its head is fully terminal. The 30-line
        // terminal prefix flushes only once a genuine boundary closes the
        // run — never speculatively mid-run.
        let mut entries: Vec<Value> = (0..30)
            .map(|i| {
                entry_j(
                    shell_j(&format!("done-{i}"), "completed", "ok"),
                    Some("t1"),
                    10 + i,
                    10 + i,
                )
            })
            .collect();
        entries.push(entry_j(
            shell_j("run-a", "running", "slow"),
            Some("t1"),
            40,
            40,
        ));
        entries.push(entry_j(
            shell_j("run-b", "running", "slow"),
            Some("t1"),
            41,
            41,
        ));
        let mut driver = PageDriver::new();
        driver.push_json(&page_j("e1", entries));
        assert!(driver.drain().is_empty());

        // A later user row closes the run: the terminal 30-line prefix
        // flushes, but the user step itself still waits behind the running
        // tail (strict in-order emission).
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(user_j("status?"), Some("t1"), 50, 50)],
        ));
        let closed = driver.drain();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].kind, StepKind::Tools);
        assert_eq!(closed[0].body.lines().count(), 30);

        // The completions release both the retained 2-line tail and the
        // waiting user step, in order.
        driver.push_json(&page_j(
            "e1",
            vec![
                entry_j(shell_j("run-a", "completed", "slow"), Some("t1"), 40, 40),
                entry_j(shell_j("run-b", "completed", "slow"), Some("t1"), 41, 41),
            ],
        ));
        let released = driver.drain();
        assert_eq!(released.len(), 2);
        assert_eq!(released[0].body, "[Shell] slow\n[Shell] slow");
        assert_eq!(released[1].body, "[User] status?");
        assert!(driver.finish().is_empty());
    }

    #[test]
    fn two_tools_one_page_vs_two_pages() {
        // Owner repro (G1): the same two completed tools must segment
        // identically whether they arrive in one page or two.
        let both = page_j(
            "e1",
            vec![
                entry_j(shell_j("c1", "completed", "one"), Some("t1"), 1, 1),
                entry_j(shell_j("c2", "completed", "two"), Some("t1"), 2, 2),
            ],
        );
        let first_only = page_j(
            "e1",
            vec![entry_j(shell_j("c1", "completed", "one"), Some("t1"), 1, 1)],
        );
        let second_only = page_j(
            "e1",
            vec![entry_j(shell_j("c2", "completed", "two"), Some("t1"), 2, 2)],
        );
        let mut single = PageDriver::new();
        single.push_json(&both);
        assert!(single.drain().is_empty());
        let mut split = PageDriver::new();
        split.push_json(&first_only);
        assert!(split.drain().is_empty());
        split.push_json(&second_only);
        assert!(split.drain().is_empty());
        let run = |pages: &[&Value]| {
            let mut driver = PageDriver::new();
            for page in pages {
                driver.push_json(page);
            }
            driver.finish()
        };
        let from_single = run(&[&both]);
        let from_split = run(&[&first_only, &second_only]);
        assert_eq!(from_single, from_split);
        assert_eq!(from_single.len(), 1);
        assert_eq!(from_single[0].kind, StepKind::Tools);
        assert_eq!(from_single[0].body, "[Shell] one\n[Shell] two");
        assert_eq!(from_single[0].seq_start, 1);
        assert_eq!(from_single[0].seq_end, 2);
    }

    #[test]
    fn marker_kind_change_across_pages() {
        // An early marker must not strand a step whose kind later changes:
        // [error] alone, then a tool joining it, then a user closing it is
        // one Tools step — however the pages split.
        let all_at_once = page_j(
            "e1",
            vec![
                entry_j(
                    json!({"type": "error", "message": "boom"}),
                    Some("t1"),
                    1,
                    1,
                ),
                entry_j(shell_j("c1", "completed", "fix"), Some("t1"), 2, 2),
                entry_j(user_j("ok"), Some("t1"), 3, 3),
            ],
        );
        let incremental = [
            page_j(
                "e1",
                vec![entry_j(
                    json!({"type": "error", "message": "boom"}),
                    Some("t1"),
                    1,
                    1,
                )],
            ),
            page_j(
                "e1",
                vec![
                    entry_j(
                        json!({"type": "error", "message": "boom"}),
                        Some("t1"),
                        1,
                        1,
                    ),
                    entry_j(shell_j("c1", "completed", "fix"), Some("t1"), 2, 2),
                ],
            ),
            page_j("e1", vec![entry_j(user_j("ok"), Some("t1"), 3, 3)]),
        ];
        let run = |pages: &[&Value]| {
            let mut driver = PageDriver::new();
            for page in pages {
                driver.push_json(page);
            }
            driver.finish()
        };
        // While the run stays open the marker emits nothing early.
        let mut early = PageDriver::new();
        early.push_json(&incremental[0]);
        assert!(early.drain().is_empty());
        early.push_json(&incremental[1]);
        assert!(early.drain().is_empty());

        let from_single = run(&[&all_at_once]);
        let from_split = run(&[&incremental[0], &incremental[1], &incremental[2]]);
        assert_eq!(from_single, from_split);
        assert_eq!(from_single.len(), 2);
        assert_eq!(from_single[0].kind, StepKind::Tools);
        assert_eq!(from_single[0].body, "[Error] boom\n[Shell] fix");
        assert_eq!(from_single[1].body, "[User] ok");
    }

    #[test]
    fn partition_equivalence_canonical_timeline() {
        // The same final canonical timeline fed as one page, as growing
        // prefixes, and as disjoint pages plus a refresh must yield
        // identical steps (kind/body/parts/fingerprints/spans) under the
        // same end_turn boundary.
        let canonical: Vec<Value> = vec![
            entry_j(user_j("build it"), Some("t1"), 1, 1),
            entry_j(asst_j("on it", Some("m1")), Some("t1"), 2, 2),
            entry_j(shell_j("c1", "completed", "cargo build"), Some("t1"), 3, 3),
            entry_j(shell_j("c2", "running", "cargo test"), Some("t1"), 4, 4),
            entry_j(
                json!({"type": "todo", "items": [{"text": "verify", "completed": false}]}),
                Some("t1"),
                5,
                5,
            ),
            entry_j(user_j("thanks"), Some("t2"), 6, 6),
        ];
        let completed = {
            let mut entries = canonical.clone();
            entries[3] = entry_j(shell_j("c2", "completed", "cargo test"), Some("t1"), 4, 4);
            entries
        };
        let feedings: Vec<Vec<Value>> = vec![
            // One page with everything (running tool version).
            vec![page_j("e1", canonical.clone())],
            // Growing prefixes, one new row per page.
            (1..=canonical.len())
                .map(|n| page_j("e1", canonical[..n].to_vec()))
                .collect(),
            // Disjoint pages plus a completion refresh of the running tool.
            vec![
                page_j("e1", canonical[..3].to_vec()),
                page_j("e1", canonical[3..].to_vec()),
                page_j("e1", vec![completed[3].clone()]),
            ],
        ];
        let mut results = Vec::new();
        for feeding in &feedings {
            let mut driver = PageDriver::new();
            for page in feeding {
                driver.push_json(page);
            }
            results.push(driver.finish());
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0], results[2]);
        // Spot-check the shared shape: user, agent (assistant + both tools
        // + tasks), trailing user — with stable spans and fingerprints.
        let steps = &results[0];
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].kind, StepKind::User);
        assert_eq!(steps[0].body, "[User] build it");
        assert_eq!(steps[1].kind, StepKind::Agent);
        assert_eq!(
            steps[1].body,
            "on it\n[Shell] cargo build\n[Shell] cargo test\n[Tasks]\n- [ ] verify"
        );
        assert_eq!(steps[1].seq_start, 2);
        assert_eq!(steps[1].seq_end, 5);
        assert_eq!(steps[2].body, "[User] thanks");
        assert_ne!(steps[0].fingerprint, steps[1].fingerprint);
    }

    #[test]
    fn epoch_switch_reports_and_guards() {
        // G2: the curator reports epoch switches; the caller owns the
        // drain-before-switch discipline (the outbox is untouched by resets)
        // and must never feed stale-epoch pages.
        let mut driver = PageDriver::new();
        // Adopting the initial epoch reports a switch (from empty).
        assert!(driver.push_json(&page_j(
            "epoch-1",
            vec![entry_j(user_j("old"), Some("t1"), 1, 1)],
        )));
        assert!(!driver.push_json(&page_j(
            "epoch-1",
            vec![entry_j(user_j("old"), Some("t1"), 1, 1)],
        )));
        assert!(driver.push_json(&page_j(
            "epoch-2",
            vec![entry_j(user_j("new"), Some("t9"), 1, 1)],
        )));
        // Undrained epoch-1 output survives the reset in push order; the
        // new epoch contributes only its own rows.
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].body, "[User] old");
        assert_eq!(steps[1].body, "[User] new");
        assert!(driver.finish().is_empty());
    }

    #[test]
    fn turn_end_closes_books_on_running_tools() {
        let mut driver = PageDriver::new();
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(shell_j("c1", "running", "make"), Some("t1"), 5, 5)],
        ));
        assert!(driver.drain().is_empty());
        driver.end_turn();
        let steps = driver.drain();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[Shell] make");
        // A completion arriving after turn end updates the snapshot copy but
        // is never re-emitted: emitted steps are never rewritten.
        driver.push_json(&page_j(
            "e1",
            vec![entry_j(
                shell_j("c1", "completed", "make"),
                Some("t1"),
                5,
                5,
            )],
        ));
        assert!(driver.drain().is_empty());
    }

    // -- rendering: summaries, markers, exclusions --------------------------

    #[test]
    fn tool_lines_attach_to_assistant_step() {
        let page = page_j(
            "e1",
            vec![
                entry_j(asst_j("Let me look.", None), Some("t1"), 1, 1),
                entry_j(
                    read_j("read-1", "completed", "src/index.ts"),
                    Some("t1"),
                    2,
                    2,
                ),
                entry_j(
                    shell_j("shell-1", "completed", "npm test"),
                    Some("t1"),
                    3,
                    3,
                ),
                entry_j(user_j("done"), Some("t1"), 4, 4),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].kind, StepKind::Agent);
        assert_eq!(
            steps[0].body,
            "Let me look.\n[Read] src/index.ts\n[Shell] npm test"
        );
        assert_eq!(steps[1].body, "[User] done");
    }

    #[test]
    fn tool_summaries_are_single_line_and_bounded() {
        let long_command = format!("run {}", "x".repeat(500));
        let line = format_tool_line(
            "shell",
            &ToolDetail::Shell {
                command: long_command,
            },
            &HashMap::new(),
        );
        assert!(!line.contains('\n'));
        assert!(line.len() <= "[Shell] ".len() + MAX_TOOL_SUMMARY_CHARS);
        assert!(line.ends_with("..."));

        let terminal = format_tool_line(
            "terminal",
            &ToolDetail::PlainText {
                label: Some("first line\nsecond line".to_owned()),
            },
            &HashMap::new(),
        );
        assert_eq!(terminal, "[Terminal] first line second line");
    }

    #[test]
    fn tool_display_names_cover_real_details() {
        let metadata = HashMap::new();
        let cases = [
            (
                ToolDetail::Read {
                    file_path: "a/b.ts".to_owned(),
                },
                "exec",
                "[Read] a/b.ts",
            ),
            (
                ToolDetail::Search {
                    query: "zod union".to_owned(),
                },
                "search",
                "[Search] zod union",
            ),
            (
                ToolDetail::Fetch {
                    url: "https://x.example".to_owned(),
                },
                "fetch",
                "[Fetch] https://x.example",
            ),
            (ToolDetail::Plan, "plan", "[Plan]"),
            (
                ToolDetail::SubAgent {
                    kind: Some("Explore".to_owned()),
                    description: Some("Investigate".to_owned()),
                },
                "Task",
                "[Explore] Investigate",
            ),
        ];
        for (detail, name, expected) in cases {
            assert_eq!(format_tool_line(name, &detail, &metadata), expected);
        }
    }

    #[test]
    fn external_tool_input_is_excluded_not_rendered() {
        // Desktop renders a 400-char input-JSON line for likely-external
        // tools; S2 excludes it and keeps the bare tool name.
        let page = page_j(
            "e1",
            vec![entry_j(
                tool_j(
                    "mcp-1",
                    "paseo__create_agent",
                    "completed",
                    json!({"type": "unknown", "input": {"cwd": "/tmp"}, "output": null}),
                ),
                Some("t1"),
                1,
                1,
            )],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        let steps = driver.finish();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[paseo__create_agent]");
        assert!(!steps[0].body.contains("cwd"));
    }

    #[test]
    fn failed_tool_renders_summary_not_error() {
        // Raw error payloads stay out: failure is display-identical to
        // success (documented F7c divergence).
        let page = page_j(
            "e1",
            vec![entry_j(
                json!({
                    "type": "tool_call",
                    "callId": "c1",
                    "name": "shell",
                    "status": "failed",
                    "error": {"content": "secret traceback"},
                    "detail": {"type": "shell", "command": "make", "output": "raw"},
                    "metadata": {},
                }),
                Some("t1"),
                1,
                1,
            )],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        let steps = driver.finish();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[Shell] make");
        assert!(!steps[0].body.contains("traceback"));
        assert!(!steps[0].body.contains("raw"));
    }

    #[test]
    fn empty_call_ids_are_retained_not_collapsed() {
        // Desktop collapses by "" identity; S2 keeps each arrival as its own
        // line (retention-safe, documented F7a divergence).
        let page = page_j(
            "e1",
            vec![
                entry_j(shell_j("", "completed", "one"), Some("t1"), 1, 1),
                entry_j(shell_j("", "completed", "two"), Some("t1"), 2, 2),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        let steps = driver.finish();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[Shell] one\n[Shell] two");
    }

    #[test]
    fn exclusions_leave_no_trace() {
        let page = page_j(
            "e1",
            vec![
                entry_j(
                    json!({"type": "reasoning", "text": "private chain"}),
                    Some("t1"),
                    1,
                    1,
                ),
                entry_j(
                    json!({"type": "notification", "level": "info", "message": "ping"}),
                    Some("t1"),
                    2,
                    2,
                ),
                entry_j(
                    json!({"type": "plugin", "id": "p", "pluginId": "plug", "kind": "k", "version": 1, "data": {}}),
                    Some("t1"),
                    3,
                    3,
                ),
                entry_j(shell_j("raw-1", "completed", ""), Some("t1"), 4, 4),
                entry_j(
                    tool_j(
                        "child-1",
                        "Sub-agent",
                        "completed",
                        json!({"type": "sub_agent", "subAgentType": "Child one", "description": "First investigation", "log": "dropped log"}),
                    ),
                    Some("t1"),
                    5,
                    5,
                ),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        let steps = driver.finish();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].body, "[Shell]\n[Child one] First investigation");
        assert!(!steps[0].body.contains("private chain"));
        assert!(!steps[0].body.contains("ping"));
        assert!(!steps[0].body.contains("dropped log"));
    }

    #[test]
    fn tasks_error_compacted_and_attachments_render() {
        let page = page_j(
            "e1",
            vec![
                entry_j(
                    json!({"type": "todo", "items": [
                        {"text": "One", "completed": false},
                        {"text": "Two", "completed": true},
                    ]}),
                    Some("t1"),
                    1,
                    1,
                ),
                entry_j(
                    json!({"type": "error", "message": "boom"}),
                    Some("t1"),
                    2,
                    2,
                ),
                entry_j(
                    json!({"type": "compaction", "status": "completed"}),
                    Some("t1"),
                    3,
                    3,
                ),
                entry_j(
                    json!({
                        "type": "user_message", "text": "",
                        "attachments": [
                            {"type": "image", "data": "…", "mimeType": "image/png"},
                            {"type": "uploaded_file", "id": "f1", "fileName": "notes.pdf", "mimeType": "application/pdf", "size": 10, "path": "/tmp/x"},
                        ],
                    }),
                    Some("t1"),
                    4,
                    4,
                ),
            ],
        );
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        // Marker group emits (closed by the user row); the user row emits on
        // sight; nothing pending remains.
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps[0].body,
            "[Tasks]\n- [ ] One\n- [x] Two\n[Error] boom\n[Compacted]"
        );
        assert_eq!(steps[0].kind, StepKind::Tools);
        assert_eq!(steps[1].body, "[image]\n[attachment: notes.pdf]");
        assert_eq!(steps[1].kind, StepKind::User);
        assert!(driver.finish().is_empty());
    }

    #[test]
    fn long_error_and_task_lines_are_bounded() {
        let long = "e".repeat(2000);
        let line = truncate_bounded(&format!("[Error] {long}"), MAX_ERROR_CHARS);
        assert!(line.len() <= MAX_ERROR_CHARS);
        assert!(line.ends_with("..."));
    }

    #[test]
    fn owner_quote_envelope_is_preserved_verbatim() {
        let quoted = "fyi\n> quoted reply text\n> second line";
        let page = page_j("e1", vec![entry_j(user_j(quoted), Some("t1"), 1, 1)]);
        let mut driver = PageDriver::new();
        driver.push_json(&page);
        let steps = driver.finish();
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].body,
            "[User] fyi\n> quoted reply text\n> second line"
        );
    }

    // -- split bounds ------------------------------------------------------

    #[test]
    fn oversized_steps_split_within_bound_including_labels() {
        // Paragraph path: three large paragraphs stay whole, labels fit.
        let paragraph = format!("{}\n\n", "p".repeat(40 * 1024));
        let body = format!("{paragraph}{paragraph}{paragraph}");
        let parts = split_step_body(&body);
        assert_eq!(parts.len(), 3);
        for (index, part) in parts.iter().enumerate() {
            assert!(
                part.len() <= MAX_STEP_BYTES,
                "part {index} is {} bytes",
                part.len()
            );
            assert!(part.ends_with(&format!("…({}/{})", index + 1, 3)));
        }

        // Exact bound: single part, no label.
        let exact = "x".repeat(MAX_STEP_BYTES);
        assert_eq!(split_step_body(&exact), vec![exact]);

        // One byte over: two parts, both within bound including labels.
        let over = "x".repeat(MAX_STEP_BYTES + 1);
        let parts = split_step_body(&over);
        assert_eq!(parts.len(), 2);
        for part in &parts {
            assert!(part.len() <= MAX_STEP_BYTES);
        }
        assert!(parts[0].ends_with("…(1/2)"));
        assert!(parts[1].ends_with("…(2/2)"));

        // Multibyte-only body: hard splits never break a code point.
        let emoji_body = "🦀".repeat(20 * 1024);
        assert!(emoji_body.len() > MAX_STEP_BYTES);
        let hard_parts = split_step_body(&emoji_body);
        assert!(hard_parts.len() >= 2);
        for part in &hard_parts {
            assert!(part.len() <= MAX_STEP_BYTES);
            let unlabelled = part.split(" …(").next().unwrap_or(part);
            assert!(unlabelled.len() <= MAX_STEP_BYTES);
        }
        assert_eq!(hard_parts, split_step_body(&emoji_body));

        // Multi-digit labels: ~600 KiB without paragraphs forces 10+ parts;
        // the digit growth is covered by the packing reserve.
        let big = "z".repeat(600 * 1024);
        let many = split_step_body(&big);
        assert!(many.len() >= 10);
        for (index, part) in many.iter().enumerate() {
            assert!(
                part.len() <= MAX_STEP_BYTES,
                "part {index} is {} bytes",
                part.len()
            );
            assert!(part.ends_with(&format!("…({}/{})", index + 1, many.len())));
        }
    }

    // -- wakeup classification ----------------------------------------------

    #[test]
    fn wakeup_classification_uses_verbatim_stream_shapes() {
        let timeline_event = json!({
            "type": "timeline",
            "provider": "claude",
            "item": {"type": "assistant_message", "text": "hi"},
            "turnId": "t1",
        });
        assert_eq!(
            classify_wakeup(stream_inner(&stream_j(timeline_event))),
            Wakeup::TimelineActivity
        );

        for event_type in ["turn_completed", "turn_failed", "turn_canceled"] {
            let event = json!({"type": event_type, "provider": "codex", "turnId": "t1"});
            assert_eq!(
                classify_wakeup(stream_inner(&stream_j(event))),
                Wakeup::TurnEnded,
                "{event_type}"
            );
        }

        let permission = json!({
            "type": "permission_requested",
            "provider": "claude",
            "request": {"id": "p1", "provider": "claude", "name": "shell", "kind": "tool"},
        });
        assert_eq!(
            classify_wakeup(stream_inner(&stream_j(permission))),
            Wakeup::Other
        );
        assert_eq!(
            classify_wakeup(&json!({"type": "status", "payload": {}})),
            Wakeup::Other
        );
        // Raw live items are wakeup data, never curator input: the timeline
        // event above classifies without its item reaching any step.
        let mut driver = PageDriver::new();
        driver.push_json(&page_j("e1", vec![]));
        assert!(driver.drain().is_empty());
    }

    #[test]
    fn wakeup_drives_page_fetch_and_turn_end() {
        let mut driver = PageDriver::new();
        // Timeline wakeup -> fetch page -> user step emits immediately.
        assert_eq!(
            classify_wakeup(stream_inner(&stream_j(json!({
                "type": "timeline",
                "provider": "claude",
                "item": user_j("hi"),
                "turnId": "t1",
            })))),
            Wakeup::TimelineActivity
        );
        driver.push_json(&page_j(
            "e1",
            vec![
                entry_j(asst_j("answering", None), Some("t1"), 1, 1),
                entry_j(user_j("hi"), Some("t1"), 2, 2),
            ],
        ));
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[1].body, "[User] hi");
        // Turn wakeup closes the still-open assistant tail.
        assert_eq!(
            classify_wakeup(stream_inner(&stream_j(json!({
                "type": "turn_completed",
                "provider": "claude",
                "turnId": "t1",
            })))),
            Wakeup::TurnEnded
        );
        driver.end_turn();
        assert!(driver.drain().is_empty());
    }

    // -- verbatim page tolerance --------------------------------------------

    #[test]
    fn real_response_entries_parse_verbatim() {
        // Full envelope keys plus per-entry provider/collapse metadata and
        // one unknown future kind: accepted without a schema change.
        let entries = vec![
            entry_j(user_j("hi"), Some("t1"), 1, 1),
            entry_j(asst_j("hello ", Some("m1")), Some("t1"), 2, 2),
            entry_j(read_j("call_1", "completed", "f"), Some("t1"), 3, 3),
            json!({
                "provider": "claude",
                "item": {"type": "mystery_future_kind", "text": "dropped"},
                "turnId": "t1",
                "timestamp": "2026-10-16T00:00:04.000Z",
                "seqStart": 4,
                "seqEnd": 4,
                "sourceSeqRanges": [{"startSeq": 4, "endSeq": 4}],
                "collapsed": ["identity"],
            }),
        ];
        let page = page_j("epoch-7", entries);
        let payload = page.pointer("/payload").unwrap();
        let (epoch, parsed) = parse_fetch_page(payload);
        assert_eq!(epoch, "epoch-7");
        assert_eq!(parsed.len(), 4);
        let mut driver = PageDriver::new();
        let (epoch, parsed) = parse_fetch_page(payload);
        driver.curator.push_page(&epoch, parsed);
        driver.curator.end_turn();
        let steps = driver.drain();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].body, "[User] hi");
        assert_eq!(steps[1].body, "hello\n[Read] f");
        assert!(!steps[1].body.contains("raw never shown"));
        assert!(!steps[1].body.contains("dropped"));
    }
}
