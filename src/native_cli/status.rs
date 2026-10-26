//! `native status`: the state of the hosted node, in a few short lines for
//! people and as one stable JSON object (`--json`) for agents.
//!
//! It connects to the node's Unix socket exactly as `native node connect` does
//! and makes three calls: `initialize`, then two MCP `tools/call`s,
//! `standby_status` (the local copy) and `node_status` (hosted health, the
//! write queue, the bound account). Field names are the node's own; nothing
//! here infers what the node did not say. A read that fails is reported as its
//! own state (no config, no socket, stale socket, permission or UID mismatch,
//! not answering, status unavailable), never as an age or a count.
//!
//! Exit codes: 0 healthy, 1 degraded, 2 the node is not running or cannot be
//! reached (or is misconfigured).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use super::node_client::{clean, down, read_config, structured, Connection, Limits};
pub use super::node_client::{NodeInfo, NodeState};

/// The schema name carried by `--json` output.
pub const SCHEMA: &str = "native.status.v1";
/// The target recovery point, if the node does not say (it always does).
const DEFAULT_RPO_SECONDS: u64 = 300;
/// Most recent held writes listed.
const RECENT_WRITES: usize = 5;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Degraded,
    Down,
}

#[derive(Debug, Serialize)]
pub struct ModeInfo {
    /// `reachable`, `unreachable`, `auth_refused`, `protocol_failed`,
    /// `revision_unsupported`, or `unknown` (the node does not track it).
    pub hosted: String,
    /// `local_copy` (serving reads from the copy), `status_only` or `none`.
    pub serving: String,
    pub status_only_reason: Option<String>,
    pub summary: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshFailure {
    pub class: Option<String>,
    pub detail: Option<String>,
    pub at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LocalCopy {
    /// The copy is serving local reads.
    pub serving: bool,
    /// An accepted copy exists (it may not be serving yet).
    pub accepted: bool,
    /// `fresh`, `beyond_rpo` or `unavailable` (the node's own word), or
    /// `stale_revision` while following is paused for a newer interchange revision.
    pub freshness: String,
    pub age_seconds: Option<u64>,
    /// Where `age_seconds` came from: `freshness` (the serving copy) or
    /// `accepted_generation` (when the copy is not serving).
    pub age_basis: Option<String>,
    pub rpo_seconds: u64,
    /// `true` past the RPO or while following is paused, `false` within it,
    /// `null` when it cannot be said (no age).
    pub stale: Option<bool>,
    /// Following hosted is paused (hosted uses a newer interchange revision).
    pub following_paused: bool,
    pub last_refresh_failure: Option<RefreshFailure>,
    pub consecutive_failures: Option<u64>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HeldWrite {
    pub operation: String,
    pub title: Option<String>,
    pub state: String,
    pub reason: Option<String>,
    pub accepted_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct HeldWrites {
    /// Writes needing attention: pending, hosted_pending, uncertain, not_sent,
    /// refused and unrecognised.
    pub waiting: u64,
    pub pending: u64,
    pub oldest_accepted_at: Option<String>,
    pub counts: BTreeMap<String, u64>,
    /// The most recent writes, newest first, up to five. Never bodies.
    pub recent: Vec<HeldWrite>,
    /// Writes beyond `recent`.
    pub more: u64,
    /// `false` when this node cannot list its newest writes (an older node that
    /// ignores `order` and returned only its oldest ones): `recent` is then empty.
    pub recent_available: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceInfo {
    /// The `native service status` line.
    pub line: String,
    pub installed: Option<bool>,
    pub running: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub health: Health,
    pub exit_code: i32,
    pub node: NodeInfo,
    pub mode: Option<ModeInfo>,
    pub local_copy: Option<LocalCopy>,
    pub held_writes: Option<HeldWrites>,
    pub account: Option<String>,
    pub service: Option<ServiceInfo>,
    /// Why the status is not healthy, one short sentence each.
    pub problems: Vec<String>,
}

pub struct StatusOptions {
    pub config_dir: PathBuf,
    /// How long to wait for the node to connect and to answer each call.
    pub timeout: Duration,
    /// The service line, gathered by the caller (it asks the service manager).
    pub service: Option<ServiceInfo>,
}

// ---- reading the node -------------------------------------------------------------

/// What reading the node produced.
struct Observed {
    standby: Result<Value, String>,
    node: Value,
}

/// Collect a [`Report`]. Never fails: every failure is a state in the report.
pub async fn collect(options: StatusOptions) -> Report {
    collect_with(options, Limits::standard()).await
}

async fn collect_with(options: StatusOptions, limits: Limits) -> Report {
    let StatusOptions {
        config_dir,
        timeout,
        service,
    } = options;
    let config_path = config_dir.join(crate::native_cli::setup::NODE_FILE);
    let config = match read_config(&config_path) {
        Ok(config) => config,
        Err(node) => return report_down(node, service),
    };
    let socket = config.socket_path();
    match observe(&config_path, &socket, timeout, &limits).await {
        Ok(observed) => build(&config_path, &socket, observed, service),
        Err(node) => report_down(node, service),
    }
}

fn report_down(node: NodeInfo, service: Option<ServiceInfo>) -> Report {
    let mut problems = vec![node
        .detail
        .clone()
        .unwrap_or_else(|| "the node cannot be read".into())];
    problems.dedup();
    Report {
        schema: SCHEMA,
        health: Health::Down,
        exit_code: 2,
        node,
        mode: None,
        local_copy: None,
        held_writes: None,
        account: None,
        service,
        problems,
    }
}

async fn observe(
    config_path: &Path,
    socket: &Path,
    timeout: Duration,
    limits: &Limits,
) -> Result<Observed, NodeInfo> {
    let here = |state, detail: String| down(state, detail, Some(config_path), Some(socket));
    let mut node = Connection::open("native status", config_path, socket, timeout, limits).await?;
    node.initialize("native-status", "2025-06-18").await?;
    let standby_call = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"standby_status","arguments":{}}});
    let standby_reply = node
        .exchange(standby_call, false)
        .await
        .map_err(|why| node.not_answering(&why))?;
    let node_call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"node_status","arguments":{"limit":RECENT_WRITES,"order":"newest_first"}}});
    let node_reply = node
        .exchange(node_call, false)
        .await
        .map_err(|why| node.not_answering(&why))?;

    let node = structured(&node_reply).map_err(|why| {
        here(
            NodeState::StatusUnavailable,
            format!("the node could not report its status: {why}"),
        )
    })?;
    Ok(Observed {
        standby: structured(&standby_reply),
        node,
    })
}

// ---- building the report (pure) --------------------------------------------------------------

fn text_of(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn seconds_between(earlier: &str, later: &str) -> Option<u64> {
    let a = chrono::DateTime::parse_from_rfc3339(earlier).ok()?;
    let b = chrono::DateTime::parse_from_rfc3339(later).ok()?;
    u64::try_from(b.signed_duration_since(a).num_seconds()).ok()
}

fn count_of(value: &Value, pointer: &str) -> u64 {
    value.pointer(pointer).and_then(Value::as_u64).unwrap_or(0)
}

/// Build the report from the two replies' `structuredContent`.
fn build(
    config_path: &Path,
    socket: &Path,
    observed: Observed,
    service: Option<ServiceInfo>,
) -> Report {
    let Observed { standby, node } = observed;
    let mut problems = Vec::new();

    // --- hosted and local copy ---
    // Healthy needs positive evidence of every condition below; a missing or
    // unknown field is a problem, with its reason, never a pass.
    let hosted_state = text_of(&node, "/hosted/health");
    let hosted_revision = node.pointer("/hosted/revision_unsupported") == Some(&Value::Bool(true));
    let hosted_checked = node.pointer("/hosted/checked") == Some(&Value::Bool(true));
    let (copy, standby_note) = match &standby {
        Ok(status) => (Some(local_copy(status, hosted_revision)), None),
        Err(why) => (None, Some(why.clone())),
    };
    let hosted = match hosted_state {
        // `reachable` before the first probe is only the node's starting assumption.
        Some(state) if state == "reachable" && !hosted_checked => "not_checked".to_owned(),
        Some(state) => state,
        None => "unknown".to_owned(),
    };
    let mode = mode_info(
        &hosted,
        standby.as_ref().ok(),
        copy.as_ref(),
        standby_note.as_deref(),
    );

    match hosted.as_str() {
        "reachable" => {}
        "unreachable" => problems.push("hosted Native is unreachable".to_owned()),
        "auth_refused" => problems
            .push("hosted Native refused the node's credentials; run `native login`".to_owned()),
        "protocol_failed" => problems.push("hosted Native answered unexpectedly".to_owned()),
        "revision_unsupported" => {
            problems.push("hosted uses a newer interchange revision; upgrade native".to_owned())
        }
        "not_checked" => problems
            .push("hosted has not been checked yet (the node probes about every 30 s)".to_owned()),
        _ => problems.push("the node did not report hosted health".to_owned()),
    }
    match (&copy, standby.as_ref().ok()) {
        (Some(copy), Some(status)) => {
            if !copy.serving {
                problems.push(match &mode.status_only_reason {
                    Some(reason) => format!("the local copy is not serving ({reason})"),
                    None => "the local copy is not serving".to_owned(),
                });
            }
            if copy.following_paused {
                problems.push(
                    "following hosted is paused (newer interchange revision); the local copy is stale"
                        .to_owned(),
                );
            } else if copy.stale == Some(true) {
                problems.push("the local copy is stale (beyond the recovery target)".to_owned());
            } else if copy.serving && copy.freshness != "fresh" {
                problems.push(format!(
                    "the local copy's freshness is not confirmed ({})",
                    copy.freshness
                ));
            } else if copy.serving && copy.age_seconds.is_none() {
                problems.push("the node did not report the local copy's age".to_owned());
            }
            // Every degradation flag the node reports, by its own name.
            match status.get("degraded") {
                Some(Value::Bool(false)) => {}
                Some(Value::Bool(true)) => {
                    problems.push("the local copy reports itself degraded".to_owned())
                }
                _ => problems
                    .push("the node did not report whether the local copy is degraded".to_owned()),
            }
            for reason in &copy.degraded_reasons {
                problems.push(format!("local copy: {reason}"));
            }
            if status
                .get("degraded_reasons")
                .and_then(Value::as_array)
                .is_none()
            {
                problems
                    .push("the node did not list the local copy's degradation reasons".to_owned());
            }
            if copy.serving && status.get("consumer_compatible") != Some(&Value::Bool(true)) {
                problems.push("the local copy's reader compatibility is not confirmed".to_owned());
            }
            if status.pointer("/refresh/controller_available") != Some(&Value::Bool(true)) {
                problems.push("the refresh controller is not available".to_owned());
            }
            if text_of(status, "/refresh/diagnostics").as_deref() != Some("available") {
                problems.push(format!(
                    "refresh diagnostics are {}",
                    text_of(status, "/refresh/diagnostics")
                        .unwrap_or_else(|| "not reported".into())
                ));
            }
            match copy.consecutive_failures {
                Some(0) => {}
                Some(_) => problems.push("the last refresh failed".to_owned()),
                None => problems.push("the node did not report refresh failures".to_owned()),
            }
        }
        _ => problems.push("no local copy is configured or readable".to_owned()),
    }

    // --- held writes ---
    let held = held_writes(&node);
    // Every count the "none waiting" claim rests on must be there.
    let counted = node
        .pointer("/held_writes/matched")
        .is_some_and(Value::is_u64)
        && node
            .pointer("/held_writes/counts")
            .is_some_and(Value::is_object)
        && node
            .pointer("/held_writes/writes")
            .is_some_and(Value::is_array)
        && node.pointer("/queue/pending").is_some_and(Value::is_u64);
    if !counted {
        problems.push("the node did not report its held writes".to_owned());
    }
    if held.waiting > 0 {
        problems.push(format!(
            "{} held write{} waiting",
            held.waiting,
            if held.waiting == 1 { "" } else { "s" }
        ));
    }

    let account = text_of(&node, "/account_id").or_else(|| {
        standby
            .as_ref()
            .ok()
            .and_then(|s| text_of(s, "/account_id"))
    });
    if account.is_none() {
        problems.push("the node did not report its account".to_owned());
    }
    problems.dedup();
    let health = if problems.is_empty() {
        Health::Healthy
    } else {
        Health::Degraded
    };
    Report {
        schema: SCHEMA,
        health,
        exit_code: if health == Health::Healthy { 0 } else { 1 },
        node: NodeInfo {
            state: NodeState::Running,
            detail: None,
            config: Some(config_path.display().to_string()),
            socket: Some(socket.display().to_string()),
        },
        mode: Some(mode),
        local_copy: copy,
        held_writes: Some(held),
        account,
        service,
        problems,
    }
}

fn mode_info(
    hosted: &str,
    standby: Option<&Value>,
    copy: Option<&LocalCopy>,
    standby_note: Option<&str>,
) -> ModeInfo {
    let status_only_reason = standby.and_then(|s| text_of(s, "/status_only/reason"));
    let serving = match copy {
        Some(copy) if copy.serving => "local_copy",
        Some(_) => "status_only",
        None => "none",
    };
    let hosted_phrase = match hosted {
        "reachable" => "hosted reachable",
        "unreachable" => "hosted unreachable",
        "auth_refused" => "hosted refused the node's credentials",
        "protocol_failed" => "hosted answered unexpectedly",
        "revision_unsupported" => "hosted uses a newer interchange revision",
        "not_checked" => "hosted not yet checked",
        _ => "hosted state not reported",
    };
    let local_phrase = match (serving, hosted) {
        ("local_copy", "unreachable") => "serving local reads".to_owned(),
        ("local_copy", "revision_unsupported") => {
            "local reads are stale until the node is upgraded".to_owned()
        }
        ("local_copy", _) => "local copy serving".to_owned(),
        ("status_only", _) => match &status_only_reason {
            Some(reason) => format!("status only, not serving local reads ({reason})"),
            None => "status only, not serving local reads".to_owned(),
        },
        _ => match standby_note {
            Some(note) => format!("no local copy ({note})"),
            None => "no local copy".to_owned(),
        },
    };
    ModeInfo {
        hosted: hosted.to_owned(),
        serving: serving.to_owned(),
        status_only_reason,
        summary: format!("{hosted_phrase}; {local_phrase}"),
    }
}

fn local_copy(status: &Value, hosted_revision_unsupported: bool) -> LocalCopy {
    let serving = text_of(status, "/mode").as_deref() == Some("standby");
    let rpo = status
        .pointer("/freshness/target_rpo_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_RPO_SECONDS);
    let freshness = text_of(status, "/freshness/state").unwrap_or_else(|| "unavailable".into());
    let reasons: Vec<String> = status
        .get("degraded_reasons")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    // The node says so itself (`node_health`, a degraded reason); so does the
    // `hosted` block of `node_status`.
    let following_paused = hosted_revision_unsupported
        || text_of(status, "/node_health/state").as_deref() == Some("revision_unsupported")
        || status.pointer("/node_health/local_reads_stale") == Some(&Value::Bool(true))
        || reasons.iter().any(|r| r == "revision_unsupported");

    let accepted_source = if serving {
        "/serving_generation"
    } else {
        "/accepted_generation"
    };
    let accepted = status
        .get(accepted_source.trim_start_matches('/'))
        .is_some_and(Value::is_object);
    let (age_seconds, age_basis) = match status
        .pointer("/freshness/age_seconds")
        .and_then(Value::as_u64)
    {
        Some(age) => (Some(age), Some("freshness".to_owned())),
        // A serving copy's age is the node's own `freshness.age_seconds`, or unknown.
        None if serving => (None, None),
        None => {
            // Not serving: the accepted copy still says when it last matched hosted.
            let synced = text_of(status, &format!("{accepted_source}/synced_at"))
                .or_else(|| text_of(status, &format!("{accepted_source}/captured_at")));
            let observed = text_of(status, "/observed_at");
            match (synced, observed) {
                (Some(synced), Some(observed)) => seconds_between(&synced, &observed)
                    .map_or((None, None), |age| {
                        (Some(age), Some("accepted_generation".to_owned()))
                    }),
                _ => (None, None),
            }
        }
    };
    // While following is paused the copy is stale whatever its age says (the
    // node says as much); the age is kept as a fact, never as a verdict.
    let freshness = if following_paused {
        "stale_revision".to_owned()
    } else {
        freshness
    };
    let stale = if following_paused {
        Some(true)
    } else {
        match (freshness.as_str(), age_seconds) {
            ("beyond_rpo", _) => Some(true),
            // "fresh" is only a claim without an age to show for it.
            ("fresh", Some(_)) => Some(false),
            ("fresh", None) => None,
            (_, Some(age)) => Some(age > rpo),
            _ => None,
        }
    };

    let failure = text_of(status, "/refresh/last_failure_class");
    let detail = text_of(status, "/refresh/last_failure").map(|d| clean(&d, 200));
    let last_refresh_failure = if failure.is_some() || detail.is_some() {
        Some(RefreshFailure {
            class: failure,
            detail,
            at: text_of(status, "/refresh/last_attempt_at"),
        })
    } else {
        None
    };
    LocalCopy {
        serving,
        accepted,
        freshness,
        age_seconds,
        age_basis,
        rpo_seconds: rpo,
        stale,
        following_paused,
        last_refresh_failure,
        consecutive_failures: status
            .pointer("/refresh/consecutive_failure_count")
            .and_then(Value::as_u64),
        degraded_reasons: reasons,
    }
}

fn held_writes(node: &Value) -> HeldWrites {
    let counts_value = node
        .pointer("/held_writes/counts")
        .and_then(Value::as_object);
    let mut counts: BTreeMap<String, u64> = counts_value
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n)))
                .collect()
        })
        .unwrap_or_default();
    // Open "uncertain" writes that were never held show only in the journal counts.
    let uncertain = count_of(node, "/entry_counts/uncertain");
    if uncertain > counts.get("uncertain").copied().unwrap_or(0) {
        counts.insert("uncertain".into(), uncertain);
    }
    let unrecognised = node
        .get("unrecognised")
        .and_then(Value::as_array)
        .map_or(0, |list| list.len() as u64);
    if unrecognised > 0 {
        counts.insert("unrecognised".into(), unrecognised);
    }
    let pending = count_of(node, "/queue/pending").max(counts.get("pending").copied().unwrap_or(0));
    let waiting: u64 = [
        "pending",
        "hosted_pending",
        "uncertain",
        "not_sent",
        "refused",
        "unrecognised",
    ]
    .iter()
    .map(|state| {
        if *state == "pending" {
            pending
        } else {
            counts.get(*state).copied().unwrap_or(0)
        }
    })
    .sum();

    // Newest first, never bodies: only these named fields are read.
    let writes = node
        .pointer("/held_writes/writes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = node
        .pointer("/held_writes/matched")
        .and_then(Value::as_u64)
        .unwrap_or(writes.len() as u64);
    // The node lists newest first when asked (`order`); an older node lists
    // oldest first, so reverse what it sent.
    let newest_first = text_of(node, "/held_writes/order").as_deref() == Some("newest_first");
    let truncated = total > writes.len() as u64;
    let (ordered, recent_available): (Vec<&Value>, bool) = if newest_first {
        (writes.iter().collect(), true)
    } else if !truncated {
        // The whole list came back oldest first: its tail is the newest.
        (writes.iter().rev().collect(), true)
    } else {
        // An older node that ignored `order` sent the oldest few of many: the
        // newest cannot be told from this, so none are listed.
        (Vec::new(), false)
    };
    let recent: Vec<HeldWrite> = ordered
        .into_iter()
        .take(RECENT_WRITES)
        .map(|write| HeldWrite {
            operation: text_of(write, "/operation")
                .map(|s| clean(&s, 60))
                .unwrap_or_else(|| "unknown".into()),
            title: text_of(write, "/title").map(|s| clean(&s, 80)),
            state: text_of(write, "/state")
                .map(|s| clean(&s, 30))
                .unwrap_or_else(|| "unknown".into()),
            reason: text_of(write, "/reason").map(|s| clean(&s, 60)),
            accepted_at: text_of(write, "/accepted_at"),
        })
        .collect();
    let more = if recent_available {
        total.saturating_sub(recent.len() as u64)
    } else {
        0
    };
    HeldWrites {
        waiting,
        pending,
        // The oldest across every state `waiting` counts; older nodes only
        // report the send queue's.
        oldest_accepted_at: text_of(node, "/queue/oldest_waiting_accepted_at")
            .or_else(|| text_of(node, "/queue/oldest_accepted_at")),
        counts,
        recent,
        more,
        recent_available,
    }
}

// ---- rendering --------------------------------------------------------------------------------

/// `5m 12s`, `2h 3m`, `1d 4h`.
pub fn human_age(seconds: u64) -> String {
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m {}s", seconds / 60, seconds % 60),
        3600..=86_399 => format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60),
        _ => format!("{}d {}h", seconds / 86_400, (seconds % 86_400) / 3600),
    }
}

/// The short human text. The first line is always the node line.
pub fn render_text(report: &Report) -> String {
    let mut out = Vec::new();
    if report.node.state != NodeState::Running {
        out.push(format!(
            "Native node: {}",
            report
                .node
                .detail
                .clone()
                .unwrap_or_else(|| "cannot be read".into())
        ));
        if let Some(service) = &report.service {
            out.push(format!("Service:     {}", service.line));
        }
        return out.join("\n");
    }
    let account = report.account.as_deref().unwrap_or("account not reported");
    out.push(format!(
        "Native node: running, {}",
        match report.health {
            Health::Healthy => format!("healthy ({account})"),
            _ => format!("needs attention ({account})"),
        }
    ));
    if let Some(mode) = &report.mode {
        out.push(format!("Mode:        {}", mode.summary));
    }
    if let Some(copy) = &report.local_copy {
        out.push(format!("Local copy:  {}", copy_line(copy)));
        if let Some(failure) = &copy.last_refresh_failure {
            let mut line = String::from("             last refresh failed");
            if let Some(class) = &failure.class {
                line.push_str(&format!(" ({class})"));
            }
            if let Some(detail) = &failure.detail {
                line.push_str(&format!(": {detail}"));
            }
            if let Some(n) = copy.consecutive_failures.filter(|n| *n > 1) {
                line.push_str(&format!(" [{n} in a row]"));
            }
            out.push(line);
        }
    } else {
        out.push("Local copy:  none".to_owned());
    }
    if let Some(held) = &report.held_writes {
        out.push(format!("Held writes: {}", held_line(held)));
        for write in &held.recent {
            let mut line = format!("             - {}", write.operation);
            if let Some(title) = &write.title {
                line.push_str(&format!(" \"{title}\""));
            }
            line.push_str(&format!(": {}", write.state));
            if let Some(reason) = &write.reason {
                line.push_str(&format!(" ({reason})"));
            }
            out.push(line);
        }
        if !held.recent_available {
            out.push(
                "             recent writes unavailable from this node version; restart the node after upgrading"
                    .to_owned(),
            );
        }
        if held.more > 0 {
            out.push(format!(
                "             ... and {} more (see node_status)",
                held.more
            ));
        }
    }
    if let Some(service) = &report.service {
        out.push(format!("Service:     {}", service.line));
    }
    out.join("\n")
}

fn copy_line(copy: &LocalCopy) -> String {
    let rpo = human_age(copy.rpo_seconds);
    let age = copy.age_seconds.map(human_age);
    let main = match (copy.serving, &age) {
        (true, Some(age)) => format!("synced {age} ago"),
        (true, None) => "serving, age unknown".to_owned(),
        (false, Some(age)) if copy.accepted => {
            format!("not serving; accepted copy synced {age} ago")
        }
        (false, _) if copy.accepted => "not serving; accepted copy of unknown age".to_owned(),
        (false, _) => "no accepted copy yet".to_owned(),
    };
    let verdict = if copy.following_paused {
        "stale: following is paused because hosted uses a newer interchange revision".to_owned()
    } else {
        match (copy.stale, copy.serving) {
            (Some(true), true) => format!("stale, beyond the {rpo} target"),
            (Some(false), true) => format!("fresh, within the {rpo} target"),
            // A copy that is not serving is not "fresh": only its age is known.
            (Some(true), false) => format!("older than the {rpo} target"),
            (Some(false), false) => format!("age within the {rpo} target"),
            (None, _) => "freshness unknown".to_owned(),
        }
    };
    format!("{main} ({verdict})")
}

fn held_line(held: &HeldWrites) -> String {
    if held.waiting == 0 && held.recent.is_empty() {
        return "none waiting".to_owned();
    }
    let mut parts = Vec::new();
    for state in [
        "pending",
        "hosted_pending",
        "uncertain",
        "not_sent",
        "refused",
        "unrecognised",
    ] {
        let n = if state == "pending" {
            held.pending
        } else {
            held.counts.get(state).copied().unwrap_or(0)
        };
        if n > 0 {
            parts.push(format!("{n} {state}"));
        }
    }
    let mut line = if held.waiting == 0 {
        "none waiting".to_owned()
    } else {
        format!("{} waiting", held.waiting)
    };
    if !parts.is_empty() {
        line.push_str(&format!(" ({})", parts.join(", ")));
    }
    if let Some(oldest) = &held.oldest_accepted_at {
        line.push_str(&format!("; oldest accepted {oldest}"));
    }
    line
}

/// The `native service status` line, as a [`ServiceInfo`], or `None` when the
/// service manager cannot be consulted at all.
pub fn service_info(config_dir: &Path) -> Option<ServiceInfo> {
    use crate::native_cli::service::{self, Installed};
    let ctx = service::ServiceContext::detect(config_dir, false).ok()?;
    let report = service::status(&ctx, &service::SystemRunner).ok()?;
    Some(ServiceInfo {
        line: report.to_string(),
        installed: Some(report.installed == Installed::Ours),
        running: report.running,
    })
}

#[cfg(test)]
pub(crate) mod tests;
