//! Run keys — `handle-disambiguator-run_id` (spec fbfaf25 §3.2, §3.3, §3.4).
//!
//! ## A run key is a hashtag, not a session token
//!
//! That is the whole model, and every rule below follows from it. Bootstrap is
//! the sole product surface that issues a key, but a hashtag can also be invented,
//! two people can collide on one, and its meaning comes entirely from consistent
//! use.
//!
//! Concretely:
//!
//! - There is **no issuance event and no registry**. A key becomes real by being
//!   used; `MIN(created_at) WHERE run_key = ?` is its birth.
//! - **Any legal key is accepted by run-participating tools, always** — including
//!   one the agent invented and this server has never seen. A self-minted key is
//!   not grudgingly tolerated but correct: correlation does not need authority,
//!   and an invented key used consistently across forty calls groups those calls
//!   perfectly. QuickStart is the intentional exception: it accepts no run key.
//! - `bootstrap` mints one for the caller to carry through the run; QuickStart
//!   is callable beforehand but deliberately does not establish run context.
//!
//! The wordlist is the syntax rule that makes typos loud. That is the entire
//! extent of the server's involvement.
//!
//! ## Validated for shape and membership, NEVER for liveness
//!
//! Three hyphen-separated tokens: a handle in [`HANDLES`], a disambiguator in
//! [`DISAMBIGUATORS`], and a six-character lowercase Crockford Base32 run id.
//! That is all. *"Has this key been seen before?"* is never asked on the accept path.
//!
//! This is the seam where a registry creeps in, so it is worth naming: the moment
//! newness becomes a **decision** rather than a **remark**, a sessions table has
//! been built without anyone deciding to build one. Nobody decides to build a
//! sessions table — they decide to check whether a key is valid.
//!
//! ## Fail-open is an invariant, not a nicety
//!
//! A malformed key is recorded as NULL, the raw string is kept verbatim in the
//! logged `arguments`, and **the call still succeeds**. Rejecting it would make
//! the read log the reason a tool fails, which is precisely the outcome fail-open
//! exists to prevent. [`validate`] therefore has no error path: every input
//! produces an outcome, and the worst outcome is a null key with a repair hint.
//!
//! ## What validation does NOT catch
//!
//! A hallucinated-but-legal key — `scout-chair-b748b2` where the real key was
//! `scout-chair-a748b2` — passes every check here, because it is a valid key. Worth
//! stating plainly rather than letting a reader assume shape checking covers it.
//! Three things soften it, none of which is a check:
//!
//!   1. It is a symptom of ABSENCE, not of bad copying. Reproducing a structured
//!      key already in context is among the most reliable copying a model
//!      does; confabulation arises when the key is *not* in context. So omission
//!      and hallucination are one failure with two outputs, and echoing the key
//!      on every response is the mitigation for both — it prevents the loss
//!      rather than detecting its consequence.
//!   2. Two-level identity absorbs most of the damage: `scout-chair-b748b2`
//!      preserves `scout-chair`. Agent identity survives; only the run boundary breaks.
//!      The loss is run *precision*, not the run.
//!   3. It has a signature in the raw rows — one call under a key, same agent key,
//!      temporally interleaved with a different key on the same credential,
//!      usually sharing a prefix. Readable only while the no-folding constraint
//!      holds.
//!
//! ## Why the key IS required — and why that is not a gate
//!
//! Amended 1 Aug 2026 (proposal ecc586d), reversing fbfaf25 §3.2's position.
//! Read that section before touching this: it gives four arguments for
//! optionality and they are good ones. What changed is not that they were
//! refuted but that `"new"` and declarative-only requiring answer three of them.
//!
//! `run_key` is now in each tool's `required` array. That is a **capture**
//! decision, never a **trust** decision — 33b4e59's own carve-out — and it is
//! enforced *nowhere in this server*. Nothing validates schemas here; run
//! context is stripped before a handler's serde ever sees it. So the required
//! array is a statement to the CLIENT, read at call-construction time, which is
//! the one channel a harness cannot discard the way it discards server
//! `instructions`. An absent key still resolves to null, still falls through to
//! rung 3, still gets the nudge. **Required in the schema, fail-open in the
//! server**: the forcing function without the gate.
//!
//! That is what preserves §3.2's arguments 3 and 4. The free instrument
//! survives, because clients that ignore the schema still produce nulls to
//! count. Curl, one-shot scripts and the human-facing workbench keep working,
//! because nothing refuses them.
//!
//! §3.2's argument 2 — the decisive one — is that requiring converts visible
//! absence into invisible wrongness, since an agent compelled to supply
//! something invents a plausible key, and the garbage version of a run key IS a
//! valid key. `"new"` is the answer: it redirects the lazy path from
//! fabrication to honesty, and being retained verbatim in `arguments` it is
//! *more* legible than null, which conflates "does not know about keys" with
//! "harness stripped it".
//!
//! What is NOT answered: the same key supplied forever, a working day
//! collapsing into one hyperedge. That failure is orthogonal to requiring, and
//! it remains a read-time problem.

use std::collections::HashSet;

use rand::Rng;
use sqlx::Row;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;
use crate::wordlist::{nearest, DISAMBIGUATORS, HANDLES, MIN_DISTANCE};

/// The one value a caller with no key can always supply. Required-ness is only
/// safe because this exists: it makes the argument trivially satisfiable, so
/// the schema can compel an answer without any call ever being refused.
pub const SENTINEL: &str = "new";
pub const AGENT_KEY_SENTINEL_PREFIX: &str = "new:";
pub const RUN_ID_LEN: usize = 6;
const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// What validating a supplied key produced.
///
/// Note there is no `Err` variant and no `Result`: rejecting a call over a
/// malformed key is the one thing this module must never cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyOutcome {
    /// No key supplied. Still honest, still recoverable at read time — but no
    /// longer the *expected* case, since the schema now asks for `"new"` from a
    /// caller who has nothing to carry.
    Absent,
    /// The `"new"` sentinel: the caller said, in the one place the schema makes
    /// them say something, that they are not carrying a key. Resolved to
    /// [`KeyOutcome::Minted`] by the async layer — minting needs a read, and
    /// validation is a pure function on purpose (fbfaf25 §3.2).
    Requested { agent_key: Option<String> },
    /// A key minted in response to [`KeyOutcome::Requested`]. Stored exactly
    /// like a supplied one; distinguished only so the echo can hand it back.
    Minted(String),
    /// Shape and membership hold. Accepted, with no liveness question asked.
    Valid(String),
    /// Recorded as null; the raw string is preserved in the logged arguments.
    Malformed {
        raw: String,
        complaint: String,
        /// Present when the garble was a single character away from exactly one
        /// valid word — which the distance floor guarantees is unambiguous.
        suggestion: Option<String>,
    },
}

impl KeyOutcome {
    /// The key as it should be STORED: `Some` once there is a real key to
    /// stamp. `Requested` is deliberately absent here — an unresolved sentinel
    /// must never reach a row, and the async layer is what resolves it.
    pub fn stored(&self) -> Option<&str> {
        match self {
            KeyOutcome::Valid(key) | KeyOutcome::Minted(key) => Some(key),
            _ => None,
        }
    }

    /// The caller-facing note, if there is anything worth saying. `None` on both
    /// the absent and the valid paths — silence is the normal case.
    pub fn note(&self) -> Option<String> {
        match self {
            // The whole point of the sentinel: a caller who arrives with
            // nothing leaves with a key and instructions, in one call, without
            // having had to know `bootstrap` existed.
            KeyOutcome::Minted(key) => Some(format!(
                "Minted run key '{key}' for this run. Pass it as run_key on every \
                 subsequent call, reads included, so this run's activity stays one \
                 selectable set."
            )),
            KeyOutcome::Malformed {
                raw,
                complaint,
                suggestion,
            } => Some(match suggestion {
                Some(fix) => format!(
                    "run key '{raw}' was not recorded: {complaint}. Did you mean '{fix}'? \
                     Use the corrected key as run_key on every subsequent call in this run."
                ),
                None => format!(
                    "run key '{raw}' was not recorded: {complaint}. Call bootstrap to obtain \
                     a valid key, then pass the same run_key on every subsequent call."
                ),
            }),
            _ => None,
        }
    }

    /// Parent-key repair feedback. A parent is always an already-existing run,
    /// so its guidance must never suggest minting or reusing `run_key`'s
    /// sentinel semantics.
    pub(crate) fn parent_note(&self) -> Option<String> {
        let KeyOutcome::Malformed {
            raw,
            complaint,
            suggestion,
        } = self
        else {
            return None;
        };
        Some(match suggestion {
            Some(fix) => format!(
                "parent key '{raw}' was not recorded: {complaint}. Did you mean '{fix}'? \
                 Use the corrected key as parent_key."
            ),
            None if raw == SENTINEL => format!(
                "parent key '{raw}' was not recorded: {complaint}. Pass the existing parent \
                 run's full key as parent_key; parent_key does not support the 'new' sentinel."
            ),
            None => format!(
                "parent key '{raw}' was not recorded: {complaint}. Pass an existing valid full \
                 key as parent_key."
            ),
        })
    }
}

/// Validate a supplied run key for SHAPE and MEMBERSHIP. Never for liveness.
/// The run-only issuance sentinel is recognized before ordinary key validation.
pub fn validate(raw: Option<&str>) -> KeyOutcome {
    match raw {
        None => KeyOutcome::Absent,
        Some(raw) if raw == SENTINEL => KeyOutcome::Requested { agent_key: None },
        Some(raw) if raw.starts_with(AGENT_KEY_SENTINEL_PREFIX) => {
            let agent_key = &raw[AGENT_KEY_SENTINEL_PREFIX.len()..];
            match validate_agent_key(agent_key) {
                Ok(()) => KeyOutcome::Requested {
                    agent_key: Some(agent_key.to_string()),
                },
                Err(outcome) => outcome,
            }
        }
        Some(raw) => validate_string(raw),
    }
}

/// Validate a full run key with no issuance-sentinel semantics.
///
/// Query targets and lineage assertions refer to a key that is already fully
/// specified, so the run-only `"new"` sentinel must be treated as malformed.
pub(crate) fn validate_full(raw: Option<&str>) -> KeyOutcome {
    match raw {
        None => KeyOutcome::Absent,
        Some(raw) => validate_string(raw),
    }
}

/// Validate `run_key`, including its one caller-facing issuance sentinel.
pub(crate) fn validate_run_key_value(raw: Option<&serde_json::Value>) -> KeyOutcome {
    validate_value(raw)
}

/// Validate `parent_key` as an existing full key. Giving this path its own API
/// keeps the run-only sentinel out of lineage validation by construction.
pub(crate) fn validate_parent_key_value(raw: Option<&serde_json::Value>) -> KeyOutcome {
    validate_plain_value(raw)
}

/// Validate an exact JSON run-key value, including its issuance sentinel.
/// Non-strings are malformed, fail open, and stay untouched in
/// `ToolCallOutcome::original_arguments`.
pub fn validate_value(raw: Option<&serde_json::Value>) -> KeyOutcome {
    match raw {
        Some(serde_json::Value::String(raw)) => validate(Some(raw)),
        _ => validate_plain_value(raw),
    }
}

/// Validate a JSON value strictly as a full key, with no sentinel semantics.
fn validate_plain_value(raw: Option<&serde_json::Value>) -> KeyOutcome {
    match raw {
        None => KeyOutcome::Absent,
        Some(serde_json::Value::String(raw)) => validate_full(Some(raw)),
        Some(raw) => KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: format!("expected a string, got {}", json_kind(raw)),
            suggestion: None,
        },
    }
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn validate_string(raw: &str) -> KeyOutcome {
    if raw.is_empty() {
        return KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: "expected a non-empty handle-disambiguator-run_id string".into(),
            suggestion: None,
        };
    }
    if raw.trim() != raw {
        return KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: "leading or trailing whitespace is not part of handle-disambiguator-run_id"
                .into(),
            suggestion: None,
        };
    }
    if raw.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: "whitespace is not allowed in handle-disambiguator-run_id".into(),
            suggestion: None,
        };
    }

    let tokens: Vec<&str> = raw.split('-').collect();
    if tokens.len() != 3 {
        return KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: format!(
                "expected handle-disambiguator-run_id, got {} hyphen-separated components",
                tokens.len()
            ),
            suggestion: None,
        };
    }

    // Position is structural, so each human-facing token is checked against its
    // own list. The lists deliberately overlap.
    let checks = [
        (tokens[0], &HANDLES[..], "handle"),
        (tokens[1], &DISAMBIGUATORS[..], "disambiguator"),
    ];
    for (index, (token, list, position)) in checks.iter().enumerate() {
        if list.contains(token) {
            continue;
        }
        let (closest, distance) = nearest(token, list);
        // At a floor of MIN_DISTANCE, a distance-1 garble has exactly ONE nearest
        // valid word, so the repair is unambiguous. Beyond that it is a guess,
        // and a confidently wrong suggestion is worse than none.
        let suggestion = (distance < MIN_DISTANCE - 1).then(|| {
            let mut repaired: Vec<&str> = tokens.clone();
            repaired[index] = closest;
            repaired.join("-")
        });
        return KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: format!("the {position} '{token}' is not in the wordlist"),
            suggestion,
        };
    }

    if !valid_run_id(tokens[2]) {
        return KeyOutcome::Malformed {
            raw: raw.to_string(),
            complaint: format!("run id must be {RUN_ID_LEN} lowercase Crockford Base32 characters"),
            suggestion: None,
        };
    }

    KeyOutcome::Valid(raw.to_string())
}

fn validate_agent_key(raw: &str) -> std::result::Result<(), KeyOutcome> {
    let tokens: Vec<&str> = raw.split('-').collect();
    if tokens.len() != 2 {
        return Err(KeyOutcome::Malformed {
            raw: format!("{AGENT_KEY_SENTINEL_PREFIX}{raw}"),
            complaint: "expected new:<handle>-<disambiguator>".into(),
            suggestion: None,
        });
    }
    for (index, (token, list, position)) in [
        (tokens[0], &HANDLES[..], "handle"),
        (tokens[1], &DISAMBIGUATORS[..], "disambiguator"),
    ]
    .iter()
    .enumerate()
    {
        if list.contains(token) {
            continue;
        }
        let (closest, distance) = nearest(token, list);
        let suggestion = (distance < MIN_DISTANCE - 1).then(|| {
            let mut repaired = tokens.clone();
            repaired[index] = closest;
            format!("{AGENT_KEY_SENTINEL_PREFIX}{}", repaired.join("-"))
        });
        return Err(KeyOutcome::Malformed {
            raw: format!("{AGENT_KEY_SENTINEL_PREFIX}{raw}"),
            complaint: format!("the {position} '{token}' is not in the wordlist"),
            suggestion,
        });
    }
    Ok(())
}

fn valid_run_id(value: &str) -> bool {
    value.len() == RUN_ID_LEN && value.bytes().all(|byte| CROCKFORD.contains(&byte))
}

/// The agent handle — word 1 of a valid key.
pub fn handle_of(key: &str) -> &str {
    key.split('-').next().unwrap_or(key)
}

/// The stable agent identity — `handle-disambiguator`.
pub fn agent_key_of(key: &str) -> &str {
    key.rsplit_once('-').map(|(agent, _)| agent).unwrap_or(key)
}

/// Mint an unused candidate key (spec §3.3). Bootstrap and the universal
/// sentinels are convenience minting points, never issuance authorities.
///
/// Collision avoidance is a read, not an allocation. Nothing is reserved or
/// written. Both durable event use and the disposable read log are consulted so
/// an actually used key is never minted again while its evidence exists.
///
/// If the read log is gone, permanent event use is still checked. The exhaustive
/// bounded search returns a key whenever a fresh agent identity exists; it never
/// falls back to a previously observed agent key or a known full-key collision.
pub async fn suggest(db: &Db) -> Result<String> {
    let mut taken = HashSet::new();
    let rows = sqlx::query("SELECT DISTINCT run_key FROM content_events WHERE run_key IS NOT NULL")
        .fetch_all(db.write_pool())
        .await?;
    extend_taken(&mut taken, &rows);

    // The read log is disposable: its absence costs collision information only
    // for read-only runs, never the bootstrap call. Permanent event use is still
    // checked above.
    if let Ok(rows) =
        sqlx::query("SELECT DISTINCT run_key FROM read_log_calls WHERE run_key IS NOT NULL")
            .fetch_all(db.write_pool())
            .await
    {
        extend_taken(&mut taken, &rows);
    }

    mint_fresh_agent_run(&taken)
}

/// Mint a fresh run under a fresh persistent agent identity, given whatever
/// run-key evidence the calling backend can see.
///
/// Bare `new` establishes a fresh persistent identity, not merely a fresh run.
/// Any agent key represented in the supplied evidence is unavailable, even
/// though most of its run-id space remains unused.
///
/// Backends differ only in which evidence tiers they can gather, never in the
/// selection rule; a backend that reimplemented this walk would be a second
/// minting semantics with its own collision behaviour.
pub(crate) fn mint_fresh_agent_run(taken: &HashSet<String>) -> Result<String> {
    let used_agent_keys: HashSet<&str> = taken.iter().map(|key| agent_key_of(key)).collect();

    let agent_count = HANDLES.len() * DISAMBIGUATORS.len();
    let start = rand::rng().random_range(0..agent_count);
    for step in 0..agent_count {
        let index = (start + step) % agent_count;
        let agent_key = format!(
            "{}-{}",
            HANDLES[index / DISAMBIGUATORS.len()],
            DISAMBIGUATORS[index % DISAMBIGUATORS.len()]
        );
        if used_agent_keys.contains(agent_key.as_str()) {
            continue;
        }
        if let Some(key) = first_unused_run(&agent_key, taken, rand::rng().random()) {
            return Ok(key);
        }
    }
    Err(Error::engine("run-key namespace exhausted"))
}

/// Mint a fresh run under an existing validated agent identity, given whatever
/// run-key evidence the calling backend can see.
pub(crate) fn mint_run_for_agent(agent_key: &str, taken: &HashSet<String>) -> Result<String> {
    validate_agent_key(agent_key).map_err(|_| Error::engine("invalid agent key"))?;
    first_unused_run(agent_key, taken, rand::rng().random())
        .ok_or_else(|| Error::engine("run-id namespace exhausted"))
}

/// Mint a fresh run under an existing validated agent identity.
pub async fn suggest_for_agent(db: &Db, agent_key: &str) -> Result<String> {
    validate_agent_key(agent_key).map_err(|_| Error::engine("invalid agent key"))?;
    let mut taken = HashSet::new();
    let pattern = format!("{agent_key}-%");
    let rows = sqlx::query(
        "SELECT DISTINCT run_key FROM content_events WHERE run_key LIKE ? AND run_key IS NOT NULL",
    )
    .bind(&pattern)
    .fetch_all(db.write_pool())
    .await?;
    extend_taken(&mut taken, &rows);
    if let Ok(rows) = sqlx::query(
        "SELECT DISTINCT run_key FROM read_log_calls WHERE run_key LIKE ? AND run_key IS NOT NULL",
    )
    .bind(&pattern)
    .fetch_all(db.write_pool())
    .await
    {
        extend_taken(&mut taken, &rows);
    }
    mint_run_for_agent(agent_key, &taken)
}

fn extend_taken(taken: &mut HashSet<String>, rows: &[sqlx::sqlite::SqliteRow]) {
    taken.extend(
        rows.iter()
            .filter_map(|row| row.try_get::<Option<String>, _>("run_key").ok().flatten()),
    );
}

/// Walk every candidate exactly once from a randomized offset. Unlike retrying
/// random draws, this is bounded AND proof-safe: it returns a free key whenever
/// one exists and never returns a collided key.
fn first_unused_run(agent_key: &str, taken: &HashSet<String>, start: u32) -> Option<String> {
    const SPACE: u32 = 1 << 30;
    for step in 0..SPACE {
        let value = start.wrapping_add(step) & (SPACE - 1);
        let candidate = format!("{agent_key}-{}", encode_run_id(value));
        if !taken.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn encode_run_id(mut value: u32) -> String {
    let mut bytes = [b'0'; RUN_ID_LEN];
    for index in (0..RUN_ID_LEN).rev() {
        bytes[index] = CROCKFORD[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(bytes.to_vec()).expect("Crockford alphabet is ASCII")
}

/// Resolve the intent currently in force for a run (spec §5.2), for the echo.
///
/// Fill-forward partitioned on the WHOLE key, never on the agent key. An agent key
/// is persistent and reusable across runs, so partitioning on it would fill
/// yesterday's intent forward over today's unrelated work — a confident wrong
/// answer produced deterministically. Partitioning on the run returns NULL, which
/// is the honest answer. The run is bounded; the agent key is not; fill-forward needs
/// a bounded partition.
///
/// Reads the disposable tier on purpose, and therefore degrades to `None` rather
/// than failing when the read log is absent. That degradation is correct
/// behaviour, not a defect — it is what keeps the disposability check green.
pub async fn intent_at(db: &Db, run_key: Option<&str>) -> Option<String> {
    let run_key = run_key?;
    sqlx::query(
        "SELECT intent FROM read_log_calls
          WHERE run_key = ? AND tool = 'set_intent' AND outcome = 'ok'
            AND intent IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(run_key)
    .fetch_optional(db.write_pool())
    .await
    .ok()
    .flatten()
    .and_then(|row| row.try_get::<Option<String>, _>("intent").ok().flatten())
}

/// Advisory for a complete, never-seen key that may be a mistyped continuation
/// of a recent run under the same authenticated account and exact agent key.
/// Read-log absence is deliberately indistinguishable from "no advice".
pub async fn displaced_key_note(db: &Db, caller: &Caller) -> Option<String> {
    let run_key = caller.run_key()?;
    let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE run_key = ?")
        .bind(run_key)
        .fetch_one(db.write_pool())
        .await
        .ok()?;
    if seen != 0 {
        return None;
    }
    let agent_key = agent_key_of(run_key);
    let row = sqlx::query(
        "SELECT run_key, MAX(ended_at) AS last_ended
           FROM read_log_calls
          WHERE actor = ? AND run_key <> ? AND run_key LIKE ?
            AND julianday(ended_at) >= julianday('now', '-30 minutes')
          GROUP BY run_key
          ORDER BY last_ended DESC, run_key
          LIMIT 1",
    )
    .bind(caller.credential())
    .bind(run_key)
    .bind(format!("{agent_key}-%"))
    .fetch_optional(db.write_pool())
    .await
    .ok()??;
    let prior: String = row.try_get("run_key").ok()?;
    Some(format!(
        "The supplied run key '{run_key}' is valid but may have displaced recent run key \
         '{prior}' for agent '{agent_key}'. Reuse '{prior}' if this was accidental."
    ))
}

/// The authenticated `actor` to stamp on an event (decision 0ab24f7).
///
/// Run context is an adjacent product field, never an alternate identity:
/// `run_key` carries the exact run and [`handle_of`] derives its display handle,
/// while `actor` remains the credential on every call.
pub fn actor_for(caller: &Caller) -> String {
    caller.credential().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_stays_the_credential_when_a_run_is_present() {
        let caller = Caller::authenticated("acct_test")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        assert_eq!(actor_for(&caller), "acct_test");
        assert_eq!(handle_of(caller.run_key().unwrap()), "scout");
        assert_eq!(agent_key_of(caller.run_key().unwrap()), "scout-chair");
    }

    #[test]
    fn only_run_key_validation_recognizes_the_new_sentinel() {
        let sentinel = serde_json::json!(SENTINEL);
        assert_eq!(
            validate_run_key_value(Some(&sentinel)),
            KeyOutcome::Requested { agent_key: None }
        );
        assert_eq!(
            validate_value(Some(&sentinel)),
            KeyOutcome::Requested { agent_key: None }
        );
        assert_eq!(
            validate(Some("new:scout-chair")),
            KeyOutcome::Requested {
                agent_key: Some("scout-chair".into())
            }
        );

        let parent = validate_parent_key_value(Some(&sentinel));
        let KeyOutcome::Malformed {
            raw,
            complaint,
            suggestion,
        } = parent
        else {
            panic!("parent sentinel must be malformed, got {parent:?}");
        };
        assert_eq!(raw, SENTINEL);
        assert!(complaint.contains("hyphen-separated components"));
        assert_eq!(suggestion, None);

        // Both public run-key APIs preserve their sentinel-aware behavior.
        assert_eq!(
            validate(Some(SENTINEL)),
            KeyOutcome::Requested { agent_key: None }
        );
    }

    #[test]
    fn exhaustive_search_skips_deterministic_collisions() {
        let taken = HashSet::from([
            "scout-chair-000001".to_string(),
            "scout-chair-000002".to_string(),
        ]);

        assert_eq!(
            first_unused_run("scout-chair", &taken, 1).as_deref(),
            Some("scout-chair-000003")
        );
    }

    #[test]
    fn run_id_encoding_is_lowercase_crockford_base32() {
        assert_eq!(encode_run_id(0), "000000");
        assert_eq!(encode_run_id(31), "00000z");
        assert!(valid_run_id("a748b2"));
        assert!(!valid_run_id("a748io"));
    }

    #[tokio::test]
    async fn candidate_generation_avoids_durable_and_disposable_usage() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        sqlx::query(
            "INSERT INTO content_events \
             (id, record_id, type, payload, run_key, created_at, causal_envelope_version, causal_status) \
             VALUES ('evt-1', 'rec-1', 'record.created', '{}', \
                     'scout-chair-a748b2', '2026-01-01T00:00:00Z', 1, 'legacy_unknown')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO read_log_calls \
             (id, tool, run_key, outcome, started_at, ended_at) \
             VALUES ('call-1', 'ping', 'heron-river-b748b2', 'ok', \
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let candidate = suggest(&db).await.unwrap();
        assert_ne!(agent_key_of(&candidate), "scout-chair");
        assert_ne!(agent_key_of(&candidate), "heron-river");

        sqlx::query("DROP TABLE read_log_calls")
            .execute(db.write_pool())
            .await
            .unwrap();
        let without_read_log = suggest(&db).await.unwrap();
        assert_ne!(agent_key_of(&without_read_log), "scout-chair");
    }
}
