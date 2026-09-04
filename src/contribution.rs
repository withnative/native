//! Record-body contribution provenance — one generic projection.
//!
//! # What this answers, and what it deliberately refuses to answer
//!
//! A reader of a record body or a comment utterance wants to know who produced
//! it. That single-sounding question is really six, and the whole point of this
//! module is that they stay six:
//!
//! | Question | Field | Strength |
//! |---|---|---|
//! | For whom / in whose workspace? | `principal` | authenticated |
//! | Was the accepted write produced by a human, an agent, a local process? | `executor.kind` | engine-attested, unforgeable |
//! | Which transport did the server observe? | `channel.kind` | server-observed, weaker than executor |
//! | Which bounded run produced the event? | `run.run_key` | correlation only |
//! | Which event produced the body being read? | `revision` | engine fact |
//! | Was that a different event from creation? | `created_by` | engine fact |
//!
//! **Principal association is not authorship. Authorship is not endorsement. A
//! run correlation handle is not verified persistent identity. Generating an
//! option is not expressing a belief.** Every collapse this module exists to
//! prevent is a collapse of one of those four sentences.
//!
//! ## The one rule that must never bend
//!
//! [`ChannelFacts::display_inference`] is a *rendering* hint. `executor.kind`
//! is an engine attestation. Decision `425a001b` settles that the first may
//! never be written into the second: an ordinary MCP write is almost always an
//! agent, but the counterexample — a person driving an MCP client directly —
//! is real, and turning a good guess into a ledger fact makes that person's
//! own writes permanently misattributed. So they are two separately typed
//! fields on two separate structs, and no code path assigns one from the
//! other.
//!
//! ## Generic, not comment-specific
//!
//! Comments are the first consumer, not the model. Everything here is keyed by
//! record id and body-producing event, so any record surface can adopt it
//! without redesigning the semantics.

use serde::{Deserialize, Serialize};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Capability;
use crate::error::Result;
use crate::mcp::registry::Caller;
use crate::provenance::Channel;

/// The governed facet key that promotes an ordinary `Collection kind:selection`
/// into an exploration. The namespace matters: a bare `selection_role` would be
/// a globally indexed key that unrelated future features would collide with.
pub const SELECTION_ROLE_FACET: &str = "decision.selection_role";
/// The one governed value this slice defines for [`SELECTION_ROLE_FACET`].
pub const ALTERNATIVE_SET_ROLE: &str = "alternative_set";
/// The vocabulary governing [`SELECTION_ROLE_FACET`].
pub const SELECTION_ROLE_VOCABULARY: &str = "selection-role";
/// Directed, open-additive token from a decision to the candidate it chose.
///
/// None of the nine guaranteed interoperability relationships is truthful
/// enough — `relates_to` is too weak, `implements` means realization, and
/// `supersedes` means replacement — so this is deliberately *outside* the
/// guaranteed floor. Generic clients must not infer an inverse.
pub const SELECTS_RELATIONSHIP: &str = "selects";

// ---------------------------------------------------------------------------
// Machine-readable interpretation limitations
// ---------------------------------------------------------------------------

pub const LIMIT_PRINCIPAL_NOT_ENDORSEMENT: &str =
    "principal_association_does_not_establish_endorsement";
pub const LIMIT_RUN_KEY_NOT_IDENTITY: &str = "run_key_does_not_establish_persistent_agent_identity";
pub const LIMIT_CREATION_NOT_STANCE: &str = "content_creation_does_not_establish_stance";
pub const LIMIT_CHANNEL_INFERENCE_NOT_ATTESTED: &str =
    "channel_display_inference_is_not_attested_execution";
pub const LIMIT_DELEGATED_EXECUTION_NOT_AUTHORSHIP: &str =
    "delegated_execution_does_not_establish_principal_authorship";
pub const LIMIT_ALTERNATIVE_SET_FILTERED: &str = "alternative_set_may_be_visibility_filtered";
pub const LIMIT_FIELDS_WITHHELD: &str = "some_contribution_fields_are_unknown_or_withheld";
pub const LIMIT_MEMBERSHIP_UNORDERED: &str = "alternative_set_membership_has_no_authored_order";

/// Assurance vocabulary. `UnknownOrWithheld` is deliberately ONE token for both
/// "the engine never knew" and "the viewer may not see it": a distinguishable
/// absence-versus-denial reason is itself a disclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    /// The engine stamped this itself and no caller could influence it.
    EngineAttested,
    /// The server observed this about its own transport.
    ServerObserved,
    /// Useful for grouping related calls; establishes no persistent identity.
    CorrelationOnly,
    /// Not established, or not disclosable to this viewer. One token for both.
    UnknownOrWithheld,
}

/// A hedged rendering hint. Never an attestation, never `executor.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayInference {
    /// Verified human execution. This one is not a guess — it is echoed from
    /// the attestation so a renderer never has to consult two fields.
    Human,
    /// An unverified MCP write. Richard's reasonable starting assumption, kept
    /// visibly hedged because a person with an MCP credential is the real
    /// counterexample.
    LikelyAgent,
    /// A verified delegated service. Like `Human`, this echoes an attested
    /// executor class for renderers; it never changes `executor.kind`.
    Automated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalRef {
    /// The principal's *person record* id. Never the account credential or
    /// principal token, which are not the viewer's to learn.
    pub id: String,
    pub display_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorFacts {
    /// `human` | `agent` | `delegated_service` | `authenticated_principal` |
    /// `local`, exactly as the engine stamped it. `None` when no attestation
    /// covers the event.
    ///
    /// This field is never derived from [`ChannelFacts::display_inference`].
    pub kind: Option<String>,
    /// Nulled when the executor identity is not the viewer's to see. The
    /// *kind* survives that redaction; the reference does not.
    #[serde(rename = "ref")]
    pub reference: Option<String>,
    pub assurance: Assurance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelFacts {
    /// `web` | `mcp` | `webhook` | `local` | `unknown`. Non-identifying, so it
    /// survives redaction of the principal.
    pub kind: String,
    pub assurance: Assurance,
    /// Separately typed on purpose. A consumer must never receive the hedge in
    /// [`ExecutorFacts::kind`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_inference: Option<DisplayInference>,
}

/// Exact-run correlation. Two runs sharing `agent_key` are still two runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunCorrelation {
    /// The machine speaker id. Always the FULL key — a short suffix is a human
    /// label, never an identity.
    pub run_key: String,
    /// `handle-disambiguator`. Secondary detail; it must not merge two runs
    /// into one thread persona.
    pub agent_key: String,
    pub assurance: Assurance,
}

/// The event that produced the body currently being read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionFacts {
    /// Immutable event id — the durable address. `seq` orders and displays;
    /// it does not address.
    pub event_id: String,
    pub event_type: String,
    pub produced_current_body: bool,
    /// Deep-link input. The server supplies the run key and event id rather
    /// than a fabricated absolute URL, because the route is a client concern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_key: Option<String>,
}

/// The event that created the contribution's identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreationFacts {
    pub event_id: Option<String>,
    /// `Some(true)`/`Some(false)` only when BOTH runs are disclosable to the
    /// viewer. A withheld run yields `None` — never `false`, which would be a
    /// claim the viewer has not earned and may be wrong.
    pub same_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternativeSetContext {
    pub id: String,
    pub label: Option<String>,
    /// Always `alternative_set` in this slice; present so a client dispatches
    /// on data rather than on the collection's kind alone.
    pub role: String,
    /// Members THIS VIEWER can see. Never the true total, which would leak the
    /// existence of records the viewer may not read.
    pub visible_member_count: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionContext {
    /// The `Resolution kind:decision` that selected this candidate.
    pub decision_id: String,
    pub decision_name: Option<String>,
    pub decided_at: String,
    /// Whether the decision is the currently effective one, i.e. nothing
    /// supersedes it.
    pub effective: bool,
}

/// Whether the content is an option, proposal, critique… Creation alone
/// establishes none of these, so this is `None` unless something durable says
/// otherwise.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_set: Option<AlternativeSetContext>,
    /// A selection decision naming this record. Present even for unchosen
    /// siblings' readers, because selection never erases the option history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection: Option<SelectionContext>,
}

/// The generic envelope. One shape for records and comments alike.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionProvenance {
    /// Omitted entirely when the principal's identity record is not visible.
    /// Never replaced by an account token or principal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalRef>,
    pub executor: ExecutorFacts,
    pub channel: ChannelFacts,
    /// Present only for the caller's own run or a disclosable actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<RunCorrelation>,
    pub revision: RevisionFacts,
    pub created_by: CreationFacts,
    #[serde(default)]
    pub context: ContributionContext,
    /// Machine-readable statements about what these fields do NOT establish.
    pub interpretation_limits: Vec<String>,
}

// ---------------------------------------------------------------------------
// Raw facts, gathered before any viewer is considered
// ---------------------------------------------------------------------------

/// One accepted-action attestation covering a content event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedAction {
    pub principal: String,
    pub executor_kind: String,
    pub executor_ref: Option<String>,
    pub channel: Channel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawEventFact {
    pub event_id: String,
    pub event_type: String,
    pub run_key: Option<String>,
    pub actor: Option<String>,
    pub attestation: Option<AttestedAction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawContribution {
    pub current: RawEventFact,
    pub creation: Option<RawEventFact>,
}

/// What this viewer is permitted to learn. Computed once, applied by
/// [`project`], so the disclosure policy is testable without a database.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewerDisclosure {
    /// The principal's person record, when the viewer may see it.
    pub principal: Option<PrincipalRef>,
    /// Whether the executor reference itself is disclosable.
    pub executor_ref_visible: bool,
    /// Whether the current body event's run may be disclosed.
    pub current_run_visible: bool,
    /// Whether the creation event's run may be disclosed.
    pub creation_run_visible: bool,
}

/// The exact predicate for "this event produced a body".
///
/// A create always produces one; an update only when its payload object
/// actually carries a `body` key. Attribution already relies on this rule, and
/// duplicating a *different* rule here would let a comment's byline and its
/// attribution disagree about which event a reader is looking at.
pub const BODY_PRODUCING_EVENT_SQL: &str = "(type = 'record.created' \
     OR (type = 'record.updated' AND json_type(payload, '$.body') IS NOT NULL))";

/// Fold raw engine facts plus a viewer's disclosure into the wire projection.
///
/// Deliberately pure: every visibility rule in the specification is decided
/// here, once, and can be exercised without a store.
pub fn project(
    raw: &RawContribution,
    disclosure: &ViewerDisclosure,
    context: ContributionContext,
) -> ContributionProvenance {
    let attested = raw.current.attestation.as_ref();

    let executor = ExecutorFacts {
        // The attested CLASS survives redaction of the executor identity. That
        // asymmetry is the existing public-attestation-summary contract, not a
        // new one.
        kind: attested.map(|action| action.executor_kind.clone()),
        reference: attested
            .filter(|_| disclosure.executor_ref_visible)
            .and_then(|action| action.executor_ref.clone()),
        assurance: if attested.is_some() {
            Assurance::EngineAttested
        } else {
            Assurance::UnknownOrWithheld
        },
    };

    let channel = attested.map_or(Channel::Unknown, |action| action.channel);
    let channel_facts = ChannelFacts {
        kind: channel.as_str().to_string(),
        assurance: if attested.is_some() && channel.is_observed() {
            Assurance::ServerObserved
        } else {
            Assurance::UnknownOrWithheld
        },
        display_inference: display_inference(
            executor.kind.as_deref(),
            channel,
            disclosure.executor_ref_visible,
        ),
    };

    let run = raw
        .current
        .run_key
        .as_deref()
        .filter(|_| disclosure.current_run_visible)
        .map(run_correlation);

    let creation_run = raw
        .creation
        .as_ref()
        .and_then(|creation| creation.run_key.as_deref())
        .filter(|_| disclosure.creation_run_visible);

    // `same_run` is knowable only when BOTH runs are disclosed. Any other case
    // is unknown, and unknown is `null` — never `false`.
    let same_run = match (
        raw.current.run_key.as_deref(),
        disclosure.current_run_visible,
        raw.creation
            .as_ref()
            .map(|creation| creation.run_key.as_deref()),
        disclosure.creation_run_visible,
    ) {
        (Some(current), true, Some(Some(created)), true) => Some(current == created),
        // Two events that both genuinely carry no run key are the same
        // (absent) run only in a sense that would mislead; say nothing.
        _ => None,
    };

    let created_same_event = raw
        .creation
        .as_ref()
        .is_some_and(|creation| creation.event_id == raw.current.event_id);

    let mut limits = vec![
        LIMIT_PRINCIPAL_NOT_ENDORSEMENT.to_string(),
        LIMIT_CREATION_NOT_STANCE.to_string(),
    ];
    if run.is_some() || creation_run.is_some() {
        limits.push(LIMIT_RUN_KEY_NOT_IDENTITY.to_string());
    }
    if channel_facts.display_inference == Some(DisplayInference::LikelyAgent) {
        limits.push(LIMIT_CHANNEL_INFERENCE_NOT_ATTESTED.to_string());
    }
    if executor.kind.as_deref() == Some("delegated_service") {
        limits.push(LIMIT_DELEGATED_EXECUTION_NOT_AUTHORSHIP.to_string());
    }
    if context.alternative_set.is_some() {
        limits.push(LIMIT_ALTERNATIVE_SET_FILTERED.to_string());
        limits.push(LIMIT_MEMBERSHIP_UNORDERED.to_string());
    }
    if executor.assurance == Assurance::UnknownOrWithheld
        || channel_facts.assurance == Assurance::UnknownOrWithheld
        || disclosure.principal.is_none()
        || (raw.current.run_key.is_some() && run.is_none())
    {
        limits.push(LIMIT_FIELDS_WITHHELD.to_string());
    }

    ContributionProvenance {
        principal: disclosure.principal.clone(),
        executor,
        channel: channel_facts,
        run,
        revision: RevisionFacts {
            event_id: raw.current.event_id.clone(),
            event_type: raw.current.event_type.clone(),
            produced_current_body: true,
            run_key: raw
                .current
                .run_key
                .clone()
                .filter(|_| disclosure.current_run_visible),
        },
        created_by: CreationFacts {
            event_id: raw
                .creation
                .as_ref()
                .map(|creation| creation.event_id.clone()),
            same_run: if created_same_event {
                Some(true)
            } else {
                same_run
            },
            run_key: creation_run.map(str::to_owned),
        },
        context,
        interpretation_limits: limits,
    }
}

fn run_correlation(run_key: &str) -> RunCorrelation {
    RunCorrelation {
        run_key: run_key.to_string(),
        agent_key: crate::runkey::agent_key_of(run_key).to_string(),
        assurance: Assurance::CorrelationOnly,
    }
}

/// The permitted rendering inference, and nothing beyond it.
///
/// An undisclosed executor suppresses the hint entirely. Both hints say
/// something about an executor the viewer is not allowed to resolve, and the
/// non-identifying facts (`executor.kind`, `channel.kind`) already survive
/// redaction, so the hedge would add risk and no information.
fn display_inference(
    executor_kind: Option<&str>,
    channel: Channel,
    executor_disclosed: bool,
) -> Option<DisplayInference> {
    if !executor_disclosed {
        return None;
    }
    match (executor_kind, channel) {
        (Some("human"), _) => Some(DisplayInference::Human),
        (Some("delegated_service"), Channel::Webhook) => Some(DisplayInference::Automated),
        (Some("authenticated_principal"), Channel::Mcp) => Some(DisplayInference::LikelyAgent),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Store access
// ---------------------------------------------------------------------------

const ACTOR_PERSON_QUERY: &str = "SELECT person.id, person.name
   FROM bindings account
   JOIN records person ON person.id = account.record_id
  WHERE account.system = 'account' AND account.identifier = ?
  LIMIT 1";

/// Gather the two provenance points for one record: the event that produced
/// the body currently visible, and the event that created the record.
pub async fn raw_contribution_in(
    tx: &mut Transaction<'_, Sqlite>,
    record_id: &str,
) -> Result<Option<RawContribution>> {
    let current = sqlx::query(&format!(
        "SELECT id, type, run_key, actor FROM content_events
          WHERE record_id = ? AND {BODY_PRODUCING_EVENT_SQL}
          ORDER BY seq DESC LIMIT 1"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(current) = current else {
        return Ok(None);
    };
    let creation = sqlx::query(
        "SELECT id, type, run_key, actor FROM content_events
          WHERE record_id = ? AND type = 'record.created'
          ORDER BY seq ASC LIMIT 1",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;

    let current = event_fact_in(tx, &current).await?;
    let creation = match creation {
        Some(row) => Some(event_fact_in(tx, &row).await?),
        None => None,
    };
    Ok(Some(RawContribution { current, creation }))
}

async fn event_fact_in(
    tx: &mut Transaction<'_, Sqlite>,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<RawEventFact> {
    let event_id: String = row.try_get("id")?;
    let attestation = attestation_for_event_in(tx, &event_id).await?;
    Ok(RawEventFact {
        event_type: row.try_get("type")?,
        run_key: row.try_get("run_key")?,
        actor: row.try_get("actor")?,
        event_id,
        attestation,
    })
}

/// The attestation covering one content event, if one exists and is still
/// valid.
///
/// An invalidated attestation is treated as absent rather than as evidence:
/// the whole point of invalidation is that its facts stopped being trustworthy,
/// and a byline is exactly the wrong place to keep quoting them.
pub async fn attestation_for_event_in(
    tx: &mut Transaction<'_, Sqlite>,
    event_id: &str,
) -> Result<Option<AttestedAction>> {
    let row = sqlx::query(
        "SELECT a.id, a.principal, a.executor_kind, a.executor_ref, a.channel
           FROM provenance_action_outputs o
           JOIN provenance_action_attestations a ON a.id = o.action_attestation_id
          WHERE o.output_domain = 'content' AND o.output_event_id = ?
          UNION ALL
         SELECT a.id, a.principal, a.executor_kind, a.executor_ref, a.channel
           FROM provenance_action_events e
           JOIN provenance_action_attestations a ON a.id = e.action_attestation_id
          WHERE e.output_event_id = ?
          LIMIT 1",
    )
    .bind(event_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let attestation_id: String = row.try_get("id")?;
    let validity: Option<String> = sqlx::query_scalar(
        "SELECT status FROM provenance_attestation_validity_events
          WHERE attestation_id = ? ORDER BY ordinal DESC LIMIT 1",
    )
    .bind(&attestation_id)
    .fetch_optional(&mut **tx)
    .await?;
    if validity.as_deref() == Some("invalidated") {
        return Ok(None);
    }
    Ok(Some(AttestedAction {
        principal: row.try_get("principal")?,
        executor_kind: row.try_get("executor_kind")?,
        executor_ref: row.try_get("executor_ref")?,
        channel: Channel::from_stored(row.try_get::<Option<String>, _>("channel")?.as_deref()),
    }))
}

/// Decide what this viewer may learn about a gathered contribution.
///
/// The actor-disclosure gate is [`crate::authorization::actor_disclosable_with`],
/// the same single decision point history redaction uses. Reimplementing it
/// here would create a second copy of the policy free to drift from the first.
pub async fn viewer_disclosure_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    raw: &RawContribution,
) -> Result<ViewerDisclosure> {
    let trusted_local = crate::mcp::tools::is_legacy_local(caller);
    let principal_token = raw
        .current
        .attestation
        .as_ref()
        .map(|action| action.principal.clone())
        .or_else(|| raw.current.actor.clone());

    let disclose = match principal_token.as_deref() {
        Some(token) if trusted_local => Some(token.to_string()),
        Some(token) => {
            let mut state = crate::portable_sql::BorrowedSqliteStatementExecutor::new(tx);
            let visible = crate::authorization::actor_disclosable_with(
                &mut state,
                crate::mcp::tools::principal(caller),
                token,
            )
            .await?;
            visible.then(|| token.to_string())
        }
        None => None,
    };

    let actor_disclosed = disclose.is_some();

    // Two gates, not one. `actor_disclosable_with` decides whether the ACTOR
    // may be named at all — that is what carries the run and intent. Naming a
    // person RECORD additionally requires ordinary View on that record, which
    // is the same rule that nulls a hidden `owner_id`. Collapsing the two
    // would publish a person record id to a viewer who may not read it, and a
    // principal is sometimes hidden even from themselves.
    let principal = match disclose.as_deref() {
        Some(token) => {
            let resolved = sqlx::query(ACTOR_PERSON_QUERY)
                .bind(token)
                .fetch_optional(&mut **tx)
                .await?
                .map(|row| {
                    Ok::<_, sqlx::Error>(PrincipalRef {
                        id: row.try_get("id")?,
                        display_name: row.try_get("name")?,
                    })
                })
                .transpose()?;
            match resolved {
                Some(reference) => {
                    let visible = trusted_local
                        || crate::mcp::tools::can_record_in(
                            tx,
                            caller,
                            &reference.id,
                            Capability::View,
                        )
                        .await?;
                    // Omit the whole object rather than substituting the
                    // account or principal token, which is never the viewer's
                    // to learn.
                    visible.then_some(reference)
                }
                None => None,
            }
        }
        None => None,
    };

    // The caller's own run is always its own to see. Otherwise the run rides
    // with the disclosable actor, exactly as `redact_event` already decides.
    let own_run = |run: Option<&str>| run.is_some() && run == caller.run_key();
    let current_run_visible =
        trusted_local || actor_disclosed || own_run(raw.current.run_key.as_deref());
    let creation_run_visible = match raw.creation.as_ref() {
        Some(creation) => trusted_local || actor_disclosed || own_run(creation.run_key.as_deref()),
        None => false,
    };

    Ok(ViewerDisclosure {
        principal,
        // The executor reference is the credential, verifier, or executor id.
        // It rides on the same gate as the principal identity.
        executor_ref_visible: trusted_local || actor_disclosed,
        current_run_visible,
        creation_run_visible,
    })
}

/// The exploration this record is a candidate in, if any is visible.
///
/// Returns `None` — not an empty set, and never a hidden id — when the
/// governing selection is not the viewer's to read.
pub async fn alternative_set_context_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    record_id: &str,
) -> Result<Option<AlternativeSetContext>> {
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT link.target_id
           FROM links link
           JOIN records collection ON collection.id = link.target_id
           JOIN facet_values facet ON facet.record_id = collection.id
          WHERE link.source_id = ?
            AND link.relationship = 'member_of'
            AND collection.type = 'Collection'
            AND collection.deleted_at IS NULL
            AND facet.key = ?
            AND facet.value = ?
          ORDER BY link.created_at, link.target_id",
    )
    .bind(record_id)
    .bind(SELECTION_ROLE_FACET)
    .bind(ALTERNATIVE_SET_ROLE)
    .fetch_all(&mut **tx)
    .await?;

    for collection_id in candidates {
        if !crate::mcp::tools::can_record_in(tx, caller, &collection_id, Capability::View).await? {
            // Omit the whole object. Reporting "an exploration you cannot see"
            // is itself the disclosure the rule forbids.
            continue;
        }
        let label: Option<String> = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(&collection_id)
            .fetch_optional(&mut **tx)
            .await?;
        let members: Vec<String> = sqlx::query_scalar(
            "SELECT link.source_id
               FROM links link
               JOIN records member ON member.id = link.source_id
              WHERE link.target_id = ?
                AND link.relationship = 'member_of'
                AND member.deleted_at IS NULL",
        )
        .bind(&collection_id)
        .fetch_all(&mut **tx)
        .await?;
        // Count only what this viewer can see. A true total would disclose the
        // existence of records they may not read.
        let mut visible_member_count = 0;
        for member in members {
            if crate::mcp::tools::can_record_in(tx, caller, &member, Capability::View).await? {
                visible_member_count += 1;
            }
        }
        return Ok(Some(AlternativeSetContext {
            id: collection_id,
            label,
            role: ALTERNATIVE_SET_ROLE.to_string(),
            visible_member_count,
        }));
    }
    Ok(None)
}

/// A visible `Resolution kind:decision` that `selects` this record.
///
/// Newest first; a later decision choosing a different candidate supersedes an
/// earlier one, and both remain inspectable. Nothing here removes or hides the
/// unchosen members.
pub async fn selection_context_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    record_id: &str,
) -> Result<Option<SelectionContext>> {
    let rows = sqlx::query(
        "SELECT decision.id, decision.name, link.created_at
           FROM links link
           JOIN records decision ON decision.id = link.source_id
          WHERE link.target_id = ?
            AND link.relationship = ?
            AND decision.type = 'Resolution'
            AND decision.deleted_at IS NULL
          ORDER BY link.created_at DESC, decision.id DESC",
    )
    .bind(record_id)
    .bind(SELECTS_RELATIONSHIP)
    .fetch_all(&mut **tx)
    .await?;
    for row in rows {
        let decision_id: String = row.try_get("id")?;
        if !crate::mcp::tools::can_record_in(tx, caller, &decision_id, Capability::View).await? {
            continue;
        }
        let superseded: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM links WHERE target_id = ? AND relationship = 'supersedes')",
        )
        .bind(&decision_id)
        .fetch_one(&mut **tx)
        .await?;
        return Ok(Some(SelectionContext {
            decision_name: row.try_get("name")?,
            decided_at: row.try_get("created_at")?,
            decision_id,
            effective: superseded == 0,
        }));
    }
    Ok(None)
}

/// End-to-end: gather, disclose, and project one record's contribution.
pub async fn contribution_for_record_in(
    tx: &mut Transaction<'_, Sqlite>,
    caller: &Caller,
    record_id: &str,
) -> Result<Option<ContributionProvenance>> {
    let Some(raw) = raw_contribution_in(tx, record_id).await? else {
        return Ok(None);
    };
    let disclosure = viewer_disclosure_in(tx, caller, &raw).await?;
    let alternative_set = alternative_set_context_in(tx, caller, record_id).await?;
    let selection = selection_context_in(tx, caller, record_id).await?;
    let context = ContributionContext {
        // Membership in an alternative set is the one durable signal this
        // slice has that a contribution was offered as an option rather than
        // asserted as a view. Creation alone still establishes nothing.
        mode: alternative_set.is_some().then(|| "option".to_string()),
        alternative_set,
        selection,
    };
    Ok(Some(project(&raw, &disclosure, context)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str, run: Option<&str>, kind: &str, channel: Channel) -> RawEventFact {
        RawEventFact {
            event_id: id.into(),
            event_type: "record.created".into(),
            run_key: run.map(str::to_owned),
            actor: Some("acct".into()),
            attestation: Some(AttestedAction {
                principal: "acct".into(),
                executor_kind: kind.into(),
                executor_ref: Some("acct".into()),
                channel,
            }),
        }
    }

    fn visible() -> ViewerDisclosure {
        ViewerDisclosure {
            principal: Some(PrincipalRef {
                id: "person-1".into(),
                display_name: Some("Richard".into()),
            }),
            executor_ref_visible: true,
            current_run_visible: true,
            creation_run_visible: true,
        }
    }

    #[test]
    fn mcp_authenticated_principal_renders_likely_agent_without_touching_executor_kind() {
        let raw = RawContribution {
            current: event(
                "e1",
                Some("plover-archery-kt0gyr"),
                "authenticated_principal",
                Channel::Mcp,
            ),
            creation: None,
        };
        let projected = project(&raw, &visible(), ContributionContext::default());
        assert_eq!(
            projected.executor.kind.as_deref(),
            Some("authenticated_principal"),
            "the hedge must never occupy the attested executor slot"
        );
        assert_eq!(projected.channel.kind, "mcp");
        assert_eq!(
            projected.channel.display_inference,
            Some(DisplayInference::LikelyAgent)
        );
        assert!(projected
            .interpretation_limits
            .iter()
            .any(|limit| limit == LIMIT_CHANNEL_INFERENCE_NOT_ATTESTED));
    }

    #[test]
    fn web_authenticated_principal_infers_nothing() {
        let raw = RawContribution {
            current: event(
                "e1",
                Some("plover-archery-kt0gyr"),
                "authenticated_principal",
                Channel::Web,
            ),
            creation: None,
        };
        let projected = project(&raw, &visible(), ContributionContext::default());
        assert_eq!(projected.channel.kind, "web");
        assert_eq!(projected.channel.display_inference, None);
    }

    #[test]
    fn delegated_webhook_is_explicitly_not_principal_authorship() {
        let raw = RawContribution {
            current: event("e1", None, "delegated_service", Channel::Webhook),
            creation: None,
        };
        let projected = project(&raw, &visible(), ContributionContext::default());
        assert_eq!(
            projected.executor.kind.as_deref(),
            Some("delegated_service")
        );
        assert_eq!(projected.channel.kind, "webhook");
        assert_eq!(
            projected.channel.display_inference,
            Some(DisplayInference::Automated)
        );
        assert!(projected
            .interpretation_limits
            .iter()
            .any(|limit| limit == LIMIT_DELEGATED_EXECUTION_NOT_AUTHORSHIP));
    }

    #[test]
    fn verified_human_renders_human() {
        let raw = RawContribution {
            current: event("e1", None, "human", Channel::Web),
            creation: None,
        };
        let projected = project(&raw, &visible(), ContributionContext::default());
        assert_eq!(projected.executor.kind.as_deref(), Some("human"));
        assert_eq!(
            projected.channel.display_inference,
            Some(DisplayInference::Human)
        );
    }

    #[test]
    fn withheld_run_yields_null_same_run_never_false() {
        let raw = RawContribution {
            current: event("e2", Some("plover-archery-bbbbbb"), "agent", Channel::Mcp),
            creation: Some(event(
                "e1",
                Some("plover-archery-aaaaaa"),
                "agent",
                Channel::Mcp,
            )),
        };
        let hidden = ViewerDisclosure {
            principal: None,
            executor_ref_visible: false,
            current_run_visible: false,
            creation_run_visible: false,
        };
        let projected = project(&raw, &hidden, ContributionContext::default());
        assert_eq!(projected.created_by.same_run, None);
        assert!(projected.run.is_none());
        assert!(projected.principal.is_none());
        assert_eq!(projected.revision.run_key, None);
        // The attested class survives; the identity does not.
        assert_eq!(projected.executor.kind.as_deref(), Some("agent"));
        assert_eq!(projected.executor.reference, None);
        assert_eq!(projected.channel.kind, "mcp");
        assert!(projected
            .interpretation_limits
            .iter()
            .any(|limit| limit == LIMIT_FIELDS_WITHHELD));
    }

    #[test]
    fn undisclosed_executor_suppresses_the_display_inference() {
        let raw = RawContribution {
            current: event(
                "e1",
                Some("plover-archery-kt0gyr"),
                "authenticated_principal",
                Channel::Mcp,
            ),
            creation: None,
        };
        let hidden = ViewerDisclosure::default();
        let projected = project(&raw, &hidden, ContributionContext::default());
        assert_eq!(projected.channel.display_inference, None);
    }

    #[test]
    fn cross_run_edit_reports_distinct_runs() {
        let raw = RawContribution {
            current: event("e2", Some("plover-archery-bbbbbb"), "agent", Channel::Mcp),
            creation: Some(event(
                "e1",
                Some("scout-chair-aaaaaa"),
                "agent",
                Channel::Mcp,
            )),
        };
        let projected = project(&raw, &visible(), ContributionContext::default());
        assert_eq!(projected.created_by.same_run, Some(false));
        assert_eq!(
            projected.created_by.run_key.as_deref(),
            Some("scout-chair-aaaaaa")
        );
        assert_eq!(
            projected.run.as_ref().map(|run| run.run_key.as_str()),
            Some("plover-archery-bbbbbb")
        );
    }

    #[test]
    fn same_agent_key_distinct_runs_do_not_merge() {
        let first = run_correlation("plover-archery-aaaaaa");
        let second = run_correlation("plover-archery-bbbbbb");
        assert_eq!(first.agent_key, second.agent_key);
        assert_ne!(first.run_key, second.run_key);
        assert_eq!(first.assurance, Assurance::CorrelationOnly);
    }

    #[test]
    fn missing_attestation_is_unknown_not_invented() {
        let raw = RawContribution {
            current: RawEventFact {
                event_id: "e1".into(),
                event_type: "record.created".into(),
                run_key: None,
                actor: None,
                attestation: None,
            },
            creation: None,
        };
        let projected = project(
            &raw,
            &ViewerDisclosure::default(),
            ContributionContext::default(),
        );
        assert_eq!(projected.executor.kind, None);
        assert_eq!(projected.executor.assurance, Assurance::UnknownOrWithheld);
        assert_eq!(projected.channel.kind, "unknown");
        assert_eq!(projected.channel.assurance, Assurance::UnknownOrWithheld);
        assert_eq!(projected.channel.display_inference, None);
    }

    #[test]
    fn alternative_set_context_carries_its_limitations() {
        let raw = RawContribution {
            current: event("e1", Some("plover-archery-kt0gyr"), "agent", Channel::Mcp),
            creation: None,
        };
        let context = ContributionContext {
            mode: Some("option".into()),
            alternative_set: Some(AlternativeSetContext {
                id: "collection-1".into(),
                label: Some("Homepage directions".into()),
                role: ALTERNATIVE_SET_ROLE.into(),
                visible_member_count: 5,
            }),
            selection: None,
        };
        let projected = project(&raw, &visible(), context);
        assert!(projected
            .interpretation_limits
            .iter()
            .any(|limit| limit == LIMIT_ALTERNATIVE_SET_FILTERED));
        assert!(projected
            .interpretation_limits
            .iter()
            .any(|limit| limit == LIMIT_MEMBERSHIP_UNORDERED));
    }

    #[test]
    fn creation_and_current_event_identity_reports_one_participant() {
        let raw = RawContribution {
            current: event("e1", Some("plover-archery-kt0gyr"), "agent", Channel::Mcp),
            creation: Some(event(
                "e1",
                Some("plover-archery-kt0gyr"),
                "agent",
                Channel::Mcp,
            )),
        };
        let projected = project(&raw, &visible(), ContributionContext::default());
        assert_eq!(projected.created_by.same_run, Some(true));
        assert_eq!(projected.created_by.event_id.as_deref(), Some("e1"));
    }
}
