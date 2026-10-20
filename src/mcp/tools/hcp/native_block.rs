//! The optional `native` provenance block (slice 3, Layer 2).
//!
//! Every preference `/hcp` returns may carry `native`, which ContextRouter
//! clients ignore. This file is the pure part: it turns facts Native already
//! recorded about a value into `assertedBy` (with `basis`), `recordedBy`,
//! `evidence` and the Layer 1 `sourceType`. Reading those facts is `store.rs`.
//!
//! Derivation is a lookup, never an inference. It looks at which transport the
//! server observed, which operation and executor an action attestation names,
//! attribution annotations and who resolved a suggestion. It never reads the
//! text of a value, a reason or a quote. A fact the caller cannot see is
//! `None`, and `None` never turns into a guess.
//!
//! * `direct`: the owner wrote the current body through a person channel. Only
//!   a body write: never an acceptance, whoever authored the proposal.
//! * `endorsed`: the owner accepted the suggestion that produced the body
//!   through a person channel (exactly one in that action's immutable record),
//!   or attributed the exact current revision to themselves through a person
//!   channel (or with a verified direct declaration). Who authored the
//!   proposal does not matter: the owner endorsed the whole result.
//! * `reported`: an agent wrote it and declared it the person's view, through
//!   an attribution created through the agent channel, or the HCP write's
//!   `evidence` says `"speaker": "user"`.
//! * anything else: `assertedBy: null`, the agent's own inference.

use serde_json::{json, Map, Value};

use crate::provenance::Channel;

/// The attestation operation of every write made through `mutatePreferences`.
/// The tool is only registered on `/hcp`, so no `/mcp` write carries it.
pub(super) const HCP_OPERATION: &str = "mutatePreferences";

/// Longest evidence text echoed in the block.
const EVIDENCE_TEXT_MAX_CHARS: usize = 1000;

/// A valid action attestation covering one content event. `None` where a
/// fact is needed means no valid attestation covers it, so Native cannot say
/// which channel or executor wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Writer {
    pub operation: String,
    pub channel: Channel,
    pub executor_kind: String,
    /// The attestation's id, so two events can be shown to belong to one action.
    pub attestation_id: String,
    /// The attested principal is the preference's owner. Compared inside the
    /// store and never exposed.
    pub by_owner: bool,
    /// Who wrote it when it was not the owner: a name Native already shows this
    /// caller (the `actors` relation), or `None` when it does not.
    pub actor_name: Option<String>,
}

impl Writer {
    /// Written by `mutatePreferences`, so the `hcp.*` facets of the same call
    /// describe it.
    pub(super) fn is_hcp(&self) -> bool {
        self.operation == HCP_OPERATION
    }

    /// The server observed the first-party web route, and the attested
    /// executor is not an agent or a delegated service. Native cannot tell a
    /// person's click from a script holding their token on this route; that is
    /// the strongest "the person did this" the channel gives.
    pub(super) fn is_person_channel(&self) -> bool {
        self.channel == Channel::Web
            && !matches!(self.executor_kind.as_str(), "agent" | "delegated_service")
    }

    /// The preference's owner acted through a person channel. Only this can be
    /// the owner's own statement: a collaborator's web edit is theirs.
    pub(super) fn is_owner_person(&self) -> bool {
        self.by_owner && self.is_person_channel()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Basis {
    Direct,
    Endorsed,
    Reported,
}

impl Basis {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Endorsed => "endorsed",
            Self::Reported => "reported",
        }
    }
}

/// How an attribution was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Via {
    /// A verified direct declaration, or created through a person channel.
    Person,
    /// Created through the MCP channel.
    Agent,
    /// Any other or unattested channel: counts for nothing.
    Unknown,
}

/// An attribution annotation about the current revision of the value, about
/// the person, not retracted and not superseded by a later claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Attribution {
    /// `expresses_view`/`endorses` with polarity `affirmed`. A denial is kept
    /// as counterevidence and never as a basis.
    pub affirms: bool,
    pub via: Via,
    pub rationale: String,
}

/// A suggestion whose acceptance produced the current value.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Accepted {
    /// Native's immutable record of the action does not show that it resolved
    /// exactly one suggestion (several, incomplete, or unreadable). Nobody's
    /// statement can be derived from it, so the basis is `null`, never the
    /// authorship of an ordinary write. (`recordedBy` is still the actor of the
    /// body-producing action.)
    pub ambiguous: bool,
    /// The proposal's confidence and evidence, when HCP authored it: they
    /// describe the proposal itself. Its author is not kept: it is neither
    /// the basis nor who recorded the body.
    pub confidence: Option<f64>,
    pub evidence: Option<Value>,
}

/// Everything recorded about where the current value came from.
#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Origin {
    /// The action that produced the current body.
    pub writer: Option<Writer>,
    /// The OAuth client of the HCP write (only when `writer` is HCP).
    pub client: Option<String>,
    /// The `hcp.evidence` of the HCP write (only when `writer` is HCP).
    pub evidence: Option<Value>,
    /// Set when accepting a suggestion produced the body.
    pub accepted: Option<Accepted>,
    pub attributions: Vec<Attribution>,
}

impl Accepted {
    /// An acceptance whose author cannot be established.
    pub(super) fn ambiguous() -> Self {
        Self {
            ambiguous: true,
            confidence: None,
            evidence: None,
        }
    }
}

impl Origin {
    /// Confidence of whatever produced the current body: HCP's own write
    /// carries the record's `hcp.confidence`; an accepted suggestion, its own;
    /// a hand edit or any other writer, none.
    pub(super) fn confidence(&self, record_confidence: Option<f64>) -> Option<f64> {
        if let Some(accepted) = &self.accepted {
            return accepted.confidence;
        }
        match &self.writer {
            Some(writer) if writer.is_hcp() => record_confidence,
            _ => None,
        }
    }
}

/// `evidence` structured as the person's own words: `{ "speaker": "user", ... }`.
/// A structural key, not a reading of the quote.
fn declares_person_instruction(evidence: Option<&Value>) -> bool {
    evidence
        .and_then(|evidence| evidence.get("speaker"))
        .and_then(Value::as_str)
        == Some("user")
}

pub(super) fn basis(origin: &Origin) -> Option<Basis> {
    // An acceptance that cannot be tied to exactly one suggestion fails closed:
    // no asserter, whatever else is recorded.
    if origin
        .accepted
        .as_ref()
        .is_some_and(|accepted| accepted.ambiguous)
    {
        return None;
    }
    let owner_wrote = origin.writer.as_ref().is_some_and(Writer::is_owner_person);
    let instruction = match &origin.accepted {
        // The body is the result of accepting a suggestion. Whoever proposed
        // it, the content the body now holds is not necessarily theirs (the
        // target may have changed since), so authorship of the proposal gives
        // nothing: only the acceptance does. The owner accepting the whole
        // result through a person channel endorses it; anyone else, or any
        // other channel, says nothing about the owner.
        Some(_) => {
            if owner_wrote {
                return Some(Basis::Endorsed);
            }
            false
        }
        // An ordinary write. `direct` comes only from the owner writing the
        // body through a person channel.
        None => {
            if owner_wrote {
                return Some(Basis::Direct);
            }
            origin.writer.as_ref().is_some_and(Writer::is_hcp)
                && declares_person_instruction(origin.evidence.as_ref())
        }
    };
    let by = |via: Via| {
        origin
            .attributions
            .iter()
            .any(|attribution| attribution.affirms && attribution.via == via)
    };
    // Attributions are facts about the exact current revision, independent of
    // how the body was produced.
    if by(Via::Person) {
        return Some(Basis::Endorsed);
    }
    // The instruction counts only when HCP itself wrote this body with that
    // evidence.
    if by(Via::Agent) || instruction {
        return Some(Basis::Reported);
    }
    None
}

/// Layer 1 `sourceType`: the basis decides first, then the writer's channel.
pub(super) fn source_type(origin: &Origin, basis: Option<Basis>) -> &'static str {
    if matches!(basis, Some(Basis::Direct | Basis::Endorsed)) {
        return "USER";
    }
    match origin.writer.as_ref().map(|writer| writer.channel) {
        Some(Channel::Webhook) => "IMPORTED",
        Some(Channel::Local) => "SYSTEM",
        _ => "INFERRED",
    }
}

/// Who wrote the value into Native: the actor of the body-producing action. On
/// an acceptance that is whoever accepted, not the proposal's author. `None`
/// when no valid attestation covers it, or the actor is hidden from this caller.
fn recorded_by(origin: &Origin, person: &str) -> Option<Value> {
    let writer = origin.writer.as_ref()?;
    let client = origin.client.as_deref();
    if !writer.by_owner {
        // Someone else wrote it: name them only if Native already shows this
        // caller who they are.
        let name = writer.actor_name.as_deref()?;
        let kind = if writer.is_person_channel() {
            "person"
        } else {
            "agent"
        };
        return Some(json!({ "kind": kind, "name": name }));
    }
    if writer.is_person_channel() {
        return Some(json!({ "kind": "person", "name": person }));
    }
    let client = client.filter(|client| writer.is_hcp() && *client != "unknown");
    let name = match (writer.channel, client) {
        (_, Some(client)) => client,
        (Channel::Webhook, None) => "external service",
        (Channel::Local, None) => "Native (local process)",
        (_, None) if writer.is_hcp() => "unidentified HCP client",
        (_, None) => "MCP client",
    };
    let mut actor = Map::new();
    actor.insert("kind".into(), json!("agent"));
    actor.insert("name".into(), json!(name));
    if let Some(client) = client {
        actor.insert("client".into(), json!(client));
    }
    Some(Value::Object(actor))
}

fn evidence_entry(evidence: &Value) -> Value {
    let mut entry = Map::new();
    if let Some(reference) = evidence.get("ref").and_then(Value::as_str) {
        entry.insert("ref".into(), json!(reference));
    }
    let text = ["text", "quote"]
        .iter()
        .find_map(|key| evidence.get(*key).and_then(Value::as_str))
        .map_or_else(|| evidence.to_string(), str::to_string);
    entry.insert(
        "text".into(),
        json!(text
            .chars()
            .take(EVIDENCE_TEXT_MAX_CHARS)
            .collect::<String>()),
    );
    let role = if evidence.get("role").and_then(Value::as_str) == Some("counterevidence") {
        "counterevidence"
    } else {
        "basis"
    };
    entry.insert("role".into(), json!(role));
    Value::Object(entry)
}

fn evidence(origin: &Origin) -> Vec<Value> {
    let authored = match &origin.accepted {
        Some(accepted) => accepted.evidence.as_ref(),
        None => origin.evidence.as_ref(),
    };
    let mut entries: Vec<Value> = authored.map(evidence_entry).into_iter().collect();
    for attribution in &origin.attributions {
        entries.push(json!({
            "text": attribution.rationale.chars().take(EVIDENCE_TEXT_MAX_CHARS).collect::<String>(),
            "role": if attribution.affirms { "basis" } else { "counterevidence" },
        }));
    }
    entries
}

/// The block for one value. `person` names the account holder.
pub(super) fn native_block(
    origin: &Origin,
    person: &str,
    record_ref: &str,
    url: &str,
    revision: &str,
) -> Value {
    let basis = basis(origin);
    json!({
        "recordRef": record_ref,
        "url": url,
        "revision": revision,
        "assertedBy": basis.map(|basis| json!({
            "kind": "person",
            "name": person,
            "basis": basis.as_str(),
        })),
        "recordedBy": recorded_by(origin, person),
        "evidence": evidence(origin),
    })
}

/// The block for a definition. A definition is not a statement of the
/// person's view, so `assertedBy` is always `null`. It was recorded by the
/// `/hcp` client stamped on it, or by nobody Native can name.
pub(super) fn definition_block(
    client: Option<&str>,
    record_ref: &str,
    url: &str,
    revision: &str,
) -> Value {
    let recorded_by = client.map(|client| {
        let client = Some(client).filter(|client| *client != "unknown");
        let mut actor = Map::new();
        actor.insert("kind".into(), json!("agent"));
        actor.insert(
            "name".into(),
            json!(client.unwrap_or("unidentified HCP client")),
        );
        if let Some(client) = client {
            actor.insert("client".into(), json!(client));
        }
        Value::Object(actor)
    });
    json!({
        "recordRef": record_ref,
        "url": url,
        "revision": revision,
        "assertedBy": null,
        "recordedBy": recorded_by,
        "evidence": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writer(operation: &str, channel: Channel, executor: &str) -> Writer {
        Writer {
            operation: operation.into(),
            channel,
            executor_kind: executor.into(),
            attestation_id: format!("att-{operation}"),
            by_owner: true,
            actor_name: None,
        }
    }

    fn hcp() -> Writer {
        writer(HCP_OPERATION, Channel::Mcp, "authenticated_principal")
    }

    fn web() -> Writer {
        writer("update_record", Channel::Web, "authenticated_principal")
    }

    fn origin(writer: Option<Writer>) -> Origin {
        Origin {
            writer,
            ..Origin::default()
        }
    }

    fn attribution(affirms: bool, via: Via) -> Attribution {
        Attribution {
            affirms,
            via,
            rationale: "said so".into(),
        }
    }

    #[test]
    fn a_person_channel_write_is_direct() {
        assert_eq!(basis(&origin(Some(web()))), Some(Basis::Direct));
    }

    #[test]
    fn a_web_write_by_an_attested_agent_is_not_a_person_channel() {
        for executor in ["agent", "delegated_service"] {
            let writer = writer("update_record", Channel::Web, executor);
            assert_eq!(basis(&origin(Some(writer))), None, "{executor}");
        }
    }

    #[test]
    fn a_collaborators_person_channel_write_is_not_the_owners_statement() {
        let other = Writer {
            by_owner: false,
            actor_name: Some("Bob".into()),
            ..web()
        };
        assert_eq!(basis(&origin(Some(other.clone()))), None);
        // The writer is named only as Native already shows them, never as the owner.
        let block = native_block(&origin(Some(other)), "Alice", "r", "/r", "d");
        assert_eq!(
            block["recordedBy"],
            json!({ "kind": "person", "name": "Bob" })
        );
        let hidden = Writer {
            by_owner: false,
            actor_name: None,
            ..web()
        };
        let block = native_block(&origin(Some(hidden)), "Alice", "r", "/r", "d");
        assert_eq!(block["recordedBy"], Value::Null);
        assert_eq!(block["assertedBy"], Value::Null);
    }

    #[test]
    fn an_acceptance_or_authorship_by_someone_else_is_not_the_owners() {
        let bob = Writer {
            by_owner: false,
            actor_name: None,
            ..web()
        };
        let mut accepted = origin(Some(bob.clone()));
        accepted.accepted = Some(Accepted {
            ambiguous: false,
            confidence: None,
            evidence: None,
        });
        assert_eq!(
            basis(&accepted),
            None,
            "bob accepting is not the owner endorsing"
        );
        let mut authored = origin(Some(web()));
        authored.accepted = Some(Accepted {
            ambiguous: false,
            confidence: None,
            evidence: None,
        });
        assert_eq!(
            basis(&authored),
            Some(Basis::Endorsed),
            "the owner accepted bob's proposal"
        );
    }

    #[test]
    fn an_ambiguous_acceptance_gives_no_asserter_whoever_accepted() {
        // The owner accepted, through a person channel, but the record does not
        // show which single suggestion: nothing is derived, and the write is
        // not treated as an ordinary owner write either.
        let mut ambiguous = origin(Some(web()));
        ambiguous.accepted = Some(Accepted::ambiguous());
        ambiguous.attributions = vec![attribution(true, Via::Person)];
        assert_eq!(basis(&ambiguous), None);
        assert_eq!(source_type(&ambiguous, basis(&ambiguous)), "INFERRED");
        let block = native_block(&ambiguous, "Alice", "r", "/r", "d");
        assert_eq!(block["assertedBy"], Value::Null);
        assert_eq!(
            block["recordedBy"],
            json!({ "kind": "person", "name": "Alice" }),
            "whoever accepted recorded it, however unclear whose view it is"
        );
        assert_eq!(ambiguous.confidence(Some(0.9)), None);
    }

    #[test]
    fn an_agent_write_alone_has_no_asserter() {
        let origin = origin(Some(hcp()));
        assert_eq!(basis(&origin), None);
        assert_eq!(source_type(&origin, None), "INFERRED");
    }

    #[test]
    fn a_person_channel_acceptance_of_an_agent_suggestion_is_endorsed() {
        let mut origin = origin(Some(web()));
        origin.accepted = Some(Accepted {
            ambiguous: false,
            confidence: Some(0.4),
            evidence: None,
        });
        assert_eq!(basis(&origin), Some(Basis::Endorsed));
        assert_eq!(source_type(&origin, basis(&origin)), "USER");
    }

    #[test]
    fn an_agent_accepting_a_suggestion_is_not_endorsed() {
        let mut origin = origin(Some(writer("resolve_suggestions", Channel::Mcp, "x")));
        origin.accepted = Some(Accepted {
            ambiguous: false,
            confidence: None,
            evidence: None,
        });
        assert_eq!(basis(&origin), None);
    }

    #[test]
    fn accepting_a_suggestion_is_never_direct_whoever_authored_it() {
        // The owner wrote the proposal and accepted it: the whole result is
        // endorsed, not "written", because the body may hold more than the
        // proposal.
        let mut origin = origin(Some(web()));
        origin.accepted = Some(Accepted {
            ambiguous: false,
            confidence: None,
            evidence: None,
        });
        assert_eq!(basis(&origin), Some(Basis::Endorsed));
    }

    #[test]
    fn a_person_authored_proposal_accepted_by_an_agent_says_nothing_about_the_person() {
        let mut origin = origin(Some(writer("resolve_suggestions", Channel::Mcp, "x")));
        origin.accepted = Some(Accepted {
            ambiguous: false,
            confidence: None,
            evidence: Some(json!({ "speaker": "user" })),
        });
        assert_eq!(basis(&origin), None);
    }

    #[test]
    fn attributions_decide_endorsed_over_reported() {
        let mut origin = origin(Some(hcp()));
        origin.attributions = vec![attribution(true, Via::Agent)];
        assert_eq!(basis(&origin), Some(Basis::Reported));
        origin.attributions.push(attribution(true, Via::Person));
        assert_eq!(basis(&origin), Some(Basis::Endorsed));
    }

    #[test]
    fn a_denial_or_an_unknown_channel_never_counts() {
        let mut origin = origin(Some(hcp()));
        origin.attributions = vec![
            attribution(false, Via::Person),
            attribution(true, Via::Unknown),
        ];
        assert_eq!(basis(&origin), None);
    }

    #[test]
    fn person_instruction_evidence_is_reported_only_for_an_hcp_write() {
        let mut hcp_origin = origin(Some(hcp()));
        hcp_origin.evidence = Some(json!({ "speaker": "user", "quote": "keep it short" }));
        assert_eq!(basis(&hcp_origin), Some(Basis::Reported));

        // The same evidence left on the record by an earlier HCP write does not
        // count once someone else wrote the body.
        let mut other = origin(Some(writer("update_record", Channel::Mcp, "x")));
        other.evidence = Some(json!({ "speaker": "user" }));
        assert_eq!(basis(&other), None);

        // Evidence that merely mentions the user is not the structured key.
        let mut text_only = origin(Some(hcp()));
        text_only.evidence = Some(json!({ "quote": "the user said keep it short" }));
        assert_eq!(basis(&text_only), None);
    }

    #[test]
    fn source_type_maps_from_basis_then_channel() {
        let direct = origin(Some(web()));
        assert_eq!(source_type(&direct, Some(Basis::Direct)), "USER");
        assert_eq!(source_type(&direct, Some(Basis::Endorsed)), "USER");
        assert_eq!(source_type(&direct, Some(Basis::Reported)), "INFERRED");
        assert_eq!(source_type(&direct, None), "INFERRED");
        let webhook = origin(Some(writer(
            "update_record",
            Channel::Webhook,
            "delegated_service",
        )));
        assert_eq!(source_type(&webhook, None), "IMPORTED");
        let local = origin(Some(writer("update_record", Channel::Local, "local")));
        assert_eq!(source_type(&local, None), "SYSTEM");
        assert_eq!(source_type(&origin(None), None), "INFERRED");
        // A webhook value the person later endorsed is theirs.
        assert_eq!(source_type(&webhook, Some(Basis::Endorsed)), "USER");
    }

    #[test]
    fn confidence_follows_the_producer() {
        assert_eq!(origin(Some(hcp())).confidence(Some(0.7)), Some(0.7));
        assert_eq!(origin(Some(web())).confidence(Some(0.7)), None);
        assert_eq!(origin(None).confidence(Some(0.7)), None);
        let mut accepted = origin(Some(web()));
        accepted.accepted = Some(Accepted {
            ambiguous: false,
            confidence: Some(0.2),
            evidence: None,
        });
        assert_eq!(accepted.confidence(Some(0.7)), Some(0.2));
    }

    #[test]
    fn recorded_by_names_the_hcp_client_and_hides_unknown_ones() {
        let mut origin = origin(Some(hcp()));
        origin.client = Some("client_app".into());
        let block = native_block(&origin, "Richard", "ab12cd3", "/ab12cd3", "deadbeef");
        assert_eq!(
            block["recordedBy"],
            json!({ "kind": "agent", "name": "client_app", "client": "client_app" })
        );
        assert_eq!(block["assertedBy"], Value::Null);
        origin.client = Some("unknown".into());
        let block = native_block(&origin, "Richard", "ab12cd3", "/ab12cd3", "deadbeef");
        assert_eq!(
            block["recordedBy"],
            json!({ "kind": "agent", "name": "unidentified HCP client" })
        );
        assert_eq!(
            native_block(&Origin::default(), "R", "r", "/r", "d")["recordedBy"],
            Value::Null
        );
    }

    #[test]
    fn evidence_lists_the_authored_evidence_and_attribution_rationales() {
        let mut origin = origin(Some(hcp()));
        origin.evidence = Some(json!({ "speaker": "user", "quote": "keep it concise" }));
        origin.attributions = vec![
            attribution(true, Via::Agent),
            attribution(false, Via::Person),
        ];
        let block = native_block(&origin, "Richard", "r", "/r", "d");
        assert_eq!(
            block["evidence"],
            json!([
                { "text": "keep it concise", "role": "basis" },
                { "text": "said so", "role": "basis" },
                { "text": "said so", "role": "counterevidence" },
            ])
        );
    }
}
