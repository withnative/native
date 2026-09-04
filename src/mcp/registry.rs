//! The tool-handler registry — tools registered once, dispatched by every
//! transport.
//!
//! A handler is `(Db, Caller, arguments) -> Result<Output>` where `Output` is
//! either the historical `serde_json::Value` or a transport-neutral
//! [`ToolResult`](super::evidence::ToolResult) carrying structured data plus
//! transient evidence. It
//! receives a connection to *some* per-user database (the stdio transport's
//! local `.db`, or the connection the hosting router resolved from a bearer
//! token) and the identity established by that transport. Rendering — MCP
//! content blocks, HTTP bodies — is the transport's job (decision 2231ad3,
//! option C), so nothing here imports or mentions response framing.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use futures::future::{BoxFuture, FutureExt};
use serde_json::Value;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::provenance::Channel;
use crate::DeploymentReadOnlyOperation;

use super::evidence::ToolResult;
use super::interactions::{
    CustomInteractionPolicy, ExposureProfile, Extractor, ResolvedToolExposure, ToolExposure,
    ToolKind,
};
use super::{
    DeploymentAdmission, DeploymentMutationBarrier, DeploymentPersistenceLease, OperationAccess,
};

pub const STANDBY_READ_ONLY_ERROR: &str = "STANDBY_READ_ONLY";

pub use crate::domain_transaction::request::{
    governed_request_pipeline_is_exhaustive, GovernedRequestOperation, GovernedRequestStage,
    ToolCallOutcome, GOVERNED_REQUEST_PIPELINE,
};
#[cfg(test)]
use crate::domain_transaction::request::{
    GovernedRequestStageDisposition, GovernedRequestStageEvent,
};

/// Exact compact `result.tools` byte ceilings decided for the named profiles.
pub const FOCUSED_PROFILE_MAX_BYTES: usize = 65_536;
/// Raised from 192 KiB to 224 KiB on 3 Sep 2026, deliberately and as a stopgap.
///
/// The federated-lens Complete projection reached 196,637 bytes against the
/// old 196,608 ceiling, and a profile that does not fit is not a failed check
/// — the server refuses to advertise its tools and so never starts. It had
/// been landing within a few hundred bytes for several merges, which meant
/// whichever pull request happened to be next took production offline for a
/// reason that had nothing to do with it.
///
/// This buys room; it does not answer the question, which is what the tool
/// surface should be allowed to cost an agent's context window and which
/// tools earn their place in the Complete profile at all. That question is
/// filed separately. Treat another approach to this ceiling as a signal to
/// answer it rather than to raise the number again.
pub const COMPLETE_PROFILE_MAX_BYTES: usize = 229_376;

/// Trusted workspace audience classification supplied by the transport.
/// Agent-authored tool arguments cannot influence this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedAudience {
    Solo,
    Shared,
    Unknown,
}

impl TrustedAudience {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solo => "solo",
            Self::Shared => "shared",
            Self::Unknown => "unknown",
        }
    }
}

/// Identity established by the transport, never by tool arguments — plus the run
/// context the CALLER asserted, which is the opposite (fbfaf25 §3.2, §3.4).
///
/// The two live on one struct because they answer the same question at two
/// levels, but they must not be confused for one another:
///
/// - The **credential** is authenticated. Hosted HTTP resolves the catalog user
///   behind the bearer session to the account token carried by the user's file;
///   stdio has no application authentication boundary (filesystem access owns
///   the single local database), so startup adopts one portable account token
///   from that file and carries it for the process lifetime.
/// - The **run key** is asserted, unverified, and optional. It is a correlation
///   handle, not a claim of identity — validated for shape and membership only,
///   accepted whether or not the server has seen it before.
///
/// [`actor`] is always the authenticated credential. The optional run remains
/// in the adjacent `run_key` column, so each event retains both the durable
/// account identity and the exact coordination run without overloading either.
///
/// [`actor`]: Caller::actor
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    credential: String,
    /// The transport the server observed itself serving this call on.
    ///
    /// This is a SERVER-OBSERVED FACT, not a claim: no tool argument can set
    /// it, and the caller cannot fake it. It is deliberately WEAKER than
    /// `executor_kind` — "arrived over MCP" is true whether an agent or a
    /// person holding an MCP credential made the call. Decision 425a001b
    /// settles the consequence: channel may drive a hedged rendering
    /// inference, and may never be written into the attested executor slot.
    channel: Channel,
    /// Unforgeable compatibility boundary for trusted in-process callers.
    /// Public credential construction must never be able to enable it.
    trusted_local: bool,
    /// Host-scoped routing identity. This is deliberately separate from the
    /// portable credential stamped on events and is absent for stdio callers.
    hosting_principal: Option<String>,
    /// Host-scoped selected database. Kept alongside (not instead of) the user
    /// principal so hosting capabilities can authorize the user and act on the
    /// database without changing portable event attribution.
    hosting_database: Option<String>,
    /// Current hosted roster established by the catalog at request ingress.
    /// Routing context alone never populates this capability.
    hosted_activity_roster: Option<Vec<crate::query::principal::ActivityRosterMember>>,
    hosting_owner: bool,
    trusted_audience: TrustedAudience,
    /// Request-scoped hosted discovery preference. Standalone callers leave
    /// this unset and inherit the registry's deployment profile.
    exposure_policy: Option<Arc<ResolvedToolExposure>>,
    run_key: Option<String>,
    parent_key: Option<String>,
    intent: Option<String>,
    /// Present only after a trusted host/UI ingress verifies an unforgeable
    /// human interaction token. Tool arguments can never populate it.
    verified_human_interaction: Option<crate::awareness::VerifiedHumanInteraction>,
    /// Rich verified interaction facts for generic provenance issuance. This is
    /// populated only by the signed ingress verifier, never by tool arguments.
    verified_provenance_interaction: Option<crate::provenance::VerifiedInteractionEvidence>,
    /// Server-verified executor/delegation identity. Asserted run keys are
    /// intentionally insufficient to populate agent provenance.
    verified_agent_executor: Option<crate::awareness::VerifiedAgentExecutor>,
    /// Server-verified third-party service identity. Only the hosted ingress
    /// boundary can attach it; tool arguments have no representation for it.
    verified_delegated_service: Option<VerifiedDelegatedService>,
    /// Exact structured human attribution gesture verified at trusted ingress.
    /// Ordinary tool arguments and general human-interaction tokens cannot set it.
    verified_attribution_declaration: Option<crate::attribution::VerifiedAttributionDeclaration>,
    /// Trusted policy evaluator authority. Ordinary authenticated agent calls
    /// never receive this bit and therefore cannot reroute obligations.
    policy_authority: bool,
    /// Trusted, request-local write-plan claim. Only the in-process executor
    /// can populate this; source tool arguments cannot manufacture it.
    write_plan_execution: Option<WritePlanExecution>,
    /// Trusted, request-local hosted executor claim. Only the signed plan
    /// runtime can populate this; source tool arguments have no representation
    /// for it. Membership handlers consume it to couple their catalogue
    /// mutation to the durable plan claim in one transaction.
    #[cfg(feature = "mcp-executor-prototype")]
    hosted_plan_execution: Option<HostedMembershipPlanExecution>,
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct HostedMembershipPlanExecution {
    plan_id: String,
    attempt_id: String,
    payload_sha256: String,
    operation_evidence: serde_json::Value,
    now_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedDelegatedService {
    pub(crate) endpoint_id: String,
    pub(crate) credential_id: String,
}

#[cfg(feature = "mcp-executor-prototype")]
impl HostedMembershipPlanExecution {
    /// Build a detached execution value. Constructing this value does not
    /// attach it to a [`Caller`]; only the in-process executor can do that.
    #[doc(hidden)]
    pub fn detached(
        plan_id: String,
        attempt_id: String,
        payload_sha256: String,
        operation_evidence: serde_json::Value,
        now_ms: i64,
    ) -> Self {
        Self {
            plan_id,
            attempt_id,
            payload_sha256,
            operation_evidence,
            now_ms,
        }
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    pub fn now_ms(&self) -> i64 {
        self.now_ms
    }

    pub fn catalogue_snapshot(&self) -> Option<&serde_json::Value> {
        self.operation_evidence.get("catalogue_snapshot")
    }

    pub fn cleanup_projection(&self) -> Option<&serde_json::Value> {
        self.operation_evidence
            .pointer("/source_evidence/content_projection")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WritePlanExecution {
    pub plan_id: String,
    pub effect_digest: String,
    pub executor: String,
    pub operation: String,
}

impl Caller {
    pub fn authenticated(identity: impl Into<String>) -> Self {
        Caller {
            credential: identity.into(),
            channel: Channel::Unknown,
            trusted_local: false,
            hosting_principal: None,
            hosting_database: None,
            hosted_activity_roster: None,
            hosting_owner: false,
            trusted_audience: TrustedAudience::Solo,
            exposure_policy: None,
            run_key: None,
            parent_key: None,
            intent: None,
            verified_human_interaction: None,
            verified_provenance_interaction: None,
            verified_agent_executor: None,
            verified_delegated_service: None,
            verified_attribution_declaration: None,
            policy_authority: false,
            write_plan_execution: None,
            #[cfg(feature = "mcp-executor-prototype")]
            hosted_plan_execution: None,
        }
    }

    pub fn local() -> Self {
        let mut caller = Caller::authenticated("local");
        caller.trusted_local = true;
        caller.channel = Channel::Local;
        caller
    }

    /// Host ingress seam for the observed transport. Only a host that knows
    /// which listener it is serving may call this; there is deliberately no
    /// MCP argument for it, and it never influences `executor_kind`.
    pub fn with_channel(mut self, channel: Channel) -> Self {
        self.channel = if self.verified_delegated_service.is_some() {
            Channel::Webhook
        } else {
            channel
        };
        self
    }

    /// The transport this call was observed to arrive on.
    pub fn channel(&self) -> Channel {
        self.channel
    }

    /// Attach the run context a call asserted. Only ever called with keys that
    /// already passed validation — a malformed key arrives here as `None`, which
    /// is the whole of fail-open at this layer.
    pub fn with_run_context(mut self, run_key: Option<String>, parent_key: Option<String>) -> Self {
        self.run_key = run_key;
        self.parent_key = parent_key;
        self
    }

    pub(crate) fn with_intent(mut self, intent: Option<String>) -> Self {
        self.intent = intent;
        self
    }

    /// Attach both pieces of authenticated host routing context. The database
    /// id never becomes the portable credential or event actor.
    #[doc(hidden)]
    pub fn with_hosting_context(
        mut self,
        principal: impl Into<String>,
        database: impl Into<String>,
    ) -> Self {
        self.hosting_principal = Some(principal.into());
        self.hosting_database = Some(database.into());
        self.trusted_audience = TrustedAudience::Unknown;
        self
    }

    /// Attach current hosted membership authority and its portable roster.
    ///
    /// # Safety
    ///
    /// The host must have authenticated `principal`, verified that it is an
    /// active member of `database`, and obtained every roster row from that
    /// same current catalog snapshot. Each roster entry must have been mapped
    /// read-only to the portable identity in this exact workspace. Tool
    /// arguments must never reach this seam.
    #[doc(hidden)]
    pub unsafe fn with_verified_hosted_activity(
        mut self,
        principal: impl Into<String>,
        database: impl Into<String>,
        roster: Vec<crate::query::principal::ActivityRosterMember>,
    ) -> Result<Self> {
        let principal = principal.into();
        let database = database.into();
        if !roster
            .iter()
            .any(|member| member.account_id() == self.credential)
        {
            return Err(Error::auth(
                "verified hosted activity roster does not contain the caller",
            ));
        }
        self.hosting_principal = Some(principal);
        self.hosting_database = Some(database);
        self.hosted_activity_roster = Some(roster);
        self.trusted_audience = TrustedAudience::Unknown;
        Ok(self)
    }

    #[doc(hidden)]
    pub fn with_trusted_audience(mut self, audience: TrustedAudience) -> Self {
        self.trusted_audience = audience;
        self
    }

    pub fn trusted_audience(&self) -> TrustedAudience {
        self.trusted_audience
    }

    #[doc(hidden)]
    pub fn with_hosting_owner(mut self, is_owner: bool) -> Self {
        self.hosting_owner = is_owner;
        self
    }

    #[doc(hidden)]
    pub fn with_exposure_profile(mut self, profile: ExposureProfile) -> Self {
        self.exposure_policy = Some(Arc::new(ResolvedToolExposure::new(profile)));
        self
    }

    #[doc(hidden)]
    pub fn with_exposure_policy(mut self, policy: Arc<ResolvedToolExposure>) -> Self {
        self.exposure_policy = Some(policy);
        self
    }

    pub(crate) fn exposure_policy(&self) -> Option<&ResolvedToolExposure> {
        self.exposure_policy.as_deref()
    }

    /// Host administration is authoritative only for hosted callers. A
    /// standalone/ejected file has no catalog plane; filesystem possession is
    /// its explicit advisory operator boundary.
    pub fn is_host_owner(&self) -> bool {
        self.hosting_database.is_none() || self.hosting_owner
    }

    /// The authenticated identity stamped on every event, independent of any
    /// asserted run context. The full validated run key is stored separately on
    /// the same row and its first word remains the display handle.
    pub fn actor(&self) -> &str {
        &self.credential
    }

    /// The authenticated identity, independent of any asserted key.
    pub fn credential(&self) -> &str {
        &self.credential
    }

    pub(crate) fn is_trusted_local(&self) -> bool {
        self.trusted_local
    }

    pub(crate) fn with_write_plan_execution(mut self, execution: WritePlanExecution) -> Self {
        self.write_plan_execution = Some(execution);
        self
    }

    pub(crate) fn write_plan_execution(&self) -> Option<&WritePlanExecution> {
        self.write_plan_execution.as_ref()
    }

    /// Authenticated hosted principal selected by trusted ingress, when this
    /// call is routed through the hosted control plane.
    #[doc(hidden)]
    pub fn hosting_principal(&self) -> Option<&str> {
        self.hosting_principal.as_deref()
    }

    #[cfg(feature = "mcp-executor-prototype")]
    pub(crate) fn with_hosted_plan_execution(
        mut self,
        execution: HostedMembershipPlanExecution,
    ) -> Self {
        self.hosted_plan_execution = Some(execution);
        self
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[doc(hidden)]
    pub fn hosted_membership_plan_execution(&self) -> Option<&HostedMembershipPlanExecution> {
        self.hosted_plan_execution.as_ref()
    }

    /// Selected hosted database id, when the caller came through hosted HTTP.
    /// This is routing context only; [`Self::credential`] remains the portable
    /// identity used for event attribution.
    pub fn hosting_database(&self) -> Option<&str> {
        self.hosting_database.as_deref()
    }

    pub fn run_key(&self) -> Option<&str> {
        self.run_key.as_deref()
    }

    pub fn parent_key(&self) -> Option<&str> {
        self.parent_key.as_deref()
    }

    pub fn intent(&self) -> Option<&str> {
        self.intent.as_deref()
    }

    pub(crate) fn verified_human_interaction(
        &self,
    ) -> Option<&crate::awareness::VerifiedHumanInteraction> {
        self.verified_human_interaction.as_ref()
    }

    pub(crate) fn has_policy_authority(&self) -> bool {
        self.policy_authority
    }

    pub(crate) fn verified_agent_executor(
        &self,
    ) -> Option<&crate::awareness::VerifiedAgentExecutor> {
        self.verified_agent_executor.as_ref()
    }

    pub(crate) fn verified_delegated_service(&self) -> Option<&VerifiedDelegatedService> {
        self.verified_delegated_service.as_ref()
    }

    pub(crate) fn verified_provenance_interaction(
        &self,
    ) -> Option<&crate::provenance::VerifiedInteractionEvidence> {
        self.verified_provenance_interaction.as_ref()
    }

    pub(crate) fn verified_attribution_declaration(
        &self,
    ) -> Option<&crate::attribution::VerifiedAttributionDeclaration> {
        self.verified_attribution_declaration.as_ref()
    }

    /// Bind a signed UI declaration gesture to the complete canonical accepted
    /// `create_attribution` action. Native derives the closed declaration facts
    /// from that same argument object; callers cannot verify one action and
    /// attach the result to a different target, subject, or assertion.
    pub fn with_attribution_declaration_token(
        mut self,
        issuer: &crate::provenance::ProvenanceInteractionTokenIssuer,
        token: &str,
        accepted_arguments: &serde_json::Value,
    ) -> crate::Result<Self> {
        let declaration =
            crate::attribution::VerifiedAttributionDeclaration::from_accepted_arguments(
                accepted_arguments,
            )?;
        let scope =
            crate::provenance::verified_action_scope("create_attribution", accepted_arguments);
        self.verified_provenance_interaction =
            Some(issuer.verify(token, self.credential(), &scope)?);
        self.verified_attribution_declaration = Some(declaration);
        Ok(self)
    }

    /// Host ingress seam: call only after signature, account, exact action,
    /// expiry, and nonce checks have succeeded. This is deliberately not public
    /// API and has no corresponding MCP argument.
    pub(crate) fn with_verified_human_interaction(
        mut self,
        attestation: crate::awareness::VerifiedHumanInteraction,
    ) -> Self {
        self.verified_human_interaction = Some(attestation);
        self
    }

    /// Generic host ingress seam for a verified human interaction bound to the
    /// full canonical accepted action, not a messaging-specific subject set.
    pub fn with_provenance_interaction_token(
        mut self,
        issuer: &crate::provenance::ProvenanceInteractionTokenIssuer,
        token: &str,
        scope: &serde_json::Value,
    ) -> crate::Result<Self> {
        self.verified_provenance_interaction =
            Some(issuer.verify(token, self.credential(), scope)?);
        Ok(self)
    }

    /// Bind a host-issued, signed and short-lived human gesture to this exact
    /// authenticated account, action, and Message set. Supplying an arbitrary
    /// boolean or ordinary agent metadata cannot pass this verification.
    pub fn with_human_interaction_token(
        mut self,
        issuer: &crate::awareness::HumanInteractionTokenIssuer,
        token: &str,
        action: &str,
        message_ids: &[String],
    ) -> crate::Result<Self> {
        let (attestation, provenance) =
            issuer.verify_for_provenance(token, self.credential(), action, message_ids)?;
        self.verified_provenance_interaction = Some(provenance);
        Ok(self.with_verified_human_interaction(attestation))
    }

    /// Host policy-evaluator seam. The policy version and reason remain durable
    /// in the awareness event; this bit establishes only the trusted ingress.
    pub(crate) fn with_policy_authority(mut self) -> Self {
        self.policy_authority = true;
        self
    }

    /// Bind a signed policy-evaluator decision to the exact account, policy
    /// version, and Message set before enabling route mutation.
    pub fn with_policy_authority_token(
        self,
        issuer: &crate::awareness::HumanInteractionTokenIssuer,
        token: &str,
        policy_version: &str,
        message_ids: &[String],
    ) -> crate::Result<Self> {
        issuer.verify(
            token,
            self.credential(),
            &format!("routing-policy:{policy_version}"),
            message_ids,
        )?;
        Ok(self.with_policy_authority())
    }

    /// Bind server-derived agent executor and delegation provenance to this
    /// account and exact Message set. A run_key supplied in tool arguments can
    /// never create this authority.
    pub fn with_agent_executor_token(
        mut self,
        issuer: &crate::awareness::HumanInteractionTokenIssuer,
        token: &str,
        executor_ref: &str,
        delegation_ref: &str,
        message_ids: &[String],
    ) -> crate::Result<Self> {
        if executor_ref.trim().is_empty() || delegation_ref.trim().is_empty() {
            return Err(crate::Error::engine(
                "agent executor and delegation references must be non-empty",
            ));
        }
        issuer.verify(
            token,
            self.credential(),
            &format!("agent-executor:{executor_ref}:{delegation_ref}"),
            message_ids,
        )?;
        self.verified_agent_executor = Some(crate::awareness::VerifiedAgentExecutor {
            executor_ref: executor_ref.into(),
            delegation_ref: delegation_ref.into(),
        });
        Ok(self)
    }

    /// Attach service identity after the hosting boundary has verified the
    /// endpoint credential and re-established the issuer's live authority.
    ///
    /// # Safety
    ///
    /// The caller must have authenticated `credential_id` for `endpoint_id`,
    /// rechecked the issuing principal's current membership and destination
    /// capability, and kept both identifiers out of caller-controlled tool
    /// arguments. Ordinary MCP callers must never reach this seam.
    #[doc(hidden)]
    pub unsafe fn with_verified_delegated_service(
        mut self,
        endpoint_id: impl Into<String>,
        credential_id: impl Into<String>,
    ) -> crate::Result<Self> {
        let endpoint_id = endpoint_id.into();
        let credential_id = credential_id.into();
        if endpoint_id.trim().is_empty() || credential_id.trim().is_empty() {
            return Err(crate::Error::engine(
                "delegated service endpoint and credential references must be non-empty",
            ));
        }
        self.channel = Channel::Webhook;
        self.verified_delegated_service = Some(VerifiedDelegatedService {
            endpoint_id,
            credential_id,
        });
        Ok(self)
    }
}

/// The one sanctioned crossing from orchestration identity to the narrow
/// query read principal. The trusted-local read bypass requires BOTH
/// `is_trusted_local()` (only `Caller::local()` can set it) and the absence
/// of a hosting database route — the same predicate the SQLite and Postgres
/// executors previously duplicated inline. Effective hosted activity-read is
/// carried only when trusted ingress attached the catalog-authorized current
/// roster for this request; routing fields alone confer no query authority.
impl From<&Caller> for crate::query::QueryPrincipal {
    fn from(caller: &Caller) -> Self {
        if caller.is_trusted_local() && caller.hosting_database().is_none() {
            // SAFETY: this is the sole production crossing into the bypass.
            // The predicate above proves both invariants required by the
            // extracted contract's privileged constructor.
            unsafe { crate::query::QueryPrincipal::trusted_local_unchecked(caller.credential()) }
        } else if let Some(roster) = caller.hosted_activity_roster.as_ref() {
            // SAFETY: QueryPrincipal conversion is the transport-to-query
            // boundary. Trusted hosted ingress attaches this roster only after
            // resolving the caller and all active members in the selected
            // workspace. No tool argument can populate the capability or its
            // admitted rows.
            unsafe {
                crate::query::QueryPrincipal::activity_reader_unchecked(
                    caller.credential(),
                    roster.clone(),
                )
            }
        } else {
            crate::query::QueryPrincipal::authenticated(caller.credential())
        }
    }
}

impl From<Caller> for crate::query::QueryPrincipal {
    fn from(caller: Caller) -> Self {
        (&caller).into()
    }
}

#[cfg(test)]
mod query_principal_conversion_tests {
    use super::Caller;
    use crate::query::QueryPrincipal;

    #[test]
    fn trusted_local_caller_converts_with_the_bypass() {
        let principal = QueryPrincipal::from(&Caller::local());
        assert_eq!(principal.credential(), "local");
        assert!(principal.trusted_local_bypass());
    }

    #[test]
    fn hosting_routing_alone_cannot_grant_activity_read() {
        let caller = Caller::local().with_hosting_context("owner", "db-1");
        let principal = QueryPrincipal::from(&caller);
        assert!(!principal.activity_read());
        assert!(!principal.trusted_local_bypass());
    }

    #[test]
    fn verified_hosted_roster_grants_only_when_it_contains_the_caller() {
        let member = unsafe {
            crate::query::principal::ActivityRosterMember::verified_unchecked(
                "alice",
                "native:workspace-member:alice",
            )
        };
        let caller = unsafe {
            Caller::authenticated("alice").with_verified_hosted_activity(
                "catalog-alice",
                "db-1",
                vec![member],
            )
        }
        .unwrap();
        let principal = QueryPrincipal::from(&caller);
        assert!(principal.activity_read());
        assert_eq!(principal.activity_roster().len(), 1);

        assert!(unsafe {
            Caller::authenticated("bea").with_verified_hosted_activity(
                "catalog-bea",
                "db-1",
                Vec::new(),
            )
        }
        .is_err());
    }

    #[test]
    fn authenticated_caller_converts_without_the_bypass() {
        let principal = QueryPrincipal::from(&Caller::authenticated("alice"));
        assert!(!principal.activity_read());
        assert!(!principal.trusted_local_bypass());
    }
}

/// Physical implementation selected before dispatch. This is deliberately a
/// small closed routing key, not a generic SQL or storage API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EngineKind {
    Sqlite,
    #[cfg(feature = "postgres")]
    Postgres,
    #[cfg(feature = "turso-local")]
    TursoLocal,
}

#[cfg(test)]
mod governed_pipeline_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    use crate::domain_transaction::request::{
        InteractionCapture, RequestLifecyclePort, RequestStageCapability,
    };
    use crate::mcp::TransientEvidence;

    #[derive(Clone, Default)]
    struct FakePortableRequestPort {
        events: Arc<Mutex<Vec<&'static str>>>,
        unsupported: Option<GovernedRequestOperation>,
    }

    impl RequestLifecyclePort for FakePortableRequestPort {
        fn backend_label(&self) -> &'static str {
            "fake-portable"
        }

        fn capability(&self, operation: GovernedRequestOperation) -> RequestStageCapability {
            if self.unsupported == Some(operation) {
                RequestStageCapability::Unsupported
            } else {
                RequestStageCapability::Applied
            }
        }

        fn mint_run_key<'a>(
            &'a self,
            _agent_key: Option<&'a str>,
        ) -> BoxFuture<'a, Result<String>> {
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                events.lock().unwrap().push("mint");
                Ok("minted-key-a748b2".into())
            })
        }

        fn intent_at<'a>(&'a self, _run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>> {
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                events.lock().unwrap().push("intent");
                None
            })
        }

        fn persist_intent<'a>(
            &'a self,
            _run_key: &'a str,
            _intent: &'a str,
            _authenticated_account: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn displaced_key_note<'a>(&'a self, _caller: &'a Caller) -> BoxFuture<'a, Option<String>> {
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                events.lock().unwrap().push("displaced");
                None
            })
        }

        fn with_operation_admission<'a>(
            &'a self,
            operation: &'a str,
            capability: Option<&'a str>,
            future: BoxFuture<'a, Result<ToolResult>>,
        ) -> BoxFuture<'a, Result<ToolResult>> {
            assert_eq!(operation, "portable_parity");
            assert_eq!(capability, Some("native.extension.unclassified"));
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                events.lock().unwrap().push("admission.enter");
                let result = future.await;
                events.lock().unwrap().push("admission.exit");
                result
            })
        }

        fn with_realtime_completion<'a>(
            &'a self,
            future: BoxFuture<'a, Result<ToolResult>>,
        ) -> BoxFuture<'a, Result<ToolResult>> {
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                events.lock().unwrap().push("realtime.enter");
                let result = future.await;
                events.lock().unwrap().push("realtime.exit");
                result
            })
        }

        fn capture_interaction<'a>(&'a self, capture: InteractionCapture<'a>) -> BoxFuture<'a, ()> {
            let events = Arc::clone(&self.events);
            let tool_name = capture.tool_name.to_owned();
            let structured = capture.outcome.ok().cloned();
            let run_key = capture.run_context["run_key"].as_str().map(str::to_owned);
            Box::pin(async move {
                assert_eq!(tool_name, "portable_parity");
                assert_eq!(structured, Some(serde_json::json!({"ok": true})));
                assert_eq!(run_key.as_deref(), Some("scout-chair-a748b2"));
                events.lock().unwrap().push("interaction");
            })
        }
    }

    #[test]
    fn dispatch_pipeline_exactly_equals_the_governed_request_inventory() {
        assert!(governed_request_pipeline_is_exhaustive());
        let pipeline = GOVERNED_REQUEST_PIPELINE
            .iter()
            .map(|stage| stage.operation.id())
            .collect::<BTreeSet<_>>();
        let governed = GovernedRequestOperation::ALL
            .iter()
            .map(|operation| operation.id())
            .collect::<BTreeSet<_>>();
        assert_eq!(pipeline, governed);
        assert!(GOVERNED_REQUEST_PIPELINE
            .iter()
            .all(|stage| !stage.dispatch_responsibility.is_empty()));
    }

    #[tokio::test]
    async fn real_dispatch_records_every_wrapper_in_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pipeline.sqlite3");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();

        let captured = registry
            .call_detailed(db.clone(), Caller::local(), "ping", serde_json::json!({}))
            .await
            .unwrap();
        let recorded = captured
            .governed_request_trace
            .iter()
            .map(|event| event.operation)
            .collect::<Vec<_>>();
        let expected = GOVERNED_REQUEST_PIPELINE
            .iter()
            .map(|stage| stage.operation)
            .collect::<Vec<_>>();
        assert_eq!(recorded, expected);
        assert!(captured
            .governed_request_trace
            .iter()
            .all(|event| event.disposition == GovernedRequestStageDisposition::Applied));

        let uncaptured = registry
            .call_detailed_uncaptured(db.clone(), Caller::local(), "ping", serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(
            uncaptured.governed_request_trace[5],
            GovernedRequestStageEvent {
                operation: GovernedRequestOperation::InteractionCapture,
                disposition: GovernedRequestStageDisposition::Suppressed,
            }
        );
        assert_eq!(
            uncaptured
                .governed_request_trace
                .iter()
                .map(|event| event.operation)
                .collect::<Vec<_>>(),
            expected
        );
        db.close().await;
    }

    #[tokio::test]
    async fn all_applied_non_sqlite_port_matches_sqlite_request_results() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("portable-parity.sqlite3");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        let mut registry = ToolRegistry::new();
        registry
            .register_custom(
                "portable_parity",
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                "portable request parity",
                serde_json::json!({"type": "object", "properties": {}}),
                |_db, caller, arguments| async move {
                    assert_eq!(caller.run_key(), Some("scout-chair-a748b2"));
                    assert!(arguments.as_object().unwrap().is_empty());
                    Ok(ToolResult::rich(
                        serde_json::json!({"ok": true}),
                        vec![TransientEvidence::image("proof", "image/png", b"pixels")?],
                    ))
                },
            )
            .unwrap();
        let arguments = serde_json::json!({"run_key": "scout-chair-a748b2"});
        let sqlite = registry
            .call_detailed(
                db.clone(),
                Caller::local(),
                "portable_parity",
                arguments.clone(),
            )
            .await
            .unwrap();

        let fake = FakePortableRequestPort::default();
        let handler_events = Arc::clone(&fake.events);
        let portable = crate::domain_transaction::request::execute_request(
            &fake,
            Caller::local(),
            "portable_parity",
            None,
            Extractor::Custom(CustomInteractionPolicy::NoRecordInteractions),
            arguments,
            true,
            None,
            None,
            move |caller, arguments| {
                let events = Arc::clone(&handler_events);
                async move {
                    assert_eq!(caller.run_key(), Some("scout-chair-a748b2"));
                    assert!(arguments.as_object().unwrap().is_empty());
                    events.lock().unwrap().push("handler");
                    Ok(ToolResult::rich(
                        serde_json::json!({"ok": true}),
                        vec![TransientEvidence::image("proof", "image/png", b"pixels")?],
                    ))
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(portable.original_arguments, sqlite.original_arguments);
        assert_eq!(portable.run_context, sqlite.run_context);
        assert_eq!(
            portable.governed_request_trace,
            sqlite.governed_request_trace
        );
        assert!(portable
            .governed_request_trace
            .iter()
            .all(|event| event.disposition == GovernedRequestStageDisposition::Applied));
        let portable_result = portable.outcome.unwrap();
        let sqlite_result = sqlite.outcome.unwrap();
        assert_eq!(portable_result.structured, sqlite_result.structured);
        assert_eq!(portable_result.evidence.len(), sqlite_result.evidence.len());
        for (portable, sqlite) in portable_result.evidence.iter().zip(&sqlite_result.evidence) {
            assert_eq!(portable.handle, sqlite.handle);
            assert_eq!(portable.kind, sqlite.kind);
            assert_eq!(portable.media_type, sqlite.media_type);
            assert_eq!(portable.bytes, sqlite.bytes);
        }
        assert_eq!(
            *fake.events.lock().unwrap(),
            [
                "intent",
                "displaced",
                "realtime.enter",
                "admission.enter",
                "handler",
                "admission.exit",
                "realtime.exit",
                "interaction",
            ]
        );
        db.close().await;
    }

    #[tokio::test]
    async fn unsupported_request_capability_fails_before_handler_execution() {
        let fake = FakePortableRequestPort {
            unsupported: Some(GovernedRequestOperation::InteractionCapture),
            ..FakePortableRequestPort::default()
        };
        let handler_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&handler_called);
        let result = crate::domain_transaction::request::execute_request(
            &fake,
            Caller::local(),
            "portable_parity",
            None,
            Extractor::Custom(CustomInteractionPolicy::NoRecordInteractions),
            serde_json::json!({}),
            true,
            None,
            None,
            move |_, _| {
                called.store(true, Ordering::SeqCst);
                async { Ok(ToolResult::from(serde_json::json!({"ok": true}))) }
            },
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("unsupported request capability reached the handler"),
        };

        assert_eq!(
            error.to_string(),
            "fake-portable request capability 'request.interaction-capture' is unsupported"
        );
        assert!(!handler_called.load(Ordering::SeqCst));
        assert!(fake.events.lock().unwrap().is_empty());
    }
}

impl EngineKind {
    fn label(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            #[cfg(feature = "postgres")]
            Self::Postgres => "postgres",
            #[cfg(feature = "turso-local")]
            Self::TursoLocal => "turso-local",
        }
    }
}

/// Opaque database selected by a transport or contract harness.
#[derive(Clone)]
pub enum EngineHandle {
    Sqlite(Db),
    #[cfg(feature = "postgres")]
    Postgres(crate::postgres::PostgresDb),
    #[cfg(feature = "turso-local")]
    TursoLocal(crate::turso_local::TursoLocalDb),
}

impl EngineHandle {
    pub fn kind(&self) -> EngineKind {
        match self {
            Self::Sqlite(_) => EngineKind::Sqlite,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => EngineKind::Postgres,
            #[cfg(feature = "turso-local")]
            Self::TursoLocal(_) => EngineKind::TursoLocal,
        }
    }

    fn sqlite(&self) -> Option<&Db> {
        match self {
            Self::Sqlite(db) => Some(db),
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => None,
            #[cfg(feature = "turso-local")]
            Self::TursoLocal(_) => None,
        }
    }

    fn into_sqlite(self) -> Db {
        match self {
            Self::Sqlite(db) => db,
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => {
                unreachable!("registry selected the SQLite handler for Postgres")
            }
            #[cfg(feature = "turso-local")]
            Self::TursoLocal(_) => {
                unreachable!("registry selected the SQLite handler for Turso-local")
            }
        }
    }
}

impl From<Db> for EngineHandle {
    fn from(db: Db) -> Self {
        Self::Sqlite(db)
    }
}

struct SqliteRequestLifecycle<'a> {
    db: &'a Db,
    persistence_lease: Option<DeploymentPersistenceLease>,
}

impl crate::domain_transaction::request::RequestLifecyclePort for SqliteRequestLifecycle<'_> {
    fn backend_label(&self) -> &'static str {
        "sqlite"
    }

    fn capability(
        &self,
        _operation: GovernedRequestOperation,
    ) -> crate::domain_transaction::request::RequestStageCapability {
        crate::domain_transaction::request::RequestStageCapability::Applied
    }

    fn mint_run_key<'a>(&'a self, agent_key: Option<&'a str>) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            match agent_key {
                Some(agent_key) => crate::runkey::suggest_for_agent(self.db, agent_key).await,
                None => crate::runkey::suggest(self.db).await,
            }
        })
    }

    fn intent_at<'a>(&'a self, run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>> {
        Box::pin(crate::runkey::intent_at(self.db, run_key))
    }

    fn persist_intent<'a>(
        &'a self,
        run_key: &'a str,
        _intent: &'a str,
        authenticated_account: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            crate::control::ensure_agent_run(self.db, run_key, authenticated_account)
                .await
                .map(|_| ())
        })
    }

    fn displaced_key_note<'a>(&'a self, caller: &'a Caller) -> BoxFuture<'a, Option<String>> {
        Box::pin(crate::runkey::displaced_key_note(self.db, caller))
    }

    fn with_operation_admission<'a>(
        &'a self,
        operation: &'a str,
        capability: Option<&'a str>,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>> {
        Box::pin(crate::storage_profile::with_operation(
            self.db, operation, capability, future,
        ))
    }

    fn with_realtime_completion<'a>(
        &'a self,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>> {
        Box::pin(self.db.with_request_realtime_completion(future))
    }

    fn capture_interaction<'a>(
        &'a self,
        capture: crate::domain_transaction::request::InteractionCapture<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Some(task) = super::interactions::spawn_record_call(
                self.db,
                capture.extractor,
                capture.tool_name,
                capture.caller,
                capture.original_arguments,
                capture.run_context,
                capture.outcome,
                capture.started_at,
                capture.ended_at,
                Some("native.interaction-log.v1"),
                self.persistence_lease.clone(),
            ) {
                let _ = task.await;
            }
        })
    }
}

/// Explicit compatibility port for a routed backend whose current partial
/// slice predates the canonical physical request capabilities. Nothing is
/// inferred from a missing database handle; every suppressed operation is
/// named here and remains visible in the governed trace.
struct SuppressedRequestLifecycle {
    backend: &'static str,
}

#[cfg(feature = "postgres")]
struct PostgresRequestLifecycle<'a> {
    db: &'a crate::postgres::PostgresDb,
}

#[cfg(feature = "postgres")]
impl crate::domain_transaction::request::RequestLifecyclePort for PostgresRequestLifecycle<'_> {
    fn backend_label(&self) -> &'static str {
        "postgres"
    }

    fn capability(
        &self,
        _operation: GovernedRequestOperation,
    ) -> crate::domain_transaction::request::RequestStageCapability {
        crate::domain_transaction::request::RequestStageCapability::Applied
    }

    fn mint_run_key<'a>(&'a self, agent_key: Option<&'a str>) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.db.mint_run_key(agent_key))
    }

    fn intent_at<'a>(&'a self, run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>> {
        Box::pin(self.db.intent_at(run_key))
    }

    fn persist_intent<'a>(
        &'a self,
        run_key: &'a str,
        intent: &'a str,
        _authenticated_account: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.db.persist_intent(run_key, intent))
    }

    fn displaced_key_note<'a>(&'a self, _caller: &'a Caller) -> BoxFuture<'a, Option<String>> {
        // Explicitly not applicable, not deferred. The displacement note is an
        // advisory reading of SQLite's disposable read log, and this profile
        // declares no equivalent evidence tier. Synthesising one from the
        // Postgres request-interaction rows would invent a semantics the
        // profile does not claim, so no note is produced for any caller.
        Box::pin(async { None })
    }

    fn with_operation_admission<'a>(
        &'a self,
        operation: &'a str,
        capability: Option<&'a str>,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>> {
        Box::pin(
            self.db
                .with_operation_admission(operation, capability, future),
        )
    }

    fn with_realtime_completion<'a>(
        &'a self,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>> {
        Box::pin(self.db.with_request_realtime_completion(future))
    }

    fn capture_interaction<'a>(
        &'a self,
        capture: crate::domain_transaction::request::InteractionCapture<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.db.capture_request_interaction(capture))
    }
}

impl crate::domain_transaction::request::RequestLifecyclePort for SuppressedRequestLifecycle {
    fn backend_label(&self) -> &'static str {
        self.backend
    }

    fn capability(
        &self,
        operation: GovernedRequestOperation,
    ) -> crate::domain_transaction::request::RequestStageCapability {
        use crate::domain_transaction::request::RequestStageCapability::{Applied, Suppressed};
        match operation {
            GovernedRequestOperation::RunContext
            | GovernedRequestOperation::StrictPortability
            | GovernedRequestOperation::RealtimeWakeup
            | GovernedRequestOperation::InteractionCapture => Suppressed,
            GovernedRequestOperation::Authorization
            | GovernedRequestOperation::TransientEvidence
            | GovernedRequestOperation::StableErrors => Applied,
        }
    }

    fn mint_run_key<'a>(&'a self, _agent_key: Option<&'a str>) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { Err(Error::engine("run-key persistence is suppressed")) })
    }

    fn intent_at<'a>(&'a self, _run_key: Option<&'a str>) -> BoxFuture<'a, Option<String>> {
        Box::pin(async { None })
    }

    fn persist_intent<'a>(
        &'a self,
        _run_key: &'a str,
        _intent: &'a str,
        _authenticated_account: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::engine("run-context persistence is suppressed")) })
    }

    fn displaced_key_note<'a>(&'a self, _caller: &'a Caller) -> BoxFuture<'a, Option<String>> {
        Box::pin(async { None })
    }

    fn with_operation_admission<'a>(
        &'a self,
        _operation: &'a str,
        _capability: Option<&'a str>,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>> {
        future
    }

    fn with_realtime_completion<'a>(
        &'a self,
        future: BoxFuture<'a, Result<ToolResult>>,
    ) -> BoxFuture<'a, Result<ToolResult>> {
        future
    }

    fn capture_interaction<'a>(
        &'a self,
        _capture: crate::domain_transaction::request::InteractionCapture<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

#[cfg(feature = "postgres")]
impl From<crate::postgres::PostgresDb> for EngineHandle {
    fn from(db: crate::postgres::PostgresDb) -> Self {
        Self::Postgres(db)
    }
}

#[cfg(feature = "turso-local")]
impl From<crate::turso_local::TursoLocalDb> for EngineHandle {
    fn from(db: crate::turso_local::TursoLocalDb) -> Self {
        Self::TursoLocal(db)
    }
}

/// A registered handler: backend + caller + structured JSON in, rich
/// transport-neutral result out.
type HandlerFn = Arc<
    dyn Fn(EngineHandle, Caller, Value) -> BoxFuture<'static, Result<ToolResult>> + Send + Sync,
>;

#[allow(clippy::too_many_arguments)]
async fn dispatch_with_request_port<
    P: crate::domain_transaction::request::RequestLifecyclePort + ?Sized,
>(
    port: &P,
    engine: EngineHandle,
    caller: Caller,
    name: &str,
    kind: Option<ToolKind>,
    extractor: Extractor,
    arguments: Value,
    capture: bool,
    public_origin: Option<&str>,
    bootstrap_exposure: Option<Value>,
    handler: &HandlerFn,
) -> Result<ToolCallOutcome> {
    crate::domain_transaction::request::execute_request(
        port,
        caller,
        name,
        kind,
        extractor,
        arguments,
        capture,
        public_origin,
        bootstrap_exposure,
        // The one argument-admission chokepoint that has both the arguments
        // and a database handle. `execute_request` has already stripped the
        // run context by the time this runs, so abbreviated record ids are
        // expanded to full ids before any handler — and therefore before any
        // durable row — can observe them. Resolving here rather than at each
        // of the ~200 id-shaped parameter sites is what keeps the affordance
        // from decaying as the tool surface grows.
        |caller, arguments| async move {
            let arguments =
                crate::mcp::record_ref::resolve_record_ids(&engine, &caller, name, arguments)
                    .await?;
            handler(engine, caller, arguments).await
        },
    )
    .await
}

/// One registered tool: name + JSON-Schema argument shape + handler.
#[derive(Clone, Copy)]
enum EngineOperationSupport {
    None,
    All,
    SelectorValues {
        field: &'static str,
        values: &'static [&'static str],
    },
}

struct EngineHandler {
    call: HandlerFn,
    operations: EngineOperationSupport,
}

pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's arguments (MCP `inputSchema`).
    pub input_schema: Value,
    /// `Some` for every builtin and v1 surface tool. `None` is reserved for the
    /// explicit extension registration path.
    pub kind: Option<ToolKind>,
    /// Discovery metadata. This is never consulted by dispatch or
    /// authorization; it only determines which named profiles advertise the
    /// already-registered capability.
    pub exposure: ToolExposure,
    /// MCP Apps metadata owned by the registry. Transports serialize this
    /// uniformly; protocol code must never switch on a tool name.
    pub ui: Option<AppMetadata>,
    /// Exact schemas hydrated only after an action selector is chosen. These
    /// are registry authority, but deliberately do not enlarge the compact
    /// direct-tool descriptor advertised by [`descriptor`](Self::descriptor).
    operation_schemas: HashMap<String, Value>,
    extractor: Extractor,
    handlers: HashMap<EngineKind, EngineHandler>,
}

impl ToolSpec {
    pub(crate) fn operation_schema(&self, selector_value: &str) -> Option<&Value> {
        self.operation_schemas.get(selector_value)
    }

    /// The authored MCP descriptor before surface-specific runtime projection.
    pub fn descriptor(&self) -> Value {
        let mut descriptor = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        });
        if let Some(ui) = &self.ui {
            descriptor
                .as_object_mut()
                .expect("descriptor object")
                .insert(
                    "_meta".into(),
                    serde_json::json!({
                        "ui": {
                            "resourceUri": ui.resource_uri,
                            "visibility": ui.visibility,
                        },
                        "ui/resourceUri": ui.resource_uri,
                    }),
                );
        }
        descriptor
    }

    pub fn descriptor_bytes(&self) -> usize {
        serde_json::to_vec(&self.descriptor())
            .expect("tool descriptors are JSON values")
            .len()
    }
}

/// One classified descriptor in an actual transport discovery projection.
/// Projections may overlay schemas or add transport-only capabilities, but
/// every emitted descriptor must still carry the same exposure metadata.
#[derive(Clone, Debug)]
pub struct AdvertisedTool {
    pub name: String,
    pub descriptor: Value,
    pub exposure: ToolExposure,
}

impl AdvertisedTool {
    pub fn descriptor_bytes(&self) -> usize {
        serde_json::to_vec(&self.descriptor)
            .expect("tool descriptors are JSON values")
            .len()
    }
}

pub fn descriptor_projection_bytes(tools: &[AdvertisedTool]) -> usize {
    let descriptors = tools
        .iter()
        .map(|tool| &tool.descriptor)
        .collect::<Vec<_>>();
    serde_json::to_vec(&descriptors)
        .expect("tool descriptors are JSON values")
        .len()
}

pub fn validate_descriptor_projection(
    surface: &str,
    profile: ExposureProfile,
    tools: &[AdvertisedTool],
    limit: usize,
) -> Result<()> {
    let total = descriptor_projection_bytes(tools);
    if total <= limit {
        return Ok(());
    }
    let mut deltas = tools
        .iter()
        .map(|tool| (tool.name.as_str(), tool.descriptor_bytes()))
        .collect::<Vec<_>>();
    deltas.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
    let largest = deltas
        .into_iter()
        .take(10)
        .map(|(name, bytes)| format!("{name}={bytes}"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::engine(format!(
        "MCP {surface} {profile} profile is {total} bytes; limit is {limit}; largest descriptor deltas: {largest}"
    )))
}

/// UI resource associated with an MCP Apps launcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppMetadata {
    pub resource_uri: &'static str,
    pub visibility: &'static [&'static str],
}

impl AppMetadata {
    pub const fn model_and_app(resource_uri: &'static str) -> Self {
        Self {
            resource_uri,
            visibility: &["model", "app"],
        }
    }
}

/// The registry both transports dispatch through. Tools are registered once;
/// registration order is preserved (it is the `tools/list` order).
#[derive(Default)]
pub struct ToolRegistry {
    tools: Vec<ToolSpec>,
    exposure_profile: ExposureProfile,
    /// Standby is a runtime capability boundary, not a discovery preference.
    /// Discovery is narrowed for usability, while exact-name dispatch is
    /// independently rejected below.
    standby_read_only: bool,
    /// Verified activation and live refresh evidence for a local standby.
    /// Kept separate from the capability bit so tests and non-process callers
    /// can still exercise the fail-closed admission policy in isolation.
    standby_status: Option<crate::standby::StandbyStatusProvider>,
    /// Optional process-wide persistence boundary for hosted deployment
    /// transitions. Immutable standby remains a separate capability mode.
    deployment_mutation_barrier: Option<DeploymentMutationBarrier>,
    /// Deployment-authoritative origin for model-facing follow links. `None`
    /// is the stdio/local shape and deliberately renders a relative route.
    public_origin: Option<String>,
    /// Optional deployment-authoritative short-link origin. There is no
    /// default: local, stdio, and self-hosted registries must never cause an
    /// agent to guess that the hosted short domain applies to their records.
    share_origin: Option<String>,
}

/// Attach deployment-authoritative absolute addresses anywhere a read
/// projection already carries the canonical relative record paths. The
/// relative fields remain the durable substrate contract; these annotations
/// are deliberately absent when their corresponding origin is unconfigured.
fn annotate_record_urls(
    tool: &str,
    value: &mut Value,
    public_origin: Option<&str>,
    share_origin: Option<&str>,
) {
    if !matches!(tool, "get_record" | "query_record" | "search" | "scan") {
        return;
    }
    annotate_record_urls_in_projection(value, public_origin, share_origin);
}

fn annotate_record_urls_in_projection(
    value: &mut Value,
    public_origin: Option<&str>,
    share_origin: Option<&str>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                annotate_record_urls_in_projection(item, public_origin, share_origin);
            }
        }
        Value::Object(object) => {
            let record_path = object.get("record_path").and_then(Value::as_str);
            let engine_record_path = object
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| uuid::Uuid::parse_str(id).ok().map(|parsed| (id, parsed)))
                .zip(object.get("record_path_full").and_then(Value::as_str))
                .filter(|((id, parsed), full_path)| {
                    parsed.hyphenated().to_string() == *id
                        && full_path.strip_prefix('/') == Some(*id)
                })
                .and(record_path)
                .filter(|path| path.starts_with('/'))
                .map(str::to_owned);
            if let Some(path) = engine_record_path {
                // Remove handler-supplied absolute annotations in the absent
                // case. The registry is the sole authority, so transports and
                // agents cannot inherit a guessed or stale deployment hostname.
                object.remove("record_url");
                object.remove("share_url");
                if let Some(origin) = public_origin {
                    object.insert(
                        "record_url".into(),
                        Value::String(format!("{origin}{path}")),
                    );
                }
                if let Some(origin) = share_origin {
                    object.insert("share_url".into(), Value::String(format!("{origin}{path}")));
                }
            }
            for (key, child) in object.iter_mut() {
                // Open facet values and anchored-target selector payloads are
                // user content, not nested record projections.
                if matches!(key.as_str(), "facets" | "target") {
                    continue;
                }
                annotate_record_urls_in_projection(child, public_origin, share_origin);
            }
        }
        _ => {}
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        ToolRegistry::default()
    }

    /// Set the already-validated public origin used by universal run echoes.
    /// Validation belongs to deployment configuration, not this shared seam.
    pub fn set_public_origin(&mut self, origin: Option<String>) {
        self.public_origin = origin;
    }

    /// Set the already-validated short-link origin used on record projections.
    pub fn set_share_origin(&mut self, origin: Option<String>) {
        self.share_origin = origin;
    }

    pub fn set_exposure_profile(&mut self, profile: ExposureProfile) {
        self.exposure_profile = profile;
    }

    pub fn set_standby_read_only(&mut self, standby_read_only: bool) {
        self.standby_read_only = standby_read_only;
    }

    pub fn set_standby_status_provider(&mut self, provider: crate::standby::StandbyStatusProvider) {
        self.standby_read_only = true;
        self.standby_status = Some(provider);
    }

    pub fn is_standby_read_only(&self) -> bool {
        self.standby_read_only
    }

    pub fn set_deployment_mutation_barrier(&mut self, barrier: DeploymentMutationBarrier) {
        self.deployment_mutation_barrier = Some(barrier);
    }

    pub fn deployment_mutation_barrier(&self) -> Option<&DeploymentMutationBarrier> {
        self.deployment_mutation_barrier.as_ref()
    }

    pub fn exposure_profile(&self) -> ExposureProfile {
        self.exposure_profile
    }

    pub(crate) fn public_origin(&self) -> Option<&str> {
        self.public_origin.as_deref()
    }

    pub(crate) fn share_origin(&self) -> Option<&str> {
        self.share_origin.as_deref()
    }

    fn annotate_record_urls(&self, tool: &str, outcome: &mut ToolCallOutcome) {
        let Ok(result) = &mut outcome.outcome else {
            return;
        };
        annotate_record_urls(
            tool,
            &mut result.structured,
            self.public_origin(),
            self.share_origin(),
        );
    }

    async fn annotate_standby_status(&self, tool: &str, outcome: &mut ToolCallOutcome) {
        let (Some(provider), Ok(result)) = (&self.standby_status, &mut outcome.outcome) else {
            return;
        };
        let Some(object) = result.structured.as_object_mut() else {
            return;
        };
        match tool {
            // Bootstrap receives the same full shape through its bounded
            // tool-exposure component. The dedicated status tool already
            // returns the provider's full report directly.
            "bootstrap" | "standby_status" => {}
            "engine_info" => {
                object.insert(
                    "runtime".into(),
                    serde_json::to_value(Box::pin(provider.status()).await)
                        .expect("standby status is serializable"),
                );
            }
            _ => {
                object.insert(
                    "standby_context".into(),
                    serde_json::to_value(provider.response_context())
                        .expect("standby response context is serializable"),
                );
            }
        }
    }

    /// Register a tool. Names are unique — a second registration under the
    /// same name is a programming error, rejected rather than shadowed.
    pub fn register<F, Fut, Output>(
        &mut self,
        kind: ToolKind,
        description: &str,
        input_schema: Value,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Db, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        self.register_inner(
            kind.name(),
            Some(kind),
            Extractor::Shipped(kind),
            kind.exposure(),
            description,
            input_schema,
            None,
            handler,
        )
    }

    /// Register a shipped tool whose result is rendered by an MCP App.
    pub fn register_app<F, Fut, Output>(
        &mut self,
        kind: ToolKind,
        description: &str,
        input_schema: Value,
        ui: AppMetadata,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Db, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        self.register_inner(
            kind.name(),
            Some(kind),
            Extractor::Shipped(kind),
            kind.exposure(),
            description,
            input_schema,
            Some(ui),
            handler,
        )
    }

    /// Register an embedding-specific synthetic tool.
    ///
    /// Production builtin/surface registrars must use [`register`] and its
    /// exhaustive [`ToolKind`]. This path requires an explicit interaction
    /// policy and is audited out of the shipped registry by tests, so it cannot
    /// silently become the way tool 27 bypasses the extractor decision.
    pub fn register_custom<F, Fut, Output>(
        &mut self,
        name: &str,
        interaction_policy: CustomInteractionPolicy,
        exposure: ToolExposure,
        description: &str,
        input_schema: Value,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Db, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        self.register_inner(
            name,
            None,
            Extractor::Custom(interaction_policy),
            exposure,
            description,
            input_schema,
            None,
            handler,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_inner<F, Fut, Output>(
        &mut self,
        name: &str,
        kind: Option<ToolKind>,
        extractor: Extractor,
        exposure: ToolExposure,
        description: &str,
        mut input_schema: Value,
        ui: Option<AppMetadata>,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(Db, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        if self.tools.iter().any(|tool| tool.name == name) {
            return Err(Error::engine(format!("tool already registered: {name}")));
        }
        add_run_context_arguments(&mut input_schema, kind);
        let mut handlers: HashMap<EngineKind, EngineHandler> = HashMap::new();
        handlers.insert(
            EngineKind::Sqlite,
            EngineHandler {
                call: Arc::new(move |engine, caller, args| {
                    let db = engine.into_sqlite();
                    handler(db, caller, args)
                        .map(|result| result.map(Into::into))
                        .boxed()
                }),
                operations: EngineOperationSupport::All,
            },
        );
        self.tools.push(ToolSpec {
            name: name.to_string(),
            description: description.to_string(),
            input_schema,
            kind,
            exposure,
            ui,
            operation_schemas: HashMap::new(),
            extractor,
            handlers,
        });
        Ok(())
    }

    /// Attach an exact progressive-disclosure schema to one selector value.
    /// The shared direct-tool schema remains the dispatch and discovery
    /// envelope; executor contracts may hydrate this narrower registered
    /// schema once they have resolved the selector.
    pub(crate) fn register_operation_schema(
        &mut self,
        name: &str,
        selector_value: &str,
        schema: Value,
    ) -> Result<()> {
        if selector_value.is_empty() {
            return Err(Error::engine(format!(
                "tool {name} operation schema selector cannot be empty"
            )));
        }
        let tool = self
            .tools
            .iter_mut()
            .find(|tool| tool.name == name)
            .ok_or_else(|| Error::engine(format!("unknown tool: {name}")))?;
        if tool.operation_schemas.contains_key(selector_value) {
            return Err(Error::engine(format!(
                "tool {name} already has an operation schema for {selector_value}"
            )));
        }
        tool.operation_schemas
            .insert(selector_value.to_string(), schema);
        Ok(())
    }

    /// Register one physical implementation for an already-advertised tool.
    ///
    /// Tool metadata remains single-source: a backend can implement a selected
    /// vertical slice, but it cannot silently redefine the MCP name or schema.
    pub fn register_engine_handler<F, Fut, Output>(
        &mut self,
        name: &str,
        engine_kind: EngineKind,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(EngineHandle, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        self.register_engine_handler_inner(name, engine_kind, EngineOperationSupport::All, handler)
    }

    /// Register a backend implementation that truthfully supports only the
    /// named selector branches of a shared legacy tool schema.
    pub fn register_engine_handler_for_selector_values<F, Fut, Output>(
        &mut self,
        name: &str,
        engine_kind: EngineKind,
        field: &'static str,
        values: &'static [&'static str],
        handler: F,
    ) -> Result<()>
    where
        F: Fn(EngineHandle, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        if values.is_empty() {
            return Err(Error::engine(format!(
                "tool {name} backend operation support cannot be empty"
            )));
        }
        self.register_engine_handler_inner(
            name,
            engine_kind,
            EngineOperationSupport::SelectorValues { field, values },
            handler,
        )
    }

    fn register_engine_handler_inner<F, Fut, Output>(
        &mut self,
        name: &str,
        engine_kind: EngineKind,
        operations: EngineOperationSupport,
        handler: F,
    ) -> Result<()>
    where
        F: Fn(EngineHandle, Caller, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output>> + Send + 'static,
        Output: Into<ToolResult> + 'static,
    {
        let tool = self
            .tools
            .iter_mut()
            .find(|tool| tool.name == name)
            .ok_or_else(|| Error::engine(format!("unknown tool: {name}")))?;
        if tool.handlers.contains_key(&engine_kind) {
            return Err(Error::engine(format!(
                "tool {name} already has a {} handler",
                engine_kind.label()
            )));
        }
        tool.handlers.insert(
            engine_kind,
            EngineHandler {
                call: Arc::new(move |engine, caller, args| {
                    handler(engine, caller, args)
                        .map(|result| result.map(Into::into))
                        .boxed()
                }),
                operations,
            },
        );
        Ok(())
    }

    /// Mark a descriptor-only registration as non-executable. Generators use
    /// this after reusing the production schema registrar; runtime registrars
    /// must retain their concrete handler.
    pub(crate) fn mark_engine_operations_unavailable(
        &mut self,
        name: &str,
        engine_kind: EngineKind,
    ) -> Result<()> {
        let tool = self
            .tools
            .iter_mut()
            .find(|tool| tool.name == name)
            .ok_or_else(|| Error::engine(format!("unknown tool: {name}")))?;
        let handler = tool.handlers.get_mut(&engine_kind).ok_or_else(|| {
            Error::engine(format!(
                "tool {name} has no {} handler to mark unavailable",
                engine_kind.label()
            ))
        })?;
        handler.operations = EngineOperationSupport::None;
        Ok(())
    }

    /// Look a tool up by name (metadata only — dispatch goes through [`call`]).
    ///
    /// [`call`]: ToolRegistry::call
    pub fn get(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.iter().find(|tool| tool.name == name)
    }

    /// Whether the named tool has a concrete handler for one physical engine.
    ///
    /// This is release-evidence introspection, not dispatch or capability
    /// negotiation. The backend contract manifest uses it to prevent a
    /// "proven" classification from drifting away from the registry that will
    /// actually receive exact-name calls.
    pub fn has_engine_handler(&self, name: &str, engine_kind: EngineKind) -> bool {
        self.get(name)
            .is_some_and(|tool| tool.handlers.contains_key(&engine_kind))
    }

    /// Whether one exact source operation has executable backend evidence.
    /// Selector-shaped handlers may support fewer operations than their shared
    /// schema advertises; descriptor-only registrations support none.
    pub fn has_engine_operation(
        &self,
        name: &str,
        engine_kind: EngineKind,
        selector: Option<(&str, &str)>,
    ) -> bool {
        let Some(handler) = self
            .get(name)
            .and_then(|tool| tool.handlers.get(&engine_kind))
        else {
            return false;
        };
        match handler.operations {
            EngineOperationSupport::None => false,
            EngineOperationSupport::All => true,
            EngineOperationSupport::SelectorValues { field, values } => {
                selector.is_some_and(|(selected_field, selected_value)| {
                    selected_field == field && values.contains(&selected_value)
                })
            }
        }
    }

    /// All registered tools, in registration order.
    pub fn specs(&self) -> impl Iterator<Item = &ToolSpec> {
        self.tools.iter()
    }

    /// Tools advertised for the configured profile, in complete-registry
    /// order. Hidden tools remain in [`Self::specs`] and [`Self::get`].
    pub fn advertised_specs(&self) -> impl Iterator<Item = &ToolSpec> {
        self.specs_for_profile(self.exposure_profile)
    }

    pub fn specs_for_profile(&self, profile: ExposureProfile) -> impl Iterator<Item = &ToolSpec> {
        self.tools.iter().filter(move |tool| {
            tool.exposure.shown_in(profile)
                && (!self.standby_read_only
                    || tool
                        .kind
                        .is_some_and(|kind| kind.standby_disposition().has_read_operation()))
        })
    }

    pub fn specs_for_policy<'a>(
        &'a self,
        policy: &'a ResolvedToolExposure,
    ) -> impl Iterator<Item = &'a ToolSpec> + 'a {
        self.tools.iter().filter(move |tool| {
            policy.shows(&tool.name, tool.exposure)
                && (!self.standby_read_only
                    || tool
                        .kind
                        .is_some_and(|kind| kind.standby_disposition().has_read_operation()))
        })
    }

    /// Exact compact JSON bytes of the descriptor array returned as
    /// `result.tools`, excluding the surrounding MCP result/envelope.
    pub fn descriptor_array_bytes(&self, profile: ExposureProfile) -> usize {
        descriptor_projection_bytes(&self.descriptor_projection(profile))
    }

    pub fn descriptor_projection(&self, profile: ExposureProfile) -> Vec<AdvertisedTool> {
        self.specs_for_profile(profile)
            .map(|tool| AdvertisedTool {
                name: tool.name.clone(),
                descriptor: self.descriptor_for_runtime(tool),
                exposure: tool.exposure,
            })
            .collect()
    }

    pub fn descriptor_projection_for_policy(
        &self,
        policy: &ResolvedToolExposure,
    ) -> Vec<AdvertisedTool> {
        self.specs_for_policy(policy)
            .map(|tool| AdvertisedTool {
                name: tool.name.clone(),
                descriptor: self.descriptor_for_runtime(tool),
                exposure: tool.exposure,
            })
            .collect()
    }

    fn descriptor_for_runtime(&self, tool: &ToolSpec) -> Value {
        let mut descriptor = tool.descriptor();
        // Response representation is part of the ordinary MCP callable
        // projection, not the authored ToolSpec. Fixed-format projections
        // (Apps, lenses, and hosted HTTP) therefore cannot inherit it.
        if tool.ui.is_none() {
            if let Some(schema) = descriptor.get_mut("inputSchema") {
                super::render::add_format_argument(schema, &tool.name);
            }
        }
        if !self.standby_read_only {
            return descriptor;
        }
        if let Some(schema) = descriptor.get_mut("inputSchema") {
            make_run_context_optional(schema);
        }
        let Some(actions) = tool
            .kind
            .and_then(|kind| kind.standby_disposition().actions())
        else {
            return descriptor;
        };
        if let Some(schema) = descriptor.get_mut("inputSchema") {
            let admitted = restrict_action_schema(schema, actions);
            debug_assert!(admitted, "advertised standby tool has no read action");
        }
        descriptor
    }

    /// Standby admission is intentionally callable by transports before they
    /// parse renderer or operation-specific arguments, and is repeated by the
    /// registry immediately before request lifecycle/handler dispatch.
    pub(crate) fn admit_standby_call(&self, name: &str, arguments: &Value) -> Result<()> {
        if !self.standby_read_only {
            return Ok(());
        }
        let admitted = self
            .get(name)
            .and_then(|tool| tool.kind)
            .is_some_and(|kind| kind.standby_disposition().admits(arguments));
        if admitted {
            Ok(())
        } else {
            Err(Error::engine(STANDBY_READ_ONLY_ERROR))
        }
    }

    fn classify_registered_operation(
        &self,
        name: &str,
        arguments: &Value,
    ) -> Result<(DeploymentReadOnlyOperation, OperationAccess)> {
        let tool = self
            .get(name)
            .ok_or_else(|| Error::engine(format!("unknown tool: {name}")))?;
        let access = match tool.kind {
            Some(kind) if kind.authoritative_disposition().admits(arguments) => {
                OperationAccess::Read
            }
            Some(_) | None => OperationAccess::Mutation,
        };
        let operation = DeploymentReadOnlyOperation::registered(
            tool.kind
                .map(ToolKind::name)
                .unwrap_or(tool.name.as_str())
                .to_string(),
        );
        Ok((operation, access))
    }

    /// Classify a server-selected registered source operation without
    /// admitting it. Executor catalogues synthesize the source selector from
    /// their pinned contract and use this seam so caller-controlled routing
    /// strings can never decide whether an operation is observational.
    pub(crate) fn registered_operation_access(
        &self,
        name: &str,
        arguments: &Value,
    ) -> Result<OperationAccess> {
        self.classify_registered_operation(name, arguments)
            .map(|(_, access)| access)
    }

    /// Early no-write refusal used before renderer and request-envelope
    /// parsing. Dispatch repeats admission and retains the resulting lease.
    pub(crate) fn preflight_deployment_call(&self, name: &str, arguments: &Value) -> Result<()> {
        let Some(barrier) = &self.deployment_mutation_barrier else {
            return Ok(());
        };
        if !barrier.is_read_only() {
            return Ok(());
        }
        let (operation, access) = self.classify_registered_operation(name, arguments)?;
        if access == OperationAccess::Mutation {
            return Err(Error::deployment_read_only(operation));
        }
        Ok(())
    }

    fn admit_deployment_call(
        &self,
        name: &str,
        arguments: &Value,
    ) -> Result<Option<DeploymentAdmission>> {
        let Some(barrier) = &self.deployment_mutation_barrier else {
            return Ok(None);
        };
        let (operation, access) = self.classify_registered_operation(name, arguments)?;
        barrier.admit(&operation, access).map(Some)
    }

    pub(crate) fn reuse_deployment_admission(
        &self,
        lease: &DeploymentPersistenceLease,
    ) -> Result<Option<DeploymentAdmission>> {
        let Some(barrier) = &self.deployment_mutation_barrier else {
            return Err(Error::engine(
                "deployment persistence lease supplied without a mutation barrier",
            ));
        };
        barrier.reuse(lease).map(Some)
    }

    pub fn descriptor_array_bytes_for_policy(&self, policy: &ResolvedToolExposure) -> usize {
        descriptor_projection_bytes(&self.descriptor_projection_for_policy(policy))
    }

    pub fn validate_policy_budget(&self, policy: &ResolvedToolExposure) -> Result<()> {
        validate_descriptor_projection(
            "registry",
            policy.base_profile,
            &self.descriptor_projection_for_policy(policy),
            policy.base_profile.max_descriptor_bytes(),
        )
    }

    pub fn validate_profile_budgets(&self) -> Result<()> {
        for (profile, limit) in [
            (ExposureProfile::Focused, FOCUSED_PROFILE_MAX_BYTES),
            (ExposureProfile::Complete, COMPLETE_PROFILE_MAX_BYTES),
        ] {
            let projection = self.descriptor_projection(profile);
            super::tools::quickstart::validate_actionable_dependency_closure(
                "registry",
                profile,
                projection.iter().map(|tool| tool.name.as_str()),
            )?;
            validate_descriptor_projection("registry", profile, &projection, limit)?;
        }
        Ok(())
    }

    async fn exposure_summary(&self, policy: &ResolvedToolExposure, hosted: bool) -> Result<Value> {
        let advertised_count = self.specs_for_policy(policy).count();
        let complete_count = self.specs_for_profile(ExposureProfile::Complete).count();
        let mut summary = serde_json::json!({
            "profile": policy.base_profile.as_str(),
            "customized": policy.is_customized(),
            "discovery_semantics": if policy.base_profile == ExposureProfile::Complete && !policy.is_customized() {
                "complete: every registered tool for this transport is advertised"
            } else {
                "filtered: tools may be intentionally hidden and workflows may have undiscoverable dependencies"
            },
            "authorization_semantics": "independent: every exact-name call retains its ordinary authorization and validation",
            "advertised_count": advertised_count,
            "advertised_bytes": self.descriptor_array_bytes_for_policy(policy),
            "budget_bytes": policy.base_profile.max_descriptor_bytes(),
            "complete_count": complete_count,
            "complete_bytes": self.descriptor_array_bytes(ExposureProfile::Complete),
            "configurable": !hosted,
        });
        if !hosted {
            summary["configure_with"] =
                serde_json::json!("NATIVE_CE_MCP_TOOL_PROFILE=focused|complete");
        }
        if let Some(provider) = &self.standby_status {
            summary["runtime"] = serde_json::to_value(Box::pin(provider.status()).await)
                .expect("standby status is serializable");
        } else if self.standby_read_only {
            summary["runtime"] = serde_json::json!({
                "mode": "standby",
                "read_only": true,
                "writes_supported": false,
                "canonical_authority": "hosted",
                "mutation_error": STANDBY_READ_ONLY_ERROR,
                "interaction_capture": false,
                "run_persistence": false,
            });
        }
        let bytes = serde_json::to_vec(&summary)?.len();
        if bytes > crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES {
            return Err(Error::engine(format!(
                "bootstrap tool_exposure is {bytes} bytes; component limit is {} bytes",
                crate::mcp::tools::orientation::MAX_BOOTSTRAP_TOOL_EXPOSURE_BYTES
            )));
        }
        Ok(summary)
    }

    /// Dispatch a call to the named tool against `db`. The returned value is
    /// the handler's structured payload, unrendered.
    ///
    /// Three things happen around the handler from this one central seam:
    ///
    /// 1. `run_key` / `parent_key` are lifted OUT of the arguments and validated.
    ///    Lifting them keeps every handler's `deny_unknown_fields` shape honest:
    ///    a handler never sees an argument it does not model.
    /// 2. The validated keys are attached to the [`Caller`] and later stamped
    ///    beside the caller's credential; they never replace event attribution.
    /// 3. Every response after bootstrap carries the echo — the key and intent
    ///    in force — because forgetting a key is mostly a COMPACTION failure.
    ///    Bootstrap instead owns the same handle in its bounded `run` block so
    ///    its five-key response contract is not widened by this wrapper.
    ///
    /// A malformed key never reaches step 2 and never fails the call. The raw
    /// string stays in `arguments` as the caller sent it, which is what the
    /// capture point logs — the record of what was actually attempted must
    /// survive the fact that it was rejected.
    pub async fn call(
        &self,
        db: Db,
        caller: Caller,
        name: &str,
        arguments: Value,
    ) -> Result<Value> {
        self.call_engine(EngineHandle::Sqlite(db), caller, name, arguments)
            .await
    }

    /// Dispatch through the same registered MCP surface using an opaque engine
    /// handle. Production SQLite callers continue through [`Self::call`]; the
    /// Postgres portability slice uses this method for the selected tools.
    pub async fn call_engine(
        &self,
        engine: EngineHandle,
        caller: Caller,
        name: &str,
        arguments: Value,
    ) -> Result<Value> {
        self.call_engine_detailed(engine, caller, name, arguments)
            .await?
            .into_result()
    }

    /// Dispatch while retaining the exact input and run-context echo even when
    /// the handler fails. Transports use this form so error responses obey the
    /// same universal echo contract as successful calls.
    pub async fn call_detailed(
        &self,
        db: Db,
        caller: Caller,
        name: &str,
        arguments: Value,
    ) -> Result<ToolCallOutcome> {
        self.call_engine_detailed(EngineHandle::Sqlite(db), caller, name, arguments)
            .await
    }

    pub async fn call_engine_detailed(
        &self,
        engine: EngineHandle,
        caller: Caller,
        name: &str,
        arguments: Value,
    ) -> Result<ToolCallOutcome> {
        self.call_detailed_with_capture(engine, caller, name, arguments, true, None)
            .await
    }

    pub(crate) async fn call_engine_detailed_with_persistence(
        &self,
        engine: EngineHandle,
        caller: Caller,
        name: &str,
        arguments: Value,
        persistence_lease: DeploymentPersistenceLease,
    ) -> Result<ToolCallOutcome> {
        self.call_detailed_with_capture(
            engine,
            caller,
            name,
            arguments,
            true,
            Some(persistence_lease),
        )
        .await
    }

    /// Dispatch a read without persisting the constituent database's ordinary
    /// read-capture envelope.
    ///
    /// This seam exists only for the federated lens gateway. A lens request is
    /// audited once in the catalog, while its source reads must remain
    /// observational: they cannot leave `read_log_calls` or
    /// `read_log_touches` behind in every database searched. Direct MCP calls
    /// and destination-routed writes continue through [`Self::call_detailed`]
    /// and therefore retain their existing capture behavior.
    pub(crate) async fn call_detailed_uncaptured(
        &self,
        db: Db,
        caller: Caller,
        name: &str,
        arguments: Value,
    ) -> Result<ToolCallOutcome> {
        self.call_detailed_with_capture(
            EngineHandle::Sqlite(db),
            caller,
            name,
            arguments,
            false,
            None,
        )
        .await
    }

    fn call_detailed_with_capture<'a>(
        &'a self,
        engine: EngineHandle,
        caller: Caller,
        name: &'a str,
        arguments: Value,
        capture: bool,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> BoxFuture<'a, Result<ToolCallOutcome>> {
        async move {
            let exposure_policy = caller
                .exposure_policy()
                .cloned()
                .unwrap_or_else(|| ResolvedToolExposure::new(self.exposure_profile));
            let hosted = caller.hosting_principal().is_some();
            let Some(tool) = self.get(name) else {
                return Err(Error::engine(format!("unknown tool: {name}")));
            };
            self.admit_standby_call(name, &arguments)?;
            let deployment_admission = if self.standby_read_only {
                None
            } else if let Some(lease) = &persistence_lease {
                self.reuse_deployment_admission(lease)?
            } else {
                self.admit_deployment_call(name, &arguments)?
            };
            let suppress_persistence = self.standby_read_only
                || matches!(&deployment_admission, Some(DeploymentAdmission::FrozenRead));
            let engine_kind = engine.kind();
            let handler = tool.handlers.get(&engine_kind).ok_or_else(|| {
                crate::domain_transaction::request::unsupported_backend_tool(
                    name,
                    engine_kind.label(),
                )
            })?;
            let bootstrap_exposure = if tool.kind == Some(ToolKind::Bootstrap) {
                Some(Box::pin(self.exposure_summary(&exposure_policy, hosted)).await?)
            } else {
                None
            };
            match engine.sqlite() {
                Some(db) => {
                    let sqlite_port = SqliteRequestLifecycle {
                        db,
                        persistence_lease: match &deployment_admission {
                            Some(DeploymentAdmission::Writable(lease)) => Some(lease.clone()),
                            Some(DeploymentAdmission::FrozenRead) | None => None,
                        },
                    };
                    let suppressed_port = SuppressedRequestLifecycle {
                        backend: "sqlite-standby",
                    };
                    let principal = caller.credential().to_string();
                    let lookup_arguments = arguments.clone();
                    let mut dispatched = if suppress_persistence {
                        dispatch_with_request_port(
                            &suppressed_port,
                            engine.clone(),
                            caller,
                            name,
                            tool.kind,
                            tool.extractor,
                            arguments,
                            false,
                            self.public_origin(),
                            bootstrap_exposure,
                            &handler.call,
                        )
                        .await?
                    } else {
                        dispatch_with_request_port(
                            &sqlite_port,
                            engine.clone(),
                            caller,
                            name,
                            tool.kind,
                            tool.extractor,
                            arguments,
                            capture,
                            self.public_origin(),
                            bootstrap_exposure,
                            &handler.call,
                        )
                        .await?
                    };
                    if !suppress_persistence && dispatched.outcome.is_ok() {
                        // The handler has now authorized the caller and resolved
                        // its own durable idempotency result. Only at that point
                        // may the wrapper attach the original action receipt
                        // without becoming a command-existence oracle.
                        match crate::provenance::lookup_authorized_command_attestation(
                            db,
                            &principal,
                            name,
                            &lookup_arguments,
                            dispatched.run_context.get("intent").and_then(Value::as_str),
                        )
                        .await
                        {
                            Ok(Some(id)) => {
                                if let Ok(result) = &mut dispatched.outcome {
                                    if let Some(object) = result.structured.as_object_mut() {
                                        object
                                            .entry("action_attestation_ids")
                                            .or_insert_with(|| serde_json::json!([id]));
                                    }
                                }
                            }
                            Ok(None) => {}
                            Err(error) => dispatched.outcome = Err(error),
                        }
                    }
                    Box::pin(self.annotate_standby_status(name, &mut dispatched)).await;
                    self.annotate_record_urls(name, &mut dispatched);
                    Ok(dispatched)
                }
                #[cfg(feature = "turso-local")]
                None if matches!(&engine, EngineHandle::TursoLocal(_)) => {
                    let EngineHandle::TursoLocal(db) = &engine else {
                        unreachable!()
                    };
                    let port = crate::turso_local::TursoRuntimeRequestLifecycle::new(db.clone());
                    let suppressed_port = SuppressedRequestLifecycle {
                        backend: "turso-deployment-read-only",
                    };
                    let mut dispatched = dispatch_with_request_port(
                        if suppress_persistence {
                            &suppressed_port
                                as &dyn crate::domain_transaction::request::RequestLifecyclePort
                        } else {
                            &port as &dyn crate::domain_transaction::request::RequestLifecyclePort
                        },
                        engine.clone(),
                        caller,
                        name,
                        tool.kind,
                        tool.extractor,
                        arguments,
                        capture,
                        self.public_origin(),
                        bootstrap_exposure,
                        &handler.call,
                    )
                    .await?;
                    Box::pin(self.annotate_standby_status(name, &mut dispatched)).await;
                    self.annotate_record_urls(name, &mut dispatched);
                    Ok(dispatched)
                }
                None => {
                    #[cfg(feature = "postgres")]
                    if let EngineHandle::Postgres(db) = &engine {
                        let port = PostgresRequestLifecycle { db };
                        let suppressed_port = SuppressedRequestLifecycle {
                            backend: "postgres-deployment-read-only",
                        };
                        let mut dispatched = dispatch_with_request_port(
                            if suppress_persistence {
                                &suppressed_port
                                    as &dyn crate::domain_transaction::request::RequestLifecyclePort
                            } else {
                                &port
                                    as &dyn crate::domain_transaction::request::RequestLifecyclePort
                            },
                            engine.clone(),
                            caller,
                            name,
                            tool.kind,
                            tool.extractor,
                            arguments,
                            capture,
                            self.public_origin(),
                            bootstrap_exposure,
                            &handler.call,
                        )
                        .await?;
                        Box::pin(self.annotate_standby_status(name, &mut dispatched)).await;
                        self.annotate_record_urls(name, &mut dispatched);
                        return Ok(dispatched);
                    }
                    let port = SuppressedRequestLifecycle {
                        backend: engine_kind.label(),
                    };
                    let mut dispatched = dispatch_with_request_port(
                        &port,
                        engine.clone(),
                        caller,
                        name,
                        tool.kind,
                        tool.extractor,
                        arguments,
                        capture,
                        self.public_origin(),
                        bootstrap_exposure,
                        &handler.call,
                    )
                    .await?;
                    Box::pin(self.annotate_standby_status(name, &mut dispatched)).await;
                    self.annotate_record_urls(name, &mut dispatched);
                    Ok(dispatched)
                }
            }
        }
        .boxed()
    }

    pub(crate) async fn run_context_for_engine(
        &self,
        engine: &EngineHandle,
        caller: Caller,
        arguments: &Value,
    ) -> Value {
        let deployment_admission = self.deployment_mutation_barrier.as_ref().map(|barrier| {
            barrier
                .admit(
                    &DeploymentReadOnlyOperation::server("request_lifecycle"),
                    OperationAccess::Read,
                )
                .expect("read-only lifecycle admission cannot reject")
        });
        if self.standby_read_only
            || matches!(&deployment_admission, Some(DeploymentAdmission::FrozenRead))
        {
            let port = SuppressedRequestLifecycle {
                backend: "sqlite-standby",
            };
            return crate::domain_transaction::request::run_context_for(
                &port,
                caller,
                arguments,
                self.public_origin(),
            )
            .await;
        }
        run_context_for_engine(engine, caller, arguments, self.public_origin()).await
    }
}

fn restrict_action_schema(schema: &mut Value, allowed: &[&str]) -> bool {
    let Some(object) = schema.as_object_mut() else {
        return true;
    };
    if let Some(action) = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("action"))
        .and_then(Value::as_object_mut)
    {
        if let Some(selected) = action.get("const").and_then(Value::as_str) {
            if !allowed.contains(&selected) {
                return false;
            }
        }
        if let Some(values) = action.get_mut("enum").and_then(Value::as_array_mut) {
            values.retain(|value| {
                value
                    .as_str()
                    .is_some_and(|selected| allowed.contains(&selected))
            });
            if values.is_empty() {
                return false;
            }
        }
    }
    for keyword in ["oneOf", "anyOf"] {
        if let Some(branches) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            branches.retain_mut(|branch| restrict_action_schema(branch, allowed));
            if branches.is_empty() {
                return false;
            }
        }
    }
    true
}

fn make_run_context_optional(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|field| field.as_str() != Some("run_key"));
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                make_run_context_optional(branch);
            }
        }
    }
}
/// Inject the canonical correlation arguments into one registered schema.
fn add_run_context_arguments(schema: &mut Value, kind: Option<ToolKind>) {
    crate::domain_transaction::request::add_run_context_arguments(schema, kind);
}

/// Resolve the same universal echo without executing a handler. Transport
/// validation errors use this so they cannot bypass correlation feedback.
pub(crate) async fn run_context_for(
    db: &Db,
    caller: Caller,
    arguments: &Value,
    public_origin: Option<&str>,
) -> Value {
    let port = SqliteRequestLifecycle {
        db,
        persistence_lease: None,
    };
    crate::domain_transaction::request::run_context_for(&port, caller, arguments, public_origin)
        .await
}

pub(crate) async fn run_context_for_engine(
    engine: &EngineHandle,
    caller: Caller,
    arguments: &Value,
    public_origin: Option<&str>,
) -> Value {
    match engine.sqlite() {
        Some(db) => run_context_for(db, caller, arguments, public_origin).await,
        None => {
            #[cfg(feature = "postgres")]
            if let EngineHandle::Postgres(db) = engine {
                let port = PostgresRequestLifecycle { db };
                return crate::domain_transaction::request::run_context_for(
                    &port,
                    caller,
                    arguments,
                    public_origin,
                )
                .await;
            }
            let port = SuppressedRequestLifecycle {
                backend: engine.kind().label(),
            };
            crate::domain_transaction::request::run_context_for(
                &port,
                caller,
                arguments,
                public_origin,
            )
            .await
        }
    }
}

pub(crate) fn attach_run_context(result: Value, run_context: Value) -> Value {
    crate::domain_transaction::request::attach_run_context(result, run_context)
}

#[cfg(test)]
mod record_url_annotation_tests {
    use serde_json::json;

    use super::annotate_record_urls;

    #[test]
    fn configured_origins_annotate_every_nested_record_projection() {
        let mut value = json!({
            "records": [{
                "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
                "record_path": "/0189d4c",
                "record_path_full": "/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
                "children": [{
                    "id": "0189d4d6-1f2a-7b3c-9d4e-5f60718293a4",
                    "record_path": "/0189d4d",
                    "record_path_full": "/0189d4d6-1f2a-7b3c-9d4e-5f60718293a4"
                }]
            }]
        });

        annotate_record_urls(
            "get_record",
            &mut value,
            Some("https://app.withnative.ai"),
            Some("https://n8v.to"),
        );

        assert_eq!(
            value["records"][0]["record_url"],
            json!("https://app.withnative.ai/0189d4c")
        );
        assert_eq!(
            value["records"][0]["share_url"],
            json!("https://n8v.to/0189d4c")
        );
        assert_eq!(
            value["records"][0]["children"][0]["record_url"],
            json!("https://app.withnative.ai/0189d4d")
        );
    }

    #[test]
    fn absent_origins_remove_guessed_absolute_annotations_and_keep_paths_stable() {
        let mut value = json!({
            "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "record_path": "/0189d4c",
            "record_path_full": "/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "record_url": "https://guessed.invalid/0189d4c",
            "share_url": "https://guessed.invalid/0189d4c"
        });

        annotate_record_urls("get_record", &mut value, None, None);

        assert_eq!(value["record_path"], json!("/0189d4c"));
        assert_eq!(
            value["record_path_full"],
            json!("/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4")
        );
        assert!(value.get("record_url").is_none());
        assert!(value.get("share_url").is_none());
    }

    #[test]
    fn each_absolute_annotation_has_independent_absence_semantics() {
        let mut public_only = json!({
            "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "record_path": "/0189d4c",
            "record_path_full": "/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4"
        });
        annotate_record_urls(
            "query_record",
            &mut public_only,
            Some("https://self-hosted.example"),
            None,
        );
        assert_eq!(
            public_only["record_url"],
            json!("https://self-hosted.example/0189d4c")
        );
        assert!(public_only.get("share_url").is_none());

        let mut share_only = json!({
            "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "record_path": "/0189d4c",
            "record_path_full": "/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4"
        });
        annotate_record_urls(
            "query_record",
            &mut share_only,
            None,
            Some("https://go.example"),
        );
        assert!(share_only.get("record_url").is_none());
        assert_eq!(share_only["share_url"], json!("https://go.example/0189d4c"));
    }

    #[test]
    fn arbitrary_nested_user_objects_are_not_treated_as_record_projections() {
        let original = json!({
            "facets": {
                "embedded": {
                    "record_path": "/user/value",
                    "record_url": "https://user.example/original",
                    "share_url": "https://user.example/shared"
                }
            }
        });
        let mut value = original.clone();

        annotate_record_urls(
            "get_record",
            &mut value,
            Some("https://app.withnative.ai"),
            Some("https://n8v.to"),
        );

        assert_eq!(value, original);
    }

    #[test]
    fn non_record_tools_never_annotate_query_sql_like_arbitrary_rows() {
        let original = json!({"rows": [{
            "id": "0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "record_path": "/literal-user-column",
            "record_path_full": "/0189d4c6-1f2a-7b3c-9d4e-5f60718293a4",
            "record_url": "literal record_url column",
            "share_url": "literal share_url column"
        }]});
        let mut value = original.clone();

        annotate_record_urls(
            "query_sql",
            &mut value,
            Some("https://app.withnative.ai"),
            Some("https://n8v.to"),
        );

        assert_eq!(value, original);
    }
}

const MAX_MEMBERSHIP_PAGE_SIZE: u32 = 200;

const MANAGE_MEMBERSHIPS_DESCRIPTION: &str = "Hosted database membership administration. Use action=list for the bounded roster; action=set_role for owner/member administration; action=remove for durable full offboarding that fences access, transfers ordinary record ownership, retains immutable Message authorship, and sweeps direct account grants.";

fn manage_memberships_schema() -> Value {
    serde_json::json!({
        "type":"object",
        "oneOf":[
            {
                "type":"object",
                "required":["action"],
                "properties":{
                    "action":{"const":"list"},
                    "cursor":{"type":"string"},
                    "limit":{"type":"integer","minimum":1,"maximum":MAX_MEMBERSHIP_PAGE_SIZE}
                },
                "additionalProperties":false
            },
            {
                "type":"object", "required":["action"], "properties":{"action":{"enum":["invitations_list"]},"cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":MAX_MEMBERSHIP_PAGE_SIZE}}, "additionalProperties":false
            },
            {
                "type":"object", "required":["action","invitation_id"], "properties":{"action":{"const":"invitations_inspect"},"invitation_id":{"type":"string","minLength":1}}, "additionalProperties":false
            },
            {
                "type":"object", "required":["action","email","role","idempotency_key","reason"], "properties":{"action":{"const":"invitations_create"},"email":{"type":"string","minLength":1},"role":{"enum":["member"]},"expires_at":{"type":"string"},"idempotency_key":{"type":"string","minLength":1,"maxLength":256},"reason":{"type":"string","minLength":1,"maxLength":2000}}, "additionalProperties":false
            },
            {
                "type":"object", "required":["action","invitation_id","idempotency_key","reason"], "properties":{"action":{"const":"invitations_copy_link"},"invitation_id":{"type":"string","minLength":1},"idempotency_key":{"type":"string","minLength":1,"maxLength":256},"reason":{"type":"string","minLength":1,"maxLength":2000}}, "additionalProperties":false
            },
            {
                "type":"object", "required":["action","invitation_id","idempotency_key","reason"], "properties":{"action":{"const":"invitations_send"},"invitation_id":{"type":"string","minLength":1},"idempotency_key":{"type":"string","minLength":1,"maxLength":256},"reason":{"type":"string","minLength":1,"maxLength":2000}}, "additionalProperties":false
            },
            {
                "type":"object", "required":["action","invitation_id","idempotency_key","reason"], "properties":{"action":{"const":"invitations_revoke"},"invitation_id":{"type":"string","minLength":1},"idempotency_key":{"type":"string","minLength":1,"maxLength":256},"reason":{"type":"string","minLength":1,"maxLength":2000}}, "additionalProperties":false
            },
            {
                "type":"object",
                "required":["action","member_id","role","reason"],
                "properties":{
                    "action":{"const":"set_role"},
                    "member_id":{"type":"string","minLength":1},
                    "role":{"type":"string","enum":["owner","member"]},
                    "expected_role":{"type":"string","enum":["owner","member"]},
                    "reason":{"type":"string","minLength":1,"maxLength":2000}
                },
                "additionalProperties":false
            },
            {
                "type":"object",
                "required":["action","member_id","idempotency_key","reason"],
                "properties":{
                    "action":{"const":"remove"},
                    "member_id":{"type":"string","minLength":1},
                    "idempotency_key":{"type":"string","minLength":1,"maxLength":256},
                    "reason":{"type":"string","minLength":1,"maxLength":2000},
                    "transfer_to_member_id":{"type":"string","minLength":1}
                },
                "additionalProperties":false
            }
        ]
    })
}

/// Return whether a requested hosted membership page size is in range.
#[doc(hidden)]
pub fn membership_page_size_is_valid(page_size: u32) -> bool {
    (1..=MAX_MEMBERSHIP_PAGE_SIZE).contains(&page_size)
}

/// Register the hosted descriptor against one narrow execution delegate.
#[doc(hidden)]
pub fn register_membership_tool_with<F, Fut>(registry: &mut ToolRegistry, handler: F) -> Result<()>
where
    F: Fn(Db, Caller, Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Value>> + Send + 'static,
{
    registry.register(
        ToolKind::ManageMemberships,
        MANAGE_MEMBERSHIPS_DESCRIPTION,
        manage_memberships_schema(),
        handler,
    )
}

/// Register only the maximal-hosted descriptor for deterministic generators.
///
/// Generated registries are never dispatched; hosted composition must use a
/// concrete handler through [`register_membership_tool_with`].
#[doc(hidden)]
pub fn register_membership_tool_schema(registry: &mut ToolRegistry) -> Result<()> {
    register_membership_tool_with(registry, |_db, _caller, _arguments| async {
        Err(Error::engine(
            "manage_memberships schema-only delegate cannot be dispatched",
        ))
    })?;
    registry
        .mark_engine_operations_unavailable(ToolKind::ManageMemberships.name(), EngineKind::Sqlite)
}

#[cfg(test)]
mod hosting_context_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use serde_json::json;

    use super::{Caller, ToolRegistry};

    #[tokio::test]
    async fn standby_discovery_and_dispatch_share_one_fail_closed_policy() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry.set_standby_read_only(true);

        let projection = registry.descriptor_projection(super::ExposureProfile::Complete);
        assert!(!projection.iter().any(|tool| tool.name == "create_record"));
        let links = projection
            .iter()
            .find(|tool| tool.name == "manage_links")
            .expect("mixed read tool stays discoverable");
        assert_eq!(
            links.descriptor["inputSchema"]["properties"]["action"]["enum"],
            json!(["list"])
        );
        assert!(!links.descriptor["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "run_key"));

        let error = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"not":"even parsed"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), super::STANDBY_READ_ONLY_ERROR);
        let error = registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_links",
                json!({"action":"add"}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), super::STANDBY_READ_ONLY_ERROR);

        let ping = registry
            .call(db.clone(), Caller::local(), "ping", json!({}))
            .await
            .unwrap();
        assert_eq!(ping["ok"], true);
        let captured: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(captured, 0);
    }

    #[tokio::test]
    async fn deployment_freeze_refuses_mutations_and_suppresses_read_persistence() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .register_custom(
                "future_custom_operation",
                crate::mcp::CustomInteractionPolicy::NoRecordInteractions,
                crate::mcp::ToolKind::Ping.exposure(),
                "test-only future operation",
                json!({"type":"object"}),
                |_db, _caller, _arguments| async { Ok(json!({"escaped":true})) },
            )
            .unwrap();
        registry.set_deployment_mutation_barrier(barrier.clone());
        let _frozen = barrier.freeze().await;

        for (name, arguments, operation) in [
            ("create_record", json!({"not":"parsed"}), "create_record"),
            ("manage_links", json!({"action":"add"}), "manage_links"),
            (
                "future_custom_operation",
                json!({"anything":"caller controlled"}),
                "future_custom_operation",
            ),
        ] {
            let error = registry
                .call(db.clone(), Caller::local(), name, arguments)
                .await
                .unwrap_err();
            assert_eq!(error.deployment_read_only_operation(), Some(operation));
        }

        let ping = registry
            .call(db.clone(), Caller::local(), "ping", json!({}))
            .await
            .unwrap();
        assert_eq!(ping["ok"], true);
        let captured: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(captured, 0);
    }

    #[tokio::test]
    async fn deployment_freeze_drains_the_complete_registry_dispatch() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let mut registry = ToolRegistry::new();
        registry
            .register_custom(
                "paused_mutation",
                crate::mcp::CustomInteractionPolicy::NoRecordInteractions,
                crate::mcp::ToolKind::Ping.exposure(),
                "test-only paused mutation",
                json!({"type":"object"}),
                {
                    let entered = entered.clone();
                    let release = release.clone();
                    move |_db, _caller, _arguments| {
                        let entered = entered.clone();
                        let release = release.clone();
                        async move {
                            entered.add_permits(1);
                            release.acquire().await.unwrap().forget();
                            Ok(json!({"completed":true}))
                        }
                    }
                },
            )
            .unwrap();
        registry.set_deployment_mutation_barrier(barrier.clone());
        let registry = Arc::new(registry);

        let call = {
            let registry = registry.clone();
            let db = db.clone();
            tokio::spawn(async move {
                registry
                    .call(db, Caller::local(), "paused_mutation", json!({}))
                    .await
            })
        };
        entered.acquire().await.unwrap().forget();
        let freeze = {
            let barrier = barrier.clone();
            tokio::spawn(async move { barrier.freeze().await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !barrier.is_read_only() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("freeze intent was not registered");
        assert!(!freeze.is_finished(), "freeze bypassed the active handler");
        let late = registry
            .call(db.clone(), Caller::local(), "paused_mutation", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            late.deployment_read_only_operation(),
            Some("paused_mutation")
        );

        release.add_permits(1);
        call.await.unwrap().unwrap();
        let frozen = tokio::time::timeout(Duration::from_secs(2), freeze)
            .await
            .expect("freeze did not acquire after handler completion")
            .unwrap();
        drop(frozen);
    }

    #[tokio::test]
    async fn deployment_freeze_drains_capture_after_transport_cancellation() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let gate = Arc::new(crate::mcp::interactions::CaptureTestGate::default());
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        registry.set_deployment_mutation_barrier(barrier.clone());
        let registry = Arc::new(registry);

        let call = {
            let registry = registry.clone();
            let db = db.clone();
            let gate = gate.clone();
            tokio::spawn(async move {
                crate::mcp::interactions::with_capture_test_gate(gate, async move {
                    registry.call(db, Caller::local(), "ping", json!({})).await
                })
                .await
            })
        };
        gate.wait_until_entered().await;
        call.abort();
        let _ = call.await;

        let freeze = {
            let barrier = barrier.clone();
            tokio::spawn(async move { barrier.freeze().await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !barrier.is_read_only() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("freeze intent was not registered");
        assert!(
            !freeze.is_finished(),
            "freeze bypassed detached interaction capture"
        );

        gate.release();
        gate.wait_until_completed().await;
        let frozen = tokio::time::timeout(Duration::from_secs(2), freeze)
            .await
            .expect("freeze did not acquire after detached capture completed")
            .unwrap();
        drop(frozen);
    }

    #[test]
    fn hosted_database_context_does_not_replace_portable_attribution() {
        let caller = Caller::authenticated("acct_portable")
            .with_hosting_context("catalog-user", "shared-database");
        assert_eq!(caller.actor(), "acct_portable");
        assert_eq!(caller.credential(), "acct_portable");
        assert_eq!(caller.hosting_principal(), Some("catalog-user"));
        assert_eq!(caller.hosting_database(), Some("shared-database"));
    }

    #[tokio::test]
    async fn cancelled_request_leaves_owned_capture_to_finish_before_the_next_call() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let gate = Arc::new(super::super::interactions::CaptureTestGate::default());

        let request = tokio::spawn({
            let db = db.clone();
            let registry = registry.clone();
            let gate = gate.clone();
            async move {
                super::super::interactions::with_capture_test_gate(
                    gate,
                    registry.call(db, Caller::local(), "ping", json!({})),
                )
                .await
            }
        });
        tokio::time::timeout(Duration::from_secs(1), gate.wait_until_entered())
            .await
            .expect("capture entered its write transaction");

        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        gate.release();
        tokio::time::timeout(Duration::from_secs(1), gate.wait_until_completed())
            .await
            .expect("detached capture completed after request cancellation");

        let captured: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE tool = 'ping'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(captured, 1);

        let next = registry
            .call(db.clone(), Caller::local(), "ping", json!({}))
            .await
            .unwrap();
        assert_eq!(next["ok"], true);
        crate::store::create_record(
            &db,
            json!({ "type": "Document", "kind": "note", "name": "after cancellation" }),
        )
        .await
        .unwrap();
        let captured: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE tool = 'ping'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(captured, 2);
        db.close().await;
    }
}
