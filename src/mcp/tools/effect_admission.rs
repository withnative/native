//! App-neutral declaring-package seam (D7 §4C.2, slice N2 b1: types + alpha
//! resolver types).
//!
//! Each admission source resolves its claim, inside the write transaction, to
//! one neutral [`DeclaringPackage`]. Everything after that point is
//! source-agnostic. This module holds the neutral types plus the alpha-tab
//! refusal rendering. It performs no I/O: the alpha resolver wrapper lives
//! beside the existing guard in `alpha_tabs` so refusal order, codes and
//! texts stay byte-identical by delegation, never by reimplementation.
//!
//! Scope of this slice (b1 only): the types below and the alpha
//! `render_refusal`. The write-path threading (N2 b2), the catalogue-driven
//! consent stage (N3) and the app admission source (N5) are explicitly out of
//! scope — no `artifact_interactions`/`lifecycle` changes, no tool, schema or
//! host changes.

use serde_json::Value;

use crate::control::{ALPHA_TAB_ADOPTION_SHELL_AUTO, ALPHA_TAB_ADOPTION_VERIFIED};
use native_artifact_runtime::artifact_intents::AlphaTabInstallGuard;

/// Which admission source a package claim resolves from (D7 §4C.2).
// N2b threads the first non-test callers; unit tests only until then.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionSource {
    /// An alpha tab install (`alpha_install_guard` on the wire).
    AlphaTabInstall,
    /// A future app declaration under the apps contract (N5; no resolver yet).
    AppDeclaration,
}

/// How consent was established for one capability (D7 §4C.2, Rev 4.1: per
/// capability).
// N2b threads the first non-test callers; unit tests only until then.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentMode {
    /// K1: consent at adoption — `shell_adopt.v1` preview+adopt, or
    /// `shell_auto.v1` hosted authored adopt. Every resolved alpha package
    /// carries this for both capabilities.
    Adopted,
    /// Apps: the declaration is shown, no consent prompt — ratified by
    /// Richard (239beea answer 2: "not sure app writes should need consent,
    /// let's go for low friction"). Gesture evidence, attribution and Undo
    /// are the safeguards instead. Widening shows a change note. Constructed
    /// by N5's app resolver; alpha resolution never yields it.
    Declared,
}

/// Per-capability consent carried by a resolved package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackageConsent {
    pub reads: ConsentMode,
    pub effects: ConsentMode,
}

/// A parsed admission claim: the source plus its pin. Today built only from
/// `invocation.alpha_install_guard`; the wire and digest are unchanged.
/// `PartialEq` only: the guard itself is `PartialEq` without `Eq`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PackageClaim<'a> {
    pub source: AdmissionSource,
    pub pin: &'a AlphaTabInstallGuard,
}

impl<'a> PackageClaim<'a> {
    /// Build the alpha-tab claim from an install guard.
    pub(crate) fn alpha(pin: &'a AlphaTabInstallGuard) -> Self {
        Self {
            source: AdmissionSource::AlphaTabInstall,
            pin,
        }
    }
}

impl<'a> From<&'a AlphaTabInstallGuard> for PackageClaim<'a> {
    fn from(pin: &'a AlphaTabInstallGuard) -> Self {
        Self::alpha(pin)
    }
}

/// The neutral declaring package one admission source resolves to (D7 §4C.2).
///
/// `generation` is the install event id (the generation CAS token);
/// `declaration` is the stored consented declaration and
/// `declaration_digest` its canonical digest pin.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeclaringPackage {
    pub source: AdmissionSource,
    pub consent: PackageConsent,
    pub package: String,
    pub generation: String,
    pub artifact_id: String,
    pub source_revision: String,
    pub declaration: Value,
    pub declaration_digest: String,
}

/// Consent for a resolved alpha install: `Adopted` for both capabilities.
///
/// Returns `Some` exactly for the verified adoptions (`shell_adopt.v1`,
/// `shell_auto.v1`) and `None` otherwise. The alpha resolver only reaches
/// this after the existing guard passes — which itself requires verified
/// adoption — so `None` is unreachable there; it keeps a misrouted caller
/// from minting a package rather than failing closed elsewhere.
pub(crate) fn alpha_consent_for_adoption(adoption: &str) -> Option<PackageConsent> {
    if adoption == ALPHA_TAB_ADOPTION_VERIFIED || adoption == ALPHA_TAB_ADOPTION_SHELL_AUTO {
        Some(PackageConsent {
            reads: ConsentMode::Adopted,
            effects: ConsentMode::Adopted,
        })
    } else {
        None
    }
}

/// Why resolution refused (D7 §4C.2 seam). The spec-named variants carry the
/// owned details each source renderer needs for byte-identical texts; the
/// trailing variants cover the alpha gate refusals the sketch leaves as "…".
/// Two transitional parts, both justified below: `NoUsableBound` still wraps
/// the object-bound helpers' exact pairs (they are shared with the kernels
/// and move to `effect_bounds::admit` in N3), and the `AppDeclaration`
/// renderer reuses the alpha texts until N5 defines `app_effect_*` codes (no
/// app resolver constructs these variants in this slice, so that arm is
/// unreachable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionRefusal {
    /// No alpha-resolvable package scope: either no authenticated account is
    /// bound to the caller (so there is no package namespace to resolve in),
    /// or the claim's source is not `AlphaTabInstall` — a misrouted claim,
    /// failed closed before any install I/O. Both render the existing
    /// `alpha_guard_no_account` refusal; no new code is minted for a path
    /// that cannot arise from real traffic.
    NoPackage,
    /// The claimed package has no install row for this account.
    PackageMissing { package: String },
    /// The generation CAS diverged: the guarded generation is stale.
    Stale { expected: String, current: String },
    /// A pin field differs: the guard names another artifact than the
    /// invocation, or the guard differs from the stored pin field-for-field.
    PinMismatch { kind: PinMismatchKind },
    /// The install is present but not live: removed or disabled.
    Inactive {
        state: InactiveState,
        package: String,
    },
    /// The entry's effect family cannot use this scope: the wrong entry shape
    /// for the scope, or a forged position/emoji discriminator. All render
    /// as `alpha_guard_unsupported_effect`.
    ScopeUnsupported { reason: ScopeUnsupportedReason },
    /// The stored declaration holds no consent for the entry: a catalogue
    /// miss, a legacy string-only declaration facing an object entry, or a
    /// string-effect declaration lacking the arm's required effect.
    Unconsented { reason: UnconsentedReason },
    /// Transitional: an object-bound helper (`facet_set_admission`,
    /// `comment_admission`, `react_admission`, `title_admission`) refused with
    /// its exact pair. The helpers are shared with the write kernels and
    /// their tests; N3's `effect_bounds::admit` constructs structured reasons
    /// for these paths instead.
    NoUsableBound { code: String, message: String },
    /// The install is not verified (`shell_adopt.v1`/`shell_auto.v1`).
    AdoptionUnverified { package: String },
    /// The install target is missing, archived, of the wrong record type, or
    /// not viewer-visible.
    TargetUnavailable {
        reason: TargetUnavailableReason,
        package: String,
        artifact_id: String,
    },
    /// The stored declaration digest does not recompute from the consented
    /// declaration.
    DeclarationMismatch,
    /// The install target is not renderable, its source revision resolves to
    /// no body-carrying event, or the digest does not recompute.
    SourceUnresolved { reason: SourceUnresolvedReason },
    /// The invocation source digest is not the consented source revision.
    InvocationSourceMismatch,
}

/// Which pin comparison failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinMismatchKind {
    /// The guard names a different artifact than the invocation.
    ArtifactVsInvocation,
    /// The guard differs from the stored install pin field-for-field.
    GuardVsStored,
}

/// Which not-live state the install is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InactiveState {
    Removed,
    Disabled,
}

/// Which scope/shape check failed. Every reason renders a fixed
/// `alpha_guard_unsupported_effect` text except `PositionDiverge`, which
/// names the forged position and the entry's own position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopeUnsupportedReason {
    /// A comment entry under the facet scope.
    CommentUnderFacet,
    /// A non facet-set/unset effect under the facet scope.
    NonPairUnderFacet,
    /// A non-comment entry (or one without its envelope) under the comment
    /// scope.
    NonCommentEntry,
    /// The supplied position diverges from the entry's own position.
    PositionDiverge { expected: String, actual: String },
    /// A non-react entry (or one without its envelope) under the react
    /// scope.
    NonReactEntry,
    /// The invocation emoji sits outside the entry's declared subset.
    EmojiOutsideSubset,
    /// A non-title entry (or one without its envelope) under the title
    /// scope.
    NonTitleEntry,
    /// A non-body entry or missing body envelope under the dormant body scope.
    NonBodyEntry,
}

/// Which declaration-consent check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnconsentedReason {
    /// The facet-scope catalogue gate (and the legacy string-only facet arm):
    /// the install consents only to the triage facet or the tasks lifecycle
    /// arm, and this entry targets another facet.
    FacetCatalogueMiss { entry_id: String, facet: String },
    /// A string-effect declaration lacking the arm's required effect.
    EffectNotConsented {
        package: String,
        required_effect: String,
    },
}

/// Which liveness/visibility check failed on the install target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetUnavailableReason {
    Missing,
    Archived,
    WrongRecordType,
    Unauthorized,
}

/// Which source/digest gate failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceUnresolvedReason {
    NotRenderable,
    RevisionUnresolved,
    DigestMismatch,
}

/// Render a refusal per source. `AlphaTabInstall` renders today's
/// `alpha_guard_*` codes and texts byte-identically — the existing guard
/// tests are the oracle. Transitional: `AppDeclaration` reuses the same
/// rendering until N5's app resolver defines `app_effect_*` codes; no app
/// resolver exists in this slice, so that arm is unreachable by
/// construction.
pub(crate) fn render_refusal(
    source: AdmissionSource,
    refusal: &AdmissionRefusal,
) -> (String, String) {
    match source {
        AdmissionSource::AlphaTabInstall => render_alpha_refusal(refusal),
        AdmissionSource::AppDeclaration => render_alpha_refusal(refusal),
    }
}

/// The alpha-tab rendering: today's codes and texts, byte-identical.
fn render_alpha_refusal(refusal: &AdmissionRefusal) -> (String, String) {
    match refusal {
        AdmissionRefusal::NoPackage => (
            "alpha_guard_no_account".into(),
            "no authenticated account is bound to this caller; the personal-install guard cannot be checked".into(),
        ),
        AdmissionRefusal::PackageMissing { package } => (
            "alpha_guard_missing_install".into(),
            format!(
                "package {package} is not installed for this account; other Workbench use of the artifact is unaffected"
            ),
        ),
        AdmissionRefusal::Stale { expected, current } => (
            "alpha_guard_cas_mismatch".into(),
            format!(
                "installation changed; the guarded generation {expected} is stale (current {current})"
            ),
        ),
        AdmissionRefusal::PinMismatch { kind } => match kind {
            PinMismatchKind::ArtifactVsInvocation => (
                "alpha_guard_artifact_mismatch".into(),
                "the install guard names a different artifact than the invocation; re-read the consented install and retry".into(),
            ),
            PinMismatchKind::GuardVsStored => (
                "alpha_guard_pin_mismatch".into(),
                "the install guard does not match the installed pin field-for-field; re-read the install and retry".into(),
            ),
        },
        AdmissionRefusal::Inactive { state, package } => match state {
            InactiveState::Removed => (
                "alpha_guard_removed".into(),
                format!(
                    "the personal alpha install {package} was removed; the guarded invocation is refused but other Workbench use of the artifact is unaffected"
                ),
            ),
            InactiveState::Disabled => (
                "alpha_guard_disabled".into(),
                format!(
                    "the personal alpha install {package} is disabled; the guarded invocation is refused but other Workbench use of the artifact is unaffected"
                ),
            ),
        },
        AdmissionRefusal::ScopeUnsupported { reason } => (
            "alpha_guard_unsupported_effect".into(),
            match reason {
                ScopeUnsupportedReason::CommentUnderFacet => {
                    "comment.create cannot use a facet-scoped guard".into()
                }
                ScopeUnsupportedReason::NonPairUnderFacet => {
                    "the personal-install guard applies only to the declared triage facet.set/facet.unset pair; record.create with a guard is refused".into()
                }
                ScopeUnsupportedReason::NonCommentEntry => {
                    "the comment guard applies only to comment.create entries carrying a comment envelope".into()
                }
                ScopeUnsupportedReason::PositionDiverge { expected, actual } => {
                    format!(
                        "comment guard position '{expected}' diverges from entry position '{actual}'"
                    )
                }
                ScopeUnsupportedReason::NonReactEntry => {
                    "the react guard applies only to message.react entries carrying a react envelope".into()
                }
                ScopeUnsupportedReason::EmojiOutsideSubset => {
                    "react guard emoji is outside the entry's declared subset".into()
                }
                ScopeUnsupportedReason::NonTitleEntry => {
                    "the title guard applies only to title.set entries carrying a title envelope".into()
                }
                ScopeUnsupportedReason::NonBodyEntry => {
                    "the body guard applies only to body.set entries carrying a body envelope".into()
                }
            },
        ),
        AdmissionRefusal::Unconsented { reason } => match reason {
            UnconsentedReason::FacetCatalogueMiss { entry_id, facet } => (
                "alpha_guard_facet_unconsented".into(),
                format!(
                    "the personal-install guard consents only to facet '{}' or the tasks lifecycle arm; entry '{entry_id}' targets '{facet}'",
                    super::tab_effect_catalogue::ALPHA_GUARD_FACET,
                ),
            ),
            UnconsentedReason::EffectNotConsented {
                package,
                required_effect,
            } => (
                "alpha_guard_effect_unconsented".into(),
                format!(
                    "the personal alpha install {package} does not consent to {required_effect}; a declared interaction alone is never effect consent"
                ),
            ),
        },
        AdmissionRefusal::NoUsableBound { code, message } => (code.clone(), message.clone()),
        AdmissionRefusal::AdoptionUnverified { package } => (
            "alpha_guard_adoption_unverified".into(),
            format!(
                "the personal alpha install {package} is not verified (shell_adopt.v1 or shell_auto.v1); the guarded invocation is refused"
            ),
        ),
        AdmissionRefusal::TargetUnavailable {
            reason,
            package,
            artifact_id,
        } => match reason {
            TargetUnavailableReason::Missing => (
                "alpha_guard_target_missing".into(),
                format!("the personal alpha install {package} target {artifact_id} is missing"),
            ),
            TargetUnavailableReason::Archived => (
                "alpha_guard_target_archived".into(),
                format!("the personal alpha install {package} target {artifact_id} is archived"),
            ),
            TargetUnavailableReason::WrongRecordType => (
                "alpha_guard_target_wrong_type".into(),
                format!(
                    "the personal alpha install {package} target {artifact_id} is not an artifact"
                ),
            ),
            TargetUnavailableReason::Unauthorized => (
                "alpha_guard_unauthorized".into(),
                format!(
                    "the viewer may not view the personal alpha install {package} target {artifact_id}"
                ),
            ),
        },
        AdmissionRefusal::DeclarationMismatch => (
            "alpha_guard_declaration_mismatch".into(),
            "the installed declaration digest does not match the consented declaration".into(),
        ),
        AdmissionRefusal::SourceUnresolved { reason } => match reason {
            SourceUnresolvedReason::NotRenderable => (
                "alpha_guard_not_renderable".into(),
                "the guarded install target is not renderable".into(),
            ),
            SourceUnresolvedReason::RevisionUnresolved => (
                "alpha_guard_source_unresolved".into(),
                "the guarded install source revision resolves to no body-carrying event".into(),
            ),
            SourceUnresolvedReason::DigestMismatch => (
                "alpha_guard_digest_mismatch".into(),
                "the guarded install digest does not match the consented source; re-read the install and retry".into(),
            ),
        },
        AdmissionRefusal::InvocationSourceMismatch => (
            "alpha_guard_source_mismatch".into(),
            "the invocation source digest is not the consented source revision; re-render from the consented revision and retry".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_guard() -> AlphaTabInstallGuard {
        AlphaTabInstallGuard {
            package: "agent.effect-admission-test".into(),
            expected_install_event_id: "event-1".into(),
            artifact_id: "artifact-1".into(),
            source_revision: "revision-1".into(),
            version: "0.1.0".into(),
            digest: "digest-1".into(),
            declaration_digest: "declaration-1".into(),
        }
    }

    #[test]
    fn dormant_body_scope_has_fixed_source_neutral_refusal() {
        let refusal = AdmissionRefusal::ScopeUnsupported {
            reason: ScopeUnsupportedReason::NonBodyEntry,
        };
        for source in [
            AdmissionSource::AlphaTabInstall,
            AdmissionSource::AppDeclaration,
        ] {
            assert_eq!(
                render_refusal(source, &refusal),
                (
                    "alpha_guard_unsupported_effect".to_owned(),
                    "the body guard applies only to body.set entries carrying a body envelope"
                        .to_owned(),
                )
            );
        }
    }

    #[test]
    fn alpha_claim_from_guard_names_alpha_source() {
        let guard = sample_guard();
        let claim = PackageClaim::alpha(&guard);
        assert_eq!(claim.source, AdmissionSource::AlphaTabInstall);
        assert_eq!(claim.pin, &guard);
        let converted: PackageClaim<'_> = (&guard).into();
        assert_eq!(converted, claim);
    }

    #[test]
    fn verified_adoptions_resolve_to_adopted_consent() {
        for adoption in [ALPHA_TAB_ADOPTION_VERIFIED, ALPHA_TAB_ADOPTION_SHELL_AUTO] {
            let consent = alpha_consent_for_adoption(adoption).expect("verified adoption must map");
            assert_eq!(consent.reads, ConsentMode::Adopted, "{adoption}");
            assert_eq!(consent.effects, ConsentMode::Adopted, "{adoption}");
        }
        assert_eq!(ALPHA_TAB_ADOPTION_VERIFIED, "shell_adopt.v1");
        assert_eq!(ALPHA_TAB_ADOPTION_SHELL_AUTO, "shell_auto.v1");
        assert!(alpha_consent_for_adoption("caller_asserted").is_none());
    }

    #[test]
    fn alpha_render_refusal_reproduces_todays_texts() {
        let cases: Vec<(AdmissionRefusal, &str, &str)> = vec![
            (
                AdmissionRefusal::NoPackage,
                "alpha_guard_no_account",
                "no authenticated account is bound to this caller; the personal-install guard cannot be checked",
            ),
            (
                AdmissionRefusal::PackageMissing {
                    package: "agent.pkg".into(),
                },
                "alpha_guard_missing_install",
                "package agent.pkg is not installed for this account; other Workbench use of the artifact is unaffected",
            ),
            (
                AdmissionRefusal::Stale {
                    expected: "old".into(),
                    current: "new".into(),
                },
                "alpha_guard_cas_mismatch",
                "installation changed; the guarded generation old is stale (current new)",
            ),
            (
                AdmissionRefusal::PinMismatch {
                    kind: PinMismatchKind::ArtifactVsInvocation,
                },
                "alpha_guard_artifact_mismatch",
                "the install guard names a different artifact than the invocation; re-read the consented install and retry",
            ),
            (
                AdmissionRefusal::PinMismatch {
                    kind: PinMismatchKind::GuardVsStored,
                },
                "alpha_guard_pin_mismatch",
                "the install guard does not match the installed pin field-for-field; re-read the install and retry",
            ),
            (
                AdmissionRefusal::Inactive {
                    state: InactiveState::Removed,
                    package: "agent.pkg".into(),
                },
                "alpha_guard_removed",
                "the personal alpha install agent.pkg was removed; the guarded invocation is refused but other Workbench use of the artifact is unaffected",
            ),
            (
                AdmissionRefusal::Inactive {
                    state: InactiveState::Disabled,
                    package: "agent.pkg".into(),
                },
                "alpha_guard_disabled",
                "the personal alpha install agent.pkg is disabled; the guarded invocation is refused but other Workbench use of the artifact is unaffected",
            ),
            (
                AdmissionRefusal::ScopeUnsupported {
                    reason: ScopeUnsupportedReason::CommentUnderFacet,
                },
                "alpha_guard_unsupported_effect",
                "comment.create cannot use a facet-scoped guard",
            ),
            (
                AdmissionRefusal::ScopeUnsupported {
                    reason: ScopeUnsupportedReason::PositionDiverge {
                        expected: "reply".into(),
                        actual: "root".into(),
                    },
                },
                "alpha_guard_unsupported_effect",
                "comment guard position 'reply' diverges from entry position 'root'",
            ),
            (
                AdmissionRefusal::ScopeUnsupported {
                    reason: ScopeUnsupportedReason::EmojiOutsideSubset,
                },
                "alpha_guard_unsupported_effect",
                "react guard emoji is outside the entry's declared subset",
            ),
            (
                AdmissionRefusal::Unconsented {
                    reason: UnconsentedReason::FacetCatalogueMiss {
                        entry_id: "e1".into(),
                        facet: "other".into(),
                    },
                },
                "alpha_guard_facet_unconsented",
                "the personal-install guard consents only to facet 'triage' or the tasks lifecycle arm; entry 'e1' targets 'other'",
            ),
            (
                AdmissionRefusal::Unconsented {
                    reason: UnconsentedReason::EffectNotConsented {
                        package: "agent.pkg".into(),
                        required_effect: "task.triage-set.v1".into(),
                    },
                },
                "alpha_guard_effect_unconsented",
                "the personal alpha install agent.pkg does not consent to task.triage-set.v1; a declared interaction alone is never effect consent",
            ),
            (
                AdmissionRefusal::AdoptionUnverified {
                    package: "agent.pkg".into(),
                },
                "alpha_guard_adoption_unverified",
                "the personal alpha install agent.pkg is not verified (shell_adopt.v1 or shell_auto.v1); the guarded invocation is refused",
            ),
            (
                AdmissionRefusal::TargetUnavailable {
                    reason: TargetUnavailableReason::Missing,
                    package: "agent.pkg".into(),
                    artifact_id: "artifact-1".into(),
                },
                "alpha_guard_target_missing",
                "the personal alpha install agent.pkg target artifact-1 is missing",
            ),
            (
                AdmissionRefusal::DeclarationMismatch,
                "alpha_guard_declaration_mismatch",
                "the installed declaration digest does not match the consented declaration",
            ),
            (
                AdmissionRefusal::SourceUnresolved {
                    reason: SourceUnresolvedReason::DigestMismatch,
                },
                "alpha_guard_digest_mismatch",
                "the guarded install digest does not match the consented source; re-read the install and retry",
            ),
            (
                AdmissionRefusal::InvocationSourceMismatch,
                "alpha_guard_source_mismatch",
                "the invocation source digest is not the consented source revision; re-render from the consented revision and retry",
            ),
        ];
        for (refusal, code, message) in &cases {
            let (rendered_code, rendered_message) =
                render_refusal(AdmissionSource::AlphaTabInstall, refusal);
            assert_eq!(&rendered_code, code);
            assert_eq!(&rendered_message, message);
        }
        // The app source reuses the alpha rendering transitionally (N5 owns
        // `app_effect_*` codes; unreachable until its resolver lands).
        let (refusal, code, message) = &cases[2];
        let (rendered_code, rendered_message) =
            render_refusal(AdmissionSource::AppDeclaration, refusal);
        assert_eq!(&rendered_code, code);
        assert_eq!(&rendered_message, message);
    }
}
