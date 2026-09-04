//! Backend-neutral classification for governed same-bearer type correction.
//!
//! Physical adapters are responsible for obtaining one coherent snapshot. The
//! kernel is deliberately pure: identical snapshot facts produce identical
//! eligibility, reasons and target identity on every backend.

use serde::Serialize;

mod classifier;
pub mod preparation;

pub use preparation::{
    correction_digest, Blocker, CorrectionFacts, CorrectionPlan, PreparedCorrection,
    NEW_BEARER_GUIDANCE,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Eligibility {
    Autonomous,
    ConfirmationRequired,
    Ineligible,
}

impl Eligibility {
    /// Canonical executor argument used to bind preparation to execution.
    pub const fn execution_mode(&self) -> &'static str {
        match self {
            Self::Autonomous => "autonomous",
            Self::ConfirmationRequired => "confirmed",
            Self::Ineligible => "ineligible",
        }
    }

    pub const fn confirmation_required(&self) -> bool {
        matches!(self, Self::ConfirmationRequired)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Identity {
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MechanicalReason {
    pub code: String,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct ClassificationInput {
    pub current: Identity,
    pub target: Identity,
    pub target_active: bool,
    pub unique_wrong_type_match: bool,
    pub same_run_provenance: bool,
    pub shared_use: bool,
    pub blockers: Vec<MechanicalReason>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Classification {
    pub eligibility: Eligibility,
    pub reasons: Vec<MechanicalReason>,
    pub current: Identity,
    pub target: Identity,
}

pub fn classify(input: ClassificationInput) -> Classification {
    classifier::classify(input)
}
