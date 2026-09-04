//! MCP composition for the storage-free record-policy kernel.

use native_policy_kernel::{PlanError, PolicySnapshot};
pub(super) use native_policy_kernel::{PolicyMutation, PolicyTransition};

use crate::{Error, Result};

use super::TOOL;

fn map_plan_error(error: PlanError) -> Error {
    match error {
        PlanError::MembersManageMutation => Error::engine(format!("{TOOL}: {error}")),
        _ => Error::engine(error.to_string()),
    }
}

pub(super) fn validate_inheritance_restoration(
    record_id: &str,
    before: &PolicySnapshot,
) -> Result<()> {
    native_policy_kernel::validate_inheritance_restoration(
        record_id,
        record_id == crate::schema::ROOT_RECORD_ID,
        before,
    )
    .map_err(map_plan_error)
}

pub(super) fn plan_policy_transition(
    record_id: &str,
    before: &PolicySnapshot,
    mutation: PolicyMutation,
) -> Result<PolicyTransition> {
    native_policy_kernel::plan_policy_transition(
        record_id,
        record_id == crate::schema::ROOT_RECORD_ID,
        before,
        mutation,
    )
    .map_err(map_plan_error)
}
