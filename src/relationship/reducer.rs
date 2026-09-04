//! Root-crate composition for the storage-free relationship kernel.

pub(crate) use native_relationship_kernel::{
    AssertionHead, EffectiveOutcome, ReductionFacts, RelationshipProposition,
};

pub(super) fn reduce_effective_relationship(
    facts: ReductionFacts<'_>,
) -> crate::Result<EffectiveOutcome> {
    native_relationship_kernel::reduce_effective_relationship(facts)
        .map_err(|error| crate::Error::engine(error.to_string()))
}

pub(super) fn validate_reducer(id: &str, version: u64) -> crate::Result<()> {
    native_relationship_kernel::validate_reducer(id, version)
        .map_err(|error| crate::Error::engine(error.to_string()))
}
