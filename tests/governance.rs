//! Schema, migration, facet, kind and policy governance, plus repository provenance checks.
//!
//! Every `mod` below was previously its own `tests/*.rs` target. Cargo links
//! one test binary per target against the whole dependency graph, and those
//! link steps are not cacheable, so the suite is grouped into a few binaries
//! instead of a hundred. The tests themselves are unchanged; they now share a
//! process with their neighbours.

mod common;

#[path = "governance/build_provenance.rs"]
mod build_provenance;
#[path = "governance/canonical_interchange.rs"]
mod canonical_interchange;
#[path = "governance/definitions.rs"]
mod definitions;
#[path = "governance/facet_history.rs"]
mod facet_history;
#[path = "governance/facet_value_binding.rs"]
mod facet_value_binding;
#[path = "governance/home_contract.rs"]
mod home_contract;
#[path = "governance/kind_governance.rs"]
mod kind_governance;
#[path = "governance/migration_fixtures.rs"]
mod migration_fixtures;
#[path = "governance/policy_events.rs"]
mod policy_events;
#[path = "governance/policy_write_funnel.rs"]
mod policy_write_funnel;
#[path = "governance/record_id_prefix.rs"]
mod record_id_prefix;
#[path = "governance/record_id_validation.rs"]
mod record_id_validation;
#[path = "governance/relationship_write_funnel.rs"]
mod relationship_write_funnel;
#[path = "governance/required_facets.rs"]
mod required_facets;
#[path = "governance/schema.rs"]
mod schema;
#[path = "governance/schema_evolution.rs"]
mod schema_evolution;
#[path = "governance/source_boundary.rs"]
mod source_boundary;
#[path = "governance/type_immutability.rs"]
mod type_immutability;
#[path = "governance/typed_facets.rs"]
mod typed_facets;
