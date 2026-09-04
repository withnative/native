//! Record and content semantics: artifacts, attachments, annotations, messages and rendering.
//!
//! Every `mod` below was previously its own `tests/*.rs` target. Cargo links
//! one test binary per target against the whole dependency graph, and those
//! link steps are not cacheable, so the suite is grouped into a few binaries
//! instead of a hundred. The tests themselves are unchanged; they now share a
//! process with their neighbours.

mod common;

#[path = "records/annotations.rs"]
mod annotations;
#[path = "records/artifact_interactions.rs"]
mod artifact_interactions;
#[path = "records/artifact_modules.rs"]
mod artifact_modules;
#[path = "records/artifacts.rs"]
mod artifacts;
#[path = "records/attachments.rs"]
mod attachments;
#[path = "records/attribution.rs"]
mod attribution;
#[path = "records/bears_shape.rs"]
mod bears_shape;
#[path = "records/citations.rs"]
mod citations;
#[path = "records/comments.rs"]
mod comments;
#[path = "records/contribution_provenance.rs"]
mod contribution_provenance;
#[path = "records/embed_seam.rs"]
mod embed_seam;
#[path = "records/identity.rs"]
mod identity;
#[path = "records/interpretive_claims.rs"]
mod interpretive_claims;
#[path = "records/interventions.rs"]
mod interventions;
#[path = "records/member_destinations.rs"]
mod member_destinations;
#[path = "records/message_expectation.rs"]
mod message_expectation;
#[path = "records/message_first_conversations.rs"]
mod message_first_conversations;
#[path = "records/message_origins.rs"]
mod message_origins;
#[path = "records/multiplayer_axis.rs"]
mod multiplayer_axis;
#[path = "records/outcome_impact.rs"]
mod outcome_impact;
#[path = "records/read_log_capture.rs"]
mod read_log_capture;
#[path = "records/render.rs"]
mod render;
#[path = "records/search_semantics.rs"]
mod search_semantics;
#[path = "records/wordlist.rs"]
mod wordlist;
