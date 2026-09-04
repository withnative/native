//! Transport-independent descriptor and policy projection for federated lenses.

use std::collections::HashSet;

use serde_json::{json, Map, Value};

use crate::error::Error;

use super::interactions::{
    AdmissionReason, ExposureProfile, ResolvedToolExposure, ToolExposure, ToolFamily, ToolKind,
};
use super::protocol::tool_descriptor;
use super::registry::{
    descriptor_projection_bytes, validate_descriptor_projection, AdvertisedTool, ToolRegistry,
    COMPLETE_PROFILE_MAX_BYTES, FOCUSED_PROFILE_MAX_BYTES,
};

pub(super) const MAX_PAGE_SIZE: usize = 50;

#[derive(Clone, Copy)]
pub(super) enum LensToolDispatch {
    MaterializeRecord,
}

/// One lens-local capability truth. Name lookup, exposure, descriptor
/// projection and dispatch all derive from this table rather than coordinated
/// transport special cases.
pub(super) struct LensToolSpec {
    pub(super) name: &'static str,
    exposure: ToolExposure,
    descriptor: fn(&LensToolSpec) -> Value,
    pub(super) dispatch: LensToolDispatch,
}

const LENS_TOOL_SPECS: [LensToolSpec; 1] = [LensToolSpec {
    name: "materialize_record",
    // Governed materialization is both atomic and the sole door from a
    // federated source into a durable local shadow, so it is focused.
    exposure: ToolExposure::new(ToolFamily::Identity, true, AdmissionReason::Atomicity),
    descriptor: materialize_descriptor,
    dispatch: LensToolDispatch::MaterializeRecord,
}];

/// Authoritative exposure metadata for tools that exist only on federated
/// lens connections. Settings inventory consumes this registry directly.
pub fn lens_local_tool_exposures() -> impl Iterator<Item = (&'static str, ToolExposure)> {
    LENS_TOOL_SPECS
        .iter()
        .map(|tool| (tool.name, tool.exposure))
}

pub(super) fn lens_tool(name: &str) -> Option<&'static LensToolSpec> {
    LENS_TOOL_SPECS.iter().find(|tool| tool.name == name)
}

/// The actual descriptor projection emitted by a federated lens. This is the
/// single source for tools/list, bootstrap accounting and generated CI totals.
pub fn lens_descriptor_projection(
    registry: &ToolRegistry,
    profile: ExposureProfile,
) -> crate::Result<Vec<AdvertisedTool>> {
    lens_descriptor_projection_for_policy(registry, &ResolvedToolExposure::new(profile))
}

pub fn lens_descriptor_projection_for_policy(
    registry: &ToolRegistry,
    policy: &ResolvedToolExposure,
) -> crate::Result<Vec<AdvertisedTool>> {
    let mut local_names = HashSet::new();
    for tool in &LENS_TOOL_SPECS {
        if registry.get(tool.name).is_some() || !local_names.insert(tool.name) {
            return Err(Error::engine(format!(
                "lens tool registry collision: {} is registered more than once",
                tool.name
            )));
        }
    }
    let mut tools = registry
        .specs_for_policy(policy)
        .map(|tool| {
            let mut descriptor = tool_descriptor(tool);
            let Some(schema) = descriptor
                .get_mut("inputSchema")
                .and_then(Value::as_object_mut)
            else {
                return AdvertisedTool {
                    name: tool.name.clone(),
                    descriptor,
                    exposure: tool.exposure,
                };
            };
            match lens_tool_policy(tool.kind, &tool.name) {
                LensToolPolicy::FederatedRead => {
                    let properties = schema
                        .entry("properties")
                        .or_insert_with(|| json!({}))
                        .as_object_mut()
                        .expect("tool properties object");
                    properties.insert(
                        "cursor".into(),
                        json!({
                            "type": "string",
                            "description": "Opaque short-lived lens cursor from the previous page. Cursors invalidate conservatively when any source authorization state changes."
                        }),
                    );
                    properties.insert(
                        "page_size".into(),
                        json!({
                            "type": "integer", "minimum": 1, "maximum": MAX_PAGE_SIZE,
                            "description": "Global lens page size (default 25, maximum 50)."
                        }),
                    );
                    match tool.kind {
                        Some(ToolKind::GetRecord) => {
                            properties.insert("ids".into(), composite_ref_array_schema());
                        }
                        Some(ToolKind::Search) => {
                            properties.insert("scope".into(), composite_ref_schema());
                        }
                        Some(ToolKind::QueryRecord) => overlay_query_filter_ids(schema),
                        _ => {}
                    }
                }
                LensToolPolicy::DestinationPassThrough | LensToolPolicy::UnsupportedRead => {
                    overlay_top_level_property(
                        schema,
                        "destination_db_id",
                        &destination_schema(),
                    );
                }
            }
            AdvertisedTool {
                name: tool.name.clone(),
                descriptor,
                exposure: tool.exposure,
            }
        })
        .collect::<Vec<_>>();
    for tool in LENS_TOOL_SPECS
        .iter()
        .filter(|tool| policy.shows(tool.name, tool.exposure))
    {
        tools.push(AdvertisedTool {
            name: tool.name.into(),
            descriptor: (tool.descriptor)(tool),
            exposure: tool.exposure,
        });
    }
    Ok(tools)
}

pub fn validate_lens_policy_budget(
    registry: &ToolRegistry,
    policy: &ResolvedToolExposure,
) -> crate::Result<()> {
    validate_descriptor_projection(
        "federated-lens",
        policy.base_profile,
        &lens_descriptor_projection_for_policy(registry, policy)?,
        policy.base_profile.max_descriptor_bytes(),
    )
}

pub fn validate_lens_profile_budgets(registry: &ToolRegistry) -> crate::Result<()> {
    for (profile, limit) in [
        (ExposureProfile::Focused, FOCUSED_PROFILE_MAX_BYTES),
        (ExposureProfile::Complete, COMPLETE_PROFILE_MAX_BYTES),
    ] {
        let tools = lens_descriptor_projection(registry, profile)?;
        super::tools::quickstart::validate_actionable_dependency_closure(
            "federated-lens",
            profile,
            tools.iter().map(|tool| tool.name.as_str()),
        )?;
        validate_descriptor_projection("federated-lens", profile, &tools, limit)?;
    }
    Ok(())
}

pub(super) fn lens_exposure_summary(
    registry: &ToolRegistry,
    policy: &ResolvedToolExposure,
) -> crate::Result<Value> {
    let advertised = lens_descriptor_projection_for_policy(registry, policy)?;
    let complete = lens_descriptor_projection(registry, ExposureProfile::Complete)?;
    Ok(json!({
        "profile": policy.base_profile.as_str(),
        "customized": policy.is_customized(),
        "discovery_semantics": if policy.base_profile == ExposureProfile::Complete && !policy.is_customized() {
            "complete: every registered tool for this transport is advertised"
        } else {
            "filtered: tools may be intentionally hidden and workflows may have undiscoverable dependencies"
        },
        "authorization_semantics": "independent: every exact-name call retains its ordinary authorization and validation",
        "advertised_count": advertised.len(),
        "advertised_bytes": descriptor_projection_bytes(&advertised),
        "complete_count": complete.len(),
        "complete_bytes": descriptor_projection_bytes(&complete),
        "configurable": false,
        "budget_bytes": policy.base_profile.max_descriptor_bytes(),
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LensToolPolicy {
    FederatedRead,
    DestinationPassThrough,
    UnsupportedRead,
}

pub fn lens_tool_policy(kind: Option<ToolKind>, name: &str) -> LensToolPolicy {
    use LensToolPolicy::*;
    use ToolKind::*;
    match kind {
        Some(GetRecord | QueryRecord | Search) => FederatedRead,
        Some(
            SetIntent
            | CloseRun
            | CreateRecord
            | CreateMany
            | CreateExploration
            | UpdateRecord
            | ClaimUnownedRecord
            | CorrectRecordType
            | DeleteRecord
            | ArchiveRecord
            | ManageLinks
            | ManageMessages
            | ManageInterventions
            | InstantiateArtifact
            | ManageRendererBinding
            | ManageFacetObservations
            | ManageVocabularies
            | ManageSchemaConfig
            | AttachText
            | AttachFromUrl
            | ManageAttachments
            | StartWork
            | ResolveSuggestions
            | ManageCitations
            | CreateAttribution
            | ManageAttributions
            | ManageBindings
            | ManageRecordPolicy
            | ResolveExternal
            | ObserveExternal
            | ManageInstructions
            | ManageOnboarding
            | ManageMdxModules
            | ManageArtifactInputs
            | ManageArtifactModuleGrants
            | ManageChangeSummaries
            | ManageCanvas,
        ) => DestinationPassThrough,
        // A moment projection is scoped to one database's own event log and
        // read log. There is nothing to federate and nothing to pass through.
        Some(GetEventContext) => UnsupportedRead,
        Some(
            Ping
            | EngineInfo
            | StandbyStatus
            | Bootstrap
            | Quickstart
            | ReadGuide
            | GetStructure
            | GetDashboard
            | DescribeSchema
            | PreviewRecordShape
            | RenderRecord
            | GetHistory
            | WhatsChanged
            | GetRunActivity
            | RenderRecordVersionDiff
            | ManageRelationships
            | RenderArtifact
            | VerifyArtifact
            | InvokeArtifactInteraction
            | OpenCollection
            | ResolveFacets
            | SuggestFacetValues
            | ResolveRollup
            | QuerySql
            | Scan
            | ReadAttachment
            | RenderSuggestionReview
            | ExportSnapshot
            | ResolveCitation
            | ReadAttributions
            | ManageMemberships
            | QueryChangeSummaries
            | ResolveMany
            | ReadCanvas,
        ) => UnsupportedRead,
        // Embedding-only custom tools have no mutation policy. They remain
        // routable only when the caller explicitly names one lens source.
        None if matches!(name, "get_record" | "query_record" | "search") => FederatedRead,
        None => UnsupportedRead,
    }
}

fn destination_schema() -> Value {
    json!({
        "type": "string",
        "description": "Destination database ID; required for a multi-database lens."
    })
}

/// Add one transport-owned argument to the top-level object grammar and every
/// composed top-level object branch. Action-discriminated tools commonly close
/// each `oneOf` branch with `additionalProperties: false`; decorating only the
/// root would advertise an argument that every real action rejects. Do not walk
/// into property schemas: nested `oneOf` values describe authored fields, not
/// the transport call envelope.
fn overlay_top_level_property(schema: &mut Map<String, Value>, name: &str, property: &Value) {
    schema
        .entry("properties")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("tool properties object")
        .insert(name.into(), property.clone());
    for keyword in ["oneOf", "anyOf", "allOf"] {
        let Some(branches) = schema.get_mut(keyword).and_then(Value::as_array_mut) else {
            continue;
        };
        for branch in branches {
            if let Some(branch) = branch.as_object_mut() {
                overlay_top_level_property(branch, name, property);
            }
        }
    }
}

fn composite_ref_schema() -> Value {
    json!({
        "oneOf": [
            {
                "type": "string",
                "description": "A local record id; valid only when the lens contains one database."
            },
            {
                "type": "object",
                "properties": {
                    "db_id": { "type": "string", "minLength": 1 },
                    "record_id": { "type": "string", "minLength": 1 }
                },
                "required": ["db_id", "record_id"],
                "additionalProperties": false
            }
        ]
    })
}

fn composite_ref_array_schema() -> Value {
    json!({
        "type": "array",
        "minItems": 1,
        "items": composite_ref_schema(),
        "description": "Exact record identities. Multi-database lenses require {db_id, record_id} references."
    })
}

/// Overlay only the filter-id leaf. The surrounding query grammar remains the
/// registry's current shape, including saved-query additions merged later.
fn overlay_query_filter_ids(schema: &mut Map<String, Value>) {
    let filter_properties = schema
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .filter(|properties| properties.contains_key("step"));
    if let Some(properties) = filter_properties {
        if let Some(ids) = properties.get_mut("ids") {
            *ids = composite_ref_array_schema();
        }
    }
    for value in schema.values_mut() {
        overlay_query_filter_ids_value(value);
    }
}

fn overlay_query_filter_ids_value(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        overlay_query_filter_ids(object);
    } else if let Some(array) = value.as_array_mut() {
        for value in array {
            overlay_query_filter_ids_value(value);
        }
    }
}

fn materialize_descriptor(tool: &LensToolSpec) -> Value {
    json!({
        "name": tool.name,
        "description": "Create or refresh a governed local shadow from one exact lens source. Identity-only is the default and stores no readable source content. Snapshot content is captured only when explicitly selected by this call or the named lens policy. Multi-database lenses require destination_db_id; one-database lenses infer it. The source and destination must differ.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_ref": {
                    "type": "object",
                    "properties": {
                        "db_id": {"type":"string", "minLength":1},
                        "record_id": {"type":"string", "minLength":1}
                    },
                    "required": ["db_id", "record_id"],
                    "additionalProperties": false
                },
                "destination_db_id": {"type":"string", "minLength":1, "description":"Required only when this lens contains multiple databases."},
                "cache_policy": {"type":"string", "enum":["identity_only","snapshot"], "description":"Omit to inherit the named lens policy (identity_only by default)."},
                "snapshot_fields": {"type":"array", "minItems":1, "maxItems":8, "uniqueItems":true, "items":{"type":"string", "enum":["type","kind","name","summary","body","facets","updated_at"]}},
                "reason": {"type":"string", "minLength":1},
                "run_key": {"type":"string"},
                "parent_key": {"type":"string"}
            },
            "required": ["source_ref", "reason"],
            "additionalProperties": false
        }
    })
}
