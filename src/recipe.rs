//! Governed immutable recipe publications.
//!
//! A recipe's mutable authored definition lives on a `Program kind:recipe`.
//! Publication pins one exact body event and folds an immutable, hard-shaped
//! `native.recipe.v1` descriptor into content-log projections.  Draft edits do
//! not affect published releases.  Deprecation and withdrawal change only the
//! release's eligibility for future use; they never rewrite the descriptor.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};
use uuid::Uuid;

use crate::authorization::{Capability, Principal};
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};
use crate::events::EventRow;
use crate::store::{append_in, append_with_event_id_in, AppendSpec};

pub const RECIPE_RUNTIME: &str = "native.recipe.v1";
pub const RECIPE_RELEASE_SCHEMA: &str = "native.recipe.v1";

const MAX_INSTRUCTION_BYTES: usize = 64 * 1024;
const MAX_SCHEMA_BYTES: usize = 128 * 1024;
const MAX_ALLOWED_INPUT_CLASSES: usize = 16;
const MAX_CONTEXTUAL_INPUTS: usize = 16;
const MAX_PROFILE_CAPABILITIES: usize = 16;
const MAX_REPAIRS: u8 = 3;
const MAX_DEFINITION_BYTES: usize = 512 * 1024;
const MAX_RELEASE_PAYLOAD_BYTES: usize = 640 * 1024;
const MAX_STATUS_PAYLOAD_BYTES: usize = 4 * 1024;
const RECIPE_UNAVAILABLE: &str = "recipe release is unavailable";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeInputClass {
    Blob,
    ContentEvent,
    RecordBody,
    Versioned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeContextClass {
    ActorPreferences,
    RecordContext,
    WorkspaceInstructions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeBudgetField {
    MaxInputBytes,
    MaxInputItems,
    MaxInputTokens,
    MaxOutputBytes,
    MaxOutputTokens,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipeModelCapability {
    JsonSchemaOutput,
    LongContext,
    ToolReads,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeInstructions {
    pub revision: String,
    pub text: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeContract {
    pub id: String,
    pub version: u32,
    pub schema: Value,
    pub schema_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeRenderer {
    pub id: String,
    pub revision: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeBudgetLimits {
    pub max_input_bytes: u64,
    pub max_input_items: u32,
    pub max_input_tokens: u32,
    pub max_output_bytes: u64,
    pub max_output_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeBudgetPolicy {
    pub supported_fields: Vec<RecipeBudgetField>,
    pub defaults: RecipeBudgetLimits,
    pub maxima: RecipeBudgetLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeContextualInput {
    pub class: RecipeContextClass,
    pub required: bool,
    pub max_items: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeExecutionProfile {
    pub profile_id: String,
    pub required_capabilities: Vec<RecipeModelCapability>,
    pub temperature_milli: u16,
    pub max_output_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeRepairPolicy {
    pub max_repairs: u8,
    pub max_validation_errors: u16,
    pub repair_profile_id: Option<String>,
}

/// The authored recipe body.  This is deliberately closed: there is no caller
/// prompt, provider credential, ambient tool list, or arbitrary extension map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeDefinition {
    pub instructions: RecipeInstructions,
    pub query_contract: RecipeContract,
    pub allowed_input_classes: Vec<RecipeInputClass>,
    pub result_contract: RecipeContract,
    pub output_contract: RecipeContract,
    pub renderer: RecipeRenderer,
    pub budgets: RecipeBudgetPolicy,
    pub contextual_inputs: Vec<RecipeContextualInput>,
    pub execution_profile: RecipeExecutionProfile,
    pub repair_policy: RecipeRepairPolicy,
}

/// Portable immutable release descriptor.  Its digest is stored beside it in
/// the publication event so the descriptor itself has no hash self-reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeReleaseDescriptor {
    pub schema: String,
    pub publication_event_id: String,
    pub program_id: String,
    pub source_event_id: String,
    pub source_sha256: String,
    pub runtime: String,
    pub definition: RecipeDefinition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeReleasePublishedPayload {
    pub descriptor: RecipeReleaseDescriptor,
    pub descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeReleaseStatusPayload {
    pub publication_event_id: String,
    pub expected_status_event_seq: i64,
}

#[derive(Debug, Clone)]
pub struct PublishRecipeRelease {
    pub publication_event_id: String,
    pub program_id: String,
    pub source_event_id: String,
    pub source_sha256: String,
    pub definition: RecipeDefinition,
}

#[derive(Debug, Clone)]
pub struct ChangeRecipeReleaseStatus {
    pub program_id: String,
    pub publication_event_id: String,
    pub expected_status_event_seq: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeReleaseInspection {
    pub descriptor: RecipeReleaseDescriptor,
    pub descriptor_sha256: String,
    pub status: String,
    pub local_event_seq: i64,
    pub status_event_seq: i64,
    pub published_at: String,
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!("recipe {label} cannot be empty")));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn require_sha256(label: &str, value: &str) -> Result<()> {
    if !valid_sha256(value) {
        return Err(Error::engine(format!(
            "recipe {label} must be a lowercase sha256"
        )));
    }
    Ok(())
}

fn canonical_uuid(label: &str, value: &str) -> Result<()> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| Error::engine(format!("recipe {label} must be a canonical UUID")))?;
    if parsed.get_version() != Some(uuid::Version::Random)
        || parsed.hyphenated().to_string() != value
    {
        return Err(Error::engine(format!(
            "recipe {label} must be a canonical lowercase UUIDv4"
        )));
    }
    Ok(())
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn canonical_value(value: &Value) -> Result<String> {
    String::from_utf8(crate::canonical_json::canonical_json(value))
        .map_err(|_| Error::engine("canonical recipe JSON was not UTF-8"))
}

fn digest_value(value: &Value) -> Result<String> {
    Ok(sha256_bytes(canonical_value(value)?.as_bytes()))
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_contract(label: &str, contract: &RecipeContract) -> Result<()> {
    nonblank(&format!("{label} id"), &contract.id)?;
    if contract.version == 0 {
        return Err(Error::engine(format!(
            "recipe {label} version must be positive"
        )));
    }
    if !contract.schema.is_object() {
        return Err(Error::engine(format!(
            "recipe {label} schema must be an object"
        )));
    }
    // Bound the ordinary representation before invoking recursive JCS
    // canonicalization. This is deliberately a cheap rejection gate rather
    // than the digest representation itself.
    if serde_json::to_vec(&contract.schema)?.len() > MAX_SCHEMA_BYTES {
        return Err(Error::engine(format!(
            "recipe {label} schema exceeds {MAX_SCHEMA_BYTES} bytes"
        )));
    }
    require_sha256(&format!("{label} schema digest"), &contract.schema_sha256)?;
    if digest_value(&contract.schema)? != contract.schema_sha256 {
        return Err(Error::engine(format!(
            "recipe {label} schema digest does not match its canonical schema"
        )));
    }
    Ok(())
}

fn limits_fit(defaults: &RecipeBudgetLimits, maxima: &RecipeBudgetLimits) -> bool {
    defaults.max_input_bytes > 0
        && defaults.max_input_items > 0
        && defaults.max_input_tokens > 0
        && defaults.max_output_bytes > 0
        && defaults.max_output_tokens > 0
        && defaults.max_input_bytes <= maxima.max_input_bytes
        && defaults.max_input_items <= maxima.max_input_items
        && defaults.max_input_tokens <= maxima.max_input_tokens
        && defaults.max_output_bytes <= maxima.max_output_bytes
        && defaults.max_output_tokens <= maxima.max_output_tokens
}

pub fn validate_recipe_definition(definition: &RecipeDefinition) -> Result<()> {
    nonblank("instruction revision", &definition.instructions.revision)?;
    if definition.instructions.text.trim().is_empty()
        || definition.instructions.text.len() > MAX_INSTRUCTION_BYTES
    {
        return Err(Error::engine(format!(
            "recipe instructions must contain 1..={MAX_INSTRUCTION_BYTES} bytes"
        )));
    }
    if serde_json::to_vec(definition)?.len() > MAX_DEFINITION_BYTES {
        return Err(Error::engine(format!(
            "recipe definition exceeds {MAX_DEFINITION_BYTES} bytes"
        )));
    }
    require_sha256("instruction digest", &definition.instructions.sha256)?;
    if sha256_bytes(definition.instructions.text.as_bytes()) != definition.instructions.sha256 {
        return Err(Error::engine(
            "recipe instruction digest does not match its text",
        ));
    }
    validate_contract("query contract", &definition.query_contract)?;
    validate_contract("result contract", &definition.result_contract)?;
    validate_contract("output contract", &definition.output_contract)?;
    if definition.allowed_input_classes.is_empty()
        || definition.allowed_input_classes.len() > MAX_ALLOWED_INPUT_CLASSES
        || !sorted_unique(&definition.allowed_input_classes)
    {
        return Err(Error::engine(
            "recipe allowed input classes must be non-empty, bounded, sorted and unique",
        ));
    }
    nonblank("renderer id", &definition.renderer.id)?;
    nonblank("renderer revision", &definition.renderer.revision)?;
    require_sha256("renderer digest", &definition.renderer.sha256)?;
    if definition.budgets.supported_fields.is_empty()
        || definition.budgets.supported_fields.len() > MAX_PROFILE_CAPABILITIES
        || !sorted_unique(&definition.budgets.supported_fields)
        || !limits_fit(&definition.budgets.defaults, &definition.budgets.maxima)
    {
        return Err(Error::engine(
            "recipe reading budgets must have sorted unique fields and positive defaults within maxima",
        ));
    }
    if definition.contextual_inputs.len() > MAX_CONTEXTUAL_INPUTS
        || !definition
            .contextual_inputs
            .windows(2)
            .all(|pair| pair[0].class < pair[1].class)
        || definition
            .contextual_inputs
            .iter()
            .any(|input| input.max_items == 0)
    {
        return Err(Error::engine(
            "recipe contextual inputs must be bounded, sorted, unique and positive",
        ));
    }
    nonblank(
        "execution profile id",
        &definition.execution_profile.profile_id,
    )?;
    if definition.execution_profile.required_capabilities.len() > MAX_PROFILE_CAPABILITIES
        || !sorted_unique(&definition.execution_profile.required_capabilities)
        || definition.execution_profile.temperature_milli > 2_000
        || definition.execution_profile.max_output_tokens == 0
        || definition.execution_profile.max_output_tokens
            > definition.budgets.maxima.max_output_tokens
    {
        return Err(Error::engine(
            "recipe execution profile is not canonical or exceeds its declared budget",
        ));
    }
    if definition.repair_policy.max_repairs > MAX_REPAIRS
        || definition.repair_policy.max_validation_errors == 0
    {
        return Err(Error::engine(
            "recipe repair policy is not positively bounded",
        ));
    }
    match (
        definition.repair_policy.max_repairs,
        definition.repair_policy.repair_profile_id.as_deref(),
    ) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err(Error::engine(
                "recipe repair profile requires at least one repair",
            ))
        }
        (_, Some(profile)) => nonblank("repair profile id", profile)?,
        (_, None) => {
            return Err(Error::engine(
                "recipe repairs require an explicit repair profile",
            ))
        }
    }
    Ok(())
}

pub fn canonical_recipe_definition(definition: &RecipeDefinition) -> Result<String> {
    validate_recipe_definition(definition)?;
    canonical_value(&serde_json::to_value(definition)?)
}

pub fn recipe_definition_sha256(definition: &RecipeDefinition) -> Result<String> {
    Ok(sha256_bytes(
        canonical_recipe_definition(definition)?.as_bytes(),
    ))
}

pub fn validate_recipe_release_descriptor(descriptor: &RecipeReleaseDescriptor) -> Result<()> {
    if descriptor.schema != RECIPE_RELEASE_SCHEMA || descriptor.runtime != RECIPE_RUNTIME {
        return Err(Error::engine(
            "recipe release must use native.recipe.v1 schema and runtime",
        ));
    }
    canonical_uuid("publication event id", &descriptor.publication_event_id)?;
    canonical_uuid("source event id", &descriptor.source_event_id)?;
    nonblank("Program id", &descriptor.program_id)?;
    require_sha256("source digest", &descriptor.source_sha256)?;
    validate_recipe_definition(&descriptor.definition)
}

pub fn canonical_recipe_release_descriptor(descriptor: &RecipeReleaseDescriptor) -> Result<String> {
    validate_recipe_release_descriptor(descriptor)?;
    canonical_value(&serde_json::to_value(descriptor)?)
}

pub fn recipe_release_sha256(descriptor: &RecipeReleaseDescriptor) -> Result<String> {
    Ok(sha256_bytes(
        canonical_recipe_release_descriptor(descriptor)?.as_bytes(),
    ))
}

fn is_recipe_program_type(record_type: &str) -> bool {
    record_type == "Program"
}

/// Requires the canonical live `Program kind:recipe` carrier and exact runtime.
async fn require_live_recipe_program(conn: &mut SqliteConnection, program_id: &str) -> Result<()> {
    let row = sqlx::query(
        "SELECT r.type,r.kind,r.deleted_at,
                (SELECT value FROM facet_values WHERE record_id=r.id AND key='runtime') AS runtime
           FROM records r WHERE r.id=?",
    )
    .bind(program_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("recipe Program does not exist"))?;
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    let deleted_at: Option<String> = row.try_get("deleted_at")?;
    let runtime: Option<String> = row.try_get("runtime")?;
    if !is_recipe_program_type(&record_type)
        || kind.as_deref() != Some("recipe")
        || deleted_at.is_some()
        || runtime.as_deref() != Some(RECIPE_RUNTIME)
    {
        return Err(Error::engine(
            "recipe publication requires a live Program kind:recipe with runtime native.recipe.v1",
        ));
    }
    Ok(())
}

/// Load the named body event itself, then prove that it was still the current
/// body at `upper_exclusive`. `None` means the current end of the log. Looking
/// up the exact event first is important for deterministic replay: later rows
/// in the ambient database cannot change what an older publication meant.
async fn exact_source_definition_before(
    conn: &mut SqliteConnection,
    program_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    upper_exclusive: Option<i64>,
) -> Result<RecipeDefinition> {
    let row = sqlx::query(
        "SELECT id,record_id,type,seq,json_type(payload,'$.body') AS body_type,
                json_extract(payload,'$.body') AS body
           FROM content_events
          WHERE id=?",
    )
    .bind(source_event_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("recipe source event does not exist"))?;
    let actual_event_id: String = row.try_get("id")?;
    let actual_program_id: String = row.try_get("record_id")?;
    let event_type: String = row.try_get("type")?;
    let source_seq: i64 = row.try_get("seq")?;
    let body_type: Option<String> = row.try_get("body_type")?;
    if actual_event_id != source_event_id
        || actual_program_id != program_id
        || !matches!(
            event_type.as_str(),
            "record.created" | "record.updated" | "receipt.committed.v1"
        )
        || body_type.as_deref() != Some("text")
    {
        return Err(Error::engine(
            "recipe source event is not an exact body event for this Program",
        ));
    }
    if let Some(upper) = upper_exclusive {
        if source_seq >= upper {
            return Err(Error::engine(
                "recipe source event must precede its publication event",
            ));
        }
    }
    let intervening: i64 = match upper_exclusive {
        Some(upper) => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM content_events
                     WHERE record_id=? AND seq>? AND seq<?
                       AND type IN ('record.created','record.updated','receipt.committed.v1')
                       AND json_type(payload,'$.body') IS NOT NULL
                 )",
            )
            .bind(program_id)
            .bind(source_seq)
            .bind(upper)
            .fetch_one(&mut *conn)
            .await?
        }
        None => {
            sqlx::query_scalar(
                "SELECT EXISTS(
                    SELECT 1 FROM content_events
                     WHERE record_id=? AND seq>?
                       AND type IN ('record.created','record.updated','receipt.committed.v1')
                       AND json_type(payload,'$.body') IS NOT NULL
                 )",
            )
            .bind(program_id)
            .bind(source_seq)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    if intervening != 0 {
        return Err(Error::engine(
            "recipe source event changed since publication preflight",
        ));
    }
    let body: Option<String> = row.try_get("body")?;
    let body = body.ok_or_else(|| Error::engine("recipe source body is missing"))?;
    if body.len() > MAX_DEFINITION_BYTES {
        return Err(Error::engine(format!(
            "recipe source body exceeds {MAX_DEFINITION_BYTES} bytes"
        )));
    }
    if sha256_bytes(body.as_bytes()) != source_sha256 {
        return Err(Error::engine(
            "recipe source digest changed since publication preflight",
        ));
    }
    let definition: RecipeDefinition = serde_json::from_str(&body)
        .map_err(|err| Error::engine(format!("recipe source body is invalid: {err}")))?;
    validate_recipe_definition(&definition)?;
    Ok(definition)
}

fn principal_actor<'a>(principal: Principal<'a>) -> Result<&'a str> {
    let actor = principal
        .account_id
        .ok_or_else(|| Error::engine("recipe publication requires a bound account principal"))?;
    nonblank("actor", actor)?;
    Ok(actor)
}

fn unavailable(message: &'static str) -> Error {
    Error::engine(message)
}

fn conceal_resource_error(error: Error, message: &'static str) -> Error {
    match error {
        Error::Engine(_) | Error::Auth(_) => unavailable(message),
        internal => internal,
    }
}

async fn require_public_capability(
    db: &Db,
    principal: Principal<'_>,
    record_id: &str,
    required: Capability,
    message: &'static str,
) -> Result<()> {
    crate::authorization::require_capability(db, principal, record_id, required)
        .await
        .map_err(|error| conceal_resource_error(error, message))
}

async fn require_public_capability_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    record_id: &str,
    required: Capability,
    message: &'static str,
) -> Result<()> {
    crate::authorization::require_capability_on(tx, principal, record_id, required)
        .await
        .map_err(|error| conceal_resource_error(error, message))
}

pub async fn publish_recipe_release(
    db: &Db,
    principal: Principal<'_>,
    input: PublishRecipeRelease,
) -> Result<RecipeReleaseInspection> {
    // Fail closed on the cheap authorization boundary before recursive
    // validation/JCS work. The write transaction repeats this check so a
    // policy change cannot race publication.
    require_public_capability(
        db,
        principal,
        &input.program_id,
        Capability::Manage,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    let descriptor = RecipeReleaseDescriptor {
        schema: RECIPE_RELEASE_SCHEMA.into(),
        publication_event_id: input.publication_event_id.clone(),
        program_id: input.program_id.clone(),
        source_event_id: input.source_event_id.clone(),
        source_sha256: input.source_sha256.clone(),
        runtime: RECIPE_RUNTIME.into(),
        definition: input.definition.clone(),
    };
    let descriptor_sha256 = recipe_release_sha256(&descriptor)?;
    let actor = principal_actor(principal)
        .map_err(|_| unavailable(RECIPE_UNAVAILABLE))?
        .to_owned();
    let mut tx = begin_write(db.write_pool()).await?;
    require_public_capability_on(
        &mut tx,
        principal,
        &input.program_id,
        Capability::Manage,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    require_live_recipe_program(&mut tx, &input.program_id)
        .await
        .map_err(|error| conceal_resource_error(error, RECIPE_UNAVAILABLE))?;
    let stored = exact_source_definition_before(
        &mut tx,
        &input.program_id,
        &input.source_event_id,
        &input.source_sha256,
        None,
    )
    .await?;
    if stored != input.definition {
        return Err(Error::engine(
            "recipe publication definition does not match the pinned source body",
        ));
    }
    let event = append_with_event_id_in(
        db,
        &mut tx,
        input.publication_event_id,
        AppendSpec {
            record_id: input.program_id.clone(),
            event_type: "recipe.release_published".into(),
            payload: serde_json::to_value(RecipeReleasePublishedPayload {
                descriptor,
                descriptor_sha256,
            })?,
            actor: Some(actor),
        },
    )
    .await?;
    let release = read_release_on(&mut tx, &input.program_id, &event.id)
        .await?
        .ok_or_else(|| Error::engine("recipe publication projection was not created"))?;
    db.commit_content(tx).await?;
    Ok(release)
}

async fn change_status(
    db: &Db,
    principal: Principal<'_>,
    input: ChangeRecipeReleaseStatus,
    event_type: &str,
) -> Result<RecipeReleaseInspection> {
    canonical_uuid("publication event id", &input.publication_event_id)?;
    if input.expected_status_event_seq <= 0 {
        return Err(Error::engine(
            "recipe expected status event sequence must be positive",
        ));
    }
    require_public_capability(
        db,
        principal,
        &input.program_id,
        Capability::Manage,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    let actor = principal_actor(principal)
        .map_err(|_| unavailable(RECIPE_UNAVAILABLE))?
        .to_owned();
    let mut tx = begin_write(db.write_pool()).await?;
    require_public_capability_on(
        &mut tx,
        principal,
        &input.program_id,
        Capability::Manage,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    require_live_recipe_program(&mut tx, &input.program_id)
        .await
        .map_err(|error| conceal_resource_error(error, RECIPE_UNAVAILABLE))?;
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM recipe_releases
                        WHERE program_id=? AND publication_event_id=?)",
    )
    .bind(&input.program_id)
    .bind(&input.publication_event_id)
    .fetch_one(&mut *tx)
    .await?;
    if exists == 0 {
        return Err(unavailable(RECIPE_UNAVAILABLE));
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: input.program_id.clone(),
            event_type: event_type.into(),
            payload: serde_json::to_value(RecipeReleaseStatusPayload {
                publication_event_id: input.publication_event_id.clone(),
                expected_status_event_seq: input.expected_status_event_seq,
            })?,
            actor: Some(actor),
        },
    )
    .await?;
    let release = read_release_on(&mut tx, &input.program_id, &input.publication_event_id)
        .await?
        .ok_or_else(|| Error::engine("recipe status projection disappeared"))?;
    db.commit_content(tx).await?;
    Ok(release)
}

pub async fn deprecate_recipe_release(
    db: &Db,
    principal: Principal<'_>,
    input: ChangeRecipeReleaseStatus,
) -> Result<RecipeReleaseInspection> {
    change_status(db, principal, input, "recipe.release_deprecated").await
}

pub async fn withdraw_recipe_release(
    db: &Db,
    principal: Principal<'_>,
    input: ChangeRecipeReleaseStatus,
) -> Result<RecipeReleaseInspection> {
    change_status(db, principal, input, "recipe.release_withdrawn").await
}

fn release_from_row(row: sqlx::sqlite::SqliteRow) -> Result<RecipeReleaseInspection> {
    Ok(RecipeReleaseInspection {
        descriptor: serde_json::from_str(&row.try_get::<String, _>("descriptor")?)?,
        descriptor_sha256: row.try_get("descriptor_sha256")?,
        status: row.try_get("status")?,
        local_event_seq: row.try_get("local_event_seq")?,
        status_event_seq: row.try_get("status_event_seq")?,
        published_at: row.try_get("published_at")?,
    })
}

async fn read_release_on(
    tx: &mut Transaction<'_, Sqlite>,
    program_id: &str,
    publication_id: &str,
) -> Result<Option<RecipeReleaseInspection>> {
    let row = sqlx::query(
        "SELECT descriptor,descriptor_sha256,status,local_event_seq,status_event_seq,published_at
           FROM recipe_releases WHERE program_id=? AND publication_event_id=?",
    )
    .bind(program_id)
    .bind(publication_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(release_from_row).transpose()
}

/// Inspect one release using the caller's existing authorization snapshot.
pub async fn inspect_recipe_release_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
) -> Result<RecipeReleaseInspection> {
    require_public_capability_on(
        tx,
        principal,
        program_id,
        Capability::View,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    read_release_on(tx, program_id, publication_id)
        .await?
        .ok_or_else(|| unavailable(RECIPE_UNAVAILABLE))
}

pub async fn inspect_recipe_release(
    db: &Db,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
) -> Result<RecipeReleaseInspection> {
    let mut tx = db.pool().begin().await?;
    let result = inspect_recipe_release_on(&mut tx, principal, program_id, publication_id).await;
    tx.rollback().await?;
    result
}

/// List releases using the caller's existing authorization snapshot.
pub async fn inspect_recipe_releases_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    program_id: &str,
) -> Result<Vec<RecipeReleaseInspection>> {
    require_public_capability_on(
        tx,
        principal,
        program_id,
        Capability::View,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    let rows = sqlx::query(
        "SELECT descriptor,descriptor_sha256,status,local_event_seq,status_event_seq,published_at
           FROM recipe_releases WHERE program_id=? ORDER BY local_event_seq",
    )
    .bind(program_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut releases = Vec::with_capacity(rows.len());
    for row in rows {
        releases.push(release_from_row(row)?);
    }
    Ok(releases)
}

pub async fn inspect_recipe_releases(
    db: &Db,
    principal: Principal<'_>,
    program_id: &str,
) -> Result<Vec<RecipeReleaseInspection>> {
    let mut tx = db.pool().begin().await?;
    let result = inspect_recipe_releases_on(&mut tx, principal, program_id).await;
    tx.rollback().await?;
    result
}

/// Inspect whether a release could start a new series in this read snapshot.
/// This is advisory: a caller that subsequently creates a series must repeat
/// the fenced eligibility check inside the transaction that acquires it.
pub async fn recipe_release_for_new_series(
    db: &Db,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
) -> Result<RecipeReleaseInspection> {
    let mut tx = db.pool().begin().await?;
    let result =
        recipe_release_for_new_series_on(&mut tx, principal, program_id, publication_id).await;
    tx.rollback().await?;
    result
}

/// Read-snapshot counterpart to [`recipe_release_for_new_series`].
pub async fn recipe_release_for_new_series_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
) -> Result<RecipeReleaseInspection> {
    let release = inspect_recipe_release_on(tx, principal, program_id, publication_id).await?;
    match release.status.as_str() {
        "published" => Ok(release),
        "deprecated" => Err(Error::engine(
            "deprecated recipe release cannot start a new derivation series",
        )),
        "withdrawn" => Err(Error::engine(
            "withdrawn recipe release cannot start a new derivation series",
        )),
        _ => unreachable!("recipe release status is schema constrained"),
    }
}

/// Inspect whether an exact release already pinned by a series could execute in
/// this read snapshot. Deprecated releases remain eligible; withdrawn releases
/// remain inspectable but cannot execute. This result is advisory only: request
/// acquisition must call [`require_recipe_release_for_execution_on`] in its own
/// write transaction.
pub async fn recipe_release_for_execution(
    db: &Db,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
) -> Result<RecipeReleaseInspection> {
    let mut tx = db.pool().begin().await?;
    let result =
        recipe_release_for_execution_on(&mut tx, principal, program_id, publication_id).await;
    tx.rollback().await?;
    result
}

/// Read-snapshot counterpart to [`recipe_release_for_execution`]. This remains
/// advisory because it has no expected-status fence.
pub async fn recipe_release_for_execution_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
) -> Result<RecipeReleaseInspection> {
    let release = inspect_recipe_release_on(tx, principal, program_id, publication_id).await?;
    if release.status == "withdrawn" {
        Err(Error::engine(
            "withdrawn recipe release cannot start a new execution",
        ))
    } else {
        Ok(release)
    }
}

/// Authoritative execution gate for eventual request acquisition.
///
/// The caller supplies the status sequence it observed and must keep this
/// transaction open through creation/acquisition of the execution request.
/// Because status transitions use the same SQLite writer lock, the exact
/// sequence fence and eligibility decision cannot be invalidated before that
/// mutation commits.
pub async fn require_recipe_release_for_execution_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
    expected_status_event_seq: i64,
) -> Result<RecipeReleaseInspection> {
    if expected_status_event_seq <= 0 {
        return Err(Error::engine(
            "recipe expected status event sequence must be positive",
        ));
    }
    require_public_capability_on(
        tx,
        principal,
        program_id,
        Capability::View,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    let row = sqlx::query(
        "SELECT descriptor,descriptor_sha256,status,local_event_seq,status_event_seq,published_at
           FROM recipe_releases
          WHERE program_id=? AND publication_event_id=? AND status_event_seq=?
            AND status IN ('published','deprecated')",
    )
    .bind(program_id)
    .bind(publication_id)
    .bind(expected_status_event_seq)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| unavailable(RECIPE_UNAVAILABLE))?;
    release_from_row(row)
}

/// Authoritative exact-status gate for creating a new stable series. Unlike
/// execution of an existing series, deprecation is not eligible here.
pub async fn require_recipe_release_for_new_series_on(
    tx: &mut Transaction<'_, Sqlite>,
    principal: Principal<'_>,
    program_id: &str,
    publication_id: &str,
    expected_status_event_seq: i64,
) -> Result<RecipeReleaseInspection> {
    if expected_status_event_seq <= 0 {
        return Err(Error::engine(
            "recipe expected status event sequence must be positive",
        ));
    }
    require_public_capability_on(
        tx,
        principal,
        program_id,
        Capability::View,
        RECIPE_UNAVAILABLE,
    )
    .await?;
    let row = sqlx::query(
        "SELECT descriptor,descriptor_sha256,status,local_event_seq,status_event_seq,published_at
           FROM recipe_releases
          WHERE program_id=? AND publication_event_id=? AND status_event_seq=?
            AND status='published'",
    )
    .bind(program_id)
    .bind(publication_id)
    .bind(expected_status_event_seq)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| unavailable(RECIPE_UNAVAILABLE))?;
    release_from_row(row)
}

pub(crate) async fn project_recipe_release_published(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let raw_payload = event
        .payload
        .as_deref()
        .ok_or_else(|| Error::engine("recipe publication payload is missing"))?;
    if raw_payload.len() > MAX_RELEASE_PAYLOAD_BYTES {
        return Err(Error::engine(format!(
            "recipe publication payload exceeds {MAX_RELEASE_PAYLOAD_BYTES} bytes"
        )));
    }
    let payload: RecipeReleasePublishedPayload = serde_json::from_str(raw_payload)?;
    let descriptor = &payload.descriptor;
    validate_recipe_release_descriptor(descriptor)?;
    require_sha256("release descriptor digest", &payload.descriptor_sha256)?;
    if descriptor.publication_event_id != event.id || descriptor.program_id != event.record_id {
        return Err(Error::engine(
            "recipe publication event envelope does not match descriptor identity",
        ));
    }
    if recipe_release_sha256(descriptor)? != payload.descriptor_sha256 {
        return Err(Error::engine(
            "recipe release descriptor digest does not match canonical descriptor",
        ));
    }
    require_live_recipe_program(conn, &event.record_id).await?;
    let source = exact_source_definition_before(
        conn,
        &event.record_id,
        &descriptor.source_event_id,
        &descriptor.source_sha256,
        Some(event.local_seq),
    )
    .await?;
    if source != descriptor.definition {
        return Err(Error::engine(
            "recipe release descriptor does not match pinned source definition",
        ));
    }
    sqlx::query(
        "INSERT INTO recipe_releases
           (publication_event_id,program_id,source_event_id,source_sha256,descriptor_sha256,
            descriptor,status,local_event_seq,status_event_seq,published_at)
         VALUES(?,?,?,?,?,?,'published',?,?,?)",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(&descriptor.source_event_id)
    .bind(&descriptor.source_sha256)
    .bind(&payload.descriptor_sha256)
    .bind(canonical_recipe_release_descriptor(descriptor)?)
    .bind(event.local_seq)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    for (ordinal, input_class) in descriptor
        .definition
        .allowed_input_classes
        .iter()
        .enumerate()
    {
        let encoded = serde_json::to_value(input_class)?
            .as_str()
            .expect("recipe input class serializes as string")
            .to_owned();
        sqlx::query(
            "INSERT INTO recipe_release_input_classes(publication_event_id,ordinal,input_class)
             VALUES(?,?,?)",
        )
        .bind(&event.id)
        .bind(ordinal as i64)
        .bind(encoded)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query("UPDATE records SET last_activity_at=? WHERE id=?")
        .bind(&event.created_at)
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub(crate) async fn project_recipe_release_status(
    conn: &mut SqliteConnection,
    event: &EventRow,
    status: &str,
) -> Result<()> {
    require_live_recipe_program(conn, &event.record_id).await?;
    let raw_payload = event
        .payload
        .as_deref()
        .ok_or_else(|| Error::engine("recipe release status payload is missing"))?;
    if raw_payload.len() > MAX_STATUS_PAYLOAD_BYTES {
        return Err(Error::engine(format!(
            "recipe release status payload exceeds {MAX_STATUS_PAYLOAD_BYTES} bytes"
        )));
    }
    let payload: RecipeReleaseStatusPayload = serde_json::from_str(raw_payload)?;
    canonical_uuid("publication event id", &payload.publication_event_id)?;
    if payload.expected_status_event_seq <= 0 {
        return Err(Error::engine(
            "recipe expected status event sequence must be positive",
        ));
    }
    let allowed = if status == "deprecated" {
        "status='published'"
    } else {
        "status IN ('published','deprecated')"
    };
    let changed = sqlx::query(&format!(
        "UPDATE recipe_releases SET status=?,status_event_seq=?
          WHERE publication_event_id=? AND program_id=? AND status_event_seq=? AND {allowed}"
    ))
    .bind(status)
    .bind(event.local_seq)
    .bind(&payload.publication_event_id)
    .bind(&event.record_id)
    .bind(payload.expected_status_event_seq)
    .execute(&mut *conn)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine(
            "recipe release status target does not exist or lost its status race",
        ));
    }
    sqlx::query("UPDATE records SET last_activity_at=? WHERE id=?")
        .bind(&event.created_at)
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{AllowEntry, Capability};
    use crate::events::FacetSetPayload;
    use serde_json::json;

    fn digest(value: &str) -> String {
        sha256_bytes(value.as_bytes())
    }

    fn contract(id: &str) -> RecipeContract {
        let schema = json!({"type":"object","additionalProperties":false});
        RecipeContract {
            id: id.into(),
            version: 1,
            schema_sha256: digest_value(&schema).unwrap(),
            schema,
        }
    }

    fn definition() -> RecipeDefinition {
        let instructions = "Summarize the selected changes as structured evidence.";
        RecipeDefinition {
            instructions: RecipeInstructions {
                revision: "change-summary:1".into(),
                text: instructions.into(),
                sha256: digest(instructions),
            },
            query_contract: contract("native.change-query.v1"),
            allowed_input_classes: vec![
                RecipeInputClass::ContentEvent,
                RecipeInputClass::RecordBody,
            ],
            result_contract: contract("native.change-summary.result.v1"),
            output_contract: contract("native.document-body.v1"),
            renderer: RecipeRenderer {
                id: "native.change-summary.renderer".into(),
                revision: "1".into(),
                sha256: "a".repeat(64),
            },
            budgets: RecipeBudgetPolicy {
                supported_fields: vec![
                    RecipeBudgetField::MaxInputItems,
                    RecipeBudgetField::MaxOutputTokens,
                ],
                defaults: RecipeBudgetLimits {
                    max_input_bytes: 32_000,
                    max_input_items: 100,
                    max_input_tokens: 8_000,
                    max_output_bytes: 8_000,
                    max_output_tokens: 1_000,
                },
                maxima: RecipeBudgetLimits {
                    max_input_bytes: 128_000,
                    max_input_items: 1_000,
                    max_input_tokens: 32_000,
                    max_output_bytes: 32_000,
                    max_output_tokens: 4_000,
                },
            },
            contextual_inputs: vec![RecipeContextualInput {
                class: RecipeContextClass::WorkspaceInstructions,
                required: false,
                max_items: 4,
            }],
            execution_profile: RecipeExecutionProfile {
                profile_id: "native.structured-summary.v1".into(),
                required_capabilities: vec![RecipeModelCapability::JsonSchemaOutput],
                temperature_milli: 200,
                max_output_tokens: 2_000,
            },
            repair_policy: RecipeRepairPolicy {
                max_repairs: 1,
                max_validation_errors: 8,
                repair_profile_id: Some("native.structured-repair.v1".into()),
            },
        }
    }

    async fn fixture() -> (Db, String, String, String, RecipeDefinition) {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let definition = definition();
        let body = canonical_recipe_definition(&definition).unwrap();
        let id = crate::store::create_record_as(
            &db,
            json!({
                "id":"4ec1be00-0000-4000-8000-000000000001",
                "type":"Program",
                "kind":"recipe",
                "name":"Change summary recipe",
                "body":body
            }),
            Some("acct:publisher"),
        )
        .await
        .unwrap();
        crate::store::set_facet(
            &db,
            &id,
            FacetSetPayload {
                key: "runtime".into(),
                value: Some(RECIPE_RUNTIME.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "acct:publisher",
            &id,
            vec![AllowEntry::account("acct:publisher", Capability::Manage)],
        )
        .await
        .unwrap();
        let row = sqlx::query(
            "SELECT id,json_extract(payload,'$.body') AS body FROM content_events
              WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let source_event: String = row.try_get("id").unwrap();
        let source_body: String = row.try_get("body").unwrap();
        let source_sha = digest(&source_body);
        (db, id, source_event, source_sha, definition)
    }

    fn publish_input(
        id: &str,
        source_event: &str,
        source_sha: &str,
        definition: RecipeDefinition,
    ) -> PublishRecipeRelease {
        PublishRecipeRelease {
            publication_event_id: Uuid::new_v4().to_string(),
            program_id: id.into(),
            source_event_id: source_event.into(),
            source_sha256: source_sha.into(),
            definition,
        }
    }

    #[test]
    fn definition_validation_is_canonical_and_bounded() {
        let valid = definition();
        assert!(validate_recipe_definition(&valid).is_ok());
        let mut arbitrary = serde_json::to_value(&valid).unwrap();
        arbitrary
            .as_object_mut()
            .unwrap()
            .insert("prompt".into(), json!("caller supplied"));
        assert!(serde_json::from_value::<RecipeDefinition>(arbitrary).is_err());
        let mut unsorted = valid.clone();
        unsorted.allowed_input_classes.reverse();
        assert!(validate_recipe_definition(&unsorted)
            .unwrap_err()
            .to_string()
            .contains("sorted and unique"));
        let mut bad_digest = valid;
        bad_digest.instructions.sha256 = "b".repeat(64);
        assert!(validate_recipe_definition(&bad_digest)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
    }

    #[tokio::test]
    async fn publication_is_manage_authorized_source_fenced_and_replayable() {
        let (db, id, source_event, source_sha, definition) = fixture().await;
        let denied = publish_recipe_release(
            &db,
            Principal::bound("acct:other", true),
            publish_input(&id, &source_event, &source_sha, definition.clone()),
        )
        .await
        .unwrap_err();
        assert_eq!(denied.to_string(), RECIPE_UNAVAILABLE);

        let published = publish_recipe_release(
            &db,
            Principal::bound("acct:publisher", true),
            publish_input(&id, &source_event, &source_sha, definition.clone()),
        )
        .await
        .unwrap();
        assert_eq!(published.status, "published");
        assert_eq!(published.descriptor.definition, definition);
        let classes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM recipe_release_input_classes WHERE publication_event_id=?",
        )
        .bind(&published.descriptor.publication_event_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(classes, 2);
        let diff = crate::conformance::rebuild_and_diff(&db).await.unwrap();
        assert!(diff.equal, "{diff:?}");

        crate::store::update_record(&db, &id, json!({"body":"{}"}))
            .await
            .unwrap();

        // Re-project the older publication while the ambient database already
        // contains a future body edit. Its meaning must remain fixed at the
        // source and publication sequence, not at the latest row today.
        let event_row = sqlx::query(
            "SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at
               FROM content_events WHERE id=?",
        )
        .bind(&published.descriptor.publication_event_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let publication_event = EventRow {
            local_seq: event_row.try_get("seq").unwrap(),
            id: event_row.try_get("id").unwrap(),
            record_id: event_row.try_get("record_id").unwrap(),
            event_type: event_row.try_get("type").unwrap(),
            payload: event_row.try_get("payload").unwrap(),
            actor: event_row.try_get("actor").unwrap(),
            run_key: event_row.try_get("run_key").unwrap(),
            parent_key: event_row.try_get("parent_key").unwrap(),
            intent: event_row.try_get("intent").unwrap(),
            created_at: event_row.try_get("created_at").unwrap(),
            causal_envelope: crate::events::CausalEnvelopeV1::complete(
                crate::events::CausalFrontierV1::empty(),
            ),
        };
        let mut replay_tx = begin_write(db.write_pool()).await.unwrap();
        sqlx::query("DELETE FROM recipe_release_input_classes WHERE publication_event_id=?")
            .bind(&publication_event.id)
            .execute(&mut *replay_tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM recipe_releases WHERE publication_event_id=?")
            .bind(&publication_event.id)
            .execute(&mut *replay_tx)
            .await
            .unwrap();
        project_recipe_release_published(&mut replay_tx, &publication_event)
            .await
            .unwrap();
        replay_tx.rollback().await.unwrap();

        let stale = publish_recipe_release(
            &db,
            Principal::bound("acct:publisher", true),
            publish_input(&id, &source_event, &source_sha, definition),
        )
        .await
        .unwrap_err();
        assert!(stale.to_string().contains("source event changed"));
    }

    #[tokio::test]
    async fn deprecated_and_withdrawn_have_distinct_use_semantics() {
        let (db, id, source_event, source_sha, definition) = fixture().await;
        let principal = Principal::bound("acct:publisher", true);
        let published = publish_recipe_release(
            &db,
            principal,
            publish_input(&id, &source_event, &source_sha, definition),
        )
        .await
        .unwrap();
        let publication_id = published.descriptor.publication_event_id.clone();
        let deprecated = deprecate_recipe_release(
            &db,
            principal,
            ChangeRecipeReleaseStatus {
                program_id: id.clone(),
                publication_event_id: publication_id.clone(),
                expected_status_event_seq: published.status_event_seq,
            },
        )
        .await
        .unwrap();
        assert_eq!(deprecated.status, "deprecated");
        assert!(
            recipe_release_for_new_series(&db, principal, &id, &publication_id)
                .await
                .is_err()
        );
        assert!(
            recipe_release_for_execution(&db, principal, &id, &publication_id)
                .await
                .is_ok()
        );
        let mut execution_tx = begin_write(db.write_pool()).await.unwrap();
        let fenced = require_recipe_release_for_execution_on(
            &mut execution_tx,
            principal,
            &id,
            &publication_id,
            deprecated.status_event_seq,
        )
        .await
        .unwrap();
        assert_eq!(fenced.status, "deprecated");
        execution_tx.rollback().await.unwrap();

        let withdrawn = withdraw_recipe_release(
            &db,
            principal,
            ChangeRecipeReleaseStatus {
                program_id: id.clone(),
                publication_event_id: publication_id.clone(),
                expected_status_event_seq: deprecated.status_event_seq,
            },
        )
        .await
        .unwrap();
        assert_eq!(withdrawn.status, "withdrawn");
        assert!(
            recipe_release_for_execution(&db, principal, &id, &publication_id)
                .await
                .is_err()
        );
        assert_eq!(
            inspect_recipe_release(&db, principal, &id, &publication_id)
                .await
                .unwrap()
                .status,
            "withdrawn"
        );
    }

    #[tokio::test]
    async fn controlled_derivation_acquire_fences_recipe_and_pinned_digest_atomically() {
        use crate::derivation::{
            acquire_request_for_controlled_execution, append_derivation_event_in,
            create_or_join_request, AcquireRequestResult, CanonicalDerivationRequest,
            CreateOrJoinRequest, DerivationEventPayload, DerivationRequestSpec,
            DerivationRequestState, DerivationSeriesCreated, EffectiveSourceBoundary,
            NewDerivationEvent, RecipeRevisionRef,
        };

        let (db, program_id, source_event, source_sha, definition) = fixture().await;
        let principal = Principal::bound("acct:publisher", true);
        let published = publish_recipe_release(
            &db,
            principal,
            publish_input(&program_id, &source_event, &source_sha, definition),
        )
        .await
        .unwrap();
        let mut series_tx = begin_write(db.write_pool()).await.unwrap();
        append_derivation_event_in(
            &mut series_tx,
            NewDerivationEvent::authored(
                "controlled-acquire-series",
                "acct:publisher",
                None,
                "define controlled execution series",
                DerivationEventPayload::SeriesCreated(DerivationSeriesCreated {
                    id: "series:controlled-acquire".into(),
                    series_key: "controlled-acquire".into(),
                    definition: json!({"recipe":"controlled"}),
                }),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        series_tx.commit().await.unwrap();

        let request_spec = |digest: String, audience: char| DerivationRequestSpec {
            series_id: "series:controlled-acquire".into(),
            definition_sha256: crate::derivation::digest_json(&json!({"recipe":"controlled"})),
            canonical_request: CanonicalDerivationRequest {
                query_contract: "native.test.v1".into(),
                query_contract_version: 1,
                selection: json!({}),
                scope: json!({}),
            },
            recipe_revision: RecipeRevisionRef {
                definition_id: program_id.clone(),
                publication_id: published.descriptor.publication_event_id.clone(),
                sha256: digest,
            },
            effective_source_boundary: EffectiveSourceBoundary {
                after_seq: None,
                through_seq: 0,
                resolved_scope_membership_sha256: "2".repeat(64),
                metadata: json!({}),
            },
            target_basis: json!({}),
            budget: json!({}),
            audience_policy: None,
            audience_sha256: audience.to_string().repeat(64),
        };
        let valid = create_or_join_request(
            &db,
            request_spec(published.descriptor_sha256.clone(), '3'),
            CreateOrJoinRequest {
                requested_by: "acct:publisher".into(),
                requested_run_key: None,
            },
        )
        .await
        .unwrap()
        .request;
        let result = acquire_request_for_controlled_execution(
            &db,
            principal,
            &valid.id,
            "worker:controlled",
            None,
            published.status_event_seq,
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert!(matches!(result, AcquireRequestResult::Acquired(_)));

        let mismatched = create_or_join_request(
            &db,
            request_spec("f".repeat(64), '4'),
            CreateOrJoinRequest {
                requested_by: "acct:publisher".into(),
                requested_run_key: None,
            },
        )
        .await
        .unwrap()
        .request;
        let error = acquire_request_for_controlled_execution(
            &db,
            principal,
            &mismatched.id,
            "worker:controlled",
            None,
            published.status_event_seq,
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("digest does not match"));
        assert_eq!(
            crate::derivation::inspect_request(&db, &mismatched.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            DerivationRequestState::Pending
        );
    }

    #[tokio::test]
    async fn public_inspection_does_not_disclose_missing_vs_unauthorized() {
        let (db, id, _, _, _) = fixture().await;
        let publication_id = Uuid::new_v4().to_string();
        let missing = inspect_recipe_release(
            &db,
            Principal::bound("acct:publisher", true),
            &id,
            &publication_id,
        )
        .await
        .unwrap_err();
        let unauthorized = inspect_recipe_release(
            &db,
            Principal::bound("acct:other", true),
            &id,
            &publication_id,
        )
        .await
        .unwrap_err();
        assert_eq!(missing.to_string(), RECIPE_UNAVAILABLE);
        assert_eq!(unauthorized.to_string(), missing.to_string());
    }
}
