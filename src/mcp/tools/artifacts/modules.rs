//! Immutable MDX module publication, release closure, and lifecycle governance.

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub(super) enum ManageMdxModulesArgs {
    Publish {
        module_id: String,
        expected_source_event_id: String,
        expected_source_sha256: String,
    },
    Inspect {
        module_id: String,
        publication_event_id: Option<String>,
    },
    Impact {
        module_id: String,
        publication_event_id: Option<String>,
    },
    Deprecate {
        module_id: String,
        publication_event_id: String,
        expected_status_event_seq: i64,
        replacement: Option<String>,
    },
    Withdraw {
        module_id: String,
        publication_event_id: String,
        expected_status_event_seq: i64,
    },
}

#[derive(Clone)]
pub(super) struct ReleaseMaterial {
    pub(super) address: mdx_v2::ModuleAddress,
    pub(super) source_event_id: String,
    pub(super) release_sha256: String,
    pub(super) dependency_closure_sha256: String,
    pub(super) descriptor: Value,
    pub(super) source: String,
    pub(super) parsed: mdx_v2::ParsedSource,
    pub(super) cache_state: &'static str,
}

pub(super) fn release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": mdx_v2::ADAPTER_REVISION,
        "compiler_lock_sha256": mdx::sha256_hex(include_bytes!("../../../../Cargo.lock")),
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": mdx::V2_COMPONENT_POLICY,
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) const V2_REVISION_4_COMPILER_LOCK_SHA256: &str =
    "972f1fbaab31c6b514c3b4b3158e39024c14b5468cbb8ad282a8b80b8d36ae25";
pub(super) const V2_REVISION_7_COMPILER_LOCK_SHA256: &str =
    "e40b7480cde958eb8dec82cbb36e49db58d167d7c5c114149a26c0c6b5113975";
pub(super) const V2_REVISION_8_COMPILER_LOCK_SHA256: &str =
    "e40b7480cde958eb8dec82cbb36e49db58d167d7c5c114149a26c0c6b5113975";
pub(super) const V2_REVISION_9_COMPILER_LOCK_SHA256: &str =
    "7ef902d8fdde4245b02d1b0bb885e10e316dae5914c4fdf568093a52377d609a";

pub(super) fn revision_four_release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": 4,
        "compiler_lock_sha256": V2_REVISION_4_COMPILER_LOCK_SHA256,
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": "native.mdx.components@1",
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) fn revision_five_release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": 5,
        "compiler_lock_sha256": V2_REVISION_4_COMPILER_LOCK_SHA256,
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": "native.mdx.components@2",
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) fn revision_six_release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": 6,
        "compiler_lock_sha256": V2_REVISION_4_COMPILER_LOCK_SHA256,
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": "native.mdx.components@2",
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) fn revision_seven_release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": 7,
        "compiler_lock_sha256": V2_REVISION_7_COMPILER_LOCK_SHA256,
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": "native.mdx.components@3",
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) fn revision_eight_release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": 8,
        "compiler_lock_sha256": V2_REVISION_8_COMPILER_LOCK_SHA256,
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": "native.mdx.components@3",
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) fn revision_nine_release_runtime_contract() -> Value {
    json!({
        "id": mdx_v2::RUNTIME_ID,
        "adapter_revision": 9,
        "compiler_lock_sha256": V2_REVISION_9_COMPILER_LOCK_SHA256,
        "compile_profile": "native.mdx.compile.v2",
        "component_policy": "native.mdx.components@3",
        "input_abi": mdx_v2::NAMED_INPUT_ABI,
        "module_abi": mdx_v2::MODULE_SCHEMA,
        "output_abi": mdx::SAFE_TREE_VERSION,
    })
}

pub(super) fn supported_release_runtime_contract(contract: &Value) -> bool {
    contract == &release_runtime_contract()
        || contract == &revision_nine_release_runtime_contract()
        || contract == &revision_eight_release_runtime_contract()
        || contract == &revision_seven_release_runtime_contract()
        || contract == &revision_six_release_runtime_contract()
        || contract == &revision_five_release_runtime_contract()
        || contract == &revision_four_release_runtime_contract()
}

pub(super) fn supported_release_input_surface(runtime: &Value, inputs: &Value) -> bool {
    if !supported_release_runtime_contract(runtime) {
        return false;
    }
    let current = runtime == &release_runtime_contract();
    let revision_nine = runtime == &revision_nine_release_runtime_contract();
    let revision_eight = runtime == &revision_eight_release_runtime_contract();
    let revision_seven = runtime == &revision_seven_release_runtime_contract();
    let revision_six = runtime == &revision_six_release_runtime_contract();
    let revision_five = runtime == &revision_five_release_runtime_contract();
    debug_assert!(
        current
            || revision_nine
            || revision_eight
            || revision_seven
            || revision_six
            || revision_five
            || runtime == &revision_four_release_runtime_contract()
    );
    inputs.as_object().is_some_and(|inputs| {
        inputs.values().all(|declaration| {
            let Some(object) = declaration.as_object() else {
                return false;
            };
            if !object.contains_key("envelope")
                || !object.contains_key("required")
                || object.keys().any(|key| {
                    !(matches!(key.as_str(), "envelope" | "required" | "expose_to_root")
                        || (current
                            || revision_nine
                            || revision_eight
                            || revision_seven
                            || revision_six
                            || revision_five)
                            && key == "projection"
                        || (current || revision_nine) && key == "schema_sha256"
                        || current && key == "relations")
                })
            {
                return false;
            }
            serde_json::from_value::<mdx_v2::InputDecl>(declaration.clone()).is_ok_and(|input| {
                let supported = if current {
                    mdx_v2::input_decl_is_supported(&input)
                } else if revision_nine {
                    input.relations.is_empty() && mdx_v2::input_decl_is_supported(&input)
                } else if revision_eight {
                    input.schema_sha256.is_none() && mdx_v2::input_decl_is_supported(&input)
                } else if revision_seven || revision_six {
                    input.envelope != mdx_v2::RELATION_ENVELOPE
                        && mdx_v2::input_decl_is_supported(&input)
                } else if revision_five {
                    match input.projection.as_ref() {
                        None => input.envelope == mdx_v2::COLLECTION_ENVELOPE,
                        Some(mdx_v2::InputProjection::GroupedCount { axis }) => {
                            input.envelope == mdx_v2::GROUPED_COUNT_ENVELOPE
                                && matches!(axis, mdx_v2::GroupedCountAxis::RecordField { .. })
                        }
                    }
                } else {
                    input.envelope == mdx_v2::COLLECTION_ENVELOPE && input.projection.is_none()
                };
                supported && json!(input) == *declaration
            })
        })
    })
}

pub(super) fn normalized_release_imports(parsed: &mdx_v2::ParsedSource) -> Value {
    Value::Array(
        parsed
            .imports
            .iter()
            .map(|import| {
                let input_map = import
                    .names
                    .iter()
                    .filter_map(|name| {
                        parsed
                            .manifest
                            .module_inputs()
                            .get(&name.local)
                            .map(|mapping| (name.local.clone(), json!(mapping)))
                    })
                    .collect::<Map<_, _>>();
                json!({
                    "specifier": import.specifier,
                    "module_record_id": import.address.module_record_id,
                    "publication_event_id": import.address.publication_event_id,
                    "source_sha256": import.address.source_sha256,
                    "names": import.names,
                    "input_map": input_map,
                    "source_range": import.source_range,
                })
            })
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_release_descriptor(
    publication_event_id: &str,
    module_record_id: &str,
    source_event_id: &str,
    source: &str,
    parsed: &mdx_v2::ParsedSource,
    descriptor: &Value,
    release_sha256: &str,
    dependency_closure_sha256: &str,
) -> std::result::Result<(), mdx::Failure> {
    let manifest = match &parsed.manifest {
        mdx_v2::Manifest::Module(manifest) => manifest,
        _ => {
            return Err(mdx::Failure::new(
                "module_descriptor_invalid",
                "verify",
                "release source is not a module manifest",
            ))
        }
    };
    let object = descriptor.as_object().ok_or_else(|| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "release descriptor must be an object",
        )
    })?;
    let exact_keys = [
        "schema",
        "publication_event_id",
        "module_record_id",
        "source_event_id",
        "source_sha256",
        "runtime",
        "inputs",
        "exports",
        "imports",
        "capability_requests",
        "closure_capability_summary",
        "dependency_closure_sha256",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != exact_keys
        || descriptor["schema"] != mdx_v2::RELEASE_SCHEMA
        || descriptor["publication_event_id"] != publication_event_id
        || descriptor["module_record_id"] != module_record_id
        || descriptor["source_event_id"] != source_event_id
        || descriptor["source_sha256"] != parsed.source_sha256
        || !supported_release_input_surface(&descriptor["runtime"], &descriptor["inputs"])
        || descriptor["inputs"] != json!(manifest.inputs)
        || descriptor["imports"] != normalized_release_imports(parsed)
        || descriptor["capability_requests"] != json!(manifest.capability_requests)
        || descriptor["dependency_closure_sha256"] != dependency_closure_sha256
        || parsed.source_sha256 != mdx::sha256_hex(source.as_bytes())
        || !publication_event_id
            .parse::<uuid::Uuid>()
            .is_ok_and(|id| id.hyphenated().to_string() == publication_event_id)
        || !source_event_id
            .parse::<uuid::Uuid>()
            .is_ok_and(|id| id.hyphenated().to_string() == source_event_id)
    {
        return Err(mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "release descriptor does not exactly match reparsed authoritative source bytes",
        ));
    }
    let expected_exports = manifest
        .exports
        .iter()
        .map(|(name, interface)| {
            json!({
                "name": name, "kind": interface.kind, "interface": interface,
            })
        })
        .collect::<Vec<_>>();
    if descriptor["exports"] != json!(expected_exports)
        || mdx::sha256_hex(&mdx_v2::canonical_json_bytes(descriptor)) != release_sha256
    {
        return Err(mdx::Failure::new(
            "module_digest_mismatch",
            "verify",
            "release descriptor content or digest does not verify",
        ));
    }
    Ok(())
}

pub(super) async fn load_release_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    address: &mdx_v2::ModuleAddress,
    cache_partition: &str,
) -> std::result::Result<ReleaseMaterial, mdx::Failure> {
    let row = sqlx::query(
        "SELECT r.source_event_id,r.release_sha256,r.dependency_closure_sha256,r.descriptor,r.status,
                r.local_event_seq,e.seq AS source_event_seq,e.type AS source_event_type,
                e.record_id AS source_record_id,json_extract(e.payload,'$.body') AS source,
                rec.type AS record_type,rec.kind AS record_kind,rec.deleted_at,
                runtime.value AS runtime
           FROM module_releases r
           LEFT JOIN content_events e ON e.id=r.source_event_id
           LEFT JOIN records rec ON rec.id=r.module_record_id
           LEFT JOIN facet_values runtime ON runtime.record_id=rec.id AND runtime.key='runtime'
          WHERE r.publication_event_id=? AND r.module_record_id=?",
    )
    .bind(&address.publication_event_id)
    .bind(&address.module_record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| {
        mdx::Failure::new(
            "module_release_missing",
            "resolve",
            "module release lookup failed",
        )
    })?
    .ok_or_else(|| {
        mdx::Failure::new(
            "module_release_missing",
            "resolve",
            "the exact module publication does not exist",
        )
        .detail("publication_event_id", address.publication_event_id.clone())
    })?;
    let status: String = row.try_get("status").map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "resolve",
            "module release status is invalid",
        )
    })?;
    if status == "withdrawn" {
        return Err(mdx::Failure::new(
            "module_release_withdrawn",
            "resolve",
            "the exact module release is withdrawn",
        )
        .detail("publication_event_id", address.publication_event_id.clone()));
    }
    let source: Option<String> = row.try_get("source").map_err(|_| {
        mdx::Failure::new(
            "module_release_missing",
            "resolve",
            "module source event is invalid",
        )
    })?;
    let source = source.ok_or_else(|| {
        mdx::Failure::new(
            "module_release_unpublished",
            "resolve",
            "the release's portable source event is unavailable",
        )
    })?;
    let source_event_id: String = row.try_get("source_event_id").map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "source event id is invalid",
        )
    })?;
    let source_event_seq: i64 = row.try_get("source_event_seq").map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "source event is missing",
        )
    })?;
    let local_event_seq: i64 = row.try_get("local_event_seq").map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "publication order is invalid",
        )
    })?;
    let invalid_identity = || {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "release identity projection is missing or malformed",
        )
    };
    let source_event_type: String = row
        .try_get("source_event_type")
        .map_err(|_| invalid_identity())?;
    let source_record_id: String = row
        .try_get("source_record_id")
        .map_err(|_| invalid_identity())?;
    let record_type: String = row.try_get("record_type").map_err(|_| invalid_identity())?;
    let record_kind: String = row.try_get("record_kind").map_err(|_| invalid_identity())?;
    let runtime: String = row.try_get("runtime").map_err(|_| invalid_identity())?;
    let deleted_at: Option<String> = row.try_get("deleted_at").map_err(|_| invalid_identity())?;
    if !matches!(
        source_event_type.as_str(),
        "record.created" | "record.updated" | "receipt.committed.v1"
    ) || source_record_id != address.module_record_id
        || source_event_seq >= local_event_seq
    {
        return Err(mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "release identity or source event ordering is invalid",
        ));
    }
    let _live_identity_is_checked_by_consumption_authority =
        (record_type, record_kind, runtime, deleted_at);
    let actual_source_sha = mdx::sha256_hex(source.as_bytes());
    if actual_source_sha != address.source_sha256 {
        return Err(mdx::Failure::new(
            "module_digest_mismatch",
            "resolve",
            "module source digest does not match the exact import",
        )
        .detail("expected", address.source_sha256.clone())
        .detail("actual", actual_source_sha));
    }
    let descriptor_text: String = row.try_get("descriptor").map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "resolve",
            "module descriptor is invalid",
        )
    })?;
    let descriptor: Value = serde_json::from_str(&descriptor_text).map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "resolve",
            "module descriptor is not JSON",
        )
    })?;
    let release_sha256: String = row.try_get("release_sha256").map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "resolve",
            "module release digest is invalid",
        )
    })?;
    if mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&descriptor)) != release_sha256 {
        return Err(mdx::Failure::new(
            "module_digest_mismatch",
            "resolve",
            "module release descriptor digest does not verify",
        ));
    }
    let parse_source = source.clone();
    let parse_partition = cache_partition.to_owned();
    let (parsed, cache_state) = tokio::task::spawn_blocking(move || {
        mdx_v2::parse_module_cached(&parse_source, &parse_partition)
    })
    .await
    .map_err(|_| {
        mdx::Failure::new(
            "mdx_runtime_failed",
            "compile",
            "module compiler worker terminated unexpectedly",
        )
    })??;
    let dependency_closure_sha256: String =
        row.try_get("dependency_closure_sha256").map_err(|_| {
            mdx::Failure::new(
                "module_descriptor_invalid",
                "verify",
                "closure digest is invalid",
            )
        })?;
    verify_release_descriptor(
        &address.publication_event_id,
        &address.module_record_id,
        &source_event_id,
        &source,
        &parsed,
        &descriptor,
        &release_sha256,
        &dependency_closure_sha256,
    )?;
    let projected_imports = sqlx::query(
        "SELECT specifier,dependency_module_record_id,dependency_publication_event_id,
                dependency_source_sha256,names,source_range,input_map
           FROM module_release_imports WHERE consumer_publication_event_id=? ORDER BY ordinal",
    )
    .bind(&address.publication_event_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| {
        mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "release dependency edge projection could not be read",
        )
    })?;
    let projected_imports = projected_imports
        .into_iter()
        .map(|row| {
            let parse = |column: &str| -> std::result::Result<Value, mdx::Failure> {
                let text: String = row.try_get(column).map_err(|_| {
                    mdx::Failure::new(
                        "module_descriptor_invalid",
                        "verify",
                        "release dependency edge projection is malformed",
                    )
                })?;
                serde_json::from_str(&text).map_err(|_| {
                    mdx::Failure::new(
                        "module_descriptor_invalid",
                        "verify",
                        "release dependency edge JSON is malformed",
                    )
                })
            };
            Ok(json!({
                "specifier": row.try_get::<String,_>("specifier").map_err(|_| mdx::Failure::new("module_descriptor_invalid", "verify", "release specifier is malformed"))?,
                "module_record_id": row.try_get::<String,_>("dependency_module_record_id").map_err(|_| mdx::Failure::new("module_descriptor_invalid", "verify", "dependency module id is malformed"))?,
                "publication_event_id": row.try_get::<String,_>("dependency_publication_event_id").map_err(|_| mdx::Failure::new("module_descriptor_invalid", "verify", "dependency publication id is malformed"))?,
                "source_sha256": row.try_get::<String,_>("dependency_source_sha256").map_err(|_| mdx::Failure::new("module_descriptor_invalid", "verify", "dependency digest is malformed"))?,
                "names": parse("names")?, "source_range": parse("source_range")?, "input_map": parse("input_map")?,
            }))
        })
        .collect::<std::result::Result<Vec<_>, mdx::Failure>>()?;
    if json!(projected_imports) != normalized_release_imports(&parsed) {
        return Err(mdx::Failure::new(
            "module_descriptor_invalid",
            "verify",
            "projected dependency edges do not match reparsed exact source bytes",
        ));
    }
    Ok(ReleaseMaterial {
        address: address.clone(),
        source_event_id,
        release_sha256,
        dependency_closure_sha256,
        descriptor,
        source,
        parsed,
        cache_state,
    })
}

pub(super) async fn authorize_module_consumption_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> std::result::Result<(), mdx::Failure> {
    if caller.hosting_principal().is_some() != caller.hosting_database().is_some() {
        return Err(mdx::Failure::new(
            "module_consumption_denied",
            "authorize",
            "hosted module consumption requires a consistent principal and selected database",
        ));
    }
    let root_allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records r
           JOIN facet_values f ON f.record_id=r.id AND f.key='runtime'
           JOIN content_events e ON e.id=? AND e.record_id=r.id
          WHERE r.id=? AND r.deleted_at IS NULL AND r.type='Document' AND r.kind='artifact'
            AND f.value=? AND e.type IN ('record.created','record.updated','receipt.committed.v1'))",
    )
    .bind(source_event_id)
    .bind(artifact_id)
    .bind(mdx_v2::RUNTIME_ID)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| {
        mdx::Failure::new(
            "module_consumption_denied",
            "authorize",
            "artifact consumption authority could not be verified",
        )
    })?;
    if !root_allowed {
        return Err(mdx::Failure::new(
            "module_consumption_denied",
            "authorize",
            "the root artifact is not visible as a live native.mdx.v2 artifact in this database snapshot",
        )
        .detail("artifact_id", artifact_id.to_owned()));
    }
    for release in releases.values() {
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records r
               JOIN facet_values f ON f.record_id=r.id AND f.key='runtime'
              WHERE r.id=? AND r.deleted_at IS NULL AND r.type='Program' AND r.kind='module'
                AND f.value=?)",
        )
        .bind(&release.address.module_record_id)
        .bind(mdx_v2::RUNTIME_ID)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| {
            mdx::Failure::new(
                "module_consumption_denied",
                "authorize",
                "module consumption authority could not be verified",
            )
        })?;
        if !allowed {
            return Err(mdx::Failure::new(
                "module_consumption_denied",
                "authorize",
                "an exact module is not visible as a live native.mdx.v2 module in this database snapshot",
            )
            .detail(
                "module_record_id",
                release.address.module_record_id.clone(),
            )
            .detail(
                "publication_event_id",
                release.address.publication_event_id.clone(),
            ));
        }
    }
    Ok(())
}

pub(super) async fn resolve_closure_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    root: &mdx_v2::ParsedSource,
    cache_partition: &str,
) -> std::result::Result<BTreeMap<String, ReleaseMaterial>, mdx::Failure> {
    let mut stack = root
        .imports
        .iter()
        .map(|import| {
            (
                import.address.clone(),
                1usize,
                vec![json!({
                    "importer": "$root", "specifier": import.specifier,
                    "source_range": import.source_range,
                })],
            )
        })
        .collect::<Vec<_>>();
    let mut releases = BTreeMap::new();
    let mut import_chains = BTreeMap::<String, Vec<Value>>::new();
    let mut versions = BTreeMap::<String, String>::new();
    let mut edges = root.imports.len();
    let mut source_bytes = root.source_bytes;
    let mut compiled_bytes = root.compiled.len();
    let mut public_exports = 0usize;
    while let Some((address, depth, import_chain)) = stack.pop() {
        if depth > mdx_v2::MAX_DEPTH {
            return Err(module_limit("dependency_depth", mdx_v2::MAX_DEPTH)
                .detail("import_chain", json!(import_chain)));
        }
        if let Some(existing) = versions.get(&address.module_record_id) {
            if existing != &address.publication_event_id {
                return Err(mdx::Failure::new(
                    "module_version_conflict",
                    "resolve",
                    "one closure contains multiple releases of one stable module",
                )
                .detail("module_record_id", address.module_record_id)
                .detail("import_chain", json!(import_chain)));
            }
        } else {
            versions.insert(
                address.module_record_id.clone(),
                address.publication_event_id.clone(),
            );
        }
        if releases.contains_key(&address.publication_event_id) {
            continue;
        }
        let release = load_release_in(tx, &address, cache_partition)
            .await
            .map_err(|failure| failure.detail("import_chain", json!(import_chain.clone())))?;
        source_bytes = source_bytes.saturating_add(release.source.len());
        compiled_bytes = compiled_bytes.saturating_add(release.parsed.compiled.len());
        public_exports = public_exports.saturating_add(match &release.parsed.manifest {
            mdx_v2::Manifest::Module(manifest) => manifest.exports.len(),
            _ => 0,
        });
        edges = edges.saturating_add(release.parsed.imports.len());
        if releases.len() + 1 > mdx_v2::MAX_MODULES {
            return Err(module_limit("dependency_modules", mdx_v2::MAX_MODULES)
                .detail("import_chain", json!(import_chain)));
        }
        if edges > mdx_v2::MAX_EDGES {
            return Err(module_limit("dependency_edges", mdx_v2::MAX_EDGES)
                .detail("import_chain", json!(import_chain)));
        }
        if source_bytes > mdx_v2::MAX_AGGREGATE_SOURCE {
            return Err(
                module_limit("aggregate_source_utf8_bytes", mdx_v2::MAX_AGGREGATE_SOURCE)
                    .detail("import_chain", json!(import_chain)),
            );
        }
        if compiled_bytes > mdx_v2::MAX_AGGREGATE_COMPILED {
            return Err(
                module_limit("compiled_js_bytes", mdx_v2::MAX_AGGREGATE_COMPILED)
                    .detail("import_chain", json!(import_chain)),
            );
        }
        if public_exports > mdx_v2::MAX_EXPORTS {
            return Err(module_limit("public_exports", mdx_v2::MAX_EXPORTS)
                .detail("import_chain", json!(import_chain)));
        }
        for import in &release.parsed.imports {
            let mut child_chain = import_chain.clone();
            child_chain.push(json!({
                "importer": release.address.publication_event_id,
                "specifier": import.specifier,
                "source_range": import.source_range,
            }));
            stack.push((import.address.clone(), depth + 1, child_chain));
        }
        import_chains.insert(address.publication_event_id.clone(), import_chain);
        releases.insert(address.publication_event_id.clone(), release);
    }
    detect_cycles(root, &releases)?;
    validate_import_interfaces(root, "$root", &[], &releases)?;
    for release in releases.values() {
        let chain = import_chains
            .get(&release.address.publication_event_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        validate_import_interfaces(
            &release.parsed,
            &release.address.publication_event_id,
            chain,
            &releases,
        )?;
        let subclosure = reachable_releases(&release.parsed, &releases)?;
        let actual_closure = closure_sha256(&release.parsed, &subclosure);
        if actual_closure != release.dependency_closure_sha256 {
            return Err(mdx::Failure::new(
                "module_digest_mismatch",
                "verify",
                "release dependency closure digest does not match exact dependency edges",
            )
            .detail(
                "publication_event_id",
                release.address.publication_event_id.clone(),
            ));
        }
        let mut expected_summary = subclosure
            .values()
            .map(|dependency| {
                json!({
                    "module_record_id": dependency.address.module_record_id,
                    "publication_event_id": dependency.address.publication_event_id,
                    "requests": dependency.parsed.manifest.capability_requests(),
                })
            })
            .collect::<Vec<_>>();
        expected_summary.push(json!({
            "module_record_id": release.address.module_record_id,
            "publication_event_id": release.address.publication_event_id,
            "requests": release.parsed.manifest.capability_requests(),
        }));
        expected_summary.sort_by_key(|value| {
            value["publication_event_id"]
                .as_str()
                .unwrap_or("")
                .to_owned()
        });
        if release.descriptor["closure_capability_summary"] != json!(expected_summary) {
            return Err(mdx::Failure::new(
                "module_descriptor_invalid",
                "verify",
                "release capability summary does not match its exact verified closure",
            ));
        }
    }
    Ok(releases)
}

pub(super) fn reachable_releases(
    root: &mdx_v2::ParsedSource,
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> std::result::Result<BTreeMap<String, ReleaseMaterial>, mdx::Failure> {
    let mut pending = root
        .imports
        .iter()
        .map(|import| import.address.publication_event_id.clone())
        .collect::<Vec<_>>();
    let mut reachable = BTreeMap::new();
    while let Some(id) = pending.pop() {
        if reachable.contains_key(&id) {
            continue;
        }
        let release = releases.get(&id).ok_or_else(|| {
            mdx::Failure::new(
                "module_release_missing",
                "verify",
                "release closure is incomplete",
            )
            .detail("publication_event_id", id.clone())
        })?;
        pending.extend(
            release
                .parsed
                .imports
                .iter()
                .map(|import| import.address.publication_event_id.clone()),
        );
        reachable.insert(id, release.clone());
    }
    Ok(reachable)
}

pub(super) fn module_limit(limit: &'static str, maximum: usize) -> mdx::Failure {
    mdx::Failure::new(
        "module_closure_limit",
        "resolve",
        "the verified dependency closure exceeds a runtime limit",
    )
    .detail("limit", limit)
    .detail("maximum", maximum as u64)
}

pub(super) fn detect_cycles(
    root: &mdx_v2::ParsedSource,
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> std::result::Result<(), mdx::Failure> {
    fn visit(
        id: &str,
        releases: &BTreeMap<String, ReleaseMaterial>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
        import_chain: Vec<Value>,
    ) -> std::result::Result<(), mdx::Failure> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.to_owned()) {
            return Err(mdx::Failure::new(
                "module_cycle",
                "resolve",
                "the exact module dependency graph contains a cycle",
            )
            .detail("publication_event_id", id.to_owned())
            .detail("import_chain", json!(import_chain)));
        }
        let release = releases.get(id).ok_or_else(|| {
            mdx::Failure::new(
                "module_release_missing",
                "resolve",
                "closure node is missing",
            )
        })?;
        for import in &release.parsed.imports {
            let mut child_chain = import_chain.clone();
            child_chain.push(json!({
                "importer": release.address.publication_event_id,
                "specifier": import.specifier,
                "source_range": import.source_range,
            }));
            visit(
                &import.address.publication_event_id,
                releases,
                visiting,
                visited,
                child_chain,
            )?;
        }
        visiting.remove(id);
        visited.insert(id.to_owned());
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for import in &root.imports {
        let import_chain = vec![json!({
            "importer": "$root",
            "specifier": import.specifier,
            "source_range": import.source_range,
        })];
        visit(
            &import.address.publication_event_id,
            releases,
            &mut visiting,
            &mut visited,
            import_chain,
        )?;
    }
    Ok(())
}

pub(super) fn validate_import_interfaces(
    parent: &mdx_v2::ParsedSource,
    parent_origin: &str,
    parent_chain: &[Value],
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> std::result::Result<(), mdx::Failure> {
    for import in &parent.imports {
        let mut import_chain = parent_chain.to_vec();
        import_chain.push(json!({
            "importer": parent_origin,
            "specifier": import.specifier,
            "source_range": import.source_range,
        }));
        let checked = (|| -> std::result::Result<(), mdx::Failure> {
            let child = releases
                .get(&import.address.publication_event_id)
                .ok_or_else(|| {
                    mdx::Failure::new("module_release_missing", "resolve", "closure node missing")
                })?;
            let mdx_v2::Manifest::Module(child_manifest) = &child.parsed.manifest else {
                return Err(mdx::Failure::new(
                    "module_descriptor_invalid",
                    "resolve",
                    "dependency is not a module manifest",
                ));
            };
            let mut mapped_child_ports = BTreeSet::new();
            for name in &import.names {
                let interface = child_manifest.exports.get(&name.exported).ok_or_else(|| {
                    mdx::Failure::new(
                        "module_export_missing",
                        "resolve",
                        format!("release does not export '{}'", name.exported),
                    )
                })?;
                let mapping = parent.manifest.module_inputs().get(&name.local);
                if let Some(mapping) = mapping {
                    for child_port in mapping.ports.keys() {
                        if !interface.uses_inputs.contains(child_port)
                            || !mapped_child_ports.insert(child_port.clone())
                        {
                            return Err(mdx::Failure::new(
                            "named_input_incompatible",
                            "preflight",
                            format!(
                                "import '{}' maps an undeclared, unused, or duplicate child port '{child_port}'",
                                name.local
                            ),
                        )
                        .detail("publication_event_id", import.address.publication_event_id.clone())
                        .detail("export", name.exported.clone())
                        .detail("module_port", child_port.clone()));
                        }
                        let requested = child_manifest.capability_requests.iter().any(|request| {
                            request.capability == "input.read"
                                && request.scope.get("port").and_then(Value::as_str)
                                    == Some(child_port.as_str())
                        });
                        if !requested {
                            return Err(mdx::Failure::new(
                                "module_capability_denied",
                                "preflight",
                                "an input mapping cannot create an input.read request",
                            )
                            .detail(
                                "publication_event_id",
                                import.address.publication_event_id.clone(),
                            )
                            .detail("export", name.exported.clone())
                            .detail("module_port", child_port.clone()));
                        }
                    }
                }
                let required = interface
                    .uses_inputs
                    .iter()
                    .filter(|port| {
                        child_manifest
                            .inputs
                            .get(*port)
                            .is_some_and(|input| input.required)
                    })
                    .collect::<BTreeSet<_>>();
                if !required.is_empty() {
                    let mapping = mapping.ok_or_else(|| {
                        mdx::Failure::new(
                            "named_input_missing",
                            "preflight",
                            format!("import '{}' is missing required input mappings", name.local),
                        )
                    })?;
                    if required
                        .iter()
                        .any(|port| !mapping.ports.contains_key(*port))
                    {
                        return Err(mdx::Failure::new(
                            "named_input_incompatible",
                            "preflight",
                            format!("import '{}' has an incomplete input mapping", name.local),
                        ));
                    }
                }
            }
            Ok(())
        })();
        checked.map_err(|failure| failure.detail("import_chain", json!(import_chain)))?;
    }
    Ok(())
}

pub(super) fn closure_sha256(
    root: &mdx_v2::ParsedSource,
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> String {
    let nodes = releases
        .values()
        .map(|release| {
            json!({
                "module_record_id": release.address.module_record_id,
                "publication_event_id": release.address.publication_event_id,
                "source_sha256": release.address.source_sha256,
                "release_sha256": release.release_sha256,
            })
        })
        .collect::<Vec<_>>();
    let mut edges = Vec::new();
    for (importer, parsed) in
        std::iter::once(("$root", root)).chain(releases.values().map(|release| {
            (
                release.address.publication_event_id.as_str(),
                &release.parsed,
            )
        }))
    {
        for import in &parsed.imports {
            edges.push(json!({
                "importer": importer, "specifier": import.specifier,
                "source_range": import.source_range, "names": import.names,
            }));
        }
    }
    edges.sort_by_key(|edge| {
        String::from_utf8_lossy(&mdx_v2::canonical_json_bytes(edge)).to_string()
    });
    let payload = json!({
        "namespace": "native.module-dependency-closure.v1",
        "nodes": nodes,
        "edges": edges,
    });
    mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&payload))
}

pub(super) fn runtime_import_edge(importer: &str, import: &mdx_v2::ImportRef) -> Value {
    json!({
        "importer": importer,
        "specifier": import.specifier,
        "source_range": import.source_range,
        "module_record_id": import.address.module_record_id,
        "publication_event_id": import.address.publication_event_id,
        "source_sha256": import.address.source_sha256,
    })
}

pub(super) fn runtime_edge_catalog(
    root: &mdx_v2::ParsedSource,
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> BTreeMap<String, Value> {
    let mut catalog = BTreeMap::new();
    for import in &root.imports {
        catalog.insert(
            mdx_v2::runtime_edge_key("$root", import),
            runtime_import_edge("$root", import),
        );
    }
    for release in releases.values() {
        for import in &release.parsed.imports {
            catalog.insert(
                mdx_v2::runtime_edge_key(&release.address.publication_event_id, import),
                runtime_import_edge(&release.address.publication_event_id, import),
            );
        }
    }
    catalog
}

pub(super) fn canonical_runtime_import_chain(
    root: &mdx_v2::ParsedSource,
    releases: &BTreeMap<String, ReleaseMaterial>,
    target: &str,
) -> Option<Vec<Value>> {
    fn visit(
        parsed: &mdx_v2::ParsedSource,
        importer: &str,
        target: &str,
        releases: &BTreeMap<String, ReleaseMaterial>,
        visited: &mut BTreeSet<String>,
        path: &mut Vec<Value>,
    ) -> bool {
        for import in &parsed.imports {
            path.push(runtime_import_edge(importer, import));
            if import.address.publication_event_id == target {
                return true;
            }
            if visited.insert(import.address.publication_event_id.clone()) {
                if let Some(child) = releases.get(&import.address.publication_event_id) {
                    if visit(
                        &child.parsed,
                        &child.address.publication_event_id,
                        target,
                        releases,
                        visited,
                        path,
                    ) {
                        return true;
                    }
                }
            }
            path.pop();
        }
        false
    }

    let mut path = Vec::new();
    let mut visited = BTreeSet::new();
    visit(root, "$root", target, releases, &mut visited, &mut path).then_some(path)
}

pub(super) fn attribute_runtime_failure(
    mut failure: mdx::Failure,
    root: &mdx_v2::ParsedSource,
    releases: &BTreeMap<String, ReleaseMaterial>,
) -> mdx::Failure {
    let Some(details) = failure.details.as_object_mut() else {
        return failure;
    };
    let Some(origin_key) = details
        .remove("runtime_origin_key")
        .and_then(|value| value.as_str().map(str::to_owned))
    else {
        details.remove("runtime_import_chain_keys");
        return failure;
    };
    let Some(release) = releases.get(&origin_key) else {
        details.remove("runtime_import_chain_keys");
        return failure;
    };
    let catalog = runtime_edge_catalog(root, releases);
    let supplied_chain = details
        .remove("runtime_import_chain_keys")
        .and_then(|value| value.as_array().cloned())
        .and_then(|keys| {
            keys.into_iter()
                .map(|key| key.as_str().and_then(|key| catalog.get(key)).cloned())
                .collect::<Option<Vec<_>>>()
        })
        .filter(|chain| {
            chain.first().and_then(|edge| edge["importer"].as_str()) == Some("$root")
                && chain
                    .last()
                    .and_then(|edge| edge["publication_event_id"].as_str())
                    == Some(origin_key.as_str())
        });
    let import_chain =
        supplied_chain.or_else(|| canonical_runtime_import_chain(root, releases, &origin_key));
    let export = details
        .get("export")
        .and_then(Value::as_str)
        .unwrap_or("$module")
        .to_owned();
    let source_range = release
        .parsed
        .export_ranges
        .get(&export)
        .cloned()
        .unwrap_or_else(|| {
            let end_line = release.source.bytes().filter(|byte| *byte == b'\n').count() + 1;
            let end_column = release
                .source
                .rsplit_once('\n')
                .map_or(release.source.as_str(), |(_, tail)| tail)
                .chars()
                .count()
                + 1;
            json!({
                "source": "authored_mdx",
                "start": { "line": 1, "column": 1, "offset": 0 },
                "end": { "line": end_line, "column": end_column, "offset": release.source.len() },
            })
        });
    details.insert(
        "origin".into(),
        json!({
            "module_record_id": release.address.module_record_id,
            "publication_event_id": release.address.publication_event_id,
            "source_event_id": release.source_event_id,
            "source_sha256": release.address.source_sha256,
            "release_sha256": release.release_sha256,
            "dependency_closure_sha256": release.dependency_closure_sha256,
            "export": export.clone(),
            "source_range": source_range.clone(),
        }),
    );
    details.insert("export".into(), json!(export));
    details.insert("source_range".into(), source_range);
    if let Some(import_chain) = import_chain {
        details.insert("import_chain".into(), json!(import_chain));
    }
    failure
}

pub(super) async fn latest_body_source_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<(String, String)> {
    let row = sqlx::query(
        "SELECT e.id,json_extract(e.payload,'$.body') AS body
           FROM content_events e
          WHERE e.record_id=? AND e.type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(e.payload,'$.body') IS NOT NULL
          ORDER BY e.seq DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("module has no authoritative body source event"))?;
    Ok((row.try_get("id")?, row.try_get("body")?))
}

pub(super) async fn manage_mdx_modules(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_mdx_modules";
    match parse_args::<ManageMdxModulesArgs>(TOOL, arguments)? {
        ManageMdxModulesArgs::Publish {
            module_id,
            expected_source_event_id,
            expected_source_sha256,
        } => {
            let _permit =
                mdx::try_admit().map_err(|failure| mdx_v2_engine_error(&module_id, failure))?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_record_in(&mut tx, &caller, TOOL, &module_id, Capability::Edit).await?;
            let predicate = identity_predicate("r", "Program", MODULE_KIND_VALUE_ID);
            let valid: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT 1 FROM records r JOIN facet_values f ON f.record_id=r.id AND f.key='runtime'
                  WHERE r.id=? AND r.deleted_at IS NULL AND f.value=? AND {predicate})"
            ))
            .bind(&module_id)
            .bind(mdx_v2::RUNTIME_ID)
            .fetch_one(&mut *tx)
            .await?;
            if !valid {
                return Err(Error::engine(format!(
                    "{TOOL}: {module_id} must be a live governed Program kind:module using native.mdx.v2"
                )));
            }
            let (source_event_id, source) = latest_body_source_in(&mut tx, &module_id).await?;
            let source_sha256 = mdx::sha256_hex(source.as_bytes());
            if source_event_id != expected_source_event_id
                || source_sha256 != expected_source_sha256
            {
                return Err(Error::engine(format!(
                    "{TOOL}: module source changed; expected exact source event/digest no longer matches"
                )));
            }
            let compile_source = source.clone();
            let parsed = tokio::task::spawn_blocking(move || mdx_v2::parse_module(&compile_source))
                .await
                .map_err(|_| {
                    Error::engine(
                        "manage_mdx_modules: module compiler worker terminated unexpectedly",
                    )
                })?
                .map_err(|failure| mdx_v2_engine_error(&module_id, failure))?;
            let closure = resolve_closure_in(
                &mut tx,
                &parsed,
                caller.hosting_principal().unwrap_or("local"),
            )
            .await
            .map_err(|failure| mdx_v2_engine_error(&module_id, failure))?;
            for release in closure.values() {
                require_record_in(
                    &mut tx,
                    &caller,
                    TOOL,
                    &release.address.module_record_id,
                    Capability::View,
                )
                .await?;
            }
            let publication_event_id = uuid::Uuid::new_v4().to_string();
            let dependency_closure_sha256 = closure_sha256(&parsed, &closure);
            let manifest = match &parsed.manifest {
                mdx_v2::Manifest::Module(value) => value,
                _ => unreachable!("module parser returns module manifest"),
            };
            let proof_ports = manifest
                .inputs
                .keys()
                .map(|port| (port.clone(), port.clone()))
                .collect::<BTreeMap<_, _>>();
            let proof_parsed = parsed.clone();
            let proof_closure = closure.clone();
            let proof_publication_event_id = publication_event_id.clone();
            let proof_compiled_bytes = tokio::task::spawn_blocking(move || {
                let mut proof = V2BuildOutput {
                    modules: HashMap::new(),
                    contexts: Map::new(),
                    instances: HashMap::new(),
                    compiled_bytes: proof_parsed.compiled.len(),
                };
                let linked_root = build_v2_instance(
                    &proof_parsed,
                    "native.mdx.v2/publication-proof",
                    &proof_publication_event_id,
                    &proof_ports,
                    &proof_closure,
                    &BTreeMap::new(),
                    &BTreeSet::new(),
                    false,
                    &mut proof,
                )?;
                Ok::<_, mdx::Failure>(
                    linked_root
                        .len()
                        .saturating_add(proof.modules.values().map(String::len).sum::<usize>()),
                )
            })
            .await
            .map_err(|_| {
                Error::engine("manage_mdx_modules: module linker worker terminated unexpectedly")
            })?
            .map_err(|failure| mdx_v2_engine_error(&module_id, failure))?;
            if proof_compiled_bytes > mdx_v2::MAX_AGGREGATE_COMPILED {
                return Err(mdx_v2_engine_error(
                    &module_id,
                    module_limit("compiled_js_bytes", mdx_v2::MAX_AGGREGATE_COMPILED),
                ));
            }
            let imports = normalized_release_imports(&parsed);
            let mut capability_summary = closure
                .values()
                .map(|release| {
                    json!({
                        "module_record_id": release.address.module_record_id,
                        "publication_event_id": release.address.publication_event_id,
                        "requests": release.parsed.manifest.capability_requests(),
                    })
                })
                .collect::<Vec<_>>();
            capability_summary.push(json!({
                "module_record_id": module_id,
                "publication_event_id": publication_event_id,
                "requests": manifest.capability_requests,
            }));
            capability_summary.sort_by_key(|value| {
                value["publication_event_id"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned()
            });
            let release_core = json!({
                "schema": mdx_v2::RELEASE_SCHEMA,
                "publication_event_id": publication_event_id,
                "module_record_id": module_id,
                "source_event_id": source_event_id,
                "source_sha256": source_sha256,
                "runtime": release_runtime_contract(),
                "inputs": manifest.inputs,
                "exports": manifest.exports.iter().map(|(name, interface)| json!({
                    "name": name, "kind": interface.kind, "interface": interface,
                })).collect::<Vec<_>>(),
                "imports": imports,
                "capability_requests": manifest.capability_requests,
                "closure_capability_summary": capability_summary,
                "dependency_closure_sha256": dependency_closure_sha256,
            });
            let release_sha256 = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&release_core));
            verify_release_descriptor(
                &publication_event_id,
                &module_id,
                &source_event_id,
                &source,
                &parsed,
                &release_core,
                &release_sha256,
                &dependency_closure_sha256,
            )
            .map_err(|failure| mdx_v2_engine_error(&module_id, failure))?;
            let event = append_with_event_id_in(
                &db,
                &mut tx,
                publication_event_id.clone(),
                AppendSpec {
                    record_id: module_id.clone(),
                    event_type: "module.release_published".into(),
                    payload: serde_json::to_value(ModuleReleasePublishedPayload {
                        release_core: release_core.clone(),
                        release_sha256: release_sha256.clone(),
                    })?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?;
            db.commit_content(tx).await?;
            Ok(json!({
                "status": "published", "module_id": module_id,
                "publication_event_id": publication_event_id,
                "local_event_seq": event.local_seq, "source_event_id": source_event_id,
                "source_sha256": source_sha256, "release_sha256": release_sha256,
                "dependency_closure_sha256": dependency_closure_sha256,
                "release": { "release_core": release_core, "release_sha256": release_sha256 },
            }))
        }
        ManageMdxModulesArgs::Inspect {
            module_id,
            publication_event_id,
        } => {
            require_record(&db, &caller, TOOL, &module_id, Capability::View).await?;
            if !live_module(&db, &module_id).await? {
                return Err(Error::engine(format!("{TOOL}: invalid module {module_id}")));
            }
            let mut snapshot = db.write_pool().begin().await?;
            let (draft_source_event_id, draft_source) =
                latest_body_source_in(&mut snapshot, &module_id).await?;
            let draft_source_sha256 = mdx::sha256_hex(draft_source.as_bytes());
            let rows = sqlx::query(
                "SELECT publication_event_id,source_event_id,source_sha256,release_sha256,
                        dependency_closure_sha256,descriptor,status,replacement,local_event_seq,status_event_seq,published_at
                   FROM module_releases WHERE module_record_id=?
                     AND (? IS NULL OR publication_event_id=?) ORDER BY local_event_seq DESC",
            )
            .bind(&module_id)
            .bind(&publication_event_id)
            .bind(&publication_event_id)
            .fetch_all(&mut *snapshot)
            .await?;
            let releases = rows
                .into_iter()
                .map(|row| -> Result<Value> {
                    Ok(json!({
                        "module_record_id": module_id,
                        "publication_event_id": row.try_get::<String,_>("publication_event_id")?,
                        "source_event_id": row.try_get::<String,_>("source_event_id")?,
                        "source_sha256": row.try_get::<String,_>("source_sha256")?,
                        "release_sha256": row.try_get::<String,_>("release_sha256")?,
                        "dependency_closure_sha256": row.try_get::<String,_>("dependency_closure_sha256")?,
                        "descriptor": serde_json::from_str::<Value>(&row.try_get::<String,_>("descriptor")?)?,
                        "status": row.try_get::<String,_>("status")?,
                        "replacement": row.try_get::<Option<String>,_>("replacement")?,
                        "local_event_seq": row.try_get::<i64,_>("local_event_seq")?,
                        "status_event_seq": row.try_get::<i64,_>("status_event_seq")?,
                        "published_at": row.try_get::<String,_>("published_at")?,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(json!({
                "status": "inspected", "module_id": module_id,
                "draft": {
                    "source_event_id": draft_source_event_id,
                    "source_sha256": draft_source_sha256,
                },
                "releases": releases,
            }))
        }
        ManageMdxModulesArgs::Impact {
            module_id,
            publication_event_id,
        } => {
            require_record(&db, &caller, TOOL, &module_id, Capability::View).await?;
            if !live_module(&db, &module_id).await? {
                return Err(Error::engine(format!("{TOOL}: invalid module {module_id}")));
            }
            let _permit =
                mdx::try_admit().map_err(|failure| mdx_v2_engine_error(&module_id, failure))?;
            let rows = sqlx::query(
                "WITH RECURSIVE impacted(publication_event_id,module_record_id,depth) AS (
                     SELECT publication_event_id,module_record_id,0 FROM module_releases
                      WHERE module_record_id=? AND (? IS NULL OR publication_event_id=?)
                     UNION
                     SELECT i.consumer_publication_event_id,r.module_record_id,impacted.depth+1
                       FROM impacted
                       JOIN module_release_imports i
                         ON i.dependency_publication_event_id=impacted.publication_event_id
                       JOIN module_releases r
                         ON r.publication_event_id=i.consumer_publication_event_id
                      WHERE impacted.depth < ?
                 )
                 SELECT publication_event_id,module_record_id,MIN(depth) AS depth
                   FROM impacted WHERE depth > 0
                  GROUP BY publication_event_id,module_record_id
                  ORDER BY depth,module_record_id,publication_event_id",
            )
            .bind(&module_id)
            .bind(&publication_event_id)
            .bind(&publication_event_id)
            .bind(mdx_v2::MAX_DEPTH as i64)
            .fetch_all(db.write_pool())
            .await?;
            let mut consumers = Vec::new();
            for row in rows {
                let consumer_module_id = row.get::<String, _>("module_record_id");
                if !can_record(&db, &caller, &consumer_module_id, Capability::View).await? {
                    continue;
                }
                consumers.push(json!({
                    "module_record_id": consumer_module_id,
                    "publication_event_id": row.get::<String,_>("publication_event_id"),
                    "depth": row.get::<i64,_>("depth"),
                }));
            }
            let impacted_publications = sqlx::query_scalar::<_, String>(
                "WITH RECURSIVE impacted(publication_event_id,depth) AS (
                     SELECT publication_event_id,0 FROM module_releases
                      WHERE module_record_id=? AND (? IS NULL OR publication_event_id=?)
                     UNION
                     SELECT i.consumer_publication_event_id,impacted.depth+1
                       FROM impacted JOIN module_release_imports i
                         ON i.dependency_publication_event_id=impacted.publication_event_id
                      WHERE impacted.depth < ?
                 ) SELECT DISTINCT publication_event_id FROM impacted ORDER BY publication_event_id",
            )
            .bind(&module_id)
            .bind(&publication_event_id)
            .bind(&publication_event_id)
            .bind(mdx_v2::MAX_DEPTH as i64)
            .fetch_all(db.write_pool())
            .await?
            .into_iter()
            .collect::<BTreeSet<_>>();
            let root_rows = sqlx::query(
                "WITH body_source AS (
                     SELECT e.record_id,e.id,e.seq,json_extract(e.payload,'$.body') AS body,
                            ROW_NUMBER() OVER (PARTITION BY e.record_id ORDER BY e.seq DESC) AS rank
                       FROM content_events e
                      WHERE e.type IN ('record.created','record.updated','receipt.committed.v1')
                        AND json_type(e.payload,'$.body') IS NOT NULL
                 )
                 SELECT r.id,r.name,body_source.body,body_source.id AS source_event_id,
                        body_source.seq AS source_event_seq FROM records r
                   JOIN facet_values f ON f.record_id=r.id AND f.key='runtime'
                   JOIN body_source ON body_source.record_id=r.id AND body_source.rank=1
                  WHERE r.type='Document' AND r.kind='artifact' AND r.deleted_at IS NULL AND f.value=?
                  ORDER BY r.name COLLATE NOCASE,r.id",
            )
            .bind(mdx_v2::RUNTIME_ID)
            .fetch_all(db.write_pool())
            .await?;
            let mut root_artifacts = Vec::new();
            let mut invalid_root_artifacts = Vec::new();
            for row in root_rows {
                let artifact_id = row.try_get::<String, _>("id")?;
                if !can_record(&db, &caller, &artifact_id, Capability::View).await? {
                    continue;
                }
                let Some(body) = row.try_get::<Option<String>, _>("body")? else {
                    invalid_root_artifacts.push(json!({
                        "artifact_id": artifact_id,
                        "source_event_id": row.try_get::<String,_>("source_event_id")?,
                        "source_event_seq": row.try_get::<i64,_>("source_event_seq")?,
                        "diagnostic": { "code": "invalid_artifact_body",
                            "message": "artifact has no authoritative body source" },
                    }));
                    continue;
                };
                let parse_body = body.clone();
                let parsed =
                    match tokio::task::spawn_blocking(move || mdx_v2::parse_artifact(&parse_body))
                        .await
                        .map_err(|_| {
                            Error::engine("native.mdx.v2 impact worker terminated unexpectedly")
                        })? {
                        Ok(parsed) => parsed,
                        Err(failure) => {
                            invalid_root_artifacts.push(json!({
                                "artifact_id": artifact_id,
                                "source_event_id": row.try_get::<String,_>("source_event_id")?,
                                "source_event_seq": row.try_get::<i64,_>("source_event_seq")?,
                                "diagnostic": { "code": failure.code, "message": failure.message,
                                    "details": failure.details },
                            }));
                            continue;
                        }
                    };
                if parsed.imports.is_empty() {
                    continue;
                }
                let pins = parsed
                    .imports
                    .iter()
                    .filter(|import| {
                        impacted_publications.contains(&import.address.publication_event_id)
                    })
                    .map(|import| import.address.publication_event_id.clone())
                    .collect::<Vec<_>>();
                if !pins.is_empty() {
                    root_artifacts.push(json!({
                        "artifact_id": artifact_id,
                        "name": row.try_get::<String,_>("name")?,
                        "direct_impacted_publication_event_ids": pins,
                        "source_event_id": row.try_get::<String,_>("source_event_id")?,
                        "source_event_seq": row.try_get::<i64,_>("source_event_seq")?,
                        "source_sha256": mdx::sha256_hex(body.as_bytes()),
                    }));
                }
            }
            Ok(json!({
                "status": "impact", "module_id": module_id,
                "consumers": consumers, "root_artifacts": root_artifacts,
                "invalid_root_artifacts": invalid_root_artifacts,
            }))
        }
        ManageMdxModulesArgs::Deprecate {
            module_id,
            publication_event_id,
            expected_status_event_seq,
            replacement,
        } => {
            update_release_status(
                &db,
                &caller,
                &module_id,
                &publication_event_id,
                expected_status_event_seq,
                "module.release_deprecated",
                replacement,
            )
            .await
        }
        ManageMdxModulesArgs::Withdraw {
            module_id,
            publication_event_id,
            expected_status_event_seq,
        } => {
            update_release_status(
                &db,
                &caller,
                &module_id,
                &publication_event_id,
                expected_status_event_seq,
                "module.release_withdrawn",
                None,
            )
            .await
        }
    }
}

pub(super) async fn update_release_status(
    db: &Db,
    caller: &Caller,
    module_id: &str,
    publication_event_id: &str,
    expected_status_event_seq: i64,
    event_type: &str,
    replacement: Option<String>,
) -> Result<Value> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    require_record_in(
        &mut tx,
        caller,
        "manage_mdx_modules",
        module_id,
        Capability::Edit,
    )
    .await?;
    let current = sqlx::query(
        "SELECT status,status_event_seq,descriptor FROM module_releases WHERE module_record_id=? AND publication_event_id=?",
    )
    .bind(module_id)
    .bind(publication_event_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        return Err(Error::engine("module release status target does not exist"));
    };
    let current_status: String = current.try_get("status")?;
    let current_status_event_seq: i64 = current.try_get("status_event_seq")?;
    if current_status_event_seq != expected_status_event_seq {
        return Err(Error::engine(format!(
            "module release status changed underneath this request (expected status event {expected_status_event_seq}, current status event is {current_status_event_seq})"
        )));
    }
    let allowed = match event_type {
        "module.release_deprecated" => current_status == "published",
        "module.release_withdrawn" => {
            matches!(current_status.as_str(), "published" | "deprecated")
        }
        _ => false,
    };
    if !allowed {
        return Err(Error::engine(format!(
            "module release status changed underneath this request (current status is '{current_status}')"
        )));
    }
    if let Some(replacement_id) = replacement.as_deref() {
        if event_type != "module.release_deprecated" {
            return Err(Error::engine(
                "only deprecation may name a replacement release",
            ));
        }
        let parsed = uuid::Uuid::parse_str(replacement_id)
            .map_err(|_| Error::engine("replacement must be a canonical lowercase event UUID"))?;
        if parsed.hyphenated().to_string() != replacement_id
            || replacement_id == publication_event_id
        {
            return Err(Error::engine(
                "replacement must be a different canonical lowercase event UUID",
            ));
        }
        let replacement_row = sqlx::query(
            "SELECT module_record_id,status,descriptor FROM module_releases WHERE publication_event_id=?",
        )
        .bind(replacement_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("replacement release does not exist"))?;
        let replacement_module: String = replacement_row.try_get("module_record_id")?;
        let replacement_status: String = replacement_row.try_get("status")?;
        if replacement_module != module_id || replacement_status != "published" {
            return Err(Error::engine(
                "replacement must be a published release of the same stable module",
            ));
        }
        let current_descriptor: Value =
            serde_json::from_str(&current.try_get::<String, _>("descriptor")?)?;
        let replacement_descriptor: Value =
            serde_json::from_str(&replacement_row.try_get::<String, _>("descriptor")?)?;
        let compatible = ["runtime", "inputs", "exports", "capability_requests"]
            .into_iter()
            .all(|field| current_descriptor.get(field) == replacement_descriptor.get(field));
        if !compatible {
            return Err(Error::engine(
                "replacement release does not have the exact compatible runtime, input, export, and capability interface",
            ));
        }
    }
    let previous_seq = previous_record_seq_in(&mut tx, module_id).await?;
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: module_id.into(),
            event_type: event_type.into(),
            payload: serde_json::to_value(ModuleReleaseStatusPayload {
                publication_event_id: publication_event_id.into(),
                expected_status_event_seq,
                replacement: replacement.clone(),
            })?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "status": event_type.trim_start_matches("module.release_"),
        "module_id": module_id, "publication_event_id": publication_event_id,
        "replacement": replacement, "previous_seq": previous_seq,
    }))
}
