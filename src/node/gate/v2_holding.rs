//! V2 ordinary custody is separate from legacy/typed-merge custody. The
//! namespace is derived from a verified account and exact database binding;
//! no old v1 request becomes replayable merely because hosted changed engine.
//! Scoped gates reuse the same queue implementation, with no workers or
//! recursive forwarding of their own. Their only entry point is forward_scoped.
use super::*;
use crate::node::journal::{CompatibilityBlock, CustodyBinding, V2_EVIDENCE_VERSION};

pub(super) async fn binding(hooks: Option<&dyn Outage>) -> Option<CustodyBinding> {
    let binding = hooks?.custody_binding().await?;
    binding.valid().then_some(binding)
}

#[cfg(feature = "v2-kernel-probe")]
pub(super) fn eligible(executor: &str, operation: &str, arguments: &Value) -> bool {
    if executor != "records_write"
        || crate::mcp::executor_prototype::declared_requires_acceptance(executor, operation)
            != Some(false)
    {
        return false;
    }
    let Some(args) = arguments.as_object() else {
        return false;
    };
    let explicit = |field: &str| {
        args.get(field)
            .and_then(Value::as_str)
            .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id))
    };
    match operation {
        "update_record" => crate::fork::kernel_v2_plain_append_target(arguments).is_some(),
        "manage_links.add" => explicit("source_id") && explicit("target_id"),
        "attach_text" => {
            (explicit("record_id") || explicit("id"))
                && !args.contains_key("ids")
                && args.get("text").is_some_and(Value::is_string)
        }
        _ => false,
    }
}

#[cfg(not(feature = "v2-kernel-probe"))]
pub(super) fn eligible(_: &str, _: &str, _: &Value) -> bool {
    false
}

/// Creates are admitted only by the explicit working manager, never ordinary
/// v2 custody or description-only compatibility.
#[cfg(feature = "v2-kernel-probe")]
pub(super) fn working_eligible(executor: &str, operation: &str, args: &Value) -> bool {
    record_projection(executor, operation, args).is_ok()
}

#[cfg(feature = "v2-kernel-probe")]
pub(super) fn record_projection(
    executor: &str,
    operation: &str,
    args: &Value,
) -> Result<(
    crate::mcp::kernel_v2::writes::replay::RecordOperation,
    Value,
)> {
    use crate::mcp::kernel_v2::writes::replay::RecordOperation;
    let kind = RecordOperation::from_catalog(executor, operation)
        .ok_or_else(|| Error::engine("unsupported working record operation"))?;
    let (tool, native) =
        crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2()?
            .working_native_arguments(executor, operation, args)?;
    if tool != kind.source_tool() {
        return Err(Error::engine("working record source changed"));
    }
    let mut source = native.clone();
    if kind == RecordOperation::Create {
        if let Some(object) = source.as_object_mut() {
            object.remove("id");
            object.remove("id_nonce");
        }
    }
    kind.validate(&source)?;
    Ok((kind, native))
}

#[cfg(feature = "v2-kernel-probe")]
fn legacy_working_eligible(executor: &str, operation: &str, args: &Value) -> bool {
    if operation != "create_record" {
        return eligible(executor, operation, args);
    }
    executor == "records_write"
        && crate::mcp::executor_prototype::declared_requires_acceptance(executor, operation)
            == Some(false)
        && crate::fork::validate_working_shape_kernel_v2(operation, args, 1024 * 1024).is_ok()
}
#[cfg(not(feature = "v2-kernel-probe"))]
fn legacy_working_eligible(_: &str, _: &str, _: &Value) -> bool {
    false
}

#[cfg(not(feature = "v2-kernel-probe"))]
fn working_eligible(_: &str, _: &str, _: &Value) -> bool {
    false
}

pub(super) fn target_record(operation: &str, arguments: &Value) -> Option<String> {
    let field = if operation == "manage_links.add" {
        "source_id"
    } else if operation == "attach_text" {
        "record_id"
    } else {
        "id"
    };
    arguments
        .get(field)
        .and_then(Value::as_str)
        .or_else(|| {
            arguments
                .get(if field == "id" { "record_id" } else { "id" })
                .and_then(Value::as_str)
        })
        .map(str::to_owned)
}

#[cfg(feature = "v2-kernel-probe")]
fn private_directory(path: &Path) -> Result<()> {
    validate_credential_path(path, "v2 pending directory")?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => check_owned(&meta, 0o700),
        Ok(_) => Err(Error::engine("invalid v2 pending directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(path)?;
            std::fs::File::open(
                path.parent()
                    .ok_or_else(|| Error::engine("missing pending parent"))?,
            )?
            .sync_all()?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

impl WriteGate {
    #[cfg(not(feature = "v2-kernel-probe"))]
    pub(in crate::node) fn scoped_v2_gate(&self, _: &CustodyBinding) -> Result<Arc<WriteGate>> {
        Err(Error::engine("v2 holding requires v2-kernel-probe"))
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(in crate::node) fn scoped_v2_gate(
        &self,
        binding: &CustodyBinding,
    ) -> Result<Arc<WriteGate>> {
        if self.custody_scope.is_some() || !binding.valid() {
            return Err(Error::engine("invalid v2 scope owner"));
        }
        let key = crate::canonical_json::digest_json(&serde_json::to_value(binding)?);
        let mut gates = self.v2_holding.lock().expect("v2 holding gates");
        if let Some(gate) = gates.get(&key) {
            return Ok(gate.clone());
        }
        let root = self.socket_directory.join("v2-held");
        private_directory(&root)?;
        let directory = root.join(&key);
        private_directory(&directory)?;
        let mut gate = Self::open_scoped(&directory, self.config.clone(), Some(binding.clone()))?;
        gate.ordering_root = Some(self.journal.clone());
        gate.merge_admission = self.merge_admission.clone();
        gate.set_kernel_v2_upstream(true);
        let gate = Arc::new(gate);
        gates.insert(key, gate.clone());
        Ok(gate)
    }

    pub(super) fn retained_v2_namespaces(&self) -> Result<usize> {
        match std::fs::read_dir(self.socket_directory.join("v2-held")) {
            Ok(mut entries) => entries.try_fold(0, |count, entry| {
                entry.map(|_| count + 1).map_err(Error::from)
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn root_merge_blocks(&self, entry: &Entry) -> bool {
        if entry.installed_working() {
            return self.journal.has_opaque_custody()
                || entry
                    .record_id
                    .iter()
                    .chain(entry.record_ids.iter())
                    .any(|record| {
                        self.ordering_root
                            .as_ref()
                            .is_some_and(|root| root.has_open_body_custody(record, true))
                    });
        }
        entry.ordinary_v2()
            && entry.operation == "update_record"
            && (self.journal.has_opaque_custody()
                || entry.record_id.as_deref().is_some_and(|record| {
                    self.ordering_root
                        .as_ref()
                        .is_some_and(|root| root.has_open_body_custody(record, true))
                }))
    }

    pub(super) fn scope_targets(&self, upstream: &Upstream) -> bool {
        self.custody_scope.as_ref().is_none_or(|scope| {
            scope.database_id == upstream.config.db_id
                && scope.resource_origin == upstream.config.hosted_base_url.trim_end_matches('/')
                && scope.install_id == upstream.install_key.as_ref().map(|key| key.id())
        })
    }

    pub(super) async fn credential_for_scope(
        &self,
        hooks: Option<&dyn Outage>,
    ) -> Option<Option<[u8; 32]>> {
        if self.custody_scope.is_none() {
            return Some(None);
        }
        let fingerprint = hooks?.custody_credential().await?;
        self.scope_matches(hooks).await.then_some(Some(fingerprint))
    }

    pub(super) async fn scope_matches(&self, hooks: Option<&dyn Outage>) -> bool {
        match &self.custody_scope {
            None => true,
            Some(scope) => {
                self.kernel_v2_upstream() && binding(hooks).await.as_ref() == Some(scope)
            }
        }
    }

    fn v2_identity_eligible(&self, entry: &Entry) -> bool {
        match (&self.custody_scope, &entry.kernel_v2_custody) {
            (Some(scope), Some(custody)) => {
                (entry.ordinary_v2() || entry.installed_working())
                    && custody.engine == "native-kernel-v2"
                    && &custody.binding == scope
                    && entry.app_identity.is_none()
                    && entry.arguments.as_ref().is_some_and(|args| {
                        if entry.installed_working() {
                            if entry.version == super::super::journal::INSTALLED_RECORD_VERSION {
                                working_eligible(&entry.executor, &entry.operation, args)
                            } else {
                                legacy_working_eligible(&entry.executor, &entry.operation, args)
                            }
                        } else {
                            eligible(&entry.executor, &entry.operation, args)
                        }
                    })
            }
            _ => false,
        }
    }

    pub(super) fn compatible_entry(&self, entry: &Entry) -> bool {
        if self.custody_scope.is_none() {
            return entry.kernel_v2_custody.is_none()
                && !matches!(
                    entry.version,
                    3 | V2_EVIDENCE_VERSION
                        | INSTALLED_WORKING_VERSION
                        | super::super::journal::INSTALLED_CREATE_VERSION
                        | super::super::journal::INSTALLED_RECORD_VERSION
                );
        }
        if !self.v2_identity_eligible(entry) {
            return false;
        }
        let custody = entry.kernel_v2_custody.as_ref().expect("verified custody");
        if installed_working_version(entry.version) {
            return custody.original.is_none()
                && self
                    .hold_contracts(&entry.operation)
                    .digest(&entry.executor, &entry.operation)
                    == Some(custody.contract_digest.as_str());
        }
        if entry.version == V2_EVIDENCE_VERSION {
            custody.original.as_ref().is_some_and(|original| {
                original.rule == super::super::journal::SOURCE_DESCRIPTION_RULE
                    && self
                        .hold_contracts(&entry.operation)
                        .holding_contract(&entry.executor, &entry.operation)
                        .is_some_and(|local| original.contract.matches_custody(&local))
            })
        } else {
            self.hold_contracts(&entry.operation)
                .digest(&entry.executor, &entry.operation)
                == Some(custody.contract_digest.as_str())
        }
    }

    /// Only cached authenticated discovery for the actual queue protocol; no network wait.
    pub(super) async fn v2_contract_block(
        &self,
        entry: &Entry,
        hooks: Option<&dyn Outage>,
    ) -> Option<CompatibilityBlock> {
        let custody = entry.kernel_v2_custody.as_ref()?;
        if !self.v2_identity_eligible(entry) {
            return Some(CompatibilityBlock::Incompatible);
        }
        if entry.version != 3 && !self.compatible_entry(entry) {
            return Some(CompatibilityBlock::Incompatible);
        }
        if let Some(hooks) = hooks {
            if hooks
                .holding_operation_absent(&entry.executor, &entry.operation, None)
                .await
            {
                return Some(CompatibilityBlock::Incompatible);
            }
        }
        if installed_working_version(entry.version) {
            let digest = if let Some(hooks) = hooks {
                hooks
                    .contract_digest(&entry.executor, &entry.operation, None)
                    .await
            } else {
                None
            };
            return match digest {
                None => Some(CompatibilityBlock::EvidenceMissing),
                Some(digest) if digest != custody.contract_digest => {
                    let hosted = if let Some(hooks) = hooks {
                        hooks
                            .holding_contract(&entry.executor, &entry.operation, None)
                            .await
                    } else {
                        None
                    };
                    let paired = entry.version == super::super::journal::INSTALLED_WORKING_VERSION
                        && self
                            .hold_contracts(&entry.operation)
                            .holding_contract(&entry.executor, &entry.operation)
                            .zip(hosted)
                            .is_some_and(|(local, hosted)| {
                                let original = super::receiver_contracts::recorded_v7(
                                    &entry.executor,
                                    &entry.operation,
                                    super::receiver_contracts::RecordedLocalDigest(
                                        &custody.contract_digest,
                                    ),
                                    &local,
                                );
                                hosted.description["contract_digest"].as_str()
                                    == Some(digest.as_str())
                                    && original.is_some_and(|original| {
                                        entry.arguments.as_ref().is_some_and(|args| {
                                            super::receiver_contracts::no_observation_pair(
                                                &entry.executor,
                                                &entry.operation,
                                                args,
                                                original,
                                                &local,
                                                &hosted,
                                            )
                                        })
                                    })
                            });
                    (!paired).then_some(CompatibilityBlock::LegacyDigestDrift)
                }
                _ => None,
            };
        }
        if let Some(original) = &custody.original {
            let hosted = if let Some(hooks) = hooks {
                hooks
                    .holding_contract(&entry.executor, &entry.operation, None)
                    .await
            } else {
                None
            };
            let Some(hosted) = hosted else {
                return Some(CompatibilityBlock::EvidenceMissing);
            };
            let paired = self
                .hold_contracts(&entry.operation)
                .holding_contract(&entry.executor, &entry.operation)
                .is_some_and(|local| {
                    entry.arguments.as_ref().is_some_and(|args| {
                        super::receiver_contracts::no_observation_pair(
                            &entry.executor,
                            &entry.operation,
                            args,
                            &original.contract,
                            &local,
                            &hosted,
                        )
                    })
                });
            if !hosted.valid_hosted_evidence(&entry.executor, &entry.operation)
                || (!original.contract.matches_custody(&hosted) && !paired)
            {
                return Some(CompatibilityBlock::Incompatible);
            }
        } else {
            let digest = if let Some(hooks) = hooks {
                hooks
                    .contract_digest(&entry.executor, &entry.operation, None)
                    .await
            } else {
                None
            };
            match digest {
                None => return Some(CompatibilityBlock::EvidenceMissing),
                Some(digest)
                    if digest != custody.contract_digest || !self.compatible_entry(entry) =>
                {
                    return Some(CompatibilityBlock::LegacyDigestDrift)
                }
                _ => {}
            }
        }
        None
    }

    /// Private details are read only after the caller's current credential is
    /// tied to this exact namespace. Other namespaces remain durable; disclose
    /// their existence without their account names, record ids or keys.
    pub(in crate::node) async fn scoped_status(
        &self,
        filter: &StatusFilter,
        hooks: Option<&dyn Outage>,
    ) -> Value {
        let mut status = self.status(filter);
        let scope = binding(hooks).await;
        let mut legacy_drift = 0;
        let details = if self.kernel_v2_upstream() {
            if let Some(gate) = scope
                .as_ref()
                .and_then(|scope| self.scoped_v2_gate(scope).ok())
            {
                for entry in gate.journal.pending_entries() {
                    if entry.version == 3
                        && (!(entry.maybe_applied || entry.in_flight)
                            || automatic_replay_safe(&entry))
                        && !gate.root_merge_blocks(&entry)
                        && gate.journal.refused_creator_of(&entry).is_none()
                        && !gate.journal.hosted_pending_creator_of(&entry)
                        && gate.v2_contract_block(&entry, hooks).await
                            == Some(CompatibilityBlock::LegacyDigestDrift)
                    {
                        legacy_drift += 1;
                    }
                }
                if gate.scope_matches(hooks).await {
                    Some(gate.status(filter))
                } else {
                    legacy_drift = 0;
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let retained = self.retained_v2_namespaces();
        status["v2_ordinary_custody"] = json!({
            "legacy_v3_digest_drift": if details.is_some() {Some(legacy_drift)} else {None},
            "available": details.is_some(), "retained_namespaces":retained.as_ref().ok(),
            "namespace_inventory_available":retained.is_ok(),
            "scope":"verified_account_and_database", "status":details,
            "reason": if scope.is_none() { "verified_credential_binding_unavailable" } else { "scoped" },
        });
        status
    }
}
