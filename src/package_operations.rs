//! Gated generic package-operation seam (proof slice: describe + call).
//!
//! Compiled only under `cfg(any(test, feature = "v2-kernel-probe"))` (see the
//! gated `mod` declaration in the crate root). Nothing here touches the
//! default build: no v1 schema change, no migration, no MCP tool surface.
//!
//! This is the *only* place a package operation is called. It owns the initial
//! and delivery authority/selection/record snapshots and hands the provider nothing
//! but the source text and optional immutable expression declaration. It never
//! sees the database, caller or record; the caller never sees raw rows.
//!
//! Fail-closed order inside one snapshot:
//!
//! 1. the record must exist (missing and hidden are indistinguishable), and
//!    the caller must hold `View` on it;
//! 2. the package must be active in the record's own home (ancestor adoption
//!    activates children; a disabled or displaced selection refuses);
//! 3. the record's definition pin must equal the active manifest's embedded
//!    definition for its family — an old record after an upgrade refuses
//!    rather than being reinterpreted (`family`, `version`, `digest`, `kind`);
//! 4. every read the operation declares must be in the manifest's declared
//!    reads;
//! 5. the source text is size-capped before parsing;
//! 6. the pure provider runs without a transaction or host capabilities;
//! 7. fresh authority, selection, record and (development transport) app
//!    installation/consent/source checks must agree before delivery. Drift
//!    discards the result and requires an explicit retry. The receipt pins
//!    the package, definition, operation, provider, record revision, and input
//!    digest.
//!
//! Nothing is appended: a call is a read plus a pure computation. A domain
//! failure (missing reference, cycle, malformed source) is returned inside
//! `result.error` so the receipt is still produced; only an authority,
//! selection, or pin failure is a transport-level error.

use serde::Serialize;
use sqlx::SqliteConnection;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::kernel::{kernel_require, require_package_active_in, HIDDEN_OR_MISSING};
use crate::package_manifest::{OperationDescriptor, OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC};

/// Largest source-text field the seam will read into memory before parsing.
/// A budget sheet's `cells_json` is far below this; the cap is a bound, not a
/// schema promise.
pub const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// Raw columns of the target record's identity/pin row: `home_id`, `kind`,
/// `pin_family`, `pin_version`, `pin_digest`.
type RecordPinRow = (
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
);

/// A receipt pinning exactly what one call computed and read. It is evidence,
/// not authority: it records the package/definition pins and the record
/// revision at call time so a later reader can detect drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageOperationReceipt {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub package_version: u32,
    pub package_digest: String,
    pub family: String,
    pub kind: String,
    pub definition_version: u32,
    pub definition_digest: String,
    pub operation: String,
    pub provider: String,
    pub record_id: String,
    pub record_revision: i64,
    pub input_digest: String,
    pub ack_event_seq: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<crate::package_cel_dev::ExecutionReceipt>,
}

/// One operation call outcome: the provider result plus its receipt.
#[derive(Debug, Clone, Serialize)]
pub struct PackageOperationOutcome {
    pub result: serde_json::Value,
    pub receipt: PackageOperationReceipt,
}

/// Describe the operations a package advertises in a scope, or refuse when
/// none are visible/usable. Returns the descriptor plus the trusted provider's
/// request/result shape (descriptive, not a validated schema claim).
pub async fn describe_package_operations_as(
    db: &Db,
    caller: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<serde_json::Value> {
    describe_checked(db, caller, None, scope_home, namespace, name).await
}

#[cfg(feature = "package-cel-dev")]
pub(crate) async fn describe_authenticated_as(
    db: &Db,
    caller: &str,
    credential: &str,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<serde_json::Value> {
    describe_checked(db, caller, Some(credential), scope_home, namespace, name).await
}

async fn describe_checked(
    db: &Db,
    caller: &str,
    credential: Option<&str>,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<serde_json::Value> {
    let mut tx = db.write_pool().begin().await?;
    #[cfg(feature = "package-cel-dev")]
    crate::kernel::app_installs::admit_dispatched_on(&mut tx, caller).await?;
    require_binding(&mut tx, caller, credential).await?;
    kernel_require(&mut tx, caller, scope_home, Capability::View).await?;
    let (selection, manifest) =
        require_package_active_in(&mut tx, scope_home, namespace, name).await?;
    tx.rollback().await?;
    let selected = selection
        .selected
        .as_ref()
        .ok_or_else(|| Error::engine("package is disabled in this scope"))?;
    if manifest.operations.is_empty() {
        return Err(Error::engine(format!(
            "package '{namespace}/{name}' declares no operations"
        )));
    }
    let operations: Vec<serde_json::Value> = manifest
        .operations
        .iter()
        .filter(|operation| operation.available_in_build())
        .map(operation_json)
        .collect();
    if operations.is_empty() {
        return Err(Error::engine(
            "package declares no operations available in this build",
        ));
    }
    let mut output = serde_json::json!({
        "scope_home": scope_home,
        "namespace": namespace,
        "name": name,
        "version": selected.version,
        "package_digest": selected.digest,
        "ack_event_seq": selection.event_seq,
        "operations": operations,
        "provider_schemas": provider_schemas(),
    });
    if manifest
        .operations
        .iter()
        .any(|op| op.provider == crate::v2_standard::relates_to::PROVIDER)
    {
        output["provider_schemas"][crate::v2_standard::relates_to::PROVIDER] =
            crate::kernel::provider_port_contract();
    }
    #[cfg(feature = "package-cel-dev")]
    if manifest
        .operations
        .iter()
        .any(|op| op.provider == crate::package_cel_dev::PROVIDER)
    {
        output["provider_schemas"][crate::package_cel_dev::PROVIDER] =
            crate::package_cel_dev::provider_schema();
    }
    Ok(output)
}

/// Call one operation on one record. The record's own home is the scope; the
/// caller supplies no scope, so a record in an unscoped or differently-scoped
/// home simply fails activation.
pub async fn call_package_operation_as(
    db: &Db,
    caller: &str,
    namespace: &str,
    name: &str,
    operation: &str,
    record_id: &str,
) -> Result<PackageOperationOutcome> {
    call_checked(
        db,
        caller,
        None,
        namespace,
        name,
        operation,
        record_id,
        std::future::ready(()),
    )
    .await
}

/// Transport supplies only its host-authenticated credential. Re-resolve the
/// binding inside both authority snapshots, alongside app consent if dispatched.
#[cfg(feature = "package-cel-dev")]
pub(crate) async fn call_authenticated_as(
    db: &Db,
    caller: &str,
    credential: &str,
    namespace: &str,
    name: &str,
    operation: &str,
    record_id: &str,
) -> Result<PackageOperationOutcome> {
    call_checked(
        db,
        caller,
        Some(credential),
        namespace,
        name,
        operation,
        record_id,
        std::future::ready(()),
    )
    .await
}

const DELIVERY_CHANGED: &str =
    "package operation delivery changed; result discarded; explicitly retry the call";

struct CallSnapshot {
    descriptor: OperationDescriptor,
    source: String,
    receipt: PackageOperationReceipt,
    #[cfg(feature = "package-cel-dev")]
    app: Option<serde_json::Value>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn call_checked(
    db: &Db,
    caller: &str,
    credential: Option<&str>,
    namespace: &str,
    name: &str,
    operation: &str,
    record_id: &str,
    before_delivery: impl std::future::Future<Output = ()>,
) -> Result<PackageOperationOutcome> {
    let initial = call_snapshot(
        db, caller, credential, namespace, name, operation, record_id,
    )
    .await?;
    let descriptor = &initial.descriptor;
    // Neither a transaction nor a host capability crosses the worker boundary.
    let (result, execution) = if descriptor.provider == crate::package_cel_dev::PROVIDER {
        let declaration = descriptor
            .executable
            .clone()
            .ok_or_else(|| Error::engine("CEL operation lacks executable declaration"))?;
        let (result, receipt) = crate::package_cel_dev::run(declaration, initial.source).await?;
        (result, Some(receipt))
    } else {
        (run_provider(&descriptor.provider, &initial.source)?, None)
    };
    before_delivery.await;
    let current = call_snapshot(
        db, caller, credential, namespace, name, operation, record_id,
    )
    .await
    .map_err(|_| Error::engine(DELIVERY_CHANGED))?;
    let changed = current.receipt != initial.receipt;
    #[cfg(feature = "package-cel-dev")]
    let changed = changed || current.app != initial.app;
    if changed {
        return Err(Error::engine(DELIVERY_CHANGED));
    }
    let mut receipt = initial.receipt;
    receipt.execution = execution;
    Ok(PackageOperationOutcome { result, receipt })
}

async fn call_snapshot(
    db: &Db,
    caller: &str,
    credential: Option<&str>,
    namespace: &str,
    name: &str,
    operation: &str,
    record_id: &str,
) -> Result<CallSnapshot> {
    let mut tx = db.write_pool().begin().await?;

    #[cfg(feature = "package-cel-dev")]
    let app = crate::kernel::app_installs::admit_dispatched_on(&mut tx, caller)
        .await?.map(|a| serde_json::json!({
            "principal":a.principal,"account":a.account,"package":a.package,
            "version":a.version,"generation":a.generation,"install_event_seq":a.install_event_seq,
            "revocation_epoch":a.revocation_epoch,"frozen_source_seq":a.frozen_source_seq,"pin":a.pin
        }));
    require_binding(&mut tx, caller, credential).await?;
    // 1. Existence (private) then the View gate, before any package detail.
    let row: Option<RecordPinRow> = sqlx::query_as(
        "SELECT home_id, kind, pin_family, pin_version, pin_digest
           FROM kernel_records WHERE id = ?",
    )
    .bind(record_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((home_id, record_kind, pin_family, pin_version, pin_digest)) = row else {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    };
    kernel_require(&mut tx, caller, record_id, Capability::View).await?;

    kernel_require(&mut tx, caller, &home_id, Capability::View).await?;

    // 2. The package must be active in the record's actual home.
    let (selection, manifest) =
        require_package_active_in(&mut tx, &home_id, namespace, name).await?;
    let selected = selection
        .selected
        .as_ref()
        .ok_or_else(|| Error::engine("package is disabled in this scope"))?;

    // 3. The record's pin must equal the embedded definition exactly.
    let (pin_family, record_kind) = match (pin_family, record_kind) {
        (Some(family), Some(kind)) => (family, kind),
        _ => {
            return Err(Error::engine(
                "record carries no definition revision for this operation",
            ))
        }
    };
    let pin_version = pin_version
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| Error::engine("record pin version is invalid"))?;
    let pin_digest = pin_digest.ok_or_else(|| Error::engine("record pin digest is missing"))?;
    let definition = manifest
        .definitions
        .iter()
        .find(|entry| entry.family == pin_family)
        .ok_or_else(|| {
            Error::engine(format!(
                "active package does not embed definition '{}'",
                pin_family
            ))
        })?;
    if definition.version != pin_version || definition.digest != pin_digest {
        return Err(Error::engine(
            "record pins a definition revision that the active package no longer embeds; refusing rather than reinterpreting",
        ));
    }

    // 4. Resolve the operation and its declared reads against the manifest.
    let descriptor = manifest
        .operations
        .iter()
        .find(|candidate| candidate.name == operation)
        .ok_or_else(|| {
            Error::engine(format!(
                "package '{namespace}/{name}' declares no operation '{operation}'"
            ))
        })?;
    descriptor.require_available()?;
    if descriptor.family != pin_family || descriptor.kind != record_kind {
        return Err(Error::engine(
            "operation descriptor does not match the record's family and kind",
        ));
    }
    for scope in &descriptor.reads {
        if !manifest
            .declared_reads
            .iter()
            .any(|declared| declared == scope)
        {
            return Err(Error::engine(format!(
                "operation read '{scope}' is not acknowledged by the active package"
            )));
        }
        // The manifest declares the read and the adopting caller acknowledged
        // it. Both must cover it, exactly as the surface read path requires.
        if !selection
            .acknowledged_reads
            .iter()
            .any(|acknowledged| acknowledged == scope)
        {
            return Err(Error::engine(format!(
                "operation read '{scope}' was not acknowledged by the adopting caller"
            )));
        }
    }

    // 5. Read the source text (capped) and the record revision in this snapshot.
    let source = read_source_field(&mut tx, record_id, &descriptor.source_field).await?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Error::engine(format!(
            "operation source is {} bytes, over the cap of {MAX_SOURCE_BYTES}",
            source.len()
        )));
    }
    let record_revision: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id = ?")
            .bind(record_id)
            .fetch_one(&mut *tx)
            .await?;

    let receipt = PackageOperationReceipt {
        scope_home: home_id,
        namespace: namespace.to_string(),
        name: name.to_string(),
        package_version: selected.version,
        package_digest: selected.digest.clone(),
        family: pin_family,
        kind: record_kind,
        definition_version: definition.version,
        definition_digest: definition.digest.clone(),
        operation: descriptor.name.clone(),
        provider: descriptor.provider.clone(),
        record_id: record_id.to_string(),
        record_revision,
        input_digest: crate::meta::definition_artifact::digest_artifact_bytes(source.as_bytes()),
        ack_event_seq: selection.event_seq,
        execution: None,
    };
    let descriptor = descriptor.clone();
    tx.rollback().await?;
    Ok(CallSnapshot {
        descriptor,
        source,
        receipt,
        #[cfg(feature = "package-cel-dev")]
        app,
    })
}

async fn require_binding(
    conn: &mut SqliteConnection,
    caller: &str,
    credential: Option<&str>,
) -> Result<()> {
    if let Some(credential) = credential {
        let bound: Option<String> =
            sqlx::query_scalar("SELECT principal_id FROM kernel_principals WHERE auth_binding = ?")
                .bind(credential)
                .fetch_optional(&mut *conn)
                .await?;
        if bound.as_deref() != Some(caller) {
            return Err(Error::engine("database membership not found"));
        }
    }
    Ok(())
}

async fn read_source_field(
    conn: &mut SqliteConnection,
    record_id: &str,
    field: &str,
) -> Result<String> {
    // Metadata gate first: `length(CAST(... AS BLOB))` reads the stored byte
    // count without materialising the text, so an oversized source value is
    // refused before it is fetched or deserialised.
    let stored_len: Option<i64> = sqlx::query_scalar(
        "SELECT length(CAST(value_json AS BLOB)) FROM kernel_record_fields
          WHERE record_id = ? AND name = ?",
    )
    .bind(record_id)
    .bind(field)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(stored_len) = stored_len else {
        return Err(Error::engine(format!(
            "record does not carry source field '{field}'"
        )));
    };
    if stored_len > MAX_SOURCE_BYTES as i64 {
        return Err(Error::engine(format!(
            "operation source is {stored_len} stored bytes, over the cap of {MAX_SOURCE_BYTES}"
        )));
    }
    let stored: String = sqlx::query_scalar(
        "SELECT value_json FROM kernel_record_fields WHERE record_id = ? AND name = ?",
    )
    .bind(record_id)
    .bind(field)
    .fetch_one(&mut *conn)
    .await?;
    let value: serde_json::Value = serde_json::from_str(&stored)
        .map_err(|_| Error::engine("record source field is not valid stored JSON"))?;
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::engine("record source field is not text"))
}

/// The trusted provider registry. A descriptor can only name a provider in
/// this closed set; the manifest validator refuses anything else.
fn run_provider(provider: &str, source: &str) -> Result<serde_json::Value> {
    match provider {
        OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC => {
            Ok(crate::v2_budget::run_table_arithmetic(source))
        }
        crate::v2_standard::relates_to::PROVIDER => Err(Error::engine("relationship commands use prepare_provider_as / commit_provider_as; discover the command contract from describe")),
        other => Err(Error::engine(format!(
            "unknown package operation provider '{other}'"
        ))),
    }
}

pub(crate) fn operation_json(operation: &OperationDescriptor) -> serde_json::Value {
    let mut value = serde_json::json!({
        "name": operation.name,
        "description": operation.description,
        "provider": operation.provider,
        "family": operation.family,
        "kind": operation.kind,
        "source_field": operation.source_field,
        "reads": operation.reads,
        "effects": operation.effects,
    });
    if let Some(executable) = &operation.executable {
        value["executable"] = serde_json::to_value(executable).expect("executable JSON");
    }
    value
}

/// Descriptive request/result shapes for the trusted providers. These are
/// host-owned documentation of the envelope, not validated JSON Schema and
/// not a claim that arbitrary provider data is validated.
fn provider_schemas() -> serde_json::Value {
    serde_json::json!({
        "host.table-arithmetic/1": {
            "request": {"record_id": "string"},
            "result": {
                "cells": {
                    "<address>": {
                        "expression": "string",
                        "value": "number | null",
                        "error": "object | null"
                    }
                },
                "error": {
                    "kind": "string",
                    "message": "string",
                    "address": "string?",
                    "referenced": "string?"
                }
            }
        }
    })
}

/// Record-scoped discovery is an explicit development transport only. It does
/// not load a source field, admit an expression or invoke any provider.
#[cfg(feature = "package-cel-dev")]
pub(crate) mod discovery {
    use super::*;
    use serde_json::{json, Value};

    const MAX_CANDIDATES: usize = 32;
    const MAX_RESPONSE_BYTES: usize = 64 * 1024;
    const BOUNDED_REFUSAL: &str = "record package discovery exceeds development bounds";

    pub(crate) async fn describe_record_checked(
        db: &Db,
        actor: &str,
        credential: &str,
        record: &str,
        before_delivery: impl std::future::Future<Output = ()>,
    ) -> Result<Value> {
        let initial = snapshot(db, actor, credential, record).await?;
        before_delivery.await;
        let current = snapshot(db, actor, credential, record)
            .await
            .map_err(|_| Error::engine(DELIVERY_CHANGED))?;
        if initial != current {
            return Err(Error::engine(DELIVERY_CHANGED));
        }
        Ok(initial.0)
    }

    async fn snapshot(
        db: &Db,
        actor: &str,
        credential: &str,
        record: &str,
    ) -> Result<(Value, Value)> {
        let mut tx = db.write_pool().begin().await?;
        let app = crate::kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?
            .map(|a| json!({"principal":a.principal,"account":a.account,"package":a.package,
                "version":a.version,"generation":a.generation,"install_event_seq":a.install_event_seq,
                "revocation_epoch":a.revocation_epoch,"frozen_source_seq":a.frozen_source_seq,"pin":a.pin}));
        require_binding(&mut tx, actor, Some(credential)).await?;
        let row: RecordPinRow = sqlx::query_as(
            "SELECT home_id, kind, pin_family, pin_version, pin_digest FROM kernel_records WHERE id=?")
            .bind(record).fetch_optional(&mut *tx).await?
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
        kernel_require(&mut tx, actor, record, Capability::View).await?;
        kernel_require(&mut tx, actor, &row.0, Capability::View).await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=?")
                .bind(record)
                .fetch_one(&mut *tx)
                .await?;
        let homes = crate::kernel::package_discovery_ancestors_in(&mut tx, &row.0).await?;
        // Cap+1 is checked BEFORE any manifest is fetched or decoded. This
        // scoped metadata query neither walks all homes nor enumerates installs.
        let candidates: Vec<(String, String)> = sqlx::query_as(
            "SELECT DISTINCT namespace,name FROM kernel_package_selections WHERE scope_home IN (SELECT value FROM json_each(?)) ORDER BY namespace,name LIMIT ?")
            .bind(serde_json::to_string(&homes)?).bind((MAX_CANDIDATES + 1) as i64)
            .fetch_all(&mut *tx).await?;
        if candidates.len() > MAX_CANDIDATES {
            return Err(Error::engine(BOUNDED_REFUSAL));
        }
        let mut selections = Vec::new();
        let mut output = json!({"record_id":record,"scope_home":row.0,"record_revision":revision,
            "packages":[],"provider_schemas":provider_schemas(),"complete":true});
        for (namespace, name) in candidates {
            let stored = crate::kernel::resolve_effective_package_selection(
                &mut tx, &row.0, &namespace, &name,
            )
            .await?;
            selections.push(match stored {
                Some(s) => json!({"scope":s.scope_home,"namespace":s.namespace,"name":s.name,
                    "selected":s.selected,"actor":s.ack_actor,"reads":s.acknowledged_reads,"event":s.event_seq}),
                None => Value::Null,
            });
            let active =
                crate::kernel::inspect_package_active_in(&mut tx, &row.0, &namespace, &name)
                    .await?;
            let crate::kernel::PackageActivation::Active(active) = active else {
                continue;
            };
            let (selection, manifest) = *active;
            let selected = selection.selected.as_ref().expect("active selection");
            let matching_pin = manifest.definitions.iter().any(|d| {
                row.2.as_deref() == Some(d.family.as_str())
                    && row.3 == Some(i64::from(d.version))
                    && row.4.as_deref() == Some(d.digest.as_str())
            });
            if !matching_pin {
                continue;
            }
            let mut operations: Vec<_> = manifest
                .operations
                .iter()
                .filter(|op| {
                    op.available_in_build()
                        && matches!(
                            op.provider.as_str(),
                            OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC
                                | crate::package_cel_dev::PROVIDER
                        )
                        && row.2.as_deref() == Some(op.family.as_str())
                        && row.1.as_deref() == Some(op.kind.as_str())
                        && op.reads.iter().all(|r| {
                            manifest.declared_reads.contains(r)
                                && selection.acknowledged_reads.contains(r)
                        })
                })
                .collect();
            operations.sort_by(|a, b| a.name.cmp(&b.name));
            if operations.is_empty() {
                continue;
            }
            if operations
                .iter()
                .any(|op| op.provider == crate::package_cel_dev::PROVIDER)
            {
                output["provider_schemas"][crate::package_cel_dev::PROVIDER] =
                    crate::package_cel_dev::provider_schema();
            }
            output["packages"]
                .as_array_mut()
                .expect("package array")
                .push(json!({
                "namespace":namespace,"name":name,"version":selected.version,
                "package_digest":selected.digest,"ack_event_seq":selection.event_seq,
                "operations":operations.into_iter().map(operation_json).collect::<Vec<_>>() }));
            check_size(&output)?;
        }
        check_size(&output)?;
        let fence = json!({"record":row,"revision":revision,"homes":homes,"selections":selections,"app":app});
        tx.rollback().await?;
        Ok((output, fence))
    }

    fn check_size(output: &Value) -> Result<()> {
        if serde_json::to_vec(output)?.len() > MAX_RESPONSE_BYTES {
            return Err(Error::engine(BOUNDED_REFUSAL));
        }
        Ok(())
    }
}
