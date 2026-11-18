//! Receiver compatibility is independent of the shape canonical writers emit.
//!
//! These are release evidence, not a range of schema versions. A producer must
//! negotiate its actual shape for each consumer; a manifest cannot extend this
//! executable's registry. Keep the selected shape out of consumer attribution.
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const ACCEPTED_SHAPES_HEADER: &str = "native-accepted-shapes";
pub const SELECTED_SHAPE_HEADER: &str = "native-selected-shape";
pub const UPDATE_REQUIRED: &str = "receiver_shape_update_required";
pub(crate) const UNSUPPORTED: &str = "receiver_shape_unsupported";
// Fixed wire identity, also decoded by v1-only receiver builds.
pub(crate) const WRITE_RECEIPT_EVENT: &str = "kernel.mcp_write_receipt_recorded.v1";
pub const V2_94: &str = "0295db140abe29a6c4c2dce429e325eb37d1235031a6d1068d2df561e8618da7";
pub const V2_95: &str = "770fb261b350ed747bb12db56f6b40cccc33c39ab01baaef2b2298d9b6b3ad90";
pub const V2_TERMINAL_94: &str = "bac8d8a8c0f417775a3fc18faa1f3404472b2507da3ec75196e6b77a59dbbd87";
pub const V2_TERMINAL_95: &str = "10a1b9ac392d5e3d1d3ee4a15381e177306f3ca2613bcf6ee88cccfbf2d51d5c";
pub const V1_94: &str = "e8975ea5ec8a281d7ed4f70ca3bf68d56f70f7038571e3f20109423bda348fe5";
pub const V1_95: &str = "a122164c9e26ac98db3e04f3769a3edcc60ce25f78ecc2305c7aa5037afdc30f";
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) const CALLER_INDEX: &str = "CREATE INDEX idx_content_events_caller_write ON content_events(actor, caller_write_ordinal DESC) WHERE caller_write_ordinal IS NOT NULL";
pub(crate) const APP_INDEX: &str = "CREATE INDEX idx_kernel_app_write_ordinal ON content_events(actor,record_id,CAST(json_extract(payload,'$.caller_write_ordinal') AS INTEGER) DESC) WHERE type='kernel.app_action_recorded.v1' AND json_type(payload,'$.caller_write_ordinal')='integer'";

/// Frozen source DDL, independent of canonical emission and used only to
/// build private reference databases. Every entry verifies its complete digest.
pub(crate) fn frozen_v1_ddl(entry: &Entry) -> Result<Vec<String>> {
    use sha2::{Digest, Sha256};
    let statements: Vec<String> = serde_json::from_str(
        entry
            .v1_ddl_json
            .ok_or_else(|| Error::engine("receiver shape has no frozen v1 DDL"))?,
    )?;
    if entry.family != Family::V1
        || hex::encode(Sha256::digest(statements.join("\n;\n").as_bytes())) != entry.schema_sha256
    {
        return Err(Error::engine("receiver frozen DDL evidence differs"));
    }
    Ok(statements)
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
fn reference_95_ddl() -> Result<Vec<String>> {
    frozen_v1_ddl(v1(95, V1_95).expect("frozen95 entry"))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    V1,
    KernelV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Shape {
    pub family: Family,
    pub engine_schema: i64,
    pub schema_sha256: String,
    pub reader_format: u32,
}

pub struct Entry {
    pub family: Family,
    pub engine_schema: i64,
    pub schema_sha256: &'static str,
    pub reader_format: u32,
    pub wire_revisions: &'static [u64],
    /// Directed transition evidence. Equal shapes need no edge.
    pub predecessors: &'static [Predecessor],
    pub observation_envelope: bool,
    pub v1_ddl_json: Option<&'static str>,
    /// Exact nullable columns allowed on the shared prefix, by table.
    pub nullable_prefix_columns: &'static [(&'static str, &'static [&'static str])],
    pub required_indexes: &'static [&'static str],
}

pub struct Predecessor {
    pub engine_schema: i64,
    pub schema_sha256: &'static str,
    pub reader_format: u32,
}

const OBSERVATION_COLUMNS: &[&str] = &["observed_act", "observed_basis", "caller_write_ordinal"];

pub const REGISTRY: &[Entry] = &[
    Entry {
        family: Family::V1,
        engine_schema: 94,
        schema_sha256: V1_94,
        reader_format: 1,
        wire_revisions: &[8],
        predecessors: &[],
        observation_envelope: false,
        v1_ddl_json: Some(include_str!("shapes/engine94-ddl.json")),
        nullable_prefix_columns: &[],
        required_indexes: &[],
    },
    Entry {
        family: Family::V1,
        engine_schema: 95,
        schema_sha256: V1_95,
        reader_format: 1,
        wire_revisions: &[8],
        predecessors: &[Predecessor {
            engine_schema: 94,
            schema_sha256: V1_94,
            reader_format: 1,
        }],
        observation_envelope: true,
        v1_ddl_json: Some(include_str!("shapes/engine95-ddl.json")),
        nullable_prefix_columns: &[("content_events", OBSERVATION_COLUMNS)],
        required_indexes: &[],
    },
    Entry {
        family: Family::KernelV2,
        engine_schema: 94,
        schema_sha256: V2_94,
        reader_format: 1,
        wire_revisions: &[8],
        predecessors: &[],
        observation_envelope: false,
        v1_ddl_json: None,
        nullable_prefix_columns: &[],
        required_indexes: &[],
    },
    Entry {
        family: Family::KernelV2,
        engine_schema: 95,
        schema_sha256: V2_95,
        reader_format: 1,
        wire_revisions: &[8],
        predecessors: &[Predecessor {
            engine_schema: 94,
            schema_sha256: V2_94,
            reader_format: 1,
        }],
        observation_envelope: true,
        v1_ddl_json: None,
        nullable_prefix_columns: &[("content_events", OBSERVATION_COLUMNS)],
        required_indexes: &[APP_INDEX],
    },
    // Terminal rows are incompatible with format 1. Upgrade via FULL only;
    // no predecessor edge permits a delta across this semantic boundary.
    Entry {
        family: Family::KernelV2,
        engine_schema: 94,
        schema_sha256: V2_TERMINAL_94,
        reader_format: 2,
        wire_revisions: &[8],
        predecessors: &[],
        observation_envelope: false,
        v1_ddl_json: None,
        nullable_prefix_columns: &[],
        required_indexes: &[],
    },
    Entry {
        family: Family::KernelV2,
        engine_schema: 95,
        schema_sha256: V2_TERMINAL_95,
        reader_format: 2,
        wire_revisions: &[8],
        predecessors: &[Predecessor {
            engine_schema: 94,
            schema_sha256: V2_TERMINAL_94,
            reader_format: 2,
        }],
        observation_envelope: true,
        v1_ddl_json: None,
        nullable_prefix_columns: &[("content_events", OBSERVATION_COLUMNS)],
        required_indexes: &[APP_INDEX],
    },
];

impl Entry {
    /// A non-probe binary can parse a known v2 head to disclose why it must
    /// pause; that is not admission/serving capability and must not advertise it.
    pub fn receiver_enabled(&self) -> bool {
        self.family == Family::V1 || cfg!(feature = "v2-kernel-probe")
    }

    pub fn shape(&self) -> Shape {
        Shape {
            family: self.family,
            engine_schema: self.engine_schema,
            schema_sha256: self.schema_sha256.into(),
            reader_format: self.reader_format,
        }
    }
}

pub fn lookup(shape: &Shape) -> Option<&'static Entry> {
    REGISTRY.iter().find(|entry| entry.shape() == *shape)
}

pub fn v1(version: i64, ddl: &str) -> Option<&'static Entry> {
    REGISTRY
        .iter()
        .find(|e| e.family == Family::V1 && e.engine_schema == version && e.schema_sha256 == ddl)
}

pub fn v2(reader_format: u32, schema: &str) -> Option<&'static Entry> {
    REGISTRY.iter().find(|e| {
        e.family == Family::KernelV2
            && e.reader_format == reader_format
            && e.schema_sha256 == schema
    })
}

pub fn follows(before: &Entry, after: &Entry) -> bool {
    before.family == after.family
        && (before.shape() == after.shape()
            || after.predecessors.iter().any(|predecessor| {
                predecessor.engine_schema == before.engine_schema
                    && predecessor.schema_sha256 == before.schema_sha256
                    && predecessor.reader_format == before.reader_format
            }))
}

pub(crate) fn check_selection(selected: Option<&Shape>, actual: &Entry) -> Result<()> {
    match selected {
        Some(shape) if shape == &actual.shape() => Ok(()),
        None if !actual.observation_envelope => Ok(()),
        _ => Err(Error::engine(
            "missing or conflicting selected receiver shape",
        )),
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Advertisement {
    version: u32,
    shapes: Vec<Shape>,
}

pub fn advertisement() -> String {
    serde_json::to_string(&Advertisement {
        version: 1,
        shapes: REGISTRY
            .iter()
            .filter(|entry| entry.receiver_enabled())
            .map(Entry::shape)
            .collect(),
    })
    .expect("static receiver shapes serialize")
}

/// Shared producer gate for B and subsequent releases. Never infer capability
/// from an account, a fleet default, a version number, or another request.
pub fn negotiate<'a>(producer: &'a Shape, header: Option<&str>) -> Result<&'a Shape> {
    let refused = || Error::engine(UPDATE_REQUIRED);
    let header = header.filter(|h| h.len() <= 4096).ok_or_else(refused)?;
    let advertisement: Advertisement = serde_json::from_str(header).map_err(|_| refused())?;
    if advertisement.version != 1
        || advertisement.shapes.len() > 16
        || lookup(producer).is_none()
        || !advertisement.shapes.contains(producer)
    {
        return Err(refused());
    }
    Ok(producer)
}

pub(crate) fn manifest(
    manifest: &crate::standby_snapshot::StandbySnapshotManifest,
) -> Option<&'static Entry> {
    match &manifest.kernel_v2 {
        Some(k) => v2(k.reader_format, &k.schema_sha256),
        None => v1(manifest.engine.schema_version, &manifest.engine.ddl_sha256),
    }
}

pub(crate) async fn on(conn: &mut sqlx::SqliteConnection) -> Result<&'static Entry> {
    let application_id: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *conn)
        .await?;
    if application_id == crate::db::V2_APPLICATION_ID {
        #[cfg(any(test, feature = "v2-kernel-probe"))]
        {
            let k = super::kernel_v2::coordinates(conn).await?;
            return v2(k.reader_format, &k.schema_sha256)
                .ok_or_else(|| Error::engine("unsupported receiver owned shape"));
        }
        #[cfg(not(any(test, feature = "v2-kernel-probe")))]
        return Err(Error::engine("kernel-v2 receiver requires v2-kernel-probe"));
    }
    crate::db::qualify_receiver_shape_on(conn).await
}

/// Complete inventories, including empty sections, are evidence; a column
/// intersection is not. The references never open or modify a serving copy.
pub(crate) async fn check_v1_cut(
    cut: &super::act_cut::AuthorityActCut,
    entry: &Entry,
) -> Result<()> {
    use sqlx::Connection;
    use std::collections::BTreeMap;
    type Inventory = BTreeMap<String, (Vec<crate::interchange::Column>, Vec<String>)>;
    static REFERENCES: tokio::sync::OnceCell<Vec<(&'static Entry, Inventory)>> =
        tokio::sync::OnceCell::const_new();
    let references = REFERENCES
        .get_or_try_init(|| async {
            let mut references = Vec::new();
            for registered in REGISTRY.iter().filter(|shape| shape.family == Family::V1) {
                let mut reference = sqlx::SqliteConnection::connect("sqlite::memory:").await?;
                for statement in frozen_v1_ddl(registered)? {
                    sqlx::query(&statement).execute(&mut reference).await?;
                }
                let mut inventory = Inventory::new();
                for table in crate::act::ACT_STAMPED_TABLES
                    .iter()
                    .chain(super::companion_closure::COMPANION_TABLES.iter())
                {
                    inventory.insert(
                        (*table).into(),
                        crate::interchange::section_shape(&mut reference, table).await?,
                    );
                }
                reference.close().await?;
                references.push((registered, inventory));
            }
            Ok::<_, Error>(references)
        })
        .await?;
    let expected = &references
        .iter()
        .find(|(shape, _)| shape.shape() == entry.shape())
        .ok_or_else(|| Error::engine("selected shape has no frozen cut inventory"))?
        .1;
    super::receiver::require_authority_lanes(
        &cut.sections()
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        &cut.companions()
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
    )?;
    for section in cut.sections().iter().chain(cut.companions()) {
        let (columns, pk) = expected
            .get(&section.name)
            .ok_or_else(|| Error::engine("unknown receiver cut section"))?;
        if &section.columns != columns || &section.primary_key != pk {
            return Err(Error::engine(
                "receiver cut is not the selected exact dialect",
            ));
        }
        crate::interchange::validate_section_shape(section)?;
        if !entry.observation_envelope {
            // Recovery receipts are system codec positions, never arbitrary
            // authored JSON. Keep nested95 metadata/arguments out of legacy94
            // even when a producer has omitted the optional HTTP selection.
            for (index, column) in columns.iter().enumerate() {
                if !["receipt_json", "response_json", "request_json"]
                    .contains(&column.name.as_str())
                {
                    continue;
                }
                for row in &section.rows {
                    if let crate::interchange::Cell::Text(bytes) = &row[index] {
                        let value: serde_json::Value = serde_json::from_str(bytes)?;
                        let new_arguments = column.name == "request_json"
                            && ["observed", "observed_act", "observed_basis"]
                                .iter()
                                .any(|key| value.get(*key).is_some());
                        if new_arguments || has_95_receipt_metadata(&value) {
                            return Err(Error::engine(
                                "95 recovery codec cannot use the legacy94 dialect",
                            ));
                        }
                    }
                }
            }
        }
        if !entry.observation_envelope && section.name == "content_events" {
            let payload = columns.iter().position(|c| c.name == "payload").unwrap();
            let kind = columns.iter().position(|c| c.name == "type").unwrap();
            for row in &section.rows {
                if let (
                    crate::interchange::Cell::Text(kind),
                    crate::interchange::Cell::Text(payload),
                ) = (&row[kind], &row[payload])
                {
                    let value: serde_json::Value = serde_json::from_str(payload)?;
                    if kind == "kernel.app_action_recorded.v1"
                        && value.get("caller_write_ordinal").is_some()
                    {
                        return Err(Error::engine(
                            "95 app action cannot use the legacy 94 dialect",
                        ));
                    }
                    if kind == WRITE_RECEIPT_EVENT {
                        if let Some(receipt) = value
                            .get("receipt_json")
                            .and_then(serde_json::Value::as_str)
                        {
                            let receipt: serde_json::Value = serde_json::from_str(receipt)?;
                            if has_95_receipt_metadata(&receipt) {
                                return Err(Error::engine(
                                    "95 receipt cannot use the legacy 94 dialect",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn has_95_receipt_metadata(value: &serde_json::Value) -> bool {
    [
        "observed_act",
        "observed_basis",
        "caller_write_ordinal",
        "as_of_act",
        "freshness_coordinate",
        "workspace_coordinate",
    ]
    .iter()
    .any(|key| value.get(*key).is_some())
        || ["record", "receipt", "result"]
            .iter()
            .any(|key| value.get(*key).is_some_and(has_95_receipt_metadata))
        || value
            .get("results")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.iter().any(has_95_receipt_metadata))
}

/// Only known system receipt positions, never authored bodies/facets or
/// arbitrary recursive JSON. A preserves this data internally, without
/// publishing the future observation/coordinate API in local history.
pub(crate) fn scrub_receipt_metadata(value: &mut serde_json::Value) -> bool {
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    for key in [
        "observed_act",
        "observed_basis",
        "caller_write_ordinal",
        "as_of_act",
        "freshness_coordinate",
        "workspace_coordinate",
    ] {
        changed |= object.remove(key).is_some();
    }
    for key in ["record", "receipt", "result"] {
        if let Some(inner) = object.get_mut(key) {
            changed |= scrub_receipt_metadata(inner);
        }
    }
    if let Some(items) = object
        .get_mut("results")
        .and_then(serde_json::Value::as_array_mut)
    {
        for inner in items {
            changed |= scrub_receipt_metadata(inner);
        }
    }
    changed
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn exact_registry_and_directed_transitions() {
        for entry in REGISTRY {
            assert_eq!(
                REGISTRY
                    .iter()
                    .filter(|other| other.shape() == entry.shape())
                    .count(),
                1
            );
            for predecessor in entry.predecessors {
                assert!(REGISTRY.iter().any(|other| other.family == entry.family
                    && other.engine_schema == predecessor.engine_schema
                    && other.schema_sha256 == predecessor.schema_sha256
                    && other.reader_format == predecessor.reader_format));
            }
            if entry.family == Family::V1 {
                assert!(!frozen_v1_ddl(entry).unwrap().is_empty());
            }
            assert!(lookup(&entry.shape()).is_some());
            assert_eq!(
                negotiate(&entry.shape(), Some(&advertisement())).is_ok(),
                entry.receiver_enabled()
            );
            assert!(negotiate(&entry.shape(), None).is_err());
            let mut drift = entry.shape();
            drift.schema_sha256 = "f".repeat(64);
            assert!(lookup(&drift).is_none());
            drift = entry.shape();
            drift.engine_schema = 96;
            assert!(lookup(&drift).is_none());
        }
        for family in [Family::V1, Family::KernelV2] {
            let old = REGISTRY
                .iter()
                .find(|e| e.family == family && e.engine_schema == 94)
                .unwrap();
            let new = REGISTRY
                .iter()
                .find(|e| e.family == family && e.engine_schema == 95)
                .unwrap();
            assert!(follows(old, new));
            assert!(!follows(new, old));
        }
    }

    #[test]
    fn compiled_emission_is_an_exact_registry_member() {
        assert_eq!(
            WRITE_RECEIPT_EVENT,
            crate::kernel::mcp_write_receipts::EVENT
        );
        assert!(v1(
            crate::CURRENT_ENGINE_SCHEMA_VERSION,
            crate::schema::FROZEN_DDL_SHA256
        )
        .is_some());
        assert!(v2(
            super::super::kernel_v2::KERNEL_V2_READER_FORMAT,
            super::super::kernel_v2::KERNEL_V2_READER_SCHEMA_SHA256
        )
        .is_some());
    }

    #[test]
    fn frozen_95_ddl_is_independent_of_emission() {
        assert!(reference_95_ddl().is_ok());
        assert_eq!(crate::schema::ddl_sha256(), V1_94);
        assert_eq!(crate::CURRENT_ENGINE_SCHEMA_VERSION, 94);
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) async fn upgrade_fixture_to_95(db: &crate::db::Db) {
        // Only disposable qualification fixtures. Production must obtain a
        // fully verified FULL; serving must never run this preparation.
        for ddl in [
            "ALTER TABLE content_events ADD COLUMN observed_act INTEGER",
            "ALTER TABLE content_events ADD COLUMN observed_basis TEXT",
            "ALTER TABLE content_events ADD COLUMN caller_write_ordinal INTEGER",
            CALLER_INDEX,
            APP_INDEX,
        ] {
            sqlx::query(ddl).execute(db.write_pool()).await.unwrap();
        }
    }

    #[cfg(feature = "v2-kernel-probe")]
    #[tokio::test]
    async fn frozen_owned_shapes_and_exact_marking_normalization() {
        for version in [94, 95] {
            let (db, _) =
                crate::kernel::create_v2_database(":memory:", "account", "Owner", "fixture-owner")
                    .await
                    .unwrap();
            if version == 95 {
                upgrade_fixture_to_95(&db).await;
            }
            let mut conn = db.write_pool().acquire().await.unwrap();
            let before = super::super::kernel_v2::coordinates(&mut conn)
                .await
                .unwrap();
            let expected = if version == 94 { V2_94 } else { V2_95 };
            assert_eq!(before.schema_sha256, expected);
            drop(conn);
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            crate::kernel::stored_visibility::install_on(&mut tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let mut conn = db.write_pool().acquire().await.unwrap();
            let marked = super::super::kernel_v2::coordinates(&mut conn)
                .await
                .unwrap();
            assert_eq!(
                before, marked,
                "exact marking DDL must not change receiver coordinates"
            );
            sqlx::query("CREATE TABLE p_receiver_drift(untrusted INTEGER)")
                .execute(&mut *conn)
                .await
                .unwrap();
            assert!(
                super::super::kernel_v2::coordinates(&mut conn)
                    .await
                    .is_err(),
                "unregistered objects cannot be normalized away"
            );
            drop(conn);
            db.close().await;
        }
    }
}
