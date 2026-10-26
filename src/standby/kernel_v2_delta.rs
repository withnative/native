//! A separate, closed wire format for kernel-v2 events; no v1 section relabelling.
use super::kernel_v2::{self, KernelGeneration};
use crate::interchange::{ConflictMode, Section, SelectionBind};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqliteConnection;

const CONTRACT: &str = "native.standby-kernel-v2-delta.v1";
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelDelta {
    pub contract: String,
    pub version: u32,
    pub origin_database_id: String,
    pub from_exclusive_act: i64,
    pub head: KernelDeltaHead,
    pub sections: Vec<Section>,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KernelDeltaHead {
    pub generation: KernelGeneration,
    pub projection_sha256: String,
}
impl std::ops::Deref for KernelDeltaHead {
    type Target = KernelGeneration;
    fn deref(&self) -> &Self::Target {
        &self.generation
    }
}

impl KernelDelta {
    fn digest(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("content_sha256");
        Ok(crate::standby_snapshot::sha256_bytes(&serde_jcs::to_vec(
            &value,
        )?))
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_jcs::to_vec(self)?)
    }
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        let delta: Self = serde_json::from_slice(bytes)?;
        if delta.bytes()? != bytes
            || delta.contract != CONTRACT
            || delta.version != 1
            || delta.digest()? != delta.content_sha256
        {
            return Err(Error::engine(
                "invalid kernel-v2 delta contract/canonical bytes/digest",
            ));
        }
        delta.head.validate()?;
        if delta.head.projection_sha256.len() != 64
            || !delta
                .head
                .projection_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::engine("invalid kernel-v2 projection digest"));
        }
        if !crate::identity::is_database_id(&delta.origin_database_id)
            || delta.from_exclusive_act < 0
            || delta.from_exclusive_act > delta.head.head_act
            || delta
                .sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                != [
                    "content_events",
                    "meta_events",
                    "kernel_blobs",
                    "content_event_causal_frontier",
                ]
        {
            return Err(Error::engine("invalid kernel-v2 delta bounds or inventory"));
        }
        for section in &delta.sections {
            if section.format != crate::interchange::SECTION_FORMAT
                || section.revision != crate::interchange::REVISION
            {
                return Err(Error::engine("kernel-v2 delta section codec mismatch"));
            }
            crate::interchange::validate_section_shape(section)?;
        }
        Ok(delta)
    }
}

pub(crate) const MAX_BLOB_INVENTORY: usize = 65_536;

pub(crate) fn validate_blob_inventory(inventory: &[String]) -> Result<()> {
    if inventory.len() > MAX_BLOB_INVENTORY
        || !inventory.windows(2).all(|p| p[0] < p[1])
        || inventory.iter().any(|sha| {
            sha.len() != 64
                || !sha
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(Error::engine("invalid kernel-v2 base blob inventory"));
    }
    Ok(())
}

pub(crate) async fn cut(
    conn: &mut SqliteConnection,
    from: i64,
    inventory: &[String],
) -> Result<KernelDelta> {
    validate_blob_inventory(inventory)?;
    let head = kernel_v2::coordinates(conn).await?;
    let origin_database_id = kernel_v2::origin(conn, &head).await?;
    if from < 0 || from > head.head_act {
        return Err(Error::engine("kernel-v2 delta lower bound beyond head"));
    }
    let mut sections = Vec::new();
    for name in ["content_events", "meta_events"] {
        sections.push(
            crate::interchange::export_act_range_section(conn, name, from, head.head_act).await?,
        );
    }
    // The consumer names only verified CAS keys, never byte payloads. This also
    // finds unbound blobs added without advancing the event/act head.
    sections.push(
        crate::interchange::export_where_section(
            conn,
            "kernel_blobs",
            "sha256 NOT IN (SELECT value FROM json_each(?))",
            &[SelectionBind::Text(serde_json::to_string(inventory)?)],
        )
        .await?,
    );
    sections.push(
        crate::interchange::export_where_section(
            conn,
            "content_event_causal_frontier",
            "event_id IN (SELECT id FROM content_events WHERE act > ? AND act <= ?)",
            &[
                SelectionBind::Integer(from),
                SelectionBind::Integer(head.head_act),
            ],
        )
        .await?,
    );
    let mut delta = KernelDelta {
        contract: CONTRACT.into(),
        version: 1,
        origin_database_id,
        from_exclusive_act: from,
        head: KernelDeltaHead {
            generation: head,
            projection_sha256: crate::kernel::projection_dump::dump_on(conn).await?.sha256,
        },
        sections,
        content_sha256: String::new(),
    };
    delta.content_sha256 = delta.digest()?;
    KernelDelta::parse(&delta.bytes()?)
}

// Only the authenticated transport can construct this witness.
pub(crate) struct TrustedKernelDelta {
    delta: KernelDelta,
}
impl TrustedKernelDelta {
    pub(super) fn from_authenticated(
        witness: super::delta_transport::AuthenticatedKernelDelta,
    ) -> Self {
        Self {
            delta: witness.into_delta(),
        }
    }
    pub(crate) fn delta(&self) -> &KernelDelta {
        &self.delta
    }
}

pub(crate) async fn apply(db: &crate::Db, trusted: &TrustedKernelDelta) -> Result<()> {
    let delta = trusted.delta();
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let before = kernel_v2::coordinates(&mut tx).await?;
    let origin = kernel_v2::origin(&mut tx, &before).await?;
    if before.head_act != delta.from_exclusive_act
        || origin != delta.origin_database_id
        || before.genesis_event_id != delta.head.genesis_event_id
        || before.schema_sha256 != delta.head.schema_sha256
    {
        return Err(Error::engine("kernel-v2 delta fails base continuity"));
    }
    for section in &delta.sections {
        crate::interchange::validate_destination_section(&mut tx, section).await?;
    }
    for (section, old_seq) in delta.sections[..2]
        .iter()
        .zip([before.content_event_seq, before.meta_event_seq])
    {
        let seq_index = section
            .columns
            .iter()
            .position(|c| c.name == "seq")
            .ok_or_else(|| Error::engine("event section lacks sequence"))?;
        let act_index = section
            .columns
            .iter()
            .position(|c| c.name == "act")
            .ok_or_else(|| Error::engine("event section lacks act"))?;
        for row in &section.rows {
            if !matches!(row[seq_index],crate::interchange::Cell::Integer(seq) if seq > old_seq)
                || !matches!(row[act_index],crate::interchange::Cell::Integer(act) if act > before.head_act && act <= delta.head.head_act)
            {
                return Err(Error::engine(
                    "kernel-v2 event lies outside the advertised tail",
                ));
            }
        }
    }
    let blobs = &delta.sections[2];
    let sha_column = blobs
        .columns
        .iter()
        .position(|c| c.name == "sha256")
        .ok_or_else(|| Error::engine("blob section lacks digest"))?;
    let mut added_blobs = Vec::new();
    for row in &blobs.rows {
        let crate::interchange::Cell::Text(sha) = &row[sha_column] else {
            return Err(Error::engine("blob digest is not text"));
        };
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_blobs WHERE sha256=?)")
                .bind(sha)
                .fetch_one(&mut *tx)
                .await?;
        if !exists {
            added_blobs.push(sha.clone());
        }
    }
    for section in &delta.sections {
        crate::interchange::ingest_section_rows(
            &mut tx,
            section,
            if ["kernel_blobs", "content_event_causal_frontier"].contains(&section.name.as_str()) {
                ConflictMode::ImmutableAllowIdentical
            } else {
                ConflictMode::ActLogRefuseExisting
            },
        )
        .await?;
    }
    // The admitted base already verified its existing immutable bytes. Check
    // only rows actually inserted by this delta, one at a time.
    for digest in added_blobs {
        let (bytes, size): (Vec<u8>, i64) =
            sqlx::query_as("SELECT bytes,size_bytes FROM kernel_blobs WHERE sha256=?")
                .bind(&digest)
                .fetch_one(&mut *tx)
                .await?;
        if size != bytes.len() as i64 || crate::standby_snapshot::sha256_bytes(&bytes) != digest {
            return Err(Error::engine("kernel-v2 delta blob checksum mismatch"));
        }
    }
    // Validate contiguous whole acts and exact sequence tails before replay.
    let (acts,lo,hi): (i64,Option<i64>,Option<i64>) = sqlx::query_as("SELECT COUNT(DISTINCT act),MIN(act),MAX(act) FROM (SELECT act FROM content_events WHERE act>? UNION ALL SELECT act FROM meta_events WHERE act>?)")
        .bind(before.head_act).bind(before.head_act).fetch_one(&mut *tx).await?;
    if acts != delta.head.head_act - before.head_act
        || (acts > 0 && (lo != Some(before.head_act + 1) || hi != Some(delta.head.head_act)))
    {
        return Err(Error::engine("kernel-v2 delta has an act gap"));
    }
    for (table, old, new) in [
        (
            "content_events",
            before.content_event_seq,
            delta.head.content_event_seq,
        ),
        (
            "meta_events",
            before.meta_event_seq,
            delta.head.meta_event_seq,
        ),
    ] {
        let (count, min, max): (i64, Option<i64>, Option<i64>) = sqlx::query_as(&format!(
            "SELECT COUNT(*),MIN(seq),MAX(seq) FROM {table} WHERE seq>?"
        ))
        .bind(old)
        .fetch_one(&mut *tx)
        .await?;
        if new < old
            || count != new - old
            || (count > 0 && (min != Some(old + 1) || max != Some(new)))
        {
            return Err(Error::engine("kernel-v2 delta has a sequence gap"));
        }
    }
    sqlx::query("UPDATE act_state SET next_act=? WHERE singleton=1")
        .bind(delta.head.head_act)
        .execute(&mut *tx)
        .await?;
    if acts > 0 {
        crate::kernel::replay_projection_tail_on(
            &mut tx,
            before.content_event_seq,
            before.meta_event_seq,
        )
        .await?;
    }
    if kernel_v2::coordinates(&mut tx).await? != delta.head.generation {
        return Err(Error::engine("kernel-v2 delta postcondition mismatch"));
    }
    if crate::kernel::projection_dump::dump_on(&mut tx)
        .await?
        .sha256
        != delta.head.projection_sha256
    {
        return Err(Error::engine("kernel_v2_projection_divergence"));
    }
    let violations: i64 =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
            .fetch_one(&mut *tx)
            .await?;
    if violations != 0 {
        return Err(Error::engine("kernel-v2 delta foreign-key violation"));
    }
    tx.commit().await?;
    Ok(())
}
