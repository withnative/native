//! Read-only native body identity. Neither projection nor birth is authority.
use super::KernelRecordView;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BodyEventEvidence {
    pub id: String,
    pub seq: i64,
}
#[derive(Clone, Debug)]
pub(crate) struct ProjectedBody {
    pub body: Option<String>,
    pub event: Option<BodyEventEvidence>,
}

/// Common foundation proof ONLY. No birth, authority, scope or body budget.
/// The foundation retains its existing view-text/presence compatibility check.
pub(crate) async fn projection_on(
    conn: &mut SqliteConnection,
    record: &str,
) -> Result<ProjectedBody> {
    let stored: Option<(String, i64, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT b.body,b.event_seq,e.id,CASE e.type WHEN 'kernel.body_set.v1' THEN json_extract(e.payload,'$.body') WHEN 'kernel.import_state.v1' THEN json_extract(e.payload,'$.state.body') WHEN 'kernel.import_state_delta.v1' THEN json_extract(e.payload,'$.snapshot.state.body') END FROM kernel_record_bodies b LEFT JOIN main.content_events e ON e.seq=b.event_seq AND e.record_id=b.record_id WHERE b.record_id=?"
    ).bind(record).fetch_optional(&mut *conn).await?;
    match stored {
        Some((body, seq, id, event_body)) => {
            if event_body.as_deref() != Some(body.as_str()) {
                return Err(Error::engine(
                    "kernel body event bytes disagree with projection",
                ));
            }
            let id = id
                .filter(|id| !id.is_empty())
                .filter(|_| seq > 0)
                .ok_or_else(|| Error::engine("kernel body event evidence missing"))?;
            Ok(ProjectedBody {
                body: Some(body),
                event: Some(BodyEventEvidence { id, seq }),
            })
        }
        None => Ok(ProjectedBody {
            body: None,
            event: None,
        }),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NativeBodyBasis {
    pub record_id: String,
    pub birth: BodyEventEvidence,
    pub record_revision: i64,
    pub body: Option<String>,
    pub digest: String,
    pub event: Option<BodyEventEvidence>,
}

/// Only the inactive current-read lane demands birth and strict presence.
/// Native creation is proved by the actual projector's created_seq. Imported
/// birth forms remain unsupported here until independently qualified.
pub(crate) async fn read_body_basis_on(
    conn: &mut SqliteConnection,
    view: &KernelRecordView,
) -> Result<NativeBodyBasis> {
    let projection = projection_on(conn, &view.id).await?;
    if projection.body != view.body {
        return Err(Error::engine(
            "current body read: projection presence/bytes disagree",
        ));
    }
    let birth: Option<(String, i64)> = sqlx::query_as(
        "SELECT e.id,e.seq FROM kernel_records r JOIN main.content_events e ON e.seq=r.created_seq AND e.record_id=r.id WHERE r.id=? AND e.type='kernel.record_created.v1'"
    ).bind(&view.id).fetch_optional(&mut *conn).await?;
    let (id, seq) = birth
        .filter(|(id, seq)| !id.is_empty() && *seq > 0)
        .ok_or_else(|| {
            Error::engine("current body read: unsupported or missing record birth evidence")
        })?;
    let digest = hex::encode(Sha256::digest(
        projection.body.as_deref().unwrap_or_default().as_bytes(),
    ));
    Ok(NativeBodyBasis {
        record_id: view.id.clone(),
        birth: BodyEventEvidence { id, seq },
        record_revision: view.revision,
        body: projection.body,
        digest,
        event: projection.event,
    })
}
