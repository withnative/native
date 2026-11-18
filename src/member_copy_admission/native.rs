//! Native lifecycle admission. Never opens NKM2 with a v1/canonical Db.
use super::*;
use crate::{
    member_copy_kernel_v2::profile::AdmittedMemberFile, member_copy_transport::MemberCopyContext,
};

fn rejected() -> AdmissionError {
    AdmissionError::ManifestRejected {
        detail: "native member admission refused".into(),
    }
}

pub(crate) fn verify(
    root: &Path,
    path: &Path,
    json: &[u8],
    context: &MemberCopyContext,
    installed: Option<&InstalledGeneration>,
    expected: &ExpectedFooting,
) -> Result<(AdmittedGeneration, AdmittedMemberFile), AdmissionError> {
    let facts = validate_manifest(json)?;
    if facts.origin_database_id != expected.origin_database_id {
        return Err(AdmissionError::OriginMismatch);
    }
    if facts.scope_ref != expected.scope_ref || facts.scope_ref != context.scope_ref() {
        return Err(AdmissionError::AccountMismatch);
    }
    if facts.consumer != expected.consumer {
        return Err(AdmissionError::ConsumerMismatch);
    }
    // Must precede file copying, verification and promotion, including when an
    // old pair is internally consistent and contains a valid file identity.
    refuse_rollback(installed, &facts)?;
    let manifest: ReplicaGenerationManifest =
        serde_json::from_slice(json).map_err(|_| rejected())?;
    check_regular_file(path)?;
    refuse_sidecars(path)?;
    let file = AdmittedMemberFile::open(path, root, context, &manifest).map_err(|_| rejected())?;
    Ok((
        AdmittedGeneration {
            generation_id: facts.generation_id.clone(),
            scope_ref: facts.scope_ref,
            ordinal: facts.ordinal,
            content_digest: facts.content_digest,
            cut_at: facts.captured_at,
            schema_incomplete_for: facts.schema_incomplete_for,
            generation_dir: root.join(CACHE_DIR_NAME).join(facts.generation_id),
        },
        file,
    ))
}

pub(crate) fn admit(
    root: &Path,
    staged: &Path,
    json: &[u8],
    context: &MemberCopyContext,
    installed: Option<&InstalledGeneration>,
    expected: &ExpectedFooting,
    lifecycle: &mut MemberCopyLifecycle,
) -> Result<AdmittedGeneration, AdmissionError> {
    if !lifecycle.status().can_read() {
        return Err(not_admitted(&lifecycle.status()));
    }
    let (admitted, file) = verify(root, staged, json, context, installed, expected)?;
    let snapshot = admitted.generation_dir.join(SNAPSHOT_FILENAME);
    if snapshot.exists() {
        // Redelivery cannot overwrite a held generation, even with equal size.
        verify(root, &snapshot, json, context, installed, expected)?;
    } else {
        fs::create_dir_all(&admitted.generation_dir).map_err(|_| rejected())?;
        let temporary = admitted.generation_dir.join("snapshot.tmp");
        file.copy_to(&temporary).map_err(|_| rejected())?;
        fs::rename(temporary, &snapshot).map_err(|_| rejected())?;
        File::open(&admitted.generation_dir)
            .and_then(|d| d.sync_all())
            .map_err(|_| rejected())?;
    }
    write_pointer(root, &admitted.generation_id)?;
    lifecycle
        .purge_superseded(
            &admitted.generation_id,
            &crate::member_copy_lifecycle::NoFail,
        )
        .map_err(|_| rejected())?;
    let status = lifecycle
        .mark_refreshed(admitted.cut_at.clone())
        .map_err(|_| rejected())?;
    if !matches!(status, CopyStatus::Ready { .. }) {
        return Err(not_admitted(&status));
    }
    Ok(admitted)
}
