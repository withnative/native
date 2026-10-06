//! Serialized core member-copy refresh driver (D2; contract c323277 rev 10
//! §1.3, §4.3, §6.1, §7.1; consumer da0a471).
//!
//! Owns one [`MemberCopyServing`] and one injected [`MemberCopyTransport`]
//! and drives request -> (optional) bounded download -> verify -> admit. It
//! preserves every typed outcome, never sleeps, re-requests at most once on a
//! `Restart`, and removes its staging file on every failure. It performs no
//! HTTP and names no hosted crate: the authenticated adapter is a later
//! increment at the existing `held` boundary.
//!
//! Footing discipline: the scope is adopted only from a typed `Current`/
//! `Replace` answer through the sealed token, never from the manifest or a
//! config/caller string. A scope change purges (and so deletes the durable
//! binding) *before* staging, and the owner refuses a rebind over a held
//! generation. SHA-256 **and** size are verified against the manifest before
//! admission.

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::export::BINARY_MAX_CHUNK_BYTES;
use crate::member_copy_admission::AdmissionError;
use crate::member_copy_lifecycle::{CopyStatus, ReconnectAnswer, RemovedCause};
use crate::member_copy_serving::{MemberCopyServing, ReceiptEligibility};
use crate::member_copy_transport::{
    CredentialSelection, MemberCopyAnswer, MemberCopyChunk, MemberCopyContext,
    MemberCopyDownloadRefusal, MemberCopyRequest, MemberCopyTransport,
};
use crate::replica_generation::ReplicaGenerationManifest;
use crate::standby_snapshot::StandbyConsumerIdentity;

const CONFIG_CONTRACT: &str = "native.member-copy-device.v1";
const PROTOCOL_VERSION: u32 = 1;

/// Local, non-secret configuration that binds one member-copy installation to
/// its hosted route, canonical origin and local copy root. The credential is
/// a rotatable bearer read per attempt by the HTTP adapter; it is never
/// persisted in the copy.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCopyDeviceConfig {
    pub contract: String,
    pub version: u32,
    /// Exact hosted origin; `https`, or `http` only on loopback.
    pub hosted_origin: String,
    /// The hosted route database id used in the wire path (exact route).
    pub hosted_route_database_id: String,
    /// Optional trusted canonical origin pin. `None` is ungrounded: the first
    /// authenticated success supplies it. A set value is only a constraint and
    /// must equal the authenticated origin.
    pub origin_database_id: Option<String>,
    pub credential_file: PathBuf,
    pub copy_root: PathBuf,
}

impl MemberCopyDeviceConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes).map_err(|error| {
            Error::engine(format!("invalid member copy device config: {error}"))
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract != CONFIG_CONTRACT || self.version != PROTOCOL_VERSION {
            return Err(Error::engine("invalid member copy device config contract"));
        }
        crate::standby::validate_exact_origin(&self.hosted_origin)?;
        let route = self.hosted_route_database_id.as_str();
        if route.is_empty()
            || route.trim() != route
            || route.len() > 256
            || route.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "member copy hosted route database id must contain 1..=256 non-control characters with no leading or trailing whitespace",
            ));
        }
        if let Some(origin) = &self.origin_database_id {
            if !crate::identity::is_database_id(origin) {
                return Err(Error::engine(
                    "member copy origin_database_id must be a valid Native database id",
                ));
            }
        }
        if !self.credential_file.is_absolute() {
            return Err(Error::engine(
                "member copy credential_file must be absolute",
            ));
        }
        validate_absolute_unambiguous(&self.copy_root, "copy_root")?;
        Ok(())
    }
}

/// `copy_root` must be an absolute, lexically unambiguous non-root path, so
/// the managed purge and authority lock always address one directory.
fn validate_absolute_unambiguous(path: &Path, field: &str) -> Result<()> {
    let mut components = path.components();
    let rooted = matches!(components.next(), Some(Component::RootDir));
    let mut normal = 0;
    let unambiguous = components.all(|component| match component {
        Component::Normal(_) => {
            normal += 1;
            true
        }
        Component::RootDir | Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
            false
        }
    });
    if !rooted || !unambiguous || normal == 0 {
        return Err(Error::engine(format!(
            "member copy {field} must be an absolute, lexically unambiguous non-root path"
        )));
    }
    Ok(())
}

/// The typed outcome of one refresh. `Unchanged` means the server confirmed
/// the already-served generation and no bytes moved; `Admitted` means a new
/// generation was verified and promoted; the rest preserve the copy-level
/// state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefreshDisposition {
    Unchanged,
    Admitted {
        generation_id: String,
    },
    Locked,
    Removed {
        cause: RemovedCause,
    },
    /// A `Restart` survived the single immediate re-request; nothing admitted.
    RestartDiscarded,
    /// A same-identity `Current` refreshed the receipt/schema markers without a
    /// redownload. The runtime must republish to capture the (possibly fresh)
    /// serving gate.
    MetadataRefreshed {
        generation_id: String,
        markers_changed: bool,
    },
    /// A bounded refresh exceeded its budget. Staging was cleaned and the owner
    /// was reconciled (recovered only under a currently validated selection, else
    /// quiesced with files kept).
    TimedOut,
}

/// Internal driver step: either a final disposition or a `Restart` signal
/// from a chunk window that the refresh loop must honour once.
enum Step {
    Done(RefreshDisposition),
    Restart,
}

/// A download failure: a `Restart` re-request signal, or a typed refusal.
enum DownloadError {
    Restart,
    Refused(Error),
}

/// One serialized refresh driver over a single copy root.
pub struct MemberCopyDriver {
    serving: MemberCopyServing,
    transport: Arc<dyn MemberCopyTransport>,
    config: MemberCopyDeviceConfig,
    consumer: StandbyConsumerIdentity,
}

impl MemberCopyDriver {
    /// Opens the owner unbound (recovering any durable authenticated binding)
    /// and pins the device consumer. No network call is made here.
    pub async fn new(
        config: MemberCopyDeviceConfig,
        consumer: StandbyConsumerIdentity,
        transport: Arc<dyn MemberCopyTransport>,
    ) -> Result<Self> {
        config.validate()?;
        consumer.validate_declaration()?;
        let server_origin = crate::member_copy_client::canonical_origin(&config.hosted_origin)?;
        let serving = MemberCopyServing::open_unbound_routed(
            &config.copy_root,
            config.origin_database_id.clone(),
            server_origin,
            config.hosted_route_database_id.clone(),
            consumer.clone(),
        )
        .await?;
        Ok(Self {
            serving,
            transport,
            config,
            consumer,
        })
    }

    pub fn serving(&self) -> &MemberCopyServing {
        &self.serving
    }

    pub fn config(&self) -> &MemberCopyDeviceConfig {
        &self.config
    }

    /// One refresh attempt. Reads the credential selection once (driver-owned)
    /// and reuses it for the POST and all chunks. No sleeps; at most one
    /// immediate `Restart` re-request; every failure leaves staging removed and
    /// the held generation (if any) intact and fail-closed.
    pub async fn refresh(&mut self) -> Result<RefreshDisposition> {
        // The actual once-per-attempt selection polices leases BEFORE the POST.
        // A missing/failed guarded read, or a selection that does not match the
        // held receipt, retires the old serving gate first (files are kept), so
        // a network failure cannot leave an old captured registry active.
        let selection = match self.read_current_selection() {
            Ok(selection) => selection,
            Err(error) => {
                self.serving.quiesce().await;
                return Err(error);
            }
        };
        if self.serving.held_receipt_eligibility(&selection) == ReceiptEligibility::NotServable {
            self.serving.quiesce().await;
        }
        let mut restart_used = false;
        loop {
            // One predicate for BOTH hints; excludes Unavailable/unbound.
            let (installed_generation_id, installed_scope_ref) = match self.serving.held_hints() {
                Some((generation_id, scope_ref)) => (Some(generation_id), Some(scope_ref)),
                None => (None, None),
            };
            let request = MemberCopyRequest {
                db_id: self.config.hosted_route_database_id.clone(),
                consumer: self.consumer.clone(),
                installed_generation_id,
                installed_scope_ref,
            };
            let attempt = self.transport.request(request, &selection).await?;
            let step = match attempt.answer {
                MemberCopyAnswer::Restart => Step::Restart,
                answer => self.apply_answer(answer, attempt.context).await?,
            };
            match step {
                Step::Done(disposition) => return Ok(disposition),
                Step::Restart => {
                    self.discard_staging();
                    if restart_used {
                        return Ok(RefreshDisposition::RestartDiscarded);
                    }
                    restart_used = true;
                }
            }
        }
    }

    /// Bounded variant of [`Self::refresh`] for the runtime's outer timeout.
    /// A single serialized refresh runs under `budget`; on elapse it cleans the
    /// managed incoming staging and reconciles the owner with the durable
    /// admission/lifecycle, returning [`RefreshDisposition::TimedOut`]. It
    /// recovers the held copy ONLY under the currently validated selection; a
    /// `NotServable` or missing/failed selection leaves the owner quiesced with
    /// files kept (never reactivates an old selection).
    pub async fn refresh_bounded(&mut self, budget: Duration) -> Result<RefreshDisposition> {
        self.refresh_until_deadline(tokio::time::sleep(budget))
            .await
    }

    /// Shared bounded-refresh core: races one serialized refresh against an
    /// injected `deadline`. Production passes `tokio::time::sleep(budget)`;
    /// tests pass a oneshot deadline fired only after the transport confirms a
    /// blocked request/read (and any rotation), so the timeout is deterministic
    /// and never fires before attempt entry. On elapse the owner is reconciled
    /// as in [`Self::on_timeout`].
    async fn refresh_until_deadline<D>(&mut self, deadline: D) -> Result<RefreshDisposition>
    where
        D: std::future::Future<Output = ()>,
    {
        let mut refresh = Box::pin(self.refresh());
        let mut deadline = Box::pin(deadline);
        tokio::select! {
            result = &mut refresh => result,
            _ = &mut deadline => {
                drop(refresh);
                self.on_timeout().await;
                Ok(RefreshDisposition::TimedOut)
            }
        }
    }

    async fn on_timeout(&mut self) {
        self.discard_staging();
        let eligible = match self.read_current_selection() {
            Ok(selection) => {
                self.serving.held_receipt_eligibility(&selection)
                    == ReceiptEligibility::HeldValidated
            }
            Err(_) => false,
        };
        // A selection that changed (or vanished) after attempt entry must retire
        // the active copy even if it is still serving; recovery is only allowed
        // under a currently validated selection.
        if !eligible {
            self.serving.quiesce().await;
            return;
        }
        if !self.serving.is_serving() {
            let _ = self.serving.recover_after_failed_candidate().await;
        }
        if !self.serving.is_serving() {
            self.serving.quiesce().await;
        }
    }

    /// Driver-owned, once-per-attempt guarded credential read.
    pub fn read_current_selection(&self) -> Result<CredentialSelection> {
        let bytes = crate::credential_file::read_guarded_credential(
            &self.config.credential_file,
            "member copy",
        )?;
        Ok(CredentialSelection::from_bearer(bytes))
    }

    /// Whether the held copy may be published/served under `current`.
    pub fn held_receipt_eligibility(&self, current: &CredentialSelection) -> ReceiptEligibility {
        self.serving.held_receipt_eligibility(current)
    }

    /// Recover/activate the held copy under the **current** validated selection
    /// with no authentication or redownload. Returns `HeldValidated` once the
    /// copy is serving; `NotServable` (owner left quiesced, files intact) when
    /// the current selection does not match the held receipt. A missing/failed
    /// guarded read is an error (owner quiesced). This is the only recovery
    /// seam exposed to the runtime; it never activates without a validated
    /// selection and installs a fresh serving gate.
    pub async fn recover_if_eligible(&mut self) -> Result<ReceiptEligibility> {
        let selection = match self.read_current_selection() {
            Ok(selection) => selection,
            Err(error) => {
                self.serving.quiesce().await;
                return Err(error);
            }
        };
        if self.serving.held_receipt_eligibility(&selection) != ReceiptEligibility::HeldValidated {
            self.serving.quiesce().await;
            return Ok(ReceiptEligibility::NotServable);
        }
        if !self.serving.is_serving() {
            let _ = self.serving.recover_after_failed_candidate().await;
        }
        Ok(if self.serving.is_serving() {
            ReceiptEligibility::HeldValidated
        } else {
            ReceiptEligibility::NotServable
        })
    }

    /// Quiesce the owner (deactivate + drain + close pools) for the runtime's
    /// shutdown path. Never called while a session lock is held.
    pub async fn quiesce(&mut self) {
        self.serving.quiesce().await;
    }

    async fn apply_answer(
        &mut self,
        answer: MemberCopyAnswer,
        context: Option<MemberCopyContext>,
    ) -> Result<Step> {
        match answer {
            MemberCopyAnswer::Revoked { cause } => {
                self.serving
                    .apply_reconnect(ReconnectAnswer::Revoked { cause })
                    .await?;
                Ok(Step::Done(RefreshDisposition::Removed {
                    cause: cause.into(),
                }))
            }
            MemberCopyAnswer::Locked => {
                self.serving
                    .apply_reconnect(ReconnectAnswer::Locked)
                    .await?;
                Ok(Step::Done(RefreshDisposition::Locked))
            }
            MemberCopyAnswer::Restart => Ok(Step::Restart),
            MemberCopyAnswer::Current {
                generation_id,
                scope_ref,
                ordinal,
                content_digest,
                download_handle,
                manifest,
                ..
            } => {
                let context = context.ok_or_else(|| {
                    Error::engine("member copy current answer carried no authenticated context")
                })?;
                self.verify_context_footing(
                    &generation_id,
                    &scope_ref,
                    ordinal,
                    &content_digest,
                    &manifest,
                    &context,
                )?;
                let account = context.account_binding().to_owned();
                self.ensure_account_position(&account, ReconnectAnswer::Current)
                    .await?;
                if let CopyStatus::Removed { cause, .. } = self.serving.lifecycle_status() {
                    return Ok(Step::Done(RefreshDisposition::Removed { cause }));
                }
                if !self.serving.is_serving() {
                    let _ = self.serving.recover_after_failed_candidate().await;
                }
                if self.serving.is_serving()
                    && self.serving.generation_id() == Some(generation_id.as_str())
                    && self.serving.installed_content_digest().as_deref()
                        == Some(content_digest.as_str())
                {
                    // Same-identity renewal: adopt fresh metadata/markers with
                    // zero chunk GETs; a marker change retires the old gate.
                    let manifest_json = serde_json::to_vec(&manifest).map_err(|error| {
                        Error::engine(format!("member copy manifest serialises: {error}"))
                    })?;
                    let markers_changed = self
                        .serving
                        .adopt_current_metadata(&manifest_json, &context)
                        .await?;
                    return Ok(Step::Done(RefreshDisposition::MetadataRefreshed {
                        generation_id,
                        markers_changed,
                    }));
                }
                self.download_and_admit(&download_handle, &manifest, &context)
                    .await
            }
            MemberCopyAnswer::Replace {
                generation_id,
                scope_ref,
                ordinal,
                content_digest,
                download_handle,
                manifest,
                ..
            } => {
                let context = context.ok_or_else(|| {
                    Error::engine("member copy replace answer carried no authenticated context")
                })?;
                let cut_at = manifest.captured_at.clone();
                self.verify_context_footing(
                    &generation_id,
                    &scope_ref,
                    ordinal,
                    &content_digest,
                    &manifest,
                    &context,
                )?;
                let account = context.account_binding().to_owned();
                self.ensure_account_position(
                    &account,
                    ReconnectAnswer::Replace {
                        cut_at: cut_at.clone(),
                    },
                )
                .await?;
                if let CopyStatus::Removed { cause, .. } = self.serving.lifecycle_status() {
                    // First step of an account switch: the purge consumed the
                    // triggering answer; discard it and stop. The next
                    // authenticated `Replace` binds and admits.
                    return Ok(Step::Done(RefreshDisposition::Removed { cause }));
                }
                if !self.serving.is_scope_bound() {
                    // No durable trusted binding (legacy/untrusted or fresh):
                    // positioned after sign-in, finish a journaled full managed
                    // purge so any held files cannot block a first binding.
                    self.serving.begin_scope_change_purge(&cut_at).await?;
                }
                if let Some(bound) = self.serving.bound_scope_ref().map(str::to_owned) {
                    if bound != context.scope_ref() {
                        self.serving.begin_scope_change_purge(&cut_at).await?;
                    }
                }
                // Unavailable (e.g. a local refresh failure) cannot promote; move
                // it to a promotable Refreshing position before admission.
                if matches!(self.serving.lifecycle_status(), CopyStatus::Unavailable) {
                    self.serving
                        .apply_reconnect(ReconnectAnswer::Replace {
                            cut_at: cut_at.clone(),
                        })
                        .await?;
                }
                self.serving.ground_origin(&context)?;
                self.serving.bind_scope(&context)?;
                self.download_and_admit(&download_handle, &manifest, &context)
                    .await
            }
        }
    }
}

impl MemberCopyDriver {
    /// Strict context↔answer↔manifest↔config↔pins footing agreement, checked
    /// at entry for `Current`/`Replace` before any lifecycle mutation, binding,
    /// purge or staging. A forged or stale envelope/context cannot reach a
    /// success path or mutate the copy.
    fn verify_context_footing(
        &self,
        envelope_generation_id: &str,
        envelope_scope_ref: &str,
        envelope_ordinal: i64,
        envelope_content_digest: &str,
        manifest: &ReplicaGenerationManifest,
        context: &MemberCopyContext,
    ) -> Result<()> {
        if context.account_binding().is_empty() {
            return Err(Error::engine("authenticated account context is empty"));
        }
        if context.server_origin() != self.config.hosted_origin {
            return Err(Error::engine(
                "authenticated context origin disagrees with the configured origin",
            ));
        }
        if context.route_database_id() != self.config.hosted_route_database_id {
            return Err(Error::engine(
                "authenticated context route disagrees with the configured route",
            ));
        }
        if context.consumer() != self.serving.device_consumer() {
            return Err(Error::engine(
                "authenticated context consumer disagrees with the device consumer",
            ));
        }
        if let Some(pin) = self.serving.origin_database_id() {
            if pin != context.origin_database_id() {
                return Err(Error::engine(
                    "authenticated context origin disagrees with the configured pin",
                ));
            }
        }
        let json = serde_json::to_vec(manifest)
            .map_err(|error| Error::engine(format!("member copy manifest serialises: {error}")))?;
        let facts = crate::member_copy_admission::validate_manifest(&json).map_err(|error| {
            Error::engine(format!("member copy manifest is not admissible: {error}"))
        })?;
        if facts.origin_database_id != context.origin_database_id() {
            return Err(Error::engine(
                "member copy manifest origin disagrees with the authenticated context",
            ));
        }
        if &facts.consumer != self.serving.device_consumer() {
            return Err(Error::engine(
                "member copy answer manifest consumer disagrees with the device pin",
            ));
        }
        if context.scope_ref() != facts.scope_ref {
            return Err(Error::engine(
                "member copy context scope disagrees with the manifest scope",
            ));
        }
        if facts.generation_id != envelope_generation_id {
            return Err(Error::engine(
                "member copy answer generation disagrees with its manifest",
            ));
        }
        if facts.scope_ref != envelope_scope_ref {
            return Err(Error::engine(
                "member copy answer scope disagrees with its manifest",
            ));
        }
        if facts.ordinal != envelope_ordinal {
            return Err(Error::engine(
                "member copy answer ordinal disagrees with its manifest",
            ));
        }
        if facts.content_digest != envelope_content_digest {
            return Err(Error::engine(
                "member copy answer content digest disagrees with its manifest",
            ));
        }
        Ok(())
    }

    /// Establish the authenticated lifecycle position only when required.
    /// A different account, an unbound first binding, or a `Locked`/`Removed`
    /// copy uses the sign-in/adoption path; an already-positioned same-account
    /// copy is left untouched (so a failed replacement can still recover the
    /// held generation), except that a `Current` re-statement is applied.
    async fn ensure_account_position(
        &mut self,
        account: &str,
        answer: ReconnectAnswer,
    ) -> Result<()> {
        let needs_sign_in = !self.serving.is_scope_bound()
            || self.serving.account_token().as_deref() != Some(account)
            || matches!(
                self.serving.lifecycle_status(),
                CopyStatus::Locked { .. } | CopyStatus::Removed { .. }
            );
        if needs_sign_in {
            self.serving.sign_in(account, answer).await?;
        } else if matches!(answer, ReconnectAnswer::Current) {
            self.serving.apply_reconnect(answer).await?;
        }
        Ok(())
    }

    /// Downloads the pinned generation in bounded windows, verifies the file
    /// identity against the manifest, then admits. The staged file is removed
    /// on every exit, and a refused or failed admission calls
    /// `recover_after_failed_candidate` so the held generation resumes.
    async fn download_and_admit(
        &mut self,
        handle: &str,
        manifest: &ReplicaGenerationManifest,
        context: &MemberCopyContext,
    ) -> Result<Step> {
        let manifest_json = serde_json::to_vec(manifest)
            .map_err(|error| Error::engine(format!("member copy manifest serialises: {error}")))?;
        let staged = self.staging_path();
        match self.download_to(context, handle, manifest, &staged).await {
            Ok(()) => {}
            Err(DownloadError::Restart) => {
                self.remove_staging(&staged);
                return Ok(Step::Restart);
            }
            Err(DownloadError::Refused(error)) => {
                self.remove_staging(&staged);
                let _ = self.serving.recover_after_failed_candidate().await;
                return Err(error);
            }
        }
        if let Err(error) = verify_file_identity(&staged, manifest) {
            self.remove_staging(&staged);
            let _ = self.serving.recover_after_failed_candidate().await;
            return Err(error);
        }
        let admitted = self
            .serving
            .admit_candidate(&staged, &manifest_json, context)
            .await;
        self.remove_staging(&staged);
        match admitted {
            Ok(admitted) => Ok(Step::Done(RefreshDisposition::Admitted {
                generation_id: admitted.generation_id,
            })),
            Err(AdmissionError::Removed { cause, .. }) => {
                let _ = self.serving.recover_after_failed_candidate().await;
                Ok(Step::Done(RefreshDisposition::Removed { cause }))
            }
            Err(AdmissionError::Locked) => {
                let _ = self.serving.recover_after_failed_candidate().await;
                Ok(Step::Done(RefreshDisposition::Locked))
            }
            Err(error) => {
                let _ = self.serving.recover_after_failed_candidate().await;
                Err(Error::engine(format!(
                    "member copy admission refused: {error}"
                )))
            }
        }
    }

    /// Bounded contiguous download. Advances by the *actual* window end from
    /// the server, never by the requested size; verifies window contiguity,
    /// total size, whole-file ETag and window length before writing.
    async fn download_to(
        &self,
        context: &MemberCopyContext,
        handle: &str,
        manifest: &ReplicaGenerationManifest,
        staged: &Path,
    ) -> std::result::Result<(), DownloadError> {
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent).map_err(|e| DownloadError::Refused(Error::Io(e)))?;
        }
        let size = manifest.bytes.size_bytes;
        let mut file = File::create(staged).map_err(|e| DownloadError::Refused(Error::Io(e)))?;
        let mut start = 0u64;
        while start < size {
            let end = start
                .saturating_add(BINARY_MAX_CHUNK_BYTES as u64 - 1)
                .min(size - 1);
            let chunk = self
                .transport
                .read_range(context, handle, start, end)
                .await
                .map_err(DownloadError::Refused)?;
            match chunk {
                MemberCopyChunk::Bytes {
                    bytes,
                    start: actual_start,
                    end: actual_end,
                    total_size,
                    sha256,
                } => {
                    if actual_start != start || actual_end < actual_start || actual_end != end {
                        return Err(DownloadError::Refused(Error::engine(
                            "member copy chunk window is not the requested contiguous range",
                        )));
                    }
                    if total_size != size {
                        return Err(DownloadError::Refused(Error::engine(
                            "member copy chunk total size disagrees with the manifest",
                        )));
                    }
                    if sha256 != manifest.bytes.sha256 {
                        return Err(DownloadError::Refused(Error::engine(
                            "member copy chunk ETag disagrees with the manifest byte identity",
                        )));
                    }
                    if bytes.len() as u64 != actual_end - actual_start + 1 {
                        return Err(DownloadError::Refused(Error::engine(
                            "member copy chunk length disagrees with its Content-Range",
                        )));
                    }
                    file.write_all(&bytes)
                        .map_err(|e| DownloadError::Refused(Error::Io(e)))?;
                    file.sync_all()
                        .map_err(|e| DownloadError::Refused(Error::Io(e)))?;
                    start = actual_end + 1;
                }
                MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Restart) => {
                    return Err(DownloadError::Restart)
                }
                MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Expired) => {
                    return Err(DownloadError::Refused(Error::engine(
                        "member copy download lease expired",
                    )))
                }
                MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Revoked { cause }) => {
                    return Err(DownloadError::Refused(Error::engine(format!(
                        "member copy download revoked: {cause:?}"
                    ))))
                }
                MemberCopyChunk::Refused(MemberCopyDownloadRefusal::Locked) => {
                    return Err(DownloadError::Refused(Error::engine(
                        "member copy download locked",
                    )))
                }
            }
        }
        Ok(())
    }

    fn staging_path(&self) -> PathBuf {
        self.config
            .copy_root
            .join("staging")
            .join(format!("incoming-{}.db", uuid::Uuid::new_v4()))
    }

    fn remove_staging(&self, staged: &Path) {
        let _ = fs::remove_file(staged);
    }

    /// Removes every partial entry under `staging/` (best effort). A scope/full
    /// managed purge DOES delete `staging/*` (only the orphan-adoption purge
    /// leaves in-flight staging), so the driver also cleans its own scratch.
    fn discard_staging(&self) {
        let staging = self.config.copy_root.join("staging");
        let Ok(entries) = fs::read_dir(&staging) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                let _ = fs::remove_dir_all(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

/// Recompute size and SHA-256 of the staged file and require both to equal
/// the manifest's byte identity. This is deliberately stronger than the
/// per-window ETag: admission must never see bytes that were not re-hashed in
/// full on this device.
fn verify_file_identity(path: &Path, manifest: &ReplicaGenerationManifest) -> Result<()> {
    let metadata = fs::metadata(path)?;
    if metadata.len() != manifest.bytes.size_bytes {
        return Err(Error::engine(
            "member copy download size does not match the manifest",
        ));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hex::encode(hasher.finalize());
    if digest != manifest.bytes.sha256 {
        return Err(Error::engine(
            "member copy download SHA-256 does not match the manifest",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use futures::future::BoxFuture;

    use super::*;
    use crate::member_copy_admission::validate_manifest;
    use crate::member_copy_producer::{
        build_member_copy, MemberCopy, MemberCopyRequest as ProducerCopyRequest,
    };
    use crate::member_copy_transport::MemberCopyAttempt;
    use crate::member_offline_fixtures::two_caller;

    const SCOPE_A: &str = "scope-a";
    const SCOPE_B: &str = "scope-b";

    fn device_consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: crate::standby_snapshot::STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: 1,
            ddl_sha256: "c".repeat(64),
        }
    }

    /// An in-memory transport scripted with typed answers and pinned bytes.
    struct MockTransport {
        account: Mutex<String>,
        answers: Mutex<VecDeque<MemberCopyAnswer>>,
        bytes: Mutex<HashMap<String, Vec<u8>>>,
        requests: AtomicUsize,
        ranges: AtomicUsize,
        corrupt_offset: Mutex<Option<u64>>,
        override_sha: Mutex<Option<String>>,
        override_total: Mutex<Option<u64>>,
        last_request: Mutex<Option<MemberCopyRequest>>,
        block_requests: std::sync::atomic::AtomicBool,
        block_reads: std::sync::atomic::AtomicBool,
        on_enter: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        on_read_enter: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }

    impl MockTransport {
        fn new(account: &str) -> Self {
            Self {
                account: Mutex::new(account.to_owned()),
                answers: Mutex::new(VecDeque::new()),
                bytes: Mutex::new(HashMap::new()),
                requests: AtomicUsize::new(0),
                ranges: AtomicUsize::new(0),
                corrupt_offset: Mutex::new(None),
                override_sha: Mutex::new(None),
                override_total: Mutex::new(None),
                last_request: Mutex::new(None),
                block_requests: std::sync::atomic::AtomicBool::new(false),
                block_reads: std::sync::atomic::AtomicBool::new(false),
                on_enter: Mutex::new(None),
                on_read_enter: Mutex::new(None),
            }
        }

        /// Run `hook` exactly once when the next request is entered, before it
        /// blocks. Lets a test mutate state (e.g. rotate the credential)
        /// deterministically while the attempt is in flight.
        fn set_on_enter<F: FnOnce() + Send + 'static>(&self, hook: F) {
            *self.on_enter.lock().unwrap() = Some(Box::new(hook));
        }

        fn set_on_read_enter<F: FnOnce() + Send + 'static>(&self, hook: F) {
            *self.on_read_enter.lock().unwrap() = Some(Box::new(hook));
        }

        fn block_requests(&self) {
            self.block_requests.store(true, Ordering::SeqCst);
        }

        fn block_reads(&self) {
            self.block_reads.store(true, Ordering::SeqCst);
        }

        fn set_account(&self, account: &str) {
            *self.account.lock().unwrap() = account.to_owned();
        }

        fn push(&self, answer: MemberCopyAnswer) {
            self.answers.lock().unwrap().push_back(answer);
        }

        fn serve(&self, handle: &str, bytes: Vec<u8>) {
            self.bytes.lock().unwrap().insert(handle.to_owned(), bytes);
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }

        fn ranges(&self) -> usize {
            self.ranges.load(Ordering::SeqCst)
        }

        fn last_request(&self) -> Option<MemberCopyRequest> {
            self.last_request.lock().unwrap().clone()
        }

        fn context_for(
            &self,
            answer: &MemberCopyAnswer,
            selection: &CredentialSelection,
        ) -> Option<MemberCopyContext> {
            match answer {
                MemberCopyAnswer::Current {
                    scope_ref,
                    manifest,
                    ..
                }
                | MemberCopyAnswer::Replace {
                    scope_ref,
                    manifest,
                    ..
                } => Some(MemberCopyContext::new(
                    self.account.lock().unwrap().clone(),
                    "http://127.0.0.1:0".to_owned(),
                    "route-test".to_owned(),
                    manifest.origin_database_id.clone(),
                    manifest.consumer.clone(),
                    scope_ref.clone(),
                    selection.clone(),
                )),
                _ => None,
            }
        }
    }

    impl MemberCopyTransport for MockTransport {
        fn request(
            &self,
            request: MemberCopyRequest,
            selection: &CredentialSelection,
        ) -> BoxFuture<'_, Result<MemberCopyAttempt>> {
            let selection = selection.clone();
            Box::pin(async move {
                self.requests.fetch_add(1, Ordering::SeqCst);
                if let Some(hook) = self.on_enter.lock().unwrap().take() {
                    hook();
                }
                if self.block_requests.load(Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
                *self.last_request.lock().unwrap() = Some(request);
                let answer = self
                    .answers
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| Error::engine("mock transport has no scripted answer"))?;
                let context = self.context_for(&answer, &selection);
                Ok(MemberCopyAttempt { answer, context })
            })
        }

        fn read_range(
            &self,
            _context: &MemberCopyContext,
            handle: &str,
            start: u64,
            end: u64,
        ) -> BoxFuture<'_, Result<MemberCopyChunk>> {
            let handle = handle.to_owned();
            Box::pin(async move {
                self.ranges.fetch_add(1, Ordering::SeqCst);
                if let Some(hook) = self.on_read_enter.lock().unwrap().take() {
                    hook();
                }
                if self.block_reads.load(Ordering::SeqCst) {
                    std::future::pending::<()>().await;
                }
                let bytes = self
                    .bytes
                    .lock()
                    .unwrap()
                    .get(&handle)
                    .cloned()
                    .ok_or_else(|| Error::engine("mock transport has no bytes for the handle"))?;
                let end = end.min(bytes.len() as u64 - 1);
                let mut window = bytes[start as usize..=end as usize].to_vec();
                if let Some(offset) = *self.corrupt_offset.lock().unwrap() {
                    if offset >= start && offset <= end {
                        window[(offset - start) as usize] ^= 0xff;
                    }
                }
                let sha256 = self
                    .override_sha
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| hex::encode(sha2::Sha256::digest(&bytes)));
                let total_size = self
                    .override_total
                    .lock()
                    .unwrap()
                    .unwrap_or(bytes.len() as u64);
                Ok(MemberCopyChunk::Bytes {
                    bytes: window,
                    start,
                    end,
                    total_size,
                    sha256,
                })
            })
        }
    }

    async fn world() -> (crate::db::Db, String) {
        let world = two_caller::build().await;
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(world.db.pool())
                .await
                .expect("origin");
        (world.db, origin)
    }

    async fn produce(db: &crate::db::Db, scope: &str, ordinal: i64, out: &Path) -> MemberCopy {
        build_member_copy(
            db,
            ProducerCopyRequest {
                member_account: crate::member_offline_fixtures::ACCT_B.to_owned(),
                scope_ref: scope.to_owned(),
                hosted_route_database_id: "route-test".to_owned(),
                ordinal,
                consumer: device_consumer(),
                out_path: out.to_path_buf(),
            },
        )
        .await
        .expect("produce member copy")
    }

    fn generation_id(manifest: &ReplicaGenerationManifest) -> String {
        let json = serde_json::to_vec(manifest).expect("manifest serialises");
        validate_manifest(&json)
            .expect("manifest validates")
            .generation_id
    }

    fn current_answer(manifest: &ReplicaGenerationManifest, handle: &str) -> MemberCopyAnswer {
        let json = serde_json::to_vec(manifest).expect("manifest serialises");
        let facts = validate_manifest(&json).expect("manifest validates");
        MemberCopyAnswer::Current {
            generation_id: facts.generation_id,
            scope_ref: facts.scope_ref,
            ordinal: facts.ordinal,
            content_digest: facts.content_digest,
            download_handle: handle.to_owned(),
            manifest: manifest.clone(),
        }
    }

    fn replace_answer(
        manifest: &ReplicaGenerationManifest,
        scope_changed: bool,
        handle: &str,
    ) -> MemberCopyAnswer {
        let json = serde_json::to_vec(manifest).expect("manifest serialises");
        let facts = validate_manifest(&json).expect("manifest validates");
        MemberCopyAnswer::Replace {
            generation_id: facts.generation_id,
            scope_ref: facts.scope_ref,
            scope_changed,
            ordinal: facts.ordinal,
            content_digest: facts.content_digest,
            download_handle: handle.to_owned(),
            manifest: manifest.clone(),
        }
    }

    fn write_credential(root: &Path, token: &str) {
        assert!(
            root.is_dir(),
            "write_credential expects a directory root, not a file"
        );
        let path = root.join("credential");
        fs::write(&path, token).expect("credential");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        }
    }

    fn config(root: &Path, origin: &str) -> MemberCopyDeviceConfig {
        write_credential(root, "test-bearer");
        MemberCopyDeviceConfig {
            contract: CONFIG_CONTRACT.to_owned(),
            version: PROTOCOL_VERSION,
            hosted_origin: "http://127.0.0.1:0".to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            origin_database_id: Some(origin.to_owned()),
            credential_file: root.join("credential"),
            copy_root: root.join("copy"),
        }
    }

    /// First publish: `scope_changed:false` still binds the authenticated
    /// scope, downloads bounded windows, verifies SHA and size, admits, and
    /// records the trusted v2 binding.
    #[tokio::test]
    async fn fresh_replace_downloads_verifies_and_admits() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let expected = generation_id(&copy.manifest);
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        let disposition = driver.refresh().await.expect("refresh");
        assert_eq!(
            disposition,
            RefreshDisposition::Admitted {
                generation_id: expected.clone()
            }
        );
        assert!(driver.serving().is_serving());
        assert_eq!(driver.serving().generation_id(), Some(expected.as_str()));
        assert_eq!(driver.serving().bound_scope_ref(), Some(SCOPE_A));
        assert_eq!(transport.requests(), 1);
        assert!(transport.ranges() > 0);
        let admission = fs::read_to_string(
            dir.path()
                .join("copy")
                .join(crate::member_copy_serving::ADMISSION_FILENAME),
        )
        .expect("admission");
        assert!(admission.contains("native.member-copy-admission.v3"));
        assert!(admission.contains(crate::member_offline_fixtures::ACCT_B));
        let staging = dir.path().join("copy").join("staging");
        assert!(fs::read_dir(&staging)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true));
    }

    /// A durable v2 binding serves the held copy offline with no transport
    /// call, and a `Current` answer reuses the pinned bytes without
    /// downloading.
    #[tokio::test]
    async fn current_reuse_and_offline_reopen_without_download() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let expected = generation_id(&copy.manifest);
        let first = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        first.push(replace_answer(&copy.manifest, false, "h"));
        first.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            first.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("first admit");
        drop(driver);

        let second = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        second.push(current_answer(&copy.manifest, "h2"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            second.clone(),
        )
        .await
        .expect("reopen");
        assert_eq!(second.requests(), 0, "reopen makes no transport call");
        assert!(driver.serving().is_serving(), "offline reopen serves");
        assert_eq!(driver.serving().generation_id(), Some(expected.as_str()));
        assert_eq!(driver.serving().bound_scope_ref(), Some(SCOPE_A));
        let disposition = driver.refresh().await.expect("current");
        assert!(matches!(
            disposition,
            RefreshDisposition::MetadataRefreshed {
                markers_changed: false,
                ..
            }
        ));
        assert_eq!(second.ranges(), 0, "current reuse must not download");
    }

    /// A corrupt download (byte flipped after the server ETag was minted) is
    /// refused before admission, staging is cleaned, and the held generation
    /// resumes.
    #[tokio::test]
    async fn corrupted_download_refuses_and_keeps_prior_generation() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out_a = dir.path().join("a.db");
        let copy_a = produce(&db, SCOPE_A, 1, &out_a).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy_a.manifest, false, "a"));
        transport.serve("a", fs::read(&out_a).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit A");
        let gen_a = driver.serving().generation_id().expect("gen").to_owned();

        crate::store::update_record(
            &db,
            two_caller::SHARED_CHILD,
            serde_json::json!({"body": "changed"}),
        )
        .await
        .expect("edit");
        let out_b = dir.path().join("b.db");
        let copy_b = produce(&db, SCOPE_A, 2, &out_b).await;
        transport.push(replace_answer(&copy_b.manifest, false, "b"));
        transport.serve("b", fs::read(&out_b).expect("bytes"));
        *transport.corrupt_offset.lock().unwrap() = Some(10);
        let error = driver
            .refresh()
            .await
            .expect_err("corrupt download must refuse");
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert_eq!(
            driver.serving().generation_id(),
            Some(gen_a.as_str()),
            "held A resumes after the refused replacement"
        );
    }

    /// A chunk whose ETag or total size disagrees with the manifest is a
    /// typed refusal, never an empty success.
    #[tokio::test]
    async fn chunk_footing_mismatch_refuses() {
        let (db, origin) = world().await;
        for (label, expected_fragment) in [("etag", "ETag"), ("total", "total size")] {
            let dir = tempfile::tempdir().expect("tempdir");
            let out = dir.path().join("producer.db");
            let copy = produce(&db, SCOPE_A, 1, &out).await;
            let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
            transport.push(replace_answer(&copy.manifest, false, "h"));
            transport.serve("h", fs::read(&out).expect("bytes"));
            if label == "etag" {
                *transport.override_sha.lock().unwrap() = Some("0".repeat(64));
            } else {
                *transport.override_total.lock().unwrap() = Some(42);
            }
            let mut driver = MemberCopyDriver::new(
                config(dir.path(), &origin),
                device_consumer(),
                transport.clone(),
            )
            .await
            .expect("driver");
            let error = driver
                .refresh()
                .await
                .expect_err("footing mismatch refuses");
            assert!(
                error.to_string().contains(expected_fragment),
                "{label}: {error}"
            );
            assert!(!driver.serving().is_serving());
        }
    }

    /// A real scope change purges the old generation before staging and admits
    /// the new scope; the new scope is bound.
    #[tokio::test]
    async fn scope_change_purges_then_admits_new_scope() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out_a = dir.path().join("a.db");
        let copy_a = produce(&db, SCOPE_A, 1, &out_a).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy_a.manifest, false, "a"));
        transport.serve("a", fs::read(&out_a).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit A");
        let gen_a = driver.serving().generation_id().expect("gen").to_owned();

        let out_b = dir.path().join("b.db");
        let copy_b = produce(&db, SCOPE_B, 2, &out_b).await;
        let gen_b = generation_id(&copy_b.manifest);
        transport.push(replace_answer(&copy_b.manifest, true, "b"));
        transport.serve("b", fs::read(&out_b).expect("bytes"));
        let disposition = driver.refresh().await.expect("scope change");
        assert_eq!(
            disposition,
            RefreshDisposition::Admitted {
                generation_id: gen_b.clone()
            }
        );
        assert_eq!(driver.serving().generation_id(), Some(gen_b.as_str()));
        assert_eq!(driver.serving().bound_scope_ref(), Some(SCOPE_B));
        assert!(
            !dir.path()
                .join("copy")
                .join("generations")
                .join(&gen_a)
                .exists(),
            "the old scope generation must be purged before the new one is staged"
        );
    }

    /// `Restart` re-requests immediately exactly once; a second `Restart`
    /// discards and admits nothing.
    #[tokio::test]
    async fn restart_rerequests_exactly_once_then_discards() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(MemberCopyAnswer::Restart);
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        assert!(matches!(
            driver.refresh().await.expect("refresh"),
            RefreshDisposition::Admitted { .. }
        ));
        assert_eq!(transport.requests(), 2, "one immediate re-request");

        let dir = tempfile::tempdir().expect("tempdir");
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(MemberCopyAnswer::Restart);
        transport.push(MemberCopyAnswer::Restart);
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        assert_eq!(
            driver.refresh().await.expect("refresh"),
            RefreshDisposition::RestartDiscarded
        );
        assert_eq!(transport.requests(), 2);
        assert!(!driver.serving().is_serving());
    }

    /// `Revoked` preserves its cause as a `Removed` copy disposition; the old
    /// registry/account no longer serves.
    #[tokio::test]
    async fn revoked_answer_removes_with_preserved_cause() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");
        transport.push(MemberCopyAnswer::Revoked {
            cause: crate::member_copy_lifecycle::RevokedCause::SessionRevoked,
        });
        assert_eq!(
            driver.refresh().await.expect("revoked"),
            RefreshDisposition::Removed {
                cause: RemovedCause::SessionRevoked
            }
        );
        assert!(!driver.serving().is_serving());
    }

    /// `Locked` stops serving but keeps bytes/binding; the same account's
    /// `Current` sign-in unlocks and revalidates them with no download.
    #[tokio::test]
    async fn locked_then_same_account_current_unlocks_without_download() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");
        transport.push(MemberCopyAnswer::Locked);
        assert_eq!(
            driver.refresh().await.expect("locked"),
            RefreshDisposition::Locked
        );
        assert!(!driver.serving().is_serving());
        assert_eq!(
            driver.serving().bound_scope_ref(),
            Some(SCOPE_A),
            "Locked preserves the binding association"
        );
        assert!(
            driver.serving().installed_generation_id().is_some(),
            "Locked preserves the held generation hint"
        );

        let ranges_before = transport.ranges();
        transport.push(current_answer(&copy.manifest, "h"));
        assert!(matches!(
            driver.refresh().await.expect("current unlock"),
            RefreshDisposition::MetadataRefreshed { .. }
        ));
        assert!(
            driver.serving().is_serving(),
            "sign-in current unlocks held bytes"
        );
        assert_eq!(
            transport.ranges(),
            ranges_before,
            "unlock must not download"
        );
    }

    /// A manifest whose consumer differs from the device pin is refused even
    /// when the scope token matched and bytes downloaded.
    #[tokio::test]
    async fn foreign_consumer_manifest_is_refused() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let mut foreign = copy.manifest.clone();
        foreign.consumer.ddl_sha256 = "9".repeat(64);
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&foreign, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        let error = driver
            .refresh()
            .await
            .expect_err("foreign consumer refuses");
        assert!(error.to_string().contains("consumer"), "{error}");
        assert!(!driver.serving().is_serving());
    }

    /// Account switch is two-step: the first authenticated `Replace` purges and
    /// ends `Removed`, discarding its token; only a second `Replace` for the
    /// now-bound account binds and admits.
    #[tokio::test]
    async fn account_switch_is_two_step() {
        const ACCOUNT_A: &str = "acct_a";
        const ACCOUNT_B: &str = "acct_b";
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out_a = dir.path().join("a.db");
        let copy_a = produce(&db, SCOPE_A, 1, &out_a).await;
        let out_b = dir.path().join("b.db");
        let copy_b = produce(&db, SCOPE_B, 2, &out_b).await;
        let transport = Arc::new(MockTransport::new(ACCOUNT_A));
        transport.push(replace_answer(&copy_a.manifest, false, "a"));
        transport.serve("a", fs::read(&out_a).expect("bytes"));
        transport.serve("b", fs::read(&out_b).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit under account A");

        transport.set_account(ACCOUNT_B);
        transport.push(replace_answer(&copy_b.manifest, true, "b"));
        assert_eq!(
            driver.refresh().await.expect("switch"),
            RefreshDisposition::Removed {
                cause: RemovedCause::AccountChanged
            },
            "the triggering answer only purges and stops"
        );
        assert!(!driver.serving().is_serving());
        assert!(
            driver.serving().bound_scope_ref().is_none(),
            "an account purge clears the stale binding association"
        );
        assert!(driver.serving().installed_generation_id().is_none());

        transport.push(replace_answer(&copy_b.manifest, true, "b"));
        assert!(matches!(
            driver.refresh().await.expect("second replace"),
            RefreshDisposition::Admitted { .. }
        ));
        assert_eq!(driver.serving().bound_scope_ref(), Some(SCOPE_B));
        assert!(driver.serving().is_serving());
    }

    /// Build a `Current` answer whose envelope and/or manifest is forged.
    fn forged_current(
        base: &ReplicaGenerationManifest,
        mutate_manifest: impl FnOnce(&mut ReplicaGenerationManifest),
        mutate_answer: impl FnOnce(&mut MemberCopyAnswer),
    ) -> MemberCopyAnswer {
        let mut answer = current_answer(base, "h");
        if let MemberCopyAnswer::Current { manifest, .. } = &mut answer {
            mutate_manifest(manifest);
        }
        mutate_answer(&mut answer);
        answer
    }

    /// A `Current` answer whose envelope or manifest disagrees with the held
    /// footing is refused before any lifecycle mutation or download.
    #[tokio::test]
    async fn forged_current_envelope_is_refused_without_mutation() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let gen_a = generation_id(&copy.manifest);
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit A");
        let ranges = transport.ranges();

        transport.push(forged_current(
            &copy.manifest,
            |m| m.origin_database_id = "ndb_66666666666666666666666666666666".into(),
            |_| {},
        ));
        assert!(driver.refresh().await.is_err(), "wrong origin must refuse");
        transport.push(forged_current(
            &copy.manifest,
            |m| m.consumer.ddl_sha256 = "9".repeat(64),
            |_| {},
        ));
        assert!(
            driver.refresh().await.is_err(),
            "wrong consumer must refuse"
        );
        transport.push(forged_current(
            &copy.manifest,
            |_| {},
            |answer| {
                if let MemberCopyAnswer::Current { generation_id, .. } = answer {
                    *generation_id = "0".repeat(64);
                }
            },
        ));
        assert!(
            driver.refresh().await.is_err(),
            "generation mismatch must refuse"
        );
        transport.push(forged_current(
            &copy.manifest,
            |_| {},
            |answer| {
                if let MemberCopyAnswer::Current { content_digest, .. } = answer {
                    *content_digest = "0".repeat(64);
                }
            },
        ));
        assert!(
            driver.refresh().await.is_err(),
            "digest mismatch must refuse"
        );
        transport.push(forged_current(
            &copy.manifest,
            |_| {},
            |answer| {
                if let MemberCopyAnswer::Current { ordinal, .. } = answer {
                    *ordinal = 99;
                }
            },
        ));
        assert!(
            driver.refresh().await.is_err(),
            "ordinal mismatch must refuse"
        );

        assert_eq!(
            driver.serving().generation_id(),
            Some(gen_a.as_str()),
            "no forgery mutated the held generation"
        );
        assert!(driver.serving().is_serving());
        assert_eq!(driver.serving().bound_scope_ref(), Some(SCOPE_A));
        assert_eq!(transport.ranges(), ranges, "no forgery downloaded bytes");
    }

    /// A `Replace` answer whose envelope disagrees with its manifest is
    /// refused before binding, purge, staging or activation.
    #[tokio::test]
    async fn forged_replace_envelope_is_refused_without_mutation() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out_a = dir.path().join("a.db");
        let copy_a = produce(&db, SCOPE_A, 1, &out_a).await;
        let out_b = dir.path().join("b.db");
        let copy_b = produce(&db, SCOPE_B, 2, &out_b).await;
        let gen_a = generation_id(&copy_a.manifest);
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy_a.manifest, false, "a"));
        transport.serve("a", fs::read(&out_a).expect("bytes"));
        transport.serve("b", fs::read(&out_b).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit A");

        let mut forged = replace_answer(&copy_b.manifest, true, "b");
        if let MemberCopyAnswer::Replace { generation_id, .. } = &mut forged {
            *generation_id = gen_a.clone();
        }
        transport.push(forged);
        assert!(
            driver.refresh().await.is_err(),
            "envelope/manifest generation mismatch"
        );

        let mut forged = replace_answer(&copy_b.manifest, true, "b");
        if let MemberCopyAnswer::Replace { manifest, .. } = &mut forged {
            manifest.origin_database_id = "ndb_77777777777777777777777777777777".into();
        }
        transport.push(forged);
        assert!(
            driver.refresh().await.is_err(),
            "origin mismatch must refuse"
        );

        assert_eq!(
            driver.serving().bound_scope_ref(),
            Some(SCOPE_A),
            "no forged replace changed the binding"
        );
        assert_eq!(driver.serving().generation_id(), Some(gen_a.as_str()));
        assert!(
            dir.path()
                .join("copy")
                .join("generations")
                .join(&gen_a)
                .exists(),
            "the held generation must not be purged"
        );
        let staging = dir.path().join("copy").join("staging");
        assert!(fs::read_dir(&staging)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true));
    }

    /// After a `Removed` transition the in-memory binding/admission cache is
    /// reconciled: the next request carries no stale installed hints, and a
    /// fresh same-account `Replace` recovers without being stuck in `Removed`.
    #[tokio::test]
    async fn revoked_then_fresh_replace_has_no_stale_hints() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");

        transport.push(MemberCopyAnswer::Revoked {
            cause: crate::member_copy_lifecycle::RevokedCause::SessionRevoked,
        });
        assert_eq!(
            driver.refresh().await.expect("revoked"),
            RefreshDisposition::Removed {
                cause: RemovedCause::SessionRevoked
            }
        );
        assert!(!driver.serving().is_serving());
        assert!(
            driver.serving().installed_generation_id().is_none(),
            "no stale installed generation hint after removal"
        );
        assert!(
            driver.serving().bound_scope_ref().is_none(),
            "no stale scope association after removal"
        );
        assert!(
            !dir.path()
                .join("copy")
                .join(crate::member_copy_serving::ADMISSION_FILENAME)
                .exists(),
            "the admission record is gone after removal"
        );
        assert!(
            fs::read_dir(dir.path().join("copy").join("generations"))
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(true),
            "held generation dirs are gone after removal"
        );

        transport.push(replace_answer(&copy.manifest, false, "h"));
        assert!(matches!(
            driver.refresh().await.expect("fresh replace"),
            RefreshDisposition::Admitted { .. }
        ));
        let request = transport.last_request().expect("last request");
        assert!(
            request.installed_generation_id.is_none(),
            "fresh request carries no installed generation"
        );
        assert!(
            request.installed_scope_ref.is_none(),
            "fresh request carries no installed scope"
        );
        assert!(driver.serving().is_serving());
    }

    /// An unbound root that still holds legacy/untrusted files finishes a
    /// journaled full managed purge before the first bind, instead of being
    /// rejected by the held-pointer guard forever.
    #[tokio::test]
    async fn unbound_but_held_root_purges_before_first_bind() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out_a = dir.path().join("a.db");
        let copy_a = produce(&db, SCOPE_A, 1, &out_a).await;
        let gen_a = generation_id(&copy_a.manifest);
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy_a.manifest, false, "a"));
        transport.serve("a", fs::read(&out_a).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit A");
        drop(driver);

        // Downgrade the durable record to legacy v1 while the held generation
        // and pointer remain; the reopen is unbound and refuses offline.
        fs::write(
            dir.path()
                .join("copy")
                .join(crate::member_copy_serving::ADMISSION_FILENAME),
            br#"{"contract":"native.member-copy-admission.v1","version":1,"manifest_json":"{}"}"#,
        )
        .expect("legacy record");
        let out_b = dir.path().join("b.db");
        let copy_b = produce(&db, SCOPE_B, 2, &out_b).await;
        transport.push(replace_answer(&copy_b.manifest, true, "b"));
        transport.serve("b", fs::read(&out_b).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("reopen");
        assert!(
            !driver.serving().is_serving(),
            "legacy record refuses offline"
        );
        assert!(driver.serving().bound_scope_ref().is_none());

        assert!(matches!(
            driver.refresh().await.expect("first bind"),
            RefreshDisposition::Admitted { .. }
        ));
        assert!(driver.serving().is_serving());
        assert_eq!(driver.serving().bound_scope_ref(), Some(SCOPE_B));
        assert!(
            !dir.path()
                .join("copy")
                .join("generations")
                .join(&gen_a)
                .exists(),
            "legacy held generation is purged before the first bind"
        );
    }

    /// A same-identity `Current` whose schema markers changed is adopted with
    /// zero chunk GETs and reports a metadata refresh for runtime republish.
    #[tokio::test]
    async fn same_identity_current_marker_change_adopts_without_download() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");
        let ranges = transport.ranges();

        let mut updated = copy.manifest.clone();
        updated.schema_incomplete_for = vec!["global".to_owned()];
        transport.push(current_answer(&updated, "h"));
        let disposition = driver.refresh().await.expect("marker current");
        assert!(
            matches!(
                disposition,
                RefreshDisposition::MetadataRefreshed {
                    markers_changed: true,
                    ..
                }
            ),
            "{disposition:?}"
        );
        assert_eq!(
            transport.ranges(),
            ranges,
            "marker adoption must not download"
        );
        assert!(driver.serving().is_serving());
    }

    /// Producer-built same-generation marker change: one source DB, baseline
    /// copy, then a single withheld global `schema_config` row whose data
    /// embeds an already-private record id. Both copies share a content digest
    /// and generation_id but differ in `schema_incomplete_for` (`[]` ->
    /// `["global"]`); a `Current` for the second adopts the markers with zero
    /// chunk GETs.
    ///
    /// The broad two-world `hidden_change` fixture is invalid for this purpose:
    /// its hidden link-touch moves VIS_H's timestamps, so the two worlds are not
    /// a same-digest pair.
    #[tokio::test]
    async fn producer_same_gid_marker_change_adopts_without_download() {
        use crate::member_offline_fixtures::{hidden_change, ACCT_B};
        use crate::meta::schema_config::{write_user_schema_config, SchemaConfigOptions};

        // One source DB, `worlds.a`, already holds HIDDEN_H private to account A
        // and therefore wholly withheld from member B. The baseline copy is
        // built first; the only change before the marker copy is a global
        // `schema_config` row whose data embeds that already-private id. The
        // exact-id gate withholds the row, so the marker moves `[] ->
        // ["global"]` while every shipped cell — and therefore the content
        // digest and generation identity — is unchanged.
        let worlds = hidden_change::build().await;
        let source = &worlds.a;
        let dir = tempfile::tempdir().expect("tempdir");
        let out_a = dir.path().join("a.db");
        let out_b = dir.path().join("b.db");
        let request = |out: &Path| ProducerCopyRequest {
            member_account: ACCT_B.to_owned(),
            scope_ref: SCOPE_A.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: device_consumer(),
            out_path: out.to_path_buf(),
        };
        let copy_a = build_member_copy(source, request(&out_a))
            .await
            .expect("baseline copy A");
        assert!(
            copy_a.manifest.schema_incomplete_for.is_empty(),
            "baseline schema is complete"
        );
        assert!(
            !fs::read(&out_a)
                .expect("baseline bytes")
                .windows(hidden_change::HIDDEN_H.len())
                .any(|w| w == hidden_change::HIDDEN_H.as_bytes()),
            "hidden record must be absent from the baseline artifact"
        );

        write_user_schema_config(
            source,
            serde_json::json!({ "shapes": {}, "note": hidden_change::HIDDEN_H }),
            SchemaConfigOptions {
                id: Some("driver-marker-global".to_owned()),
                version_lineage: None,
                applies_to_collection_id: None,
            },
        )
        .await
        .expect("withheld global schema row");

        let copy_b = build_member_copy(source, request(&out_b))
            .await
            .expect("marker copy B");
        assert!(
            !fs::read(&out_b)
                .expect("marker bytes")
                .windows(hidden_change::HIDDEN_H.len())
                .any(|w| w == hidden_change::HIDDEN_H.as_bytes()),
            "hidden record must stay absent from the marker artifact"
        );
        // Structural oracle over both produced member files: the withheld global
        // schema row and the private record are absent from the shipped rows,
        // not merely from a byte scan.
        for path in [&out_a, &out_b] {
            let connection = rusqlite::Connection::open_with_flags(
                path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("member copy opens");
            let schema_rows: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_config WHERE id = 'driver-marker-global'",
                    [],
                    |row| row.get(0),
                )
                .expect("schema_config count");
            assert_eq!(
                schema_rows,
                0,
                "withheld global schema row must be absent from {}",
                path.display()
            );
            let hidden_rows: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE id = ?1",
                    (hidden_change::HIDDEN_H,),
                    |row| row.get(0),
                )
                .expect("hidden record count");
            assert_eq!(
                hidden_rows,
                0,
                "hidden record must be absent from {}",
                path.display()
            );
        }
        assert_eq!(
            copy_a.manifest.content_digest, copy_b.manifest.content_digest,
            "the withheld schema row must not move visible content"
        );
        assert_eq!(
            generation_id(&copy_a.manifest),
            generation_id(&copy_b.manifest),
            "same generation identity"
        );
        assert_eq!(
            copy_a.manifest.schema_incomplete_for,
            Vec::<String>::new(),
            "baseline markers empty"
        );
        assert_eq!(
            copy_b.manifest.schema_incomplete_for,
            vec!["global".to_owned()],
            "withheld global schema row marks global"
        );
        let origin = copy_a.manifest.origin_database_id.clone();

        let transport = Arc::new(MockTransport::new(ACCT_B));
        transport.push(replace_answer(&copy_a.manifest, false, "h"));
        transport.serve("h", fs::read(&out_a).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        assert!(matches!(
            driver.refresh().await.expect("admit A"),
            RefreshDisposition::Admitted { .. }
        ));
        let ranges = transport.ranges();

        transport.push(current_answer(&copy_b.manifest, "h"));
        let disposition = driver.refresh().await.expect("marker current");
        assert!(
            matches!(
                disposition,
                RefreshDisposition::MetadataRefreshed {
                    markers_changed: true,
                    ..
                }
            ),
            "{disposition:?}"
        );
        assert_eq!(
            transport.ranges(),
            ranges,
            "marker adoption must not download"
        );
        assert!(driver.serving().is_serving());
    }

    /// A credential rotation between the runtime's eligibility read and the
    /// attempt retires the old serving gate **before** the POST, so a network
    /// failure cannot leave the old captured registry active; files remain.
    #[tokio::test]
    async fn selection_rotation_before_attempt_retires_old_gate_on_failure() {
        use crate::mcp::interactions::ToolKind;
        use crate::mcp::registry::{Caller, ToolRegistry};

        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");
        assert!(driver.serving().is_serving());

        let mut old = ToolRegistry::new();
        old.register(
            ToolKind::Ping,
            "probe",
            serde_json::json!({"type":"object"}),
            |_db, _caller, _args| async { Ok(serde_json::json!({"handler":"ran"})) },
        )
        .expect("probe");
        assert!(driver.serving().install_into(&mut old));
        let db_handle = driver.serving().database().expect("db");
        old.call(
            db_handle.clone(),
            Caller::authenticated(crate::member_offline_fixtures::ACCT_B),
            "ping",
            serde_json::json!({}),
        )
        .await
        .expect("old gate serves before rotation");

        // Rotate the credential; the mock has no scripted answer, i.e. the
        // attempt fails after the eligibility mismatch is policed.
        write_credential(dir.path(), "rotated-bearer");
        assert!(driver.refresh().await.is_err(), "rotated attempt fails");
        assert!(
            !driver.serving().is_serving(),
            "old serving retired before the failing POST"
        );
        assert!(
            old.call(
                db_handle,
                Caller::authenticated(crate::member_offline_fixtures::ACCT_B),
                "ping",
                serde_json::json!({})
            )
            .await
            .is_err(),
            "old captured registry permanently refuses"
        );
        assert!(
            dir.path()
                .join("copy")
                .join(crate::member_copy_serving::ADMISSION_FILENAME)
                .exists(),
            "held files remain after the failed rotated attempt"
        );
    }

    /// After a NotServable quiesce, the original receipt-matching selection
    /// recovers the held copy offline with a fresh gate; a changed/missing
    /// selection never recovers.
    #[tokio::test]
    async fn eligible_recovery_restores_held_after_rotation() {
        use crate::mcp::interactions::ToolKind;
        use crate::mcp::registry::{Caller, ToolRegistry};

        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");

        let register = |registry: &mut ToolRegistry| {
            registry
                .register(
                    ToolKind::Ping,
                    "probe",
                    serde_json::json!({"type":"object"}),
                    |_db, _caller, _args| async { Ok(serde_json::json!({"handler":"ran"})) },
                )
                .expect("probe");
        };
        let mut old = ToolRegistry::new();
        register(&mut old);
        assert!(driver.serving().install_into(&mut old));
        let old_db = driver.serving().database().expect("db");

        // Rotate to B; the offline attempt fails and retires the old gate.
        write_credential(dir.path(), "rotated-bearer");
        assert!(driver.refresh().await.is_err());
        assert!(!driver.serving().is_serving());
        assert_eq!(
            driver.recover_if_eligible().await.expect("b"),
            ReceiptEligibility::NotServable,
            "a changed selection never recovers"
        );
        assert!(!driver.serving().is_serving());

        // Back to A: eligibility-gated recovery restores the held copy offline.
        write_credential(dir.path(), "test-bearer");
        assert_eq!(
            driver.recover_if_eligible().await.expect("a"),
            ReceiptEligibility::HeldValidated
        );
        assert!(driver.serving().is_serving());
        assert!(
            old.call(
                old_db,
                Caller::authenticated(crate::member_offline_fixtures::ACCT_B),
                "ping",
                serde_json::json!({})
            )
            .await
            .is_err(),
            "the old captured gate stays retired"
        );
        let mut fresh = ToolRegistry::new();
        register(&mut fresh);
        assert!(driver.serving().install_into(&mut fresh));
        fresh
            .call(
                driver.serving().database().expect("db"),
                Caller::authenticated(crate::member_offline_fixtures::ACCT_B),
                "ping",
                serde_json::json!({}),
            )
            .await
            .expect("fresh gate serves after recovery");

        // A missing credential never recovers.
        fs::remove_file(dir.path().join("credential")).expect("remove credential");
        assert!(driver.recover_if_eligible().await.is_err());
        assert!(!driver.serving().is_serving());
    }

    /// A bounded refresh cancelled mid-download cleans staging and keeps the
    /// (unchanged-selection) held copy serving.
    #[tokio::test]
    async fn refresh_bounded_times_out_midrange_cleans_staging_and_holds() {
        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");
        let gen_a = driver.serving().generation_id().expect("gen").to_owned();

        crate::store::update_record(
            &db,
            two_caller::SHARED_CHILD,
            serde_json::json!({"body": "changed"}),
        )
        .await
        .expect("edit");
        let out_b = dir.path().join("b.db");
        let copy_b = produce(&db, SCOPE_A, 2, &out_b).await;
        transport.push(replace_answer(&copy_b.manifest, false, "b"));
        transport.serve("b", fs::read(&out_b).expect("bytes"));
        let ranges_before = transport.ranges();
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel::<()>();
        transport.set_on_read_enter(move || {
            let _ = deadline_tx.send(());
        });
        transport.block_reads();

        let disposition = driver
            .refresh_until_deadline(async move {
                let _ = deadline_rx.await;
            })
            .await
            .expect("bounded");
        assert!(
            transport.ranges() > ranges_before,
            "a read was entered before the deadline fired"
        );
        assert_eq!(disposition, RefreshDisposition::TimedOut);
        assert_eq!(
            driver.serving().generation_id(),
            Some(gen_a.as_str()),
            "unchanged-selection held copy stays served"
        );
        let staging = dir.path().join("copy").join("staging");
        assert!(
            fs::read_dir(&staging)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(true),
            "staging cleaned on timeout"
        );
    }

    /// A bounded refresh that times out after a NotServable selection quiesces
    /// the owner and never reactivates the old selection.
    #[tokio::test]
    async fn refresh_bounded_timeout_after_not_servable_never_reactivates_old() {
        use crate::mcp::interactions::ToolKind;
        use crate::mcp::registry::{Caller, ToolRegistry};

        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");

        let mut old = ToolRegistry::new();
        old.register(
            ToolKind::Ping,
            "probe",
            serde_json::json!({"type":"object"}),
            |_db, _caller, _args| async { Ok(serde_json::json!({"handler":"ran"})) },
        )
        .expect("probe");
        assert!(driver.serving().install_into(&mut old));
        let old_db = driver.serving().database().expect("db");

        write_credential(dir.path(), "rotated-bearer");
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel::<()>();
        transport.set_on_enter(move || {
            let _ = deadline_tx.send(());
        });
        transport.block_requests();
        let disposition = driver
            .refresh_until_deadline(async move {
                let _ = deadline_rx.await;
            })
            .await
            .expect("bounded");
        assert_eq!(disposition, RefreshDisposition::TimedOut);
        assert!(
            !driver.serving().is_serving(),
            "old serving retired after a NotServable timeout"
        );
        assert!(
            old.call(
                old_db,
                Caller::authenticated(crate::member_offline_fixtures::ACCT_B),
                "ping",
                serde_json::json!({})
            )
            .await
            .is_err(),
            "old captured gate permanently refuses"
        );
        assert!(
            dir.path()
                .join("copy")
                .join(crate::member_copy_serving::ADMISSION_FILENAME)
                .exists(),
            "held files remain"
        );
    }

    /// A credential rotation that happens after attempt entry (while the
    /// request is blocked) must retire the still-active copy on timeout.
    #[tokio::test]
    async fn refresh_bounded_rotation_midflight_retires_active_copy() {
        use crate::mcp::interactions::ToolKind;
        use crate::mcp::registry::{Caller, ToolRegistry};

        let (db, origin) = world().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("producer.db");
        let copy = produce(&db, SCOPE_A, 1, &out).await;
        let transport = Arc::new(MockTransport::new(crate::member_offline_fixtures::ACCT_B));
        transport.push(replace_answer(&copy.manifest, false, "h"));
        transport.serve("h", fs::read(&out).expect("bytes"));
        let mut driver = MemberCopyDriver::new(
            config(dir.path(), &origin),
            device_consumer(),
            transport.clone(),
        )
        .await
        .expect("driver");
        driver.refresh().await.expect("admit");

        let mut old = ToolRegistry::new();
        old.register(
            ToolKind::Ping,
            "probe",
            serde_json::json!({"type":"object"}),
            |_db, _caller, _args| async { Ok(serde_json::json!({"handler":"ran"})) },
        )
        .expect("probe");
        assert!(driver.serving().install_into(&mut old));
        let old_db = driver.serving().database().expect("db");

        // Next attempt reads A at entry; the transport hook rotates the
        // credential to B before the request blocks, so the rotation is
        // guaranteed complete before the deterministic timeout fires.
        let rotated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (deadline_tx, deadline_rx) = tokio::sync::oneshot::channel::<()>();
        let credential_dir = dir.path().to_path_buf();
        let rotated_flag = rotated.clone();
        transport.set_on_enter(move || {
            write_credential(&credential_dir, "rotated-bearer");
            rotated_flag.store(true, Ordering::SeqCst);
            let _ = deadline_tx.send(());
        });
        transport.block_requests();
        let disposition = driver
            .refresh_until_deadline(async move {
                let _ = deadline_rx.await;
            })
            .await
            .expect("bounded");
        assert!(
            rotated.load(Ordering::SeqCst),
            "rotation hook ran before the deadline fired"
        );
        assert_eq!(disposition, RefreshDisposition::TimedOut);
        assert!(
            !driver.serving().is_serving(),
            "rotated selection retires the active copy on timeout"
        );
        assert!(
            old.call(
                old_db,
                Caller::authenticated(crate::member_offline_fixtures::ACCT_B),
                "ping",
                serde_json::json!({})
            )
            .await
            .is_err(),
            "old captured gate permanently refuses"
        );
        assert!(
            dir.path()
                .join("copy")
                .join(crate::member_copy_serving::ADMISSION_FILENAME)
                .exists(),
            "files retained"
        );
    }
}
