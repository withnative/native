//! Production member-copy serving composition (D1; contract c323277 rev 8
//! §1.3, §1.5, §6/§6.1, §7.1; consumer da0a471; L3 review c98338b).
//!
//! One **serialized owner** per copy root. This module is the only production
//! seam that turns a delivered, admitted member generation into a servable
//! `Db` plus an installed [`MemberCopyGate`], and it is the only place that
//! may delete or replace a held generation:
//!
//! 1. [`MemberCopyAuthorityLock`] takes an exclusive `flock` on the copy-root
//!    **directory inode** for the owner's whole life. It is not a registered
//!    managed artefact and shares no purged path, so a scope/account purge can
//!    never unlink the held lock and let a second owner lock a recreated
//!    inode. A second owner is refused before, during and after a purge.
//! 2. [`MemberCopyServing::open`] reads the persisted admission and only
//!    activates when the lifecycle is `Ready`, the pointer names the
//!    generation, `activatable_generations()` is nonempty, and the installed
//!    file revalidates. Otherwise it serves nothing: the held-none limbos
//!    (`Refreshing` after a scope purge, a fresh account binding, a pending
//!    cleanup barrier) fail closed rather than report `Allow` from status.
//! 3. [`MemberCopyServing::quiesce`] deactivates the shared lease gate (a call
//!    already queued refuses), drains every in-flight handler plus decoration,
//!    then closes the immutable pools. It runs BEFORE any purge or replacement
//!    that deletes an old generation.
//! 4. [`MemberCopyServing::admit_candidate`] quiesces, purges first on a
//!    scope change, admits through the reviewed [`admit_member_copy`] path,
//!    persists the validated manifest, opens the member `Db`, and reactivates.
//!    A failed candidate leaves the held bytes and stays fail-closed.
//!
//! The gate installed by [`MemberCopyServing::install_into`] binds the actual
//! admitted `generation_id` into the `query_record` page basis (closing the
//! C4a residual where only `scope_ref`/`ordinal` were bound).
//!
//! This module does not perform transport, does not infer credential expiry,
//! and never exposes a raw SQLite path: it takes typed transport outcomes and
//! constructs the `Db`, gate and registry together.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fs2::FileExt as _;

use crate::db::{open_member_database_read_only, Db};
use crate::error::{Error, Result};
use crate::mcp::member_serving::{MemberCopyGate, MemberCopyLease, MemberCopyLeaseGate};
use crate::mcp::registry::ToolRegistry;
use crate::member_copy_admission::{
    admit_member_copy, revalidate_installed, validate_manifest, AdmissionError, AdmittedGeneration,
    ExpectedFooting, InstalledGeneration, SNAPSHOT_FILENAME,
};
use crate::member_copy_lifecycle::{CopyStatus, MemberCopyLifecycle, ReadDecision};
use crate::member_copy_transport::{CredentialSelection, MemberCopyContext};
use crate::standby_snapshot::StandbyConsumerIdentity;

/// Registered root file holding the validated admission metadata plus the
/// durable authenticated binding. It is named to the lifecycle as a managed
/// root file, so a full barrier / scope / account purge deletes it and a
/// same-scope superseded replace keeps it until the new metadata overwrites
/// it. This is the **single** durable binding: no second binding file exists.
pub const ADMISSION_FILENAME: &str = "admission.json";

const ADMISSION_CONTRACT: &str = "native.member-copy-admission.v3";
const ADMISSION_VERSION: u32 = 3;

/// The trusted binding recorded alongside a held generation. `account_binding`
/// is the opaque authenticated account context (never a bearer credential),
/// the origin/consumer/server/route are the pinned coordinates, and
/// `credential_fingerprint` is the SHA-256 of the retained credential
/// selection (never the bearer). These come from the ordered owner path
/// (authenticated context), never from the candidate manifest or config.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedBinding {
    account_binding: String,
    origin_database_id: String,
    server_origin: String,
    route_database_id: String,
    scope_ref: String,
    consumer: StandbyConsumerIdentity,
    credential_fingerprint: String,
}

/// Persisted, validated admission metadata. The manifest text is stored
/// verbatim so a reopen re-derives the exact validated facts; the metadata
/// alone never serves anything, it is an input the reopen validation must
/// confirm against the pointer, the binding and the installed bytes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedAdmission {
    contract: String,
    version: u32,
    binding: PersistedBinding,
    manifest_json: String,
}

impl PersistedAdmission {
    fn new(binding: PersistedBinding, json: &[u8]) -> std::result::Result<Self, AdmissionError> {
        validate_manifest(json)?;
        let manifest_json = std::str::from_utf8(json)
            .map_err(|e| AdmissionError::ManifestMalformed {
                detail: format!("manifest is not UTF-8: {e}"),
            })?
            .to_owned();
        Ok(Self {
            contract: ADMISSION_CONTRACT.to_owned(),
            version: ADMISSION_VERSION,
            binding,
            manifest_json,
        })
    }

    fn installed_facts(&self) -> std::result::Result<InstalledGeneration, AdmissionError> {
        let facts = validate_manifest(self.manifest_json.as_bytes())?;
        Ok(InstalledGeneration {
            generation_id: facts.generation_id,
            scope_ref: facts.scope_ref,
            ordinal: facts.ordinal,
            content_digest: facts.content_digest,
        })
    }

    fn schema_incomplete_for(&self) -> std::result::Result<Vec<String>, AdmissionError> {
        Ok(validate_manifest(self.manifest_json.as_bytes())?.schema_incomplete_for)
    }
}

/// Reads the persisted admission. A missing file is `Ok(None)` (the
/// held-none limbo). Malformed JSON is an error (corrupt trusted state fails
/// closed). A well-formed record of any other contract/version (legacy v1/v2 or
/// unknown) is `Ok(None)` **backward limbo**: its scope is never inferred, so a
/// legacy copy refuses offline until an authenticated refresh purges and
/// re-admits it as v3.
fn read_persisted(root: &Path) -> Result<Option<PersistedAdmission>> {
    let path = root.join(ADMISSION_FILENAME);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| Error::engine(format!("member copy admission metadata is malformed: {e}")))?;
    let current = value.get("contract").and_then(|c| c.as_str()) == Some(ADMISSION_CONTRACT)
        && value.get("version").and_then(|v| v.as_u64()) == Some(ADMISSION_VERSION as u64);
    if !current {
        return Ok(None);
    }
    let persisted: PersistedAdmission = serde_json::from_value(value)
        .map_err(|e| Error::engine(format!("member copy admission metadata is malformed: {e}")))?;
    Ok(Some(persisted))
}

/// Exclusive authority for one copy root. `flock` on the root directory inode.
pub struct MemberCopyAuthorityLock {
    file: Option<File>,
}

impl MemberCopyAuthorityLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        // A directory is opened read-only; `flock` needs no write access. The
        // directory inode is stable across every purge (only its children are
        // deleted), and SQLite never opens the root as a database, so this
        // cannot contend with SQLite's own locks.
        let file = File::open(root)?;
        file.try_lock_exclusive().map_err(|error| {
            Error::engine(format!(
                "member copy serving refused for {}: another owner already holds this root ({error})",
                root.display()
            ))
        })?;
        Ok(Self { file: Some(file) })
    }
}

impl Drop for MemberCopyAuthorityLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = fs2::FileExt::unlock(&file);
        }
    }
}

/// Atomic write: temp file in the copy root, fsync, rename, fsync the
/// directory. The temp name ends in `.tmp`, which the managed enumeration
/// already purges, so a crash mid-write leaves no managed residue.
fn write_persisted(root: &Path, persisted: &PersistedAdmission) -> Result<()> {
    let body = serde_json::to_vec(persisted)
        .map_err(|e| Error::engine(format!("member copy admission metadata serialises: {e}")))?;
    let temp = root.join(format!(".admission-{}.tmp", uuid::Uuid::new_v4()));
    let write = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(&body)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, root.join(ADMISSION_FILENAME))?;
        File::open(root)?.sync_all()
    })();
    if write.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write.map_err(Error::Io)
}

/// Restores the expected scope from the durable v3 binding only when every
/// trust condition holds: the binding's origin/server/route/consumer equal the
/// device pins, its account equals the lifecycle's bound account, and its scope
/// equals the scope of the held manifest. The credential is **not** read here
/// (offline open cannot); credential association is
/// `held_receipt_eligibility`'s job. Any mismatch restores nothing.
fn restored_scope(
    persisted: &Option<PersistedAdmission>,
    lifecycle_account: Option<&str>,
    origin_database_id: Option<&str>,
    server_origin: &str,
    route_database_id: &str,
    consumer: &StandbyConsumerIdentity,
) -> Option<String> {
    let persisted = persisted.as_ref()?;
    let binding = &persisted.binding;
    let manifest_scope = validate_manifest(persisted.manifest_json.as_bytes())
        .ok()?
        .scope_ref;
    if Some(binding.origin_database_id.as_str()) != origin_database_id
        || binding.server_origin != server_origin
        || binding.route_database_id != route_database_id
        || &binding.consumer != consumer
        || lifecycle_account != Some(binding.account_binding.as_str())
        || binding.scope_ref != manifest_scope
    {
        return None;
    }
    Some(binding.scope_ref.clone())
}

/// Whether any managed generation directory remains under the copy root.
fn managed_generations_present(root: &Path) -> bool {
    let Ok(entries) = fs::read_dir(root.join("generations")) else {
        return false;
    };
    entries.flatten().next().is_some()
}

/// One admitted, servable generation plus its immutable read-only `Db`.
struct ActiveServing {
    admitted: AdmittedGeneration,
    db: Db,
}

/// Outcome of [`MemberCopyServing::bind_scope`]. `Bound` is a first binding,
/// `AlreadyBound` an idempotent re-statement (reopen or periodic reconnect),
/// `Rebound` a change accepted only after the held generation was purged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeBinding {
    Bound,
    AlreadyBound,
    Rebound,
}

/// Whether the held copy may be served under the **current** credential
/// selection. Pure, no network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptEligibility {
    /// A v3 receipt exists, pins/server/route/account/scope match, and the
    /// current selection's fingerprint equals the stored fingerprint.
    HeldValidated,
    /// No receipt, or a changed/missing selection, or any mismatch: the held
    /// copy must not be published/served.
    NotServable,
}

/// The single serialized owner of one member copy root.
pub struct MemberCopyServing {
    root: PathBuf,
    /// Fixed device pins. None is an **ungrounded** origin: it must be set from
    /// an authenticated [`MemberCopyContext`] before any admission.
    origin_database_id: Option<String>,
    /// Exact configured server origin and route pins (empty on the legacy
    /// `open`/test-convenience path).
    server_origin: String,
    route_database_id: String,
    consumer: StandbyConsumerIdentity,
    /// The authenticated member scope, `None` until a typed transport answer
    /// binds it. Never set from a config/caller string or a manifest. After a
    /// scope/account purge it is retained only as a **transition hint** (so a
    /// later same-scope bind reports `Rebound`); it is inert for admission
    /// while `scope_needs_rebind` is set.
    scope_bound: Option<String>,
    /// `true` when a scope/account purge has removed the held copy and a fresh
    /// authenticated bind is required before any admission. While set,
    /// `expected_footing()`/`is_scope_bound()` treat the retained `scope_bound`
    /// as inert, so an old-scope candidate staged after the purge cannot be
    /// admitted under stale authorization.
    scope_needs_rebind: bool,
    _authority: MemberCopyAuthorityLock,
    lifecycle: Arc<Mutex<MemberCopyLifecycle>>,
    leases: Arc<MemberCopyLeaseGate>,
    active: Option<ActiveServing>,
    persisted: Option<PersistedAdmission>,
}

impl MemberCopyServing {
    /// Opens the owner with a caller-supplied footing (legacy/D1 path),
    /// binding the scope immediately. No scope is read from disk.
    pub async fn open(root: &Path, expected: ExpectedFooting) -> Result<Self> {
        Self::open_inner(
            root,
            Some(expected.origin_database_id),
            String::new(),
            String::new(),
            expected.consumer,
            Some(expected.scope_ref),
        )
        .await
    }

    /// D2 driver constructor: grounded-or-ungrounded origin pin, exact
    /// configured server origin/route, and the device consumer. The scope is
    /// unbound until the first authenticated answer; a reopen restores a v3
    /// receipt whose pins/server/route/account/scope all match.
    pub async fn open_unbound_routed(
        root: &Path,
        origin_database_id: Option<String>,
        server_origin: String,
        route_database_id: String,
        consumer: StandbyConsumerIdentity,
    ) -> Result<Self> {
        Self::open_inner(
            root,
            origin_database_id,
            server_origin,
            route_database_id,
            consumer,
            None,
        )
        .await
    }

    /// Test/D1 convenience: a grounded origin with empty server/route pins.
    pub async fn open_unbound(
        root: &Path,
        origin_database_id: String,
        consumer: StandbyConsumerIdentity,
    ) -> Result<Self> {
        Self::open_inner(
            root,
            Some(origin_database_id),
            String::new(),
            String::new(),
            consumer,
            None,
        )
        .await
    }

    async fn open_inner(
        root: &Path,
        origin_database_id: Option<String>,
        server_origin: String,
        route_database_id: String,
        consumer: StandbyConsumerIdentity,
        explicit_scope: Option<String>,
    ) -> Result<Self> {
        let authority = MemberCopyAuthorityLock::acquire(root)?;
        // Opening the lifecycle first resumes any pending cleanup before the
        // admission metadata is read, so a crash mid-purge never lets a stale
        // binding restore.
        let lifecycle = MemberCopyLifecycle::open_with_managed(
            root,
            Vec::new(),
            vec![ADMISSION_FILENAME.to_owned()],
        )?;
        let lifecycle_account = lifecycle.account_token().map(str::to_owned);
        let lifecycle = Arc::new(Mutex::new(lifecycle));
        let leases = MemberCopyLeaseGate::new(false);
        let persisted = read_persisted(root)?;
        let scope_bound = explicit_scope.or_else(|| {
            restored_scope(
                &persisted,
                lifecycle_account.as_deref(),
                origin_database_id.as_deref(),
                &server_origin,
                &route_database_id,
                &consumer,
            )
        });
        let mut serving = Self {
            root: root.to_path_buf(),
            origin_database_id,
            server_origin,
            route_database_id,
            consumer,
            scope_bound,
            scope_needs_rebind: false,
            _authority: authority,
            lifecycle,
            leases,
            active: None,
            persisted,
        };
        serving.recover_persisted().await;
        Ok(serving)
    }

    /// Assembles the admission footing from the fixed pins and the currently
    /// **active** scope. `None` while unbound or while a fresh bind is
    /// required: admission and activation then fail closed rather than compare
    /// against a retained transition hint.
    fn expected_footing(&self) -> Option<ExpectedFooting> {
        if self.scope_needs_rebind {
            return None;
        }
        Some(ExpectedFooting {
            origin_database_id: self.origin_database_id.clone()?,
            scope_ref: self.scope_bound.clone()?,
            consumer: self.consumer.clone(),
        })
    }

    /// The only scope mutator, kept crate-private to the ordered owner path.
    /// It consumes a sealed transport-derived token, so no config/caller/
    /// manifest string can reach it, and it requires the authenticated account
    /// to equal the account already bound in the lifecycle.
    ///
    /// A same-scope re-statement is a pure no-op (`AlreadyBound`) only while no
    /// fresh bind is required; after a purge a same-scope bind must still pass
    /// the clean-`Refreshing` eligibility check and reports `Rebound`. A
    /// first/new binding requires a completed, clean `Refreshing` position: no
    /// pending journal, no held pointer, no admission record, no served
    /// generation and no managed generation directories. Pointer absence alone
    /// is insufficient — it also describes barriers, `Removed` and externally
    /// deleted pointers.
    pub(crate) fn bind_scope(&mut self, context: &MemberCopyContext) -> Result<ScopeBinding> {
        let account = context.account_binding();
        let scope = context.scope_ref();
        if scope.is_empty() {
            return Err(Error::engine("empty authenticated scope"));
        }
        if account.is_empty() {
            return Err(Error::engine("empty authenticated account"));
        }
        let bound_account = self
            .lifecycle
            .lock()
            .expect("member copy lifecycle lock is never poisoned")
            .account_token()
            .map(str::to_owned);
        if bound_account.as_deref() != Some(account) {
            return Err(Error::engine(
                "scope binding refused: authenticated account does not match the bound account",
            ));
        }
        if self.scope_bound.as_deref() == Some(scope) && !self.scope_needs_rebind {
            return Ok(ScopeBinding::AlreadyBound);
        }
        self.require_binding_eligible()?;
        let rebound = self.scope_bound.is_some();
        self.scope_bound = Some(scope.to_owned());
        self.scope_needs_rebind = false;
        Ok(if rebound {
            ScopeBinding::Rebound
        } else {
            ScopeBinding::Bound
        })
    }

    /// The fail-closed eligibility predicate for a first/new binding. The
    /// effective status must be `Refreshing` (which already excludes a pending
    /// cleanup journal), nothing must be held, no admission record may exist,
    /// and no managed generation directory may remain.
    fn require_binding_eligible(&self) -> Result<()> {
        {
            let lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            if !matches!(lifecycle.effective_status(), CopyStatus::Refreshing { .. }) {
                return Err(Error::engine(
                    "scope binding refused: the copy is not in a completed refreshing state",
                ));
            }
            if lifecycle.current_generation_id()?.is_some() {
                return Err(Error::engine(
                    "scope binding refused: a held generation pointer is present",
                ));
            }
        }
        if self.active.is_some() || self.persisted.is_some() {
            return Err(Error::engine(
                "scope binding refused: a held generation or admission record is present",
            ));
        }
        if managed_generations_present(&self.root) {
            return Err(Error::engine(
                "scope binding refused: managed generations are still present",
            ));
        }
        Ok(())
    }

    /// The last authenticated scope: an **active** binding when
    /// [`Self::is_scope_bound`] is true, otherwise a transition hint retained
    /// through a purge (so a later same-scope bind reports `Rebound`). It is
    /// always inert for admission; only `expected_footing` decides that.
    pub fn bound_scope_ref(&self) -> Option<&str> {
        self.scope_bound.as_deref()
    }

    /// Whether a scope is **actively** bound (authenticated and not awaiting a
    /// fresh rebind).
    pub fn is_scope_bound(&self) -> bool {
        self.scope_bound.is_some() && !self.scope_needs_rebind
    }

    /// Whether a purge left the owner awaiting a fresh authenticated bind (the
    /// retained `scope_bound` is only a transition hint in this state).
    pub fn is_rebind_required(&self) -> bool {
        self.scope_needs_rebind
    }

    /// The pinned canonical origin, if grounded.
    pub fn origin_database_id(&self) -> Option<&str> {
        self.origin_database_id.as_deref()
    }

    /// Grounds or checks the portable origin from a sealed authenticated
    /// context. The **only** origin mutator: a configured pin is a constraint
    /// (must equal the authenticated origin), never identity proof, and the
    /// authenticated manifest origin is the first-pin source.
    pub fn ground_origin(&mut self, context: &MemberCopyContext) -> Result<()> {
        let origin = context.origin_database_id();
        if origin.is_empty() {
            return Err(Error::engine("authenticated origin is empty"));
        }
        match &self.origin_database_id {
            None => {
                self.origin_database_id = Some(origin.to_owned());
                Ok(())
            }
            Some(pinned) if pinned == origin => Ok(()),
            Some(_) => Err(Error::engine(
                "authenticated origin disagrees with the configured pin",
            )),
        }
    }

    /// The immutable pinned device consumer declaration.
    pub fn device_consumer(&self) -> &StandbyConsumerIdentity {
        &self.consumer
    }

    /// The lifecycle account token currently bound, if any.
    pub fn account_token(&self) -> Option<String> {
        self.lifecycle
            .lock()
            .ok()
            .and_then(|lifecycle| lifecycle.account_token().map(str::to_owned))
    }

    /// The effective lifecycle status.
    pub fn lifecycle_status(&self) -> CopyStatus {
        self.lifecycle
            .lock()
            .map(|lifecycle| lifecycle.effective_status())
            .unwrap_or(CopyStatus::Unavailable)
    }

    /// Both request hints from **one** predicate: `Some((generation_id,
    /// scope_ref))` only when a v3 receipt is restored, the scope is actively
    /// bound, a held admission names the pointer, and the lifecycle is
    /// servable/unlockable (`Ready`/`Locked`, or `Refreshing` with a held cut).
    /// Excludes `Unavailable`/unbound and never claims a generation whose scope
    /// is withheld. Preserves `Locked` so a same-account `Current` still
    /// unlocks without a redownload.
    pub fn held_hints(&self) -> Option<(String, String)> {
        if self.scope_needs_rebind {
            return None;
        }
        let scope = self.scope_bound.clone()?;
        let persisted = self.persisted.as_ref()?;
        let facts = persisted.installed_facts().ok()?;
        let pointer_names = self
            .lifecycle
            .lock()
            .ok()
            .and_then(|lifecycle| lifecycle.current_generation_id().ok().flatten())
            .map(|generation| generation == facts.generation_id)
            .unwrap_or(false);
        if !pointer_names {
            return None;
        }
        let servable = matches!(
            self.lifecycle_status(),
            CopyStatus::Ready { .. } | CopyStatus::Locked { .. } | CopyStatus::Refreshing { .. }
        );
        servable.then_some((facts.generation_id, scope))
    }

    /// Whether the held copy may be served under `current`. Pure, no network.
    pub fn held_receipt_eligibility(&self, current: &CredentialSelection) -> ReceiptEligibility {
        let Some(persisted) = self.persisted.as_ref() else {
            return ReceiptEligibility::NotServable;
        };
        let binding = &persisted.binding;
        if binding.credential_fingerprint.is_empty()
            || Some(binding.origin_database_id.as_str()) != self.origin_database_id.as_deref()
            || binding.server_origin != self.server_origin
            || binding.route_database_id != self.route_database_id
            || binding.consumer != self.consumer
            || self.account_token().as_deref() != Some(binding.account_binding.as_str())
            || !self.is_scope_bound()
            || self.bound_scope_ref() != Some(binding.scope_ref.as_str())
            || current.fingerprint_sha256() != binding.credential_fingerprint
        {
            return ReceiptEligibility::NotServable;
        }
        ReceiptEligibility::HeldValidated
    }

    /// Adopt fresh same-identity `Current` metadata **without a redownload**.
    /// The manifest must agree on origin/consumer/scope/account/generation/
    /// content-digest/ordinal with the held admission; a truthful fresh v3
    /// receipt is persisted. If the admitted schema markers change, the old
    /// serving leases are drained and a **fresh** lease gate is installed (old
    /// captured registries permanently refuse); otherwise leases are left
    /// intact. Returns whether markers changed.
    pub async fn adopt_current_metadata(
        &mut self,
        manifest_json: &[u8],
        context: &MemberCopyContext,
    ) -> Result<bool> {
        self.ground_origin(context)?;
        if context.account_binding().is_empty() {
            return Err(Error::engine("authenticated account is empty"));
        }
        let (installed, previous_markers) = match self.persisted.as_ref() {
            Some(persisted) => (
                persisted
                    .installed_facts()
                    .map_err(|e| Error::engine(format!("held admission invalid: {e}")))?,
                persisted
                    .schema_incomplete_for()
                    .map_err(|e| Error::engine(format!("held admission invalid: {e}")))?,
            ),
            None => return Err(Error::engine("metadata refresh refused: no held admission")),
        };
        let facts = validate_manifest(manifest_json)
            .map_err(|e| Error::engine(format!("current manifest is not admissible: {e}")))?;
        if Some(facts.origin_database_id.as_str()) != self.origin_database_id.as_deref()
            || facts.consumer != self.consumer
            || !self.is_scope_bound()
            || self.bound_scope_ref() != Some(facts.scope_ref.as_str())
            || self.account_token().as_deref() != Some(context.account_binding())
            || context.scope_ref() != facts.scope_ref
            || facts.generation_id != installed.generation_id
            || facts.content_digest != installed.content_digest
            || facts.ordinal != installed.ordinal
        {
            return Err(Error::engine(
                "metadata refresh refused: current identity does not match the held copy",
            ));
        }
        let binding = PersistedBinding {
            account_binding: context.account_binding().to_owned(),
            origin_database_id: self.origin_database_id.clone().unwrap_or_default(),
            server_origin: context.server_origin().to_owned(),
            route_database_id: context.route_database_id().to_owned(),
            scope_ref: facts.scope_ref.clone(),
            consumer: self.consumer.clone(),
            credential_fingerprint: context.selection_fingerprint_sha256(),
        };
        let rewritten = PersistedAdmission::new(binding, manifest_json)
            .map_err(|e| Error::engine(format!("metadata refresh failed: {e}")))?;
        write_persisted(&self.root, &rewritten)?;
        self.persisted = Some(rewritten);
        let markers_changed = previous_markers != facts.schema_incomplete_for;
        if markers_changed {
            // Retire old leases/gate and reactivate with a fresh gate so any
            // captured old-marker registry permanently refuses.
            self.quiesce().await;
            self.recover_persisted().await;
            if !self.is_serving() {
                return Err(Error::engine(
                    "metadata refresh could not reactivate the held copy",
                ));
            }
        } else if let Some(active) = self.active.as_mut() {
            active.admitted.cut_at = facts.captured_at.clone();
            active.admitted.schema_incomplete_for = facts.schema_incomplete_for.clone();
        }
        Ok(markers_changed)
    }

    /// Reconciles the in-memory admission/binding cache with a lifecycle
    /// transition that actually purged the managed copy. A `Removed` effective
    /// status (including a pending full-barrier journal, which reads as
    /// `Removed` when the stored status is `Removed`) means the admission
    /// record and any durable binding are gone: drop both so no stale
    /// installed-generation/scope hint can be sent and no stale association is
    /// served. `Locked` (and a local-only `Unavailable`) keep the held
    /// bytes/binding, so nothing is cleared for them.
    fn reconcile_purged_state(&mut self, status: &CopyStatus) {
        if matches!(status, CopyStatus::Removed { .. }) {
            self.persisted = None;
            self.scope_bound = None;
            self.scope_needs_rebind = false;
        }
    }

    /// Re-validates the persisted admission against the live lifecycle and
    /// installed bytes and activates only on every positive signal. Used at
    /// open and after a failed candidate; a failure leaves serving inactive.
    async fn recover_persisted(&mut self) {
        let Some(persisted) = self.persisted.clone() else {
            return;
        };
        let Some(active) = self.validate_active(&persisted).await else {
            return;
        };
        self.active = Some(active);
        self.leases = MemberCopyLeaseGate::new(true);
    }

    /// The fail-closed activation predicate: `Ready` status, allowed read
    /// decision, pointer names the generation, nonempty activatable set, and
    /// the installed file revalidates. Nothing here trusts status alone.
    async fn validate_active(&self, persisted: &PersistedAdmission) -> Option<ActiveServing> {
        let facts = validate_manifest(persisted.manifest_json.as_bytes()).ok()?;
        {
            let lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            if !matches!(lifecycle.status(), CopyStatus::Ready { .. }) {
                return None;
            }
            if !matches!(lifecycle.read_decision(), ReadDecision::Allow) {
                return None;
            }
            if lifecycle.current_generation_id().ok()?? != facts.generation_id {
                return None;
            }
            let activatable = lifecycle.activatable_generations().ok()?;
            if !activatable.iter().any(|id| id == &facts.generation_id) {
                return None;
            }
        }
        let expected = self.expected_footing()?;
        let admitted =
            revalidate_installed(&self.root, persisted.manifest_json.as_bytes(), &expected).ok()?;
        let snapshot = admitted.generation_dir.join(SNAPSHOT_FILENAME);
        let db = open_member_database_read_only(snapshot.to_str()?)
            .await
            .ok()?;
        Some(ActiveServing { admitted, db })
    }

    /// Whether a validated generation is currently served.
    pub fn is_serving(&self) -> bool {
        self.active.is_some()
    }

    /// The admitted generation id currently served, if any.
    pub fn generation_id(&self) -> Option<&str> {
        self.active
            .as_ref()
            .map(|active| active.admitted.generation_id.as_str())
    }

    /// The generation id recorded in durable admission metadata, if any. It
    /// is the device's *held* identity and is available even when serving is
    /// inactive (limbo / `Locked`); the driver uses it only as a request
    /// input, never to set scope.
    pub fn installed_generation_id(&self) -> Option<String> {
        self.persisted
            .as_ref()
            .and_then(|persisted| persisted.installed_facts().ok())
            .map(|facts| facts.generation_id)
    }

    /// The content digest recorded in durable admission metadata, if any.
    pub fn installed_content_digest(&self) -> Option<String> {
        self.persisted
            .as_ref()
            .and_then(|persisted| persisted.installed_facts().ok())
            .map(|facts| facts.content_digest)
    }

    /// The shared read-only `Db` for the active generation, if any. The
    /// composition hands this to the transport; a quiesce closes it.
    pub fn database(&self) -> Option<Db> {
        self.active.as_ref().map(|active| active.db.clone())
    }

    /// Takes one read lease for a whole dispatch. Refuses while inactive or
    /// quiescing, so no handler runs over a purged or replaced generation.
    /// Crate-visible: the transport layers hold it inside a dispatch; it is
    /// not part of the public composition surface.
    #[allow(dead_code)]
    pub(crate) fn begin_read(&self) -> Result<MemberCopyLease> {
        self.leases.acquire()
    }

    /// Deactivates new reads, drains every in-flight handler plus decoration,
    /// and only then closes the immutable pools. MUST run before any purge or
    /// replacement that deletes the held generation.
    pub async fn quiesce(&mut self) {
        self.leases.deactivate();
        self.leases.drain().await;
        if let Some(active) = self.active.take() {
            active.db.close().await;
        }
    }

    /// Installs the serving gate on `registry`, bound to the actual admitted
    /// generation. Returns whether a gate was installed; when inactive nothing
    /// is installed, so a member `Db` on that registry refuses (no raw path).
    pub fn install_into(&self, registry: &mut ToolRegistry) -> bool {
        let Some(active) = &self.active else {
            return false;
        };
        let Some(account_token) = self
            .lifecycle
            .lock()
            .ok()
            .and_then(|lifecycle| lifecycle.account_token().map(str::to_owned))
        else {
            return false;
        };
        let admitted = &active.admitted;
        let gate = MemberCopyGate::with_leases(
            self.lifecycle.clone(),
            admitted.scope_ref.clone(),
            admitted.ordinal,
            admitted.schema_incomplete_for.clone(),
            self.leases.clone(),
        )
        .with_generation_id(admitted.generation_id.clone())
        .with_admission_binding(active.db.handle_id(), account_token);
        registry.set_member_copy_gate_instance(gate);
        true
    }

    /// Applies a typed reconnect answer to the lifecycle, quiescing first
    /// whenever the answer will require an old generation to be deleted
    /// (`Replace{scope_changed}`) or must stop serving (`Locked`/`Revoked`).
    pub async fn apply_reconnect(
        &mut self,
        answer: crate::member_copy_lifecycle::ReconnectAnswer,
    ) -> Result<CopyStatus> {
        use crate::member_copy_lifecycle::ReconnectAnswer;
        let must_stop = !matches!(answer, ReconnectAnswer::Current);
        if must_stop {
            self.quiesce().await;
        }
        let (outcome, effective) = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            let outcome = lifecycle.apply_reconnect(answer);
            let effective = lifecycle.effective_status();
            (outcome, effective)
        };
        // Reconcile on the effective status even when the call returned an
        // error: a failure can leave a completed/partial full purge whose
        // in-memory cache must not survive. This is keyed on `Removed` only,
        // so an unchanged/local-`Unavailable` error clears nothing.
        self.reconcile_purged_state(&effective);
        outcome
    }

    /// Signs in and unlocks, quiescing readers first (sign-in can begin the
    /// first-binding deletion). A `Locked` copy keeps its files; this is the
    /// only path that clears `Locked`.
    pub async fn sign_in(
        &mut self,
        account_token: &str,
        answer: crate::member_copy_lifecycle::ReconnectAnswer,
    ) -> Result<CopyStatus> {
        self.quiesce().await;
        let (outcome, effective) = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            let outcome = lifecycle.sign_in(account_token, answer);
            let effective = lifecycle.effective_status();
            (outcome, effective)
        };
        // Same error-path reconciliation as `apply_reconnect`.
        self.reconcile_purged_state(&effective);
        outcome
    }

    /// §1.5 scope/account-change purge. Quiesces readers and closes the old
    /// pools FIRST, then runs the journaled full managed purge — which deletes
    /// every generation, `staging/*`, sidecars, the pointer AND the registered
    /// admission metadata. The caller downloads and calls
    /// [`Self::admit_candidate`] AFTER this returns, so nothing staged before
    /// the purge can survive into the new generation.
    ///
    /// The in-memory active binding is dropped and `scope_needs_rebind` is set
    /// so the retained old scope is inert for admission until a fresh
    /// authenticated [`Self::bind_scope`]. A `Locked`/`Removed` copy is a
    /// lifecycle no-op that keeps its held hints: the cache is cleared only
    /// when the purge actually ran.
    pub async fn begin_scope_change_purge(&mut self, target_cut_at: &str) -> Result<CopyStatus> {
        self.quiesce().await;
        let result = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            lifecycle.purge_for_scope_change(target_cut_at, &crate::member_copy_lifecycle::NoFail)
        };
        match result {
            Ok(status) => {
                if !matches!(
                    status,
                    CopyStatus::Locked { .. } | CopyStatus::Removed { .. }
                ) {
                    self.persisted = None;
                    self.scope_needs_rebind = true;
                }
                Ok(status)
            }
            Err(error) => {
                // A failed scope purge fails closed: drop the stale active
                // authorization and require a fresh authenticated bind.
                self.persisted = None;
                self.scope_needs_rebind = true;
                Err(error)
            }
        }
    }

    /// Admits a delivered candidate. Quiesces and closes the old pools BEFORE
    /// any delete or replace; admits through the reviewed path; persists
    /// validated metadata; opens the member `Db`; reactivates. A refused
    /// candidate leaves serving inactive and the held bytes untouched.
    pub async fn admit_candidate(
        &mut self,
        staged: &Path,
        manifest_json: &[u8],
        context: &MemberCopyContext,
    ) -> std::result::Result<AdmittedGeneration, AdmissionError> {
        self.quiesce().await;
        self.ground_origin(context)
            .map_err(|error| AdmissionError::Lifecycle {
                detail: error.to_string(),
            })?;
        if self.origin_database_id.is_none() {
            return Err(AdmissionError::Lifecycle {
                detail: "origin not grounded".to_owned(),
            });
        }
        let installed = match self.persisted.as_ref() {
            Some(persisted) => Some(persisted.installed_facts()?),
            None => None,
        };
        let expected = self.expected_footing().ok_or(AdmissionError::Lifecycle {
            detail: "scope not bound".to_owned(),
        })?;
        let lifecycle_account = self
            .lifecycle
            .lock()
            .ok()
            .and_then(|lifecycle| lifecycle.account_token().map(str::to_owned));
        if lifecycle_account.as_deref() != Some(context.account_binding()) {
            return Err(AdmissionError::Lifecycle {
                detail: "account context mismatch".to_owned(),
            });
        }
        let admitted = {
            let mut lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            admit_member_copy(
                &self.root,
                staged,
                manifest_json,
                installed.as_ref(),
                &expected,
                &mut lifecycle,
            )?
        };
        // Persist the trusted binding with the validated manifest AFTER a
        // successful admission and BEFORE any activation, so a crash between
        // promotion and commit can never make the device serve bytes whose
        // scope/account/credential it cannot re-derive from owner metadata.
        let binding = PersistedBinding {
            account_binding: context.account_binding().to_owned(),
            origin_database_id: expected.origin_database_id.clone(),
            server_origin: context.server_origin().to_owned(),
            route_database_id: context.route_database_id().to_owned(),
            scope_ref: expected.scope_ref.clone(),
            consumer: expected.consumer.clone(),
            credential_fingerprint: context.selection_fingerprint_sha256(),
        };
        let persisted = PersistedAdmission::new(binding, manifest_json)?;
        write_persisted(&self.root, &persisted).map_err(|e| AdmissionError::Io {
            detail: e.to_string(),
        })?;
        let snapshot = admitted.generation_dir.join(SNAPSHOT_FILENAME);
        let db = open_member_database_read_only(snapshot.to_str().unwrap_or_default())
            .await
            .map_err(|e| AdmissionError::Io {
                detail: e.to_string(),
            })?;
        self.active = Some(ActiveServing {
            admitted: admitted.clone(),
            db,
        });
        self.persisted = Some(persisted);
        self.leases = MemberCopyLeaseGate::new(true);
        Ok(admitted)
    }

    /// After a failed candidate, try to resume serving the held generation
    /// from persisted metadata. Returns whether serving was restored; failure
    /// leaves the copy fail-closed rather than serving unvalidated bytes.
    pub async fn recover_after_failed_candidate(&mut self) -> bool {
        self.quiesce().await;
        self.recover_persisted().await;
        self.is_serving()
    }
}

/// Test-only convenience wrappers that build a sealed context from the owner's
/// current origin pin. This is fixture provenance only; production callers
/// always pass a real adapter [`MemberCopyContext`].
#[cfg(test)]
impl MemberCopyServing {
    fn test_context(&self, account: &str, scope: &str) -> MemberCopyContext {
        let origin = self.origin_database_id.clone().unwrap_or_default();
        MemberCopyContext::for_test(account, &origin, scope)
    }

    pub(crate) fn bind_scope_for(&mut self, account: &str, scope: &str) -> Result<ScopeBinding> {
        let context = self.test_context(account, scope);
        self.bind_scope(&context)
    }

    /// Admit using the manifest's own scope and the lifecycle's bound account.
    /// Fixture-only; production always passes a real adapter context.
    pub(crate) async fn admit_auto(
        &mut self,
        staged: &Path,
        manifest_json: &[u8],
    ) -> std::result::Result<AdmittedGeneration, AdmissionError> {
        let facts = validate_manifest(manifest_json)?;
        let account = self.account_token().unwrap_or_default();
        let context = self.test_context(&account, &facts.scope_ref);
        self.admit_candidate(staged, manifest_json, &context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holding::{HoldingDisclosureV2, ReplicaScope};
    use crate::member_copy_lifecycle::ReconnectAnswer;
    use crate::member_digest::content_digest;
    use crate::replica_generation::{
        ReplicaGenerationManifest, ReplicaOrdering, ReplicaOwnWrites, ReplicaProfile,
        REPLICA_GENERATION_CONTRACT, REPLICA_GENERATION_VERSION,
    };
    use crate::schema::member_schema::{member_ddl_statements, member_schema_digest};
    use crate::standby_snapshot::{
        StandbyConsumerIdentity, StandbyConsumerPlatform, StandbyGenerationMaterialization,
        StandbySnapshotBytes, StandbySnapshotEngineIdentity, STANDBY_CONSUMER_CONTRACT,
        STANDBY_SNAPSHOT_MEDIA_TYPE,
    };
    use rusqlite::Connection;
    use sha2::Digest as _;

    const ORIGIN: &str = "ndb_33333333333333333333333333333333";
    const SCOPE: &str = "scope-ref-1";
    const CUT: &str = "2026-09-30T00:00:00Z";

    /// Minimal valid member world, copied from the admission fixture so the
    /// producer-built bytes pass the same closure/fk/blob checks.
    const FIXTURE_SQL: &str = "
        INSERT INTO records (id, type, kind, name, body, home_id, owner_id, lifecycle,
            persistence, maturity, summary, last_activity_at, created_at, updated_at,
            deleted_at, archived)
        VALUES ('r1','Document','note','alpha','hello',NULL,NULL,'active','enduring',
            NULL,'sum','2026-09-30T00:00:00Z','2026-09-30T00:00:00Z',
            '2026-09-30T00:00:01Z',NULL,0);
        INSERT INTO records (id, type, kind, name, home_id, persistence, created_at, updated_at, archived)
        VALUES ('a1','Document','attachment','a1.txt',NULL,'enduring',
            '2026-09-30T00:00:00Z','2026-09-30T00:00:00Z',0);
        INSERT INTO links (id, source_id, target_id, relationship, note, created_at)
        VALUES ('l1','a1','r1','part_of',NULL,'2026-09-30T00:00:00Z');
        INSERT INTO blobs (id, bytes, mime, size_bytes, sha256, original_filename,
            storage_tier, external_ref, created_at, external_ref_withheld)
        VALUES ('b1', x'0102','text/plain',2,'aaa','a1.txt','inline',NULL,
            '2026-09-30T00:00:00Z',0);
        INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at)
        VALUES ('f1','a1','blob_ref','b1',NULL,'2026-09-30T00:00:00Z');
        INSERT INTO member_display_references (record_id, display_reference)
        VALUES ('r1','a1b2'), ('a1','c3d4');";

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "c".repeat(40),
            artifact_sha256: "d".repeat(64),
            engine_schema_version: 1,
            ddl_sha256: "e".repeat(64),
        }
    }

    fn footing() -> ExpectedFooting {
        ExpectedFooting {
            origin_database_id: ORIGIN.to_owned(),
            scope_ref: SCOPE.to_owned(),
            consumer: consumer(),
        }
    }

    /// Writes a valid member file at `path`; `body` differentiates generations
    /// without changing the visible id set.
    fn write_member_file(path: &Path, body: &str) -> String {
        let connection = Connection::open(path).expect("member fixture opens");
        connection
            .execute_batch(&member_ddl_statements().join(";\n"))
            .expect("member DDL applies");
        connection
            .execute_batch(FIXTURE_SQL)
            .expect("member fixture inserts");
        connection
            .execute_batch(&format!("UPDATE records SET body='{body}' WHERE id='r1';"))
            .expect("body update");
        let digest = content_digest(&connection).expect("digest computes");
        drop(connection);
        digest
    }

    fn manifest_for(path: &Path, digest: &str, ordinal: i64) -> Vec<u8> {
        manifest_for_scope(path, digest, ordinal, SCOPE)
    }

    /// Same member bytes and pinned origin/consumer; only `scope_ref` (hence
    /// the derived `generation_id`) differs. This is what makes the scope
    /// binding test nonvacuous.
    fn manifest_for_scope(path: &Path, digest: &str, ordinal: i64, scope_ref: &str) -> Vec<u8> {
        let bytes = fs::read(path).expect("fixture bytes read");
        let manifest = ReplicaGenerationManifest {
            contract: REPLICA_GENERATION_CONTRACT.to_owned(),
            version: REPLICA_GENERATION_VERSION,
            origin_database_id: ORIGIN.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            captured_at: CUT.to_owned(),
            snapshot_completed_at: "2026-09-30T00:00:01Z".to_owned(),
            producer: StandbySnapshotEngineIdentity {
                name: "native-ce".to_owned(),
                source_sha: "a".repeat(40),
                schema_version: 1,
                ddl_sha256: "b".repeat(64),
            },
            consumer: consumer(),
            bytes: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.to_owned(),
                size_bytes: bytes.len() as u64,
                sha256: hex::encode(sha2::Sha256::digest(&bytes)),
            },
            materialization: StandbyGenerationMaterialization::Snapshot,
            scope: ReplicaScope::Member {
                scope_ref: scope_ref.to_owned(),
            },
            ordering: ReplicaOrdering::Scoped { ordinal },
            holding: HoldingDisclosureV2::member(scope_ref.to_owned(), ordinal),
            profile: ReplicaProfile::MemberReadV1 {
                member_schema_digest: member_schema_digest(),
            },
            content_digest: digest.to_owned(),
            own_writes: ReplicaOwnWrites::not_computed(),
            frontier: None,
            schema_incomplete_for: Vec::new(),
        };
        serde_json::to_vec(&manifest).expect("manifest serialises")
    }

    /// A copy root plus a staged member file.
    fn staged(root: &Path, body: &str) -> (PathBuf, String) {
        fs::create_dir_all(root.join("staging")).expect("staging dir");
        let path = root
            .join("staging")
            .join(format!("incoming-{body}-{}.db", uuid::Uuid::new_v4()));
        let digest = write_member_file(&path, body);
        (path, digest)
    }

    /// A defended authority lock must refuse a second owner before, during and
    /// after a scope-change purge: the lock is on the root directory inode, so
    /// deleting every managed child neither unlinks it nor lets a second owner
    /// lock a recreated inode.
    #[test]
    fn authority_lock_refuses_second_owner_through_scope_purge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let first = MemberCopyAuthorityLock::acquire(&root).expect("first owner");
        assert!(
            MemberCopyAuthorityLock::acquire(&root).is_err(),
            "second owner must be refused before a purge"
        );
        {
            let mut lifecycle = MemberCopyLifecycle::open(&root).expect("lifecycle");
            lifecycle
                .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
                .expect("sign-in");
            lifecycle
                .purge_for_scope_change(CUT, &crate::member_copy_lifecycle::NoFail)
                .expect("scope purge");
        }
        assert!(
            MemberCopyAuthorityLock::acquire(&root).is_err(),
            "second owner must still be refused after the purge deleted every managed child"
        );
        drop(first);
        MemberCopyAuthorityLock::acquire(&root).expect("lock releases with the first owner");
    }

    /// A stalled reader (a held lease) must block drain — and therefore the
    /// deletion that follows it — until the lease drops. The barrier is an
    /// explicit `Notify`, not a sleep.
    #[tokio::test]
    async fn drain_waits_for_a_stalled_reader_before_deletion() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sentinel = dir.path().join("generation");
        let leases = MemberCopyLeaseGate::new(true);
        let lease = leases.acquire().expect("first reader");
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let gate = leases.clone();
        let sentinel_for_task = sentinel.clone();
        let purge = tokio::spawn(async move {
            gate.deactivate();
            let _ = entered_tx.send(());
            gate.drain().await;
            fs::write(&sentinel_for_task, b"purged").expect("delete sentinel");
        });
        entered_rx.await.expect("purge reached the drain barrier");
        assert!(
            !sentinel.exists(),
            "deletion must not run while a reader still holds a lease"
        );
        drop(lease);
        purge.await.expect("purge task");
        assert!(sentinel.exists(), "deletion runs once the reader drained");
    }

    /// A call queued after deactivation refuses rather than racing the purge;
    /// reactivation (after a validated admission) lets it through again.
    #[test]
    fn queued_call_after_deactivation_refuses() {
        let leases = MemberCopyLeaseGate::new(true);
        leases.deactivate();
        assert!(leases.acquire().is_err(), "queued call must refuse");
        leases.reactivate();
        let lease = leases.acquire().expect("reactivated lease");
        drop(lease);
    }

    /// The held-none limbo (fresh root, or after a scope purge with no pointer
    /// and no activatable generation) must serve nothing even though the
    /// lifecycle status can still say `Allow`.
    #[tokio::test]
    async fn held_none_limbo_serves_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let mut serving = MemberCopyServing::open(&root, footing())
            .await
            .expect("open");
        assert!(!serving.is_serving(), "fresh root serves nothing");
        assert_eq!(serving.generation_id(), None);
        assert!(serving.database().is_none());
        assert!(
            serving.begin_read().is_err(),
            "a read lease must refuse while nothing is admitted"
        );
        serving
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        assert!(
            !serving.is_serving(),
            "Refreshing with no generation serves nothing"
        );
    }

    /// Malformed persisted metadata refuses the open rather than serving.
    #[tokio::test]
    async fn malformed_persisted_metadata_refuses_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        fs::create_dir_all(&root).expect("root");
        fs::write(root.join(ADMISSION_FILENAME), b"{ not json").expect("write metadata");
        assert!(
            MemberCopyServing::open(&root, footing()).await.is_err(),
            "corrupt admission metadata must refuse"
        );
    }

    /// A producer-built generation admits, activates, survives reopen, and
    /// binds the actual admitted `generation_id` into the page basis.
    #[tokio::test]
    async fn admitted_generation_reopens_and_binds_actual_generation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_path, digest) = staged(&root, "hello");
        let manifest = manifest_for(&staged_path, &digest, 1);
        let expected_generation = validate_manifest(&manifest)
            .expect("validate")
            .generation_id;
        let mut serving = MemberCopyServing::open(&root, footing())
            .await
            .expect("open");
        serving
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        let admitted = serving
            .admit_auto(&staged_path, &manifest)
            .await
            .expect("admit");
        assert!(serving.is_serving());
        assert_eq!(serving.generation_id(), Some(expected_generation.as_str()));
        assert_eq!(admitted.generation_id, expected_generation);
        drop(serving);

        let reopened = MemberCopyServing::open(&root, footing())
            .await
            .expect("reopen");
        assert!(reopened.is_serving(), "validated reopen activates");
        assert_eq!(reopened.generation_id(), Some(expected_generation.as_str()));
    }

    #[tokio::test]
    async fn installed_registry_binds_admitted_handle_and_account() {
        use crate::mcp::interactions::ToolKind;
        use crate::mcp::registry::Caller;
        use serde_json::json;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (path, digest) = staged(&root, "hello");
        let manifest = manifest_for(&path, &digest, 1);
        let mut owner = MemberCopyServing::open(&root, footing())
            .await
            .expect("owner");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign in");
        let admitted = owner.admit_auto(&path, &manifest).await.expect("admit");
        let db = owner.database().expect("active db");
        let other = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("fresh handle");
        assert_ne!(other.handle_id(), db.handle_id());
        let canonical = crate::db::create_database(":memory:")
            .await
            .expect("canonical");
        let mut registry = ToolRegistry::new();
        registry
            .register(
                ToolKind::Ping,
                "binding probe",
                json!({"type":"object"}),
                |_db, _caller, _args| async { Ok(json!({"handler":"ran"})) },
            )
            .expect("probe");
        assert!(owner.install_into(&mut registry));
        for (supplied, account) in [
            (other, "acct"),
            (canonical, "acct"),
            (db.clone(), "foreign"),
        ] {
            let result = registry
                .call(supplied, Caller::authenticated(account), "ping", json!({}))
                .await;
            assert!(
                result.is_err(),
                "unbound database/account reached handler: {account}"
            );
        }
        let result = registry
            .call(db.clone(), Caller::authenticated("acct"), "ping", json!({}))
            .await
            .expect("admitted clone and account");
        assert_eq!(result["handler"], "ran");
    }

    #[tokio::test]
    async fn replaced_generation_never_reactivates_an_old_registry() {
        use crate::mcp::interactions::ToolKind;
        use crate::mcp::registry::Caller;
        use serde_json::json;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (path, digest) = staged(&root, "hello");
        let manifest = manifest_for(&path, &digest, 1);
        let mut owner = MemberCopyServing::open(&root, footing())
            .await
            .expect("owner");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign in");
        owner
            .admit_auto(&path, &manifest)
            .await
            .expect("first admission");
        let old_db = owner.database().expect("old database");
        let old_generation = owner.generation_id().expect("generation").to_owned();
        let make_registry = || {
            let mut registry = ToolRegistry::new();
            registry
                .register(
                    ToolKind::Ping,
                    "no-storage probe",
                    json!({"type":"object"}),
                    |_db, _caller, _args| async { Ok(json!({"handler":"ran"})) },
                )
                .expect("probe");
            registry
        };
        let mut old_registry = make_registry();
        assert!(owner.install_into(&mut old_registry));
        old_registry
            .call(
                old_db.clone(),
                Caller::authenticated("acct"),
                "ping",
                json!({}),
            )
            .await
            .expect("old generation initially serves");
        let (path, digest) = staged(&root, "world");
        let manifest = manifest_for(&path, &digest, 2);
        owner
            .admit_auto(&path, &manifest)
            .await
            .expect("replacement");
        assert_ne!(owner.generation_id(), Some(old_generation.as_str()));
        assert!(
            old_registry
                .call(old_db, Caller::authenticated("acct"), "ping", json!({}))
                .await
                .is_err(),
            "old registry must stay inactive even for a handler with no storage"
        );
        let mut new_registry = make_registry();
        assert!(owner.install_into(&mut new_registry));
        new_registry
            .call(
                owner.database().expect("new database"),
                Caller::authenticated("acct"),
                "ping",
                json!({}),
            )
            .await
            .expect("new registry serves");
    }

    #[tokio::test]
    async fn producer_admitted_owner_serves_real_sessions_and_reopens() {
        use crate::mcp::registry::Caller;
        use crate::member_offline_fixtures::{
            assert_no_counter_fields, online_visible_ids, two_caller, ACCT_B,
        };
        use serde_json::json;
        let world = two_caller::build().await;
        let body = "d1owner authored seq rec:123 obs:456";
        crate::store::update_record(&world.db, two_caller::SHARED_CHILD, json!({"body":body}))
            .await
            .expect("authored body");
        let visible = online_visible_ids(&world.db, ACCT_B).await;
        assert!(visible.contains(two_caller::SHARED_CHILD));
        assert!(!visible.contains(two_caller::A_OWNED));
        let origin: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(world.db.pool())
                .await
                .expect("trusted source origin");
        let expected = ExpectedFooting {
            origin_database_id: origin,
            scope_ref: SCOPE.into(),
            consumer: consumer(),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let mut owner = MemberCopyServing::open(&root, expected.clone())
            .await
            .expect("owner");
        owner
            .sign_in(ACCT_B, ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign in");
        fs::create_dir_all(root.join("staging")).expect("staging");
        let staged = root.join("staging/producer.db");
        let copy = crate::member_copy_producer::build_member_copy(
            &world.db,
            crate::member_copy_producer::MemberCopyRequest {
                member_account: ACCT_B.into(),
                scope_ref: SCOPE.into(),
                hosted_route_database_id: "route-test".into(),
                ordinal: 1,
                consumer: consumer(),
                out_path: staged.clone(),
            },
        )
        .await
        .expect("actual producer");
        let admitted = owner
            .admit_auto(
                &staged,
                &serde_json::to_vec(&copy.manifest).expect("manifest"),
            )
            .await
            .expect("actual admission");
        let installed_bytes =
            fs::read(admitted.generation_dir.join(SNAPSHOT_FILENAME)).expect("installed bytes");
        assert_ne!(
            hex::encode(sha2::Sha256::digest(&installed_bytes)),
            copy.manifest.bytes.sha256,
            "reopen must revalidate canonical content after admission rebuilt the FTS bytes"
        );
        let mut online = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut online).expect("online builtins");
        crate::mcp::register_surface_tools(&mut online).expect("surface tools");
        let mut member = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut member).expect("member builtins");
        crate::mcp::register_surface_tools(&mut member).expect("surface tools");
        assert!(owner.install_into(&mut member));
        let db = owner.database().expect("admitted db");
        let caller = Caller::authenticated(ACCT_B);
        let bootstrap = member
            .call(db.clone(), caller.clone(), "bootstrap", json!({}))
            .await
            .expect("bootstrap");
        assert_eq!(
            bootstrap["principal"]["person_record_id"],
            two_caller::PERSON_B
        );
        assert_no_counter_fields(&bootstrap, "owner bootstrap");
        let search = member
            .call(
                db.clone(),
                caller.clone(),
                "search",
                json!({"query":"d1owner"}),
            )
            .await
            .expect("search");
        let online_search = online
            .call(
                world.db.clone(),
                caller.clone(),
                "search",
                json!({"query":"d1owner"}),
            )
            .await
            .expect("online search");
        assert_eq!(search["hits"], online_search["hits"]);
        assert!(!search["hits"].as_array().expect("hits").is_empty());
        for hit in search["hits"].as_array().expect("hits") {
            assert!(visible.contains(hit["id"].as_str().expect("hit id")));
        }
        assert_no_counter_fields(&search, "owner search");
        let record = member
            .call(
                db.clone(),
                caller.clone(),
                "get_record",
                json!({"ids":[two_caller::SHARED_CHILD]}),
            )
            .await
            .expect("record");
        assert_eq!(record["records"][0]["status"], "found");
        assert_eq!(record["records"][0]["body"], body);
        assert_no_counter_fields(&record, "owner record");
        let hidden = member
            .call(
                db.clone(),
                caller.clone(),
                "get_record",
                json!({"ids":[two_caller::A_OWNED]}),
            )
            .await
            .expect("hidden");
        assert_eq!(hidden["records"][0]["status"], "not_found");
        let render = member
            .call(
                db.clone(),
                caller.clone(),
                "render_record",
                json!({"id":two_caller::SHARED_CHILD}),
            )
            .await
            .expect("render");
        let online_render = online
            .call(
                world.db.clone(),
                caller.clone(),
                "render_record",
                json!({"id":two_caller::SHARED_CHILD}),
            )
            .await
            .expect("online render");
        assert_eq!(render["markdown"], online_render["markdown"]);
        assert!(render["markdown"]
            .as_str()
            .expect("markdown")
            .contains(body));
        assert_no_counter_fields(&render, "owner render");
        let generation = owner.generation_id().expect("generation").to_owned();
        owner.quiesce().await;
        drop(owner);
        let reopened = MemberCopyServing::open(&root, expected)
            .await
            .expect("reopen");
        assert_eq!(reopened.generation_id(), Some(generation.as_str()));
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).expect("reopened builtins");
        crate::mcp::register_surface_tools(&mut registry).expect("surface tools");
        assert!(reopened.install_into(&mut registry));
        let record = registry
            .call(
                reopened.database().expect("reopened db"),
                caller,
                "get_record",
                json!({"ids":[two_caller::SHARED_CHILD]}),
            )
            .await
            .expect("reopened session");
        assert_eq!(record["records"][0]["body"], body);
        assert_no_counter_fields(&record, "reopened owner record");
    }

    /// Same visible ids, changed authored content: the page basis must bind
    /// the new actual generation, so a continuation minted under one refuses
    /// under the other. Exercises the production path (not the fallback).
    #[test]
    fn page_basis_binds_actual_generation_not_the_fallback() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lifecycle = Arc::new(Mutex::new(
            MemberCopyLifecycle::open(dir.path()).expect("lifecycle"),
        ));
        let leases = MemberCopyLeaseGate::new(true);
        let make = |generation: &str| {
            MemberCopyGate::with_leases(
                lifecycle.clone(),
                SCOPE.to_owned(),
                1,
                Vec::new(),
                leases.clone(),
            )
            .with_generation_id(generation.to_owned())
        };
        let first = make(&"a".repeat(64));
        let second = make(&"b".repeat(64));
        assert_ne!(
            first.bind_page_basis("raw"),
            second.bind_page_basis("raw"),
            "different generations must refuse each other's continuations"
        );
        let same = make(&"a".repeat(64));
        assert_eq!(first.bind_page_basis("raw"), same.bind_page_basis("raw"));
    }

    /// A refused replacement must not clobber the held generation: the old
    /// bytes survive, serving stays fail-closed, and the held generation can
    /// resume from persisted metadata.
    #[tokio::test]
    async fn failed_replacement_keeps_held_bytes_and_recovers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_a, digest_a) = staged(&root, "hello");
        let manifest_a = manifest_for(&staged_a, &digest_a, 1);
        let mut serving = MemberCopyServing::open(&root, footing())
            .await
            .expect("open");
        serving
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        let admitted_a = serving
            .admit_auto(&staged_a, &manifest_a)
            .await
            .expect("admit A");
        let installed = admitted_a
            .generation_dir
            .join(crate::member_copy_admission::SNAPSHOT_FILENAME);
        let before = fs::read(&installed).expect("held bytes");

        let (staged_b, digest_b) = staged(&root, "world");
        let manifest_b = manifest_for(&staged_b, &digest_b, 2);
        let mut corrupt = fs::read(&staged_b).expect("staged B");
        corrupt.push(0);
        fs::write(&staged_b, &corrupt).expect("corrupt staged B");
        assert!(
            serving.admit_auto(&staged_b, &manifest_b).await.is_err(),
            "a corrupt candidate must be refused"
        );
        assert!(
            !serving.is_serving(),
            "serving stays fail-closed after a refusal"
        );
        assert_eq!(fs::read(&installed).expect("held bytes"), before);
        assert!(
            serving.recover_after_failed_candidate().await,
            "the held generation resumes from persisted metadata"
        );
        assert_eq!(
            serving.generation_id(),
            Some(admitted_a.generation_id.as_str())
        );
    }

    /// A scope/account-change purge quiesces first, deletes the wider copy and
    /// its metadata, and only then admits the freshly-staged generation.
    #[tokio::test]
    async fn scope_change_purge_deletes_old_generation_before_admitting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_a, digest_a) = staged(&root, "hello");
        let manifest_a = manifest_for(&staged_a, &digest_a, 1);
        let mut serving = MemberCopyServing::open(&root, footing())
            .await
            .expect("open");
        serving
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        let admitted_a = serving
            .admit_auto(&staged_a, &manifest_a)
            .await
            .expect("admit A");

        let status = serving
            .begin_scope_change_purge(CUT)
            .await
            .expect("scope purge");
        assert!(matches!(status, CopyStatus::Refreshing { .. }));
        assert!(!serving.is_serving(), "purge leaves serving fail-closed");
        assert!(
            !admitted_a.generation_dir.exists(),
            "the old generation bytes are deleted"
        );
        assert!(
            !root.join(ADMISSION_FILENAME).exists(),
            "old admission metadata is purged with the generation it described"
        );

        let (staged_b, digest_b) = staged(&root, "world");
        let manifest_b = manifest_for(&staged_b, &digest_b, 2);
        // Under the RootScopeHint contract a purge requires a fresh
        // authenticated bind even for the same scope before any admission.
        assert_eq!(
            serving.bind_scope_for("acct", SCOPE).unwrap(),
            ScopeBinding::Rebound
        );
        let admitted_b = serving
            .admit_auto(&staged_b, &manifest_b)
            .await
            .expect("admit B after the purge");
        assert!(serving.is_serving());
        assert_ne!(admitted_b.generation_id, admitted_a.generation_id);
        assert_eq!(
            serving.generation_id(),
            Some(admitted_b.generation_id.as_str())
        );
    }

    /// An unbound owner refuses admission (fail closed) until a transport
    /// token binds the scope; then the same candidate admits.
    #[tokio::test]
    async fn unbound_owner_refuses_admission_until_bound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged, digest) = staged(&root, "hello");
        let manifest = manifest_for(&staged, &digest, 1);
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        assert!(!owner.is_scope_bound(), "a driver owner starts unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        assert!(matches!(
            owner.admit_auto(&staged, &manifest).await,
            Err(AdmissionError::Lifecycle { detail }) if detail == "scope not bound"
        ));
        assert_eq!(
            owner.bind_scope_for("acct", SCOPE).unwrap(),
            ScopeBinding::Bound
        );
        owner
            .admit_auto(&staged, &manifest)
            .await
            .expect("admit after binding");
        assert!(owner.is_serving());
    }

    /// Nonvacuous scope binding: two manifests differ only in `scope_ref`
    /// (hence `generation_id`). Old scope cannot be used once a new one is
    /// bound, a live rebind is refused, and a completed purge is required
    /// before the new scope binds and admits. Origin and consumer stay pinned.
    #[tokio::test]
    async fn scope_binding_refuses_old_scope_and_accepts_new_after_purge() {
        const SCOPE_A: &str = "scope-a";
        const SCOPE_B: &str = "scope-b";
        const OTHER_ORIGIN: &str = "ndb_44444444444444444444444444444444";
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_a, digest_a) = staged(&root, "hello");
        let manifest_a = manifest_for_scope(&staged_a, &digest_a, 1, SCOPE_A);
        let (staged_b, digest_b) = staged(&root, "hello");
        let manifest_b = manifest_for_scope(&staged_b, &digest_b, 2, SCOPE_B);
        let generation_b = validate_manifest(&manifest_b)
            .expect("validate B")
            .generation_id;

        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        assert_eq!(
            owner.bind_scope_for("acct-a", SCOPE_A).unwrap(),
            ScopeBinding::Bound
        );
        owner
            .admit_auto(&staged_a, &manifest_a)
            .await
            .expect("admit A");
        assert!(owner.is_serving());

        // A manifest whose scope differs from the bound scope is refused; a
        // different scope cannot be bound while A is still served.
        assert!(matches!(
            owner.admit_auto(&staged_b, &manifest_b).await,
            Err(AdmissionError::AccountMismatch)
        ));
        assert!(owner.bind_scope_for("acct-a", SCOPE_B).is_err());
        assert!(owner.recover_after_failed_candidate().await);

        // A completed scope purge deletes A and its admission record and marks
        // a fresh bind required: the retained old scope is inert for admission.
        owner
            .begin_scope_change_purge(CUT)
            .await
            .expect("scope purge");
        assert!(!owner.is_serving());
        assert!(!root.join(ADMISSION_FILENAME).exists());
        assert!(!owner.is_scope_bound(), "a purge requires a fresh rebind");
        assert!(owner.is_rebind_required());
        assert_eq!(
            owner.bound_scope_ref(),
            Some(SCOPE_A),
            "the old scope is retained only as a transition hint"
        );
        // Staging made before the purge is gone; a valid OLD-scope candidate
        // staged AFTER the purge must not admit under the retained hint, and
        // the new scope is equally refused pre-bind.
        let (staged_a2, _digest_a2) = staged(&root, "hello");
        let (staged_b, digest_b) = staged(&root, "hello");
        let manifest_b = manifest_for_scope(&staged_b, &digest_b, 2, SCOPE_B);
        assert!(matches!(
            owner.admit_auto(&staged_a2, &manifest_a).await,
            Err(AdmissionError::Lifecycle { detail }) if detail == "scope not bound"
        ));
        assert!(matches!(
            owner.admit_auto(&staged_b, &manifest_b).await,
            Err(AdmissionError::Lifecycle { detail }) if detail == "scope not bound"
        ));

        // Binding B is now a rebound; B admits; A is refused afterward.
        assert_eq!(
            owner.bind_scope_for("acct-a", SCOPE_B).unwrap(),
            ScopeBinding::Rebound
        );
        let admitted_b = owner
            .admit_auto(&staged_b, &manifest_b)
            .await
            .expect("admit B");
        assert_eq!(admitted_b.generation_id, generation_b);
        assert_eq!(owner.bound_scope_ref(), Some(SCOPE_B));
        assert!(matches!(
            owner.admit_auto(&staged_a2, &manifest_a).await,
            Err(AdmissionError::AccountMismatch)
        ));
        assert!(owner.recover_after_failed_candidate().await);

        // Same-scope re-statement is a pure no-op.
        assert_eq!(
            owner.bind_scope_for("acct-a", SCOPE_B).unwrap(),
            ScopeBinding::AlreadyBound
        );

        // Pins stay immutable: a bad origin/consumer is refused independently.
        let mut wrong =
            serde_json::from_slice::<ReplicaGenerationManifest>(&manifest_b).expect("parse B");
        wrong.origin_database_id = OTHER_ORIGIN.to_owned();
        assert!(matches!(
            owner
                .admit_auto(&staged_b, &serde_json::to_vec(&wrong).unwrap())
                .await,
            Err(AdmissionError::OriginMismatch)
        ));
        let mut wrong =
            serde_json::from_slice::<ReplicaGenerationManifest>(&manifest_b).expect("parse B");
        wrong.consumer.ddl_sha256 = "9".repeat(64);
        assert!(matches!(
            owner
                .admit_auto(&staged_b, &serde_json::to_vec(&wrong).unwrap())
                .await,
            Err(AdmissionError::ConsumerMismatch)
        ));
    }

    /// The owner-written v2 binding supports offline held serving after a
    /// process reopen with no transport, and refuses to restore scope when the
    /// recorded pins do not match the reopening device.
    #[tokio::test]
    async fn durable_v2_binding_recovers_offline_and_rejects_mismatched_pins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged, digest) = staged(&root, "hello");
        let manifest = manifest_for(&staged, &digest, 1);
        let generation = validate_manifest(&manifest)
            .expect("validate")
            .generation_id;
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        owner.bind_scope_for("acct", SCOPE).unwrap();
        owner.admit_auto(&staged, &manifest).await.expect("admit");
        drop(owner);

        let reopened = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("offline reopen");
        assert!(reopened.is_serving(), "offline reopen serves the held copy");
        assert_eq!(reopened.generation_id(), Some(generation.as_str()));
        assert_eq!(reopened.bound_scope_ref(), Some(SCOPE));
        drop(reopened);

        let other_consumer = StandbyConsumerIdentity {
            ddl_sha256: "9".repeat(64),
            ..consumer()
        };
        let mismatched = MemberCopyServing::open_unbound(&root, ORIGIN.into(), other_consumer)
            .await
            .expect("open with wrong consumer");
        assert!(
            !mismatched.is_serving(),
            "a mismatched consumer restores nothing"
        );
        assert!(mismatched.bound_scope_ref().is_none());
        drop(mismatched);

        let mismatched = MemberCopyServing::open_unbound(
            &root,
            "ndb_55555555555555555555555555555555".into(),
            consumer(),
        )
        .await
        .expect("open with wrong origin");
        assert!(
            !mismatched.is_serving(),
            "a mismatched origin restores nothing"
        );
        assert!(mismatched.bound_scope_ref().is_none());
    }

    /// A legacy v1 admission record (valid JSON, old contract) never restores
    /// expected scope: the offline copy fails closed.
    #[tokio::test]
    async fn legacy_v1_admission_never_restores_scope() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        fs::create_dir_all(&root).expect("root");
        fs::write(
            root.join(ADMISSION_FILENAME),
            br#"{"contract":"native.member-copy-admission.v1","version":1,"manifest_json":"{}"}"#,
        )
        .expect("write legacy");
        let owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        assert!(!owner.is_scope_bound());
        assert!(!owner.is_serving());
    }

    /// Pointer absence alone does not permit rebinding: while a validated
    /// generation is still served (external pointer deletion), a different
    /// scope is refused.
    #[tokio::test]
    async fn pointer_absence_alone_does_not_allow_rebinding() {
        const SCOPE_B: &str = "scope-b";
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_a, digest_a) = staged(&root, "hello");
        let manifest_a = manifest_for(&staged_a, &digest_a, 1);
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        owner.bind_scope_for("acct", SCOPE).unwrap();
        owner
            .admit_auto(&staged_a, &manifest_a)
            .await
            .expect("admit");
        fs::remove_file(root.join("current.json")).expect("remove pointer");
        assert!(
            owner.is_serving(),
            "the validated generation is still served"
        );
        assert!(
            owner.bind_scope_for("acct", SCOPE_B).is_err(),
            "pointer absence alone must not permit rebinding over a held generation"
        );
    }

    /// A purge requires a fresh authenticated bind even when the presented
    /// scope equals the retained hint: `bind_scope` must run the clean-refresh
    /// eligibility check and report `Rebound`, never a bare `AlreadyBound`.
    #[tokio::test]
    async fn scope_purge_requires_fresh_rebind_even_for_same_scope() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_a, digest_a) = staged(&root, "hello");
        let manifest_a = manifest_for(&staged_a, &digest_a, 1);
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        owner.bind_scope_for("acct", SCOPE).unwrap();
        owner
            .admit_auto(&staged_a, &manifest_a)
            .await
            .expect("admit A");

        owner
            .begin_scope_change_purge(CUT)
            .await
            .expect("scope purge");
        assert!(owner.is_rebind_required());
        assert_eq!(owner.bound_scope_ref(), Some(SCOPE));
        assert_eq!(
            owner.bind_scope_for("acct", SCOPE).unwrap(),
            ScopeBinding::Rebound,
            "a same-scope bind after a purge is a fresh rebind, not a no-op"
        );
        assert!(owner.is_scope_bound());
        let (staged_a2, digest_a2) = staged(&root, "hello");
        let manifest_a2 = manifest_for(&staged_a2, &digest_a2, 2);
        owner
            .admit_auto(&staged_a2, &manifest_a2)
            .await
            .expect("admit same scope after rebind");
        assert!(owner.is_serving());
    }

    /// A `Locked` copy is a no-op for a scope-change purge: held bytes, the
    /// active binding and the installed hint are all retained.
    #[tokio::test]
    async fn scope_purge_on_locked_copy_retains_held_hints() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged_a, digest_a) = staged(&root, "hello");
        let manifest_a = manifest_for(&staged_a, &digest_a, 1);
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        owner.bind_scope_for("acct", SCOPE).unwrap();
        owner
            .admit_auto(&staged_a, &manifest_a)
            .await
            .expect("admit A");
        let generation = owner.generation_id().expect("gen").to_owned();
        owner
            .apply_reconnect(crate::member_copy_lifecycle::ReconnectAnswer::Locked)
            .await
            .expect("lock");
        assert!(matches!(
            owner.lifecycle_status(),
            CopyStatus::Locked { .. }
        ));

        let status = owner
            .begin_scope_change_purge(CUT)
            .await
            .expect("locked purge is a no-op");
        assert!(matches!(status, CopyStatus::Locked { .. }));
        assert!(owner.is_scope_bound(), "Locked keeps the active binding");
        assert_eq!(owner.bound_scope_ref(), Some(SCOPE));
        assert_eq!(
            owner.installed_generation_id().as_deref(),
            Some(generation.as_str()),
            "Locked keeps the installed-generation hint"
        );
        assert!(
            !owner.is_serving(),
            "Locked still refuses reads despite the retained hints"
        );
    }

    fn with_markers(manifest: &[u8], markers: &[&str]) -> Vec<u8> {
        let mut parsed: ReplicaGenerationManifest =
            serde_json::from_slice(manifest).expect("manifest parses");
        parsed.schema_incomplete_for = markers.iter().map(|value| value.to_string()).collect();
        serde_json::to_vec(&parsed).expect("manifest serialises")
    }

    fn probe_registry() -> crate::mcp::registry::ToolRegistry {
        use crate::mcp::interactions::ToolKind;
        let mut registry = crate::mcp::registry::ToolRegistry::new();
        registry
            .register(
                ToolKind::Ping,
                "probe",
                serde_json::json!({"type":"object"}),
                |_db, _caller, _args| async { Ok(serde_json::json!({"handler":"ran"})) },
            )
            .expect("probe");
        registry
    }

    /// A same-identity `Current` whose schema markers changed is adopted with
    /// no redownload: the old captured gate permanently refuses and a fresh
    /// gate serves the updated markers.
    #[tokio::test]
    async fn current_metadata_refresh_adopts_markers_and_retires_old_gate() {
        use crate::mcp::registry::Caller;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged, digest) = staged(&root, "hello");
        let manifest = manifest_for(&staged, &digest, 1);
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        owner.bind_scope_for("acct", SCOPE).unwrap();
        owner.admit_auto(&staged, &manifest).await.expect("admit");

        let mut old = probe_registry();
        assert!(owner.install_into(&mut old));
        let db = owner.database().expect("db");
        old.call(
            db.clone(),
            Caller::authenticated("acct"),
            "ping",
            serde_json::json!({}),
        )
        .await
        .expect("old gate serves before the marker change");

        let updated = with_markers(&manifest, &["global"]);
        let context = MemberCopyContext::for_test("acct", ORIGIN, SCOPE);
        let changed = owner
            .adopt_current_metadata(&updated, &context)
            .await
            .expect("adopt metadata");
        assert!(changed, "markers changed");
        assert!(owner.is_serving(), "no redownload; held copy stays served");
        assert_eq!(
            owner
                .active
                .as_ref()
                .expect("active")
                .admitted
                .schema_incomplete_for,
            vec!["global".to_string()],
            "fresh markers adopted"
        );
        assert!(
            old.call(
                db.clone(),
                Caller::authenticated("acct"),
                "ping",
                serde_json::json!({})
            )
            .await
            .is_err(),
            "old captured gate permanently refuses after a marker change"
        );
        let mut new = probe_registry();
        assert!(owner.install_into(&mut new));
        new.call(
            owner.database().expect("db"),
            Caller::authenticated("acct"),
            "ping",
            serde_json::json!({}),
        )
        .await
        .expect("fresh gate serves");
    }

    /// A metadata-only `Current` (no marker change) is adopted without
    /// retiring the serving gate.
    #[tokio::test]
    async fn current_metadata_refresh_without_marker_change_keeps_gate() {
        use crate::mcp::registry::Caller;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("copy");
        let (staged, digest) = staged(&root, "hello");
        let manifest = manifest_for(&staged, &digest, 1);
        let mut owner = MemberCopyServing::open_unbound(&root, ORIGIN.into(), consumer())
            .await
            .expect("open_unbound");
        owner
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .await
            .expect("sign-in");
        owner.bind_scope_for("acct", SCOPE).unwrap();
        owner.admit_auto(&staged, &manifest).await.expect("admit");

        let mut registry = probe_registry();
        assert!(owner.install_into(&mut registry));
        let db = owner.database().expect("db");
        let context = MemberCopyContext::for_test("acct", ORIGIN, SCOPE);
        let changed = owner
            .adopt_current_metadata(&manifest, &context)
            .await
            .expect("adopt metadata");
        assert!(!changed, "same markers");
        registry
            .call(
                db,
                Caller::authenticated("acct"),
                "ping",
                serde_json::json!({}),
            )
            .await
            .expect("gate not retired on an innocuous metadata refresh");
    }
}
