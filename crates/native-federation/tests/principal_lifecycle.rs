use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use native_federation::Result;
use native_federation::{
    adopt_eject_identity_after_database_adoption, adopt_eject_package, create_eject_package,
    extract_eject_database, retry_pending_handoff, verify_detached_jws, CustodyMasterKey,
    DirectoryAttestation, DirectoryCommit, EjectDestinationIdentity, EndpointUpdate, Error,
    FederationCrypto, FederationDirectory, FileFederationCustody, KeyPurpose, KeyStatus,
    PrincipalState, ProfileGatedFederationCrypto, PublicJwk, RootTransitionRequest,
    FEDERATION_PROFILE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const NOW: &str = "2026-08-03T12:00:00Z";
const LATER: &str = "2026-08-03T13:00:00Z";
const EXPIRES: &str = "2026-08-04T12:00:00Z";
const SOURCE_INSTALLATION: &str = "00000000-0000-4000-8000-000000000101";
const DESTINATION_INSTALLATION: &str = "00000000-0000-4000-8000-000000000202";

fn custody(directory: &TempDir, byte: u8) -> FileFederationCustody {
    FileFederationCustody::initialize(
        directory.path().join("custody"),
        CustodyMasterKey::from_bytes([byte; 32]),
    )
    .unwrap()
}

fn provision(custody: &FileFederationCustody, account: &str, installation: &str) {
    custody
        .provision(
            account,
            "native",
            installation,
            "https://node.example",
            account,
            NOW,
        )
        .unwrap();
}

#[test]
fn provisioning_is_stable_concurrent_and_account_scoped() {
    let directory = TempDir::new().unwrap();
    let custody = Arc::new(custody(&directory, 7));
    let threads = (0..8)
        .map(|_| {
            let custody = custody.clone();
            std::thread::spawn(move || {
                custody
                    .provision(
                        "account-alice",
                        "native",
                        SOURCE_INSTALLATION,
                        "https://node.example",
                        "account-alice",
                        NOW,
                    )
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    let principals = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(principals
        .iter()
        .all(|principal| principal.principal_id == principals[0].principal_id));
    assert_eq!(principals[0].keys.len(), 4);

    let bob = custody
        .provision(
            "account-bob",
            "native",
            DESTINATION_INSTALLATION,
            "https://bob.example",
            "account-bob",
            NOW,
        )
        .unwrap();
    assert_ne!(bob.principal_id, principals[0].principal_id);
    let alice_kids = principals[0]
        .keys
        .iter()
        .map(|key| &key.jwk.kid)
        .collect::<Vec<_>>();
    assert!(bob
        .keys
        .iter()
        .all(|key| !alice_kids.contains(&&key.jwk.kid)));

    let files = std::fs::read_dir(directory.path().join("custody/principals"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            let is_vault = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".vault.json"));
            is_vault.then(|| std::fs::read_to_string(path).unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(files.len(), 2);
    for vault in files {
        assert!(!vault.contains("\"secret\""));
        assert!(!vault.contains("\"d\""));
        assert_eq!(vault.matches(CUSTODY_WRAPPER_MARKER).count(), 4);
    }
}

const CUSTODY_WRAPPER_MARKER: &str = "xchacha20poly1305-v1";

#[test]
fn signs_builds_public_documents_rotates_and_revokes_without_leaking_secrets() {
    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 11);
    provision(&custody, "account-alice", SOURCE_INSTALLATION);
    let payload = json!({"message": "hello", "sequence": 1});
    let before = custody.inspect("account-alice");
    let signing = before
        .keys
        .iter()
        .find(|key| key.purpose == KeyPurpose::Signing && key.status == KeyStatus::Active)
        .unwrap()
        .jwk
        .clone();
    let jws = custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &payload,
        )
        .unwrap();
    assert!(custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Root,
            "native-envelope+jws",
            &payload,
        )
        .is_err());

    provision(
        &custody,
        "account-metadata-tamper",
        "00000000-0000-4000-8000-000000000303",
    );
    let metadata_path = std::fs::read_dir(directory.path().join("custody/principals"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                return None;
            }
            let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            (value["account_id"] == "account-metadata-tamper").then_some(path)
        })
        .next()
        .unwrap();
    let mut metadata: Value =
        serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
    metadata["document_version"] = json!(999);
    std::fs::write(metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert_eq!(
        custody.inspect("account-metadata-tamper").state,
        PrincipalState::Corrupt
    );
    assert!(custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Root,
            "native-principal+jws",
            &payload,
        )
        .is_err());
    assert!(custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Installation,
            "native-envelope+jws",
            &payload,
        )
        .is_err());
    assert!(custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Installation,
            "native-key-authorization+jws",
            &payload,
        )
        .is_err());
    verify_detached_jws(&signing, "native-envelope+jws", &payload, &jws).unwrap();
    assert!(verify_detached_jws(
        &signing,
        "native-envelope+jws",
        &json!({"message": "changed", "sequence": 1}),
        &jws,
    )
    .is_err());

    let document = custody.principal_document("account-alice", NOW).unwrap();
    let document_text = serde_json::to_string(&document).unwrap();
    assert!(!document_text.contains("ciphertext"));
    assert!(!document_text.contains("\"d\""));
    assert_eq!(document["document"]["principal_id"], before.principal_id);

    let pending = custody
        .begin_rotation(
            "account-alice",
            KeyPurpose::Signing,
            "account-alice",
            "scheduled rollover",
            LATER,
        )
        .unwrap();
    assert_eq!(pending.state, PrincipalState::RotationPending);
    assert_eq!(
        pending
            .keys
            .iter()
            .filter(|key| key.purpose == KeyPurpose::Signing && key.status == KeyStatus::Active)
            .count(),
        2
    );
    let during_rotation = custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &payload,
        )
        .unwrap();
    let committed = custody
        .finish_rotation(
            "account-alice",
            KeyPurpose::Signing,
            "account-alice",
            "overlap complete",
            "2026-09-03T13:00:00Z",
        )
        .unwrap();
    let new_signing = committed
        .keys
        .iter()
        .find(|key| key.purpose == KeyPurpose::Signing && key.status == KeyStatus::Active)
        .unwrap();
    assert_ne!(new_signing.jwk.kid, signing.kid);
    verify_detached_jws(
        &new_signing.jwk,
        "native-envelope+jws",
        &payload,
        &during_rotation,
    )
    .unwrap();
    // Historical verification remains possible with the retired public key.
    verify_detached_jws(&signing, "native-envelope+jws", &payload, &jws).unwrap();

    let revoked = custody
        .revoke_key(
            "account-alice",
            &new_signing.jwk.kid,
            "account-alice",
            "compromised",
            "2026-09-03T14:00:00Z",
        )
        .unwrap();
    assert_eq!(revoked.state, PrincipalState::Revoked);
    assert!(custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &payload,
        )
        .is_err());
    let audit = custody.audit_events("account-alice").unwrap();
    let audit_json = serde_json::to_string(&audit).unwrap();
    assert!(!audit_json.contains("ciphertext"));
    assert!(!audit_json.contains("private"));
}

#[test]
fn encryption_rotation_keeps_bounded_decrypt_only_continuity() {
    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 49);
    provision(&custody, "account-encryption", SOURCE_INSTALLATION);
    let old = custody
        .inspect("account-encryption")
        .keys
        .into_iter()
        .find(|key| key.purpose == KeyPurpose::Encryption && key.status == KeyStatus::Active)
        .unwrap();
    custody
        .begin_rotation(
            "account-encryption",
            KeyPurpose::Encryption,
            "account-encryption",
            "scheduled encryption rollover",
            LATER,
        )
        .unwrap();
    let rotated = custody
        .finish_rotation(
            "account-encryption",
            KeyPurpose::Encryption,
            "account-encryption",
            "overlap committed",
            "2026-08-03T14:00:00Z",
        )
        .unwrap();
    assert_eq!(rotated.state, PrincipalState::Active);
    assert!(rotated
        .keys
        .iter()
        .any(|key| { key.jwk.kid == old.jwk.kid && key.status == KeyStatus::DecryptOnly }));
    let before_expiry = custody
        .erase_expired_decrypt_only(
            "account-encryption",
            "account-encryption",
            "2026-08-10T14:00:00Z",
        )
        .unwrap();
    assert!(before_expiry
        .keys
        .iter()
        .any(|key| key.jwk.kid == old.jwk.kid && key.status == KeyStatus::DecryptOnly));
    let erased = custody
        .erase_expired_decrypt_only(
            "account-encryption",
            "account-encryption",
            "2026-09-03T14:00:01Z",
        )
        .unwrap();
    assert!(erased
        .keys
        .iter()
        .any(|key| key.jwk.kid == old.jwk.kid && key.status == KeyStatus::Retired));
    assert_eq!(
        custody.inspect("account-encryption").state,
        PrincipalState::Active
    );
}

#[test]
fn revocation_of_every_purpose_is_terminal_valid_and_rotation_safe() {
    for (index, purpose) in [
        KeyPurpose::Root,
        KeyPurpose::Signing,
        KeyPurpose::Encryption,
        KeyPurpose::Installation,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = TempDir::new().unwrap();
        let custody = custody(&directory, 60 + index as u8);
        let account = format!("account-revoke-{index}");
        provision(&custody, &account, SOURCE_INSTALLATION);
        let kid = custody
            .inspect(&account)
            .keys
            .into_iter()
            .find(|key| key.purpose == purpose && key.status == KeyStatus::Active)
            .unwrap()
            .jwk
            .kid;
        let revoked = custody
            .revoke_key(&account, &kid, &account, "compromised", LATER)
            .unwrap();
        assert_eq!(revoked.state, PrincipalState::Revoked);
        assert_eq!(custody.inspect(&account).state, PrincipalState::Revoked);
        assert!(revoked
            .keys
            .iter()
            .all(|key| key.status != KeyStatus::Active));
        assert!(revoked
            .keys
            .iter()
            .any(|key| key.jwk.kid == kid && key.status == KeyStatus::Revoked));
    }

    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 70);
    provision(&custody, "account-rotating-revoke", SOURCE_INSTALLATION);
    let rotating = custody
        .begin_rotation(
            "account-rotating-revoke",
            KeyPurpose::Signing,
            "account-rotating-revoke",
            "scheduled",
            LATER,
        )
        .unwrap();
    let kid = rotating
        .keys
        .iter()
        .rfind(|key| key.purpose == KeyPurpose::Signing && key.status == KeyStatus::Active)
        .unwrap()
        .jwk
        .kid
        .clone();
    custody
        .revoke_key(
            "account-rotating-revoke",
            &kid,
            "account-rotating-revoke",
            "authorization_withdrawn",
            "2026-08-03T14:00:00Z",
        )
        .unwrap();
    assert_eq!(
        custody.inspect("account-rotating-revoke").state,
        PrincipalState::Revoked
    );
}

#[test]
fn missing_or_corrupt_custody_fails_closed() {
    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 13);
    assert_eq!(
        custody.inspect("missing").state,
        PrincipalState::Unprovisioned
    );
    assert!(custody
        .sign_detached(
            "missing",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &json!({}),
        )
        .is_err());
    provision(&custody, "account-alice", SOURCE_INSTALLATION);
    let path = std::fs::read_dir(directory.path().join("custody/principals"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            let is_vault = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".vault.json"));
            is_vault.then_some(path)
        })
        .next()
        .unwrap();
    let mut json: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    json["keys"][0]["wrapped"]["ciphertext"] = json!("tampered");
    std::fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(
        custody.inspect("account-alice").state,
        PrincipalState::Corrupt
    );
    assert!(custody
        .sign_detached(
            "account-alice",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &json!({}),
        )
        .is_err());

    provision(&custody, "account-lost", DESTINATION_INSTALLATION);
    let lost_path = std::fs::read_dir(directory.path().join("custody/principals"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                return None;
            }
            let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            (value["account_id"] == "account-lost").then_some(path)
        })
        .next()
        .unwrap();
    std::fs::remove_file(lost_path).unwrap();
    assert_eq!(
        custody.inspect("account-lost").state,
        PrincipalState::Corrupt
    );
    assert!(custody
        .provision(
            "account-lost",
            "native",
            DESTINATION_INSTALLATION,
            "https://lost.example",
            "account-lost",
            LATER,
        )
        .is_err());

    let crypto = ProfileGatedFederationCrypto;
    let error = crypto
        .encrypt(FEDERATION_PROFILE, b"not ciphertext")
        .unwrap_err();
    assert!(error.to_string().contains("unsupported_profile"));

    let erased = TempDir::new().unwrap();
    let root = erased.path().join("custody");
    let key = CustodyMasterKey::from_bytes([47; 32]);
    let opened = FileFederationCustody::initialize(&root, key.clone()).unwrap();
    provision(&opened, "account-erased", SOURCE_INSTALLATION);
    std::fs::remove_dir_all(&root).unwrap();
    assert!(FileFederationCustody::open(&root, key).is_err());
    assert!(!root.exists());
}

#[derive(Clone)]
struct TestDirectory {
    version: Arc<Mutex<u64>>,
    current_root: Arc<Mutex<PublicJwk>>,
    unavailable_once: Arc<Mutex<bool>>,
    issued: Arc<Mutex<Vec<DirectoryAttestation>>>,
}

impl TestDirectory {
    fn new(source: &FileFederationCustody, account_id: &str, unavailable_once: bool) -> Self {
        let principal = source.inspect(account_id);
        let current_root = principal
            .keys
            .iter()
            .find(|key| key.purpose == KeyPurpose::Root && key.status == KeyStatus::Active)
            .unwrap()
            .jwk
            .clone();
        Self {
            version: Arc::new(Mutex::new(principal.document_version)),
            current_root: Arc::new(Mutex::new(current_root)),
            unavailable_once: Arc::new(Mutex::new(unavailable_once)),
            issued: Arc::new(Mutex::new(vec![])),
        }
    }
}

fn test_document_digest(document: &Value) -> String {
    format!(
        "sha-256:{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(serde_jcs::to_vec(document).unwrap()))
    )
}

impl FederationDirectory for TestDirectory {
    fn compare_and_swap<'a>(
        &'a self,
        request: &'a RootTransitionRequest,
    ) -> Pin<Box<dyn Future<Output = Result<DirectoryCommit>> + Send + 'a>> {
        Box::pin(async move {
            let mut unavailable = self.unavailable_once.lock().unwrap();
            if *unavailable {
                *unavailable = false;
                return Ok(DirectoryCommit::Unavailable);
            }
            drop(unavailable);
            let mut version = self.version.lock().unwrap();
            if *version != request.expected_document_version {
                return Ok(DirectoryCommit::VersionConflict {
                    current_document_version: *version,
                });
            }
            let old_jwk =
                serde_json::from_value(request.transition.statement["old_root_jwk"].clone())
                    .unwrap();
            let new_jwk: PublicJwk =
                serde_json::from_value(request.transition.statement["new_root_jwk"].clone())
                    .unwrap();
            if old_jwk != *self.current_root.lock().unwrap() {
                return Err(Error::engine(
                    "test directory rejected an untrusted current root",
                ));
            }
            verify_detached_jws(
                &old_jwk,
                "native-root-transition+jws",
                &request.transition.statement,
                &request.transition.old_root_signature,
            )?;
            verify_detached_jws(
                &new_jwk,
                "native-root-transition+jws",
                &request.transition.statement,
                &request.transition.new_root_signature,
            )?;
            let signed = &request.projected_principal_document;
            let document = &signed["document"];
            assert_eq!(
                document["document_version"],
                request.expected_document_version + 1
            );
            assert!(document["root_keys"]
                .as_array()
                .unwrap()
                .iter()
                .any(|root| {
                    root["jwk"] == serde_json::to_value(&new_jwk).unwrap()
                        && root["status"] == "active"
                }));
            let mut new_signing = None;
            let mut active_encryption = 0;
            for key in document["operational_keys"].as_array().unwrap() {
                let statement = &key["authorization"]["statement"];
                assert_eq!(statement["key"]["jwk"], key["jwk"]);
                verify_detached_jws(
                    &new_jwk,
                    "native-key-authorization+jws",
                    statement,
                    key["authorization"]["signature"].as_str().unwrap(),
                )?;
                if key["status"] == "active" && key["purpose"] == "signing" {
                    new_signing = Some(serde_json::from_value(key["jwk"].clone()).unwrap());
                }
                if key["status"] == "active" && key["purpose"] == "encryption" {
                    active_encryption += 1;
                }
            }
            assert_eq!(active_encryption, 1);
            let new_signing: PublicJwk = new_signing.unwrap();
            let mut active_installations = 0;
            for installation in document["installations"].as_array().unwrap() {
                let statement = &installation["authorization"]["statement"];
                assert_eq!(statement["installation"]["jwk"], installation["jwk"]);
                verify_detached_jws(
                    &new_signing,
                    "native-key-authorization+jws",
                    statement,
                    installation["authorization"]["signature"].as_str().unwrap(),
                )?;
                if installation["status"] == "active" {
                    active_installations += 1;
                }
            }
            assert_eq!(active_installations, 1);
            verify_detached_jws(
                &new_signing,
                "native-principal+jws",
                document,
                signed["principal_signature"].as_str().unwrap(),
            )?;
            *version += 1;
            *self.current_root.lock().unwrap() = new_jwk;
            let document_digest = test_document_digest(document);
            let authority_attestation = json!({
                "test_authority_token": test_document_digest(&json!({
                    "handoff_id": request.handoff_id,
                    "document_version": *version,
                    "document_digest": document_digest,
                    "authority_domain": "test-directory",
                }))
            });
            let evidence = DirectoryAttestation {
                handoff_id: request.handoff_id.clone(),
                document_version: *version,
                document_digest,
                authority_attestation,
            };
            self.issued.lock().unwrap().push(evidence.clone());
            Ok(DirectoryCommit::Attested(evidence))
        })
    }

    fn verify_attestation<'a>(
        &'a self,
        evidence: &'a DirectoryAttestation,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if self.issued.lock().unwrap().contains(evidence) {
                Ok(())
            } else {
                Err(Error::auth(
                    "test directory rejected fabricated authority evidence",
                ))
            }
        })
    }
}

fn make_package(
    directory: &TempDir,
    source: &FileFederationCustody,
    identity: &EjectDestinationIdentity,
) -> std::path::PathBuf {
    let database = directory.path().join("content.db");
    std::fs::write(&database, b"portable database bytes").unwrap();
    let package = directory.path().join("handoff.native-eject");
    create_eject_package(
        source,
        "account-alice",
        &database,
        &package,
        &identity.recipient(),
        SOURCE_INSTALLATION,
        NOW,
        EXPIRES,
    )
    .unwrap();
    package
}

#[tokio::test]
async fn identity_only_adoption_and_package_paths_are_digest_and_type_guarded() {
    let source_dir = TempDir::new().unwrap();
    let source = custody(&source_dir, 73);
    provision(&source, "account-alice", SOURCE_INSTALLATION);
    let identity = EjectDestinationIdentity::generate();
    let package = make_package(&source_dir, &source, &identity);
    let network = TestDirectory::new(&source, "account-alice", false);

    let destination_dir = TempDir::new().unwrap();
    let destination = custody(&destination_dir, 74);
    let mismatched_database = destination_dir.path().join("mismatched.db");
    std::fs::write(&mismatched_database, b"different database bytes").unwrap();
    let error = adopt_eject_identity_after_database_adoption(
        &destination,
        "destination-mismatch",
        &package,
        &mismatched_database,
        &identity,
        DESTINATION_INSTALLATION,
        "https://mismatch.example",
        &network,
        "destination-mismatch",
        LATER,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("does not match"));
    assert_eq!(
        destination.inspect("destination-mismatch").state,
        PrincipalState::Unprovisioned
    );

    let malformed = source_dir.path().join("malformed.native-eject");
    let mut bytes = std::fs::read(&package).unwrap();
    bytes[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    std::fs::write(&malformed, bytes).unwrap();
    assert!(extract_eject_database(
        &malformed,
        &source_dir.path().join("malformed-output.db"),
        LATER,
    )
    .is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = destination_dir.path().join("symlink-target.db");
        std::fs::write(&target, b"do not overwrite").unwrap();
        let symlink_destination = destination_dir.path().join("symlink-destination.db");
        symlink(&target, &symlink_destination).unwrap();
        assert!(adopt_eject_package(
            &destination,
            "destination-symlink",
            &package,
            &symlink_destination,
            &identity,
            DESTINATION_INSTALLATION,
            "https://symlink.example",
            &network,
            "destination-symlink",
            LATER,
        )
        .await
        .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite");
    }
}

#[tokio::test]
async fn eject_is_principal_authorized_and_directory_outage_is_retryable() {
    let directory = TempDir::new().unwrap();
    let source = custody(&directory, 17);
    source
        .provision(
            "account-alice",
            "native",
            SOURCE_INSTALLATION,
            "https://node.example",
            "account-alice",
            "2026-08-03T09:00:00Z",
        )
        .unwrap();
    source
        .provision(
            "account-bob",
            "native",
            DESTINATION_INSTALLATION,
            "https://bob.example",
            "account-bob",
            NOW,
        )
        .unwrap();
    let historical_payload = json!({"before_eject_rotation": true});
    let historical_signing = source
        .inspect("account-alice")
        .keys
        .into_iter()
        .find(|key| key.purpose == KeyPurpose::Signing && key.status == KeyStatus::Active)
        .unwrap()
        .jwk;
    let historical_signature = source
        .sign_detached(
            "account-alice",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &historical_payload,
        )
        .unwrap();
    source
        .begin_rotation(
            "account-alice",
            KeyPurpose::Signing,
            "account-alice",
            "pre-eject rollover",
            "2026-08-03T10:00:00Z",
        )
        .unwrap();
    source
        .finish_rotation(
            "account-alice",
            KeyPurpose::Signing,
            "account-alice",
            "pre-eject overlap complete",
            "2026-08-03T11:00:00Z",
        )
        .unwrap();
    let identity = EjectDestinationIdentity::generate();
    let package = make_package(&directory, &source, &identity);
    let package_bytes = std::fs::read(&package).unwrap();
    let bob = source.inspect("account-bob");
    assert!(bob.keys.iter().all(|key| !package_bytes
        .windows(key.jwk.kid.len())
        .any(|window| window == key.jwk.kid.as_bytes())));

    let unauthorized = directory.path().join("unauthorized.native-eject");
    assert!(create_eject_package(
        &source,
        "account-bob",
        &directory.path().join("content.db"),
        &unauthorized,
        &identity.recipient(),
        SOURCE_INSTALLATION,
        NOW,
        EXPIRES,
    )
    .is_err());

    let destination_dir = TempDir::new().unwrap();
    let destination = custody(&destination_dir, 19);
    let database = destination_dir.path().join("adopted.db");
    let network = TestDirectory::new(&source, "account-alice", true);
    let pending = adopt_eject_package(
        &destination,
        "destination-account",
        &package,
        &database,
        &identity,
        DESTINATION_INSTALLATION,
        "https://self-host.example",
        &network,
        "destination-account",
        LATER,
    )
    .await
    .unwrap();
    assert_eq!(pending.directory_state, PrincipalState::PendingHandoff);
    assert_eq!(
        std::fs::read(&database).unwrap(),
        b"portable database bytes"
    );
    assert!(destination
        .sign_detached(
            "destination-account",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &json!({}),
        )
        .is_err());

    let active = retry_pending_handoff(
        &destination,
        "destination-account",
        &database,
        &network,
        "destination-account",
        "2026-08-03T14:00:00Z",
    )
    .await
    .unwrap();
    assert_eq!(active.directory_state, PrincipalState::Active);
    assert_eq!(
        active.principal.principal_id,
        source.inspect("account-alice").principal_id
    );
    assert_eq!(
        active
            .principal
            .keys
            .iter()
            .filter(|key| key.status == KeyStatus::DecryptOnly)
            .count(),
        1
    );
    let adopted_historical = active
        .principal
        .keys
        .iter()
        .find(|key| key.jwk.kid == historical_signing.kid)
        .unwrap();
    assert_eq!(adopted_historical.status, KeyStatus::Retired);
    verify_detached_jws(
        &historical_signing,
        "native-envelope+jws",
        &historical_payload,
        &historical_signature,
    )
    .unwrap();
    let destination_vault = std::fs::read_dir(destination_dir.path().join("custody/principals"))
        .unwrap()
        .find_map(|entry| {
            let path = entry.unwrap().path();
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".vault.json"))
                .then_some(path)
        })
        .unwrap();
    let destination_json: Value =
        serde_json::from_slice(&std::fs::read(destination_vault).unwrap()).unwrap();
    assert!(destination_json["keys"]
        .as_array()
        .unwrap()
        .iter()
        .all(|key| { key["public"]["jwk"]["kid"] != historical_signing.kid }));
    destination
        .sign_detached(
            "destination-account",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &json!({"active": true}),
        )
        .unwrap();

    let evidence = active.authority_evidence.clone().unwrap();
    let mut fabricated = evidence.clone();
    fabricated.document_digest = format!("sha-256:{}", URL_SAFE_NO_PAD.encode([0u8; 32]));
    assert!(source
        .retire_source_after_handoff(
            "account-alice",
            &fabricated,
            &network,
            "cloud-control-plane",
            "2026-08-03T14:00:00Z",
        )
        .await
        .is_err());
    let retired = source
        .retire_source_after_handoff(
            "account-alice",
            &evidence,
            &network,
            "cloud-control-plane",
            "2026-08-03T14:00:00Z",
        )
        .await
        .unwrap();
    assert_eq!(retired.state, PrincipalState::Retired);
    assert!(source
        .sign_detached(
            "account-alice",
            KeyPurpose::Signing,
            "native-envelope+jws",
            &json!({}),
        )
        .is_err());
}

#[tokio::test]
async fn first_adoption_wins_and_a_stale_clone_is_fenced() {
    let source_dir = TempDir::new().unwrap();
    let source = custody(&source_dir, 23);
    provision(&source, "account-alice", SOURCE_INSTALLATION);
    let identity = EjectDestinationIdentity::generate();
    let package = make_package(&source_dir, &source, &identity);
    let network = TestDirectory::new(&source, "account-alice", false);

    let first_dir = TempDir::new().unwrap();
    let first = custody(&first_dir, 29);
    let accepted = adopt_eject_package(
        &first,
        "destination-one",
        &package,
        &first_dir.path().join("adopted.db"),
        &identity,
        DESTINATION_INSTALLATION,
        "https://one.example",
        &network,
        "destination-one",
        LATER,
    )
    .await
    .unwrap();
    assert_eq!(accepted.directory_state, PrincipalState::Active);

    let stale_dir = TempDir::new().unwrap();
    let stale = custody(&stale_dir, 31);
    let error = adopt_eject_package(
        &stale,
        "destination-two",
        &package,
        &stale_dir.path().join("adopted.db"),
        &identity,
        "00000000-0000-4000-8000-000000000303",
        "https://two.example",
        &network,
        "destination-two",
        LATER,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("version conflict"));
    assert_eq!(
        stale.inspect("destination-two").state,
        PrincipalState::PendingHandoff
    );
}

#[test]
fn plain_database_export_contract_remains_separate() {
    // The eject package is an explicit second artifact. A caller can still
    // copy/adopt the content file without opening or possessing any identity.
    let directory = TempDir::new().unwrap();
    let content = directory.path().join("content.db");
    std::fs::write(&content, b"content only").unwrap();
    let copy = directory.path().join("copy.db");
    std::fs::copy(&content, &copy).unwrap();
    assert_eq!(std::fs::read(copy).unwrap(), b"content only");
    assert!(!Path::new(&content).with_extension("native-eject").exists());
}

#[test]
fn installation_endpoint_origin_is_a_reconcilable_deployment_attribute() {
    // A deployment's public hostname can change without the account changing
    // installations. Custody has to re-stamp the origin in place: the keys,
    // the principal id, and the installation id all survive the cutover.
    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 21);
    provision(&custody, "account-alice", SOURCE_INSTALLATION);
    let before = custody.inspect("account-alice");

    // The dry run classifies identically and does not write.
    assert_eq!(
        custody
            .update_installation_endpoint(
                "account-alice",
                SOURCE_INSTALLATION,
                "https://app.example",
                "engine:test",
                LATER,
                true,
            )
            .unwrap(),
        EndpointUpdate::Updated
    );
    assert_eq!(
        custody.inspect("account-alice").document_version,
        before.document_version
    );

    assert_eq!(
        custody
            .update_installation_endpoint(
                "account-alice",
                SOURCE_INSTALLATION,
                "https://app.example",
                "engine:test",
                LATER,
                false,
            )
            .unwrap(),
        EndpointUpdate::Updated
    );
    let after = custody.inspect("account-alice");
    assert_eq!(after.principal_id, before.principal_id);
    assert_eq!(after.document_version, before.document_version + 1);

    let installation = after
        .keys
        .iter()
        .find(|key| key.purpose == KeyPurpose::Installation && key.status == KeyStatus::Active)
        .unwrap();
    assert_eq!(
        installation.endpoint_origin.as_deref(),
        Some("https://app.example")
    );
    assert_eq!(
        installation.installation_id.as_deref(),
        Some(SOURCE_INSTALLATION)
    );
    // No key material moved, so no rotation and no new thumbprint.
    let old_installation = before
        .keys
        .iter()
        .find(|key| key.purpose == KeyPurpose::Installation && key.status == KeyStatus::Active)
        .unwrap();
    assert_eq!(installation.jwk, old_installation.jwk);

    // The change is auditable and the re-issued document advertises it.
    let audit = custody.audit_events("account-alice").unwrap();
    let event = audit.last().unwrap();
    assert_eq!(event.event_type, "installation.endpoint_updated");
    assert_eq!(event.result, "succeeded");
    assert!(event.reason.contains("https://node.example"), "{event:?}");
    assert!(event.reason.contains("https://app.example"), "{event:?}");
    let document = custody.principal_document("account-alice", LATER).unwrap();
    let text = serde_json::to_string(&document).unwrap();
    assert!(text.contains("https://app.example"), "{text}");
    assert!(!text.contains("https://node.example"), "{text}");

    // Idempotent: a repeat is not a version bump, because this runs on every
    // authenticated connect.
    assert_eq!(
        custody
            .update_installation_endpoint(
                "account-alice",
                SOURCE_INSTALLATION,
                "https://app.example",
                "engine:test",
                LATER,
                false,
            )
            .unwrap(),
        EndpointUpdate::AlreadyCurrent
    );
    assert_eq!(
        custody.inspect("account-alice").document_version,
        after.document_version
    );

    // Another installation's id is not a hostname change; it is a different
    // claim about who holds the keys, and it is never re-stamped.
    assert_eq!(
        custody
            .update_installation_endpoint(
                "account-alice",
                DESTINATION_INSTALLATION,
                "https://app.example",
                "engine:test",
                LATER,
                false,
            )
            .unwrap(),
        EndpointUpdate::NoInstallationKey
    );
}

#[test]
fn endpoint_updates_refuse_to_write_through_an_in_flight_rotation() {
    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 22);
    provision(&custody, "account-alice", SOURCE_INSTALLATION);
    custody
        .begin_rotation(
            "account-alice",
            KeyPurpose::Signing,
            "engine:test",
            "scheduled rollover",
            LATER,
        )
        .unwrap();
    assert_eq!(
        custody
            .update_installation_endpoint(
                "account-alice",
                SOURCE_INSTALLATION,
                "https://app.example",
                "engine:test",
                LATER,
                false,
            )
            .unwrap(),
        EndpointUpdate::NotActive
    );
}

#[test]
fn endpoint_updates_refuse_to_break_a_pending_eject_retirement_fence() {
    // `create_eject_package` pins the source's exact document version and
    // leaves the vault Active. `retire_source_after_handoff` then requires the
    // attested version to be exactly one ahead, so any unrelated bump inside
    // that window would strand the source Active forever — two installations
    // holding custody for one principal, with no way back.
    let directory = TempDir::new().unwrap();
    let source = custody(&directory, 23);
    provision(&source, "account-alice", SOURCE_INSTALLATION);
    let identity = EjectDestinationIdentity::generate();
    let pinned = source.inspect("account-alice").document_version;
    make_package(&directory, &source, &identity);

    // Reported, not raised: a fleet sweep must be able to leave this account
    // alone and carry on rather than failing the whole run.
    let outcome = source
        .update_installation_endpoint(
            "account-alice",
            SOURCE_INSTALLATION,
            "https://app.example",
            "engine:test",
            LATER,
            false,
        )
        .unwrap();
    assert_eq!(outcome, EndpointUpdate::AwaitingSourceRetirement);
    assert_eq!(
        outcome.skipped_reason(),
        Some("eject package awaits source retirement")
    );
    assert_eq!(
        source.inspect("account-alice").document_version,
        pinned,
        "the retirement fence must be left exactly where the package pinned it"
    );
}

#[test]
fn endpoint_updates_treat_an_account_without_custody_as_nothing_to_do() {
    // A fleet sweep reaches accounts that have never had custody. That is an
    // ordinary state, not a failure, and it must not be reported as a skip:
    // provisioning stamps the configured origin when it happens.
    let directory = TempDir::new().unwrap();
    let custody = custody(&directory, 24);
    let outcome = custody
        .update_installation_endpoint(
            "account-nobody",
            SOURCE_INSTALLATION,
            "https://app.example",
            "engine:test",
            LATER,
            false,
        )
        .unwrap();
    assert_eq!(outcome, EndpointUpdate::Unprovisioned);
    assert_eq!(outcome.skipped_reason(), None);
    assert!(!outcome.changed());
    assert_eq!(
        custody.inspect("account-nobody").state,
        PrincipalState::Unprovisioned
    );
}
