//! Process-local, scope-bound preview receipts for native app consent.
//! Consent is durable only after its accepted kernel outcome commits.
use super::*;
use crate::mcp::tools::alpha_tabs::{
    verify_alpha_tab_adopt_confirm, AlphaTabAdoptConfirm, AlphaTabPreviewReceipt,
    ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT, ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT,
    ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Binding {
    pub database: String,
    pub activation_event: String,
    pub install_generation: String,
    pub revocation_seq: i64,
    pub hosting_session: String,
}
#[derive(Clone)]
struct Stored {
    receipt: AlphaTabPreviewReceipt,
    binding: Binding,
    consumed: bool,
}
fn store() -> &'static Mutex<HashMap<String, Stored>> {
    static STORE: OnceLock<Mutex<HashMap<String, Stored>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}
fn random_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Call only after verified hosted preview authority and current pin/View checks.
/// Native receipts never enter the v1 store: neither engine can consume the
/// other's receipt while overlooking its private database/generation binding.
pub(super) fn issue(
    account: &str,
    pin: &Value,
    binding: Binding,
    now: i64,
) -> Result<AlphaTabPreviewReceipt> {
    let expires_at_secs = now
        .checked_add(ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS)
        .ok_or_else(|| invalid("preview clock overflow"))?;
    let receipt = AlphaTabPreviewReceipt {
        receipt_id: format!("preview_{}", &random_hex()[..16]),
        nonce: random_hex(),
        account_id: account.into(),
        package: string(pin, "package")?.into(),
        version: string(pin, "version")?.into(),
        digest: string(pin, "digest")?.into(),
        artifact_id: string(pin, "artifact_id")?.into(),
        source_revision: string(pin, "source_revision")?.into(),
        declaration_digest: string(pin, "declaration_digest")?.into(),
        needs: vec![],
        effects: vec![],
        preview_session: format!("sess_{}", &random_hex()[..16]),
        last_update_event_id: Some(binding.install_generation.clone()),
        issued_at_secs: now,
        expires_at_secs,
    };
    let mut held = store()
        .lock()
        .map_err(|_| invalid("preview store unavailable"))?;
    held.retain(|_, s| s.receipt.expires_at_secs > now);
    while held.len() >= ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT
        || held
            .values()
            .filter(|s| s.receipt.account_id == account)
            .count()
            >= ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT
    {
        let account_full = held
            .values()
            .filter(|s| s.receipt.account_id == account)
            .count()
            >= ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT;
        let oldest = held
            .iter()
            .filter(|(_, s)| !account_full || s.receipt.account_id == account)
            .min_by_key(|(id, s)| (s.receipt.issued_at_secs, (*id).clone()))
            .map(|(id, _)| id.clone());
        let Some(oldest) = oldest else {
            break;
        };
        held.remove(&oldest);
    }
    if held.contains_key(&receipt.receipt_id) {
        return Err(invalid("preview receipt collision"));
    }
    held.insert(
        receipt.receipt_id.clone(),
        Stored {
            receipt: receipt.clone(),
            binding,
            consumed: false,
        },
    );
    Ok(receipt)
}

/// The delivery guard rechecks this on every reusable preview request.
/// Current membership, catalogue session, source View and pending generation
/// must also be checked against the database by the host at each redemption.
pub(super) fn pending(
    receipt_id: &str,
    binding: &Binding,
    now: i64,
) -> Result<AlphaTabPreviewReceipt> {
    let held = store()
        .lock()
        .map_err(|_| invalid("preview store unavailable"))?;
    let s = held
        .get(receipt_id)
        .ok_or_else(|| invalid("receipt_unknown"))?;
    if &s.binding != binding
        || s.consumed
        || now < s.receipt.issued_at_secs
        || now >= s.receipt.expires_at_secs
    {
        return Err(invalid("preview receipt unavailable"));
    }
    Ok(s.receipt.clone())
}

/// Verify and spend under one lock, with no await or lookup/consume race.
/// Caller must already hold the mutation transaction and prove the verified
/// hosted adopt authority plus current pin/generation/membership/View. A spent
/// receipt is not restored after an uncertain commit; a durable keyed retry
/// uses the canonical accepted outcome instead of this ephemeral store.
pub(super) fn consume(confirm: &AlphaTabAdoptConfirm, binding: &Binding, now: i64) -> Result<()> {
    let mut held = store()
        .lock()
        .map_err(|_| invalid("preview store unavailable"))?;
    let s = held
        .get_mut(&confirm.receipt_id)
        .ok_or_else(|| invalid("receipt_unknown"))?;
    verify_alpha_tab_adopt_confirm(Some(&s.receipt), confirm, now, s.consumed, false, true)
        .map_err(invalid)?;
    if &s.binding != binding {
        return Err(invalid("receipt_scope_mismatch"));
    }
    s.consumed = true;
    Ok(())
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            database: uuid::Uuid::new_v4().to_string(),
            activation_event: "frozen-activation".into(),
            install_generation: "pending-install".into(),
            revocation_seq: 0,
            hosting_session: "authenticated-cookie-session".into(),
        }
    }

    fn pin() -> Value {
        json!({"package":"agent.docs","version":"0.8.2","digest":"digest",
            "artifact_id":"artifact","source_revision":"frozen-source",
            "declaration_digest":"declaration"})
    }

    fn confirm(r: &AlphaTabPreviewReceipt) -> AlphaTabAdoptConfirm {
        AlphaTabAdoptConfirm {
            receipt_id: r.receipt_id.clone(),
            nonce: r.nonce.clone(),
            account_id: r.account_id.clone(),
            package: r.package.clone(),
            version: r.version.clone(),
            digest: r.digest.clone(),
            artifact_id: r.artifact_id.clone(),
            source_revision: r.source_revision.clone(),
            declaration_digest: r.declaration_digest.clone(),
            needs: vec![],
            effects: vec![],
            preview_session: r.preview_session.clone(),
            reason: "Adopt after reviewing the sample".into(),
            expected_install_event_id: "pending-install".into(),
            current_event_id: "pending-install".into(),
        }
    }

    #[test]
    fn native_preview_receipts_bind_scope_pin_account_generation_and_expiry() {
        let b = binding();
        let now = chrono::Utc::now().timestamp();
        let r = issue(&b.database, &pin(), b.clone(), now).unwrap();
        assert_eq!(r.last_update_event_id.as_deref(), Some("pending-install"));
        let mut c = confirm(&r);
        c.account_id = "other-member".into();
        assert!(consume(&c, &b, now + 1).is_err());
        c.account_id = r.account_id.clone();
        c.artifact_id = "other-source".into();
        assert!(consume(&c, &b, now + 1).is_err());
        c.artifact_id = r.artifact_id.clone();
        c.current_event_id = "replacement-install".into();
        assert!(consume(&c, &b, now + 1).is_err());
        c.current_event_id = "pending-install".into();
        let mut other = b.clone();
        other.database = "other-database".into();
        assert!(consume(&c, &other, now + 1).is_err());
        other = b.clone();
        other.hosting_session = "other-cookie-session".into();
        assert!(consume(&c, &other, now + 1).is_err());
        other = b.clone();
        other.revocation_seq = 1;
        assert!(consume(&c, &other, now + 1).is_err());
        assert!(consume(&c, &b, r.expires_at_secs).is_err());
        assert!(consume(&c, &b, now - 1).is_err());
        assert!(pending(&r.receipt_id, &b, now + 1).is_ok());
        consume(&c, &b, now + 1).unwrap();
        assert!(consume(&c, &b, now + 1).is_err());
        assert!(pending(&r.receipt_id, &b, now + 1).is_err());
    }

    #[test]
    fn native_preview_receipts_accept_only_one_concurrent_confirmation() {
        let b = binding();
        let now = chrono::Utc::now().timestamp();
        let r = issue(&b.database, &pin(), b.clone(), now).unwrap();
        let successes = std::thread::scope(|scope| {
            let first = scope.spawn(|| consume(&confirm(&r), &b, now + 1).is_ok());
            let second = scope.spawn(|| consume(&confirm(&r), &b, now + 1).is_ok());
            usize::from(first.join().unwrap()) + usize::from(second.join().unwrap())
        });
        assert_eq!(successes, 1);
    }
}
