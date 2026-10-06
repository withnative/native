//! Private committed-body paging mechanics and owned Hosted qualification.
//!
//! The SQLite owner resolves the binding and enforces current
//! source/declaration/View/scope in one snapshot, and supply its event and CAS
//! digest. The pure pager grants no authority; preparing a continuation
//! authenticates correlation, never access.
//! Prepare BEFORE target lookup: malformed/pair-mismatched/expired cursors must
//! not disclose present target state. Form a page only AFTER current authority.

use std::sync::OnceLock;
use std::time::Instant;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const CONTRACT: &str = "records.body.read.v1";
const MAX_PAGE_BYTES: u64 = 32768;
const MAX_RESPONSE_BYTES: usize = 262144;
const MAX_TOKEN_BYTES: usize = 1024;
const MAX_PLAINTEXT_BYTES: usize = MAX_TOKEN_BYTES / 2 - 24 - 16;
const MAX_REQUEST_BYTES: usize = 4096;
const JS_SAFE: u64 = (1 << 53) - 1;
const LIFETIME_MS: u64 = 900000;

#[doc(hidden)]
pub mod hosted;
mod sqlite;

/// Pure failures only: source admission and View/scope refusals belong to S2.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    InvalidParams,
    InvalidCursor,
    CursorExpired,
    RevisionChanged,
    ResourceExhausted,
    Engine,
}

#[cfg(test)]
mod sqlite_lifecycle_qualification {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use sqlx::Connection;

    /// Qualification only: this is not the trusted S2 resolver or executor.
    /// Rev3 permits owned async acquisition after a ready-only miss.
    #[tokio::test]
    async fn ready_only_explicit_close_exhausts_real_governed_pool() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ready-only.db");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        let pool = db.governed_pool();
        assert_eq!(pool.options().get_min_connections(), 0);

        let mut ready = Vec::new();
        while let Some(connection) = pool.try_acquire() {
            ready.push(connection);
            assert!(ready.len() <= pool.options().get_max_connections() as usize);
        }
        assert!(
            !ready.is_empty(),
            "real Db must have an initial ready checkout"
        );
        let initial = ready.len();
        assert_eq!(pool.size(), initial as u32);
        for connection in ready {
            connection.close().await.unwrap();
        }
        assert_eq!(
            pool.size(),
            0,
            "close must retain capacity until shutdown ack"
        );

        // Let already runnable maintenance run; no timer or new acquire is
        // used to manufacture an idle replacement for the reader.
        for _ in 0..32 {
            tokio::task::yield_now().await;
            assert!(pool.try_acquire().is_none());
        }
        assert_eq!(pool.size(), 0);
        eprintln!("qualification: initial_ready={initial}, after_ack=0, min_connections=0");

        // Whole acquisition futures are awaited, never raced against timeout.
        // No separate provisioner/pool: fresh pages make progress via the
        // exact ordinary acquisition allowed by clarified Rev3.
        for _ in 0..16 {
            let replacement = pool.acquire().await.unwrap();
            assert_eq!(pool.size(), 1);
            replacement.close().await.unwrap();
            assert!(pool.try_acquire().is_none());
            assert_eq!(pool.size(), 0);
        }
        db.close().await;
    }

    #[tokio::test]
    async fn explicit_governed_close_runs_no_optimization_vm_work() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("close-meter.db");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        let mut connection = db.governed_pool().try_acquire().unwrap();
        connection.close_on_drop();
        let vm_steps = Arc::new(AtomicU64::new(0));
        let meter = Arc::clone(&vm_steps);
        {
            let mut handle = connection.lock_handle().await.unwrap();
            handle.remove_progress_handler();
            handle.set_progress_handler(1, move || {
                meter.fetch_add(1, Ordering::SeqCst);
                true
            });
        }
        let mut transaction = connection.begin().await.unwrap();
        let version: String = sqlx::query_scalar("SELECT sqlite_version()")
            .fetch_one(&mut *transaction)
            .await
            .unwrap();
        // Same singleton, same snapshot. Metadata precedes hydration.
        let (storage, bytes): (String, i64) = sqlx::query_as(
            "SELECT typeof(origin_db_id), octet_length(origin_db_id) FROM database_identity WHERE singleton=1",
        )
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
        assert_eq!((storage.as_str(), bytes), ("text", 36));
        let identity: String =
            sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
                .fetch_one(&mut *transaction)
                .await
                .unwrap();
        assert!(crate::identity::is_database_id(&identity));
        assert_eq!(
            crate::identity::database_id_on(&db, &mut transaction)
                .await
                .unwrap(),
            identity
        );
        transaction.rollback().await.unwrap();
        let before_close = vm_steps.load(Ordering::SeqCst);
        assert!(before_close > 0, "meter must actually observe SQLite work");
        connection.close().await.unwrap();
        assert_eq!(vm_steps.load(Ordering::SeqCst), before_close);
        eprintln!(
            "qualification: SQLite={version}, metered_steps={before_close}, close_extra_steps=0"
        );
        db.close().await;
    }
}

type Result<T> = std::result::Result<T, Refusal>;

/// JSON-only raw entry points accept maps, never Serde's positional struct
/// representation. Keep the original bytes for typed duplicate-field checks.
fn is_json_object(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .find(|&&b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        == Some(&b'{')
}

fn present<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    record_id: String,
    #[serde(default, deserialize_with = "present")]
    page_bytes: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    revision: Option<String>,
    #[serde(default, deserialize_with = "present")]
    cursor: Option<String>,
}

impl Request {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REQUEST_BYTES || !is_json_object(bytes) {
            return Err(Refusal::InvalidParams);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| Refusal::InvalidParams)?;
        if !identity(&request.record_id)
            || request
                .page_bytes
                .is_some_and(|n| !(4..=MAX_PAGE_BYTES).contains(&n))
            || request.revision.is_some() != request.cursor.is_some()
            || request
                .revision
                .iter()
                .chain(request.cursor.iter())
                .any(|token| token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii())
        {
            return Err(Refusal::InvalidParams);
        }
        Ok(request)
    }
}

/// Trusted adapter-supplied correlation values. None is an authorization grant.
/// Generation must change on re-adoption even if source/grants are identical.
pub(crate) struct BindingContext {
    pub(crate) database: String,
    pub(crate) viewer: String,
    pub(crate) declaring_source: String,
    pub(crate) adoption_generation: String,
    pub(crate) source_runtime_pin: String,
    pub(crate) declaration_digest: String,
    pub(crate) record_id: String,
}

impl BindingContext {
    fn domain(&self, purpose: &str, event: Option<&str>) -> Result<Vec<u8>> {
        let fields = [
            self.database.as_str(),
            self.viewer.as_str(),
            self.declaring_source.as_str(),
            self.adoption_generation.as_str(),
            self.source_runtime_pin.as_str(),
            self.declaration_digest.as_str(),
            self.record_id.as_str(),
        ];
        if fields.iter().any(|s| s.is_empty() || s.len() > 256)
            || !digest(&self.declaration_digest)
            || !identity(&self.record_id)
        {
            return Err(Refusal::Engine);
        }
        // Fixed order, JSON escaping, separate purpose domain; no concatenated
        // identifiers with ambiguous separators. All input strings are bounded.
        let mut tuple = vec![
            CONTRACT, "1", purpose, fields[0], fields[1], fields[2], fields[3], fields[4],
            fields[5], fields[6],
        ];
        if let Some(event) = event {
            tuple.push(event);
        }
        serde_json::to_vec(&tuple).map_err(|_| Refusal::Engine)
    }
}

fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    version: u8,
    event: String,
    position: u64,
    total: u64,
    body_present: bool,
    body_digest: String,
    page_bytes: u64,
    expires_ms: u64,
}

impl CursorPayload {
    fn validate(&self) -> Result<()> {
        if self.version != 1
            || !identity(&self.event)
            || !digest(&self.body_digest)
            || !(4..=MAX_PAGE_BYTES).contains(&self.page_bytes)
            || self.total > JS_SAFE
            || self.position == 0
            || self.position >= self.total
            || !self.body_present
            || self.expires_ms < LIFETIME_MS
            || self.expires_ms > JS_SAFE
        {
            return Err(Refusal::InvalidCursor);
        }
        Ok(())
    }
}

/// Keys and monotonic origin live for this process only. Tests construct their
/// own private codecs/clock inputs; production key material is never exported.
pub(crate) struct Codec {
    revision_key: [u8; 32],
    cursor_cipher: XChaCha20Poly1305,
    origin: Instant,
}

impl Codec {
    pub(crate) fn process() -> &'static Self {
        static CODEC: OnceLock<Codec> = OnceLock::new();
        CODEC.get_or_init(|| {
            let mut revision_key = [0; 32];
            let mut cursor_key = [0; 32];
            rand::rng().fill_bytes(&mut revision_key);
            rand::rng().fill_bytes(&mut cursor_key);
            Self {
                revision_key,
                cursor_cipher: XChaCha20Poly1305::new((&cursor_key).into()),
                origin: Instant::now(),
            }
        })
    }

    pub(crate) fn prepare<'a>(
        &'a self,
        binding: &'a BindingContext,
        request: Request,
    ) -> Result<PreparedRead<'a>> {
        let now = u64::try_from(self.origin.elapsed().as_millis())
            .map_err(|_| Refusal::ResourceExhausted)?;
        self.prepare_at(binding, request, now)
    }

    fn revision_mac(&self, binding: &BindingContext, event: &str) -> Result<Hmac<Sha256>> {
        if !identity(event) {
            return Err(Refusal::Engine);
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.revision_key)
            .map_err(|_| Refusal::Engine)?;
        // One fixed-order tuple includes event identity, without delimiter ambiguity.
        let input = binding.domain("revision", Some(event))?;
        mac.update(&input);
        Ok(mac)
    }

    fn revision(&self, binding: &BindingContext, event: &str) -> Result<String> {
        Ok(hex::encode(
            self.revision_mac(binding, event)?.finalize().into_bytes(),
        ))
    }

    fn seal(&self, binding: &BindingContext, payload: &CursorPayload) -> Result<String> {
        payload.validate()?;
        let plaintext = serde_json::to_vec(payload).map_err(|_| Refusal::Engine)?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(Refusal::ResourceExhausted);
        }
        let aad = binding.domain("cursor", None)?;
        let mut nonce = [0; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cursor_cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Refusal::Engine)?;
        let token = hex::encode([nonce.as_slice(), ciphertext.as_slice()].concat());
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Refusal::ResourceExhausted);
        }
        Ok(token)
    }

    fn open(&self, binding: &BindingContext, token: &str) -> Result<CursorPayload> {
        if token.len() > MAX_TOKEN_BYTES || token.len() <= 2 * (24 + 16) {
            return Err(Refusal::InvalidCursor);
        }
        let bytes = hex::decode(token).map_err(|_| Refusal::InvalidCursor)?;
        let (nonce, ciphertext) = bytes.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| Refusal::InvalidCursor)?;
        let aad = binding.domain("cursor", None)?;
        let plaintext = self
            .cursor_cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Refusal::InvalidCursor)?;
        if plaintext.len() > MAX_PLAINTEXT_BYTES || !is_json_object(&plaintext) {
            return Err(Refusal::InvalidCursor);
        }
        let payload: CursorPayload =
            serde_json::from_slice(&plaintext).map_err(|_| Refusal::InvalidCursor)?;
        payload.validate()?;
        Ok(payload)
    }

    fn prepare_at<'a>(
        &'a self,
        binding: &'a BindingContext,
        request: Request,
        now: u64,
    ) -> Result<PreparedRead<'a>> {
        binding.domain("cursor", None)?;
        if request.record_id != binding.record_id {
            return Err(Refusal::InvalidParams);
        }
        let (continuation, page_bytes, expires_ms) = match (request.revision, request.cursor) {
            (Some(revision), Some(cursor)) => {
                let payload = self.open(binding, &cursor)?;
                let tag = hex::decode(revision).map_err(|_| Refusal::InvalidCursor)?;
                self.revision_mac(binding, &payload.event)?
                    .verify_slice(&tag)
                    .map_err(|_| Refusal::InvalidCursor)?;
                if request.page_bytes.is_some_and(|n| n != payload.page_bytes) {
                    return Err(Refusal::InvalidParams);
                }
                if now >= payload.expires_ms {
                    return Err(Refusal::CursorExpired);
                }
                let size = payload.page_bytes;
                let expiry = payload.expires_ms;
                (Some(payload), size, expiry)
            }
            (None, None) => {
                let expiry = now
                    .checked_add(LIFETIME_MS)
                    .filter(|n| *n <= JS_SAFE)
                    .ok_or(Refusal::ResourceExhausted)?;
                (None, request.page_bytes.unwrap_or(MAX_PAGE_BYTES), expiry)
            }
            _ => return Err(Refusal::InvalidParams),
        };
        Ok(PreparedRead {
            codec: self,
            binding,
            continuation,
            page_bytes,
            expires_ms,
        })
    }
}

/// Engine-provided committed snapshot. This helper does not verify provenance,
/// recompute the write guard, choose creation fallback, or establish authority.
pub(crate) struct Snapshot<'a> {
    pub(crate) body: Option<&'a str>,
    pub(crate) event_id: &'a str,
    pub(crate) body_digest: &'a str,
}

pub(crate) struct PreparedRead<'a> {
    codec: &'a Codec,
    binding: &'a BindingContext,
    continuation: Option<CursorPayload>,
    page_bytes: u64,
    expires_ms: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct Page {
    contract: &'static str,
    record_id: String,
    revision: String,
    body_digest: String,
    body_present: bool,
    encoding: &'static str,
    start_byte: u64,
    end_byte: u64,
    total_bytes: u64,
    text: String,
    complete: bool,
    next_cursor: Option<String>,
    limits: Limits,
}

#[derive(Debug, Serialize)]
struct Limits {
    max_page_bytes: u64,
    max_response_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_body_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_source_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_provenance_payload_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_provenance_events: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_timeout_ms: Option<u64>,
}

impl PreparedRead<'_> {
    pub(crate) fn page(self, snapshot: Snapshot<'_>) -> Result<Page> {
        if !identity(snapshot.event_id) || !digest(snapshot.body_digest) {
            return Err(Refusal::Engine);
        }
        let body = snapshot.body.unwrap_or("");
        let total = u64::try_from(body.len()).map_err(|_| Refusal::ResourceExhausted)?;
        if total > JS_SAFE {
            return Err(Refusal::ResourceExhausted);
        }
        let start = if let Some(cursor) = &self.continuation {
            if cursor.event != snapshot.event_id {
                return Err(Refusal::RevisionChanged);
            }
            // Same event with different content metadata is an inconsistent
            // engine snapshot, not a new revision or an authorization decision.
            if cursor.total != total
                || cursor.body_present != snapshot.body.is_some()
                || cursor.body_digest != snapshot.body_digest
            {
                return Err(Refusal::Engine);
            }
            cursor.position
        } else {
            0
        };
        let start_index = usize::try_from(start).map_err(|_| Refusal::InvalidCursor)?;
        if !body.is_char_boundary(start_index) {
            return Err(Refusal::InvalidCursor);
        }
        let mut end = start
            .checked_add(self.page_bytes)
            .ok_or(Refusal::ResourceExhausted)?
            .min(total);
        let mut end_index = usize::try_from(end).map_err(|_| Refusal::ResourceExhausted)?;
        while !body.is_char_boundary(end_index) {
            end_index = end_index.checked_sub(1).ok_or(Refusal::Engine)?;
            end = end.checked_sub(1).ok_or(Refusal::Engine)?;
        }
        if end <= start && start < total {
            return Err(Refusal::Engine);
        }
        let complete = end == total;
        let next_cursor = if complete {
            None
        } else {
            Some(self.codec.seal(
                self.binding,
                &CursorPayload {
                    version: 1,
                    event: snapshot.event_id.into(),
                    position: end,
                    total,
                    body_present: snapshot.body.is_some(),
                    body_digest: snapshot.body_digest.into(),
                    page_bytes: self.page_bytes,
                    expires_ms: self.expires_ms,
                },
            )?)
        };
        let page = Page {
            contract: CONTRACT,
            record_id: self.binding.record_id.clone(),
            revision: self.codec.revision(self.binding, snapshot.event_id)?,
            body_digest: snapshot.body_digest.into(),
            body_present: snapshot.body.is_some(),
            encoding: "utf-8",
            start_byte: start,
            end_byte: end,
            total_bytes: total,
            text: body
                .get(start_index..end_index)
                .ok_or(Refusal::InvalidCursor)?
                .into(),
            complete,
            next_cursor,
            limits: Limits {
                max_page_bytes: MAX_PAGE_BYTES,
                max_response_bytes: MAX_RESPONSE_BYTES,
                max_body_bytes: None,
                max_source_bytes: None,
                max_provenance_payload_bytes: None,
                max_provenance_events: None,
                request_timeout_ms: None,
            },
        };
        check_response_size(&page, MAX_RESPONSE_BYTES)?;
        Ok(page)
    }
}

fn check_response_size(page: &Page, budget: usize) -> Result<()> {
    let bytes = serde_json::to_vec(page).map_err(|_| Refusal::Engine)?;
    if bytes.len() > budget {
        return Err(Refusal::ResourceExhausted);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn codec(seed: u8) -> Codec {
        Codec {
            revision_key: [seed; 32],
            cursor_cipher: XChaCha20Poly1305::new((&[seed.wrapping_add(1); 32]).into()),
            origin: Instant::now(),
        }
    }

    fn binding() -> BindingContext {
        BindingContext {
            database: "database-a".into(),
            viewer: "viewer-a".into(),
            declaring_source: "source-a".into(),
            adoption_generation: "adoption-a".into(),
            source_runtime_pin: "runtime-and-source-pin".into(),
            declaration_digest: "a".repeat(64),
            record_id: "document-a".into(),
        }
    }

    fn request(value: Value) -> Request {
        Request::parse(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn first(size: u64) -> Request {
        request(json!({"record_id":"document-a", "page_bytes":size}))
    }

    fn next(page: &Page) -> Request {
        request(
            json!({"record_id":page.record_id,"revision":page.revision,"cursor":page.next_cursor}),
        )
    }

    fn form(
        codec: &Codec,
        ctx: &BindingContext,
        req: Request,
        body: Option<&str>,
        event: &str,
        now: u64,
    ) -> Result<Page> {
        let guard = crate::mcp::tools::lifecycle::body_digest(body);
        codec.prepare_at(ctx, req, now)?.page(Snapshot {
            body,
            event_id: event,
            body_digest: &guard,
        })
    }

    fn raw_seal(codec: &Codec, ctx: &BindingContext, value: &Value) -> String {
        raw_seal_bytes(codec, ctx, &serde_json::to_vec(value).unwrap())
    }

    fn raw_seal_bytes(codec: &Codec, ctx: &BindingContext, plaintext: &[u8]) -> String {
        // Deliberately bypass production payload validation to exercise hostile
        // authenticated plaintext; test keys never leave this module.
        let nonce = [9; 24];
        let aad = ctx.domain("cursor", None).unwrap();
        let encrypted = codec
            .cursor_cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        hex::encode([nonce.as_slice(), encrypted.as_slice()].concat())
    }

    fn payload_value(codec: &Codec, ctx: &BindingContext, page: &Page) -> Value {
        serde_json::to_value(codec.open(ctx, page.next_cursor.as_ref().unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn reconstructs_large_source_with_unicode_controls_and_whitespace() {
        let codec = codec(1);
        let ctx = binding();
        // >256 KiB AND >120000 characters; no parser/block-count dependency.
        let body = format!("  \r\n{}\n  ", "aé中🦀\0\t\r\n\\\"".repeat(40000));
        assert!(body.len() > 262144 && body.chars().count() > 120000);
        let mut page = form(&codec, &ctx, first(32768), Some(&body), "event-a", 10).unwrap();
        let revision = page.revision.clone();
        let guard = page.body_digest.clone();
        assert_ne!(revision, guard);
        let mut assembled = String::new();
        let mut position = 0;
        loop {
            assert_eq!(page.start_byte, position);
            assert_eq!(page.text.len() as u64, page.end_byte - page.start_byte);
            assert!(page.text.len() <= 32768);
            assert_eq!(page.revision, revision);
            assert_eq!(page.body_digest, guard);
            assert_eq!(page.complete, page.end_byte == page.total_bytes);
            assert_eq!(page.next_cursor.is_none(), page.complete);
            let serialized = serde_json::to_vec(&page).unwrap();
            assert!(serialized.len() <= MAX_RESPONSE_BYTES);
            let roundtrip: Value = serde_json::from_slice(&serialized).unwrap();
            assert_eq!(roundtrip["text"], page.text);
            assert!(!String::from_utf8(serialized).unwrap().contains("event-a"));
            assembled.push_str(&page.text);
            position = page.end_byte;
            if page.complete {
                break;
            }
            assert!(position > page.start_byte);
            assert!(page.next_cursor.as_ref().unwrap().len() <= MAX_TOKEN_BYTES);
            page = form(&codec, &ctx, next(&page), Some(&body), "event-a", 20).unwrap();
        }
        assert_eq!(assembled.as_bytes(), body.as_bytes());
    }

    #[test]
    fn every_small_page_size_preserves_scalar_boundaries_and_progress() {
        let codec = codec(2);
        let ctx = binding();
        let body = "aé中🦀é🦀中a".repeat(3);
        for size in 4..=17 {
            let mut page = form(&codec, &ctx, first(size), Some(&body), "event-a", 0).unwrap();
            let mut reconstructed = String::new();
            loop {
                assert!(body.is_char_boundary(page.start_byte as usize));
                assert!(body.is_char_boundary(page.end_byte as usize));
                assert!(page.text.len() <= size as usize);
                reconstructed.push_str(&page.text);
                if page.complete {
                    break;
                }
                assert!(page.end_byte > page.start_byte);
                page = form(&codec, &ctx, next(&page), Some(&body), "event-a", 0).unwrap();
            }
            assert_eq!(reconstructed, body);
        }
    }

    #[test]
    fn null_and_empty_are_distinct_and_keep_engine_guard() {
        let codec = codec(3);
        let ctx = binding();
        for body in [None, Some("")] {
            let page = form(&codec, &ctx, first(4), body, "event-null", 0).unwrap();
            assert_eq!(page.body_present, body.is_some());
            assert_eq!(
                (page.start_byte, page.end_byte, page.total_bytes),
                (0, 0, 0)
            );
            assert!(page.text.is_empty() && page.complete && page.next_cursor.is_none());
            assert_eq!(
                page.body_digest,
                crate::mcp::tools::lifecycle::body_digest(None)
            );
        }
        // The pure helper consumes, rather than synthesizes/verifies, a trusted guard.
        let supplied = "d".repeat(64);
        let page = codec
            .prepare_at(&ctx, first(4), 0)
            .unwrap()
            .page(Snapshot {
                body: Some("bytes"),
                event_id: "event-a",
                body_digest: &supplied,
            })
            .unwrap();
        assert_eq!(page.body_digest, supplied);
    }

    #[test]
    fn requests_are_strict_and_bounded() {
        for value in [
            json!({}),
            json!({"record_id":""}),
            json!({"record_id":"bad id"}),
            json!({"record_id":"x","unknown":true}),
            json!({"record_id":"x","page_bytes":3}),
            json!({"record_id":"x","page_bytes":32769}),
            json!({"record_id":"x","page_bytes":4.0}),
            json!({"record_id":"x","page_bytes":-1}),
            json!({"record_id":"x","page_bytes":null}),
            json!({"record_id":"x","revision":"x"}),
            json!({"record_id":"x","cursor":"x"}),
            json!({"record_id":"x","revision":null,"cursor":null}),
            json!({"record_id":"x","revision":"é","cursor":"a"}),
            json!({"record_id":"x","revision":"a","cursor":"a".repeat(1025)}),
            json!({"record_id":"x".repeat(129)}),
        ] {
            assert_eq!(
                Request::parse(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
                Refusal::InvalidParams
            );
        }
        assert_eq!(
            Request::parse(&vec![b' '; 4097]).unwrap_err(),
            Refusal::InvalidParams
        );
        assert!(Request::parse(br#"{"record_id":"x","record_id":"y"}"#).is_err());
        let ctx = binding();
        let codec = codec(4);
        assert!(matches!(
            codec.prepare_at(&ctx, request(json!({"record_id":"different"})), 0),
            Err(Refusal::InvalidParams)
        ));
    }

    #[test]
    fn every_binding_field_and_adoption_generation_is_sealed() {
        let codec = codec(5);
        let ctx = binding();
        let page = form(&codec, &ctx, first(4), Some("abcdefgh"), "event-a", 0).unwrap();
        for field in 0..7 {
            let mut other = binding();
            match field {
                0 => other.database.push('b'),
                1 => other.viewer.push('b'),
                2 => other.declaring_source.push('b'),
                3 => other.adoption_generation.push('b'),
                4 => other.source_runtime_pin.push('b'),
                5 => other.declaration_digest = "b".repeat(64),
                _ => other.record_id.push('b'),
            }
            let req = request(
                json!({"record_id":other.record_id,"revision":page.revision,"cursor":page.next_cursor}),
            );
            assert!(
                matches!(
                    codec.prepare_at(&other, req, 0),
                    Err(Refusal::InvalidCursor)
                ),
                "field {field}"
            );
            assert_ne!(
                codec.revision(&ctx, "event-a").unwrap(),
                codec.revision(&other, "event-a").unwrap()
            );
        }
        let a = binding();
        let mut b = binding();
        b.viewer.clear();
        assert!(matches!(
            codec.prepare_at(&b, first(4), 0),
            Err(Refusal::Engine)
        ));
        b = binding();
        b.source_runtime_pin = "é".repeat(129);
        assert!(matches!(
            codec.prepare_at(&b, first(4), 0),
            Err(Refusal::Engine)
        ));
        // Escaped tuple fields cannot alias through delimiter ambiguity.
        b = binding();
        b.database = "database-a\",\"viewer-a".into();
        b.viewer = "x".into();
        assert_ne!(
            a.domain("cursor", None).unwrap(),
            b.domain("cursor", None).unwrap()
        );
    }

    #[test]
    fn contradictory_pairs_tamper_and_restart_fail_before_lookup() {
        let codec = codec(6);
        let ctx = binding();
        let a = form(&codec, &ctx, first(4), Some("abcdefgh"), "event-a", 0).unwrap();
        let b = form(&codec, &ctx, first(4), Some("abcdefgh"), "event-b", 0).unwrap();
        let mut tampered = a.next_cursor.clone().unwrap().into_bytes();
        tampered[60] = if tampered[60] == b'0' { b'1' } else { b'0' };
        for (revision, cursor) in [
            (a.revision.clone(), b.next_cursor.clone().unwrap()),
            ("0".repeat(64), a.next_cursor.clone().unwrap()),
            (a.revision.clone(), String::from_utf8(tampered).unwrap()),
        ] {
            let mut lookup_called = false;
            let result = codec
                .prepare_at(
                    &ctx,
                    request(json!({"record_id":"document-a","revision":revision,"cursor":cursor})),
                    LIFETIME_MS,
                )
                .and_then(|prepared| {
                    lookup_called = true;
                    prepared.page(Snapshot {
                        body: None,
                        event_id: "changed",
                        body_digest: &"a".repeat(64),
                    })
                });
            assert_eq!(result.unwrap_err(), Refusal::InvalidCursor);
            assert!(!lookup_called);
        }
        assert!(matches!(
            self::codec(99).prepare_at(&ctx, next(&a), 0),
            Err(Refusal::InvalidCursor)
        ));
    }

    #[test]
    fn revision_follows_event_incarnation_not_bytes_and_retry_is_stable() {
        let codec = codec(7);
        let ctx = binding();
        let body = "abcdefghijkl";
        let a = form(&codec, &ctx, first(4), Some(body), "event-a", 0).unwrap();
        let retry1 = form(&codec, &ctx, next(&a), Some(body), "event-a", 100).unwrap();
        let retry2 = form(&codec, &ctx, next(&a), Some(body), "event-a", 200).unwrap();
        assert_eq!(
            (
                &retry1.text,
                retry1.start_byte,
                retry1.end_byte,
                &retry1.revision,
                &retry1.body_digest
            ),
            (
                &retry2.text,
                retry2.start_byte,
                retry2.end_byte,
                &retry2.revision,
                &retry2.body_digest
            )
        );
        // Same event represents non-body edits/no-op attempts: continuation works.
        for event in ["equal-byte-rewrite", "a-b-a-final-event"] {
            assert_eq!(
                form(&codec, &ctx, next(&a), Some(body), event, 0).unwrap_err(),
                Refusal::RevisionChanged
            );
            let new = form(&codec, &ctx, first(4), Some(body), event, 0).unwrap();
            assert_eq!(new.body_digest, a.body_digest);
            assert_ne!(new.revision, a.revision);
        }
        let explicit = request(
            json!({"record_id":"document-a","page_bytes":5,"revision":a.revision,"cursor":a.next_cursor}),
        );
        assert!(matches!(
            codec.prepare_at(&ctx, explicit, 0),
            Err(Refusal::InvalidParams)
        ));
        let explicit = request(
            json!({"record_id":"document-a","page_bytes":4,"revision":a.revision,"cursor":a.next_cursor}),
        );
        assert_eq!(
            form(&codec, &ctx, explicit, Some(body), "event-a", 0)
                .unwrap()
                .text,
            "efgh"
        );
    }

    #[test]
    fn fixed_monotonic_expiry_is_never_renewed_and_precedes_target_lookup() {
        let codec = codec(8);
        let ctx = binding();
        let body = "abcdefghijklmnop";
        let first_page = form(&codec, &ctx, first(4), Some(body), "event-a", 123).unwrap();
        let expiry = 123 + LIFETIME_MS;
        assert_eq!(
            payload_value(&codec, &ctx, &first_page)["expires_ms"],
            expiry
        );
        let second = form(
            &codec,
            &ctx,
            next(&first_page),
            Some(body),
            "event-a",
            expiry - 2,
        )
        .unwrap();
        let retry = form(
            &codec,
            &ctx,
            next(&first_page),
            Some(body),
            "event-a",
            expiry - 1,
        )
        .unwrap();
        for page in [&second, &retry] {
            assert_eq!(payload_value(&codec, &ctx, page)["expires_ms"], expiry);
            for now in [expiry, expiry + 1] {
                let mut target_queries = 0;
                let result = codec.prepare_at(&ctx, next(page), now).and_then(|_| {
                    target_queries += 1;
                    // Simulates either changed body or lost View: never reached.
                    Err::<Page, _>(Refusal::RevisionChanged)
                });
                assert_eq!(result.unwrap_err(), Refusal::CursorExpired);
                assert_eq!(target_queries, 0);
            }
        }
        assert!(matches!(
            codec.prepare_at(&ctx, first(4), u64::MAX),
            Err(Refusal::ResourceExhausted)
        ));
        assert!(matches!(
            codec.prepare_at(&ctx, first(4), JS_SAFE - LIFETIME_MS + 1),
            Err(Refusal::ResourceExhausted)
        ));
    }

    #[test]
    fn authenticated_payloads_are_strict_bounded_and_js_safe() {
        let codec = codec(9);
        let ctx = binding();
        let page = form(&codec, &ctx, first(4), Some("abcdefgh"), "event-a", 0).unwrap();
        let base = payload_value(&codec, &ctx, &page);
        for (key, value) in [
            ("version", json!(2)),
            ("extra", json!(true)),
            ("event", json!("")),
            ("event", json!("x".repeat(129))),
            ("event", json!("bad event")),
            ("body_digest", json!("A".repeat(64))),
            ("body_digest", json!("a".repeat(63))),
            ("body_present", json!(false)),
            ("position", json!(0)),
            ("position", json!(8)),
            ("position", json!(u64::MAX)),
            ("total", json!(0)),
            ("total", json!(JS_SAFE + 1)),
            ("page_bytes", json!(3)),
            ("page_bytes", json!(32769)),
            ("expires_ms", json!(JS_SAFE + 1)),
            ("expires_ms", json!(LIFETIME_MS - 1)),
            ("position", json!(-1)),
            ("position", json!(1.5)),
        ] {
            let mut hostile = base.clone();
            hostile[key] = value;
            let cursor = raw_seal(&codec, &ctx, &hostile);
            assert!(matches!(codec.prepare_at(&ctx,request(json!({"record_id":"document-a","revision":page.revision,"cursor":cursor})),0),Err(Refusal::InvalidCursor)),"{key}");
        }
        let mut huge = base.clone();
        huge["extra"] = json!("x".repeat(MAX_PLAINTEXT_BYTES));
        let token = raw_seal(&codec, &ctx, &huge);
        assert_eq!(
            codec.open(&ctx, &token).unwrap_err(),
            Refusal::InvalidCursor
        );
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("body_present");
        assert_eq!(
            codec
                .open(&ctx, &raw_seal(&codec, &ctx, &missing))
                .unwrap_err(),
            Refusal::InvalidCursor
        );
        let mut max = base;
        max["total"] = json!(JS_SAFE);
        max["position"] = json!(JS_SAFE - 1);
        let parsed = codec.open(&ctx, &raw_seal(&codec, &ctx, &max)).unwrap();
        assert_eq!(parsed.total, JS_SAFE); // representation bound, not supported body promise
    }

    #[test]
    fn forged_nonboundary_and_inconsistent_snapshots_refuse_without_panics() {
        let codec = codec(10);
        let ctx = binding();
        let body = "éééé";
        let page = form(&codec, &ctx, first(4), Some(body), "event-a", 0).unwrap();
        let mut payload = payload_value(&codec, &ctx, &page);
        payload["position"] = json!(1);
        let bad = request(
            json!({"record_id":"document-a","revision":page.revision,"cursor":raw_seal(&codec,&ctx,&payload)}),
        );
        assert_eq!(
            form(&codec, &ctx, bad, Some(body), "event-a", 0).unwrap_err(),
            Refusal::InvalidCursor
        );
        assert_eq!(
            form(&codec, &ctx, next(&page), Some("éé"), "event-a", 0).unwrap_err(),
            Refusal::Engine
        );
        assert_eq!(
            form(&codec, &ctx, next(&page), None, "event-a", 0).unwrap_err(),
            Refusal::Engine
        );
        let prepared = codec.prepare_at(&ctx, next(&page), 0).unwrap();
        assert_eq!(
            prepared
                .page(Snapshot {
                    body: Some(body),
                    event_id: "event-a",
                    body_digest: &"b".repeat(64)
                })
                .unwrap_err(),
            Refusal::Engine
        );
        let prepared = codec.prepare_at(&ctx, first(4), 0).unwrap();
        assert_eq!(
            prepared
                .page(Snapshot {
                    body: Some(body),
                    event_id: "",
                    body_digest: "bad"
                })
                .unwrap_err(),
            Refusal::Engine
        );
    }

    #[test]
    fn whole_result_byte_budget_and_output_token_bounds_are_enforced() {
        let codec = codec(11);
        let ctx = binding();
        let body = "\0".repeat(65536);
        let page = form(&codec, &ctx, first(32768), Some(&body), &"e".repeat(128), 0).unwrap();
        let bytes = serde_json::to_vec(&page).unwrap();
        assert!(bytes.len() > 6 * 32768 && bytes.len() <= MAX_RESPONSE_BYTES);
        assert!(page.next_cursor.as_ref().unwrap().len() <= MAX_TOKEN_BYTES);
        assert!(check_response_size(&page, bytes.len()).is_ok());
        assert_eq!(
            check_response_size(&page, bytes.len() - 1).unwrap_err(),
            Refusal::ResourceExhausted
        );
        let mut artificially_oversized = page;
        artificially_oversized.text = "\0".repeat(MAX_RESPONSE_BYTES / 6);
        assert_eq!(
            check_response_size(&artificially_oversized, MAX_RESPONSE_BYTES).unwrap_err(),
            Refusal::ResourceExhausted
        );
    }

    #[test]
    fn production_codec_reuses_one_process_origin_and_keys() {
        let codec = Codec::process();
        assert!(std::ptr::eq(codec, Codec::process()));
        let ctx = binding();
        let guard = crate::mcp::tools::lifecycle::body_digest(Some("body"));
        let page = codec
            .prepare(&ctx, first(4))
            .unwrap()
            .page(Snapshot {
                body: Some("body"),
                event_id: "event-a",
                body_digest: &guard,
            })
            .unwrap();
        assert!(page.complete);
    }

    #[test]
    fn crypto_keys_are_independent_and_large_unescaped_payload_fits() {
        let original = codec(12);
        let ctx = binding();
        let page = form(&original, &ctx, first(4), Some("abcdefgh"), "event-a", 0).unwrap();
        let mut changed_revision_key = codec(12);
        changed_revision_key.revision_key = [99; 32];
        // Cursor authentication succeeds under the unchanged cursor key,
        // but constant-time pair verification under the new HMAC key refuses.
        assert!(changed_revision_key
            .open(&ctx, page.next_cursor.as_ref().unwrap())
            .is_ok());
        assert!(matches!(
            changed_revision_key.prepare_at(&ctx, next(&page), 0),
            Err(Refusal::InvalidCursor)
        ));
        let mut changed_cursor_key = codec(12);
        changed_cursor_key.cursor_cipher = XChaCha20Poly1305::new((&[99; 32]).into());
        assert_eq!(
            changed_cursor_key.revision(&ctx, "event-a").unwrap(),
            page.revision
        );
        assert!(matches!(
            changed_cursor_key.prepare_at(&ctx, next(&page), 0),
            Err(Refusal::InvalidCursor)
        ));
        let large = CursorPayload {
            version: 1,
            event: "e".repeat(128),
            position: JS_SAFE - 1,
            total: JS_SAFE,
            body_present: true,
            body_digest: "f".repeat(64),
            page_bytes: MAX_PAGE_BYTES,
            expires_ms: JS_SAFE,
        };
        let token = original.seal(&ctx, &large).unwrap();
        assert!(token.is_ascii() && token.len() <= MAX_TOKEN_BYTES);
        assert_eq!(original.open(&ctx, &token).unwrap().position, JS_SAFE - 1);
        // Abstract identity bounds do not promise that every combination fits
        // the encoded cursor budget. Worst-case event escaping refuses intact.
        for event in ["\"".repeat(128), "\\".repeat(128)] {
            let escaped = CursorPayload {
                event,
                ..CursorPayload {
                    version: large.version,
                    event: String::new(),
                    position: large.position,
                    total: large.total,
                    body_present: large.body_present,
                    body_digest: large.body_digest.clone(),
                    page_bytes: large.page_bytes,
                    expires_ms: large.expires_ms,
                }
            };
            assert!(escaped.validate().is_ok());
            assert!(serde_json::to_vec(&escaped).unwrap().len() > MAX_PLAINTEXT_BYTES);
            assert_eq!(
                original.seal(&ctx, &escaped).unwrap_err(),
                Refusal::ResourceExhausted
            );
        }
        for hostile in ["", "0", "g", &"0".repeat(81), &"0".repeat(1025)] {
            assert_eq!(
                original.open(&ctx, hostile).unwrap_err(),
                Refusal::InvalidCursor
            );
        }
    }

    #[test]
    fn raw_requests_refuse_positional_arrays_duplicates_and_each_optional_null() {
        let codec = codec(13);
        let ctx = binding();
        let page = form(&codec, &ctx, first(4), Some("abcdefgh"), "event-a", 0).unwrap();
        for positional in [
            json!([]),
            json!(["document-a", 4]),
            json!(["document-a", 4, page.revision, page.next_cursor]),
        ] {
            let bytes = format!(" \t\r\n{}", positional).into_bytes();
            assert_eq!(Request::parse(&bytes).unwrap_err(), Refusal::InvalidParams);
        }
        for bytes in [
            br#"{"record_id":"document-a","page_bytes":4,"page_bytes":4}"#.as_slice(),
            br#"{"record_id":"document-a","revision":"r","revision":"r","cursor":"c"}"#.as_slice(),
            br#"{"record_id":"document-a","revision":"r","cursor":"c","cursor":"c"}"#.as_slice(),
            br#"{"record_id":"document-a","page_bytes":null}"#.as_slice(),
            br#"{"record_id":"document-a","revision":null,"cursor":"c"}"#.as_slice(),
            br#"{"record_id":"document-a","revision":"r","cursor":null}"#.as_slice(),
        ] {
            assert_eq!(Request::parse(bytes).unwrap_err(), Refusal::InvalidParams);
        }
        assert!(Request::parse(b" \t\r\n{\"record_id\":\"document-a\"}").is_ok());
        assert_eq!(
            Request::parse(b"\x0b{\"record_id\":\"document-a\"}").unwrap_err(),
            Refusal::InvalidParams
        );
        assert_eq!(
            Request::parse(b" \t\r\n").unwrap_err(),
            Refusal::InvalidParams
        );
    }

    #[test]
    fn authenticated_raw_payloads_refuse_arrays_and_each_required_null_or_duplicate() {
        let codec = codec(14);
        let ctx = binding();
        let page = form(&codec, &ctx, first(4), Some("abcdefgh"), "event-a", 0).unwrap();
        let base = payload_value(&codec, &ctx, &page);
        let positional = json!([1, "event-a", 4, 8, true, page.body_digest, 4, LIFETIME_MS]);
        let bytes = format!(" \t\r\n{}", positional).into_bytes();
        let token = raw_seal_bytes(&codec, &ctx, &bytes);
        let req =
            request(json!({"record_id":"document-a","revision":page.revision,"cursor":token}));
        assert!(matches!(
            codec.prepare_at(&ctx, req, 0),
            Err(Refusal::InvalidCursor)
        ));
        let base_bytes = serde_json::to_string(&base).unwrap();
        for (key, value) in base.as_object().unwrap() {
            let duplicate = format!(
                "{{{}:{},{}",
                serde_json::to_string(key).unwrap(),
                value,
                &base_bytes[1..]
            );
            let token = raw_seal_bytes(&codec, &ctx, duplicate.as_bytes());
            assert_eq!(
                codec.open(&ctx, &token).unwrap_err(),
                Refusal::InvalidCursor,
                "duplicate {key}"
            );
            let mut null = base.clone();
            null[key] = Value::Null;
            assert_eq!(
                codec
                    .open(&ctx, &raw_seal(&codec, &ctx, &null))
                    .unwrap_err(),
                Refusal::InvalidCursor,
                "null {key}"
            );
        }
        let object_with_whitespace = format!(" \t\r\n{base_bytes}");
        assert!(codec
            .open(
                &ctx,
                &raw_seal_bytes(&codec, &ctx, object_with_whitespace.as_bytes())
            )
            .is_ok());
        assert_eq!(
            codec
                .open(&ctx, &raw_seal_bytes(&codec, &ctx, b"[]"))
                .unwrap_err(),
            Refusal::InvalidCursor
        );
    }
}
