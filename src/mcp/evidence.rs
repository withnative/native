//! Transient binary evidence carried beside a tool's structured result.
//!
//! Evidence is deliberately transport-neutral and non-authoritative. MCP can
//! put image bytes directly in content blocks, while the plain JSON adapter
//! deposits the same bytes in [`EvidenceStore`] and returns short-lived,
//! authenticated handles. Nothing in this module knows about SQLite, events,
//! snapshots, backup, or export.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Structured handler data plus binary evidence that must never be persisted.
#[derive(Debug)]
pub struct ToolResult {
    pub structured: Value,
    pub evidence: Vec<TransientEvidence>,
    pub(crate) interaction_context: Option<Value>,
}

impl ToolResult {
    pub fn rich(structured: Value, evidence: Vec<TransientEvidence>) -> Self {
        Self {
            structured,
            evidence,
            interaction_context: None,
        }
    }

    /// Attach extractor-only record identities without exposing them in the
    /// transport result. This is for rich read tools whose public report must
    /// omit the underlying records while the involuntary interaction log still
    /// records exactly which records were read.
    pub fn rich_with_interactions(
        structured: Value,
        evidence: Vec<TransientEvidence>,
        interaction_context: Value,
    ) -> Self {
        Self {
            structured,
            evidence,
            interaction_context: Some(interaction_context),
        }
    }
}

impl From<Value> for ToolResult {
    fn from(structured: Value) -> Self {
        Self {
            structured,
            evidence: Vec::new(),
            interaction_context: None,
        }
    }
}

/// The semantic type of transient evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Image,
    Document,
}

impl EvidenceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Document => "document",
        }
    }
}

/// One transport-neutral binary item.
///
/// `handle` is a result-local, non-secret correlation name (for example,
/// `viewport-1440x900`). The store generates the actual unguessable bearer
/// token; handlers never mint or observe it.
#[derive(Debug)]
pub struct TransientEvidence {
    pub handle: String,
    pub kind: EvidenceKind,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl TransientEvidence {
    pub fn image(
        handle: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        let evidence = Self {
            handle: handle.into(),
            kind: EvidenceKind::Image,
            media_type: media_type.into(),
            bytes: bytes.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn pdf(handle: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let evidence = Self {
            handle: handle.into(),
            kind: EvidenceKind::Document,
            media_type: "application/pdf".into(),
            bytes: bytes.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<()> {
        if self.handle.is_empty()
            || self.handle.len() > 128
            || !self
                .handle
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(Error::engine(
                "transient evidence handle must be 1-128 URL-safe characters",
            ));
        }
        let valid_media = match self.kind {
            EvidenceKind::Image => matches!(
                self.media_type.as_str(),
                "image/png" | "image/jpeg" | "image/webp" | "image/avif"
            ),
            EvidenceKind::Document => self.media_type == "application/pdf",
        };
        if !valid_media {
            return Err(Error::engine(
                "transient evidence has an unsupported media type",
            ));
        }
        Ok(())
    }

    pub(crate) fn mcp_content_block(&self) -> Value {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.bytes);
        match self.kind {
            EvidenceKind::Image => json!({
                "type": "image",
                "data": encoded,
                "mimeType": self.media_type,
            }),
            EvidenceKind::Document => json!({
                "type": "resource",
                "resource": {
                    "uri": format!("native-evidence://transient/{}", self.handle),
                    "mimeType": self.media_type,
                    "blob": encoded,
                },
            }),
        }
    }

    pub(crate) fn metadata(&self) -> Value {
        json!({
            "handle": self.handle,
            "type": self.kind.as_str(),
            "media_type": self.media_type,
            "byte_size": self.bytes.len(),
            "sha256": hex::encode(Sha256::digest(&self.bytes)),
        })
    }
}

/// Resource limits for the transient in-process store.
#[derive(Clone, Copy, Debug)]
pub struct EvidenceStoreOptions {
    pub ttl: Duration,
    pub max_count: usize,
    pub max_bytes: usize,
}

impl Default for EvidenceStoreOptions {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(60),
            max_count: 64,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
struct StoredEvidence {
    principal: String,
    database: String,
    evidence: TransientEvidence,
    expires_at: Instant,
}

#[derive(Default)]
struct StoreState {
    entries: HashMap<String, StoredEvidence>,
    oldest: VecDeque<String>,
    bytes: usize,
}

/// Bounded, process-local, one-use evidence storage.
pub struct EvidenceStore {
    options: EvidenceStoreOptions,
    state: Mutex<StoreState>,
}

impl EvidenceStore {
    pub fn new(options: EvidenceStoreOptions) -> Self {
        Self {
            options,
            state: Mutex::new(StoreState::default()),
        }
    }

    /// Atomically deposit a result's evidence and return public metadata.
    ///
    /// Older entries are evicted first. A batch that cannot fit by itself is
    /// rejected before any token is minted, so callers never receive a partial
    /// set of handles.
    pub fn deposit(
        &self,
        principal: &str,
        database: &str,
        evidence: Vec<TransientEvidence>,
        public_origin: Option<&str>,
    ) -> Result<Vec<Value>> {
        let batch_bytes = evidence.iter().try_fold(0usize, |total, item| {
            item.validate()?;
            total
                .checked_add(item.bytes.len())
                .ok_or_else(|| Error::engine("transient evidence batch is too large"))
        })?;
        if evidence.len() > self.options.max_count || batch_bytes > self.options.max_bytes {
            return Err(Error::engine("transient evidence exceeds in-memory limits"));
        }
        let now = Instant::now();
        let mut state = self.state.lock().expect("evidence store poisoned");
        prune_expired(&mut state, now);
        while state.entries.len() + evidence.len() > self.options.max_count
            || state.bytes + batch_bytes > self.options.max_bytes
        {
            evict_oldest(&mut state);
        }

        let mut references = Vec::with_capacity(evidence.len());
        for item in evidence {
            let token = fresh_token(&state.entries);
            let url = evidence_url(public_origin, database, &token);
            let digest = hex::encode(Sha256::digest(&item.bytes));
            references.push(json!({
                "handle": item.handle,
                "type": item.kind.as_str(),
                "media_type": item.media_type,
                "byte_size": item.bytes.len(),
                "sha256": digest,
                "url": url,
                "expires_in_ms": self.options.ttl.as_millis(),
                "one_use": true,
            }));
            state.bytes += item.bytes.len();
            state.oldest.push_back(token.clone());
            state.entries.insert(
                token,
                StoredEvidence {
                    principal: principal.to_string(),
                    database: database.to_string(),
                    evidence: item,
                    expires_at: now + self.options.ttl,
                },
            );
        }
        Ok(references)
    }

    /// Consume evidence only when both authenticated bindings match.
    ///
    /// A mismatched lookup is indistinguishable from an unknown token and does
    /// not consume the rightful caller's item.
    pub fn take(&self, principal: &str, database: &str, token: &str) -> Option<TransientEvidence> {
        let mut state = self.state.lock().expect("evidence store poisoned");
        prune_expired(&mut state, Instant::now());
        let entry = state.entries.get(token)?;
        if entry.principal != principal || entry.database != database {
            return None;
        }
        let entry = state.entries.remove(token)?;
        state.bytes = state.bytes.saturating_sub(entry.evidence.bytes.len());
        if let Some(position) = state.oldest.iter().position(|queued| queued == token) {
            state.oldest.remove(position);
        }
        Some(entry.evidence)
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (state.entries.len(), state.bytes)
    }

    #[cfg(test)]
    fn queue_len(&self) -> usize {
        self.state.lock().unwrap().oldest.len()
    }
}

fn fresh_token(entries: &HashMap<String, StoredEvidence>) -> String {
    loop {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        if !entries.contains_key(&token) {
            return token;
        }
    }
}

fn evidence_url(public_origin: Option<&str>, database: &str, token: &str) -> String {
    let path = format!("/databases/{database}/tool-evidence/{token}");
    public_origin
        .map(|origin| format!("{}{path}", origin.trim_end_matches('/')))
        .unwrap_or(path)
}

fn prune_expired(state: &mut StoreState, now: Instant) {
    while let Some(token) = state.oldest.front() {
        let expired_or_gone = state
            .entries
            .get(token)
            .is_none_or(|entry| entry.expires_at <= now);
        if !expired_or_gone {
            break;
        }
        let token = state.oldest.pop_front().expect("front exists");
        if let Some(entry) = state.entries.remove(&token) {
            state.bytes = state.bytes.saturating_sub(entry.evidence.bytes.len());
        }
    }
}

fn evict_oldest(state: &mut StoreState) {
    while let Some(token) = state.oldest.pop_front() {
        if let Some(entry) = state.entries.remove(&token) {
            state.bytes = state.bytes.saturating_sub(entry.evidence.bytes.len());
            return;
        }
    }
}

/// Attach plain-route evidence references without losing non-object results.
pub(crate) fn attach_references(result: Value, references: Vec<Value>) -> Value {
    if references.is_empty() {
        return result;
    }
    match result {
        Value::Object(mut object) => {
            object.insert("transient_evidence".into(), Value::Array(references));
            Value::Object(object)
        }
        value => json!({
            "value": value,
            "transient_evidence": references,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(handle: &str, bytes: &[u8]) -> TransientEvidence {
        TransientEvidence::image(handle, "image/png", bytes).unwrap()
    }

    #[test]
    fn store_is_principal_database_bound_and_one_use() {
        let store = EvidenceStore::new(EvidenceStoreOptions::default());
        let refs = store
            .deposit("alice", "db-a", vec![image("shot", b"pixels")], None)
            .unwrap();
        let url = refs[0]["url"].as_str().unwrap();
        let token = url.rsplit('/').next().unwrap();

        assert!(store.take("mallory", "db-a", token).is_none());
        assert!(store.take("alice", "db-b", token).is_none());
        assert_eq!(store.take("alice", "db-a", token).unwrap().bytes, b"pixels");
        assert!(store.take("alice", "db-a", token).is_none());
        assert_eq!(store.queue_len(), 0);
    }

    #[test]
    fn consuming_live_entries_keeps_the_eviction_queue_bounded() {
        let store = EvidenceStore::new(EvidenceStoreOptions {
            ttl: Duration::from_secs(60),
            max_count: 2,
            max_bytes: 32,
        });
        for index in 0..100 {
            let refs = store
                .deposit("p", "d", vec![image(&format!("shot-{index}"), b"x")], None)
                .unwrap();
            let token = refs[0]["url"].as_str().unwrap().rsplit('/').next().unwrap();
            assert!(store.take("p", "d", token).is_some());
        }
        assert_eq!(store.counts(), (0, 0));
        assert_eq!(store.queue_len(), 0);
    }

    #[test]
    fn store_evicts_by_count_bytes_and_ttl() {
        let store = EvidenceStore::new(EvidenceStoreOptions {
            ttl: Duration::from_millis(5),
            max_count: 2,
            max_bytes: 6,
        });
        let first = store
            .deposit("p", "d", vec![image("one", b"111")], None)
            .unwrap();
        let first_token = first[0]["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        let second = store
            .deposit("p", "d", vec![image("two", b"2222")], None)
            .unwrap();
        assert!(store.take("p", "d", first_token).is_none());
        assert_eq!(store.counts(), (1, 4));

        let second_token = second[0]["url"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(store.take("p", "d", second_token).is_none());
        assert_eq!(store.counts(), (0, 0));
    }

    #[test]
    fn oversized_batch_is_atomic_and_metadata_has_no_bytes() {
        let store = EvidenceStore::new(EvidenceStoreOptions {
            ttl: Duration::from_secs(1),
            max_count: 2,
            max_bytes: 3,
        });
        assert!(store
            .deposit("p", "d", vec![image("too-big", b"1234")], None)
            .is_err());
        assert_eq!(store.counts(), (0, 0));

        let refs = store
            .deposit(
                "p",
                "d",
                vec![image("ok", b"123")],
                Some("https://native.test"),
            )
            .unwrap();
        let serialized = refs[0].to_string();
        assert!(!serialized.contains("MTIz"));
        assert!(serialized.contains("https://native.test/databases/d/tool-evidence/"));
    }

    #[test]
    fn mcp_content_blocks_carry_typed_image_and_pdf_bytes() {
        let block = image("shot", b"pixels").mcp_content_block();
        assert_eq!(block["type"], "image");
        assert_eq!(block["mimeType"], "image/png");
        assert_eq!(block["data"], "cGl4ZWxz");

        let block = TransientEvidence::pdf("print", b"%PDF-1.7")
            .unwrap()
            .mcp_content_block();
        assert_eq!(block["type"], "resource");
        assert_eq!(
            block["resource"]["uri"],
            "native-evidence://transient/print"
        );
        assert_eq!(block["resource"]["mimeType"], "application/pdf");
        assert_eq!(block["resource"]["blob"], "JVBERi0xLjc=");
    }
}
