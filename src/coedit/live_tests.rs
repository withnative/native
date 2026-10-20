//! In-process tests for the live-session service: real database, real tool
//! registry, `yrs` docs playing the clients.

use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::broadcast;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Doc, GetString, OffsetKind, Options, ReadTxn, StateVector, Text, Transact, Update};

use super::live::{self, AuthorKind, CloseReason, OpenRequest, SessionEvent, SessionPeer};
use super::{PeerKind, RefusalCode};
use crate::authorization::{AllowEntry, Capability};
use crate::control::{
    alpha_tab_aggregate_id, alpha_tab_pin_digest, append_control_event, AlphaTabAdoptPayload,
    AlphaTabAdoptionProvenance, AlphaTabStatePayload, AlphaTabUpdatePayload, ControlEventPayload,
    NewControlEvent, ALPHA_TAB_ADOPTION_CALLER_ASSERTED, ALPHA_TAB_ADOPTION_VERIFIED,
};
use crate::mcp::app_attribution::AppAttribution;
use crate::mcp::tools::lifecycle::body_digest;
use crate::mcp::{Caller, ToolRegistry};
use crate::Db;

const ALICE: &str = "acct:alice";
const BOB: &str = "acct:bob";
const AGENT: &str = "acct:agent";

struct Fixture {
    _directory: tempfile::TempDir,
    db: Db,
    tools: ToolRegistry,
    id: String,
}

impl Fixture {
    async fn new(body: &str) -> Self {
        Self::with_body(Some(body)).await
    }

    async fn with_body(body: Option<&str>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("live.sqlite");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        let mut tools = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut tools).unwrap();
        let mut args = json!({"type": "Document", "kind": "note", "name": "live doc",
                              "reason": "live session fixture"});
        if let Some(body) = body {
            args["body"] = json!(body);
        }
        let created = tools
            .call(db.clone(), Caller::local(), "create_record", args)
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        let fixture = Self {
            _directory: directory,
            db,
            tools,
            id,
        };
        fixture.grant(&[ALICE, BOB, AGENT]).await;
        fixture
    }

    async fn grant(&self, accounts: &[&str]) {
        crate::authorization::replace_explicit_policy(
            &self.db,
            "test:live-session",
            &self.id,
            accounts
                .iter()
                .map(|account| AllowEntry::account(*account, Capability::Edit))
                .collect(),
        )
        .await
        .unwrap();
    }

    async fn open(&self, account: &str) -> (SessionPeer, Client) {
        self.open_with(account, PeerKind::Edit, None, None).await
    }

    async fn open_with(
        &self,
        account: &str,
        mode: PeerKind,
        app: Option<AppAttribution>,
        resume_peer: Option<super::PeerId>,
    ) -> (SessionPeer, Client) {
        let caller = Caller::authenticated(account);
        let caller = match app {
            Some(app) => caller.with_host_asserted_app(app),
            None => caller,
        };
        let (peer, opened) = live::open(
            &self.db,
            &caller,
            OpenRequest {
                record_id: self.id.clone(),
                mode,
                resume_peer,
            },
        )
        .await
        .unwrap();
        let client_id = opened.doc_client_ids.first().copied().unwrap_or(1);
        (peer, Client::new(client_id, &opened.sync))
    }

    /// As `open_with`, keeping the `Opened` (its `base` is under test).
    async fn open_full(
        &self,
        account: &str,
        mode: PeerKind,
    ) -> (SessionPeer, Client, live::Opened) {
        let (peer, opened) = live::open(
            &self.db,
            &Caller::authenticated(account),
            OpenRequest {
                record_id: self.id.clone(),
                mode,
                resume_peer: None,
            },
        )
        .await
        .unwrap();
        let client_id = opened.doc_client_ids.first().copied().unwrap_or(1);
        let client = Client::new(client_id, &opened.sync);
        (peer, client, opened)
    }

    /// The record's latest body-carrying event, by the shared SQL.
    async fn body_event(&self) -> Option<String> {
        sqlx::query_scalar::<_, String>(&format!(
            "SELECT id FROM content_events WHERE record_id = ? AND ({}) ORDER BY seq DESC LIMIT 1",
            crate::record_body::BODY_CARRYING_EVENT_SQL
        ))
        .bind(&self.id)
        .fetch_optional(self.db.pool())
        .await
        .unwrap()
    }

    /// The sequence of the record's latest body-carrying event.
    async fn body_event_seq(&self) -> Option<i64> {
        sqlx::query_scalar::<_, i64>(&format!(
            "SELECT seq FROM content_events WHERE record_id = ? AND ({}) ORDER BY seq DESC LIMIT 1",
            crate::record_body::BODY_CARRYING_EVENT_SQL
        ))
        .bind(&self.id)
        .fetch_optional(self.db.pool())
        .await
        .unwrap()
    }

    /// The record's latest event of any kind.
    async fn latest_event(&self) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
        )
        .bind(&self.id)
        .fetch_one(self.db.pool())
        .await
        .unwrap()
    }

    async fn update(&self, account: &str, arguments: Value) -> crate::Result<Value> {
        self.tools
            .call(
                self.db.clone(),
                Caller::authenticated(account),
                "update_record",
                arguments,
            )
            .await
    }

    async fn get(&self, account: &str) -> Value {
        let got = self
            .tools
            .call(
                self.db.clone(),
                Caller::authenticated(account),
                "get_record",
                json!({"ids": [self.id]}),
            )
            .await
            .unwrap();
        got.get("records")
            .and_then(|records| records.get(0))
            .cloned()
            .unwrap_or(got)
    }

    async fn committed(&self) -> String {
        sqlx::query_scalar::<_, Option<String>>("SELECT body FROM records WHERE id = ?")
            .bind(&self.id)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
            .unwrap_or_default()
    }

    /// A real adopted v2 install of `package` for `account`, made through the
    /// control-event ledger exactly as `manage_alpha_tabs` records one.
    /// Returns the app a host would assert: the adopted install generation.
    async fn install_app(&self, account: &str, package: &str) -> AppAttribution {
        let pin = self.app_pin(
            account,
            package,
            "1.0.0",
            ALPHA_TAB_ADOPTION_CALLER_ASSERTED,
        );
        let installed = self
            .append_alpha(
                account,
                package,
                ControlEventPayload::AlphaTabInstalled(pin.clone()),
            )
            .await;
        let adopted = self.adopt_app(&pin, installed).await;
        AppAttribution::new(package, "1.0.0", adopted).unwrap()
    }

    /// The account updates the app to `version` (the same consented
    /// declaration, so the adoption carries over, as the shell's update does):
    /// a new install generation. The old `install_event_id` the host launched
    /// a frame with is now stale.
    async fn update_app(
        &self,
        account: &str,
        old: &AppAttribution,
        version: &str,
    ) -> AppAttribution {
        let current = self.app_pin(
            account,
            &old.package,
            &old.version,
            ALPHA_TAB_ADOPTION_VERIFIED,
        );
        let next = self.app_pin(account, &old.package, version, ALPHA_TAB_ADOPTION_VERIFIED);
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT adoption_provenance FROM alpha_tab_installs WHERE account_id = ? AND package = ?",
        )
        .bind(account)
        .bind(&old.package)
        .fetch_one(self.db.pool())
        .await
        .unwrap();
        let mut provenance: AlphaTabAdoptionProvenance =
            serde_json::from_str(&stored.expect("an adopted install has provenance")).unwrap();
        provenance.carried_from_event_id = Some(old.install_event_id.clone());
        let updated = self
            .append_alpha(
                account,
                &old.package,
                ControlEventPayload::AlphaTabUpdated(Box::new(AlphaTabUpdatePayload {
                    account_id: next.account_id.clone(),
                    package: next.package.clone(),
                    version: next.version.clone(),
                    digest: next.digest.clone(),
                    artifact_id: next.artifact_id.clone(),
                    consented_source_revision: next.consented_source_revision.clone(),
                    declaration_digest: next.declaration_digest.clone(),
                    consented_declaration: next.consented_declaration.clone(),
                    previous_event_id: old.install_event_id.clone(),
                    previous_pin_digest: alpha_tab_pin_digest(&current).unwrap(),
                    status: "installed".into(),
                    request: None,
                    command_digest: "d".repeat(64),
                    adoption: ALPHA_TAB_ADOPTION_VERIFIED.into(),
                    adoption_basis: "carried".into(),
                    adoption_provenance: Some(provenance),
                })),
            )
            .await;
        AppAttribution::new(old.package.clone(), version, updated).unwrap()
    }

    fn app_pin(
        &self,
        account: &str,
        package: &str,
        version: &str,
        adoption: &str,
    ) -> AlphaTabStatePayload {
        let declaration = json!({"contract": "native.app.v2", "needs": [], "effects": []});
        AlphaTabStatePayload {
            account_id: account.into(),
            package: package.into(),
            version: version.into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            artifact_id: self.id.clone(),
            consented_source_revision: "source-1".into(),
            declaration_digest: crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(
                &declaration,
            )
            .unwrap(),
            consented_declaration: declaration,
            adoption: adoption.into(),
            request: None,
            previous_event_id: None,
        }
    }

    async fn append_alpha(
        &self,
        account: &str,
        package: &str,
        payload: ControlEventPayload,
    ) -> String {
        append_control_event(
            &self.db,
            NewControlEvent::authored(
                uuid::Uuid::new_v4().to_string(),
                alpha_tab_aggregate_id(account, package),
                account,
                None,
                "live app attribution fixture",
                payload,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .id
    }

    async fn adopt_app(&self, pin: &AlphaTabStatePayload, previous: String) -> String {
        self.append_alpha(
            &pin.account_id,
            &pin.package,
            ControlEventPayload::AlphaTabAdopted(AlphaTabAdoptPayload {
                account_id: pin.account_id.clone(),
                package: pin.package.clone(),
                version: pin.version.clone(),
                digest: pin.digest.clone(),
                artifact_id: pin.artifact_id.clone(),
                consented_source_revision: pin.consented_source_revision.clone(),
                declaration_digest: pin.declaration_digest.clone(),
                consented_declaration: pin.consented_declaration.clone(),
                adoption: ALPHA_TAB_ADOPTION_VERIFIED.into(),
                previous_event_id: previous,
                receipt_id: Some("receipt".into()),
                preview_session: Some("session".into()),
                launch_id: None,
                authored_run_key: None,
                request: None,
            }),
        )
        .await
    }

    /// The `provenance_action_app_attributions` rows for the content events
    /// of this fixture's record: `(package, version, install, assertion)`,
    /// oldest event first.
    async fn app_rows(&self) -> Vec<(String, String, String, String)> {
        sqlx::query_as(
            "SELECT a.package, a.version, a.install_event_id, a.assertion
               FROM provenance_action_app_attributions a
               JOIN provenance_action_outputs o
                 ON o.action_attestation_id = a.action_attestation_id
               JOIN content_events e
                 ON e.id = o.output_event_id AND o.output_domain = 'content'
              WHERE e.record_id = ?
              ORDER BY e.seq",
        )
        .bind(&self.id)
        .fetch_all(self.db.pool())
        .await
        .unwrap()
    }

    /// The `record.updated` payloads written for this record, oldest first.
    async fn versions(&self) -> Vec<Value> {
        let payloads: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT payload FROM content_events WHERE record_id = ? AND type = 'record.updated' ORDER BY seq",
        )
        .bind(&self.id)
        .fetch_all(self.db.pool())
        .await
        .unwrap();
        payloads
            .into_iter()
            .flatten()
            .map(|p| serde_json::from_str(&p).unwrap())
            .filter(|p: &Value| p.get("session").is_some())
            .collect()
    }
}

/// A test client doc authoring with one leased client id.
struct Client {
    doc: Doc,
}

impl Client {
    fn new(client_id: u32, sync: &[u8]) -> Self {
        let mut options = Options::with_client_id(yrs::ClientID::new(u64::from(client_id)));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        doc.get_or_insert_text("body");
        doc.transact_mut()
            .apply_update(Update::decode_v1(sync).unwrap())
            .unwrap();
        Self { doc }
    }

    fn body(&self) -> String {
        let text = self.doc.get_or_insert_text("body");
        let txn = self.doc.transact();
        text.get_string(&txn)
    }

    /// Insert at a byte offset; returns the update bytes to send.
    fn insert(&self, at: u32, chunk: &str) -> Vec<u8> {
        let before = self.doc.transact().state_vector();
        let text = self.doc.get_or_insert_text("body");
        text.insert(&mut self.doc.transact_mut(), at, chunk);
        self.doc.transact().encode_diff_v1(&before)
    }

    fn append(&self, chunk: &str) -> Vec<u8> {
        let len = self.body().len() as u32;
        self.insert(len, chunk)
    }

    fn receive(&self, update: &[u8]) {
        self.doc
            .transact_mut()
            .apply_update(Update::decode_v1(update).unwrap())
            .unwrap();
    }
}

/// Drain everything currently queued on a subscription.
fn drain(rx: &mut broadcast::Receiver<SessionEvent>) -> Vec<SessionEvent> {
    let mut out = Vec::new();
    while let Ok(event) = rx.try_recv() {
        out.push(event);
    }
    out
}

/// Apply every remote update not authored by `me` to `client`.
fn deliver(client: &Client, me: &SessionPeer, events: &[SessionEvent]) {
    for event in events {
        if let SessionEvent::Remote { update, origin, .. } = event {
            if origin.as_ref() != Some(me.peer()) {
                client.receive(update);
            }
        }
    }
}

/// Wait for the first event matching `pick` (bounded real time, generous so
/// a loaded CI host cannot time it out).
async fn wait_for<T>(
    rx: &mut broadcast::Receiver<SessionEvent>,
    mut pick: impl FnMut(&SessionEvent) -> Option<T>,
) -> T {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(60), rx.recv())
            .await
            .expect("event within 60 s")
            .unwrap();
        if let Some(found) = pick(&event) {
            return found;
        }
    }
}

fn versioned(events: &[SessionEvent]) -> Vec<&super::live::Versioned> {
    events
        .iter()
        .filter_map(|event| match event {
            SessionEvent::Versioned(v) => Some(v),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn two_peers_converge() {
    let fx = Fixture::new("Hello world").await;
    let (alice, a) = fx.open(ALICE).await;
    let (bob, b) = fx.open(BOB).await;
    assert_eq!(alice.session(), bob.session());
    let mut a_rx = alice.subscribe();
    let mut b_rx = bob.subscribe();

    // Concurrent edits from the same base.
    let ua = a.insert(0, "Alice: ");
    let ub = b.append("!");
    alice.apply("a1", &ua).await.unwrap();
    bob.apply("b1", &ub).await.unwrap();

    deliver(&a, &alice, &drain(&mut a_rx));
    deliver(&b, &bob, &drain(&mut b_rx));
    assert_eq!(a.body(), "Alice: Hello world!");
    assert_eq!(a.body(), b.body());

    // A fresh full sync matches too, and get_record shows the live pair.
    let synced = Client::new(1, &bob.sync(&[]).await.unwrap());
    assert_eq!(synced.body(), a.body());
    let record = fx.get(ALICE).await;
    assert_eq!(record["body"], json!("Alice: Hello world!"));
    assert_eq!(record["body_state"], json!("live"));
    assert_eq!(
        record["body_digest"],
        json!(body_digest(Some("Alice: Hello world!")))
    );
    assert_eq!(
        record["committed_body_digest"],
        json!(body_digest(Some("Hello world")))
    );
    // Nothing is committed while people type.
    assert_eq!(fx.committed().await, "Hello world");
    alice.leave().await;
    bob.leave().await;
}

#[tokio::test]
async fn mcp_body_replace_arrives_live_after_the_peers_text_is_saved_on_its_own() {
    let fx = Fixture::new("Intro\n\nMiddle paragraph\n\nOutro\n").await;
    let (alice, a) = fx.open(ALICE).await;
    let (bob, b) = fx.open(BOB).await;
    let mut a_rx = alice.subscribe();
    let mut b_rx = bob.subscribe();
    alice.apply("a1", &a.insert(0, "# ")).await.unwrap();
    bob.apply("b1", &b.append("Signed, Bob\n")).await.unwrap();
    deliver(&a, &alice, &drain(&mut a_rx));
    deliver(&b, &bob, &drain(&mut b_rx));

    // The agent reads the live body and replaces a span in it.
    let read = fx.get(AGENT).await;
    assert_eq!(read["body_state"], json!("live"));
    let updated = fx
        .update(
            AGENT,
            json!({"id": fx.id, "reason": "agent tightens the middle",
                   "body_replace": [{"old": "Middle paragraph", "new": "Middle, tightened"}],
                   "if_body_digest": read["body_digest"]}),
        )
        .await
        .unwrap();
    let expected = "# Intro\n\nMiddle, tightened\n\nOutro\nSigned, Bob\n";
    assert_eq!(updated["body_digest"], json!(body_digest(Some(expected))));

    for (client, peer, rx) in [(&a, &alice, &mut a_rx), (&b, &bob, &mut b_rx)] {
        let events = drain(rx);
        let remote = events.iter().find_map(|event| match event {
            SessionEvent::Remote {
                origin: None, from, ..
            } => Some(from.clone()),
            _ => None,
        });
        let from = remote.expect("routed write is broadcast");
        assert_eq!(from.contributor.principal, AGENT);
        // An authenticated principal without a verified agent executor is
        // reported as a person.
        assert_eq!(from.kind, AuthorKind::Human);
        deliver(client, peer, &events);
        assert_eq!(client.body(), expected);
        // The peers' unsaved text is versioned on its own first; the agent's
        // version holds only the agent's change.
        let versions = versioned(&events);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].reason, "saved before a routed write");
        let principals: Vec<_> = versions[0]
            .contributors
            .iter()
            .map(|c| c.principal.as_str())
            .collect();
        assert_eq!(principals, vec![ALICE, BOB]);
        assert_eq!(versions[1].reason, "agent tightens the middle");
        let principals: Vec<_> = versions[1]
            .contributors
            .iter()
            .map(|c| c.principal.as_str())
            .collect();
        assert_eq!(principals, vec![AGENT]);
    }
    assert_eq!(fx.committed().await, expected);
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["contributors"].as_array().unwrap().len(), 2);
    assert_eq!(versions[0]["reason"], json!("saved before a routed write"));
    assert_eq!(versions[1]["contributors"].as_array().unwrap().len(), 1);
    assert_eq!(versions[1]["session"], json!(alice.session().0));
    assert_eq!(versions[1]["reason"], json!("agent tightens the middle"));

    // Peers keep editing on top of the routed write.
    alice.apply("a2", &a.append("PS\n")).await.unwrap();
    deliver(&b, &bob, &drain(&mut b_rx));
    assert_eq!(b.body(), format!("{expected}PS\n"));
    alice.leave().await;
    bob.leave().await;
}

#[tokio::test]
async fn routed_writes_set_and_append_against_live_text_and_keep_peer_edits() {
    let fx = Fixture::new("one\ntwo\nthree\n").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.apply("a1", &a.insert(0, "zero\n")).await.unwrap();
    // body_append lands after the live text, not the committed text.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "agent appends", "body_append": "four\n"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "zero\none\ntwo\nthree\nfour\n");
    // A whole-body write while live must name the live text it replaces.
    let refused = fx
        .update(
            AGENT,
            json!({"id": fx.id, "reason": "blind set", "body_set": "erased"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("live_session_changed"), "{refused}");
    assert!(refused.contains("retry with if_body_digest"), "{refused}");
    // With the live digest it applies as a diff; only changed lines move.
    let live = fx.get(AGENT).await["body_digest"].clone();
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "agent rewrites line two",
               "body_set": "zero\none\nTWO\nthree\nfour\n", "if_body_digest": live}),
    )
    .await
    .unwrap();
    deliver(&a, &alice, &drain(&mut rx));
    assert_eq!(a.body(), "zero\none\nTWO\nthree\nfour\n");
    // Non-body fields in the same call go through the ordinary path.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "rename and append", "name": "renamed",
               "body_append": "five\n"}),
    )
    .await
    .unwrap();
    let record = fx.get(ALICE).await;
    assert_eq!(record["name"], json!("renamed"));
    assert_eq!(record["body"], json!("zero\none\nTWO\nthree\nfour\nfive\n"));
    // Alice's unsaved "zero" was versioned on its own before the first routed
    // write; each of the three writes then made one version.
    assert_eq!(fx.versions().await.len(), 4);
    alice.leave().await;
}

#[tokio::test]
async fn digest_mismatch_against_live_body_is_refused() {
    let fx = Fixture::new("Base text").await;
    let committed_digest = body_digest(Some("Base text"));
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" typed live")).await.unwrap();
    // A digest of the committed body is stale against the live body.
    let error = fx
        .update(
            AGENT,
            json!({"id": fx.id, "reason": "stale agent", "body_set": "Replaced",
                   "if_body_digest": committed_digest}),
        )
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("live_session_changed"),
        "{error}"
    );
    let record = fx.get(ALICE).await;
    assert_eq!(record["body"], json!("Base text typed live"));
    // The refused write changed nothing, but a routed write is preceded by
    // saving the live text, so Alice's text is now its own version.
    assert_eq!(fx.committed().await, "Base text typed live");
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["reason"], json!("saved before a routed write"));
    alice.leave().await;
}

#[tokio::test]
async fn idle_cuts_a_version() {
    let fx = Fixture::new("Draft").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // The production idle period is `IDLE_VERSION_AFTER`; a short one keeps
    // this test fast (a paused tokio clock would trip sqlx pool timeouts).
    let idle = Duration::from_millis(300);
    alice.set_idle_after_for_test(idle);
    let started = tokio::time::Instant::now();
    alice.apply("a1", &a.append(" one")).await.unwrap();
    // Keep typing: the idle clock restarts on every op.
    tokio::time::sleep(idle / 2).await;
    alice.apply("a2", &a.append(" two🎉")).await.unwrap();
    let typed = tokio::time::Instant::now();
    let version = loop {
        match tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("idle version")
            .unwrap()
        {
            SessionEvent::Versioned(v) => break v,
            _ => continue,
        }
    };
    assert!(typed.elapsed() >= idle, "cut only after a full idle period");
    assert!(started.elapsed() >= idle + idle / 2);
    assert_eq!(version.reason, "idle");
    assert_eq!(version.contributors.len(), 1);
    assert_eq!(fx.committed().await, "Draft one two🎉");
    // Clean again: leaving cuts nothing more.
    assert!(alice.leave().await.is_none());
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1);
    let map = assert_span_map_tiles(&versions[0]);
    assert_eq!(map["spans"], json!([[0, 5, 0], [5, 17, 1]]));
    assert_eq!(span_author(map, 0)["type"], "prior_version");
    assert_eq!(span_author(map, 1)["principal"], json!(ALICE));
}

#[tokio::test]
async fn leaving_with_unsaved_edits_cuts_a_version() {
    let fx = Fixture::new("Notes").await;
    let (alice, a) = fx.open(ALICE).await;
    let (viewer, _) = fx.open_with(BOB, PeerKind::View, None, None).await;
    alice.apply("a1", &a.append(" and more")).await.unwrap();
    // The last editor leaving cuts, even with a viewer still attached.
    let version = alice.leave().await.expect("leave cuts a version");
    assert_eq!(version.reason, "session ended");
    assert_eq!(fx.committed().await, "Notes and more");
    viewer.leave().await;
}

#[tokio::test]
async fn dropped_peer_still_cuts_a_version() {
    let fx = Fixture::new("Crash").await;
    let (alice, a) = fx.open(ALICE).await;
    let (bob, _) = fx.open_with(BOB, PeerKind::View, None, None).await;
    let mut rx = bob.subscribe();
    alice.apply("a1", &a.append(" test")).await.unwrap();
    drop(alice);
    let version = loop {
        match tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("background leave versions")
            .unwrap()
        {
            SessionEvent::Versioned(v) => break v,
            _ => continue,
        }
    };
    assert_eq!(version.reason, "session ended");
    assert_eq!(fx.committed().await, "Crash test");
    bob.leave().await;
}

#[tokio::test]
async fn access_loss_closes_the_peer() {
    let fx = Fixture::new("Shared").await;
    let (alice, _) = fx.open(ALICE).await;
    let (bob, b) = fx.open(BOB).await;
    let mut rx = alice.subscribe();
    bob.apply("b1", &b.append(" by bob")).await.unwrap();
    assert!(bob
        .recheck_access(&Caller::authenticated(BOB))
        .await
        .is_ok());
    fx.grant(&[ALICE, AGENT]).await;
    let refused = bob
        .recheck_access(&Caller::authenticated(BOB))
        .await
        .unwrap_err();
    assert_eq!(refused.code, RefusalCode::AccessLost);
    assert!(drain(&mut rx).iter().any(|event| matches!(
        event,
        SessionEvent::Closed { peer: Some(p), reason: CloseReason::AccessLost } if p == bob.peer()
    )));
    let refused = bob.apply("b2", &b.append("!")).await.unwrap_err();
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
    // Bob's acknowledged edit stays, and he is still credited at the next cut.
    let version = alice.version("checkpoint").await.unwrap().unwrap();
    // The requester gets the broadcast too.
    assert_eq!(versioned(&drain(&mut rx)), vec![&version]);
    let principals: Vec<_> = version
        .contributors
        .iter()
        .map(|c| c.principal.as_str())
        .collect();
    assert_eq!(principals, vec![BOB]);
    assert_eq!(fx.committed().await, "Shared by bob");
    alice.leave().await;
}

#[tokio::test]
async fn resume_keeps_peer_and_client_ids_and_grace_keeps_the_doc() {
    let fx = Fixture::new("Resume").await;
    let (alice, opened_a) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    let a = Client::new(opened_a.doc_client_ids[0], &opened_a.sync);
    alice.apply("a1", &a.append(" me")).await.unwrap();

    // Another principal cannot resume Alice's peer.
    let (bob, opened_b) = live::open(
        &fx.db,
        &Caller::authenticated(BOB),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(opened_a.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(!opened_b.resumed);
    assert_ne!(opened_b.peer, opened_a.peer);

    // Alice reconnects while still attached: same peer and ids; the old
    // handle is superseded.
    let (alice2, reopened) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(opened_a.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(reopened.resumed);
    assert_eq!(reopened.peer, opened_a.peer);
    assert_eq!(reopened.doc_client_ids, opened_a.doc_client_ids);
    // A pending edit authored under the old ids is accepted after resume.
    alice2.apply("a2", &a.append(" again")).await.unwrap();
    assert_eq!(
        alice.apply("a3", &a.append("?")).await.unwrap_err().code,
        RefusalCode::UndeclaredSession
    );
    assert!(alice.leave().await.is_none());

    // Everyone leaves: version now, doc kept for the grace window.
    bob.leave().await;
    let version = alice2.leave().await.expect("last leave versions");
    assert_eq!(fx.committed().await, "Resume me again");
    assert_eq!(version.body_sha256, body_digest(Some("Resume me again")));
    let (alice3, again) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(opened_a.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(again.resumed, "the grace doc continues");
    assert_eq!(again.session, opened_a.session);
    alice3.leave().await;

    // During grace, an ordinary write goes to the committed path and
    // discards the doc; the next open seeds a new session from it.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "plain write", "body_append": "."}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "Resume me again.");
    let (alice4, fresh) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(opened_a.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(!fresh.resumed);
    assert_ne!(fresh.session, opened_a.session);
    assert_eq!(Client::new(1, &fresh.sync).body(), "Resume me again.");
    alice4.leave().await;
}

#[tokio::test]
async fn app_attribution_is_credited_in_versions_and_provenance() {
    let fx = Fixture::new("App").await;
    let app = fx.install_app(ALICE, "docs").await;
    let install = app.install_event_id.clone();
    let (alice, a) = fx.open_with(ALICE, PeerKind::Edit, Some(app), None).await;
    alice.apply("a1", &a.append(" edit")).await.unwrap();
    alice.leave().await.unwrap();
    let versions = fx.versions().await;
    assert_eq!(
        versions[0]["contributors"][0]["app"],
        json!({"package": "docs", "version": "1.0.0", "install_event_id": install})
    );
    // The cut is credited to the app in the official provenance table too, so
    // undo-by-app can find it.
    assert_eq!(
        fx.app_rows().await,
        vec![("docs".into(), "1.0.0".into(), install, "host".into())]
    );
}

/// Leave two peers in the order given.
async fn leave_both(first: SessionPeer, second: SessionPeer) {
    first.leave().await;
    second.leave().await;
}

/// The apps listed in the first version's `contributors[]`.
fn contributor_apps(version: &Value) -> Vec<String> {
    let mut apps: Vec<String> = version["contributors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["app"]["package"].as_str().map(str::to_owned))
        .collect();
    apps.sort();
    apps
}

#[tokio::test]
async fn a_version_holding_two_apps_carries_no_app_row_whatever_the_leave_order() {
    for docs_first in [true, false] {
        let fx = Fixture::new("Two apps").await;
        let docs = fx.install_app(ALICE, "docs").await;
        let notes = fx.install_app(ALICE, "notes").await;
        let (a_docs, c_docs) = fx.open_with(ALICE, PeerKind::Edit, Some(docs), None).await;
        let (a_notes, c_notes) = fx.open_with(ALICE, PeerKind::Edit, Some(notes), None).await;
        a_docs.apply("d1", &c_docs.append(" docs")).await.unwrap();
        a_notes
            .apply("n1", &c_notes.append(" notes"))
            .await
            .unwrap();
        if docs_first {
            leave_both(a_docs, a_notes).await;
        } else {
            leave_both(a_notes, a_docs).await;
        }
        let versions = fx.versions().await;
        assert_eq!(versions.len(), 1, "docs_first={docs_first}");
        // Both apps are in the version's own record...
        assert_eq!(
            contributor_apps(&versions[0]),
            ["docs", "notes"],
            "docs_first={docs_first}"
        );
        // ...and neither is credited in provenance: undo by either app must
        // not revert the other's text.
        assert!(fx.app_rows().await.is_empty(), "docs_first={docs_first}");
    }
}

#[tokio::test]
async fn an_app_version_that_also_holds_a_humans_text_carries_no_app_row() {
    for app_first in [true, false] {
        let fx = Fixture::new("Shared").await;
        let docs = fx.install_app(ALICE, "docs").await;
        let (a_docs, c_docs) = fx.open_with(ALICE, PeerKind::Edit, Some(docs), None).await;
        let (bob, c_bob) = fx.open(BOB).await;
        a_docs.apply("d1", &c_docs.append(" app")).await.unwrap();
        bob.apply("b1", &c_bob.append(" human")).await.unwrap();
        if app_first {
            leave_both(a_docs, bob).await;
        } else {
            leave_both(bob, a_docs).await;
        }
        let versions = fx.versions().await;
        assert_eq!(versions.len(), 1, "app_first={app_first}");
        assert_eq!(contributor_apps(&versions[0]), ["docs"]);
        assert!(fx.app_rows().await.is_empty(), "app_first={app_first}");
    }
}

#[tokio::test]
async fn a_single_app_version_gets_that_apps_row_whatever_the_leave_order() {
    for app_first in [true, false] {
        let fx = Fixture::new("Solo app").await;
        let docs = fx.install_app(ALICE, "docs").await;
        let install = docs.install_event_id.clone();
        let (a_docs, c_docs) = fx.open_with(ALICE, PeerKind::Edit, Some(docs), None).await;
        // A person who joined and typed nothing, and may well be the one
        // whose leave triggers the cut.
        let (bob, _) = fx.open(BOB).await;
        a_docs.apply("d1", &c_docs.append(" app")).await.unwrap();
        if app_first {
            leave_both(a_docs, bob).await;
        } else {
            leave_both(bob, a_docs).await;
        }
        assert_eq!(fx.versions().await.len(), 1, "app_first={app_first}");
        assert_eq!(
            fx.app_rows().await,
            vec![("docs".into(), "1.0.0".into(), install, "host".into())],
            "app_first={app_first}"
        );
    }
}

#[tokio::test]
async fn an_idle_app_peer_is_not_credited_with_a_humans_text() {
    for app_first in [true, false] {
        let fx = Fixture::new("Idle app").await;
        let docs = fx.install_app(ALICE, "docs").await;
        // The app peer joined and typed nothing; the person typed.
        let (a_docs, _) = fx.open_with(ALICE, PeerKind::Edit, Some(docs), None).await;
        let (bob, c_bob) = fx.open(BOB).await;
        bob.apply("b1", &c_bob.append(" human")).await.unwrap();
        if app_first {
            leave_both(a_docs, bob).await;
        } else {
            leave_both(bob, a_docs).await;
        }
        let versions = fx.versions().await;
        assert_eq!(versions.len(), 1, "app_first={app_first}");
        assert!(contributor_apps(&versions[0]).is_empty());
        assert!(fx.app_rows().await.is_empty(), "app_first={app_first}");
    }
}

#[tokio::test]
async fn a_hintless_cut_with_one_app_gets_that_apps_row() {
    let fx = Fixture::new("Idle cut").await;
    let docs = fx.install_app(ALICE, "docs").await;
    let install = docs.install_event_id.clone();
    let (a_docs, c_docs) = fx.open_with(ALICE, PeerKind::Edit, Some(docs), None).await;
    // A person is present too, but typed nothing.
    let (bob, _) = fx.open(BOB).await;
    let mut rx = a_docs.subscribe();
    a_docs.set_idle_after_for_test(Duration::from_millis(30));
    a_docs.apply("d1", &c_docs.append(" app")).await.unwrap();
    // The idle timer cuts: no peer asked for it, so there is no hint.
    wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(version) => Some(version.version.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        fx.app_rows().await,
        vec![("docs".into(), "1.0.0".into(), install, "host".into())]
    );
    a_docs.leave().await;
    bob.leave().await;
}

#[tokio::test]
async fn an_app_write_flushes_unsaved_human_text_without_the_apps_row() {
    let fx = Fixture::new("Flush").await;
    let docs = fx.install_app(BOB, "docs").await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    // BOB's app now saves an artifact body through the flush-and-absorb
    // path: the person's unsaved text is versioned first ("saved before a
    // routed write"), triggered by the app but not made by it.
    let caller = Caller::authenticated(BOB).with_host_asserted_app(docs);
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();
    write.cancel_absorb();
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1, "{versions:?}");
    assert_eq!(versions[0]["reason"], "saved before a routed write");
    assert!(contributor_apps(&versions[0]).is_empty(), "the flush");
    // The flush, which the app triggered, is not credited to it.
    assert!(fx.app_rows().await.is_empty());
    alice.leave().await;
}

#[tokio::test]
async fn a_routed_app_write_is_its_own_version_after_the_humans_text_is_saved() {
    let fx = Fixture::new("Routed").await;
    let docs = fx.install_app(BOB, "docs").await;
    let install = docs.install_event_id.clone();
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(BOB).with_host_asserted_app(docs),
            "update_record",
            json!({"id": fx.id, "reason": "app save", "body_append": " saved"}),
        )
        .await
        .unwrap();
    // Two versions: the person's text first, with no app row; then the app's
    // append, whose version holds only the app's change.
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 2, "{versions:?}");
    assert_eq!(versions[0]["reason"], "saved before a routed write");
    assert_eq!(versions[0]["body"], "Routed human");
    assert!(contributor_apps(&versions[0]).is_empty());
    assert_eq!(versions[0]["contributors"][0]["principal"], json!(ALICE));
    assert_eq!(versions[1]["reason"], "app save");
    assert_eq!(
        versions[1]["body"], "Routed human saved",
        "the second version differs from the first by the append alone"
    );
    assert_eq!(contributor_apps(&versions[1]), ["docs"]);
    assert_eq!(versions[1]["contributors"].as_array().unwrap().len(), 1);
    assert_eq!(versions[1]["contributors"][0]["principal"], json!(BOB));
    // The app's row is the routed write's, not the flush's.
    assert_eq!(
        fx.app_rows().await,
        vec![("docs".into(), "1.0.0".into(), install, "host".into())]
    );
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id = ? AND type = 'record.updated' ORDER BY seq",
    )
    .bind(&fx.id)
    .fetch_all(fx.db.pool())
    .await
    .unwrap();
    let credited: Vec<String> = sqlx::query_scalar(
        "SELECT o.output_event_id FROM provenance_action_app_attributions a
           JOIN provenance_action_outputs o ON o.action_attestation_id = a.action_attestation_id",
    )
    .fetch_all(fx.db.pool())
    .await
    .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(credited, [events[1].clone()]);
    alice.leave().await;
}

#[tokio::test]
async fn a_routed_agent_write_is_its_own_version_after_the_humans_text_is_saved() {
    let fx = Fixture::new("Routed").await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(AGENT).with_channel(crate::provenance::Channel::Mcp),
            "update_record",
            json!({"id": fx.id, "reason": "agent append", "body_append": " by agent"}),
        )
        .await
        .unwrap();
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 2, "{versions:?}");
    assert_eq!(versions[0]["reason"], "saved before a routed write");
    assert_eq!(versions[0]["body"], "Routed human");
    assert_eq!(versions[0]["contributors"].as_array().unwrap().len(), 1);
    assert_eq!(versions[0]["contributors"][0]["principal"], json!(ALICE));
    assert_eq!(versions[1]["reason"], "agent append");
    assert_eq!(
        versions[1]["body"], "Routed human by agent",
        "the agent's version differs from the person's by its append alone"
    );
    assert_eq!(versions[1]["contributors"].as_array().unwrap().len(), 1);
    assert_eq!(versions[1]["contributors"][0]["principal"], json!(AGENT));
    assert_eq!(versions[1]["contributors"][0]["channel"], "mcp");
    // Neither version is any app's.
    assert!(fx.app_rows().await.is_empty());
    alice.leave().await;
}

#[tokio::test]
async fn a_stale_install_generation_is_refused_after_an_update() {
    let fx = Fixture::new("Stale").await;
    let v1 = fx.install_app(ALICE, "docs").await;
    let (docs, c) = fx
        .open_with(ALICE, PeerKind::Edit, Some(v1.clone()), None)
        .await;
    let mut rx = docs.subscribe();
    docs.apply("d1", &c.append(" typed")).await.unwrap();
    // The account updates the app (a new install generation) while the host's
    // frame, launched with v1's install event, is still open.
    let v2 = fx.update_app(ALICE, &v1, "1.0.1").await;
    assert_ne!(v1.install_event_id, v2.install_event_id);
    let try_open = |app: AppAttribution| {
        let db = fx.db.clone();
        let record_id = fx.id.clone();
        async move {
            live::open(
                &db,
                &Caller::authenticated(ALICE).with_host_asserted_app(app),
                OpenRequest {
                    record_id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
            .map(|_| ())
        }
    };
    // The old claim, and the new version string riding the old install
    // generation (only the event id is stale), are both refused on open.
    for stale in [
        v1.clone(),
        AppAttribution::new("docs", "1.0.1", v1.install_event_id.clone()).unwrap(),
    ] {
        assert_eq!(
            try_open(stale.clone()).await.unwrap_err().code,
            RefusalCode::Forbidden,
            "{stale:?}"
        );
    }
    // The current generation opens.
    try_open(v2.clone()).await.unwrap();
    // The re-check of the peer still on the old claim ends it...
    let recheck = docs
        .recheck_access(&Caller::authenticated(ALICE).with_host_asserted_app(v1))
        .await
        .unwrap_err();
    assert_eq!(recheck.code, RefusalCode::AccessLost);
    // ...and its text is versioned (the cut runs after the peer is removed,
    // so wait for it) without ever being attributed to it.
    wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(version) => Some(version.version.clone()),
        _ => None,
    })
    .await;
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1, "{versions:?}");
    assert!(fx.app_rows().await.is_empty());
}

#[tokio::test]
async fn a_resume_must_come_back_through_the_same_app() {
    let fx = Fixture::new("Resume").await;
    let docs = fx.install_app(ALICE, "docs").await;
    let notes = fx.install_app(ALICE, "notes").await;
    let open = |app: Option<AppAttribution>, resume_peer: Option<super::PeerId>| {
        let db = fx.db.clone();
        let record_id = fx.id.clone();
        async move {
            let caller = Caller::authenticated(ALICE);
            let caller = match app {
                Some(app) => caller.with_host_asserted_app(app),
                None => caller,
            };
            live::open(
                &db,
                &caller,
                OpenRequest {
                    record_id,
                    mode: PeerKind::Edit,
                    resume_peer,
                },
            )
            .await
            .unwrap()
        }
    };
    let (first, opened) = open(Some(docs.clone()), None).await;
    for (label, claim) in [("another app", Some(notes)), ("no app", None)] {
        let (other, again) = open(claim, Some(opened.peer.clone())).await;
        assert!(!again.resumed, "resume under {label}");
        assert_ne!(again.peer, opened.peer, "resume under {label}");
        other.leave().await;
    }
    // The same app resumes it.
    let (same, again) = open(Some(docs), Some(opened.peer.clone())).await;
    assert!(again.resumed);
    assert_eq!(again.peer, opened.peer);
    same.leave().await;
    drop(first);
}

#[tokio::test]
async fn an_app_claim_for_an_install_the_account_does_not_hold_is_refused() {
    let fx = Fixture::new("Refused").await;
    let alices = fx.install_app(ALICE, "docs").await;
    let open = |account: &'static str, app: AppAttribution| {
        let db = fx.db.clone();
        let record_id = fx.id.clone();
        async move {
            live::open(
                &db,
                &Caller::authenticated(account).with_host_asserted_app(app),
                OpenRequest {
                    record_id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
            .map(|_| ())
        }
    };
    // Unknown install generation, a different package or version than the
    // install names, and an install that is another account's.
    for claim in [
        AppAttribution::new("docs", "1.0.0", "no-such-install").unwrap(),
        AppAttribution::new("other", "1.0.0", alices.install_event_id.clone()).unwrap(),
        AppAttribution::new("docs", "9.9.9", alices.install_event_id.clone()).unwrap(),
    ] {
        assert_eq!(
            open(ALICE, claim.clone()).await.unwrap_err().code,
            RefusalCode::Forbidden,
            "{claim:?}"
        );
    }
    assert_eq!(
        open(BOB, alices.clone()).await.unwrap_err().code,
        RefusalCode::Forbidden,
        "another account's install"
    );
    // The refusal joined nothing: no session, no version, no row.
    assert!(fx.app_rows().await.is_empty());
    // The genuine claim still opens.
    open(ALICE, alices).await.unwrap();
}

#[tokio::test]
async fn a_lapsed_install_ends_the_peer_but_not_the_version() {
    use crate::control::{
        alpha_tab_aggregate_id, append_control_event, AlphaTabStatePayload, ControlEventPayload,
        NewControlEvent, ALPHA_TAB_ADOPTION_VERIFIED,
    };
    let fx = Fixture::new("Lapse").await;
    let app = fx.install_app(ALICE, "docs").await;
    let app_claim = app.clone();
    let (docs, d) = fx.open_with(ALICE, PeerKind::Edit, Some(app), None).await;
    docs.apply("d1", &d.append(" typed")).await.unwrap();
    // The account removes the app mid-session.
    let declaration = json!({"contract": "native.app.v2", "needs": [], "effects": []});
    append_control_event(
        &fx.db,
        NewControlEvent::authored(
            uuid::Uuid::new_v4().to_string(),
            alpha_tab_aggregate_id(ALICE, "docs"),
            ALICE,
            None,
            "remove the app",
            ControlEventPayload::AlphaTabRemoved(AlphaTabStatePayload {
                account_id: ALICE.into(),
                package: "docs".into(),
                version: "1.0.0".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
                artifact_id: fx.id.clone(),
                consented_source_revision: "source-1".into(),
                declaration_digest: crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(
                    &declaration,
                )
                .unwrap(),
                consented_declaration: declaration,
                adoption: ALPHA_TAB_ADOPTION_VERIFIED.into(),
                request: None,
                previous_event_id: Some(app_claim.install_event_id.clone()),
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    // The next access re-check ends the peer, like any loss of authority...
    let recheck = docs
        .recheck_access(&Caller::authenticated(ALICE).with_host_asserted_app(app_claim))
        .await
        .unwrap_err();
    assert_eq!(recheck.code, RefusalCode::AccessLost);
    // ...but its acknowledged edit is not lost: the version cuts, still
    // crediting the app in its contributors, without a provenance row for an
    // install that no longer exists.
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1, "{versions:?}");
    assert_eq!(versions[0]["contributors"][0]["app"]["package"], "docs");
    assert!(fx.app_rows().await.is_empty());
}

#[tokio::test]
async fn a_hintless_cut_is_made_by_the_last_accepted_editor() {
    // The actor must not depend on map iteration order, which differs per
    // session: repeat with fresh sessions.
    for round in 0..10 {
        let fx = Fixture::new("Who cuts").await;
        let (alice, _) = fx.open(ALICE).await;
        let (bob, b) = fx.open(BOB).await;
        let mut rx = alice.subscribe();
        bob.set_idle_after_for_test(Duration::from_millis(30));
        // Only Bob types; Alice is present and could cut too.
        bob.apply("b1", &b.append(" by bob")).await.unwrap();
        wait_for(&mut rx, |event| match event {
            SessionEvent::Versioned(version) => Some(version.version.clone()),
            _ => None,
        })
        .await;
        let actor: String = sqlx::query_scalar(
            "SELECT actor FROM content_events
              WHERE record_id = ? AND type = 'record.updated' ORDER BY seq DESC LIMIT 1",
        )
        .bind(&fx.id)
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
        assert_eq!(actor, Caller::authenticated(BOB).actor(), "round {round}");
        alice.leave().await;
        bob.leave().await;
    }
}

#[tokio::test]
async fn a_correct_if_unmodified_since_survives_the_flush_first_version() {
    let fx = Fixture::new("Guarded").await;
    let committed_at = || async {
        sqlx::query_scalar::<_, String>("SELECT updated_at FROM records WHERE id = ?")
            .bind(&fx.id)
            .fetch_one(fx.db.pool())
            .await
            .unwrap()
    };
    let t0 = committed_at().await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    // The agent read the record at `t0` and nothing committed since. Alice's
    // unsaved text is versioned first, which moves `updated_at`, but the
    // agent's guard still holds.
    let append = |since: String| {
        fx.update(
            AGENT,
            json!({"id": fx.id, "reason": "agent append", "body_append": " agent",
                   "if_unmodified_since": since}),
        )
    };
    append(t0.clone()).await.unwrap();
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 2, "{versions:?}");
    assert_eq!(versions[0]["reason"], "saved before a routed write");
    assert_eq!(versions[1]["reason"], "agent append");

    // `t0` is stale now (the agent's own write moved it). With more unsaved
    // text, the refused write still saves it, once; retrying changes nothing.
    alice.apply("a2", &a.append(" more")).await.unwrap();
    let refused = append(t0.clone()).await.unwrap_err().to_string();
    assert!(refused.contains("updated_at"), "{refused}");
    assert_eq!(fx.versions().await.len(), 3);
    for _ in 0..3 {
        append(t0.clone()).await.unwrap_err();
    }
    assert_eq!(fx.versions().await.len(), 3, "a retry adds no version");
    alice.leave().await;
}

#[test]
fn the_guard_looks_through_the_flush_only_while_nothing_else_committed() {
    use super::live::guarded_updated_at as guard;
    // Flushed, and the record is still where the flush left it: judge by the
    // caller's view, from before the flush.
    assert_eq!(guard(Some("t0"), Some("t1"), "t1"), "t0");
    // Flushed, then something else committed: the current value is what the
    // guard must see.
    assert_eq!(guard(Some("t0"), Some("t1"), "t2"), "t2");
    // Nothing flushed: the guard behaves exactly as before.
    assert_eq!(guard(Some("t0"), None, "t0"), "t0");
    assert_eq!(guard(Some("t0"), None, "t2"), "t2");
    assert_eq!(guard(None, None, "t2"), "t2");
    assert_eq!(guard(None, Some("t1"), "t1"), "t1");
}

#[tokio::test]
async fn a_metadata_write_after_the_flush_is_not_looked_through_by_the_guard() {
    let fx = Fixture::new("Lost update").await;
    let updated_at = || async {
        sqlx::query_scalar::<_, String>("SELECT updated_at FROM records WHERE id = ?")
            .bind(&fx.id)
            .fetch_one(fx.db.pool())
            .await
            .unwrap()
    };
    let t0 = updated_at().await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" unsaved")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    // The guarded writer enters: its flush versions Alice's text and holds
    // the ops lock, as it does until its own transaction commits.
    let caller = Caller::authenticated(AGENT);
    let write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    let after_flush = updated_at().await;
    assert_ne!(after_flush, t0, "the flush moved updated_at");
    // Still at the flush's own value: the caller's view (t0) is what counts.
    assert_eq!(write.guard_updated_at(&after_flush), t0);
    // A name-only write does not take the ops lock, and commits in between.
    tokio::time::sleep(Duration::from_millis(5)).await;
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "rename", "name": "Renamed"}),
    )
    .await
    .unwrap();
    let now = updated_at().await;
    assert_ne!(now, after_flush);
    // The guard now sees the current value, so the caller's old timestamp no
    // longer matches and the write is refused rather than overwriting the
    // rename.
    assert_eq!(write.guard_updated_at(&now), now);
    assert_ne!(write.guard_updated_at(&now), t0);
    drop(write);
    alice.leave().await;
}

#[tokio::test]
async fn a_metadata_write_committing_just_before_the_flush_is_seen_by_the_guard() {
    let fx = Fixture::new("Gap A").await;
    let updated_at = || async {
        sqlx::query_scalar::<_, String>("SELECT updated_at FROM records WHERE id = ?")
            .bind(&fx.id)
            .fetch_one(fx.db.pool())
            .await
            .unwrap()
    };
    let t0 = updated_at().await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" unsaved")).await.unwrap();
    // Hold the write lock, so the flush parks at its BEGIN IMMEDIATE.
    let mut held = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
    let before_begin = std::sync::Arc::new(tokio::sync::Notify::new());
    let writer = tokio::spawn(crate::db::with_before_begin_write_notification(
        before_begin.clone(),
        {
            let (db, id) = (fx.db.clone(), fx.id.clone());
            async move {
                live::begin_body_write(&db, &id, &Caller::authenticated(AGENT))
                    .await
                    .unwrap()
            }
        },
    ));
    // The writer is about to begin the flush's transaction. This is where a
    // guard that read `updated_at` before the flush had already looked, so
    // commit a metadata-only change now (it takes no ops lock), before the
    // flush can begin.
    before_begin.notified().await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let renamed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    sqlx::query("UPDATE records SET name = 'Renamed', updated_at = ? WHERE id = ?")
        .bind(&renamed_at)
        .bind(&fx.id)
        .execute(&mut *held)
        .await
        .unwrap();
    held.commit().await.unwrap();
    let write = writer.await.unwrap();
    let current = updated_at().await;
    assert_ne!(current, renamed_at, "the flush then moved updated_at again");
    // The caller's view was T0. The record had already changed (the rename)
    // when the flush began, so the guard must not look back to T0.
    let guarded = write.guard_updated_at(&current);
    assert_ne!(guarded, t0, "the rename between read and flush was hidden");
    assert_eq!(guarded, renamed_at);
    drop(write);
    alice.leave().await;
}

#[tokio::test]
async fn open_refusals() {
    let fx = Fixture::new("x").await;
    let open = |account: &str, record: &str| {
        let caller = Caller::authenticated(account);
        let db = fx.db.clone();
        let record_id = record.to_owned();
        async move {
            live::open(
                &db,
                &caller,
                OpenRequest {
                    record_id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
        }
    };
    assert_eq!(
        open("acct:stranger", &fx.id).await.unwrap_err().code,
        RefusalCode::Forbidden
    );

    // Bodies that are not Markdown text: written straight to the store so
    // the fixtures cannot be refused (or skipped) by tool-level checks.
    let artifact = crate::store::create_record(
        &fx.db,
        json!({"type": "Document", "kind": "artifact", "name": "html", "body": "<p>x</p>"}),
    )
    .await
    .unwrap();
    let instruction = crate::store::create_record(
        &fx.db,
        json!({"type": "Document", "kind": "instruction", "name": "rules", "body": "be kind"}),
    )
    .await
    .unwrap();
    let big = crate::store::create_record(
        &fx.db,
        json!({"type": "Document", "kind": "note", "name": "big",
               "body": "a".repeat(super::registry::MAX_BODY_BYTES + 1)}),
    )
    .await
    .unwrap();
    for id in [&artifact, &instruction, &big] {
        crate::authorization::replace_explicit_policy(
            &fx.db,
            "test:live-session",
            id,
            vec![AllowEntry::account(ALICE, Capability::Edit)],
        )
        .await
        .unwrap();
    }
    assert_eq!(
        open(ALICE, &artifact).await.unwrap_err().code,
        RefusalCode::RecordUnsupported
    );
    assert_eq!(
        open(ALICE, &instruction).await.unwrap_err().code,
        RefusalCode::RecordUnsupported
    );
    assert_eq!(
        open(ALICE, &big).await.unwrap_err().code,
        RefusalCode::TooLarge
    );
}

#[test]
fn state_vector_helper_is_v1() {
    // Guard: the empty-sync shortcut in `SessionPeer::sync` encodes an empty
    // state vector the same way clients do.
    assert_eq!(StateVector::default().encode_v1(), vec![0]);
}

#[tokio::test]
async fn image_insert_is_routed_into_the_session() {
    use crate::record_images::{
        insert_record_image, ImageAlignment, ImageInsertMetadata, ImagePlacement, ImageSize,
        ImageSplice,
    };
    let fx = Fixture::new("Before\n").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.apply("a1", &a.append("typed\n")).await.unwrap();
    let live = a.body();
    let mut png = Vec::new();
    image::DynamicImage::new_rgba8(1, 1)
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let metadata = |digest_of: &str| ImageInsertMetadata {
        version: "native.record-image-insert.v1".into(),
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        if_body_digest: body_digest(Some(digest_of)),
        splice: ImageSplice {
            start: digest_of.len(),
            end: digest_of.len(),
        },
        placement: ImagePlacement {
            alt: "diagram".into(),
            caption: None,
            size: ImageSize::Medium,
            alignment: ImageAlignment::Center,
        },
        filename: None,
    };
    // A splice computed against the committed body is stale against live.
    let stale = insert_record_image(
        &fx.db,
        &Caller::local(),
        &fx.id,
        metadata("Before\n"),
        "Before\n".into(),
        png.clone(),
        "image/png",
    )
    .await;
    assert!(matches!(
        stale,
        Err(crate::record_images::RecordImageError::Conflict)
    ));

    let inserted = insert_record_image(
        &fx.db,
        &Caller::local(),
        &fx.id,
        metadata(&live),
        live.clone(),
        png,
        "image/png",
    )
    .await
    .unwrap();
    let committed = fx.committed().await;
    assert!(committed.starts_with("Before\ntyped\n"));
    assert!(committed.ends_with(&inserted.placement_source));
    let events = drain(&mut rx);
    deliver(&a, &alice, &events);
    assert_eq!(a.body(), committed, "the insert arrives live");
    let versions = versioned(&events);
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].reason, "saved before a routed write");
    assert!(versions[0]
        .contributors
        .iter()
        .any(|c| c.principal == ALICE));
    assert_eq!(versions[1].reason, "image inserted");
    // The image route's caller here is the trusted local caller (attachment
    // creation needs a portable account binding the fixture lacks), and the
    // insert's version holds only its change.
    assert_eq!(versions[1].contributors.len(), 1);
    assert!(!versions[1]
        .contributors
        .iter()
        .any(|c| c.principal == ALICE));
    alice.leave().await;
}

#[tokio::test]
async fn suggestion_accept_is_routed_against_the_live_text() {
    let fx = Fixture::new("alpha beta").await;
    let suggestion = fx
        .tools
        .call(
            fx.db.clone(),
            Caller::local(),
            "create_record",
            json!({"type": "Annotation", "kind": "suggestion", "name": "tighten",
                   "lifecycle": "open", "body": "A", "reason": "suggestion fixture",
                   "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
                   "links": [{"target_id": fx.id, "relationship": "part_of"}]}),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    crate::authorization::replace_explicit_policy(
        &fx.db,
        "test:live-session",
        &suggestion,
        vec![AllowEntry::account(AGENT, Capability::Edit)],
    )
    .await
    .unwrap();
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.apply("a1", &a.append(" gamma")).await.unwrap();
    let outcome = fx
        .tools
        .call(
            fx.db.clone(),
            Caller::authenticated(AGENT),
            "resolve_suggestions",
            json!({"action": "accept", "suggestion_ids": [suggestion],
                   "reason": "accept the tightening"}),
        )
        .await
        .unwrap();
    assert_eq!(outcome["status"], "accepted", "{outcome}");
    // Applied to the live text, so Alice's unsaved " gamma" survives.
    assert_eq!(fx.committed().await, "A beta gamma");
    let events = drain(&mut rx);
    deliver(&a, &alice, &events);
    assert_eq!(a.body(), "A beta gamma");
    let versions = versioned(&events);
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].reason, "saved before a routed write");
    assert_eq!(versions[0].contributors.len(), 1);
    assert_eq!(versions[0].contributors[0].principal, ALICE);
    assert_eq!(versions[1].reason, "accept the tightening");
    assert_eq!(versions[1].contributors.len(), 1);
    assert_eq!(versions[1].contributors[0].principal, AGENT);
    alice.leave().await;
}

#[tokio::test]
async fn other_body_writers_are_refused_by_the_backstop() {
    let fx = Fixture::new("guarded").await;
    let (alice, _) = fx.open(ALICE).await;
    // A raw body append that is not the session's own version.
    let result = crate::store::append(
        &fx.db,
        crate::store::AppendSpec {
            record_id: fx.id.clone(),
            event_type: "record.updated".into(),
            payload: json!({"body": "sneaky"}),
            actor: Some(ALICE.into()),
        },
    )
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("live editing session"));
    assert_eq!(fx.committed().await, "guarded");
    alice.leave().await;
}

#[tokio::test]
async fn requested_versions_are_rate_limited_and_coalesced() {
    let fx = Fixture::new("v").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // Wide enough that the coalesced requests below always fall inside the
    // window, however slow the first cut is; the coalesced cut is awaited as
    // an event, not timed.
    let interval = Duration::from_secs(2);
    alice.set_version_interval_for_test(interval);
    assert_eq!(
        alice.version("  ").await.unwrap_err().code,
        RefusalCode::InvalidRequest
    );
    alice.apply("a1", &a.append("1")).await.unwrap();
    let started = tokio::time::Instant::now();
    let first = alice
        .version("first")
        .await
        .unwrap()
        .expect("first cut is immediate");
    alice.apply("a2", &a.append("2")).await.unwrap();
    assert!(
        alice.version("second").await.unwrap().is_none(),
        "coalesced"
    );
    alice.apply("a3", &a.append("3")).await.unwrap();
    assert!(alice.version("third").await.unwrap().is_none(), "coalesced");
    let coalesced = wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(v) if *v != first => Some(v.clone()),
        _ => None,
    })
    .await;
    assert!(started.elapsed() >= interval, "not before the next slot");
    assert_eq!(coalesced.reason, "third", "latest reason wins");
    assert_eq!(fx.committed().await, "v123");
    // One requested cut plus one coalesced cut, nothing else.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fx.versions().await.len(), 2);
    // Routed (agent) versions are exempt from the window.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "agent", "body_append": "!"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "v123!");
    alice.leave().await;
}

#[tokio::test]
async fn repeated_failed_cuts_save_through_the_session_service_and_close() {
    let fx = Fixture::new("Locked?").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // Every contributor loses Edit *before* the edit arrives: the idle timer
    // starts with the edit, so revoking afterwards races it (a slow grant on
    // a busy host lets a cut succeed first, and the session then never
    // closes). Her open peer can still type; no cut can succeed through her.
    fx.grant(&[AGENT]).await;
    alice.set_idle_after_for_test(Duration::from_millis(30));
    alice.apply("a1", &a.append(" typed")).await.unwrap();
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::AccessLost);
    // The unsaved text was kept as a session-service version, credited to
    // Alice, and the record is writable again.
    assert_eq!(fx.committed().await, "Locked? typed");
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["contributors"][0]["principal"], json!(ALICE));
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "after", "body_append": "!"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "Locked? typed!");
}

#[tokio::test]
async fn a_writer_flushes_a_grace_doc_its_contributors_can_no_longer_save() {
    let fx = Fixture::new("Grace").await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" text")).await.unwrap();
    fx.grant(&[AGENT]).await;
    // Alice can no longer version it, so her leave cannot cut.
    assert!(alice.leave().await.is_none());
    assert_eq!(fx.committed().await, "Grace");
    // A writer with Edit versions the unsaved text through itself, discards
    // the grace doc, then writes on the committed path.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "append", "body_append": "!"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "Grace text!");
    assert_eq!(fx.versions().await.len(), 1);
}

#[tokio::test]
async fn leaving_live_scope_closes_the_session() {
    let fx = Fixture::new("Scope").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // Restating the current kind is not a scope change: no cut, no close.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "rename", "kind": "note", "name": "x"}),
    )
    .await
    .unwrap();
    alice.apply("a1", &a.append(" edit")).await.unwrap();
    // A real kind change while people type: their unsaved text is versioned
    // first (as the writer) and the change goes through. A memo is still
    // live-editable, so the session stays open.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "rekind", "kind": "memo"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "Scope edit");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = drain(&mut rx);
    assert_eq!(versioned(&events).len(), 1);
    assert!(!events
        .iter()
        .any(|event| matches!(event, SessionEvent::Closed { .. })));
    alice.apply("a2", &a.append("?")).await.unwrap();

    // A deletion takes the record out of live editing: the unsaved text is
    // saved first, then the session closes after the commit.
    fx.tools
        .call(
            fx.db.clone(),
            Caller::local(),
            "delete_record",
            json!({"id": fx.id, "reason": "remove"}),
        )
        .await
        .unwrap();
    let events = drain(&mut rx);
    assert_eq!(
        versioned(&events).len(),
        1,
        "unsaved text saved before the delete"
    );
    assert!(events.iter().any(|event| matches!(
        event,
        SessionEvent::Closed {
            peer: None,
            reason: CloseReason::AccessLost
        }
    )));
}

#[tokio::test]
async fn a_routed_write_with_a_live_kind_change_keeps_the_session() {
    let fx = Fixture::new("Both").await;
    let (alice, _) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "append and rekind", "kind": "memo", "body_append": "!"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.committed().await, "Both!");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = drain(&mut rx);
    assert_eq!(versioned(&events).len(), 1);
    assert!(!events
        .iter()
        .any(|event| matches!(event, SessionEvent::Closed { .. })));
    alice.leave().await;
}

#[tokio::test]
async fn sessions_close_only_after_a_scope_change_commits() {
    let fx = Fixture::new("Pending").await;
    let (alice, _) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    let rekind = || crate::store::AppendSpec {
        record_id: fx.id.clone(),
        event_type: "record.updated".into(),
        payload: json!({"kind": "memo", "reason": "rekind"}),
        actor: Some(ALICE.into()),
    };
    // A guarded writer whose transaction never commits leaves it open.
    {
        let mut write = live::begin_body_write(&fx.db, &fx.id, &Caller::authenticated(ALICE))
            .await
            .unwrap();
        write
            .begin_scope_change(&fx.db, &Caller::authenticated(ALICE))
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
        let mut act = crate::act::ActAllocation::new();
        crate::store::append_in(&fx.db, &mut tx, rekind(), &mut act)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }
    // An unguarded writer (a raw deletion) that rolls back leaves it open
    // too...
    let delete = || crate::store::AppendSpec {
        record_id: fx.id.clone(),
        event_type: "record.deleted".into(),
        payload: json!({"reason": "remove"}),
        actor: Some(ALICE.into()),
    };
    let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::store::append_in(&fx.db, &mut tx, delete(), &mut act)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "touch", "name": "renamed"}),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        drain(&mut rx).is_empty(),
        "nothing closed while uncommitted"
    );
    // ...and one that commits closes it after the commit, once the record
    // is re-checked and found no longer live-editable.
    let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::store::append_in(&fx.db, &mut tx, delete(), &mut act)
        .await
        .unwrap();
    fx.db.commit_content(tx).await.unwrap();
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::AccessLost);
}

#[tokio::test]
async fn view_peers_cannot_apply() {
    let fx = Fixture::new("read only").await;
    let (viewer, v) = fx.open_with(BOB, PeerKind::View, None, None).await;
    let refused = viewer.apply("v1", &v.append("!")).await.unwrap_err();
    assert_eq!(refused.code, RefusalCode::Forbidden);
    assert_eq!(
        viewer.version("no").await.unwrap_err().code,
        RefusalCode::Forbidden
    );
    viewer.leave().await;
}

#[tokio::test]
async fn routed_writes_credit_the_host_asserted_app() {
    let fx = Fixture::new("Doc").await;
    let (alice, _) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    let app = fx.install_app(BOB, "docs").await;
    let install = app.install_event_id.clone();
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(BOB).with_host_asserted_app(app),
            "update_record",
            json!({"id": fx.id, "reason": "app save", "body_append": " saved"}),
        )
        .await
        .unwrap();
    let from = wait_for(&mut rx, |event| match event {
        SessionEvent::Remote {
            origin: None, from, ..
        } => Some(from.clone()),
        _ => None,
    })
    .await;
    assert_eq!(from.kind, AuthorKind::App);
    let versions = fx.versions().await;
    assert_eq!(
        versions[0]["contributors"][0]["app"],
        json!({"package": "docs", "version": "1.0.0", "install_event_id": install})
    );
    assert_eq!(versions[0]["contributors"][0]["principal"], json!(BOB));
    // The routed write is an ordinary app tool call: its attestation carries
    // the row.
    assert_eq!(
        fx.app_rows().await,
        vec![("docs".into(), "1.0.0".into(), install, "host".into())]
    );
    alice.leave().await;
}

#[tokio::test]
async fn an_unauthorized_writer_cannot_touch_session_state() {
    let fx = Fixture::new("Private").await;
    let (alice, opened) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    alice.leave().await;
    // Grace doc in memory. A stranger's write is refused by authorization
    // and must not discard it.
    assert!(fx
        .update(
            "acct:stranger",
            json!({"id": fx.id, "reason": "x", "body_append": "!"})
        )
        .await
        .is_err());
    let (alice, again) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(opened.peer.clone()),
        },
    )
    .await
    .unwrap();
    assert!(again.resumed, "the grace doc survived");
    assert_eq!(again.session, opened.session);
    alice.leave().await;
}

#[tokio::test]
async fn multibyte_routed_diffs_land_on_char_boundaries() {
    let fx = Fixture::new("Café 🌍 日本語\r\ne\u{301} end\n").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.apply("a1", &a.insert(0, "→ ")).await.unwrap();
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "swap globe and kanji",
               "body_replace": [{"old": "🌍", "new": "🌎🌏"}, {"old": "日本語", "new": "中文"}]}),
    )
    .await
    .unwrap();
    let expected = "→ Café 🌎🌏 中文\r\ne\u{301} end\n";
    deliver(&a, &alice, &drain(&mut rx));
    assert_eq!(a.body(), expected);
    assert_eq!(fx.committed().await, expected);
    // Peers keep typing after the multibyte splice, at byte offsets.
    let at = expected.find("end").unwrap() as u32;
    alice.apply("a2", &a.insert(at, "the ")).await.unwrap();
    assert_eq!(
        fx.get(ALICE).await["body"],
        json!("→ Café 🌎🌏 中文\r\ne\u{301} the end\n")
    );
    alice.leave().await;
}

#[tokio::test]
async fn a_routed_write_racing_peer_applies_loses_nothing() {
    let fx = Fixture::new("start\n").await;
    let (alice, a) = fx.open(ALICE).await;
    let (bob, b) = fx.open(BOB).await;
    let mut a_rx = alice.subscribe();
    let mut b_rx = bob.subscribe();
    let updates: Vec<Vec<u8>> = (0..20).map(|i| a.append(&format!("a{i}\n"))).collect();
    let peer = async {
        for (i, update) in updates.iter().enumerate() {
            alice.apply(&format!("a{i}"), update).await.unwrap();
            tokio::task::yield_now().await;
        }
    };
    let writes = async {
        for i in 0..5 {
            fx.update(
                AGENT,
                json!({"id": fx.id, "reason": format!("agent {i}"), "body_append": format!("g{i}\n")}),
            )
            .await
            .unwrap();
        }
    };
    tokio::join!(peer, writes);
    deliver(&a, &alice, &drain(&mut a_rx));
    deliver(&b, &bob, &drain(&mut b_rx));
    let live = fx.get(ALICE).await["body"].as_str().unwrap().to_owned();
    assert_eq!(a.body(), live);
    assert_eq!(b.body(), live);
    for i in 0..20 {
        assert!(
            live.contains(&format!("a{i}\n")),
            "peer edit a{i} lost: {live:?}"
        );
    }
    for i in 0..5 {
        assert!(
            live.contains(&format!("g{i}\n")),
            "agent write g{i} lost: {live:?}"
        );
    }
    // Every routed write versioned exactly what was live at that moment, and
    // each saved the peer's unsaved text first, as its own version. How many
    // of those there are depends on how the applies interleaved.
    let versions = fx.versions().await;
    let agent_writes = versions
        .iter()
        .filter(|v| {
            v["reason"]
                .as_str()
                .is_some_and(|r| r.starts_with("agent "))
        })
        .count();
    assert_eq!(agent_writes, 5);
    assert!(versions.iter().all(|v| {
        let reason = v["reason"].as_str().unwrap();
        reason.starts_with("agent ") || reason == "saved before a routed write"
    }));
    alice.leave().await;
    bob.leave().await;
    assert_eq!(fx.committed().await, live);
}

#[tokio::test]
async fn a_resume_notifies_the_superseded_handle() {
    let fx = Fixture::new("Two tabs").await;
    let (old, opened) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    let mut old_rx = old.subscribe();
    let (new, _) = live::open(
        &fx.db,
        &Caller::authenticated(ALICE),
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: Some(opened.peer.clone()),
        },
    )
    .await
    .unwrap();
    let mut new_rx = new.subscribe();
    let closed = wait_for(&mut old_rx, |event| match event {
        SessionEvent::Closed {
            peer: Some(p),
            reason,
        } => Some((p.clone(), *reason)),
        _ => None,
    })
    .await;
    assert_eq!(closed, (opened.peer.clone(), CloseReason::Superseded));
    // The old handle is ended for every call, including the access recheck.
    assert_eq!(
        old.recheck_access(&Caller::authenticated(ALICE))
            .await
            .unwrap_err()
            .code,
        RefusalCode::UndeclaredSession
    );
    // The new handle saw no such notice.
    assert!(drain(&mut new_rx).is_empty());
    new.leave().await;
}

/// Freeze barrier double for one test: databases whose key is in `frozen`
/// are refused; every admission hands out a guard that records the committed
/// body of `record` (read synchronously) when it is acquired and dropped.
struct Barrier {
    frozen: std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
    seen: std::sync::Mutex<Vec<(&'static str, String)>>,
}

struct BarrierGuard {
    barrier: std::sync::Arc<Barrier>,
    path: std::path::PathBuf,
    record: String,
}

fn committed_body_sync(path: &std::path::Path, record: &str) -> String {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.query_row("SELECT body FROM records WHERE id = ?1", [record], |row| {
        row.get::<_, Option<String>>(0)
    })
    .unwrap()
    .unwrap_or_default()
}

impl Drop for BarrierGuard {
    fn drop(&mut self) {
        let body = committed_body_sync(&self.path, &self.record);
        self.barrier.seen.lock().unwrap().push(("released", body));
    }
}

/// Clears the process-wide write admission hook when dropped, so a test that
/// installs one cannot leave it behind if it panics part-way.
struct AdmissionHookGuard;

impl Drop for AdmissionHookGuard {
    fn drop(&mut self) {
        live::set_write_admission(None);
    }
}

fn install_barrier(fixtures: &[&Fixture]) -> std::sync::Arc<Barrier> {
    let barrier = std::sync::Arc::new(Barrier {
        frozen: std::sync::Mutex::new(std::collections::HashSet::new()),
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let watched: Vec<(std::path::PathBuf, String)> = fixtures
        .iter()
        .map(|fx| (fx.db.live_session_key().to_path_buf(), fx.id.clone()))
        .collect();
    let hook = std::sync::Arc::clone(&barrier);
    live::set_write_admission(Some(std::sync::Arc::new(move |db: &Db| {
        // Scoped to this test's databases: other tests share the process.
        let key = db.live_session_key();
        let Some((path, record)) = watched.iter().find(|(path, _)| path == key) else {
            return Some(Box::new(()) as Box<dyn Send>);
        };
        if hook.frozen.lock().unwrap().contains(path) {
            return None;
        }
        let body = committed_body_sync(path, record);
        hook.seen.lock().unwrap().push(("acquired", body));
        Some(Box::new(BarrierGuard {
            barrier: std::sync::Arc::clone(&hook),
            path: path.clone(),
            record: record.clone(),
        }) as Box<dyn Send>)
    })));
    barrier
}

/// One test owns the process-wide hook (tests run in parallel), covering
/// the guard lifetime, freeze deferral, and both shutdown paths.
#[tokio::test]
async fn write_admission_guards_span_cuts_freezes_defer_and_shutdown_closes() {
    let fx = Fixture::new("Guard").await;
    let fx2 = Fixture::new("Freeze").await;
    let fx3 = Fixture::new("Routed").await;
    let barrier = install_barrier(&[&fx, &fx2, &fx3]);
    let _hook = AdmissionHookGuard;

    // 1. The guard is acquired before the cut's transaction and released
    //    only after it committed.
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" held")).await.unwrap();
    alice.version("checkpoint").await.unwrap().unwrap();
    assert_eq!(
        *barrier.seen.lock().unwrap(),
        vec![
            ("acquired", "Guard".to_owned()),
            ("released", "Guard held".to_owned())
        ]
    );
    alice.leave().await;

    // 2. While frozen, idle cuts are deferred (never abandoned), and a
    //    shutdown skips the cut, logs the text, closes, and refuses opens.
    let key2 = fx2.db.live_session_key().to_path_buf();
    barrier.frozen.lock().unwrap().insert(key2.clone());
    let (bob, b) = fx2.open(BOB).await;
    let mut rx = bob.subscribe();
    let idle = Duration::from_millis(20);
    bob.set_idle_after_for_test(idle);
    bob.apply("b1", &b.append(" one")).await.unwrap();
    tokio::time::sleep(idle * 20).await;
    assert!(versioned(&drain(&mut rx)).is_empty());
    assert_eq!(fx2.committed().await, "Freeze");
    // Thawed: the deferred idle cut lands.
    barrier.frozen.lock().unwrap().remove(&key2);
    let version = wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(v) => Some(v.clone()),
        _ => None,
    })
    .await;
    assert_eq!(version.reason, "idle");
    assert_eq!(fx2.committed().await, "Freeze one");
    bob.set_idle_after_for_test(Duration::from_secs(3600));
    bob.apply("b2", &b.append(" two")).await.unwrap();
    barrier.frozen.lock().unwrap().insert(key2.clone());
    live::shutdown_database_for_test(&fx2.db).await;
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::ServerShutdown);
    assert_eq!(fx2.committed().await, "Freeze one");
    let refused = live::open(
        &fx2.db,
        &Caller::authenticated(BOB),
        OpenRequest {
            record_id: fx2.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap_err();
    assert_eq!(refused.code, RefusalCode::Unavailable);

    // 3. Not frozen: shutdown flushes unsaved edits before closing.
    let (carol, c) = fx.open(ALICE).await;
    let mut rx = carol.subscribe();
    carol.apply("c1", &c.append("!")).await.unwrap();
    live::shutdown_database_for_test(&fx.db).await;
    let version = wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(v) => Some(v.clone()),
        _ => None,
    })
    .await;
    assert_eq!(version.reason, "server shutdown");
    assert_eq!(fx.committed().await, "Guard held!");

    // 4. A routed write that finds unsaved edits must save them first, and
    //    that cut is consulted: with a freeze pending it is refused as
    //    retryable, the write changes nothing, and it lands once thawed.
    let key3 = fx3.db.live_session_key().to_path_buf();
    let (dave, d) = fx3.open(ALICE).await;
    dave.apply("d1", &d.append(" unsaved")).await.unwrap();
    barrier.frozen.lock().unwrap().insert(key3.clone());
    let refused = fx3
        .update(
            AGENT,
            json!({"id": fx3.id, "reason": "agent append", "body_append": " more"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("retry shortly"), "{refused}");
    assert_eq!(fx3.committed().await, "Routed");
    assert!(fx3.versions().await.is_empty());
    barrier.frozen.lock().unwrap().remove(&key3);
    fx3.update(
        AGENT,
        json!({"id": fx3.id, "reason": "agent append", "body_append": " more"}),
    )
    .await
    .unwrap();
    assert_eq!(fx3.committed().await, "Routed unsaved more");
    assert_eq!(fx3.versions().await.len(), 2, "the flush, then the append");
}

#[tokio::test]
async fn mcp_channel_writes_route_as_agent_and_carry_the_channel() {
    let fx = Fixture::new("Doc").await;
    let (alice, _) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // A real MCP client: an authenticated principal (no verified agent
    // executor) over the MCP transport.
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(AGENT).with_channel(crate::provenance::Channel::Mcp),
            "update_record",
            json!({"id": fx.id, "reason": "agent edit",
                   "body_replace": [{"old": "Doc", "new": "Document"}]}),
        )
        .await
        .unwrap();
    let from = wait_for(&mut rx, |event| match event {
        SessionEvent::Remote {
            origin: None, from, ..
        } => Some(from.clone()),
        _ => None,
    })
    .await;
    assert_eq!(from.kind, AuthorKind::Agent);
    assert_eq!(from.contributor.executor_kind, "authenticated_principal");
    assert_eq!(from.contributor.channel.as_deref(), Some("mcp"));
    let versions = fx.versions().await;
    assert_eq!(versions[0]["contributors"][0]["channel"], json!("mcp"));
    // The same kind of principal over the web channel is a person.
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(BOB).with_channel(crate::provenance::Channel::Web),
            "update_record",
            json!({"id": fx.id, "reason": "save", "body_append": "!"}),
        )
        .await
        .unwrap();
    let from = wait_for(&mut rx, |event| match event {
        SessionEvent::Remote {
            origin: None, from, ..
        } => Some(from.clone()),
        _ => None,
    })
    .await;
    assert_eq!(from.kind, AuthorKind::Human);
    assert_eq!(from.contributor.channel.as_deref(), Some("web"));
    alice.leave().await;
}

/// Captures `tracing` output on this thread (tests run on a current-thread
/// runtime, so spawned tasks log here too).
#[derive(Clone, Default)]
struct LogBuffer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuffer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

#[tokio::test]
async fn transient_cut_failures_retry_without_closing_the_session() {
    let fx = Fixture::new("Flaky").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.set_idle_after_for_test(Duration::from_millis(20));
    // Storage refuses every content append for this record: a transient
    // failure, not an access or policy one.
    sqlx::query(&format!(
        "CREATE TRIGGER live_test_flaky BEFORE INSERT ON content_events \
         WHEN NEW.record_id = '{}' BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END",
        fx.id
    ))
    .execute(fx.db.write_pool())
    .await
    .unwrap();
    alice.apply("a1", &a.append(" text")).await.unwrap();
    // Well past MAX_FAILED_CUTS attempts: never abandoned, never closed.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let events = drain(&mut rx);
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, SessionEvent::Closed { .. })),
        "a transient failure must never close a session"
    );
    assert!(versioned(&events).is_empty());
    alice.apply("a2", &a.append("!")).await.unwrap();
    // Storage recovers: the backed-off retry lands the version.
    sqlx::query("DROP TRIGGER live_test_flaky")
        .execute(fx.db.write_pool())
        .await
        .unwrap();
    let version = wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(v) => Some(v.clone()),
        _ => None,
    })
    .await;
    assert_eq!(version.reason, "idle");
    assert_eq!(fx.committed().await, "Flaky text!");
    alice.leave().await;
}

#[tokio::test]
async fn logs_never_carry_document_text() {
    // Tracing callsite interest is process-wide. Sibling fixtures must not
    // prime this capture's callsites using their own scoped dispatchers.
    if crate::test_process::run_isolated_if_parent().await {
        return;
    }
    let logs = LogBuffer::default();
    let writer = logs.clone();
    // WARN and above: the messages under test, without every storage
    // trace (which slowed this test enough to time out).
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::WARN)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let fx = Fixture::new("Secret").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // Every contributor loses Edit and the service fallback is refused by
    // storage too, so the unsaved text ends in the error log path. Both are
    // arranged before the edit arrives: the idle timer starts with the edit,
    // so setting them up afterwards races it.
    fx.grant(&[AGENT]).await;
    sqlx::query(&format!(
        "CREATE TRIGGER live_test_secret BEFORE INSERT ON content_events \
         WHEN NEW.record_id = '{}' BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END",
        fx.id
    ))
    .execute(fx.db.write_pool())
    .await
    .unwrap();
    alice.set_idle_after_for_test(Duration::from_millis(20));
    alice
        .apply("a1", &a.append(" plans for launch"))
        .await
        .unwrap();
    wait_for(&mut rx, |event| match event {
        SessionEvent::Closed { peer: None, .. } => Some(()),
        _ => None,
    })
    .await;
    let text = logs.text();
    assert!(text.contains("could not be versioned"), "{text}");
    assert!(
        text.contains(&body_digest(Some("Secret plans for launch"))),
        "{text}"
    );
    assert!(
        !text.contains("plans for launch"),
        "document text leaked: {text}"
    );
}

#[tokio::test]
async fn shutdown_keeps_every_acknowledged_edit() {
    let fx = Fixture::new("Shut").await;
    let (alice, a) = fx.open(ALICE).await;
    let updates: Vec<(String, Vec<u8>)> = (0..40)
        .map(|i| {
            let chunk = format!(" {i}");
            let update = a.append(&chunk);
            (chunk, update)
        })
        .collect();
    let typing = async {
        let mut acked = Vec::new();
        for (i, (chunk, update)) in updates.iter().enumerate() {
            match alice.apply(&format!("a{i}"), update).await {
                Ok(_) => acked.push(chunk.clone()),
                Err(_) => break,
            }
            tokio::task::yield_now().await;
        }
        acked
    };
    let shutdown = async {
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        live::shutdown_database_for_test(&fx.db).await;
    };
    let (acked, ()) = tokio::join!(typing, shutdown);
    let committed = fx.committed().await;
    let expected: String = std::iter::once("Shut".to_owned()).chain(acked).collect();
    assert_eq!(
        committed, expected,
        "every acknowledged edit is in the final version"
    );
}

#[tokio::test]
async fn absorbing_is_scoped_to_its_writer_and_never_left_stale() {
    let fx = Fixture::new("Absorb").await;
    let (alice, _) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    let body_event = |actor: &str| crate::store::AppendSpec {
        record_id: fx.id.clone(),
        event_type: "record.updated".into(),
        payload: json!({"body": "replaced", "reason": "absorb probe"}),
        actor: Some(actor.into()),
    };
    let caller = Caller::authenticated(BOB);
    // Only the absorbing writer's own body events pass the backstop.
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();
    for (actor, admitted) in [(ALICE, false), (caller.actor(), true)] {
        let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
        let mut act = crate::act::ActAllocation::new();
        let result = crate::store::append_in(&fx.db, &mut tx, body_event(actor), &mut act).await;
        assert_eq!(result.is_ok(), admitted, "actor {actor}: {result:?}");
        tx.rollback().await.unwrap();
    }
    // An explicitly cancelled absorb (its write did not commit) keeps the
    // session open.
    write.cancel_absorb();
    tokio::task::yield_now().await;
    assert!(drain(&mut rx).is_empty());
    // One dropped mid-flight (e.g. a cancelled request future) may have
    // committed: the session is closed rather than left stale.
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();
    drop(write);
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::Superseded);
}

#[tokio::test]
async fn a_dry_run_suggestion_accept_never_cuts() {
    let fx = Fixture::new("alpha beta").await;
    let suggestion = fx
        .tools
        .call(
            fx.db.clone(),
            Caller::local(),
            "create_record",
            json!({"type": "Annotation", "kind": "suggestion", "name": "tighten",
                   "lifecycle": "open", "body": "A", "reason": "suggestion fixture",
                   "facets": {"proposal.precondition": "span", "anchor.old": "alpha"},
                   "links": [{"target_id": fx.id, "relationship": "part_of"}]}),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    crate::authorization::replace_explicit_policy(
        &fx.db,
        "test:live-session",
        &suggestion,
        vec![AllowEntry::account(AGENT, Capability::Edit)],
    )
    .await
    .unwrap();
    // A grace doc holding unsaved text its contributor can no longer save:
    // any guarded writer would version it first.
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" gamma")).await.unwrap();
    fx.grant(&[AGENT]).await;
    assert!(alice.leave().await.is_none());
    let preview = fx
        .tools
        .call(
            fx.db.clone(),
            Caller::authenticated(AGENT),
            "resolve_suggestions",
            json!({"action": "accept", "suggestion_ids": [suggestion],
                   "reason": "preview", "dry_run": true}),
        )
        .await
        .unwrap();
    assert_eq!(preview["status"], "would_accept", "{preview}");
    // Previewed against the live text, and nothing was written.
    assert_eq!(preview["prospective_body"], json!("A beta gamma"));
    assert!(fx.versions().await.is_empty());
    assert_eq!(fx.committed().await, "alpha beta");
}

#[test]
fn author_kind_follows_executor_app_and_channel() {
    use crate::provenance::Channel;
    use live::author_kind;
    assert_eq!(author_kind("agent", false, Channel::Web), AuthorKind::Agent);
    assert_eq!(
        author_kind("delegated_service", true, Channel::Webhook),
        AuthorKind::Agent
    );
    assert_eq!(
        author_kind("authenticated_principal", true, Channel::Mcp),
        AuthorKind::App
    );
    assert_eq!(
        author_kind("authenticated_principal", false, Channel::Mcp),
        AuthorKind::Agent
    );
    // A verified human over MCP stays a person.
    assert_eq!(author_kind("human", false, Channel::Mcp), AuthorKind::Human);
    assert_eq!(
        author_kind("authenticated_principal", false, Channel::Web),
        AuthorKind::Human
    );
    assert_eq!(
        author_kind("local", false, Channel::Unknown),
        AuthorKind::Human
    );
}

#[tokio::test]
async fn an_absorbing_write_that_fails_to_open_keeps_the_session() {
    let fx = Fixture::new("Busy").await;
    let (alice, _) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    let caller = Caller::authenticated(BOB);
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();
    // E.g. a busy begin_document_write: nothing can have committed.
    let opened: crate::Result<()> = write
        .open_absorbing(async { Err(crate::Error::engine("database is busy")) })
        .await;
    assert!(opened.is_err());
    drop(write);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(drain(&mut rx).is_empty(), "the session stays open");
    alice.leave().await;
}

#[tokio::test]
async fn an_unguarded_scope_change_versions_edits_acked_during_it_before_closing() {
    let fx = Fixture::new("Race").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // An unguarded writer takes the record out of live editing while Alice
    // keeps typing (her edit is acknowledged mid-transaction).
    let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::store::append_in(
        &fx.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: fx.id.clone(),
            event_type: "facet.set".into(),
            payload: json!({"key": "runtime", "value": "native.html.v1"}),
            actor: Some(ALICE.into()),
        },
        &mut act,
    )
    .await
    .unwrap();
    alice.apply("a1", &a.append(" typed")).await.unwrap();
    fx.db.commit_content(tx).await.unwrap();
    let mut saved = None;
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(v) => {
            saved = Some(v.clone());
            None
        }
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::AccessLost);
    let saved = saved.expect("the edit acknowledged mid-transaction is versioned before the close");
    assert_eq!(saved.body_sha256, body_digest(Some("Race typed")));
}

#[tokio::test]
async fn persistent_transient_failures_become_policy_after_the_window() {
    let fx = Fixture::new("Forever").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.set_idle_after_for_test(Duration::from_millis(20));
    alice.set_transient_window_for_test(Duration::from_millis(150));
    sqlx::query(&format!(
        "CREATE TRIGGER live_test_forever BEFORE INSERT ON content_events \
         WHEN NEW.record_id = '{}' BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END",
        fx.id
    ))
    .execute(fx.db.write_pool())
    .await
    .unwrap();
    alice.apply("a1", &a.append(" text")).await.unwrap();
    // Past the window the failures count, and the usual fallback follows:
    // the session-service save (refused here too) is logged and it closes.
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::AccessLost);
}

#[test]
fn deterministic_engine_refusals_are_policy_failures() {
    let policy = live::classify_write_error_for_test(&crate::Error::engine("refused"));
    assert_eq!(policy.code, RefusalCode::RecordUnsupported);
    let auth = live::classify_write_error_for_test(&crate::Error::Auth("nope".into()));
    assert_eq!(auth.code, RefusalCode::RecordUnsupported);
    let storage =
        live::classify_write_error_for_test(&crate::Error::Sqlx(sqlx::Error::PoolTimedOut));
    assert_eq!(storage.code, RefusalCode::Unavailable);
}

#[tokio::test]
async fn restating_the_kind_while_typing_is_never_refused() {
    let fx = Fixture::new("Same").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    for i in 0..3 {
        alice
            .apply(&format!("a{i}"), &a.append(" more"))
            .await
            .unwrap();
        // Unsaved edits, and a kind that does not change: admitted at once,
        // nothing cut, nothing closed.
        fx.update(
            AGENT,
            json!({"id": fx.id, "reason": "rename", "kind": "note", "name": format!("n{i}")}),
        )
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let events = drain(&mut rx);
    assert!(versioned(&events).is_empty());
    assert!(!events
        .iter()
        .any(|event| matches!(event, SessionEvent::Closed { .. })));
    alice.leave().await;
}

#[tokio::test]
async fn a_routed_kind_change_out_of_scope_keeps_edits_acked_after_it() {
    const PAGE: &str = "<!DOCTYPE html><html lang=\"en\"><head><title>t</title></head><body><p>Doc</p></body></html>";
    let fx = Fixture::new(PAGE).await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    // A routed write (as update_record makes it) that also takes the record
    // out of live editing: an HTML artifact is not a live Markdown body.
    let caller = Caller::authenticated(AGENT);
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_scope_change(&fx.db, &caller).await.unwrap();
    let changed = PAGE.replace("<p>Doc</p>", "<p>Doc appended</p>");
    let mut base = serde_json::Map::new();
    base.insert("kind".into(), json!("artifact"));
    base.insert("reason".into(), json!("make it an artifact"));
    let payload = write
        .body_payload(&caller, &changed, "make it an artifact", base)
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::store::append_in(
        &fx.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: fx.id.clone(),
            event_type: "facet.set".into(),
            payload: json!({"key": "runtime", "value": "native.html.v1"}),
            actor: Some(AGENT.into()),
        },
        &mut act,
    )
    .await
    .unwrap();
    crate::store::append_in(
        &fx.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: fx.id.clone(),
            event_type: "record.updated".into(),
            payload: serde_json::Value::Object(payload),
            actor: Some(AGENT.into()),
        },
        &mut act,
    )
    .await
    .unwrap();
    let (event_id, seq) = live::latest_event_in(&mut tx, &fx.id).await.unwrap();
    fx.db.commit_content(tx).await.unwrap();
    write.finish(&event_id, seq).await;
    // `finish` released `ops`; the post-commit close has not run yet
    // (single-threaded runtime, no yield since). This edit lands in that
    // window and is acknowledged. (Delivering the routed change to the
    // client does not yield.)
    deliver(&a, &alice, &drain(&mut rx));
    let at = a.body().find("</p>").unwrap() as u32;
    alice.apply("a1", &a.insert(at, " late")).await.unwrap();
    let expected = PAGE.replace("<p>Doc</p>", "<p>Doc appended late</p>");
    let mut saved = Vec::new();
    let closed = wait_for(&mut rx, |event| match event {
        SessionEvent::Versioned(v) => {
            saved.push(v.clone());
            None
        }
        SessionEvent::Closed { peer: None, reason } => Some(*reason),
        _ => None,
    })
    .await;
    assert_eq!(closed, CloseReason::AccessLost);
    assert_eq!(fx.committed().await, expected);
    assert_eq!(
        saved.last().unwrap().body_sha256,
        body_digest(Some(&expected)),
        "the late edit was versioned before the close"
    );
}

#[tokio::test]
async fn flush_versions_dirty_sessions_and_leaves_them_open() {
    let fx = Fixture::new("Flush").await;
    let (alice, a) = fx.open(ALICE).await;
    let mut rx = alice.subscribe();
    alice.apply("a1", &a.append(" dirty")).await.unwrap();
    let report = live::flush_database_for_test(&fx.db).await;
    assert_eq!(
        report,
        live::FlushReport {
            flushed: 1,
            not_flushed: 0
        }
    );
    assert_eq!(fx.committed().await, "Flush dirty");
    let events = drain(&mut rx);
    assert_eq!(versioned(&events)[0].reason, "flushed before a release");
    assert!(!events
        .iter()
        .any(|event| matches!(event, SessionEvent::Closed { .. })));
    // The session is still open, and new opens still work.
    alice.apply("a2", &a.append("!")).await.unwrap();
    let (bob, _) = fx.open(BOB).await;
    let report = live::flush_database_for_test(&fx.db).await;
    assert_eq!(
        report,
        live::FlushReport {
            flushed: 1,
            not_flushed: 0
        }
    );
    assert_eq!(fx.committed().await, "Flush dirty!");
    // A clean session counts as neither.
    let report = live::flush_database_for_test(&fx.db).await;
    assert_eq!(report, live::FlushReport::default());
    bob.leave().await;
    alice.leave().await;
}

/// Keyed `update_record` (task 8bef361, A0): a keyed miss whose body would be
/// routed into a live session is refused with nothing written, because the
/// merged session version cannot be replayed; the same write without a key
/// still routes. A key committed before the session opened still replays:
/// the lookup runs before the routing refusal.
#[tokio::test]
async fn keyed_body_writes_refuse_live_routing_but_replay_earlier_commands() {
    let fx = Fixture::new("Doc").await;
    let earlier = json!({"id": fx.id, "reason": "before the session", "body_append": " one",
                         "idempotency_key": "before-session"});
    let first = fx.update(BOB, earlier.clone()).await.unwrap();
    let (alice, _) = fx.open(ALICE).await;
    let versions_before = fx.versions().await.len();

    let refused = fx
        .update(
            BOB,
            json!({"id": fx.id, "reason": "keyed save", "body_append": " two",
                   "idempotency_key": "during-session"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("live editing session"), "{refused}");
    assert!(refused.contains("retry without a key"), "{refused}");
    assert_eq!(fx.versions().await.len(), versions_before, "refusal wrote");

    let replay = fx.update(BOB, earlier).await.unwrap();
    assert_eq!(
        replay, first,
        "an earlier keyed command replays mid-session"
    );
    assert_eq!(fx.versions().await.len(), versions_before, "replay wrote");

    fx.update(
        BOB,
        json!({"id": fx.id, "reason": "unkeyed save", "body_append": " two"}),
    )
    .await
    .unwrap();
    assert_eq!(fx.versions().await.len(), versions_before + 1);
    alice.leave().await;
}

/// Task 86a40a9: a keyed call that will not route must not flush the live
/// session first. The refusal and the replay lookup both used to run after
/// `begin_body_write` had versioned Alice's unsaved text.
async fn updated_at_of(fx: &Fixture) -> String {
    sqlx::query_scalar::<_, String>("SELECT updated_at FROM records WHERE id = ?")
        .bind(&fx.id)
        .fetch_one(fx.db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn a_refused_keyed_write_does_not_flush_a_dirty_session_and_the_unkeyed_resend_passes() {
    let fx = Fixture::new("Doc").await;
    let t0 = updated_at_of(&fx).await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let versions_before = fx.versions().await.len();
    let committed_before = fx.committed().await;

    // The node's shape: a minted key plus the caller's own guard, from a read
    // taken at `t0`. Nothing else has committed since.
    let args = |key: Option<&str>| {
        let mut args = json!({"id": fx.id, "reason": "agent append", "body_append": " agent",
                              "if_unmodified_since": t0});
        if let Some(key) = key {
            args["idempotency_key"] = json!(key);
        }
        args
    };
    let refused = fx
        .update(AGENT, args(Some("node-minted")))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("live editing session"), "{refused}");
    assert_eq!(fx.versions().await.len(), versions_before, "refusal wrote");
    assert_eq!(fx.committed().await, committed_before);
    assert_eq!(updated_at_of(&fx).await, t0, "refusal moved updated_at");

    // The one unkeyed resend with the original guard succeeds: nothing
    // changed concurrently, so it is not stale.
    fx.update(AGENT, args(None)).await.unwrap();
    let versions = fx.versions().await;
    assert_eq!(versions.len(), versions_before + 2, "{versions:?}");
    assert_eq!(
        versions[versions_before]["reason"],
        "saved before a routed write"
    );
    assert_eq!(versions[versions_before + 1]["reason"], "agent append");
    alice.leave().await;
}

/// The early replay lookup only skips the live-session gate for a call that
/// really is a replay. Forced to claim a replay that is not one, the call
/// must write nothing and ask for a retry, not commit past the gate.
#[tokio::test]
async fn a_false_may_replay_never_writes_past_the_live_gate() {
    let fx = Fixture::new("Doc").await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let versions_before = fx.versions().await.len();
    let committed_before = fx.committed().await;
    let updated_before = updated_at_of(&fx).await;

    let key = "forced-may-replay";
    let _forced = crate::mcp::tools::keyed_replay::force_answer(
        key,
        crate::mcp::tools::keyed_replay::ForcedAnswer::Replay,
    );
    let refused = fx
        .update(
            AGENT,
            json!({"id": fx.id, "reason": "agent append", "body_append": " agent",
                   "idempotency_key": key}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("retry"), "{refused}");
    assert_eq!(
        fx.versions().await.len(),
        versions_before,
        "wrote a version"
    );
    assert_eq!(fx.committed().await, committed_before, "wrote the body");
    assert_eq!(updated_at_of(&fx).await, updated_before);
    alice.leave().await;
}

/// A read error in the early lookup fails the call before any gate is
/// entered: a dirty grace session (unsaved text, no peers) is not flushed by
/// a call that may turn out to be a replay.
#[tokio::test]
async fn a_failed_early_replay_lookup_fails_the_call_without_flushing() {
    let fx = Fixture::new("Doc").await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    // Only the agent keeps Edit, so Alice's leave cannot cut: the session
    // lingers in its grace window, dirty and with no peers.
    fx.grant(&[AGENT]).await;
    assert!(alice.leave().await.is_none());
    assert_eq!(
        live::session_holds_body(&fx.db, &fx.id),
        Some(live::BodyHold::Saving),
        "the session is a dirty grace doc"
    );
    let versions_before = fx.versions().await.len();
    let committed_before = fx.committed().await;
    let updated_before = updated_at_of(&fx).await;

    let key = "forced-read-error";
    let _forced = crate::mcp::tools::keyed_replay::force_answer(
        key,
        crate::mcp::tools::keyed_replay::ForcedAnswer::ReadError,
    );
    let failed = fx
        .update(
            AGENT,
            json!({"id": fx.id, "reason": "agent append", "body_append": " agent",
                   "idempotency_key": key}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(failed.contains("read failed"), "{failed}");
    assert_eq!(fx.versions().await.len(), versions_before, "flushed");
    assert_eq!(fx.committed().await, committed_before);
    assert_eq!(updated_at_of(&fx).await, updated_before);
    assert_eq!(
        live::session_holds_body(&fx.db, &fx.id),
        Some(live::BodyHold::Saving),
        "the grace doc was left unsaved"
    );
}

#[tokio::test]
async fn a_keyed_replay_against_a_dirty_session_writes_no_version() {
    let fx = Fixture::new("Doc").await;
    let earlier = json!({"id": fx.id, "reason": "before the session", "body_append": " one",
                         "idempotency_key": "before-session"});
    let first = fx.update(BOB, earlier.clone()).await.unwrap();
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" unsaved")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let versions_before = fx.versions().await.len();
    let committed_before = fx.committed().await;
    let updated_before = updated_at_of(&fx).await;

    let replay = fx.update(BOB, earlier).await.unwrap();
    assert_eq!(replay, first, "the earlier keyed command replays");
    assert_eq!(fx.versions().await.len(), versions_before, "replay flushed");
    assert_eq!(fx.committed().await, committed_before);
    assert_eq!(updated_at_of(&fx).await, updated_before);
    alice.leave().await;
}

/// The guard stays real: a genuine concurrent change after the caller's read
/// still makes the unkeyed resend stale, and the refused keyed attempt
/// before it neither hid nor caused that.
#[tokio::test]
async fn a_concurrent_change_still_makes_the_resend_stale_after_a_refused_keyed_write() {
    let fx = Fixture::new("Doc").await;
    let t0 = updated_at_of(&fx).await;
    let (alice, a) = fx.open(ALICE).await;
    alice.apply("a1", &a.append(" human")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    // Someone else's edit lands after the agent read the record at `t0`.
    fx.update(
        BOB,
        json!({"id": fx.id, "reason": "rename", "name": "Renamed"}),
    )
    .await
    .unwrap();
    assert_ne!(updated_at_of(&fx).await, t0);
    tokio::time::sleep(Duration::from_millis(5)).await;
    let versions_before = fx.versions().await.len();

    let args = |key: Option<&str>| {
        let mut args = json!({"id": fx.id, "reason": "agent append", "body_append": " agent",
                              "if_unmodified_since": t0});
        if let Some(key) = key {
            args["idempotency_key"] = json!(key);
        }
        args
    };
    let at_refusal = updated_at_of(&fx).await;
    let refused = fx
        .update(AGENT, args(Some("node-minted")))
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("live editing session"), "{refused}");
    assert_eq!(updated_at_of(&fx).await, at_refusal);

    let stale = fx.update(AGENT, args(None)).await.unwrap_err().to_string();
    assert!(stale.contains("updated_at"), "{stale}");
    assert!(
        !fx.committed().await.contains("agent"),
        "a stale resend wrote its body"
    );
    // The stale resend's own flush saved Alice's text once, as for any
    // refused unkeyed write; no agent version was written.
    let versions = fx.versions().await;
    assert_eq!(versions.len(), versions_before + 1, "{versions:?}");
    alice.leave().await;
}

// ---- cut proofs: body-carrying event identity + SnapshotV1 ----------------

fn proof_snapshot(proof: &live::CutProof) -> yrs::Snapshot {
    yrs::Snapshot::decode_v1(proof.snapshot.as_deref().expect("a proved cut")).unwrap()
}

fn client_snapshot(client: &Client) -> yrs::Snapshot {
    client.doc.transact().snapshot()
}

/// Imported-history fixture rows: the materialized body is already SQL NULL.
/// Insert only; the production append-only guards stay enabled.
async fn null_history_event(fx: &Fixture, id: &str, family: &str, payload: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status)
         VALUES (?,?,?,?,1,'legacy_unknown') RETURNING seq",
    )
    .bind(id)
    .bind(&fx.id)
    .bind(family)
    .bind(payload)
    .fetch_one(fx.db.write_pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn null_carriers_advance_live_proofs_without_widening_contribution_bylines() {
    let fx = Fixture::with_body(None).await;
    let missing = "c0ed1700-0000-4000-8000-000000000001";
    let mut tx = fx.db.pool().begin().await.unwrap();
    assert!(crate::contribution::raw_contribution_in(&mut tx, missing)
        .await
        .unwrap()
        .is_none());
    tx.rollback().await.unwrap();
    assert_eq!(
        live::open(
            &fx.db,
            &Caller::local(),
            OpenRequest {
                record_id: missing.into(),
                mode: PeerKind::Edit,
                resume_peer: None,
            }
        )
        .await
        .unwrap_err()
        .code,
        RefusalCode::Forbidden
    );
    let created = fx.latest_event().await;
    let (peer, client, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
    assert_eq!(client.body(), "");
    assert_eq!(opened.base.body_sha256, body_digest(Some("")));
    assert!(
        opened.base.proof.body_event_id.is_none(),
        "bodyless create is not a carrier"
    );
    assert!(opened.base.proof.body_event_seq.is_none());
    assert_eq!(
        fx.get(ALICE).await["contribution"]["revision"]["event_id"],
        created
    );
    peer.leave().await;

    for (id, family, payload) in [
        ("null-receipt", "receipt.committed.v1", r#"{"body":null}"#),
        (
            "null-unit",
            "unit.revision.recorded.v1",
            r#"{"content":{"content":null}}"#,
        ),
        // SQLite's first duplicate key is null; it still counts as present.
        (
            "null-update",
            "record.updated",
            r#"{"body":null,"body":"ignored"}"#,
        ),
    ] {
        // Import the history before any live session observes this database.
        // A departed peer retains a grace-session base; direct SQL after open
        // would violate the writer assumptions rather than test a reader.
        let fx = Fixture::with_body(None).await;
        let created = fx.latest_event().await;
        let legacy_winner = if family == "record.updated" {
            id
        } else {
            created.as_str()
        };
        let seq = null_history_event(&fx, id, family, payload).await;
        let metadata_seq = null_history_event(
            &fx,
            "metadata-after-null",
            "record.updated",
            r#"{"name":"rename"}"#,
        )
        .await;
        assert!(seq < metadata_seq);
        let (peer, client, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
        assert_eq!(client.body(), "");
        assert_eq!(opened.base.body_sha256, body_digest(Some("")));
        assert_eq!(opened.base.proof.body_event_id.as_deref(), Some(id));
        assert_eq!(opened.base.proof.body_event_seq, Some(seq));
        assert_eq!(proof_snapshot(&opened.base.proof), client_snapshot(&client));
        peer.leave().await;

        let record = fx.get(ALICE).await;
        assert_eq!(
            record["contribution"]["revision"]["event_id"],
            legacy_winner
        );
        assert_eq!(record["contribution"]["created_by"]["event_id"], created);
        let mut tx = fx.db.pool().begin().await.unwrap();
        let facts = crate::contribution::raw_contribution_in(&mut tx, &fx.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(facts.current.event_id, legacy_winner);
        if family == "record.updated" {
            assert!(facts.current.actor.is_none());
            assert!(facts.current.run_key.is_none());
        }
        assert_eq!(facts.creation.unwrap().event_id, created);
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn malformed_legacy_revision_keeps_live_open_unproved_and_contribution_fallible() {
    let fx = Fixture::new("kept materialized bytes").await;
    // A disposable legacy fixture bypasses only metadata admission, exactly
    // once on one connection. Restore it before either affected reader runs.
    let mut tx = crate::db::begin_write(fx.db.write_pool()).await.unwrap();
    let trigger: String = sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_event_claim_meta_insert'")
        .fetch_one(&mut *tx).await.unwrap();
    sqlx::query("DROP TRIGGER content_event_claim_meta_insert")
        .persistent(false)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES ('malformed-revision',?,'record.updated','{',1,'legacy_unknown')")
        .bind(&fx.id).execute(&mut *tx).await.unwrap();
    sqlx::query(&trigger)
        .persistent(false)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // load_supported intentionally swallows the SQL error for proof discovery;
    // it still loads the materialized text, without attributing an older event.
    let (peer, client, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
    assert_eq!(client.body(), "kept materialized bytes");
    assert!(opened.base.proof.body_event_id.is_none());
    assert!(opened.base.proof.body_event_seq.is_none());
    let mut tx = fx.db.pool().begin().await.unwrap();
    let error = crate::contribution::raw_contribution_in(&mut tx, &fx.id)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("malformed JSON"));
    tx.rollback().await.unwrap();
    peer.leave().await;
}

#[tokio::test]
async fn a_quiet_open_names_the_body_event_and_proves_the_seed_snapshot() {
    let fx = Fixture::new("Hello world").await;
    let (alice, a, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
    let event = fx.body_event().await.expect("created with a body");
    assert_eq!(
        opened.base.proof.body_event_id.as_deref(),
        Some(event.as_str())
    );
    assert_eq!(opened.base.proof.body_event_seq, fx.body_event_seq().await);
    assert!(opened.base.proof.body_event_seq.is_some());
    assert_eq!(proof_snapshot(&opened.base.proof), client_snapshot(&a));
    // A quiet joiner is told the same, from the live doc's snapshot read now.
    let (bob, b, joined) = fx.open_full(BOB, PeerKind::Edit).await;
    assert_eq!(joined.base, opened.base);
    assert_eq!(proof_snapshot(&joined.base.proof), client_snapshot(&b));
    // A view peer sees the proof and still cannot cut.
    let (viewer, _, viewed) = fx.open_full(BOB, PeerKind::View).await;
    assert_eq!(viewed.base, opened.base);
    assert_eq!(
        viewer.version("view").await.unwrap_err().code,
        RefusalCode::Forbidden
    );
    alice.leave().await;
    bob.leave().await;
    viewer.leave().await;
}

#[tokio::test]
async fn a_cut_pairs_its_event_with_the_snapshot_it_read_and_joiners_get_the_last_cut() {
    let fx = Fixture::new("Hello world").await;
    let (alice, a, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
    let mut rx = alice.subscribe();
    alice.apply("a1", &a.append("!")).await.unwrap();
    let cut = alice.version("probe").await.unwrap().expect("a cut");
    assert_eq!(
        cut.proof.body_event_id.as_deref(),
        Some(cut.event_id.as_str())
    );
    assert_eq!(fx.body_event().await, cut.proof.body_event_id);
    assert_eq!(fx.body_event_seq().await, cut.proof.body_event_seq);
    assert_eq!(proof_snapshot(&cut.proof), client_snapshot(&a));
    assert_ne!(cut.proof.snapshot, opened.base.proof.snapshot);
    let events = drain(&mut rx);
    assert_eq!(
        versioned(&events)[0].proof,
        cut.proof,
        "the broadcast carries it too"
    );

    // Unsaved text after the cut: a joiner's base is still the last cut, with
    // that cut's snapshot, not a snapshot of the dirty doc.
    alice.apply("a2", &a.append("?")).await.unwrap();
    let (bob, b, joined) = fx.open_full(BOB, PeerKind::Edit).await;
    assert_eq!(joined.base.proof, cut.proof);
    assert_eq!(joined.base.body_sha256, cut.body_sha256);
    assert_ne!(proof_snapshot(&joined.base.proof), client_snapshot(&b));
    alice.leave().await;
    bob.leave().await;
}

#[tokio::test]
async fn reinserting_identical_text_keeps_the_hash_and_changes_the_snapshot() {
    let fx = Fixture::new("Hello world").await;
    let (alice, a, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
    alice.set_version_interval_for_test(Duration::ZERO);
    let replace = |text: &str| {
        let before = a.doc.transact().state_vector();
        {
            let body = a.doc.get_or_insert_text("body");
            let mut txn = a.doc.transact_mut();
            body.remove_range(&mut txn, 6, 5);
            body.insert(&mut txn, 6, text);
        }
        a.doc.transact().encode_diff_v1(&before)
    };
    alice.apply("a1", &replace("there")).await.unwrap();
    let away = alice.version("away").await.unwrap().expect("a cut");
    alice.apply("a2", &replace("world")).await.unwrap();
    let back = alice.version("back").await.unwrap().expect("a cut");
    assert_eq!(
        back.body_sha256, opened.base.body_sha256,
        "same bytes, same hash"
    );
    assert_ne!(
        back.proof.snapshot, opened.base.proof.snapshot,
        "other items"
    );
    assert_ne!(back.proof.snapshot, away.proof.snapshot);
    assert_ne!(back.proof.body_event_id, opened.base.proof.body_event_id);
    assert_eq!(proof_snapshot(&back.proof), client_snapshot(&a));
    alice.leave().await;
}

#[tokio::test]
async fn a_routed_write_proves_the_doc_it_installed_and_metadata_writes_leave_the_body_event() {
    let fx = Fixture::new("one\ntwo\n").await;
    let (alice, a, _) = fx.open_full(ALICE, PeerKind::Edit).await;
    let mut rx = alice.subscribe();
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "agent appends", "body_append": "three\n"}),
    )
    .await
    .unwrap();
    let events = drain(&mut rx);
    deliver(&a, &alice, &events);
    assert_eq!(a.body(), "one\ntwo\nthree\n");
    let routed = versioned(&events)
        .pop()
        .expect("the routed write's version");
    assert_eq!(routed.proof.body_event_id, fx.body_event().await);
    assert_eq!(routed.proof.body_event_seq, fx.body_event_seq().await);
    assert_eq!(proof_snapshot(&routed.proof), client_snapshot(&a));

    // A rename moves the record's latest event but not its body event: a
    // joiner's base keeps naming the body-carrying one.
    fx.update(
        AGENT,
        json!({"id": fx.id, "reason": "rename", "name": "renamed"}),
    )
    .await
    .unwrap();
    assert_ne!(Some(fx.latest_event().await), fx.body_event().await);
    let (bob, b, joined) = fx.open_full(BOB, PeerKind::Edit).await;
    assert_eq!(joined.base.proof.body_event_id, fx.body_event().await);
    assert_eq!(joined.base.proof.body_event_seq, fx.body_event_seq().await);
    assert_eq!(proof_snapshot(&joined.base.proof), client_snapshot(&b));
    alice.leave().await;
    bob.leave().await;
}

#[tokio::test]
async fn an_absorbed_same_bytes_revision_refreshes_the_event_and_keeps_the_snapshot() {
    let fx = Fixture::new("Absorb").await;
    let (alice, a, opened) = fx.open_full(ALICE, PeerKind::Edit).await;
    let mut rx = alice.subscribe();
    let first = opened.base.proof.body_event_id.clone();
    let caller = Caller::authenticated(BOB);
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();
    let mut tx = write
        .open_absorbing(crate::db::enrolled::begin_document_write(&fx.db))
        .await
        .unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::store::append_in(
        &fx.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: fx.id.clone(),
            event_type: "record.updated".into(),
            payload: json!({"body": "Absorb", "reason": "same bytes"}),
            actor: Some(caller.actor().into()),
        },
        &mut act,
    )
    .await
    .unwrap();
    fx.db.commit_content(tx).await.unwrap();
    write.absorb_committed(&fx.db, &caller, "same bytes").await;
    let events = drain(&mut rx);
    let refreshed = versioned(&events)
        .pop()
        .expect("a new body event is announced");
    assert_ne!(refreshed.proof.body_event_id, first);
    assert_eq!(refreshed.proof.body_event_id, fx.body_event().await);
    assert_eq!(refreshed.proof.body_event_seq, fx.body_event_seq().await);
    assert_eq!(proof_snapshot(&refreshed.proof), client_snapshot(&a));
    assert_eq!(
        refreshed.proof.snapshot, opened.base.proof.snapshot,
        "doc unchanged"
    );

    // Absorbing again with no new revision announces nothing.
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();
    write.absorb_committed(&fx.db, &caller, "nothing new").await;
    assert!(versioned(&drain(&mut rx)).is_empty());
    alice.leave().await;
}

/// A clean join reads the session's own base under `ops`. If a body write
/// commits between the join's authorising read and its turn on `ops`, the join
/// must report that write's revision, not the older one it first read.
///
/// The join is started while a body write holds `ops`; the write commits a new
/// body and is absorbed; only then is `ops` released. Timing decides whether
/// the join had already read the old revision when the write committed, so this
/// can pass without exercising the interleaving, but it cannot fail spuriously.
#[tokio::test]
async fn a_clean_join_after_a_racing_body_write_reports_the_current_revision() {
    let fx = Fixture::new("Absorb").await;
    let (alice, a, first) = fx.open_full(ALICE, PeerKind::Edit).await;
    let mut rx = alice.subscribe();
    let caller = Caller::authenticated(BOB);
    let mut write = live::begin_body_write(&fx.db, &fx.id, &caller)
        .await
        .unwrap();
    write.begin_absorb(&fx.db, &caller).await.unwrap();

    let join = {
        let db = fx.db.clone();
        let id = fx.id.clone();
        tokio::spawn(async move {
            live::open(
                &db,
                &Caller::authenticated(ALICE),
                OpenRequest {
                    record_id: id,
                    mode: PeerKind::Edit,
                    resume_peer: None,
                },
            )
            .await
            .unwrap()
        })
    };
    // Let the join read the committed body and park on `ops`.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut tx = write
        .open_absorbing(crate::db::enrolled::begin_document_write(&fx.db))
        .await
        .unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::store::append_in(
        &fx.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: fx.id.clone(),
            event_type: "record.updated".into(),
            payload: json!({"body": "Absorb, then more", "reason": "racing write"}),
            actor: Some(caller.actor().into()),
        },
        &mut act,
    )
    .await
    .unwrap();
    fx.db.commit_content(tx).await.unwrap();
    write
        .absorb_committed(&fx.db, &caller, "racing write")
        .await;

    let (joiner, opened) = join.await.unwrap();
    let events = drain(&mut rx);
    deliver(&a, &alice, &events);
    assert_eq!(a.body(), "Absorb, then more");
    let announced = versioned(&events).pop().expect("the write is announced");
    assert_ne!(
        announced.proof.body_event_id,
        first.base.proof.body_event_id
    );
    // The joiner is told the new revision, with the snapshot of the doc it joins.
    assert_eq!(opened.base.body_sha256, announced.body_sha256);
    assert_eq!(opened.base.proof, announced.proof);
    assert_eq!(opened.base.proof.body_event_id, fx.body_event().await);
    assert_eq!(opened.base.proof.body_event_seq, fx.body_event_seq().await);
    let synced = Client::new(1, &opened.sync);
    assert_eq!(proof_snapshot(&opened.base.proof), client_snapshot(&synced));
    alice.leave().await;
    joiner.leave().await;
}

/// Span-map assertions shared by the authorship tests: the map tiles the
/// version body exactly (so concatenated span text equals the body and no
/// deleted text persisted), edges sit on character boundaries, and every
/// author reference resolves inside the map's own table.
fn assert_span_map_tiles(version: &Value) -> &Value {
    let body = version["body"].as_str().expect("version carries its body");
    let map = version
        .get("span_map")
        .expect("version carries its span map");
    assert_eq!(map["version"], 1, "span_map v1");
    assert_eq!(map["offset_kind"], "bytes");
    let authors = map["authors"].as_array().expect("author table");
    let spans = map["spans"].as_array().expect("spans");
    assert!(!spans.is_empty() || body.is_empty());
    let mut pos = 0usize;
    let mut rebuilt = String::new();
    for span in spans {
        let start = span[0].as_u64().expect("start") as usize;
        let end = span[1].as_u64().expect("end") as usize;
        let author = span[2].as_u64().expect("author") as usize;
        assert_eq!(start, pos, "spans tile without gaps");
        assert!(end > start && end <= body.len(), "span in range");
        assert!(
            body.is_char_boundary(start) && body.is_char_boundary(end),
            "span on character boundaries"
        );
        assert!(author < authors.len(), "author resolves in-table");
        rebuilt.push_str(&body[start..end]);
        pos = end;
    }
    assert_eq!(pos, body.len(), "spans cover the body");
    assert_eq!(rebuilt, body, "no deleted text persisted");
    map
}

fn span_author(map: &Value, index: usize) -> &Value {
    &map["authors"].as_array().expect("author table")[index]
}

#[tokio::test]
async fn span_map_tiles_two_peers_plus_routed_agent_across_cuts() {
    let fx = Fixture::new("Seed").await;
    let (alice, a) = fx.open(ALICE).await;
    let (bob, b) = fx.open(BOB).await;
    let mut arx = alice.subscribe();
    let mut brx = bob.subscribe();

    // Explicit cut: Alice's text over the seed.
    alice.apply("a1", &a.append(" A")).await.unwrap();
    deliver(&b, &bob, &drain(&mut brx));
    drain(&mut arx);
    alice.version("alice checkpoint").await.unwrap().unwrap();
    drain(&mut arx);
    drain(&mut brx);

    // Bob leaves while Alice remains: his unsaved text survives departure
    // and the next routed write flushes it before the agent's own version.
    bob.apply("b1", &b.append(" B")).await.unwrap();
    deliver(&a, &alice, &drain(&mut arx));
    drain(&mut brx);
    assert!(bob.leave().await.is_none(), "another editor remains");

    // Routed cut: the agent appends through update_record.
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(AGENT).with_channel(crate::provenance::Channel::Mcp),
            "update_record",
            json!({"id": fx.id, "reason": "agent append", "body_append": " R"}),
        )
        .await
        .unwrap();
    // Keep Alice's client converged as routed writes land: discarding these
    // broadcasts would leave her doc stale and corrupt her next edit's offsets.
    deliver(&a, &alice, &drain(&mut arx));

    // Routed replace deleting the seed: no prior text may survive anywhere.
    fx.tools
        .call(
            fx.db.clone(),
            Caller::authenticated(AGENT).with_channel(crate::provenance::Channel::Mcp),
            "update_record",
            json!({"id": fx.id, "reason": "drop seed",
                   "body_replace": [{"old": "Seed ", "new": ""}]}),
        )
        .await
        .unwrap();
    deliver(&a, &alice, &drain(&mut arx));

    // Flush cut: the long-lived idle timer was armed before earlier cuts.
    // Exercise idle separately with its period configured before the first op.
    assert_eq!(a.body(), "A B R");
    alice.apply("a2", &a.append("!")).await.unwrap();
    let flush = live::flush_database_for_test(&fx.db).await;
    assert_eq!(flush.flushed, 1);
    assert_eq!(flush.not_flushed, 0);

    // The last editor leaving dirty cuts a final version.
    alice.apply("a3", &a.append("?")).await.unwrap();
    let leave = alice.leave().await.expect("last editor cuts a version");
    assert_eq!(leave.reason, "session ended");

    let versions = fx.versions().await;
    assert_eq!(versions.len(), 6, "{versions:?}");
    for version in &versions {
        assert_span_map_tiles(version);
    }

    // v1 (explicit): seed is prior, Alice owns her append.
    assert_eq!(versions[0]["body"], "Seed A");
    let map = &versions[0]["span_map"];
    assert_eq!(map["spans"], json!([[0, 4, 0], [4, 6, 1]]));
    assert_eq!(span_author(map, 0)["type"], "prior_version");
    assert_eq!(span_author(map, 1)["principal"], json!(ALICE));

    // v2 (routed flush): only Bob is pending, but Alice's span survives.
    assert_eq!(versions[1]["body"], "Seed A B");
    assert_eq!(versions[1]["contributors"].as_array().unwrap().len(), 1);
    assert_eq!(versions[1]["contributors"][0]["principal"], json!(BOB));
    let map = &versions[1]["span_map"];
    assert_eq!(map["spans"], json!([[0, 4, 0], [4, 6, 1], [6, 8, 2]]));
    assert_eq!(span_author(map, 1)["principal"], json!(ALICE));
    assert_eq!(span_author(map, 2)["principal"], json!(BOB));

    // v3 (routed): the agent's append names the agent.
    assert_eq!(versions[2]["body"], "Seed A B R");
    assert_eq!(versions[2]["contributors"][0]["principal"], json!(AGENT));
    let map = &versions[2]["span_map"];
    assert_eq!(
        map["spans"],
        json!([[0, 4, 0], [4, 6, 1], [6, 8, 2], [8, 10, 3]])
    );
    assert_eq!(span_author(map, 3)["principal"], json!(AGENT));

    // v4 (routed replace): seed text deleted — no prior author anywhere,
    // survivors keep their original authors. The replace drops "Seed "
    // (bytes 0..5), so each surviving separator stays with the append that
    // inserted it: Alice [0,1), Bob [1,3), agent [3,5).
    assert_eq!(versions[3]["body"], "A B R");
    let map = &versions[3]["span_map"];
    assert_eq!(map["spans"], json!([[0, 1, 0], [1, 3, 1], [3, 5, 2]]));
    for author in map["authors"].as_array().unwrap() {
        assert_ne!(
            author["type"], "prior_version",
            "deleted seed leaves no prior span"
        );
    }
    assert_eq!(span_author(map, 0)["principal"], json!(ALICE));
    assert_eq!(span_author(map, 1)["principal"], json!(BOB));
    assert_eq!(span_author(map, 2)["principal"], json!(AGENT));

    // v5 (flush): Alice's bang closes the body under her name (author 0:
    // the table deduplicates her).
    assert_eq!(versions[4]["body"], "A B R!");
    let map = &versions[4]["span_map"];
    assert_eq!(
        map["spans"],
        json!([[0, 1, 0], [1, 3, 1], [3, 5, 2], [5, 6, 0]])
    );
    assert_eq!(span_author(map, 0)["principal"], json!(ALICE));

    // v6 (last-editor leave): Alice's adjacent punctuation coalesces.
    assert_eq!(versions[5]["body"], "A B R!?");
    let map = &versions[5]["span_map"];
    assert_eq!(
        map["spans"],
        json!([[0, 1, 0], [1, 3, 1], [3, 5, 2], [5, 7, 0]])
    );
    assert_eq!(span_author(map, 0)["principal"], json!(ALICE));

    // Minimal read: get_history with full detail surfaces the persisted map.
    let history = fx
        .tools
        .call(
            fx.db.clone(),
            Caller::authenticated(ALICE),
            "get_history",
            json!({"record_id": fx.id, "detail": "full"}),
        )
        .await
        .unwrap();
    let events = history["events"].as_array().expect("history events");
    let read: Vec<&Value> = events
        .iter()
        .filter(|event| event["payload"]["session"].is_string())
        .collect();
    assert_eq!(read.len(), 6);
    for event in read {
        assert_span_map_tiles(&event["payload"]);
    }
}

#[tokio::test]
async fn empty_run_key_caller_stays_cuttable() {
    // A trusted caller carrying an explicitly empty run key must normalize
    // to absent (like the m7 emitter), never acknowledge an edit its own
    // cut could not persist.
    let fx = Fixture::new("Seed").await;
    let caller = Caller::authenticated(ALICE).with_run_context(Some(String::new()), None);
    let (peer, opened) = live::open(
        &fx.db,
        &caller,
        OpenRequest {
            record_id: fx.id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    let client = Client::new(opened.doc_client_ids[0], &opened.sync);
    peer.apply("e1", &client.append(" x")).await.unwrap();
    peer.version("checkpoint").await.unwrap().unwrap();
    let versions = fx.versions().await;
    assert_eq!(versions.len(), 1, "{versions:?}");
    let map = assert_span_map_tiles(&versions[0]);
    assert_eq!(map["spans"], json!([[0, 4, 0], [4, 6, 1]]));
    assert!(
        !map.to_string().contains("run_key"),
        "empty run normalized to absent"
    );
    assert!(
        !versions[0]["contributors"].to_string().contains("run_key"),
        "m7 row matches the map author"
    );
    peer.leave().await;
}

/// Acknowledged text remains admitted work until its version is durable.
#[tokio::test]
async fn database_freeze_drains_acknowledged_dirty_text_and_leaves_other_sessions_writable() {
    struct DirtyHookGuard;
    impl Drop for DirtyHookGuard {
        fn drop(&mut self) {
            live::set_dirty_write_admission(None);
        }
    }
    let a = Fixture::new("Scoped A").await;
    let b = Fixture::new("Scoped B").await;
    let dir = tempfile::tempdir().unwrap();
    let store = crate::mcp::database_freeze::DatabaseFreezeStore::new(dir.path());
    let paths = [
        (a.db.live_session_key().to_owned(), "a"),
        (b.db.live_session_key().to_owned(), "b"),
    ];
    let admission = store.clone();
    live::set_dirty_write_admission(Some(std::sync::Arc::new(move |db| {
        let Some((_, id)) = paths.iter().find(|(path, _)| path == db.live_session_key()) else {
            return Some(Box::new(()) as Box<dyn Send>);
        };
        admission
            .admit(id)
            .unwrap()
            .map(|lease| Box::new(lease) as Box<dyn Send>)
    })));
    let _hook = DirtyHookGuard;
    let (alice, alice_doc) = a.open(ALICE).await;
    alice
        .apply("a1", &alice_doc.append(" admitted"))
        .await
        .unwrap();
    let worker = store.clone();
    let freeze = tokio::spawn(async move { worker.freeze("a").await.unwrap() });
    while !store.is_frozen("a").unwrap() {
        tokio::task::yield_now().await;
    }
    assert!(!freeze.is_finished());
    assert!(alice
        .apply("a2", &alice_doc.append(" refused"))
        .await
        .is_err());
    let (bob, bob_doc) = b.open(ALICE).await;
    bob.apply("b1", &bob_doc.append(" writable")).await.unwrap();
    bob.version("B stays writable").await.unwrap();
    alice.version("Finish A's admitted work").await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), freeze)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed_body_sync(a.db.path(), &a.id), "Scoped A admitted");
    assert_eq!(committed_body_sync(b.db.path(), &b.id), "Scoped B writable");
    store.unfreeze("a").unwrap();
    alice.leave().await;
    bob.leave().await;
}
