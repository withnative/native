//! In-process tests: `yrs` plays the client, the registry the server.

use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{
    Array, Doc, GetString, Map, OffsetKind, Options, ReadTxn, StateVector, Text, Transact, Update,
    WriteTxn,
};

use super::refusal::RefusalCode;
use super::registry::{
    Ack, AcknowledgedContributor, DrainOutcome, OpenParams, PeerKind, SessionRegistry,
    MAX_ATTRIBUTED_IDENTITIES, MAX_ATTRIBUTED_IDENTITY_BYTES, MAX_BODY_BYTES, MAX_UPDATE_BYTES,
};

/// One test client: a `yrs` doc synced from the server's sync-step-2.
struct Client {
    doc: Doc,
    client_id: u32,
}

impl Client {
    fn new(client_id: u32, sync_step2: &[u8]) -> Self {
        let mut options = Options::with_client_id(yrs::ClientID::new(u64::from(client_id)));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        doc.transact_mut()
            .apply_update(Update::decode_v1(sync_step2).expect("valid sync"))
            .expect("sync applies to a fresh client doc");
        Self { doc, client_id }
    }

    fn text(&self) -> yrs::TextRef {
        self.doc.get_or_insert_text("body")
    }

    fn state_vector(&self) -> Vec<u8> {
        self.doc.transact().state_vector().encode_v1()
    }

    fn body(&self) -> String {
        self.text().get_string(&self.doc.transact())
    }

    /// Update bytes carrying everything since `since_sv`.
    fn diff_since(&self, since_sv: &[u8]) -> Vec<u8> {
        let since = StateVector::decode_v1(since_sv).expect("valid sv");
        self.doc.transact().encode_diff_v1(&since)
    }
}

fn edit_params(body: &str, kind: PeerKind) -> OpenParams {
    OpenParams {
        database_id: "db-test".to_string(),
        record_id: "rec-test".to_string(),
        committed_body: body.to_string(),
        kind,
        record_supported: true,
    }
}

fn open_edit(reg: &mut SessionRegistry, body: &str) -> (Client, AckInfo) {
    let opened = reg.open(edit_params(body, PeerKind::Edit)).expect("open");
    let client = Client::new(opened.client_ids[0], &opened.sync_step2);
    (
        client,
        AckInfo {
            session_id: opened.session_id,
            peer_id: opened.peer_id,
        },
    )
}

struct AckInfo {
    session_id: super::registry::SessionId,
    peer_id: super::registry::PeerId,
}

#[test]
fn two_peers_concurrent_edits_converge_to_exact_bytes() {
    let mut reg = SessionRegistry::new();
    // Non-overlapping edits: deterministic regardless of CRDT tie-breaks.
    let (a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(OpenParams {
            database_id: "db-test".to_string(),
            record_id: "rec-test".to_string(),
            committed_body: "IGNORED-live-state-wins".to_string(),
            kind: PeerKind::Edit,
            record_supported: true,
        })
        .expect("second joiner");
    let b = Client::new(opened_b.client_ids[0], &opened_b.sync_step2);
    assert_eq!(b.body(), "hello", "joiner gets live state, not the seed");

    let a_sv = a.state_vector();
    {
        let text = a.text();
        let mut txn = a.doc.transact_mut();
        text.insert(&mut txn, 0, "A");
    }
    let b_sv = b.state_vector();
    {
        let text = b.text();
        let mut txn = b.doc.transact_mut();
        text.insert(&mut txn, 5, "B");
    }
    let ack_a: Ack = reg
        .apply_update(&a_info.session_id, &a_info.peer_id, &a.diff_since(&a_sv))
        .expect("a applies");
    let ack_b: Ack = reg
        .apply_update(
            &opened_b.session_id,
            &opened_b.peer_id,
            &b.diff_since(&b_sv),
        )
        .expect("b applies");
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "AhelloB");
    // Broadcasts replay onto the other peer: all three replicas agree.
    for (client, ack) in [(&b, &ack_a), (&a, &ack_b)] {
        client
            .doc
            .transact_mut()
            .apply_update(Update::decode_v1(&ack.broadcast).expect("valid"))
            .expect("broadcast applies");
    }
    assert_eq!(a.body(), "AhelloB");
    assert_eq!(b.body(), "AhelloB");
}

#[test]
fn foreign_client_id_is_refused_and_doc_unchanged() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("b joins");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");

    // B authors with A's leased client id.
    let impostor = Client::new(a.client_id, &opened_b.sync_step2);
    let base_sv = impostor.state_vector();
    {
        let text = impostor.text();
        let mut txn = impostor.doc.transact_mut();
        text.insert(&mut txn, 5, "EVIL");
    }
    let evil = impostor.diff_since(&base_sv);
    let refused = reg
        .apply_update(&opened_b.session_id, &opened_b.peer_id, &evil)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::ForeignClientId);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
    assert_eq!(a.body(), "hello");
}

#[test]
fn all_three_pool_ids_can_author_for_their_own_edit_peer() {
    let mut reg = SessionRegistry::new();
    let opened = reg.open(edit_params("hello", PeerKind::Edit)).unwrap();
    assert_eq!(opened.client_ids.len(), 3);
    for (i, id) in opened.client_ids.iter().enumerate() {
        let c = Client::new(*id, &opened.sync_step2);
        let sv = c.state_vector();
        c.text().insert(&mut c.doc.transact_mut(), 0, "x");
        reg.apply_update(&opened.session_id, &opened.peer_id, &c.diff_since(&sv))
            .expect("every pool member belongs to this edit peer");
        assert_eq!(
            reg.live_body(&opened.session_id).unwrap(),
            format!("{}hello", "x".repeat(i + 1))
        );
    }
}

#[test]
fn resending_known_structs_is_idempotent() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let base_sv = a.state_vector();
    {
        let text = a.text();
        let mut txn = a.doc.transact_mut();
        text.insert(&mut txn, 5, "!");
    }
    let update = a.diff_since(&base_sv);
    reg.apply_update(&a_info.session_id, &a_info.peer_id, &update)
        .expect("first apply");
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "hello!");
    // Same bytes again: all structs already integrated, accepted as no-op.
    reg.apply_update(&a_info.session_id, &a_info.peer_id, &update)
        .expect("resend accepted");
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "hello!");
}

#[test]
fn second_root_is_refused_bad_doc_shape() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    let base_sv = a.state_vector();
    {
        let mut txn = a.doc.transact_mut();
        let map = txn.get_or_insert_map("x");
        map.insert(&mut txn, "k", "v");
    }
    let bad = a.diff_since(&base_sv);
    let refused = reg
        .apply_update(&a_info.session_id, &a_info.peer_id, &bad)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
}

#[test]
fn hostile_non_text_body_is_refused_bad_doc_shape() {
    let mut reg = SessionRegistry::new();
    let (_a, a_info) = open_edit(&mut reg, "hello");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    // Hostile client: fresh doc that never synced, map root named `body`.
    let hostile = Doc::with_client_id(0xbeef);
    {
        let mut txn = hostile.transact_mut();
        let map = txn.get_or_insert_map("body");
        map.insert(&mut txn, "k", "v");
    }
    let bad = hostile
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    let refused = reg
        .apply_update(&a_info.session_id, &a_info.peer_id, &bad)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
}

#[test]
fn hostile_map_body_with_leased_id_is_still_bad_doc_shape() {
    // Same attack, but authored with a legitimately leased client id, so
    // authorship checks pass and only the shape check can catch it: yrs
    // merges the map entries into the text branch's map slots invisibly.
    let mut reg = SessionRegistry::new();
    let (_a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("b joins");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let hostile = Doc::with_client_id(u64::from(opened_b.client_ids[0]));
    {
        let mut txn = hostile.transact_mut();
        let map = txn.get_or_insert_map("body");
        map.insert(&mut txn, "k", "v");
    }
    let bad = hostile
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    let refused = reg
        .apply_update(&opened_b.session_id, &opened_b.peer_id, &bad)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
}

fn edit_params_rec(record: &str, body: &str, kind: PeerKind) -> OpenParams {
    OpenParams {
        database_id: "db-test".to_string(),
        record_id: record.to_string(),
        committed_body: body.to_string(),
        kind,
        record_supported: true,
    }
}

/// Apply one client edit and return the server's new live body.
fn apply_edit(
    reg: &mut SessionRegistry,
    info: &AckInfo,
    c: &Client,
    edit: impl FnOnce(&mut yrs::TransactionMut, yrs::TextRef),
) -> String {
    let text = c.text();
    let sv = c.state_vector();
    {
        let mut txn = c.doc.transact_mut();
        edit(&mut txn, text);
    }
    reg.apply_update(&info.session_id, &info.peer_id, &c.diff_since(&sv))
        .expect("conformance edit applies");
    reg.live_body(&info.session_id).expect("live")
}

#[test]
fn open_refuses_body_over_1mib() {
    let mut reg = SessionRegistry::new();
    let big = "x".repeat(MAX_BODY_BYTES + 1);
    let refused = reg
        .open(edit_params(&big, PeerKind::Edit))
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::TooLarge);
}

#[test]
fn update_over_64kib_is_refused_whole() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let base_sv = a.state_vector();
    {
        let text = a.text();
        let mut txn = a.doc.transact_mut();
        text.insert(&mut txn, 5, &"y".repeat(70_000));
    }
    let big = a.diff_since(&base_sv);
    assert!(
        big.len() > MAX_UPDATE_BYTES,
        "test update must exceed the cap"
    );
    let refused = reg
        .apply_update(&a_info.session_id, &a_info.peer_id, &big)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::TooLarge);
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "hello");
}

#[test]
fn resulting_body_over_1mib_is_refused() {
    let mut reg = SessionRegistry::new();
    let seed = "x".repeat(MAX_BODY_BYTES - 10);
    let opened = reg.open(edit_params(&seed, PeerKind::Edit)).expect("open");
    let info = AckInfo {
        session_id: opened.session_id,
        peer_id: opened.peer_id,
    };
    let c = Client::new(opened.client_ids[0], &opened.sync_step2);
    let base_sv = c.state_vector();
    {
        let text = c.text();
        let mut txn = c.doc.transact_mut();
        text.insert(&mut txn, 0, &"y".repeat(20));
    }
    let update = c.diff_since(&base_sv);
    assert!(update.len() <= MAX_UPDATE_BYTES, "update itself is small");
    let refused = reg
        .apply_update(&info.session_id, &info.peer_id, &update)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::TooLarge);
    assert_eq!(reg.live_body(&info.session_id).expect("live"), seed);
}

#[test]
fn pending_forgery_is_refused_and_never_integrates() {
    use yrs::{ClientID, StateVector};
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("b joins");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    // B forges a struct authored by A (A's leased id) whose origin is a
    // clock A has not sent: hostile doc keyed to A's client id makes two
    // inserts, but only the second block ships, so (X,0) is missing
    // server-side and the struct would park as pending.
    let hostile = Doc::with_client_id(u64::from(a.client_id));
    let htext = hostile.get_or_insert_text("body");
    {
        let mut txn = hostile.transact_mut();
        htext.insert(&mut txn, 0, "A");
        htext.insert(&mut txn, 1, "B");
    }
    let mut only_second = StateVector::default();
    only_second.set_max(ClientID::new(u64::from(a.client_id)), 1);
    let forged = hostile.transact().encode_diff_v1(&only_second);
    let refused = reg
        .apply_update(&opened_b.session_id, &opened_b.peer_id, &forged)
        .expect_err("forgery must be refused");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
    // A's legitimate update integrates cleanly and carries no trace of B:
    // had the forgery parked, A's (X,0) arrival would integrate it.
    let base_sv = a.state_vector();
    {
        let text = a.text();
        let mut txn = a.doc.transact_mut();
        text.insert(&mut txn, 5, "!");
    }
    reg.apply_update(&a_info.session_id, &a_info.peer_id, &a.diff_since(&base_sv))
        .expect("A applies");
    let live = reg.live_body(&a_info.session_id).expect("live");
    assert_eq!(live, "hello!");
}

#[test]
fn reseed_uses_fresh_ids_and_stale_state_merges() {
    use std::collections::HashSet;
    use yrs::updates::decoder::Decode;
    fn sv_clients(sv: &[u8]) -> HashSet<u64> {
        StateVector::decode_v1(sv)
            .expect("valid sv")
            .iter()
            .map(|(c, _)| c.get())
            .collect()
    }
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "v1-body");
    let live = apply_edit(&mut reg, &a_info, &a, |txn, t| t.insert(txn, 7, "!"));
    assert_eq!(live, "v1-body!");
    let old_sv = reg.state_vector(&a_info.session_id).expect("sv");
    // Last peer leaves: the session (and its seed ids) is dropped.
    assert!(reg.leave(&a_info.session_id, &a_info.peer_id));
    // Re-open with a DIFFERENT committed body: a new session, new seed.
    let reopened = reg
        .open(edit_params("v2-body-longer", PeerKind::Edit))
        .expect("reopen");
    assert_ne!(reopened.session_id, a_info.session_id);
    let new_sv = reg.state_vector(&reopened.session_id).expect("sv");
    assert!(
        sv_clients(&old_sv).is_disjoint(&sv_clients(&new_sv)),
        "re-seed must not reuse struct ids"
    );
    // A stale client that keeps old state and applies the new full sync
    // merges both histories and diverges: it must discard instead.
    a.doc
        .transact_mut()
        .apply_update(Update::decode_v1(&reopened.sync_step2).expect("valid"))
        .expect("sync applies");
    assert!(
        a.body().contains("v1-body"),
        "stale half retained: {}",
        a.body()
    );
    assert_ne!(a.body(), "v2-body-longer");
    // A client that discards (fresh doc) lands exactly on the new body.
    let fresh = Client::new(reopened.client_ids[0], &reopened.sync_step2);
    assert_eq!(fresh.body(), "v2-body-longer");
    assert_eq!(
        reg.live_body(&reopened.session_id).expect("live"),
        "v2-body-longer"
    );
}

#[test]
fn embed_on_body_is_refused() {
    let mut reg = SessionRegistry::new();
    let (_a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("b joins");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    let m = Client::new(opened_b.client_ids[0], &opened_b.sync_step2);
    let text = m.text();
    let base = m.state_vector();
    {
        let mut txn = m.doc.transact_mut();
        text.insert_embed(&mut txn, 5, vec![7u8, 8, 9]);
    }
    let refused = reg
        .apply_update(
            &opened_b.session_id,
            &opened_b.peer_id,
            &m.diff_since(&base),
        )
        .expect_err("embed must be refused");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
}

#[test]
fn array_item_on_body_is_refused() {
    let mut reg = SessionRegistry::new();
    let (_a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("b joins");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    let m = Client::new(opened_b.client_ids[0], &opened_b.sync_step2);
    let base = m.state_vector();
    {
        let mut txn = m.doc.transact_mut();
        let arr = txn.get_or_insert_array("body");
        arr.insert(&mut txn, 0, 42);
    }
    let refused = reg
        .apply_update(
            &opened_b.session_id,
            &opened_b.peer_id,
            &m.diff_since(&base),
        )
        .expect_err("array item must be refused");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
}

#[test]
fn format_attribute_on_body_is_refused() {
    use yrs::types::Attrs;
    let mut reg = SessionRegistry::new();
    let (_a, a_info) = open_edit(&mut reg, "hello");
    let opened_b = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("b joins");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    let m = Client::new(opened_b.client_ids[0], &opened_b.sync_step2);
    let text = m.text();
    let base = m.state_vector();
    {
        let mut txn = m.doc.transact_mut();
        text.format(&mut txn, 0, 5, Attrs::from([("b".into(), true.into())]));
    }
    let refused = reg
        .apply_update(
            &opened_b.session_id,
            &opened_b.peer_id,
            &m.diff_since(&base),
        )
        .expect_err("format attribute must be refused");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
}

#[test]
fn byte_offsets_conform_on_emoji_cjk_combining_crlf() {
    let mut reg = SessionRegistry::new();
    let opened = reg
        .open(edit_params_rec("rec-bytes", "", PeerKind::Edit))
        .expect("open");
    let info = AckInfo {
        session_id: opened.session_id,
        peer_id: opened.peer_id,
    };
    let c = Client::new(opened.client_ids[0], &opened.sync_step2);

    // Astral-plane emoji: "a😀b" is 6 bytes; insert between a and 😀.
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.insert(txn, 0, "a😀b")),
        "a😀b"
    );
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.insert(txn, 1, "X")),
        "aX😀b"
    );
    // Delete exactly the 4 emoji bytes.
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.remove_range(txn, 2, 4)),
        "aXb"
    );
    // CJK (3 bytes each): insert after X, delete the first one by bytes.
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.insert(txn, 2, "日本")),
        "aX日本b"
    );
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.remove_range(txn, 2, 3)),
        "aX本b"
    );
    // Combining mark: e + U+0301 is 3 bytes; append at byte 6.
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.insert(txn, 6, "é")),
        "aX本bé"
    );
    // CRLF: insert at 0, then delete only the LF byte.
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.insert(txn, 0, "\r\n")),
        "\r\naX本bé"
    );
    assert_eq!(
        apply_edit(&mut reg, &info, &c, |txn, t| t.remove_range(txn, 1, 1)),
        "\raX本bé"
    );
}

#[test]
fn view_peer_updates_are_forbidden() {
    let mut reg = SessionRegistry::new();
    let opened = reg
        .open(edit_params("hello", PeerKind::View))
        .expect("view joins");
    let c = Client::new(opened.client_ids[0], &opened.sync_step2);
    let base_sv = c.state_vector();
    {
        let text = c.text();
        let mut txn = c.doc.transact_mut();
        text.insert(&mut txn, 5, "!");
    }
    let refused = reg
        .apply_update(&opened.session_id, &opened.peer_id, &c.diff_since(&base_sv))
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::Forbidden);
    assert_eq!(reg.live_body(&opened.session_id).expect("live"), "hello");
}

#[test]
fn unknown_session_or_peer_is_undeclared() {
    use super::registry::{PeerId, SessionId};
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let base_sv = a.state_vector();
    let update = a.diff_since(&base_sv); // empty but well-formed
    let ghost_session = SessionId("sess-ghost".to_string());
    let refused = reg
        .apply_update(&ghost_session, &a_info.peer_id, &update)
        .expect_err("ghost session");
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
    let ghost_peer = PeerId("peer-ghost".to_string());
    let refused = reg
        .apply_update(&a_info.session_id, &ghost_peer, &update)
        .expect_err("ghost peer");
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
    assert!(reg.live_body(&ghost_session).is_err());
}

#[test]
fn peer_caps_are_enforced_per_record() {
    let mut reg = SessionRegistry::new();
    for _ in 0..16 {
        reg.open(edit_params_rec("rec-caps", "hi", PeerKind::Edit))
            .expect("up to 16 edit peers");
    }
    let refused = reg
        .open(edit_params_rec("rec-caps", "hi", PeerKind::Edit))
        .expect_err("17th edit peer");
    assert_eq!(refused.code, RefusalCode::TooManyPeers);
    for _ in 0..32 {
        reg.open(edit_params_rec("rec-caps", "hi", PeerKind::View))
            .expect("up to 32 view peers");
    }
    let refused = reg
        .open(edit_params_rec("rec-caps", "hi", PeerKind::View))
        .expect_err("33rd view peer");
    assert_eq!(refused.code, RefusalCode::TooManyPeers);
}

#[test]
fn unsupported_record_is_refused_without_creating_a_session() {
    let mut reg = SessionRegistry::new();
    let refused = reg
        .open(OpenParams {
            record_supported: false,
            ..edit_params("hello", PeerKind::Edit)
        })
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::RecordUnsupported);
    // Nothing was created: a supported open seeds fresh from its own body.
    let opened = reg
        .open(edit_params("hello", PeerKind::Edit))
        .expect("open");
    assert_eq!(reg.live_body(&opened.session_id).expect("live"), "hello");
}

#[test]
fn leased_client_ids_are_unique_and_never_reissued() {
    let mut reg = SessionRegistry::new();
    let mut ids = Vec::new();
    let mut infos = Vec::new();
    for i in 0..4 {
        let opened = reg
            .open(edit_params_rec(
                &format!("rec-lease-{i}"),
                "hi",
                if i % 2 == 0 {
                    PeerKind::Edit
                } else {
                    PeerKind::View
                },
            ))
            .expect("open");
        assert_eq!(opened.client_ids.len(), 3);
        assert!(opened
            .client_ids
            .windows(2)
            .all(|pair| pair[1] == pair[0] + 1));
        ids.extend(opened.client_ids.iter().copied());
        infos.push((opened.session_id, opened.peer_id));
    }
    // Joining an existing room with another kind gets a disjoint full pool.
    let joined = reg
        .open(edit_params_rec("rec-lease-0", "ignored", PeerKind::View))
        .unwrap();
    assert_eq!(joined.client_ids.len(), 3);
    ids.extend(joined.client_ids.iter().copied());
    assert!(reg.leave(&joined.session_id, &joined.peer_id));
    // Leaving frees the seat but must not recycle the pool.
    assert!(reg.leave(&infos[0].0, &infos[0].1));
    let reopened = reg
        .open(edit_params_rec("rec-lease-0", "hi", PeerKind::Edit))
        .expect("reopen");
    assert_eq!(reopened.client_ids.len(), 3);
    ids.extend(reopened.client_ids.iter().copied());
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "every leased id is unique");
}

#[test]
fn partially_valid_update_is_refused_whole() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    // One transaction carrying a valid text insert plus a hostile second
    // root: the valid half must not land when the update is refused.
    let text = a.text();
    let base = a.state_vector();
    {
        let mut txn = a.doc.transact_mut();
        text.insert(&mut txn, 5, "!");
        let map = txn.get_or_insert_map("x");
        map.insert(&mut txn, "k", "v");
    }
    let refused = reg
        .apply_update(&a_info.session_id, &a_info.peer_id, &a.diff_since(&base))
        .expect_err("mixed update must be refused");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
    assert_eq!(before_body, "hello");
}

#[test]
fn joiner_oversized_body_is_ignored_when_session_exists() {
    let mut reg = SessionRegistry::new();
    let (_a, a_info) = open_edit(&mut reg, "hi");
    // The session exists, so the (ignored) committed body is not measured —
    // only seeding reads it.
    let big = "x".repeat(MAX_BODY_BYTES + 1);
    let joined = reg
        .open(edit_params(&big, PeerKind::View))
        .expect("join ok");
    assert_eq!(joined.session_id, a_info.session_id);
    assert_eq!(reg.live_body(&joined.session_id).expect("live"), "hi");
}

#[test]
fn resync_state_vector_and_diff_replay_live_state() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let after_open_sv = a.state_vector();
    {
        let text = a.text();
        let mut txn = a.doc.transact_mut();
        text.insert(&mut txn, 5, " world");
    }
    reg.apply_update(
        &a_info.session_id,
        &a_info.peer_id,
        &a.diff_since(&after_open_sv),
    )
    .expect("edit applies");
    // A fresh client replays everything since the empty vector.
    let empty = StateVector::default().encode_v1();
    let full = reg
        .encode_diff(&a_info.session_id, &empty)
        .expect("diff since empty");
    let late = Doc::with_client_id(0x1a7e);
    late.transact_mut()
        .apply_update(Update::decode_v1(&full).expect("valid"))
        .expect("replay applies");
    let body = late.get_or_insert_text("body").get_string(&late.transact());
    assert_eq!(body, "hello world");
    // A client already caught up gets an empty (accepted) diff.
    let current = reg.state_vector(&a_info.session_id).expect("sv");
    let nothing = reg
        .encode_diff(&a_info.session_id, &current)
        .expect("diff since current");
    assert!(Update::decode_v1(&nothing).expect("valid").is_empty());
}

fn pair(principal: &str, executor_kind: &str) -> AcknowledgedContributor {
    AcknowledgedContributor {
        principal: principal.into(),
        executor_kind: executor_kind.into(),
    }
}

/// Update bytes for one client edit (the caller applies them, possibly as
/// another contributor, to pin replay semantics).
fn edit_bytes(c: &Client, edit: impl FnOnce(&mut yrs::TransactionMut, yrs::TextRef)) -> Vec<u8> {
    let sv = c.state_vector();
    {
        let text = c.text();
        let mut txn = c.doc.transact_mut();
        edit(&mut txn, text);
    }
    c.diff_since(&sv)
}

fn ledger(reg: &SessionRegistry, info: &AckInfo) -> Vec<AcknowledgedContributor> {
    reg.acknowledged_contributors(&info.session_id)
        .expect("readout")
}

fn last(reg: &SessionRegistry, info: &AckInfo) -> Option<AcknowledgedContributor> {
    reg.last_accepted_contributor(&info.session_id)
        .expect("readout")
}

#[test]
fn attributed_accepted_edit_stamps_pair_and_last() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let update = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice.clone()));

    let (b, b_info) = open_edit(&mut reg, "hello!");
    assert_eq!(b_info.session_id, a_info.session_id);
    let bob = pair("bob", "agent");
    let b_update = edit_bytes(&b, |txn, text| text.insert(txn, 6, "?"));
    reg.apply_update_attributed(&b_info.session_id, &b_info.peer_id, &b_update, &bob)
        .expect("applies");
    assert_eq!(ledger(&reg, &a_info), vec![alice, bob.clone()]);
    assert_eq!(last(&reg, &a_info), Some(bob));
}

#[test]
fn attributed_delete_only_update_stamps() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let update = edit_bytes(&a, |txn, text| text.remove_range(txn, 0, 1));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "ello");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
}

#[test]
fn attributed_insert_delete_net_zero_stamps_on_clock_advance() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    // Insert then remove in one transaction: visible body is unchanged but
    // the insert's clocks still land, so the op counts as authored.
    let update = edit_bytes(&a, |txn, text| {
        text.insert(txn, 5, "xy");
        text.remove_range(txn, 5, 2);
    });
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "hello");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
}

#[test]
fn exact_duplicate_replay_records_nothing() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let mallory = pair("mallory", "agent");
    let update = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    // Same bytes again as a different identity: still acknowledged (the
    // existing idempotence contract) but records nothing.
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &mallory)
        .expect("resend accepted");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
}

#[test]
fn empty_diff_replay_records_nothing() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let mallory = pair("mallory", "agent");
    let update = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    // A client already caught up sends an empty (accepted) diff: distinct
    // bytes, zero new state, no attribution.
    let nothing = a.diff_since(&a.state_vector());
    assert!(Update::decode_v1(&nothing).expect("valid").is_empty());
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &nothing, &mallory)
        .expect("empty diff accepted");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
}

#[test]
fn duplicate_delete_replay_records_nothing() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let mallory = pair("mallory", "agent");
    let delete = edit_bytes(&a, |txn, text| text.remove_range(txn, 0, 1));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &delete, &alice)
        .expect("applies");
    // The same delete bytes again: already-deleted ranges contribute
    // nothing to the transaction delete set, so no new authorship.
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &delete, &mallory)
        .expect("delete replay accepted");
    assert_eq!(reg.live_body(&a_info.session_id).expect("live"), "ello");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
}

#[test]
fn foreign_replays_refuse_without_attribution() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let update = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    let (_b, b_info) = open_edit(&mut reg, "hello!");
    let mallory = pair("mallory", "agent");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");

    // B replays A's already-integrated bytes: authors nothing new, so the
    // replay is acknowledged as a no-op and records no relay identity.
    reg.apply_update_attributed(&b_info.session_id, &b_info.peer_id, &update, &mallory)
        .expect("replay accepted");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice.clone()));
    // A full-state sync of fully-known state (seed included) is likewise an
    // accepted no-op with no attribution.
    let full = a
        .doc
        .transact()
        .encode_state_as_update_v1(&StateVector::default());
    reg.apply_update_attributed(&b_info.session_id, &b_info.peer_id, &full, &mallory)
        .expect("known-state sync accepted");
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice.clone()));
    // Forging NEW structs under A's client id as B is refused outright.
    let full_now = reg
        .encode_diff(&a_info.session_id, &StateVector::default().encode_v1())
        .expect("full state");
    let impostor = Client::new(a.client_id, &full_now);
    let evil = edit_bytes(&impostor, |txn, text| text.insert(txn, 5, "EVIL"));
    let refused = reg
        .apply_update_attributed(&b_info.session_id, &b_info.peer_id, &evil, &mallory)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::ForeignClientId);
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
}

#[test]
fn refused_and_view_updates_leave_ledger_and_last_untouched() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let update = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    let mallory = pair("mallory", "agent");
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");

    // Undecodable bytes with attribution: shape refusal, nothing recorded.
    let refused = reg
        .apply_update_attributed(&a_info.session_id, &a_info.peer_id, &[0xff, 0x00], &mallory)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::BadDocShape);
    // View-mode peers cannot author, attributed or not.
    let viewer = reg
        .open(edit_params("hello!", PeerKind::View))
        .expect("viewer joins");
    let view_update = edit_bytes(&a, |txn, text| text.insert(txn, 0, "V"));
    let refused = reg
        .apply_update_attributed(&viewer.session_id, &viewer.peer_id, &view_update, &mallory)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::Forbidden);
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);
    assert_eq!(last(&reg, &a_info), Some(alice));
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
}

#[test]
fn ledger_dedups_sorts_and_repeat_author_refreshes_last() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    // Insertion order is zeta-then-alpha; readout must be sorted.
    let zeta = pair("zeta", "human");
    let alpha = pair("alpha", "agent");
    for (fact, suffix) in [(&zeta, "1"), (&alpha, "2"), (&zeta, "3")] {
        let update = edit_bytes(&a, |txn, text| {
            text.insert(txn, 5, suffix);
        });
        reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, fact)
            .expect("applies");
    }
    assert_eq!(ledger(&reg, &a_info), vec![alpha, zeta.clone()]);
    // Same author again with new state still refreshes last-accepted.
    assert_eq!(last(&reg, &a_info), Some(zeta));
}

#[test]
fn leave_keeps_ledger_terminal_teardown_drops_session() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let update = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &alice)
        .expect("applies");
    let (b, b_info) = open_edit(&mut reg, "hello!");
    let bob = pair("bob", "agent");
    let b_update = edit_bytes(&b, |txn, text| text.insert(txn, 6, "?"));
    reg.apply_update_attributed(&b_info.session_id, &b_info.peer_id, &b_update, &bob)
        .expect("applies");
    // Non-terminal leave: landed contributors persist while the session lives.
    assert!(reg.leave(&a_info.session_id, &a_info.peer_id));
    assert_eq!(ledger(&reg, &b_info), vec![alice.clone(), bob.clone()]);
    assert_eq!(last(&reg, &b_info), Some(bob));
    // Terminal teardown drops doc and ledger whole (ephemeral inc1); the
    // future version owner must cut/extract before the last leave.
    assert!(reg.leave(&b_info.session_id, &b_info.peer_id));
    let refused = reg
        .acknowledged_contributors(&b_info.session_id)
        .expect_err("session is gone");
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
    let refused = reg
        .last_accepted_contributor(&b_info.session_id)
        .expect_err("session is gone");
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
}

#[test]
fn unknown_session_readouts_refuse_undeclared_session() {
    let reg = SessionRegistry::new();
    let missing = super::registry::SessionId("sess-missing".into());
    let refused = reg
        .acknowledged_contributors(&missing)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
    let refused = reg
        .last_accepted_contributor(&missing)
        .expect_err("must refuse");
    assert_eq!(refused.code, RefusalCode::UndeclaredSession);
}

#[test]
fn quota_count_refuses_new_pair_atomically() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "");
    for i in 0..MAX_ATTRIBUTED_IDENTITIES {
        let fact = pair(&format!("q{i:04}"), "human");
        let update = edit_bytes(&a, |txn, text| {
            text.insert(txn, 0, "x");
        });
        reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &fact)
            .expect("ledger has room");
    }
    assert_eq!(ledger(&reg, &a_info).len(), MAX_ATTRIBUTED_IDENTITIES);
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    let before_last = last(&reg, &a_info);

    // One more distinct identity with new state: exact atomic refusal.
    let overflow = pair("overflow", "human");
    let update = edit_bytes(&a, |txn, text| {
        text.insert(txn, 0, "x");
    });
    let refused = reg
        .apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &overflow)
        .expect_err("count budget exhausted");
    assert_eq!(refused.code, RefusalCode::TooLarge);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
    assert_eq!(ledger(&reg, &a_info).len(), MAX_ATTRIBUTED_IDENTITIES);
    assert_eq!(last(&reg, &a_info), before_last);

    // The refused apply left the client's clock ahead of confirmed state
    // (real refusal-rebuild semantics): resync before authoring again.
    let full_now = reg
        .encode_diff(&a_info.session_id, &StateVector::default().encode_v1())
        .expect("full state");
    let a = Client::new(a.client_id, &full_now);
    // An already-ledgered identity with new state needs no new quota.
    let existing = pair("q0000", "human");
    let update = edit_bytes(&a, |txn, text| {
        text.insert(txn, 0, "x");
    });
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &existing)
        .expect("existing identity accepted at cap");
    assert_eq!(ledger(&reg, &a_info).len(), MAX_ATTRIBUTED_IDENTITIES);
    assert_eq!(last(&reg, &a_info), Some(existing));

    // A no-op with a new identity needs no quota either — and records nothing.
    let nothing = a.diff_since(&a.state_vector());
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &nothing, &overflow)
        .expect("no-op accepted at cap");
    assert_eq!(ledger(&reg, &a_info).len(), MAX_ATTRIBUTED_IDENTITIES);
    assert!(!ledger(&reg, &a_info).contains(&overflow));
}

#[test]
fn quota_bytes_refuse_new_pair_atomically() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "");
    // 64 entries x (1019 + 5) bytes hit the byte budget exactly.
    for i in 0..64 {
        let principal = format!("byte-{i:04}-{}", "x".repeat(1019 - 10));
        assert_eq!(principal.len(), 1019);
        let fact = pair(&principal, "human");
        let update = edit_bytes(&a, |txn, text| {
            text.insert(txn, 0, "x");
        });
        reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &fact)
            .expect("byte budget has room");
    }
    assert_eq!(ledger(&reg, &a_info).len(), 64);
    let budgeted: usize = ledger(&reg, &a_info)
        .iter()
        .map(|fact| fact.principal.len() + fact.executor_kind.len())
        .sum();
    assert_eq!(budgeted, MAX_ATTRIBUTED_IDENTITY_BYTES);
    let before_body = reg.live_body(&a_info.session_id).expect("live");
    let before_sv = reg.state_vector(&a_info.session_id).expect("sv");
    let before_last = last(&reg, &a_info);

    let overflow = pair("overflow", "human");
    let update = edit_bytes(&a, |txn, text| {
        text.insert(txn, 0, "x");
    });
    let refused = reg
        .apply_update_attributed(&a_info.session_id, &a_info.peer_id, &update, &overflow)
        .expect_err("byte budget exhausted");
    assert_eq!(refused.code, RefusalCode::TooLarge);
    assert_eq!(
        reg.live_body(&a_info.session_id).expect("live"),
        before_body
    );
    assert_eq!(reg.state_vector(&a_info.session_id).expect("sv"), before_sv);
    assert_eq!(ledger(&reg, &a_info).len(), 64);
    assert_eq!(last(&reg, &a_info), before_last);
}

#[test]
fn snapshot_captures_facts_and_is_immutable_under_later_applies() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let first = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &first, &alice)
        .expect("attributed apply");
    let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
    assert_eq!(snapshot.session_id(), &a_info.session_id);
    assert_eq!(snapshot.body(), "hello!");
    assert_eq!(snapshot.contributors(), std::slice::from_ref(&alice));
    assert_eq!(snapshot.last_accepted(), Some(&alice));

    // A later local apply and a later remote apply must not change it.
    let second = edit_bytes(&a, |txn, text| text.insert(txn, 6, "?"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &second, &alice)
        .expect("later local apply");
    let (b, b_info) = open_edit(&mut reg, "hello!?");
    let bob = pair("bob", "agent");
    let remote = edit_bytes(&b, |txn, text| text.insert(txn, 7, "."));
    reg.apply_update_attributed(&b_info.session_id, &b_info.peer_id, &remote, &bob)
        .expect("later remote apply");
    assert_eq!(snapshot.body(), "hello!");
    assert_eq!(snapshot.contributors(), std::slice::from_ref(&alice));
    assert_eq!(snapshot.last_accepted(), Some(&alice));
}

#[test]
fn snapshot_unknown_session_refuses_undeclared_session() {
    let reg = SessionRegistry::new();
    let missing = super::registry::SessionId("sess-missing".into());
    let error = reg
        .version_snapshot(&missing)
        .err()
        .expect("unknown session is refused");
    assert_eq!(error.code, RefusalCode::UndeclaredSession);
}

#[test]
fn drain_removes_contributors_retains_last_and_is_repeatable() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let bob = pair("bob", "agent");
    let u1 = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u1, &alice)
        .expect("apply");
    let (b, b_info) = open_edit(&mut reg, "hello!");
    let u2 = edit_bytes(&b, |txn, text| text.insert(txn, 6, "?"));
    reg.apply_update_attributed(&b_info.session_id, &b_info.peer_id, &u2, &bob)
        .expect("apply");
    let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
    assert_eq!(
        reg.drain_version_snapshot(&snapshot).expect("drain"),
        DrainOutcome::Drained
    );
    assert!(reg
        .acknowledged_contributors(&a_info.session_id)
        .expect("readout")
        .is_empty());
    // last accepted (last attributed editor) is preserved across the drain.
    assert_eq!(
        reg.last_accepted_contributor(&a_info.session_id)
            .expect("readout"),
        Some(bob)
    );
    // Repeating the same drain removes nothing further.
    assert_eq!(
        reg.drain_version_snapshot(&snapshot).expect("repeat drain"),
        DrainOutcome::Drained
    );
    assert!(reg
        .acknowledged_contributors(&a_info.session_id)
        .expect("readout")
        .is_empty());
}

#[test]
fn drain_is_stale_after_later_attributed_or_legacy_mutation() {
    // Same author writes again after the snapshot.
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let u1 = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u1, &alice)
        .expect("apply");
    let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
    let u2 = edit_bytes(&a, |txn, text| text.insert(txn, 6, "?"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u2, &alice)
        .expect("later apply");
    assert_eq!(
        reg.drain_version_snapshot(&snapshot).expect("drain"),
        DrainOutcome::Stale
    );
    assert_eq!(ledger(&reg, &a_info), vec![alice.clone()]);

    // A legacy unattributed mutation advances the epoch too.
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let u1 = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u1, &alice)
        .expect("apply");
    let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
    let u2 = edit_bytes(&a, |txn, text| text.insert(txn, 6, "?"));
    reg.apply_update(&a_info.session_id, &a_info.peer_id, &u2)
        .expect("legacy apply");
    assert_eq!(
        reg.drain_version_snapshot(&snapshot).expect("drain"),
        DrainOutcome::Stale
    );
}

#[test]
fn duplicate_and_refused_updates_do_not_invalidate_a_pending_snapshot() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let u1 = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u1, &alice)
        .expect("apply");
    let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
    // Exact duplicate replay: accepted no-op, no new CRDT state.
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u1, &alice)
        .expect("duplicate accepted");
    // A refused update mutates nothing.
    assert_eq!(
        reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &[0xff, 0x00], &alice)
            .unwrap_err()
            .code,
        RefusalCode::BadDocShape
    );
    assert_eq!(
        reg.drain_version_snapshot(&snapshot).expect("drain"),
        DrainOutcome::Drained
    );
}

#[test]
fn delete_only_and_net_zero_updates_advance_the_epoch() {
    for edit in [
        (|txn: &mut yrs::TransactionMut, text: yrs::TextRef| text.remove_range(txn, 0, 1))
            as fn(&mut yrs::TransactionMut, yrs::TextRef),
        |txn: &mut yrs::TransactionMut, text: yrs::TextRef| {
            text.insert(txn, 0, "xy");
            text.remove_range(txn, 0, 2);
        },
    ] {
        let mut reg = SessionRegistry::new();
        let (a, a_info) = open_edit(&mut reg, "hello");
        let alice = pair("alice", "human");
        let seed = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
        reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &seed, &alice)
            .expect("seed apply");
        let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
        let next = edit_bytes(&a, edit);
        reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &next, &alice)
            .expect("state-changing apply");
        assert_eq!(
            reg.drain_version_snapshot(&snapshot).expect("drain"),
            DrainOutcome::Stale
        );
    }
}

#[test]
fn drain_after_terminal_teardown_refuses_undeclared_session() {
    let mut reg = SessionRegistry::new();
    let (a, a_info) = open_edit(&mut reg, "hello");
    let alice = pair("alice", "human");
    let u1 = edit_bytes(&a, |txn, text| text.insert(txn, 5, "!"));
    reg.apply_update_attributed(&a_info.session_id, &a_info.peer_id, &u1, &alice)
        .expect("apply");
    let snapshot = reg.version_snapshot(&a_info.session_id).expect("snapshot");
    assert!(reg.leave(&a_info.session_id, &a_info.peer_id));
    assert_eq!(
        reg.drain_version_snapshot(&snapshot).unwrap_err().code,
        RefusalCode::UndeclaredSession
    );
}
