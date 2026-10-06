//! Test-owned JSON-lines framing around the actual in-process session core.
//! Not a host, authority evaluator, production wire codec or persistence driver.
// This executable is exercised by the SDK; core unit tests belong to native_ce.
#![cfg(not(test))]
#![forbid(unsafe_code)]

// The source-path modules deliberately compile the real core, including private
// internals, without linking native_ce. Unused version/attribution APIs remain
// unconsumed: this fixture supplies neither identity nor a version commit sink.
#[allow(dead_code)]
#[path = "../../../src/coedit/refusal.rs"]
mod refusal;
#[allow(dead_code)]
#[path = "../../../src/coedit/registry.rs"]
mod registry;

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use registry::{OpenParams, PeerId, PeerKind, SessionId, SessionRegistry, MAX_UPDATE_BYTES};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use yrs::updates::encoder::Encode;
use yrs::StateVector;

const SEED: &str = "A😀漢e\u{301}\r\nZ";
const RECORD: &str = "record";
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_LINKS: usize = 16;
const MAX_SAFE_JS_INTEGER: u64 = (1 << 53) - 1;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    request_id: u32,
    control: Control,
}

// This wrapper is fixture control, deliberately separate from session.* shapes.
#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum Control {
    #[serde(rename = "handshake")]
    Handshake,
    #[serde(rename = "attach")]
    Attach { database: String, link: String },
    #[serde(rename = "message")]
    Message { link: String, message: Value },
    #[serde(rename = "inspect")]
    Inspect { link: String },
    #[serde(rename = "shutdown")]
    Shutdown,
}

#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum ClientMessage {
    #[serde(rename = "session.open")]
    Open {
        key: String,
        record_id: String,
        mode: Mode,
    },
    #[serde(rename = "session.update")]
    Update {
        session: String,
        update: Vec<u8>,
        update_id: String,
    },
    #[serde(rename = "session.close")]
    Close { session: String },
    #[serde(rename = "session.version")]
    Version { session: String, reason: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Edit,
    View,
}

#[derive(Clone)]
struct Binding {
    session: SessionId,
    peer: PeerId,
}
struct Link {
    database: String,
    opened: bool,
    binding: Option<Binding>,
}
struct Fixture {
    databases: BTreeMap<String, SessionRegistry>,
    links: BTreeMap<String, Link>,
    handshook: bool,
    clock: u64,
}

fn digest(body: &str) -> String {
    format!("{:x}", Sha256::digest(body.as_bytes()))
}
fn event(link: &str, message: Value) -> Value {
    json!({ "link": link, "message": message })
}
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Fixture {
    fn new() -> Self {
        Self {
            databases: ["db-a", "db-b"]
                .into_iter()
                .map(|id| (id.to_owned(), SessionRegistry::new()))
                .collect(),
            links: BTreeMap::new(),
            handshook: false,
            clock: 0,
        }
    }

    fn binding(&self, link: &str, session: Option<&str>) -> Result<(String, Binding), String> {
        let attached = self.links.get(link).ok_or("unknown fixture link")?;
        let binding = attached.binding.as_ref().ok_or("link has no live peer")?;
        if session.is_some_and(|id| id != binding.session.0) {
            return Err("session binding mismatch".into());
        }
        Ok((attached.database.clone(), binding.clone()))
    }

    fn handle(&mut self, control: Control) -> Result<(Value, Vec<Value>), String> {
        if !self.handshook && !matches!(&control, Control::Handshake) {
            return Err("fixture handshake required".into());
        }
        match control {
            Control::Handshake => {
                if self.handshook {
                    return Err("fixture already handshook".into());
                }
                self.handshook = true;
                Ok((
                    json!({
                        "fixture_version": 1,
                        "source_sha256": {
                            "src/coedit/registry.rs": env!("COEDIT_REGISTRY_SHA256"),
                            "src/coedit/refusal.rs": env!("COEDIT_REFUSAL_SHA256")
                        },
                        "seed": SEED, "record_id": RECORD,
                        "max_frame_bytes": MAX_FRAME_BYTES, "max_links": MAX_LINKS
                    }),
                    vec![],
                ))
            }
            Control::Attach { database, link } => {
                if !self.databases.contains_key(&database) {
                    return Err("unknown fixture database".into());
                }
                if !valid_id(&link) || self.links.contains_key(&link) {
                    return Err("invalid or duplicate fixture link".into());
                }
                if self.links.len() >= MAX_LINKS {
                    return Err("fixture link cap reached".into());
                }
                self.links.insert(
                    link,
                    Link {
                        database,
                        opened: false,
                        binding: None,
                    },
                );
                Ok((json!({ "attached": true }), vec![]))
            }
            Control::Message { link, message } => {
                let parsed = serde_json::from_value::<ClientMessage>(message)
                    .map_err(|error| format!("malformed session message: {error}"))?;
                self.message(&link, parsed)
            }
            Control::Inspect { link } => {
                let (database, binding) = self.binding(&link, None)?;
                let core = self
                    .databases
                    .get(&database)
                    .ok_or("missing fixture database")?;
                let body = core
                    .live_body(&binding.session)
                    .map_err(|error| error.to_string())?;
                let sync = core
                    .encode_diff(&binding.session, &StateVector::default().encode_v1())
                    .map_err(|error| error.to_string())?;
                Ok((
                    json!({ "body": body, "body_sha256": digest(&body), "sync": sync }),
                    vec![],
                ))
            }
            Control::Shutdown => Ok((json!({ "shutdown": true }), vec![])),
        }
    }

    fn message(
        &mut self,
        link: &str,
        message: ClientMessage,
    ) -> Result<(Value, Vec<Value>), String> {
        match message {
            ClientMessage::Open {
                key,
                record_id,
                mode,
            } => {
                let attached = self.links.get(link).ok_or("unknown fixture link")?;
                if key != attached.database {
                    return Err("database binding mismatch".into());
                }
                if record_id != RECORD {
                    return Err("unknown fixture record".into());
                }
                if attached.opened {
                    return Err("fixture link is single-use".into());
                }
                let database = attached.database.clone();
                let core = self
                    .databases
                    .get_mut(&database)
                    .ok_or("missing fixture database")?;
                let opened = core
                    .open(OpenParams {
                        database_id: database,
                        record_id,
                        committed_body: SEED.into(),
                        kind: match mode {
                            Mode::Edit => PeerKind::Edit,
                            Mode::View => PeerKind::View,
                        },
                        record_supported: true,
                    })
                    .map_err(|error| error.to_string())?;
                let binding = Binding {
                    session: opened.session_id.clone(),
                    peer: opened.peer_id.clone(),
                };
                let attached = self.links.get_mut(link).ok_or("missing attached link")?;
                attached.opened = true;
                attached.binding = Some(binding);
                Ok((
                    json!({ "dispatched": true }),
                    vec![event(
                        link,
                        json!({
                            "op": "session.opened", "session": opened.session_id.0, "peer": opened.peer_id.0,
                            "doc_client_ids": opened.client_ids, "sync": opened.sync_step2,
                            "base": { "version": 0, "body_sha256": digest(SEED) },
                            "limits": { "max_update_bytes": MAX_UPDATE_BYTES },
                            "presence": { "sharing": false }
                        }),
                    )],
                ))
            }
            ClientMessage::Update {
                session,
                update,
                update_id,
            } => {
                let (database, binding) = self.binding(link, Some(&session))?;
                if update_id.is_empty() || update_id.len() > 128 {
                    return Err("invalid fixture update_id".into());
                }
                // Prepare before core mutation; never accept then fail to issue an ack.
                let next_clock = self
                    .clock
                    .checked_add(1)
                    .filter(|n| *n <= MAX_SAFE_JS_INTEGER)
                    .ok_or("fixture delivery counter exhausted")?;
                let core = self
                    .databases
                    .get_mut(&database)
                    .ok_or("missing fixture database")?;
                match core.apply_update(&binding.session, &binding.peer, &update) {
                    Ok(ack) => {
                        self.clock = next_clock;
                        let mut events = vec![event(
                            link,
                            json!({
                                "op": "session.ack", "session": session, "update_id": update_id, "clock": self.clock
                            }),
                        )];
                        for (other_id, other) in &self.links {
                            if other_id == link || other.database != database {
                                continue;
                            }
                            if other
                                .binding
                                .as_ref()
                                .is_some_and(|b| b.session == binding.session)
                            {
                                events.push(event(other_id, json!({
                                    "op": "session.remote", "session": session, "update": ack.broadcast,
                                    "from": { "person_ref": null, "kind": "fixture" }
                                })));
                            }
                        }
                        Ok((json!({ "dispatched": true }), events))
                    }
                    Err(refused) => {
                        let sync = core
                            .encode_diff(&binding.session, &StateVector::default().encode_v1())
                            .map_err(|error| error.to_string())?;
                        Ok((
                            json!({ "dispatched": true }),
                            vec![event(
                                link,
                                json!({
                                    "op": "session.refused", "session": session,
                                    "code": refused.code.as_str(), "refused": [update_id], "sync": sync
                                }),
                            )],
                        ))
                    }
                }
            }
            ClientMessage::Close { session } => {
                let (database, binding) = self.binding(link, Some(&session))?;
                let core = self
                    .databases
                    .get_mut(&database)
                    .ok_or("missing fixture database")?;
                if !core.leave(&binding.session, &binding.peer) {
                    return Err("core peer missing during leave".into());
                }
                self.links
                    .get_mut(link)
                    .ok_or("missing attached link")?
                    .binding = None;
                Ok((
                    json!({ "dispatched": true }),
                    vec![event(
                        link,
                        json!({
                            "op": "session.closed", "session": session, "reason": "left"
                        }),
                    )],
                ))
            }
            ClientMessage::Version { session, reason } => {
                self.binding(link, Some(&session))?;
                let _ = reason;
                Err(
                    "session.version unsupported: fixture has no persistence/version authority"
                        .into(),
                )
            }
        }
    }
}

// Limit allocation before parsing, including an unterminated input line.
fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    let count =
        io::Read::take(reader, (MAX_FRAME_BYTES + 1) as u64).read_until(b'\n', &mut bytes)?;
    if count == 0 {
        return Ok(None);
    }
    if bytes.len() > MAX_FRAME_BYTES || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized or unterminated fixture frame",
        ));
    }
    Ok(Some(bytes))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = io::stdin().lock();
    let mut writer = io::stdout().lock();
    let mut fixture = Fixture::new();
    let mut previous_id = 0;
    while let Some(bytes) = read_frame(&mut reader)? {
        let request: Request = serde_json::from_slice(&bytes)?;
        if request.request_id <= previous_id {
            return Err("fixture request IDs must strictly increase from 1".into());
        }
        previous_id = request.request_id;
        let shutdown = matches!(&request.control, Control::Shutdown);
        let response = match fixture.handle(request.control) {
            Ok((result, events)) => {
                json!({ "request_id": request.request_id, "result": result, "events": events })
            }
            Err(error) => json!({ "request_id": request.request_id, "error": error, "events": [] }),
        };
        let encoded = serde_json::to_vec(&response)?;
        if encoded.len() + 1 > MAX_FRAME_BYTES {
            return Err("fixture output exceeds frame bound".into());
        }
        writer.write_all(&encoded)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        if shutdown {
            break;
        }
    }
    Ok(())
}
