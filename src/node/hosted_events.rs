//! Hosted change signal for online local reads.
//!
//! With `online_local_reads` configured and a refresh controller running, the
//! node keeps one Server-Sent Events connection to hosted's
//! `GET /databases/{db_id}/events`. A `content` event is only a signal: it
//! asks the existing refresh controller for a delta, and the data still
//! arrives through that delta. Nothing here reads, writes or classifies
//! hosted health; the head probe owns that. The 60 s refresh cadence stays as
//! the backstop, so a dead, refused or unsupported stream costs freshness
//! only.
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{read_guarded_credential, Upstream};
use crate::standby::{RefreshCause, RefreshHints};

/// Hosted sends a comment heartbeat every 15 s; three missed ones is dead.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// After a refusal (credential or endpoint) retry only rarely and quietly: a
/// rotated credential is picked up, and a refusing hosted is not hammered.
const REFUSED_BACKOFF: Duration = Duration::from_secs(15 * 60);
/// A connection must live this long before the backoff resets, so a hosted
/// that accepts and immediately closes cannot be reconnected to at the floor.
const STABLE_AFTER: Duration = Duration::from_secs(30);
/// Bounds on one buffered line and one event's data.
const MAX_LINE: usize = 64 * 1024;
const MAX_EVENT_DATA: usize = 256 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct SseEvent {
    /// The `event:` name, if the block set one.
    pub event: Option<String>,
    /// All `data:` lines joined with `\n`.
    pub data: String,
    /// The `id:` set inside this block only. Unlike the browser's persistent
    /// last-event-id, a block without an id has none, so id-less frames
    /// (`stream`, `authorization`, `inbox`) can never move a resume cursor.
    pub id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ParseError {
    LineTooLong,
    EventTooLarge,
}

/// Incremental `text/event-stream` parser. Feed it arbitrary chunks; lines may
/// end in LF, CR or CRLF, split anywhere.
#[derive(Default)]
pub(super) struct SseParser {
    line: Vec<u8>,
    skip_lf: bool,
    started: bool,
    event: Option<String>,
    data: String,
    has_data: bool,
    id: Option<String>,
    retry: Option<Duration>,
}

impl SseParser {
    /// The most recent `retry:` value the server sent, if any.
    pub(super) fn retry(&self) -> Option<Duration> {
        self.retry
    }

    pub(super) fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, ParseError> {
        let mut out = Vec::new();
        for &byte in chunk {
            if std::mem::take(&mut self.skip_lf) && byte == b'\n' {
                continue;
            }
            match byte {
                b'\n' => self.end_line(&mut out)?,
                b'\r' => {
                    self.skip_lf = true;
                    self.end_line(&mut out)?;
                }
                _ => {
                    if self.line.len() >= MAX_LINE {
                        return Err(ParseError::LineTooLong);
                    }
                    self.line.push(byte);
                }
            }
        }
        Ok(out)
    }

    fn end_line(&mut self, out: &mut Vec<SseEvent>) -> Result<(), ParseError> {
        let mut raw = std::mem::take(&mut self.line);
        if !self.started {
            self.started = true;
            if raw.starts_with(&[0xEF, 0xBB, 0xBF]) {
                raw.drain(..3);
            }
        }
        if raw.is_empty() {
            if self.has_data {
                let mut data = std::mem::take(&mut self.data);
                data.pop(); // the newline appended after the last data line
                out.push(SseEvent {
                    event: self.event.take(),
                    data,
                    id: self.id.take(),
                });
            }
            self.event = None;
            self.data.clear();
            self.has_data = false;
            self.id = None;
            return Ok(());
        }
        if raw[0] == b':' {
            return Ok(()); // comment, e.g. the heartbeat
        }
        let line = String::from_utf8_lossy(&raw);
        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (&*line, ""),
        };
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => {
                if self.data.len() + value.len() + 1 > MAX_EVENT_DATA {
                    return Err(ParseError::EventTooLarge);
                }
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            "id" if !value.contains('\0') => self.id = Some(value.to_owned()),
            "retry" if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
                if let Ok(ms) = value.parse::<u64>() {
                    self.retry = Some(Duration::from_millis(ms));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum State {
    Connecting,
    Connected,
    Backoff,
    /// Hosted refused the credential. Retried rarely; never a health change.
    AuthRefused,
    /// Hosted has no events endpoint for this database.
    Unsupported,
}

#[derive(Default)]
struct Inner {
    state: Option<State>,
    ever_connected: bool,
    reconnects: u64,
    events: u64,
    last_event_at: Option<String>,
}

/// What `node_status` reports about the stream under `hosted.events`.
pub(super) struct EventStatus(std::sync::Mutex<Inner>);

impl EventStatus {
    fn new() -> Self {
        Self(std::sync::Mutex::new(Inner::default()))
    }

    fn set(&self, state: State) {
        let mut inner = self.0.lock().expect("event status");
        inner.state = Some(state);
        if matches!(state, State::Connected) {
            if inner.ever_connected {
                inner.reconnects += 1;
            }
            inner.ever_connected = true;
        }
    }

    fn note_event(&self) {
        let mut inner = self.0.lock().expect("event status");
        inner.events += 1;
        inner.last_event_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    }

    pub(super) fn summary(&self) -> Value {
        let inner = self.0.lock().expect("event status");
        let (state, connected) = match inner.state {
            None | Some(State::Connecting) => ("connecting", false),
            Some(State::Connected) => ("connected", true),
            Some(State::Backoff) => ("reconnecting", false),
            Some(State::AuthRefused) => ("auth_refused", false),
            Some(State::Unsupported) => ("unsupported", false),
        };
        json!({
            "state": state,
            "connected": connected,
            "last_event_at": inner.last_event_at,
            "reconnects": inner.reconnects,
            "events": inner.events,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) struct Timing {
    pub heartbeat_timeout: Duration,
    pub connect_timeout: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    pub refused_backoff: Duration,
    pub stable_after: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            heartbeat_timeout: HEARTBEAT_TIMEOUT,
            connect_timeout: CONNECT_TIMEOUT,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            refused_backoff: REFUSED_BACKOFF,
            stable_after: STABLE_AFTER,
        }
    }
}

/// Exponential delay for the `attempt`th consecutive failure (0 based), with
/// "equal jitter": half fixed, half scaled by `unit` in `[0, 1)`.
fn backoff_delay(attempt: u32, min: Duration, max: Duration, unit: f64) -> Duration {
    let full = min
        .checked_mul(1u32.checked_shl(attempt.min(30)).unwrap_or(u32::MAX))
        .unwrap_or(max)
        .min(max);
    full / 2 + full.mul_f64(unit.clamp(0.0, 1.0) / 2.0)
}

enum End {
    /// Transport trouble, timeout, EOF or a server close: reconnect with backoff.
    Lost,
    /// 401/403: retry only after the long backoff.
    Refused,
    /// No events endpoint here.
    Unsupported,
    /// 409: the cursor fell out of hosted's retention; resume from the head.
    CursorReset,
    /// Hosted ended a bounded replay (`ready` with `has_more`) and the cursor
    /// advanced: reconnect at once, this is progress and not a failure.
    Resume,
}

struct Session {
    end: End,
    /// How long the connection stayed up, if it connected.
    lasted: Option<Duration>,
    retry: Option<Duration>,
}

pub(super) struct EventStream {
    compatibility: crate::client_compatibility::Monitor,
    url: reqwest::Url,
    credential_file: std::path::PathBuf,
    client: reqwest::Client,
    hint: Arc<dyn Fn() + Send + Sync>,
    status: Arc<EventStatus>,
    timing: Timing,
}

impl EventStream {
    /// `Some` only when `online_local_reads` is configured. The URL is the
    /// node's already validated hosted endpoint (`<base>/mcp/<db>`) with the
    /// final two segments swapped for `databases/<db>/events`, so it keeps the
    /// same origin, prefix and database route. The credential is the node's
    /// own `credential_file`, re-read on every connect exactly as the head
    /// probe does; the OAuth renewal loop keeps that file current.
    pub(super) fn for_config(upstream: &Upstream, hints: RefreshHints) -> Option<Self> {
        if !upstream.config.tracks_local_reads() {
            return None;
        }
        let mut url = upstream.endpoint.clone();
        url.path_segments_mut()
            .ok()?
            .pop()
            .pop()
            .push("databases")
            .push(&upstream.config.db_id)
            .push("events");
        let mut stream = Self::new(
            url,
            upstream.config.credential_file.clone(),
            // A hosted change means the copy is behind; the same coalesced
            // hint as an admitted write. See docs/local-node.md for why this
            // is not a distinct cause.
            Arc::new(move || hints.request(RefreshCause::AfterAdmittedWrite)),
            Timing::default(),
        )
        .ok()?;
        stream.compatibility = upstream.compatibility.clone();
        Some(stream)
    }

    #[cfg(test)]
    pub(super) fn url(&self) -> &reqwest::Url {
        &self.url
    }

    pub(super) fn new(
        url: reqwest::Url,
        credential_file: std::path::PathBuf,
        hint: Arc<dyn Fn() + Send + Sync>,
        timing: Timing,
    ) -> Result<Self, reqwest::Error> {
        // No total timeout: the response body is meant to stay open.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(timing.connect_timeout)
            .build()?;
        Ok(Self {
            compatibility: Default::default(),
            url,
            credential_file,
            client,
            hint,
            status: Arc::new(EventStatus::new()),
            timing,
        })
    }

    pub(super) fn status(&self) -> Arc<EventStatus> {
        self.status.clone()
    }

    /// Run until aborted.
    pub(super) async fn run(self) {
        let mut cursor: Option<i64> = None;
        let mut failures: u32 = 0;
        let mut refusals: u32 = 0;
        loop {
            let mut session = self.session(&mut cursor).await;
            // Hosted's v2 stream answers 401 for maintenance and for "locator
            // or authorization changed; reconnect" as well as for a bad
            // credential, so one refusal is only a failed connect. The second
            // in a row is taken as a real refusal.
            if matches!(session.end, End::Refused) {
                refusals += 1;
                if refusals < 2 {
                    session.end = End::Lost;
                }
            } else {
                refusals = 0;
            }
            let delay = match session.end {
                End::Resume => Duration::ZERO,
                End::Refused => {
                    self.status.set(State::AuthRefused);
                    self.timing.refused_backoff
                }
                End::Unsupported => {
                    self.status.set(State::Unsupported);
                    self.timing.refused_backoff
                }
                End::CursorReset => {
                    cursor = None;
                    self.status.set(State::Backoff);
                    self.timing.backoff_min
                }
                End::Lost => {
                    if session
                        .lasted
                        .is_some_and(|lasted| lasted >= self.timing.stable_after)
                    {
                        failures = 0;
                    }
                    self.status.set(State::Backoff);
                    let mut delay = backoff_delay(
                        failures,
                        self.timing.backoff_min,
                        self.timing.backoff_max,
                        rand::random::<f64>(),
                    );
                    failures = failures.saturating_add(1);
                    if let Some(retry) = session.retry {
                        delay = delay.max(retry.min(self.timing.backoff_max));
                    }
                    delay
                }
            };
            tokio::time::sleep(delay).await;
        }
    }

    async fn session(&self, cursor: &mut Option<i64>) -> Session {
        let lost = |lasted, retry| Session {
            end: End::Lost,
            lasted,
            retry,
        };
        self.status.set(State::Connecting);
        let Ok(token) = read_guarded_credential(&self.credential_file, "node") else {
            return lost(None, None);
        };
        let mut url = self.url.clone();
        if let Some(after) = *cursor {
            url.query_pairs_mut()
                .append_pair("after", &after.to_string());
        }
        let request = self
            .client
            .get(url)
            .header(
                crate::client_compatibility::HEADER,
                crate::client_compatibility::advertisement(),
            )
            .bearer_auth(std::str::from_utf8(&token).expect("guarded UTF-8"))
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache");
        let sent = tokio::time::timeout(self.timing.connect_timeout, request.send()).await;
        let Ok(Ok(mut response)) = sent else {
            return lost(None, None);
        };
        response = match crate::client_compatibility::inspect(
            response,
            &self.compatibility,
            "events",
            "subscribe",
        )
        .await
        {
            Ok(response) => response,
            Err(_) => return lost(None, None),
        };
        let status = response.status().as_u16();
        let end = match status {
            200 => None,
            401 | 403 => Some(End::Refused),
            404 | 405 | 501 => Some(End::Unsupported),
            409 if cursor.is_some() => Some(End::CursorReset),
            _ => Some(End::Lost),
        };
        if let Some(end) = end {
            return Session {
                end,
                lasted: None,
                retry: None,
            };
        }
        let is_sse = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        if !is_sse {
            return lost(None, None);
        }
        let connected_at = Instant::now();
        self.status.set(State::Connected);
        if cursor.is_none() {
            // Nothing is replayed without a cursor, so anything committed
            // before this connect is only visible to a delta.
            (self.hint)();
        }
        let mut parser = SseParser::default();
        let started_at = *cursor;
        let mut has_more = false;
        loop {
            let chunk =
                match tokio::time::timeout(self.timing.heartbeat_timeout, response.chunk()).await {
                    Ok(Ok(Some(chunk))) => chunk,
                    // A bounded replay: hosted closes after `ready` + `has_more`.
                    Ok(Ok(None)) if has_more && *cursor > started_at => {
                        return Session {
                            end: End::Resume,
                            lasted: Some(connected_at.elapsed()),
                            retry: None,
                        };
                    }
                    // EOF (including hosted's `lagged` and access-loss closes),
                    // transport error or a missed heartbeat window.
                    _ => return lost(Some(connected_at.elapsed()), parser.retry()),
                };
            let Ok(events) = parser.push(&chunk) else {
                return lost(Some(connected_at.elapsed()), parser.retry());
            };
            for event in events {
                if event.event.as_deref() == Some("content") {
                    self.status.note_event();
                    (self.hint)();
                }
                if event.event.as_deref() == Some("ready") {
                    has_more = serde_json::from_str::<Value>(&event.data)
                        .is_ok_and(|data| data["has_more"] == true);
                }
                if let Some(id) = event.id.as_deref().and_then(|id| id.parse::<i64>().ok()) {
                    if cursor.is_none_or(|current| id > current) {
                        *cursor = Some(id);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
