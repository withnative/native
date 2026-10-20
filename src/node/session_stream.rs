//! Source-entry budget for the streaming driver. Reserve actual row anchors
//! before handing them to the curator, stage a complete finalized batch, and
//! release those rows only after all of their split parts are confirmed.
//! A strict raw page buffer and verified prefix keep partial windows distinct
//! from full source completion.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::error::{Error, Result};

use super::session_projection::FinalizedStep;

pub const CURATION_AHEAD_LIMIT: usize = 200;

/// An acknowledgement belongs to one in-memory source generation. It is not
/// a hosted position key and cannot acknowledge a replacement pipeline.
#[derive(Debug)]
pub struct SourceAck {
    generation: uuid::Uuid,
    id: u64,
}

pub struct SourceBudget {
    generation: uuid::Uuid,
    rows: BTreeMap<u64, usize>,
    retired_through: Option<u64>,
    released: Vec<u64>,
    staged: HashMap<u64, Vec<u64>>,
    next_id: u64,
}

impl Default for SourceBudget {
    fn default() -> Self {
        Self {
            generation: uuid::Uuid::new_v4(),
            rows: BTreeMap::new(),
            retired_through: None,
            released: Vec::new(),
            staged: HashMap::new(),
            next_id: 0,
        }
    }
}

impl SourceBudget {
    pub fn pending_entries(&self) -> usize {
        self.rows.len()
    }

    /// False means backpressure, with no partial reservation. Repeated wide
    /// anchors use their existing slot. Already settled anchors require none.
    pub fn reserve(&mut self, anchors: &[u64]) -> bool {
        let new: BTreeSet<_> = anchors
            .iter()
            .copied()
            .filter(|anchor| {
                !self.rows.contains_key(anchor)
                    && self.retired_through.is_none_or(|mark| *anchor > mark)
            })
            .collect();
        if self.rows.len().saturating_add(new.len()) > CURATION_AHEAD_LIMIT {
            return false;
        }
        for anchor in new {
            self.rows.insert(anchor, 0);
        }
        true
    }

    /// Account for *all* parts in one curator drain before acknowledging any
    /// part. A partial group or invalid provenance refuses without mutation.
    pub fn stage(&mut self, steps: &[FinalizedStep]) -> Result<Vec<SourceAck>> {
        let count =
            u64::try_from(steps.len()).map_err(|_| Error::engine("source batch too large"))?;
        let next = self
            .next_id
            .checked_add(count)
            .ok_or_else(|| Error::engine("source acknowledgement sequence exhausted"))?;
        let mut additions: BTreeMap<u64, usize> = BTreeMap::new();
        let mut offset = 0;
        while offset < steps.len() {
            let first = &steps[offset];
            let parts = first.part_count as usize;
            if parts == 0
                || first.step.part_index != 0
                || parts > steps.len() - offset
                || first.source_entries.is_empty()
                || first
                    .source_entries
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(Error::engine(
                    "incomplete or invalid source provenance batch",
                ));
            }
            for (index, part) in steps[offset..offset + parts].iter().enumerate() {
                if part.part_count != first.part_count
                    || part.step.part_index as usize != index
                    || part.source_entries != first.source_entries
                    || part.step.kind != first.step.kind
                {
                    return Err(Error::engine("split source provenance differs"));
                }
                for anchor in &part.source_entries {
                    let Some(current) = self.rows.get(anchor) else {
                        return Err(Error::engine(
                            "source row was not reserved or already retired",
                        ));
                    };
                    let increment = additions.entry(*anchor).or_default();
                    *increment = increment
                        .checked_add(1)
                        .ok_or_else(|| Error::engine("source reference count exhausted"))?;
                    current
                        .checked_add(*increment)
                        .ok_or_else(|| Error::engine("source reference count exhausted"))?;
                }
            }
            offset += parts;
        }
        // A finalized row cannot appear again in a later drain. Existing
        // outstanding references therefore indicate a duplicate staging call.
        if additions.keys().any(|anchor| self.rows[anchor] != 0) {
            return Err(Error::engine("source row already staged"));
        }
        for (anchor, increment) in additions {
            *self.rows.get_mut(&anchor).expect("validated source") += increment;
        }
        let mut acknowledgements = Vec::with_capacity(steps.len());
        for (index, step) in steps.iter().enumerate() {
            let id = self.next_id + index as u64 + 1;
            self.staged.insert(id, step.source_entries.clone());
            acknowledgements.push(SourceAck {
                generation: self.generation,
                id,
            });
        }
        self.next_id = next;
        Ok(acknowledgements)
    }

    pub fn confirm(&mut self, ack: SourceAck) -> Result<()> {
        if ack.generation != self.generation {
            return Err(Error::engine(
                "source acknowledgement belongs to another pipeline",
            ));
        }
        let Some(anchors) = self.staged.remove(&ack.id) else {
            return Err(Error::engine("unknown source acknowledgement"));
        };
        for anchor in anchors {
            let references = self.rows.get_mut(&anchor).expect("staged source reference");
            *references -= 1;
            if *references == 0 {
                self.rows.remove(&anchor);
                self.retired_through =
                    Some(self.retired_through.map_or(anchor, |old| old.max(anchor)));
                self.released.push(anchor);
            }
        }
        Ok(())
    }

    pub fn take_released(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.released)
    }

    /// The caller may release rows excluded by the projection policy; rows
    /// with staged output can only be released through confirmed part tokens.
    pub fn omit(&mut self, anchors: &[u64]) -> Result<()> {
        if anchors
            .iter()
            .any(|a| self.rows.get(a).is_some_and(|n| *n != 0))
        {
            return Err(Error::engine("cannot omit source with pending output"));
        }
        for anchor in anchors {
            self.rows.remove(anchor);
        }
        Ok(())
    }
}

/// The fetch buffer is a single validated page. Only reserved rows cross
/// into curation; a full pending group pauses rather than being forced closed.
#[derive(Debug, PartialEq, Eq)]
pub enum SourcePoll {
    Fetch { cursor: Option<serde_json::Value> },
    Window,
    Backlog,
    Idle,
}

struct ReadyStep {
    step: super::session_projection::ProjectedStep,
    ack: SourceAck,
}
struct WindowPart {
    index: usize,
    ack: SourceAck,
    metadata: super::session_projection::SourceStepMeta,
    bytes: usize,
}

pub struct ProducedWindow {
    pub source: super::session_catchup::CompleteTimeline,
    pub observed_replacement: bool,
    pub unknown_continuity: bool,
}

pub struct BoundedSource {
    agent: String,
    pages: super::session_catchup::TimelinePages,
    snapshot: Option<super::session_writer::SourceSnapshot>,
    curator: super::session_projection::Curator,
    budget: SourceBudget,
    prefix: super::session_catchup::ComparedPrefix,
    chain: super::session_writer::VerifiedChain,
    acknowledged_branch: Option<u64>,
    previous_epoch: Option<String>,
    observed_replacement: bool,
    unknown_continuity: bool,
    matching: bool,
    raw: std::collections::VecDeque<(super::session_projection::ProjectedEntry, usize)>,
    wire_sizes: HashMap<u64, usize>,
    body_bytes: usize,
    limit_bytes: usize,
    ready: Vec<ReadyStep>,
    pending: std::collections::VecDeque<WindowPart>,
    confirmed_metadata: Vec<super::session_projection::SourceStepMeta>,
    window_token: Option<uuid::Uuid>,
    window_exhausted: bool,
    window_end: usize,
    window_confirmed: usize,
    confirmed_cursor: Option<super::session_writer::SourceCursor>,
    more: bool,
    cursor: Option<serde_json::Value>,
    fetched_end: Option<u64>,
    waiting: bool,
    cycle_complete: bool,
    ready_window: bool,
    backlogged: bool,
    clock: Option<super::session_writer::CatchupClock>,
    invalid: bool,
}

impl BoundedSource {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent: &str,
        chain: super::session_writer::VerifiedChain,
        acknowledged_branch: Option<u64>,
        previous_epoch: Option<String>,
        observed_replacement: bool,
        unknown_continuity: bool,
        limit_bytes: usize,
    ) -> Result<Self> {
        Ok(Self {
            agent: agent.to_owned(),
            pages: super::session_catchup::TimelinePages::new(agent, limit_bytes)?,
            snapshot: None,
            curator: super::session_projection::Curator::new(),
            budget: SourceBudget::default(),
            prefix: super::session_catchup::ComparedPrefix::new(&chain),
            chain,
            acknowledged_branch,
            previous_epoch,
            observed_replacement,
            unknown_continuity,
            matching: true,
            raw: std::collections::VecDeque::new(),
            wire_sizes: HashMap::new(),
            body_bytes: 0,
            limit_bytes,
            ready: Vec::new(),
            pending: std::collections::VecDeque::new(),
            confirmed_metadata: Vec::new(),
            window_token: None,
            window_exhausted: false,
            window_end: 0,
            window_confirmed: 0,
            confirmed_cursor: None,
            more: true,
            cursor: None,
            fetched_end: None,
            waiting: false,
            cycle_complete: false,
            ready_window: false,
            backlogged: false,
            clock: None,
            invalid: false,
        })
    }

    pub fn pending_entries(&self) -> usize {
        self.budget.pending_entries()
    }
    pub fn invalidate(&mut self) {
        self.invalid = true;
        self.pages.invalidate();
    }

    pub fn accept_page(
        &mut self,
        frame: &serde_json::Value,
        request_id: &str,
    ) -> Result<super::session_catchup::FetchAction> {
        if !self.waiting || self.window_token.is_some() || !self.raw.is_empty() || self.invalid {
            return Err(Error::engine("source page is not outstanding"));
        }
        self.waiting = false;
        self.invalid = true;
        self.pages.release_page_bytes(self.limit_bytes);
        let (action, page) = self.pages.accept(frame, request_id)?;
        let Some(page) = page else { return Ok(action) };
        if self.snapshot.is_none() && page.snapshot.branch.is_none() {
            self.unknown_continuity |= self.observed_replacement
                || (self.chain.head_pos.is_some()
                    && self.previous_epoch.as_deref() != Some(page.snapshot.epoch.as_str()));
        }
        if !page.has_more
            && page.entries.is_empty()
            && self
                .wire_sizes
                .keys()
                .any(|anchor| *anchor > page.fetched_end.unwrap_or(0))
        {
            return Err(Error::engine(
                "source refresh lost unfinished rows without replacement",
            ));
        }
        self.snapshot = Some(page.snapshot);
        self.fetched_end = page.fetched_end;
        self.more = page.has_more;
        self.cursor = match &action {
            super::session_catchup::FetchAction::Next { cursor } => Some(cursor.clone()),
            _ => None,
        };
        self.raw
            .extend(page.entries.into_iter().zip(page.row_bytes));
        self.invalid = false;
        Ok(action)
    }

    fn release_confirmed_rows(&mut self) -> Result<()> {
        let released = self.budget.take_released();
        self.curator.forget_settled(&released)?;
        for anchor in released {
            self.wire_sizes.remove(&anchor);
        }
        Ok(())
    }

    fn absorb_finalized(&mut self) -> Result<()> {
        let finalized = self.curator.drain_finalized_with_sources();
        let acknowledgements = self.budget.stage(&finalized)?;
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| Error::engine("source snapshot missing"))?;
        let branch_advanced = match (self.acknowledged_branch, snapshot.branch) {
            (Some(old), Some(new)) if new < old => {
                return Err(Error::engine("source branch regressed"))
            }
            (Some(old), Some(new)) => new > old,
            (None, Some(new)) => new > 0,
            _ => false,
        };
        let resumed = snapshot.branch.is_some() && self.chain.marker_branch == snapshot.branch;
        let cut = if branch_advanced && !resumed {
            Some(
                snapshot
                    .kept_seq_end
                    .ok_or_else(|| Error::engine("source rewind lacks cut"))?,
            )
        } else {
            None
        };
        for (finalized, ack) in finalized.into_iter().zip(acknowledgements) {
            if self.matching && cut.is_some_and(|cut| finalized.step.seq_end > cut) {
                self.matching = false;
            }
            if self.matching && self.prefix.compare(&finalized.step)? {
                self.budget.confirm(ack)?;
            } else {
                self.matching = false;
                self.body_bytes = self
                    .body_bytes
                    .checked_add(finalized.step.body.len())
                    .ok_or_else(|| Error::engine("source pending bytes overflow"))?;
                self.ready.push(ReadyStep {
                    step: finalized.step,
                    ack,
                });
            }
        }
        self.release_confirmed_rows()?;
        if self
            .wire_sizes
            .values()
            .sum::<usize>()
            .saturating_add(self.body_bytes)
            > self.limit_bytes
        {
            return Err(Error::engine("curated source exceeds pending byte budget"));
        }
        Ok(())
    }

    /// Each call either asks for one page, exposes one bounded window, or
    /// stops. Ignored rows retire by policy, never by a fabricated step ack.
    pub fn poll(&mut self, turn_ended: bool) -> Result<SourcePoll> {
        if self.invalid {
            return Err(Error::engine("source pipeline is invalid"));
        }
        if self.waiting || self.window_token.is_some() || self.cycle_complete {
            return Ok(SourcePoll::Idle);
        }
        let outcome = self.poll_inner(turn_ended);
        if outcome.is_err() {
            self.invalidate();
        }
        self.ready_window = matches!(&outcome, Ok(SourcePoll::Window));
        self.backlogged = matches!(&outcome, Ok(SourcePoll::Backlog));
        outcome
    }
    fn poll_inner(&mut self, turn_ended: bool) -> Result<SourcePoll> {
        while let Some((entry, size)) = self.raw.front() {
            let anchor = entry.seq_start;
            if self.curator.is_frozen(anchor) {
                self.raw.pop_front();
                continue;
            }
            let omitted = entry.omitted_by_policy();
            let next_message = matches!(
                entry.item,
                super::session_projection::TimelineItem::UserMessage { .. }
                    | super::session_projection::TimelineItem::AssistantMessage { .. }
            );
            if !omitted {
                let retained = self
                    .wire_sizes
                    .values()
                    .sum::<usize>()
                    .saturating_sub(self.wire_sizes.get(&anchor).copied().unwrap_or(0));
                if retained
                    .saturating_add(*size)
                    .saturating_add(self.body_bytes)
                    > self.limit_bytes
                    || !self.budget.reserve(&[anchor])
                {
                    let before = self.budget.pending_entries();
                    if next_message {
                        self.curator.close_before_next_message(anchor);
                        self.absorb_finalized()?;
                    }
                    if !self.ready.is_empty() {
                        return Ok(SourcePoll::Window);
                    }
                    if self.budget.pending_entries() < before {
                        continue;
                    }
                    return Ok(SourcePoll::Backlog);
                }
            }
            let (entry, size) = self.raw.pop_front().expect("peeked source row");
            if omitted {
                self.budget.omit(&[anchor])?;
                self.wire_sizes.remove(&anchor);
            } else {
                self.wire_sizes.insert(anchor, size);
            }
            let epoch = &self.snapshot.as_ref().expect("validated page").epoch;
            self.curator.push_page(epoch, vec![entry]);
            self.absorb_finalized()?;
            if omitted {
                self.curator.forget_settled(&[anchor])?;
            }
        }
        if !self.more && turn_ended {
            self.curator.end_turn();
            self.absorb_finalized()?;
        }
        if !self.ready.is_empty() || (!self.more && self.curator.first_pending_seq().is_none()) {
            return Ok(SourcePoll::Window);
        }
        if !self.more {
            return Ok(SourcePoll::Backlog);
        }
        // A raw next page may refresh existing anchors or prove a message
        // boundary. No new row is curated without a source reservation.
        self.waiting = true;
        Ok(SourcePoll::Fetch {
            cursor: self.cursor.clone(),
        })
    }

    pub fn take_window(&mut self) -> Result<ProducedWindow> {
        if self.invalid
            || self.waiting
            || self.window_token.is_some()
            || self.cycle_complete
            || !self.ready_window
        {
            return Err(Error::engine("source window is not available"));
        }
        let snapshot = self
            .snapshot
            .clone()
            .ok_or_else(|| Error::engine("source snapshot missing"))?;
        let boundary = self
            .curator
            .first_pending_seq()
            .into_iter()
            .chain(self.raw.front().map(|(row, _)| row.seq_start))
            .min();
        let prefix_len = self.prefix.len();
        let mut steps = Vec::with_capacity(self.ready.len());
        for (offset, ready) in self.ready.drain(..).enumerate() {
            self.pending.push_back(WindowPart {
                index: prefix_len + offset,
                ack: ready.ack,
                metadata: super::session_projection::SourceStepMeta::from_step(&ready.step)?,
                bytes: ready.step.body.len(),
            });
            steps.push(ready.step);
        }
        self.ready_window = false;
        self.window_exhausted =
            !self.more && self.raw.is_empty() && self.curator.first_pending_seq().is_none();
        self.window_end = prefix_len + steps.len();
        self.window_confirmed = prefix_len;
        let mut source = super::session_catchup::CompleteTimeline::window(
            &self.agent,
            snapshot,
            self.prefix.clone(),
            steps,
            boundary,
            self.fetched_end,
            self.window_exhausted,
        )?;
        source.clock = self.clock.clone();
        self.window_token = source.window_token();
        Ok(ProducedWindow {
            source,
            observed_replacement: self.observed_replacement,
            unknown_continuity: self.unknown_continuity,
        })
    }

    /// Only the actual run minted for this window may acknowledge its rows.
    /// Markers do not advance its source prefix, so they free no source slots.
    pub fn settle_from(&mut self, run: &super::session_writer::CatchupRun) -> Result<()> {
        if self.window_token.is_none()
            || run.window_token() != self.window_token
            || run.agent_id() != self.agent
            || self
                .snapshot
                .as_ref()
                .is_none_or(|snapshot| snapshot.check_page(run.source_snapshot()).is_err())
        {
            return Err(Error::engine(
                "source confirmation belongs to another window",
            ));
        }
        let confirmed = run.confirmed_source_prefix();
        if confirmed < self.window_confirmed || confirmed > self.window_end {
            return Err(Error::engine("source confirmation exceeds window"));
        }
        for part in self
            .pending
            .iter()
            .take_while(|part| part.index < confirmed)
        {
            if !run.confirmed_step_matches(part.index, &part.metadata)? {
                return Err(Error::engine(
                    "confirmed source part differs from staged source",
                ));
            }
        }
        while self
            .pending
            .front()
            .is_some_and(|part| part.index < confirmed)
        {
            let part = self.pending.pop_front().expect("checked source part");
            self.budget.confirm(part.ack)?;
            self.body_bytes -= part.bytes;
            self.confirmed_metadata.push(part.metadata);
        }
        self.window_confirmed = confirmed;
        self.confirmed_cursor = Some(run.confirmed_cursor()?);
        self.clock = Some(run.clock());
        self.release_confirmed_rows()
    }

    pub fn finish_window(
        &mut self,
        run: &super::session_writer::CatchupRun,
        chain: super::session_writer::VerifiedChain,
        action: &super::session_writer::CatchupAction,
    ) -> Result<()> {
        self.settle_from(run)?;
        let correct_terminal = if self.window_exhausted {
            matches!(action, super::session_writer::CatchupAction::Complete)
        } else {
            matches!(action, super::session_writer::CatchupAction::WindowComplete)
        };
        if !correct_terminal
            || run.settled_action().as_ref() != Some(action)
            || !self.pending.is_empty()
        {
            return Err(Error::engine("source window has not settled"));
        }
        self.prefix.renew(&chain, &self.confirmed_metadata)?;
        self.confirmed_metadata.clear();
        self.chain = chain;
        self.window_token = None;
        self.observed_replacement = false;
        if self.window_exhausted {
            self.cycle_complete = true;
            self.acknowledged_branch = self.snapshot.as_ref().and_then(|s| s.branch);
            self.unknown_continuity = false;
        }
        Ok(())
    }

    /// Retry an ended or backlogged view from confirmed coverage only. Raw
    /// lookahead is discarded; reserved unfinished rows remain upsertable.
    pub fn refresh(&mut self) -> Result<()> {
        if !(self.cycle_complete || self.backlogged)
            || self.window_token.is_some()
            || self.waiting
            || !self.ready.is_empty()
            || self.invalid
        {
            return Err(Error::engine("cannot refresh an unsettled source pipeline"));
        }
        let cursor =
            self.confirmed_cursor
                .clone()
                .unwrap_or_else(|| super::session_writer::SourceCursor {
                    epoch: self
                        .snapshot
                        .as_ref()
                        .expect("backlogged validated source")
                        .epoch
                        .clone(),
                    seq_end: 0,
                });
        self.pages.refresh_from(&cursor)?;
        self.raw.clear();
        self.cycle_complete = false;
        self.backlogged = false;
        self.ready_window = false;
        self.more = true;
        self.cursor = Some(serde_json::json!({"epoch":cursor.epoch,"seq":cursor.seq_end}));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::session_projection::{Curator, ProjectedEntry, TimelineItem};

    fn user(start: u64, end: u64, text: &str) -> ProjectedEntry {
        ProjectedEntry {
            turn_id: None,
            timestamp: "2026-10-18T20:00:00Z".into(),
            seq_start: start,
            seq_end: end,
            item: TimelineItem::UserMessage {
                text: text.into(),
                message_id: None,
                client_message_id: None,
                attachments: Vec::new(),
            },
        }
    }

    fn empty_chain() -> super::super::session_writer::VerifiedChain {
        super::super::session_writer::VerifiedChain {
            head_pos: None,
            head_cid: None,
            head_fp: None,
            e: vec![],
            marker_branch: None,
        }
    }
    fn source_page(
        rows: Vec<serde_json::Value>,
        first: u64,
        last: u64,
        more: bool,
    ) -> serde_json::Value {
        serde_json::json!({"type":"fetch_agent_timeline_response","payload":{
            "agentId":"a","requestId":"r","projection":"projected","direction":"after",
            "epoch":"epoch","timelineBranch":1,"keptSeqEnd":0,
            "reset":false,"staleCursor":false,"gap":false,"hasNewer":more,"error":null,
            "startCursor":{"epoch":"epoch","seq":first},"endCursor":{"epoch":"epoch","seq":last},
            "entries":rows}})
    }
    fn tool_row(anchor: u64, end: u64, status: &str) -> serde_json::Value {
        serde_json::json!({"seqStart":anchor,"seqEnd":end,"timestamp":"2026-10-18T20:00:00Z",
            "item":{"type":"tool_call","callId":format!("tool-{anchor}"),"name":"read_file",
                "status":status,"detail":{}},"sourceSeqRanges":[],"collapsed":[]})
    }
    fn running_group() -> Vec<serde_json::Value> {
        let mut rows = vec![
            serde_json::json!({"seqStart":1,"seqEnd":1,"timestamp":"2026-10-18T20:00:00Z",
            "item":{"type":"assistant_message","text":"Working"},"sourceSeqRanges":[],"collapsed":[]}),
        ];
        rows.extend((2..=200).map(|seq| tool_row(seq, seq, "running")));
        rows
    }
    fn reader() -> BoundedSource {
        BoundedSource::new(
            "a",
            empty_chain(),
            Some(1),
            Some("epoch".into()),
            false,
            false,
            4 * 1024 * 1024,
        )
        .unwrap()
    }

    #[test]
    fn full_unfinished_group_never_curates_row_201_or_forces_it_at_turn_end() {
        let mut source = reader();
        assert!(matches!(
            source.poll(false).unwrap(),
            SourcePoll::Fetch { cursor: None }
        ));
        source
            .accept_page(&source_page(running_group(), 1, 200, true), "r")
            .unwrap();
        assert!(matches!(
            source.poll(false).unwrap(),
            SourcePoll::Fetch { .. }
        ));
        source
            .accept_page(
                &source_page(vec![tool_row(201, 201, "running")], 201, 201, false),
                "r",
            )
            .unwrap();
        assert_eq!(source.poll(false).unwrap(), SourcePoll::Backlog);
        assert_eq!(source.poll(true).unwrap(), SourcePoll::Backlog);
        assert_eq!(source.pending_entries(), 200);
        assert_eq!(source.raw.front().unwrap().0.seq_start, 201);
        assert!(source.take_window().is_err());
        assert!(source.curator.drain_finalized().is_empty());
    }

    #[test]
    fn unfinished_eof_requeries_confirmed_coverage_without_acknowledging_branch() {
        let mut source = reader();
        source.poll(false).unwrap();
        source
            .accept_page(&source_page(running_group(), 1, 200, false), "r")
            .unwrap();
        assert_eq!(source.poll(false).unwrap(), SourcePoll::Backlog);
        assert!(source.take_window().is_err());
        source.refresh().unwrap();
        assert_eq!(source.pending_entries(), 200);
        assert_eq!(
            source.poll(false).unwrap(),
            SourcePoll::Fetch {
                cursor: Some(serde_json::json!({"epoch":"epoch","seq":0}))
            }
        );
        let mut complete = running_group();
        for row in &mut complete[1..] {
            row["item"]["status"] = serde_json::json!("completed");
        }
        source
            .accept_page(&source_page(complete, 1, 200, false), "r")
            .unwrap();
        assert_eq!(source.poll(true).unwrap(), SourcePoll::Window);
        assert_eq!(source.pending_entries(), 200);
        let window = source.take_window().unwrap();
        assert!(window.source.exhausted());
    }

    #[test]
    fn boundary_lookahead_closes_terminal_200_without_curating_next_message() {
        let mut source = reader();
        source.poll(false).unwrap();
        let first = source_page(running_group(), 1, 200, true);
        source.accept_page(&first, "r").unwrap();
        assert!(matches!(
            source.poll(false).unwrap(),
            SourcePoll::Fetch { .. }
        ));
        let mut updated: Vec<_> = (2..=200)
            .map(|seq| tool_row(seq, seq + 199, "completed"))
            .collect();
        updated.push(
            serde_json::json!({"seqStart":400,"seqEnd":400,"timestamp":"2026-10-18T20:00:00Z",
            "item":{"type":"user_message","text":"Next"},"sourceSeqRanges":[],"collapsed":[]}),
        );
        let second = source_page(updated, 201, 400, false);
        source.accept_page(&second, "r").unwrap();
        assert_eq!(source.poll(false).unwrap(), SourcePoll::Window);
        assert_eq!(source.pending_entries(), 200);
        assert_eq!(source.raw.front().unwrap().0.seq_start, 400);
        let mut legacy = Curator::new();
        legacy.push_page(
            "epoch",
            crate::node::session_projection::parse_projected_entries(&first["payload"]["entries"]),
        );
        legacy.push_page(
            "epoch",
            crate::node::session_projection::parse_projected_entries(&second["payload"]["entries"]),
        );
        let expected = legacy.drain_finalized();
        assert_eq!(
            source
                .ready
                .iter()
                .map(|r| r.step.clone())
                .collect::<Vec<_>>(),
            expected[..expected.len() - 1]
        );
        let window = source.take_window().unwrap();
        assert!(!window.source.exhausted());
        assert!(source.take_window().is_err());
    }

    #[test]
    fn reservation_is_atomic_and_counts_anchors_instead_of_span_width() {
        let mut budget = SourceBudget::default();
        assert!(budget.reserve(&(1..=200).collect::<Vec<_>>()));
        assert!(!budget.reserve(&[1, 201]));
        assert_eq!(budget.pending_entries(), 200);
        budget.omit(&[1]).unwrap();
        assert!(budget.reserve(&[201]));
        let mut wide = SourceBudget::default();
        assert!(wide.reserve(&[10]));
        let mut curator = Curator::new();
        curator.push_page("epoch", vec![user(10, 10_000, "wide")]);
        let acks = wide.stage(&curator.drain_finalized_with_sources()).unwrap();
        assert_eq!(wide.pending_entries(), 1);
        wide.confirm(acks.into_iter().next().unwrap()).unwrap();
        assert_eq!(wide.pending_entries(), 0);
        assert!(wide.reserve(&[10]));
        assert_eq!(wide.pending_entries(), 0);
    }

    #[test]
    fn split_row_stays_reserved_until_every_part_is_confirmed() {
        let mut curator = Curator::new();
        curator.push_page("epoch", vec![user(5, 9, &"x".repeat(180_000))]);
        let parts = curator.drain_finalized_with_sources();
        assert!(parts.len() > 1);
        assert!(parts
            .iter()
            .all(|p| p.source_entries == [5] && p.part_count as usize == parts.len()));
        let mut budget = SourceBudget::default();
        assert!(budget.reserve(&[5]));
        assert!(budget.stage(&parts[..1]).is_err());
        assert_eq!(budget.pending_entries(), 1);
        let mut tokens = budget.stage(&parts).unwrap();
        assert!(budget.omit(&[5]).is_err());
        while tokens.len() > 1 {
            budget.confirm(tokens.remove(0)).unwrap();
            assert_eq!(budget.pending_entries(), 1);
        }
        budget.confirm(tokens.remove(0)).unwrap();
        assert_eq!(budget.pending_entries(), 0);
    }

    #[test]
    fn several_rendered_lines_from_one_row_share_one_source_slot() {
        use crate::node::session_projection::AttachmentRef;
        let mut entry = user(7, 90, "text");
        if let TimelineItem::UserMessage { attachments, .. } = &mut entry.item {
            attachments.extend([AttachmentRef::Image, AttachmentRef::Image]);
        }
        let mut plain = Curator::new();
        let mut sourced = Curator::new();
        plain.push_page("epoch", vec![entry.clone()]);
        sourced.push_page("epoch", vec![entry]);
        let expected = plain.drain_finalized();
        let steps = sourced.drain_finalized_with_sources();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].source_entries, [7]);
        assert_eq!(steps[0].step, expected[0]);
        let mut budget = SourceBudget::default();
        assert!(budget.reserve(&[7, 7]));
        let token = budget.stage(&steps).unwrap().remove(0);
        assert_eq!(budget.pending_entries(), 1);
        budget.confirm(token).unwrap();
        assert_eq!(budget.pending_entries(), 0);
    }

    #[test]
    fn excluded_rows_release_capacity_without_staging_output() {
        let mut omitted = user(1, 1, "");
        assert!(omitted.omitted_by_policy());
        omitted.item = TimelineItem::Reasoning {
            text: "excluded".into(),
        };
        assert!(omitted.omitted_by_policy());
        let mut budget = SourceBudget::default();
        assert!(budget.reserve(&[omitted.seq_start]));
        let mut curator = Curator::new();
        curator.push_page("epoch", vec![omitted.clone()]);
        assert!(curator.drain_finalized_with_sources().is_empty());
        budget.omit(&[omitted.seq_start]).unwrap();
        assert_eq!(budget.pending_entries(), 0);
        let mut attached = user(2, 2, "");
        if let TimelineItem::UserMessage { attachments, .. } = &mut attached.item {
            attachments.push(crate::node::session_projection::AttachmentRef::Image);
        }
        assert!(!attached.omitted_by_policy());
        curator.push_page("epoch", vec![attached]);
        assert_eq!(curator.drain_finalized_with_sources().len(), 1);
    }

    #[test]
    fn a_foreign_pipeline_cannot_release_pending_source() {
        let mut curator = Curator::new();
        curator.push_page("epoch", vec![user(1, 1, "one")]);
        let steps = curator.drain_finalized_with_sources();
        let mut first = SourceBudget::default();
        let mut second = SourceBudget::default();
        assert!(first.reserve(&[1]));
        assert!(second.reserve(&[1]));
        let token = first.stage(&steps).unwrap().remove(0);
        assert!(second.confirm(token).is_err());
        assert_eq!(second.pending_entries(), 1);
    }
}
