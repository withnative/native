//! Source-side catch-up preparation. This module consumes correlated,
//! projected daemon pages, never live stream content. No source list escapes
//! before the last page has passed the same epoch/branch/cut checks.
//!
//! Fetch continuation and confirmed restart cursors are deliberately distinct:
//! a fetched page may include an unfinished group or several parts of one row.
//! The caller must align the complete result against hosted E before using a
//! confirmed cursor, and must discard this fetch on timeline replacement.
//! This is preparation only; it starts no task and performs no hosted writes.

use serde_json::{json, Value};

use crate::error::{Error, Result};

use super::session_projection::{parse_projected_entries, Curator, ProjectedStep, SourceStepMeta};
use super::session_writer::{AlignmentPlan, SourceCursor, SourceSnapshot, VerifiedChain};

/// Maximum projected rows accepted from one requested page. The daemon
/// request must carry this limit; snapshot memory is separately bounded.
pub const SOURCE_PAGE_LIMIT: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchAction {
    Next {
        cursor: Value,
    },
    Complete,
    /// No buffered output is usable. Restart with a fresh request id and
    /// no cursor; an old response must never be fed to the replacement fetch.
    Restart,
    /// Preserve hosted/checkpoint state, pause, then refetch when capacity
    /// permits. Partial buffered curation is never published.
    Backlog,
}

/// Strict page admission shared by complete and bounded source readers.
/// Releasing byte accounting is allowed only after the caller has consumed
/// that raw page; epoch/branch/cursor continuity is retained.
pub struct TimelinePages {
    agent_id: String,
    snapshot: Option<SourceSnapshot>,
    fetched_end: Option<u64>,
    bytes: usize,
    limit_bytes: usize,
    complete: bool,
    invalid: bool,
}

pub struct ValidatedPage {
    pub snapshot: SourceSnapshot,
    pub entries: Vec<super::session_projection::ProjectedEntry>,
    pub row_bytes: Vec<usize>,
    pub fetched_end: Option<u64>,
    pub has_more: bool,
}

impl TimelinePages {
    pub fn new(agent_id: &str, limit_bytes: usize) -> Result<Self> {
        if agent_id.is_empty() || limit_bytes == 0 {
            return Err(Error::engine("invalid source catch-up limits or agent"));
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            snapshot: None,
            fetched_end: None,
            bytes: 0,
            limit_bytes,
            complete: false,
            invalid: false,
        })
    }
    pub fn invalidate(&mut self) {
        self.invalid = true;
    }
    pub fn refresh_from(&mut self, cursor: &SourceCursor) -> Result<()> {
        if self.invalid
            || self
                .snapshot
                .as_ref()
                .is_none_or(|s| s.epoch != cursor.epoch)
        {
            return Err(Error::engine(
                "cannot refresh an invalid or foreign source epoch",
            ));
        }
        self.fetched_end = Some(cursor.seq_end);
        self.complete = false;
        self.bytes = 0;
        Ok(())
    }
    pub fn release_page_bytes(&mut self, available: usize) {
        self.bytes = 0;
        self.limit_bytes = available;
    }
    pub fn accept(
        &mut self,
        frame: &Value,
        request_id: &str,
    ) -> Result<(FetchAction, Option<ValidatedPage>)> {
        if self.invalid || self.complete {
            return Err(Error::engine("source fetch is no longer accepting pages"));
        }
        // Any refusal poisons the batch, including malformed responses. The
        // caller cannot catch an error and accidentally publish its prefix.
        self.invalid = true;
        let p = &frame["payload"];
        if frame["type"] != "fetch_agent_timeline_response"
            || p["agentId"] != self.agent_id
            || p["requestId"] != request_id
            || p["projection"] != "projected"
            || p["direction"] != "after"
            || !p.get("error").is_some_and(Value::is_null)
        {
            return Err(Error::engine(
                "uncorrelated or refused source timeline page",
            ));
        }
        let epoch = p["epoch"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::engine("source page lacks epoch"))?;
        let branch = optional_u64(p, "timelineBranch", false)?;
        let cut = optional_u64(p, "keptSeqEnd", true)?;
        if branch.is_none() && cut.is_some() {
            return Err(Error::engine("source cut without branch"));
        }
        let snapshot = SourceSnapshot {
            epoch: epoch.to_owned(),
            branch,
            kept_seq_end: cut,
        };
        let stale = required_bool(p, "staleCursor")?;
        let reset = required_bool(p, "reset")?;
        let gap = required_bool(p, "gap")?;
        let more = required_bool(p, "hasNewer")?;
        if stale || gap || (self.snapshot.is_some() && reset) {
            return Ok((FetchAction::Restart, None));
        }
        if let Some(first) = &self.snapshot {
            if first.check_page(&snapshot).is_err() {
                return Ok((FetchAction::Restart, None));
            }
        }
        let rows = p["entries"]
            .as_array()
            .ok_or_else(|| Error::engine("source page lacks entries"))?;
        if rows.len() > SOURCE_PAGE_LIMIT {
            return Err(Error::engine("source page exceeds requested row limit"));
        }
        let size = serde_json::to_vec(p)
            .map_err(|e| Error::engine(format!("cannot size source page: {e}")))?
            .len();
        let Some(total) = self.bytes.checked_add(size) else {
            return Ok((FetchAction::Backlog, None));
        };
        if total > self.limit_bytes {
            return Ok((FetchAction::Backlog, None));
        }
        let end = parse_cursor(&p["endCursor"], epoch)?;
        let start = parse_cursor(&p["startCursor"], epoch)?;
        // Projected lifecycle rows can span discontiguous source ranges.
        // Their seqEnd may exceed this page's contiguous coverage cursor,
        // and their display anchor can recur on a later page.
        if start.is_some() != end.is_some()
            || start.zip(end).is_some_and(|(a, b)| a > b)
            || end.is_some_and(|seq| self.fetched_end.is_some_and(|old| seq <= old))
            || start.is_some_and(|seq| {
                self.fetched_end
                    .is_some_and(|old| old.checked_add(1) != Some(seq))
            })
            || (more && end.is_none())
            || (!rows.is_empty() && end.is_none())
        {
            return Err(Error::engine(
                "source page cursor does not advance its window",
            ));
        }
        let mut previous_start = None;
        for row in rows {
            let a = row["seqStart"]
                .as_u64()
                .ok_or_else(|| Error::engine("source row lacks seqStart"))?;
            let b = row["seqEnd"]
                .as_u64()
                .ok_or_else(|| Error::engine("source row lacks seqEnd"))?;
            if a > b || previous_start.is_some_and(|old| a <= old) {
                return Err(Error::engine("source row spans are not ordered"));
            }
            previous_start = Some(a);
        }
        self.snapshot = Some(snapshot.clone());
        self.bytes = total;
        self.fetched_end = end.or(self.fetched_end);
        self.complete = !more;
        let row_bytes = rows
            .iter()
            .map(|row| {
                serde_json::to_vec(row)
                    .map(|bytes| bytes.len())
                    .map_err(|e| Error::engine(format!("cannot size source row: {e}")))
            })
            .collect::<Result<Vec<_>>>()?;
        let page = ValidatedPage {
            snapshot,
            entries: parse_projected_entries(&p["entries"]),
            row_bytes,
            fetched_end: self.fetched_end,
            has_more: more,
        };
        let action = if more {
            FetchAction::Next {
                cursor: json!({"epoch":epoch,"seq":end}),
            }
        } else {
            FetchAction::Complete
        };
        self.invalid = false;
        Ok((action, Some(page)))
    }
}

pub struct TimelineFetch {
    pages: TimelinePages,
    curator: Curator,
    steps: Vec<ProjectedStep>,
}

impl TimelineFetch {
    pub fn new(agent_id: &str, limit_bytes: usize) -> Result<Self> {
        Ok(Self {
            pages: TimelinePages::new(agent_id, limit_bytes)?,
            curator: Curator::new(),
            steps: Vec::new(),
        })
    }
    pub fn invalidate(&mut self) {
        self.pages.invalidate();
    }
    pub fn accept(&mut self, frame: &Value, request_id: &str) -> Result<FetchAction> {
        let (action, page) = self.pages.accept(frame, request_id)?;
        if let Some(page) = page {
            self.curator.push_page(&page.snapshot.epoch, page.entries);
            self.steps.extend(self.curator.drain_finalized());
        }
        Ok(action)
    }
    pub fn finish(mut self, turn_ended: bool) -> Result<CompleteTimeline> {
        if self.pages.invalid || !self.pages.complete {
            return Err(Error::engine("cannot publish an incomplete source fetch"));
        }
        if turn_ended {
            self.curator.end_turn();
            self.steps.extend(self.curator.drain_finalized());
        }
        Ok(CompleteTimeline {
            agent_id: self.pages.agent_id,
            prefix: None,
            exhausted: true,
            window_token: None,
            clock: None,
            snapshot: self
                .pages
                .snapshot
                .ok_or_else(|| Error::engine("no source snapshot"))?,
            steps: self.steps,
            pending_seq_start: self.curator.first_pending_seq(),
            fetched_end: self.pages.fetched_end,
        })
    }
}

fn required_bool(p: &Value, key: &str) -> Result<bool> {
    p[key]
        .as_bool()
        .ok_or_else(|| Error::engine(format!("source page lacks {key}")))
}

fn optional_u64(p: &Value, key: &str, nullable: bool) -> Result<Option<u64>> {
    match p.get(key) {
        None => Ok(None),
        Some(Value::Null) if nullable => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| Error::engine(format!("invalid source {key}"))),
    }
}

fn parse_cursor(value: &Value, epoch: &str) -> Result<Option<u64>> {
    if value.is_null() {
        return Ok(None);
    }
    if value["epoch"] != epoch {
        return Err(Error::engine("source cursor belongs to another epoch"));
    }
    value["seq"]
        .as_u64()
        .map(Some)
        .ok_or_else(|| Error::engine("source cursor lacks seq"))
}

/// A streamed prefix compared to a previously verified hosted head. Body
/// bytes are discarded only after their actual curated fingerprints match.
#[derive(Clone)]
pub struct ComparedPrefix {
    head: (Option<u64>, Option<String>),
    expected: Vec<String>,
    metadata: Vec<SourceStepMeta>,
}

impl ComparedPrefix {
    pub fn new(chain: &VerifiedChain) -> Self {
        Self {
            head: (chain.head_pos, chain.head_cid.clone()),
            expected: chain.e.clone(),
            metadata: Vec::new(),
        }
    }
    pub fn compare(&mut self, step: &ProjectedStep) -> Result<bool> {
        let metadata = SourceStepMeta::from_step(step)?;
        if self.expected.get(self.metadata.len()) != Some(&metadata.fingerprint) {
            return Ok(false);
        }
        self.metadata.push(metadata);
        Ok(true)
    }
    pub fn len(&self) -> usize {
        self.metadata.len()
    }
    /// Renew only after the window's confirmed actual tail accounts for the
    /// entire current verified E. An extra foreign suffix forces realignment.
    pub fn renew(&mut self, chain: &VerifiedChain, confirmed: &[SourceStepMeta]) -> Result<()> {
        let mut metadata = self.metadata.clone();
        metadata.extend_from_slice(confirmed);
        if metadata.len() != chain.e.len()
            || metadata
                .iter()
                .zip(&chain.e)
                .any(|(m, fp)| &m.fingerprint != fp)
        {
            return Err(Error::engine(
                "confirmed window does not account for verified hosted E",
            ));
        }
        self.metadata = metadata;
        self.expected = chain.e.clone();
        self.head = (chain.head_pos, chain.head_cid.clone());
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }
}

pub struct CompleteTimeline {
    agent_id: String,
    prefix: Option<ComparedPrefix>,
    exhausted: bool,
    window_token: Option<uuid::Uuid>,
    pub(super) clock: Option<super::session_writer::CatchupClock>,
    pub snapshot: SourceSnapshot,
    pub steps: Vec<ProjectedStep>,
    pending_seq_start: Option<u64>,
    /// Continuation only. Never use this as a confirmed restart checkpoint.
    pub fetched_end: Option<u64>,
}

impl CompleteTimeline {
    /// A bounded tail behind an actual compared prefix. This constructor
    /// does not establish hosted admission: plan re-verifies the exact head,
    /// prefix and branch before any spool can be sent.
    #[allow(clippy::too_many_arguments)]
    pub fn window(
        agent_id: &str,
        snapshot: SourceSnapshot,
        prefix: ComparedPrefix,
        steps: Vec<ProjectedStep>,
        pending_seq_start: Option<u64>,
        fetched_end: Option<u64>,
        exhausted: bool,
    ) -> Result<Self> {
        if agent_id.is_empty() {
            return Err(Error::engine("source window lacks agent"));
        }
        snapshot.check_page(&snapshot)?;
        for step in &steps {
            SourceStepMeta::from_step(step)?;
        }
        Ok(Self {
            agent_id: agent_id.to_owned(),
            prefix: Some(prefix),
            exhausted,
            window_token: Some(uuid::Uuid::new_v4()),
            clock: None,
            snapshot,
            steps,
            pending_seq_start,
            fetched_end,
        })
    }
    pub fn source_len(&self) -> usize {
        self.prefix.as_ref().map_or(0, |p| p.metadata.len()) + self.steps.len()
    }
    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
    pub fn window_token(&self) -> Option<uuid::Uuid> {
        self.window_token
    }
    pub fn windowed(&self) -> bool {
        self.prefix.is_some()
    }
    pub fn step(&self, index: usize) -> Result<&ProjectedStep> {
        index
            .checked_sub(self.prefix.as_ref().map_or(0, |p| p.metadata.len()))
            .and_then(|i| self.steps.get(i))
            .ok_or_else(|| Error::engine("source index is outside pending tail"))
    }
    fn metadata(&self) -> Result<Vec<SourceStepMeta>> {
        let mut metadata = self
            .prefix
            .as_ref()
            .map_or_else(Vec::new, |p| p.metadata.clone());
        metadata.extend(
            self.steps
                .iter()
                .map(SourceStepMeta::from_step)
                .collect::<Result<Vec<_>>>()?,
        );
        Ok(metadata)
    }
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
    /// A branch marker may have committed before its state acknowledgement.
    /// Only immutable, history-verified marker evidence can suppress that
    /// same branch's second rewind marker. Compare the already-folded E with
    /// T normally, so any content divergence still produces a resync. Keep
    /// disclosure based on the old acknowledgement even when resuming.
    pub fn plan(
        &self,
        chain: &VerifiedChain,
        acknowledged_branch: Option<u64>,
        observed_replacement: bool,
        unknown_continuity: bool,
    ) -> Result<AlignmentPlan> {
        if chain
            .marker_branch
            .zip(self.snapshot.branch)
            .is_some_and(|(saved, current)| current < saved)
        {
            return Err(Error::engine(
                "source branch predates verified hosted marker",
            ));
        }
        let unknown_continuity =
            unknown_continuity || (chain.marker_branch.is_some() && self.snapshot.branch.is_none());
        let metadata = self.metadata()?;
        if let Some(prefix) = &self.prefix {
            if prefix.head != (chain.head_pos, chain.head_cid.clone())
                || prefix
                    .metadata
                    .iter()
                    .enumerate()
                    .any(|(i, m)| chain.e.get(i) != Some(&m.fingerprint))
            {
                return Err(Error::engine(
                    "compared source prefix lost its verified hosted head",
                ));
            }
        }
        // A shorter partial page is not evidence that the hosted suffix was
        // removed. Wait for divergence, the real cut, or actual source EOF.
        let ordinary_lcp = chain
            .e
            .iter()
            .zip(&metadata)
            .take_while(|(fp, m)| **fp == m.fingerprint)
            .count();
        let original = super::session_writer::plan_alignment_meta(
            &chain.e,
            &metadata,
            acknowledged_branch,
            &self.snapshot,
            observed_replacement,
            unknown_continuity,
        )?;
        if self.snapshot.branch.is_some() && chain.marker_branch == self.snapshot.branch {
            let mut resumed = super::session_writer::plan_alignment_meta(
                &chain.e,
                &metadata,
                self.snapshot.branch,
                &self.snapshot,
                false,
                unknown_continuity,
            )?;
            resumed.continuity_assumed |= original.continuity_assumed;
            self.check_window_plan(&resumed, chain, metadata.len(), ordinary_lcp)?;
            Ok(resumed)
        } else {
            self.check_window_plan(&original, chain, metadata.len(), ordinary_lcp)?;
            Ok(original)
        }
    }
    fn check_window_plan(
        &self,
        plan: &AlignmentPlan,
        chain: &VerifiedChain,
        available: usize,
        ordinary_lcp: usize,
    ) -> Result<()> {
        let prefix = self.prefix.as_ref().map_or(0, |p| p.metadata.len());
        if plan.base_len < prefix {
            return Err(Error::engine(
                "compared source prefix crosses alignment cut",
            ));
        }
        if !self.exhausted
            && plan.base_len == available
            && ordinary_lcp == available
            && available < chain.e.len()
        {
            return Err(Error::engine(
                "partial source window cannot truncate unseen hosted suffix",
            ));
        }
        Ok(())
    }

    /// Map a confirmed prefix of the *aligned* source list to a conservative
    /// restart cursor. Keep all parts of one split row replayable until the
    /// last part is confirmed, and never cross a pending curator group.
    pub fn confirmed_cursor(&self, confirmed_steps: usize) -> Result<SourceCursor> {
        let metadata = self.metadata()?;
        if confirmed_steps > metadata.len() {
            return Err(Error::engine("confirmed source prefix exceeds timeline"));
        }
        let boundary = metadata[confirmed_steps..]
            .iter()
            .map(|s| s.seq_start)
            .chain(self.pending_seq_start)
            .min();
        let seq_end = metadata[..confirmed_steps]
            .iter()
            .filter(|step| boundary.is_none_or(|next| step.seq_end < next))
            .map(|step| step.seq_end)
            .max()
            .unwrap_or(0)
            .min(self.fetched_end.unwrap_or(0));
        Ok(SourceCursor {
            epoch: self.snapshot.epoch.clone(),
            seq_end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::session_projection::MAX_STEP_BYTES;

    fn row(seq: u64, end: u64, kind: &str, text: &str) -> Value {
        json!({"seqStart":seq,"seqEnd":end,"timestamp":"2026-10-18T10:00:00Z",
            "item":{"type":kind,"text":text},"sourceSeqRanges":[],"collapsed":[]})
    }

    fn page(rows: Vec<Value>, more: bool, branch: u64) -> Value {
        let start = rows
            .first()
            .map(|r| json!({"epoch":"e","seq":r["seqStart"]}));
        let end = rows
            .iter()
            .filter_map(|r| r["seqEnd"].as_u64())
            .max()
            .map(|seq| json!({"epoch":"e","seq":seq}));
        json!({"type":"fetch_agent_timeline_response","payload":{
            "requestId":"r","agentId":"a","projection":"projected","direction":"after",
            "epoch":"e","timelineBranch":branch,"keptSeqEnd":0,
            "reset":false,"staleCursor":false,"gap":false,"hasNewer":more,
            "error":null,"startCursor":start,"endCursor":end,"entries":rows}})
    }

    #[test]
    fn pages_do_not_close_groups_or_publish_partial_snapshots() {
        let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
        assert_eq!(
            f.accept(
                &page(vec![row(1, 1, "assistant_message", "answer")], true, 1),
                "r"
            )
            .unwrap(),
            FetchAction::Next {
                cursor: json!({"epoch":"e","seq":1})
            }
        );
        assert!(f.steps.is_empty());
        let mut tool = row(2, 3, "tool_call", "");
        tool["item"] = json!({"type":"tool_call","name":"shell","status":"completed",
            "detail":{"type":"shell","command":"pwd"}});
        assert_eq!(
            f.accept(
                &page(vec![tool, row(4, 4, "user_message", "next")], false, 1),
                "r"
            )
            .unwrap(),
            FetchAction::Complete
        );
        let done = f.finish(false).unwrap();
        assert_eq!(done.steps.len(), 2);
        assert_eq!((done.steps[0].seq_start, done.steps[0].seq_end), (1, 3));
        assert_eq!(done.confirmed_cursor(1).unwrap().seq_end, 3);
        assert_eq!(done.confirmed_cursor(2).unwrap().seq_end, 4);
    }

    #[test]
    fn branch_or_cut_change_and_replacement_discard_the_entire_fetch() {
        for change in ["timelineBranch", "keptSeqEnd", "epoch"] {
            let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
            f.accept(&page(vec![row(1, 1, "user_message", "one")], true, 1), "r")
                .unwrap();
            let mut next = page(vec![row(2, 2, "user_message", "two")], false, 1);
            next["payload"][change] = if change == "epoch" {
                json!("new")
            } else {
                json!(2)
            };
            assert_eq!(f.accept(&next, "r").unwrap(), FetchAction::Restart);
            assert!(f.finish(false).is_err());
        }
        let mut f = TimelineFetch::new("a", 1024).unwrap();
        f.invalidate();
        assert!(f.accept(&page(vec![], false, 0), "r").is_err());
    }

    #[test]
    fn split_row_cannot_advance_checkpoint_until_all_parts_confirm() {
        let mut f = TimelineFetch::new("a", MAX_STEP_BYTES * 5).unwrap();
        let text = "x".repeat(MAX_STEP_BYTES * 2);
        f.accept(&page(vec![row(1, 2, "user_message", &text)], false, 0), "r")
            .unwrap();
        let done = f.finish(false).unwrap();
        assert!(done.steps.len() >= 3);
        for count in 0..done.steps.len() {
            assert_eq!(done.confirmed_cursor(count).unwrap().seq_end, 0);
        }
        assert_eq!(done.confirmed_cursor(done.steps.len()).unwrap().seq_end, 2);
    }

    #[test]
    fn fetched_cursor_never_skips_pending_assistant_group() {
        let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
        f.accept(
            &page(
                vec![
                    row(1, 1, "user_message", "prompt"),
                    row(2, 20, "assistant_message", "still streaming"),
                ],
                false,
                0,
            ),
            "r",
        )
        .unwrap();
        let done = f.finish(false).unwrap();
        assert_eq!(done.fetched_end, Some(20));
        assert_eq!(done.steps.len(), 1);
        assert_eq!(done.confirmed_cursor(1).unwrap().seq_end, 1);
        assert!(done.confirmed_cursor(2).is_err());
        let mut ended = TimelineFetch::new("a", 1024 * 1024).unwrap();
        ended
            .accept(
                &page(vec![row(2, 20, "assistant_message", "finished")], false, 0),
                "r",
            )
            .unwrap();
        let done = ended.finish(true).unwrap();
        assert_eq!(done.confirmed_cursor(1).unwrap().seq_end, 20);
    }

    #[test]
    fn malformed_or_uncorrelated_pages_poison_the_batch() {
        for mutation in ["requestId", "agentId", "endCursor", "entries"] {
            let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
            let mut p = page(vec![row(1, 1, "user_message", "one")], false, 0);
            p["payload"][mutation] = json!("invalid");
            assert!(f.accept(&p, "r").is_err());
            assert!(f.finish(false).is_err());
        }
        let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
        let mut bad = page(vec![row(3, 2, "user_message", "one")], false, 0);
        assert!(f.accept(&bad, "r").is_err());
        bad["payload"]["entries"] = json!([]);
        assert!(f.accept(&bad, "r").is_err());
    }

    #[test]
    fn bounded_fetch_and_empty_continuation_never_publish_a_prefix() {
        let mut f = TimelineFetch::new("a", 1).unwrap();
        assert_eq!(
            f.accept(&page(vec![row(1, 1, "user_message", "one")], false, 0), "r")
                .unwrap(),
            FetchAction::Backlog
        );
        assert!(f.finish(false).is_err());
        let mut f = TimelineFetch::new("a", 1024).unwrap();
        assert!(f.accept(&page(vec![], true, 0), "r").is_err());
        let mut f = TimelineFetch::new("a", 1024).unwrap();
        f.accept(&page(vec![], false, 0), "r").unwrap();
        let done = f.finish(false).unwrap();
        assert_eq!(done.confirmed_cursor(0).unwrap().seq_end, 0);
    }
    #[test]
    fn discontiguous_spans_use_daemon_cursor_and_allow_repeated_anchors() {
        let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
        let mut first = page(vec![row(1, 10, "user_message", "wide")], true, 0);
        first["payload"]["endCursor"]["seq"] = json!(1);
        assert_eq!(
            f.accept(&first, "r").unwrap(),
            FetchAction::Next {
                cursor: json!({"epoch":"e","seq":1})
            }
        );
        let mut next = page(
            vec![
                row(1, 10, "user_message", "wide"),
                row(2, 9, "user_message", "middle"),
            ],
            false,
            0,
        );
        next["payload"]["startCursor"]["seq"] = json!(2);
        assert_eq!(f.accept(&next, "r").unwrap(), FetchAction::Complete);
        let done = f.finish(false).unwrap();
        assert_eq!(done.steps.len(), 2);
        assert_eq!(done.confirmed_cursor(1).unwrap().seq_end, 0);
        assert_eq!(done.confirmed_cursor(2).unwrap().seq_end, 10);
    }

    #[test]
    fn verified_marker_resumes_before_branch_ack_without_losing_disclosure() {
        let mut f = TimelineFetch::new("a", 1024 * 1024).unwrap();
        f.accept(
            &page(vec![row(1, 1, "user_message", "regenerated")], false, 3),
            "r",
        )
        .unwrap();
        let done = f.finish(false).unwrap();
        let mut chain = VerifiedChain {
            head_pos: Some(7),
            head_cid: Some("verified".into()),
            head_fp: Some("marker".into()),
            e: vec![],
            marker_branch: Some(3),
        };
        let resumed = done.plan(&chain, Some(1), false, false).unwrap();
        assert_eq!(resumed.marker, None);
        assert_eq!(resumed.base_len, 0);
        assert!(resumed.continuity_assumed);
        chain.e.push(done.steps[0].fingerprint.clone());
        assert_eq!(
            done.plan(&chain, Some(1), false, false).unwrap().base_len,
            1
        );
        chain.e[0] = "different-content".into();
        assert_eq!(
            done.plan(&chain, Some(1), false, false).unwrap().marker,
            Some(super::super::session_writer::MarkerKind::Resync)
        );
        chain.marker_branch = None;
        assert_eq!(
            done.plan(&chain, Some(1), false, false).unwrap().marker,
            Some(super::super::session_writer::MarkerKind::Rewound)
        );
    }
    fn source_steps(texts: &[&str]) -> Vec<ProjectedStep> {
        let mut curator = Curator::new();
        curator.push_page(
            "e",
            texts
                .iter()
                .enumerate()
                .map(|(i, text)| {
                    super::super::session_projection::ProjectedEntry::from_value(
                        &row(i as u64 + 1, i as u64 + 1, "user_message", text),
                        i as u64,
                    )
                })
                .collect(),
        );
        curator.drain_finalized()
    }
    fn saved(steps: &[ProjectedStep]) -> VerifiedChain {
        VerifiedChain {
            head_pos: Some(steps.len() as u64),
            head_cid: Some("head".into()),
            head_fp: None,
            e: steps.iter().map(|s| s.fingerprint.clone()).collect(),
            marker_branch: None,
        }
    }
    fn snapshot() -> SourceSnapshot {
        SourceSnapshot {
            epoch: "e".into(),
            branch: Some(0),
            kept_seq_end: Some(0),
        }
    }
    #[test]
    fn partial_window_does_not_truncate_an_unseen_saved_suffix() {
        let steps = source_steps(&["one", "two"]);
        let chain = saved(&steps);
        let make = |exhausted| {
            CompleteTimeline::window(
                "a",
                snapshot(),
                ComparedPrefix::new(&chain),
                vec![steps[0].clone()],
                None,
                Some(1),
                exhausted,
            )
            .unwrap()
        };
        assert!(make(false).plan(&chain, Some(0), false, false).is_err());
        let plan = make(true).plan(&chain, Some(0), false, false).unwrap();
        assert_eq!(plan.base_len, 1);
        assert_eq!(
            plan.marker,
            Some(super::super::session_writer::MarkerKind::Resync)
        );
    }
    #[test]
    fn compared_prefix_requires_actual_fingerprints_and_the_same_verified_head() {
        let steps = source_steps(&["one", "two"]);
        let chain = saved(&steps[..1]);
        let mut prefix = ComparedPrefix::new(&chain);
        let mut invalid = steps[0].clone();
        invalid.body.push_str("changed");
        assert!(prefix.compare(&invalid).is_err());
        assert!(prefix.is_empty());
        assert!(prefix.compare(&steps[0]).unwrap());
        let window = CompleteTimeline::window(
            "a",
            snapshot(),
            prefix,
            vec![steps[1].clone()],
            None,
            Some(2),
            false,
        )
        .unwrap();
        assert_eq!(
            window.plan(&chain, Some(0), false, false).unwrap().base_len,
            1
        );
        assert!(window.step(0).is_err());
        assert_eq!(window.step(1).unwrap(), &steps[1]);
        let mut moved = chain.clone();
        moved.head_cid = Some("different-head".into());
        assert!(window.plan(&moved, Some(0), false, false).is_err());
    }
    #[test]
    fn compared_prefix_cannot_cross_a_known_rewind_cut() {
        let steps = source_steps(&["identical"]);
        let chain = saved(&steps);
        let mut prefix = ComparedPrefix::new(&chain);
        assert!(prefix.compare(&steps[0]).unwrap());
        let rewound = SourceSnapshot {
            epoch: "e".into(),
            branch: Some(2),
            kept_seq_end: Some(0),
        };
        let invalid =
            CompleteTimeline::window("a", rewound.clone(), prefix, vec![], None, Some(1), true)
                .unwrap();
        assert!(invalid.plan(&chain, Some(0), false, false).is_err());
        let valid = CompleteTimeline::window(
            "a",
            rewound,
            ComparedPrefix::new(&chain),
            steps,
            None,
            Some(1),
            true,
        )
        .unwrap();
        let plan = valid.plan(&chain, Some(0), false, false).unwrap();
        assert_eq!(plan.base_len, 0);
        assert_eq!(
            plan.marker,
            Some(super::super::session_writer::MarkerKind::Rewound)
        );
        assert!(plan.continuity_assumed);
    }
    #[test]
    fn split_row_remains_before_cursor_when_its_first_part_is_in_compared_prefix() {
        let mut curator = Curator::new();
        curator.push_page(
            "e",
            vec![
                super::super::session_projection::ProjectedEntry::from_value(
                    &row(1, 1, "user_message", &"x".repeat(MAX_STEP_BYTES * 2)),
                    0,
                ),
            ],
        );
        let steps = curator.drain_finalized();
        assert!(steps.len() > 1);
        let chain = saved(&steps[..1]);
        let mut prefix = ComparedPrefix::new(&chain);
        assert!(prefix.compare(&steps[0]).unwrap());
        let window = CompleteTimeline::window(
            "a",
            snapshot(),
            prefix,
            steps[1..].to_vec(),
            None,
            Some(1),
            true,
        )
        .unwrap();
        assert_eq!(window.confirmed_cursor(1).unwrap().seq_end, 0);
        assert_eq!(
            window
                .confirmed_cursor(window.source_len())
                .unwrap()
                .seq_end,
            1
        );
    }
}
