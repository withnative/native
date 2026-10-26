//! Portable, file-bound results of the v3 enrichment passes.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const FORMAT: &str = "native.enrichment.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub cli: String,
    pub model: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: String,
    pub lifecycle: Option<String>,
    #[serde(default)]
    pub lifecycle_evidence: Option<String>,
    pub date: Option<String>,
    pub topics: Vec<String>,
    pub content_sha256: String,
}
impl Note {
    pub(super) fn add_facets(&self, facets: &mut Map<String, Value>) {
        if let Some(date) = &self.date {
            facets.insert("stated_date".into(), json!(date));
        }
        if !self.topics.is_empty() {
            facets.insert("topics".into(), json!(self.topics.join(", ")));
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub source: String,
    pub target: String,
    pub relationship: String,
    #[serde(default)]
    pub evidence: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Amendment {
    pub newer: String,
    pub older: String,
    pub evidence: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    // Pair identity survives even when the agent cannot establish direction.
    #[serde(default)]
    pub pair: [String; 2],
    pub newer: Option<String>,
    pub older: Option<String>,
    pub explicit: bool,
    pub confidence: String,
    pub evidence: Option<String>,
    pub score: u8,
}
impl Candidate {
    pub fn rank(&mut self) {
        self.score = if self.explicit { 2 } else { 0 }
            + match self.confidence.as_str() {
                "high" => 2,
                "medium" => 1,
                _ => 0,
            }
            + u8::from(self.newer.is_some());
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Usage {
    pub calls: usize,
    pub cached_calls: usize,
    pub input_chars: usize,
    pub duration_ms: u64,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    pub cached_notes: usize,
    pub pass_c_pairs: usize,
    pub pass_c_calls: usize,
    pub pass_c_dropped_by_cap: usize,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub format: String,
    pub created_at: String,
    pub agent: Agent,
    pub sources: Vec<String>,
    pub notes: BTreeMap<String, Note>,
    pub links: Vec<Link>,
    pub amends: Vec<Amendment>,
    pub supersession_candidates: Vec<Candidate>,
    pub unenriched: Vec<String>,
    pub usage: Usage,
}

pub(super) fn key(root: &str, relative: &str) -> String {
    format!("{root}\0{relative}")
}

/// Only content-bound entries can influence an import. The sidecar is untrusted
/// input; type validation and every mutation still go through the ordinary tools.
#[derive(Default)]
pub(super) struct ImportPlan {
    pub notes: BTreeMap<usize, Note>,
    pub links: BTreeMap<(usize, usize), Link>,
    pub amends: BTreeMap<(usize, usize), String>,
    pub candidates: Vec<Candidate>,
    pub stale: Vec<String>,
}
impl ImportPlan {
    pub fn load(
        path: &std::path::Path,
        roots: &std::collections::BTreeSet<String>,
        entries: &[super::import::Entry],
    ) -> crate::Result<Self> {
        let sidecar: Sidecar = serde_json::from_slice(&std::fs::read(path)?)?;
        if sidecar.format != FORMAT {
            return Err(crate::Error::engine(format!(
                "unsupported enrichment format: {}",
                sidecar.format
            )));
        }
        let sources: std::collections::BTreeSet<_> = sidecar.sources.iter().cloned().collect();
        if &sources != roots || sources.len() != sidecar.sources.len() {
            return Err(crate::Error::engine(
                "enrichment sources do not match the imported directories",
            ));
        }
        let mut plan = Self::default();
        let mut valid = BTreeMap::new();
        let mut legacy_counts = BTreeMap::<String, usize>::new();
        for entry in entries {
            if let Some(file) = &entry.file {
                *legacy_counts
                    .entry(format!("{}::{file}", entry.root))
                    .or_default() += 1;
            }
        }
        for (index, entry) in entries.iter().enumerate() {
            let Some(file) = &entry.file else { continue };
            let canonical_key = key(&entry.root, file);
            let legacy_key = format!("{}::{file}", entry.root);
            let key = if sidecar.notes.contains_key(&canonical_key) {
                canonical_key
            } else {
                if sidecar.notes.contains_key(&legacy_key) && legacy_counts[&legacy_key] > 1 {
                    return Err(crate::Error::engine(
                        "ambiguous legacy enrichment key; re-run native enrich",
                    ));
                }
                legacy_key
            };
            if let Some(note) = sidecar.notes.get(&key) {
                if entry.content_sha256.as_ref() != Some(&note.content_sha256) {
                    plan.stale.push(key);
                    continue;
                }
                valid.insert(key, index);
                plan.notes.insert(index, note.clone());
            }
        }
        for link in sidecar.links {
            let (Some(&s), Some(&t)) = (valid.get(&link.source), valid.get(&link.target)) else {
                continue;
            };
            if s != t
                && ["part_of", "implements", "relates_to"].contains(&link.relationship.as_str())
            {
                plan.links.insert((s, t), link);
            }
        }
        for amendment in sidecar.amends {
            let (Some(&s), Some(&t)) = (valid.get(&amendment.newer), valid.get(&amendment.older))
            else {
                continue;
            };
            if s != t {
                plan.amends.insert((s, t), amendment.evidence);
            }
        }
        for mut candidate in sidecar.supersession_candidates {
            let pair = match (&candidate.newer, &candidate.older) {
                (Some(n), Some(o)) => [n, o],
                _ => [&candidate.pair[0], &candidate.pair[1]],
            };
            if pair[0] != pair[1] && pair.iter().all(|k| valid.contains_key(*k)) {
                candidate.rank();
                plan.candidates.push(candidate);
            }
        }
        plan.candidates
            .sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.pair.cmp(&b.pair)));
        plan.candidates.truncate(15);
        Ok(plan)
    }
}
