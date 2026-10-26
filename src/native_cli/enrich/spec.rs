//! The measured v3 briefs are embedded verbatim; schemas match the handoff scripts.
pub(super) const BRIEF_A: &str = r###"You are helping turn a folder of Markdown notes into a structured workspace. You will see a batch of notes from one person's or team's notes folder. Each note is shown with its folder path, file name and text (long notes are cut short).

For each note, decide only what the note itself supports:

1. "type" and "kind" — what the note is. Use one of these pairs where it fits:
   - Document/note — ordinary prose: write-ups, analysis, plans, meeting notes, ideas
   - Document/artifact — a built or designed deliverable (page, diagram, mock-up, HTML/visual) described or embedded
   - Document/attachment — a stored file or captured raw source with little authored prose
   - Document/review — only a critique of one specific named piece of work (a draft, a pull request, a design) by a reviewer. Analyses, assessments, investigations and findings are Document/note.
   - Document/raw_agent_response — only a verbatim model reply kept as raw source (usually titled "Raw …"); a synthesis or write-up of agent responses is a Document/note
   - WorkItem/task — only when the note itself is a unit of work that someone is doing or should do: it assigns or tracks that work (an owner, a next step, done-when, a status, a checklist, "claim this record"), or an experiment or attempt being run with a plan and a readout. A note that discusses, analyses, proposes or reports on work is a Document/note, even if it suggests next steps or has a title phrased as an action.
   - WorkItem/epic — a larger body of work grouping tasks
   - Resolution/decision — only when the note records a choice that was actually made or ratified, or is explicitly a decision record awaiting someone's choice. Proposals, recommendations, assessments, briefings and options papers are Document/note, even if they argue for an answer or have "decision" in the title. If the text says nothing was chosen or it is not ratified, it is not a decision.
   - Entity/person, Entity/organization — a profile of a person or organisation
   - Collection/query — a saved table/list/view definition rather than prose
   If none fits, use Document with your own short lowercase kind (e.g. "essay-draft").
2. "lifecycle" — only for WorkItem: one of open, in_progress, blocked, completed, closed (closed = stopped or finished without achieving its aim). Use an explicit "Status:" line if there is one. If the note reports the outcome of its own work in the past tense (results, a readout, "published", "merged", "the result was"), the work is finished: completed if it achieved its aim, closed if it did not. Use null for non-WorkItems, or if the text gives no signal at all.
3. "lifecycle_evidence" — a short verbatim quote (under 20 words) supporting the lifecycle, or null.
4. "date" — the date the note says it was written or happened (YYYY-MM-DD), or null if the text does not say.
5. "topics" — 1 to 3 short lowercase topic labels, reused across notes in this batch when they share a subject.

Do not guess beyond the text. Answer for every note id given, in the JSON format requested.
"###;
pub(super) const SCHEMA_A: &str = r###"{"type":"object","properties":{"notes":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"type":{"type":"string"},"kind":{"type":"string"},"lifecycle":{"type":["string","null"]},"lifecycle_evidence":{"type":["string","null"]},"date":{"type":["string","null"]},"topics":{"type":"array","items":{"type":"string"}}},"required":["id","type","kind","lifecycle","date","topics"]}}},"required":["notes"]}"###;
pub(super) const BRIEF_B: &str = r###"You are helping turn a folder of Markdown notes into a structured workspace. Each note below links to some other notes. For every link, say what kind of relationship it is, reading both notes.

Use one of these relationship types, from the point of view of the SOURCE note:
- part_of — the source is a component, child task, section or member of the target
- implements — the source carries out or delivers what the target asks for or decides
- relates_to — anything else: related, follows on, draws on, compares, discusses

Do not judge whether one note replaces another; that is checked separately. When unsure between part_of or implements and relates_to, choose relates_to. Give a short verbatim quote (under 20 words) from either note as evidence for part_of or implements.
"###;
pub(super) const SCHEMA_B: &str = r###"{"type":"object","properties":{"links":{"type":"array","items":{"type":"object","properties":{"source":{"type":"string"},"target":{"type":"string"},"relationship":{"type":"string"},"evidence":{"type":["string","null"]}},"required":["source","target","relationship"]}}},"required":["links"]}"###;
pub(super) const BRIEF_C: &str = r###"You are checking pairs of linked notes from a team's notes folder. For each pair, decide whether one of the two notes makes the other no longer current.

Answer one of:
- "replaces": every part of one note is no longer current because of the other. Examples: a later draft or version of the same document; a decision that reverses or overrules an earlier decision as a whole; a note that says the other is obsolete.
- "amends": one note changes, overrides, narrows or defers part of the other, while some of the other still stands.
- "independent": neither makes the other less current. They relate, follow on, build on, carry out or answer each other, but both still stand.

Rules that often decide the answer:
- If any part of the older note still stands (an open question still open, a decision limb still in force, scope still to do), it is "amends" at most, never "replaces".
- A task that carries out a decision, or a decision that adopts what a proposal or question asked for, is "independent": it settles the earlier note rather than replacing it.
- A part never replaces its whole, and a whole never replaces its part.
- Alternatives explored side by side (variants, tests, options) are "independent" unless the text says one supersedes the other.
- If a note says it was superseded by some OTHER note, not the one in this pair, answer "independent" for this pair.
- The newer note must be the one doing the replacing. Use dates, version numbers and wording to decide which is newer.

For each pair also give:
- "newer": "A", "B" or "unclear".
- "explicit": true only if the text says in so many words that one of these two notes replaces, supersedes or makes obsolete the other one (by title, reference or unmistakable description), not merely that something changed.
- "confidence": "high", "medium" or "low".
- "evidence": a short verbatim quote (under 25 words) for "replaces" or "amends".
"###;
pub(super) const SCHEMA_C: &str = r###"{"type":"object","properties":{"pairs":{"type":"array","items":{"type":"object","properties":{"pair":{"type":"integer"},"verdict":{"type":"string","enum":["replaces","amends","independent"]},"newer":{"type":"string","enum":["A","B","unclear"]},"evidence":{"type":["string","null"]},"explicit":{"type":"boolean"},"confidence":{"type":"string","enum":["high","medium","low"]}},"required":["pair","verdict","newer"]}}},"required":["pairs"]}"###;
