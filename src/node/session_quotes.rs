//! Quote attribution recovered from fully admitted saved user steps.
//!
//! The owner can compose this text too. Recognizing Desktop's frame never
//! authenticates the quoted speaker; links record owner-claimed attribution.
//! Parse complete logical user messages, not individual 64 KiB split parts.

use std::collections::BTreeMap;

use super::session_writer::RemoteStep;

const MAX_LOGICAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUOTES: usize = 8;
const PREFACE: &str =
    "Native Desktop added this envelope. The app named above composed everything inside it.\n";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuoteLink {
    /// Part containing the opening quote tag (even when the tag spans parts).
    pub source_id: String,
    pub target_id: String,
    /// Ordinal of every quoted block, including blocks without source ids.
    pub index: usize,
}
impl QuoteLink {
    pub fn key(&self) -> String {
        format!("nss3:link:{}:{}", self.source_id, self.index)
    }
}

fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

/// Only the emitted double-quoted attribute grammar, with unique keys.
fn attributes(mut text: &str) -> Option<BTreeMap<&str, &str>> {
    let mut out = BTreeMap::new();
    while !text.is_empty() {
        text = text.strip_prefix(' ')?;
        let (name, rest) = text.split_once("=\"")?;
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_lowercase() || c == b'_') {
            return None;
        }
        let end = rest.find('"')?;
        let value = &rest[..end];
        if value.contains(['<', '>', '\n', '\r']) || out.insert(name, value).is_some() {
            return None;
        }
        text = &rest[end + 1..];
    }
    Some(out)
}

fn envelope(text: &str) -> Option<Vec<(usize, usize, String)>> {
    let full_len = text.len();
    let text = text.strip_prefix("[User] ")?;
    let rest = text.strip_prefix("<native-app-message-")?;
    let nonce = rest.get(..32)?;
    if !nonce
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let header_end = rest.find(">\n")?;
    let header = attributes(rest.get(32..header_end)?)?;
    if header.len() != 8
        || !uuid(header.get("id")?)
        || header.get("on_behalf_of") != Some(&"the signed-in Native user")
        || !matches!(
            header.get("trigger"),
            Some(&"click" | &"confirmed-launch" | &"remembered-launch")
        )
        || ["app", "package", "version", "adoption"]
            .iter()
            .any(|key| header.get(key).is_none_or(|v| v.is_empty()))
        || chrono::DateTime::parse_from_rfc3339(header.get("sent")?).is_err()
    {
        return None;
    }
    let content = rest.get(header_end + 2..)?;
    let content = content.strip_prefix(PREFACE)?;
    let close = format!("\n</native-app-message-{nonce}>");
    let end = content.find(&close)?;
    let mut cursor = &content[..end];
    let open = format!("\n<quoted-{nonce}");
    let close_quote = format!("</quoted-{nonce}>");
    let mut output = Vec::new();
    let mut index = 0;
    while let Some(start) = cursor.find(&open) {
        if index == MAX_QUOTES {
            return None;
        }
        let quoted = &cursor[start + open.len()..];
        let header_end = quoted.find('>')?;
        let fields = attributes(&quoted[..header_end])?;
        if !(fields.len() == 1 || fields.len() == 2)
            || fields.keys().any(|key| !matches!(*key, "from" | "source"))
            || !fields.get("from")?.ends_with(" (app-labelled)")
        {
            return None;
        }
        let body = &quoted[header_end + 1..];
        let body_end = body.find(&close_quote)?;
        if body[..body_end].trim().is_empty() {
            return None;
        }
        if let Some(source) = fields.get("source") {
            if !uuid(source) {
                return None;
            }
            // Include the curated prefix removed above when mapping to parts.
            let offset = full_len - content.len() + end - cursor.len() + start + 1;
            output.push((index, offset, (*source).to_owned()));
        }
        cursor = &body[body_end + close_quote.len()..];
        index += 1;
    }
    Some(output)
}

fn split_label(body: &str) -> Option<(&str, usize, usize)> {
    let (content, label) = body.rsplit_once(" …(")?;
    let (part, total) = label.strip_suffix(')')?.split_once('/')?;
    let part: usize = part.parse().ok()?;
    let total: usize = total.parse().ok()?;
    (total > 1 && part > 0 && part <= total && label == format!("{part}/{total})"))
        .then_some((content, part, total))
}

/// Caller must first admit the entire chain, including create history.
/// Incomplete, mismatched or marker-interrupted split messages yield no links.
/// All parts must already exist remotely; nothing references unconfirmed text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuoteBatch {
    pub through_pos: u64,
    pub through_cid: String,
    pub links: Vec<QuoteLink>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingQuotes {
    pub batch: QuoteBatch,
    pub next: usize,
    pub mark_unverified: bool,
}

pub(super) fn plan(steps: &[RemoteStep]) -> Vec<QuoteLink> {
    batches(steps)
        .into_iter()
        .flat_map(|batch| batch.links)
        .collect()
}

pub(super) fn batches(steps: &[RemoteStep]) -> Vec<QuoteBatch> {
    let mut batches = Vec::new();
    let mut at = 0;
    while at < steps.len() {
        let first = &steps[at];
        let skip = |step: &RemoteStep| QuoteBatch {
            through_pos: step.pos,
            through_cid: step.cid.clone(),
            links: Vec::new(),
        };
        if first.step_kind != "user" || first.part_index != 0 {
            batches.push(skip(first));
            at += 1;
            continue;
        }
        let (body, total) = match split_label(&first.body) {
            Some((body, 1, total)) => (body, total),
            Some(_) => {
                batches.push(skip(first));
                at += 1;
                continue;
            }
            None => (first.body.as_str(), 1),
        };
        if total > MAX_LOGICAL_BYTES / 1024 {
            batches.push(skip(first));
            at += 1;
            continue;
        }
        let mut logical = body.to_owned();
        let mut spans = vec![(logical.len(), first.record_id.as_str())];
        let mut valid = true;
        for part in 1..total.min(steps.len() - at) {
            let step = &steps[at + part];
            let Some((body, number, count)) = split_label(&step.body) else {
                valid = false;
                break;
            };
            if step.step_kind != "user"
                || step.part_index as usize != part
                || step.pos != first.pos + part as u64
                || number != part + 1
                || count != total
                || logical.len() + body.len() > MAX_LOGICAL_BYTES
            {
                valid = false;
                break;
            }
            logical.push_str(body);
            spans.push((logical.len(), step.record_id.as_str()));
        }
        if !valid {
            batches.push(skip(first));
            at += 1;
            continue;
        }
        // The committed prefix ends inside this message. Preserve its start
        // for the next pass; do not advance a scan cursor past missing parts.
        if total > steps.len() - at {
            break;
        }
        let mut batch = skip(&steps[at + total - 1]);
        if logical.len() <= MAX_LOGICAL_BYTES {
            if let Some(found) = envelope(&logical) {
                for (index, offset, target_id) in found {
                    if let Some((_, source_id)) = spans.iter().find(|(end, _)| offset < *end) {
                        batch.links.push(QuoteLink {
                            source_id: (*source_id).to_owned(),
                            target_id,
                            index,
                        });
                    }
                }
            }
        }
        batches.push(batch);
        at += total;
    }
    batches
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIXTURE: &str =
        include_str!("../../tests/fixtures/saved-session-quotes/desktop-envelope.txt");
    const TARGET: &str = "123e4567-e89b-12d3-a456-426614174000";
    fn step(body: &str, part: u32, pos: u64) -> RemoteStep {
        RemoteStep {
            record_id: format!("step-{pos}"),
            owner_id: "owner".into(),
            home_id: "folder".into(),
            pos,
            body: body.into(),
            cid: String::new(),
            parent_cid: String::new(),
            fp: String::new(),
            step_kind: "user".into(),
            part_index: part,
            base_len: None,
            branch_no: None,
        }
    }
    fn body() -> String {
        format!("[User] {FIXTURE}")
    }
    #[test]
    fn actual_desktop_frame_preserves_ordinals_including_unlinked_quotes() {
        let links = plan(&[step(&body(), 0, 1)]);
        assert_eq!(links.len(), 2);
        assert_eq!(
            links[0],
            QuoteLink {
                source_id: "step-1".into(),
                target_id: TARGET.into(),
                index: 1
            }
        );
        assert_eq!(links[0].key(), "nss3:link:step-1:1");
        assert_eq!(links[1].index, 2);
    }
    #[test]
    fn every_utf8_split_reassembles_before_parsing_and_maps_opening_tag() {
        let body = body().replace("A paragraph.", "Καλημέρα 👋");
        let first_tag = body
            .find("<quoted-00112233445566778899aabbccddeeff from=\"A")
            .unwrap();
        for cut in 1..body.len() {
            if !body.is_char_boundary(cut) {
                continue;
            }
            let parts = [
                step(&format!("{} …(1/2)", &body[..cut]), 0, 1),
                step(&format!("{} …(2/2)", &body[cut..]), 1, 2),
            ];
            let links = plan(&parts);
            assert_eq!(links.len(), 2, "cut {cut}");
            assert_eq!(links[0].target_id, TARGET);
            assert_eq!(links[0].index, 1);
            assert_eq!(
                links[0].source_id,
                if first_tag < cut { "step-1" } else { "step-2" },
                "cut {cut}"
            );
        }
    }
    #[test]
    fn incomplete_or_interrupted_split_never_links_partial_user_text() {
        let body = body();
        let cut = body.len() / 2;
        let first = step(&format!("{} …(1/2)", &body[..cut]), 0, 1);
        assert!(plan(std::slice::from_ref(&first)).is_empty());
        let mut second = step(&format!("{} …(2/2)", &body[cut..]), 1, 2);
        second.pos = 3;
        assert!(plan(&[first.clone(), second.clone()]).is_empty());
        second.pos = 2;
        second.step_kind = "rewound".into();
        assert!(plan(&[first, second]).is_empty());
    }
    #[test]
    fn nonce_source_and_app_label_must_match_the_emitted_grammar() {
        for changed in [
            body().replace("source=\"123e", "source=\"123E"),
            body().replace(" (app-labelled)", ""),
            body().replace(
                "<quoted-00112233445566778899aabbccddeeff",
                "<quoted-11112233445566778899aabbccddeeff",
            ),
            body().replace(" on_behalf_of=", " arbitrary="),
        ] {
            assert!(plan(&[step(&changed, 0, 1)]).is_empty());
        }
        let mut agent = step(&body(), 0, 1);
        agent.step_kind = "agent".into();
        assert!(plan(&[agent]).is_empty());
    }
    #[test]
    fn adjacent_user_frames_get_their_own_keys_and_indices() {
        let links = plan(&[step(&body(), 0, 1), step(&body(), 0, 2)]);
        assert_eq!(links.len(), 4);
        assert_eq!(links[0].index, links[2].index);
        assert_ne!(links[0].key(), links[2].key());
        assert!(plan(&[step(&format!("[User] ordinary source=\"{TARGET}\""), 0, 1)]).is_empty());
    }
}
