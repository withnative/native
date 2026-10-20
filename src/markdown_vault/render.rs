use super::*;
use crate::{Error, Result};
use unicode_normalization::UnicodeNormalization;

// JSON string/scalar syntax is a YAML subset. Quote every key and value so
// authored punctuation, newlines and YAML-looking titles stay data.
fn yaml(value: &impl Serialize) -> String {
    serde_json::to_string(value).expect("serializable projection value")
}

fn filename_ref(id: &str) -> String {
    short(id)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn name(title: &str, reference: &str) -> String {
    let reference = filename_ref(reference);
    let normalized: String = title
        .nfc()
        .map(|c| {
            if c.is_control() || "/\\:*?\"<>|[]#^".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let normalized = normalized.replace("%%", "__");
    let safe = normalized
        .trim_start_matches('.')
        .trim_end_matches(['.', ' ']);
    let safe = if safe.is_empty() { "Untitled" } else { safe };
    // Leave space for the longest mapped extension and a collision suffix.
    let suffix = format!("… ({reference})");
    if safe.chars().count() <= 150 && safe.len() <= 250 {
        return safe.to_owned();
    }
    let mut end = 0;
    for (i, c) in safe.char_indices().take(150) {
        if i + c.len_utf8() + suffix.len() > 250 {
            break;
        }
        end = i + c.len_utf8();
    }
    let mut prefix = &safe[..end];
    if let Some((i, _)) = prefix.char_indices().rev().find(|(_, c)| c.is_whitespace()) {
        if i > 0 {
            prefix = &prefix[..i];
        }
    }
    format!("{}{suffix}", prefix.trim_end())
}

fn ancestor_depth(r: &SourceRecord, source: &SourceSnapshot) -> usize {
    let mut seen = BTreeSet::new();
    let mut home = r.home_id.as_deref();
    while let Some(id) = home {
        if !seen.insert(id) {
            break;
        }
        home = source.records.get(id).and_then(|r| r.home_id.as_deref());
    }
    seen.len()
}

fn fold(value: &str) -> String {
    unicase::UniCase::new(value.nfc().collect::<String>()).to_folded_case()
}

fn artifact_extension(r: &SourceRecord) -> Option<&'static str> {
    match r
        .facets
        .get("runtime")
        .or_else(|| r.facets.get("artifact_runtime"))
        .and_then(Value::as_str)
    {
        Some("native.html.v1") => Some("html"),
        Some("native.mdx.v2") => Some("mdx"),
        Some("native.board.v1") => Some("json"),
        _ => None,
    }
}
fn namespace(r: &SourceRecord, source: &SourceSnapshot) -> Option<String> {
    let mut home = r.home_id.clone();
    let mut seen = BTreeSet::new();
    while let Some(id) = home.as_deref() {
        if !seen.insert(id.to_owned()) {
            break;
        }
        match source.records.get(id) {
            Some(parent) if !parent.included() => home = parent.home_id.clone(),
            _ => break,
        }
    }
    if home.is_none() && r.id != "native:root" {
        Some("native:root".into())
    } else {
        home
    }
}
fn emitted(r: &SourceRecord, stem: &str) -> Vec<String> {
    let mut keys = vec![format!("title:{}", fold(stem))];
    if r.folder() {
        keys.push(format!("entry:{}", fold(stem)));
    } else {
        keys.push(format!("entry:{}.md", fold(stem)));
        if let Some(ext) = artifact_extension(r) {
            keys.push(format!("entry:{}.{ext}", fold(stem)));
        }
    }
    keys
}
fn allocate(
    snapshot: &SourceSnapshot,
    previous: &BTreeMap<String, Allocation>,
) -> BTreeMap<String, Allocation> {
    type Slots = BTreeMap<Option<String>, BTreeMap<String, String>>;
    let mut slots = Slots::new();
    let mut allocated = BTreeMap::new();
    let mut rows: Vec<_> = snapshot
        .records
        .values()
        .filter(|r| r.included() && !r.comment() && r.record_type != "Message")
        .collect();
    rows.sort_by_key(|r| {
        (
            ancestor_depth(r, snapshot),
            r.metadata
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or(""),
            r.id.as_str(),
        )
    });
    // Keep occupied names stable when a later sibling appears. Parent-note
    // reservations below supersede a child's old slot after a parent rename.
    for r in &rows {
        if let Some(old) = previous
            .get(&r.id)
            .filter(|a| a.title == r.title() && a.home == r.home_id)
        {
            for key in emitted(r, &old.stem) {
                slots
                    .entry(namespace(r, snapshot))
                    .or_default()
                    .entry(key)
                    .or_insert_with(|| r.id.clone());
            }
        }
    }
    let mut preferred = BTreeMap::new();
    for r in &rows {
        if let Some(old) = previous
            .get(&r.id)
            .filter(|a| a.title == r.title() && a.home == r.home_id)
        {
            preferred.insert(r.id.clone(), old.stem.clone());
            continue;
        }
        let siblings = slots.entry(namespace(r, snapshot)).or_default();
        let base = name(&r.title(), short(&r.id));
        let mut stem = base.clone();
        let mut counter = 0;
        while emitted(r, &stem)
            .iter()
            .any(|key| siblings.contains_key(key))
        {
            counter += 1;
            let suffix = if counter == 1 {
                format!(" ({})", filename_ref(&r.id))
            } else {
                format!(" ({}-{counter})", filename_ref(&r.id))
            };
            let mut end = base.len().min(250usize.saturating_sub(suffix.len()));
            while !base.is_char_boundary(end) {
                end -= 1;
            }
            stem = format!("{}{suffix}", &base[..end]);
        }
        for key in emitted(r, &stem) {
            siblings.insert(key, r.id.clone());
        }
        preferred.insert(r.id.clone(), stem);
    }
    for folder_pass in [true, false] {
        for r in rows.iter().filter(|r| r.folder() == folder_pass) {
            let siblings = slots.entry(namespace(r, snapshot)).or_default();
            siblings.retain(|_, owner| owner != &r.id);
            let base = name(&r.title(), short(&r.id));
            let mut stem = preferred[&r.id].clone();
            let mut counter = 0u64;
            while emitted(r, &stem)
                .iter()
                .any(|key| siblings.contains_key(key))
            {
                counter += 1;
                let suffix = if counter == 1 {
                    format!(" ({})", filename_ref(&r.id))
                } else {
                    format!(" ({}-{counter})", filename_ref(&r.id))
                };
                let mut end = base.len().min(250usize.saturating_sub(suffix.len()));
                while !base.is_char_boundary(end) {
                    end -= 1;
                }
                stem = format!("{}{suffix}", &base[..end]);
            }
            for key in emitted(r, &stem) {
                siblings.insert(key, r.id.clone());
            }
            if r.folder() {
                let children = slots.entry(Some(r.id.clone())).or_default();
                children.insert(format!("title:{}", fold(&stem)), r.id.clone());
                children.insert(format!("entry:{}.md", fold(&stem)), r.id.clone());
            }
            allocated.insert(
                r.id.clone(),
                Allocation {
                    title: r.title(),
                    home: r.home_id.clone(),
                    stem,
                },
            );
        }
    }
    allocated
}

fn folder_path(
    id: &str,
    source: &SourceSnapshot,
    names: &BTreeMap<String, Allocation>,
    visiting: &mut BTreeSet<String>,
) -> Result<String> {
    if !visiting.insert(id.to_owned()) {
        return Err(Error::engine("vault containment cycle"));
    }
    let record = source
        .records
        .get(id)
        .ok_or_else(|| Error::engine("vault home unavailable"))?;
    if !record.included() {
        let result = folder_path(
            record.home_id.as_deref().unwrap_or("native:root"),
            source,
            names,
            visiting,
        );
        visiting.remove(id);
        return result;
    }
    if !record.folder() {
        return Err(Error::engine("vault home is not a folder"));
    }
    let own = &names[id].stem;
    let result = match record.home_id.as_deref() {
        Some(parent) => format!("{}/{}", folder_path(parent, source, names, visiting)?, own),
        None if id != "native:root" => format!(
            "{}/{}",
            folder_path("native:root", source, names, visiting)?,
            own
        ),
        None => own.clone(),
    };
    visiting.remove(id);
    Ok(result)
}

fn dependencies(id: &str, source: &SourceSnapshot, deps: &mut BTreeSet<String>) {
    let mut current = Some(id);
    while let Some(id) = current {
        if !deps.insert(id.to_owned()) {
            break;
        }
        current = source.records.get(id).and_then(|r| r.home_id.as_deref());
    }
}

fn wiki(path: &str, title: &str) -> String {
    format!(
        "[[{}|{}]]",
        path.strip_suffix(".md").unwrap_or(path),
        title
            .replace(['|', '[', ']', '\n', '\r'], " ")
            .replace("%%", " ")
    )
}

pub(super) fn render(
    source: &SourceSnapshot,
    previous: &BTreeMap<String, Allocation>,
) -> Result<Rendered> {
    let names = allocate(source, previous);
    let root = source
        .records
        .get("native:root")
        .filter(|r| r.included() && r.folder())
        .ok_or_else(|| Error::engine("vault workspace root is not visible"))?;
    let root_path = folder_path(&root.id, source, &names, &mut BTreeSet::new())?;
    let mut paths = BTreeMap::new();
    let mut used_paths = BTreeSet::new();
    for r in source
        .records
        .values()
        .filter(|r| r.included() && !r.comment() && r.record_type != "Message")
    {
        let path = if r.folder() {
            let dir = folder_path(&r.id, source, &names, &mut BTreeSet::new())?;
            // Empty folder notes are excluded, but folders remain linkable.
            if r.body.as_deref().unwrap_or("").is_empty() {
                continue;
            }
            format!("{dir}/{}.md", names[&r.id].stem)
        } else {
            let dir = match r.home_id.as_deref() {
                Some(home) => folder_path(home, source, &names, &mut BTreeSet::new())?,
                None => root_path.clone(),
            };
            format!("{dir}/{}.md", names[&r.id].stem)
        };
        if !used_paths.insert(fold(&path)) {
            return Err(Error::engine("vault folder-note path collision"));
        }
        paths.insert(r.id.clone(), path);
    }
    let message_plan = message_groups(source, &mut used_paths);
    let mut link_paths = paths.clone();
    for group in &message_plan {
        for message in &group.messages {
            link_paths.insert(message.id.clone(), group.path.clone());
        }
    }
    // Inline comments resolve to their containing note/aggregate, not a fake
    // standalone file. Every traversal uses already authorized edges.
    for comment in source
        .records
        .values()
        .filter(|r| r.included() && r.comment())
    {
        let mut current = comment.id.as_str();
        let mut seen = BTreeSet::new();
        while seen.insert(current) {
            let targets: Vec<_> = source
                .links
                .iter()
                .filter(|l| l.source_id == current && l.relationship == "part_of")
                .collect();
            if targets.len() != 1 {
                break;
            }
            current = &targets[0].target_id;
            if let Some(path) = link_paths.get(current).cloned() {
                link_paths.insert(comment.id.clone(), path);
                break;
            }
        }
    }
    let mut directories = BTreeMap::new();
    for r in source
        .records
        .values()
        .filter(|r| r.included() && r.folder())
    {
        let path = folder_path(&r.id, source, &names, &mut BTreeSet::new())?;
        let mut deps = BTreeSet::new();
        dependencies(&r.id, source, &mut deps);
        directories.insert(path, deps);
    }
    let mut files = BTreeMap::new();
    for r in source
        .records
        .values()
        .filter(|r| paths.contains_key(&r.id))
    {
        let mut deps = BTreeSet::new();
        dependencies(&r.id, source, &mut deps);
        let mut meta = r.metadata.clone();
        for (key, value) in [
            ("id", r.id.clone()),
            ("ref", short(&r.id).into()),
            ("url", format!("https://n8v.to/{}", short(&r.id))),
            ("type", r.record_type.clone()),
            ("name", r.title()),
        ] {
            meta.insert(key.into(), Value::String(value));
        }
        if let Some(kind) = &r.kind {
            meta.insert("kind".into(), Value::String(kind.clone()));
        }
        for (key, value) in &r.facets {
            meta.insert(
                format!("facet.{key}"),
                match value {
                    Value::Array(_) | Value::Object(_) => Value::String(yaml(value)),
                    _ => value.clone(),
                },
            );
        }
        meta.insert(
            "native_projection_origin".into(),
            Value::String(source.origin.clone()),
        );
        meta.insert(
            "native_projection_renderer".into(),
            Value::String(VERSION.into()),
        );
        for key in ["owner", "author"] {
            if let Some(id) = r.metadata.get(key).and_then(Value::as_str) {
                deps.insert(id.into());
            }
        }
        let mut relation_values: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut links = String::new();
        for link in source.links.iter().filter(|l| l.source_id == r.id) {
            let Some(target) = source.records.get(&link.target_id) else {
                continue;
            };
            dependencies(&target.id, source, &mut deps);
            let value = if let Some(path) = link_paths.get(&target.id) {
                wiki(path, &target.title())
            } else {
                format!(
                    "{} ({}; https://n8v.to/{})",
                    target.title(),
                    if target.archived {
                        "archived"
                    } else if target.record_type == "Configuration" {
                        "configuration"
                    } else {
                        "no standalone note"
                    },
                    short(&target.id)
                )
            };
            relation_values
                .entry(link.relationship.clone())
                .or_default()
                .push(value.clone());
            links.push_str(&format!(
                "- {}: {}{}\n",
                link.relationship,
                value,
                link.note
                    .as_ref()
                    .map(|s| format!(" — {s}"))
                    .unwrap_or_default()
            ));
        }
        // Keep reserved keys intact even if a custom relationship has that name.
        for (mut key, value) in relation_values {
            while meta.contains_key(&key) {
                key = format!("relationship:{key}");
            }
            meta.insert(key, serde_json::to_value(value)?);
        }
        let mut text = String::from("---\n");
        for (key, value) in meta {
            text.push_str(&format!("{}: {}\n", yaml(&key), yaml(&value)));
        }
        text.push_str("---\n\n");
        let ext = artifact_extension(r);
        let path = &paths[&r.id];
        if let Some(ext) = ext {
            let artifact = format!(
                "{}.{ext}",
                path.strip_suffix(".md").expect("generated Markdown suffix")
            );
            text.push_str(&format!(
                "[Open artifact](<{}>)\n",
                artifact.rsplit('/').next().unwrap()
            ));
            files.insert(
                artifact,
                Output {
                    bytes: r.body.clone().unwrap_or_default().into_bytes(),
                    contributors: deps.clone(),
                },
            );
        } else {
            text.push_str(r.body.as_deref().unwrap_or(""));
        }
        text.push_str("\n\n<!-- native:generated links -->\n## Links\n");
        text.push_str(&links);
        let mut comments = String::new();
        append_comments(
            &r.id,
            source,
            0,
            &mut BTreeSet::new(),
            &mut deps,
            &mut comments,
        )?;
        if !comments.is_empty() {
            text.push_str("\n<!-- native:generated comments -->\n## Comments\n");
            text.push_str(&comments);
        }
        files.insert(
            path.clone(),
            Output {
                bytes: text.into_bytes(),
                contributors: deps,
            },
        );
    }
    for group in message_plan {
        let mut deps = BTreeSet::new();
        let mut body = format!("# {}\n", group.title);
        let mut properties: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let ids: Vec<_> = group.messages.iter().map(|r| r.id.as_str()).collect();
        for r in &group.messages {
            dependencies(&r.id, source, &mut deps);
            let author = r
                .metadata
                .get("author")
                .and_then(Value::as_str)
                .and_then(|id| source.records.get(id));
            if let Some(author) = author {
                deps.insert(author.id.clone());
            }
            body.push_str(&format!(
                "\n## {} — {}\n\nAuthor: {}\nNative: https://n8v.to/{}\n\n{}\n",
                r.metadata
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or("undated"),
                short(&r.id),
                author
                    .map(SourceRecord::title)
                    .unwrap_or_else(|| "Unknown author".into()),
                short(&r.id),
                r.body.as_deref().unwrap_or("")
            ));
            body.push_str("\n<!-- native:generated links -->\n### Links\n");
            for link in source.links.iter().filter(|l| l.source_id == r.id) {
                if let Some(target) = source.records.get(&link.target_id) {
                    dependencies(&target.id, source, &mut deps);
                    let value = link_paths
                        .get(&target.id)
                        .map(|p| wiki(p, &target.title()))
                        .unwrap_or_else(|| {
                            format!(
                                "{} ({}; https://n8v.to/{})",
                                target.title(),
                                if target.archived {
                                    "archived"
                                } else if target.record_type == "Configuration" {
                                    "configuration"
                                } else {
                                    "no standalone note"
                                },
                                short(&target.id)
                            )
                        });
                    properties
                        .entry(link.relationship.clone())
                        .or_default()
                        .push(value.clone());
                    body.push_str(&format!(
                        "- {}: {}{}\n",
                        link.relationship,
                        value,
                        link.note
                            .as_ref()
                            .map(|n| format!(" — {n}"))
                            .unwrap_or_default()
                    ));
                }
            }
            let mut comments = String::new();
            append_comments(
                &r.id,
                source,
                0,
                &mut BTreeSet::new(),
                &mut deps,
                &mut comments,
            )?;
            if !comments.is_empty() {
                body.push_str("\n<!-- native:generated comments -->\n### Comments\n");
                body.push_str(&comments);
            }
        }
        let mut text = format!("---\nname: {}\nsources: {}\nnative_projection_origin: {}\nnative_projection_renderer: {}\n",yaml(&group.title),yaml(&ids),yaml(&source.origin),yaml(&VERSION));
        let mut property_names: BTreeSet<String> = [
            "name",
            "sources",
            "native_projection_origin",
            "native_projection_renderer",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for (mut key, values) in properties {
            while !property_names.insert(key.clone()) {
                key = format!("relationship:{key}");
            }
            text.push_str(&format!("{}: {}\n", yaml(&key), yaml(&values)));
        }
        text.push_str("---\n\n");
        text.push_str(&body);
        files.insert(
            group.path,
            Output {
                bytes: text.into_bytes(),
                contributors: deps,
            },
        );
    }
    files.insert("README.md".into(), Output {bytes:format!("# Native Markdown vault\n\nRead-only generated view. Hosted Native is canonical. Local edits are conflicts; access revocation removes generated content even if edited. See .native/STATUS.md. Renderer: {VERSION}. The node publishes this vault by default next to its local copy; to turn it off set \"markdown_folder\": false in node.json.\n").into_bytes(),contributors:BTreeSet::new()});
    Ok(Rendered {
        files,
        allocations: names,
        directories,
    })
}

fn append_comments(
    target: &str,
    source: &SourceSnapshot,
    depth: usize,
    visited: &mut BTreeSet<String>,
    deps: &mut BTreeSet<String>,
    out: &mut String,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::engine("vault comment nesting exceeds 64 levels"));
    }
    let mut comments: Vec<_> = source
        .links
        .iter()
        .filter(|l| l.target_id == target && l.relationship == "part_of")
        .filter_map(|l| source.records.get(&l.source_id))
        .filter(|r| r.included() && r.comment())
        .collect();
    comments.sort_by_key(|r| {
        (
            r.metadata
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or(""),
            r.id.as_str(),
        )
    });
    for r in comments {
        if !visited.insert(r.id.clone()) {
            continue;
        }
        dependencies(&r.id, source, deps);
        let owner = r
            .metadata
            .get("author")
            .and_then(Value::as_str)
            .and_then(|id| source.records.get(id));
        if let Some(owner) = owner {
            deps.insert(owner.id.clone());
        }
        let indent = "  ".repeat(depth);
        out.push_str(&format!(
            "\n{indent}- {} — {}\n",
            owner
                .map(SourceRecord::title)
                .unwrap_or_else(|| "Unknown author".into()),
            r.metadata
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or("undated")
        ));
        for anchor in &r.anchors {
            let mut quotes = Vec::new();
            anchor_quotes(anchor, &mut quotes);
            for quote in quotes {
                for line in quote.lines() {
                    out.push_str(&format!("{indent}  > {line}\n"));
                }
            }
        }
        for line in r.body.as_deref().unwrap_or("").lines() {
            out.push_str(&format!("{indent}  {line}\n"));
        }
        append_comments(&r.id, source, depth + 1, visited, deps, out)?;
    }
    Ok(())
}

fn anchor_quotes<'a>(value: &'a Value, quotes: &mut Vec<&'a str>) {
    match value {
        Value::Array(items) => {
            for item in items {
                anchor_quotes(item, quotes);
            }
        }
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("text_quote" | "TextQuoteSelector")
            ) {
                if let Some(exact) = object.get("exact").and_then(Value::as_str) {
                    quotes.push(exact);
                }
            } else {
                for item in object.values() {
                    anchor_quotes(item, quotes);
                }
            }
        }
        _ => {}
    }
}

struct MessageGroup<'a> {
    path: String,
    title: String,
    messages: Vec<&'a SourceRecord>,
}
fn message_groups<'a>(
    source: &'a SourceSnapshot,
    used_paths: &mut BTreeSet<String>,
) -> Vec<MessageGroup<'a>> {
    let mut planned = Vec::new();
    let mut groups: BTreeMap<String, Vec<&SourceRecord>> = BTreeMap::new();
    for r in source
        .records
        .values()
        .filter(|r| r.included() && r.record_type == "Message")
    {
        groups
            .entry(r.home_id.clone().unwrap_or_else(|| "native:root".into()))
            .or_default()
            .push(r);
    }
    let mut group_names = BTreeSet::new();
    for (home, mut messages) in groups {
        messages.sort_by_key(|r| {
            (
                r.metadata
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                r.id.as_str(),
            )
        });
        let title = source
            .records
            .get(&home)
            .map(SourceRecord::title)
            .unwrap_or_else(|| "Messages".into());
        let mut stem = name(&title, short(&home));
        let base: String = stem.chars().take(110).collect();
        let mut counter = 0;
        while !group_names.insert(fold(&stem)) {
            counter += 1;
            stem = format!("{base} ({}-{counter})", filename_ref(&home));
        }
        let large = messages
            .iter()
            .map(|r| r.body.as_ref().map_or(0, String::len))
            .sum::<usize>()
            > 1024 * 1024;
        let mut months: BTreeMap<String, Vec<&SourceRecord>> = BTreeMap::new();
        for r in messages {
            let month = if large {
                r.metadata
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or("undated")
                    .chars()
                    .take(7)
                    .collect()
            } else {
                String::new()
            };
            months.entry(month).or_default().push(r);
        }
        for (month, messages) in months {
            let suffix = if month.is_empty() {
                String::new()
            } else {
                format!(" {month}")
            };
            let base = name(&format!("{stem}{suffix}"), &filename_ref(&home));
            let mut path = format!("Messages/{base}.md");
            let mut collision = 0;
            while !used_paths.insert(fold(&path)) {
                collision += 1;
                let mut prefix = base.clone();
                while prefix.len() > 220 {
                    prefix.pop();
                }
                path = format!("Messages/{prefix} ({}-{collision}).md", filename_ref(&home));
            }
            planned.push(MessageGroup {
                path,
                title: title.clone(),
                messages,
            });
        }
    }
    planned
}
