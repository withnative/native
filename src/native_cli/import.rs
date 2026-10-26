//! Mechanical Markdown import. Planning is read-only; mutations use MCP tools.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::sync::LazyLock;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, Row, SqlitePool};

use super::enrichment::{Candidate, ImportPlan};
const IMPORT_LINK_NOTE: &str = "native.import:resolved-markdown-link:v1";
use crate::mcp::{register_builtin_tools, register_surface_tools, Caller, ToolRegistry};
use crate::{Error, Result};

pub fn usage() -> String {
    format!("usage: native import [--db <path>] [--dry-run] [--json] [--enrichment <file>] <dir>...\n\nImport Markdown notes and folders into a local Native database.\nDefault database: {}\nRe-runs update source bindings; missing files are reported, never deleted.\n--enrichment applies content-matched types and links from a file-first sidecar.\n--dry-run plans changes without writing. --json prints one JSON report.\n", super::default_local_db_path().display())
}

pub fn run_cli(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let mut options = Options {
        db: super::default_local_db_path(),
        dry_run: false,
        dirs: Vec::new(),
    };
    let mut json_output = false;
    let mut enrichment_path: Option<PathBuf> = None;
    let mut args = args.iter();
    let mut positional = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--" if !positional => positional = true,
            "--db" if !positional => match args.next() {
                Some(path) => options.db = path.into(),
                None => {
                    eprintln!("native import: --db needs a path");
                    return ExitCode::from(2);
                }
            },
            "--enrichment" if !positional => match args.next() {
                Some(path) => enrichment_path = Some(path.into()),
                None => {
                    eprintln!("native import: --enrichment needs a path");
                    return ExitCode::from(2);
                }
            },
            "--dry-run" if !positional => options.dry_run = true,
            "--json" if !positional => json_output = true,
            flag if !positional && flag.starts_with('-') => {
                eprintln!("native import: unknown option {flag}");
                return ExitCode::from(2);
            }
            _ => options.dirs.push(arg.into()),
        }
    }
    if options.dirs.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    let result = tokio::runtime::Runtime::new()
        .map_err(Error::from)
        .and_then(|runtime| runtime.block_on(import_inner(&options, enrichment_path.as_deref())));
    match result {
        Ok(report) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string(&report).expect("serializable report")
                );
            } else {
                print!("{}", report.human());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("native import: {error}");
            ExitCode::from(1)
        }
    }
}

pub struct Options {
    pub db: PathBuf,
    pub dry_run: bool,
    pub dirs: Vec<PathBuf>,
}

#[derive(Debug, Default, Serialize)]
pub struct Counts {
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
}
#[derive(Debug, Serialize)]
pub struct LinkIssue {
    pub source_root: String,
    pub source: String,
    pub target: String,
}
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub dry_run: bool,
    pub folders: Counts,
    pub notes: Counts,
    pub links: Counts,
    pub unresolved_links: Vec<LinkIssue>,
    pub ambiguous_links: Vec<LinkIssue>,
    pub skipped_files: BTreeMap<String, usize>,
    pub skipped_hidden_entries: usize,
    pub skipped_symlinks: usize,
    pub skipped_embeds: usize,
    pub unreadable_files: Vec<String>,
    pub not_faithfully_converted: Vec<String>,
    pub disappeared: Vec<String>,
    pub stale_enrichment: Vec<String>,
    pub enrichment_fallbacks: Vec<String>,
    pub supersession_candidates: Vec<Candidate>,
    pub removed_plain_links: usize,
}
impl Report {
    pub(super) fn human(&self) -> String {
        let counts = |c: &Counts| {
            format!(
                "{} created, {} updated, {} unchanged",
                c.created, c.updated, c.unchanged
            )
        };
        let mut out = format!("{}Folders: {}\nNotes: {}\nLinks: {}\nUnresolved links: {}; ambiguous links: {}\nSkipped files by extension: {:?}; hidden entries: {}; symlinks: {}\nNot faithfully converted: {}; disappeared: {}\n",
            if self.dry_run { "Dry run (planned changes)\n" } else { "" }, counts(&self.folders), counts(&self.notes), counts(&self.links), self.unresolved_links.len(), self.ambiguous_links.len(), self.skipped_files, self.skipped_hidden_entries, self.skipped_symlinks, self.not_faithfully_converted.len(), self.disappeared.len());
        out.push_str(&format!(
            "Skipped embeds: {}; unreadable files: {}\n",
            self.skipped_embeds,
            self.unreadable_files.len()
        ));
        out.push_str(&format!(
            "Removed importer relates_to links: {}\n",
            self.removed_plain_links
        ));
        let examples = self
            .unresolved_links
            .iter()
            .map(|issue| ("Unresolved", issue))
            .chain(
                self.ambiguous_links
                    .iter()
                    .map(|issue| ("Ambiguous", issue)),
            );
        for (label, issue) in examples.take(10) {
            out.push_str(&format!("{label}: {} -> {}\n", issue.source, issue.target));
        }
        let remaining =
            (self.unresolved_links.len() + self.ambiguous_links.len()).saturating_sub(10);
        if remaining > 0 {
            out.push_str(&format!("… and {remaining} more (use --json for all)\n"));
        }
        out.push_str(&format!(
            "Stale enrichment: {}; type fallbacks: {}\n",
            self.stale_enrichment.len(),
            self.enrichment_fallbacks.len()
        ));
        if !self.supersession_candidates.is_empty() {
            out.push_str(
                "Supersession candidates (top 15; not applied, confirm with native init):\n",
            );
            for candidate in &self.supersession_candidates {
                let pair = match (&candidate.newer, &candidate.older) {
                    (Some(newer), Some(older)) => format!("{newer} -> {older}"),
                    _ => format!(
                        "{} <> {} (direction unknown)",
                        candidate.pair[0], candidate.pair[1]
                    ),
                };
                out.push_str(&format!(
                    "  [{}] {pair}: {}\n",
                    candidate.score,
                    candidate.evidence.as_deref().unwrap_or("")
                ));
            }
        }
        out
    }
}

#[derive(Debug)]
pub(super) struct Entry {
    pub(super) root: String,
    pub(super) path: String,
    pub(super) parent: Option<String>,
    pub(super) folder: bool,
    pub(super) file: Option<String>,
    pub(super) name: String,
    pub(super) body: String,
    pub(super) facets: Map<String, Value>,
    pub(super) content_sha256: Option<String>,
    pub(super) source_text: Option<String>,
}
impl Entry {
    pub(super) fn key_for_enrichment(&self) -> (String, String) {
        self.key()
    }
    fn key(&self) -> (String, String) {
        (self.root.clone(), self.path.clone())
    }
    fn display(&self) -> String {
        format!("{}/{}", self.root, self.file.as_ref().unwrap_or(&self.path))
    }
}
fn text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::engine(format!("path is not UTF-8: {}", path.display())))
}
fn relative(path: &Path, root: &Path) -> Result<String> {
    text(
        path.strip_prefix(root)
            .map_err(|e| Error::engine(e.to_string()))?,
    )
}
fn modified(path: &Path) -> Result<String> {
    let time: DateTime<Utc> = std::fs::metadata(path)?.modified()?.into();
    Ok(time.to_rfc3339_opts(SecondsFormat::Nanos, true))
}
fn folder_path(path: &str) -> String {
    if path.is_empty() {
        ".".into()
    } else {
        format!("{path}/")
    }
}

fn scan(
    root: &Path,
    dir: &Path,
    parent: Option<String>,
    entries: &mut Vec<Entry>,
    report: &mut Report,
) -> Result<()> {
    let name = text(
        dir.file_name()
            .ok_or_else(|| Error::engine("source directory needs a name"))?
            .as_ref(),
    )?;
    let path = folder_path(&relative(dir, root)?);
    let mut children = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    let folder_note = dir.join(format!("{name}.md"));
    let mut has_note = children
        .iter()
        .any(|c| c.path() == folder_note && c.file_type().is_ok_and(|t| t.is_file()));
    let mut entry = Entry {
        content_sha256: None,
        source_text: None,
        root: text(root)?,
        path: path.clone(),
        parent,
        folder: true,
        file: None,
        name,
        body: String::new(),
        facets: Map::new(),
    };
    if has_note {
        has_note = load_note(&mut entry, &folder_note, root, report)?;
    }
    entry
        .facets
        .insert("source_root".into(), json!(text(root)?));
    entry.facets.insert("source_path".into(), json!(path));
    entry.facets.insert(
        "file_modified_at".into(),
        json!(modified(if has_note { &folder_note } else { dir })?),
    );
    entries.push(entry);
    for child in children {
        let child_path = child.path();
        let child_name = child.file_name();
        let Some(filename) = child_name.to_str() else {
            report
                .unreadable_files
                .push(child_path.to_string_lossy().into_owned());
            continue;
        };
        if filename.starts_with('.') {
            report.skipped_hidden_entries += 1;
            continue;
        }
        let kind = child.file_type()?;
        if kind.is_symlink() {
            report.skipped_symlinks += 1;
            continue;
        }
        if kind.is_dir() {
            scan(root, &child_path, Some(path.clone()), entries, report)?;
        } else if kind.is_file() {
            if child_path.extension().and_then(|s| s.to_str()) != Some("md") {
                let ext = child_path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("(none)");
                *report.skipped_files.entry(ext.to_owned()).or_default() += 1;
                continue;
            }
            if has_note && child_path == folder_note {
                continue;
            }
            let note_path = relative(&child_path, root)?;
            let mut note = Entry {
                content_sha256: None,
                source_text: None,
                root: text(root)?,
                path: note_path.clone(),
                parent: Some(path.clone()),
                folder: false,
                file: None,
                name: text(child_path.file_stem().expect("file stem").as_ref())?,
                body: String::new(),
                facets: Map::new(),
            };
            if !load_note(&mut note, &child_path, root, report)? {
                continue;
            }
            note.facets.insert("source_root".into(), json!(note.root));
            note.facets.insert("source_path".into(), json!(note_path));
            note.facets
                .insert("file_modified_at".into(), json!(modified(&child_path)?));
            entries.push(note);
        }
    }
    Ok(())
}
fn load_note(entry: &mut Entry, file: &Path, root: &Path, report: &mut Report) -> Result<bool> {
    let content = match std::fs::read_to_string(file) {
        Ok(content) => content,
        Err(_) => {
            report
                .unreadable_files
                .push(file.to_string_lossy().into_owned());
            return Ok(false);
        }
    };
    entry.source_text = Some(content.clone());
    entry.content_sha256 = Some(format!("{:x}", Sha256::digest(content.as_bytes())));
    let content = content.strip_prefix('\u{feff}').unwrap_or(&content);
    entry.file = Some(relative(file, root)?);
    match frontmatter(content) {
        Ok((facets, body)) => {
            if !entry.folder {
                if let Some(title) = facets
                    .get("fm.title")
                    .and_then(Value::as_str)
                    .filter(|title| !title.trim().is_empty())
                {
                    entry.name = title.into();
                }
            }
            entry.facets = facets;
            entry.body = body.into();
        }
        Err(()) => {
            entry.body = content.into();
            report.not_faithfully_converted.push(entry.display());
        }
    }
    if entry.folder {
        entry.facets.insert("source_file".into(), json!(entry.file));
    }
    Ok(true)
}

// Deliberately a strict YAML subset: unsupported syntax is preserved, never guessed.
fn scalar(value: &str) -> std::result::Result<String, ()> {
    let value = value.trim();
    if value.starts_with('"') {
        return serde_json::from_str::<String>(value).map_err(|_| ());
    }
    if value.starts_with('\'') {
        if value.len() >= 2 && value.ends_with('\'') {
            let inner = &value[1..value.len() - 1];
            if inner.replace("''", "").contains('\'') {
                return Err(());
            }
            return Ok(inner.replace("''", "'"));
        }
        return Err(());
    }
    if value.starts_with(['[', ']', '{', '}', '&', '*', '!', '|', '>'])
        || value.contains(": ")
        || value.contains(" #")
        || value.starts_with('#')
    {
        return Err(());
    }
    Ok(value.into())
}
fn inline_list(value: &str) -> std::result::Result<String, ()> {
    if !value.ends_with(']') {
        return Err(());
    }
    let inner = &value[1..value.len() - 1];
    if inner.trim().is_empty() {
        return Ok(String::new());
    }
    let mut items = Vec::new();
    let mut quote = None;
    let mut start = 0;
    let mut escaped = false;
    for (i, c) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && c == '\\' {
            escaped = true;
            continue;
        }
        if Some(c) == quote {
            quote = None;
        } else if quote.is_none() && inner[start..i].trim().is_empty() && (c == '\'' || c == '"') {
            quote = Some(c);
        } else if quote.is_none() && c == ',' {
            items.push(scalar(&inner[start..i])?);
            start = i + 1;
        }
    }
    if quote.is_some() {
        return Err(());
    }
    items.push(scalar(&inner[start..])?);
    Ok(items.join(", "))
}
fn frontmatter(content: &str) -> std::result::Result<(Map<String, Value>, &str), ()> {
    let mut lines = content.split_inclusive('\n');
    if lines.next().map(str::trim_end) != Some("---") {
        return Ok((Map::new(), content));
    }
    let mut offset = content.find('\n').map_or(content.len(), |i| i + 1);
    let mut fields = Map::new();
    let mut pending: Option<(String, Vec<String>)> = None;
    for line in lines {
        offset += line.len();
        let line = line.trim_end();
        if line == "---" {
            if let Some((key, items)) = pending.take() {
                fields.insert(key, json!(items.join(", ")));
            }
            return Ok((fields, &content[offset..]));
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(item) = line.trim_start().strip_prefix("- ") {
            let (_, items) = pending.as_mut().ok_or(())?;
            items.push(scalar(item)?);
            continue;
        }
        if let Some((key, items)) = pending.take() {
            fields.insert(key, json!(items.join(", ")));
        }
        if line.starts_with(char::is_whitespace) {
            return Err(());
        }
        let (key, value) = line.split_once(':').ok_or(())?;
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_alphanumeric() || "_- .".contains(c))
        {
            return Err(());
        }
        let key = format!("fm.{}", key.trim());
        if fields.contains_key(&key) {
            return Err(());
        }
        let value = value.trim();
        if value.is_empty() {
            pending = Some((key, Vec::new()));
        } else {
            fields.insert(
                key,
                json!(if value.starts_with('[') {
                    inline_list(value)?
                } else {
                    scalar(value)?
                }),
            );
        }
    }
    Err(())
}

#[derive(Debug)]
struct Existing {
    id: String,
    updated_at: String,
    name: String,
    body: String,
    facets: Map<String, Value>,
}
type Binding = (String, String);
async fn bindings(
    pool: &SqlitePool,
    roots: &BTreeSet<String>,
) -> Result<BTreeMap<Binding, Existing>> {
    let rows = sqlx::query("SELECT r.id,r.updated_at,r.name,r.body,s.value AS root,p.value AS path,f.key AS facet_key,f.value AS facet_value FROM records r JOIN facet_values s ON s.record_id=r.id AND s.key='source_root' JOIN facet_values p ON p.record_id=r.id AND p.key='source_path' JOIN facet_values f ON f.record_id=r.id WHERE r.deleted_at IS NULL ORDER BY r.id,f.key").fetch_all(pool).await?;
    let mut found: BTreeMap<Binding, Existing> = BTreeMap::new();
    for row in rows {
        let root: String = row.try_get("root")?;
        if !roots.contains(&root) {
            continue;
        }
        let path: String = row.try_get("path")?;
        let id: String = row.try_get("id")?;
        let key = (root, path);
        if let Some(old) = found.get(&key) {
            if old.id != id {
                return Err(Error::engine(
                    "duplicate source binding; resolve it before importing",
                ));
            }
        }
        let old = found.entry(key).or_insert(Existing {
            id,
            updated_at: row.try_get("updated_at")?,
            name: row.try_get("name")?,
            body: row
                .try_get::<Option<String>, _>("body")?
                .unwrap_or_default(),
            facets: Map::new(),
        });
        let value: Option<String> = row.try_get("facet_value")?;
        old.facets.insert(
            row.try_get("facet_key")?,
            value.map(Value::String).unwrap_or(Value::Null),
        );
    }
    Ok(found)
}
fn normalized(path: &Path) -> Option<String> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => (),
            Component::ParentDir => {
                if !result.pop() {
                    return None;
                }
            }
            other => result.push(other.as_os_str()),
        }
    }
    result.to_str().map(str::to_owned)
}
static WIKILINK: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"(!?)\[\[([^\]\n]+)\]\]").expect("wiki regex"));
static MARKDOWN_LINK: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"!?\[[^\]\n]*\]\(<?([^\s)>]+)>?(?:\s+[^)]*)?\)").expect("Markdown regex")
});
fn is_markdown(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
}
fn targets(body: &str) -> Vec<(String, bool, bool)> {
    let mut out = Vec::new();
    for capture in WIKILINK.captures_iter(body) {
        let target = capture[2]
            .split('|')
            .next()
            .unwrap()
            .split('#')
            .next()
            .unwrap()
            .trim();
        out.push((target.to_owned(), true, !capture[1].is_empty()));
    }
    for c in MARKDOWN_LINK.captures_iter(body) {
        if c[0].starts_with('!') {
            continue;
        }
        let path = c[1].split('#').next().unwrap().split('?').next().unwrap();
        if !is_markdown(path) || path.contains(':') || path.starts_with('/') {
            continue;
        }
        out.push((
            percent_encoding::percent_decode_str(path)
                .decode_utf8_lossy()
                .into_owned(),
            false,
            false,
        ));
    }
    out
}
fn resolve(entries: &[Entry], report: &mut Report) -> BTreeSet<(usize, usize)> {
    let mut files: BTreeMap<String, usize> = BTreeMap::new();
    let mut stems: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut folded_files: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut folded_stems: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, e) in entries.iter().enumerate() {
        if let Some(file) = &e.file {
            let path = normalized(&Path::new(&e.root).join(file)).expect("source file path");
            files.insert(path.clone(), i);
            folded_files.entry(path.to_lowercase()).or_default().push(i);
            let stem = Path::new(file).file_stem().unwrap().to_str().unwrap();
            folded_stems.entry(stem.to_lowercase()).or_default().push(i);
            stems
                .entry(
                    Path::new(file)
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                )
                .or_default()
                .push(i);
        }
    }
    let mut links = BTreeSet::new();
    for (source, entry) in entries.iter().enumerate() {
        let Some(file) = &entry.file else {
            continue;
        };
        for (target, wiki, embed) in targets(&entry.body) {
            if target.is_empty() {
                continue;
            } // same-document heading
            let file_target = if wiki && !is_markdown(&target) {
                format!("{target}.md")
            } else {
                target.clone()
            };
            // Exact paths win; folded paths retain their own ambiguity rather
            // than silently picking the first file in a case-sensitive vault.
            let relative = Path::new(&entry.root)
                .join(file)
                .parent()
                .unwrap()
                .join(&file_target);
            let candidates = if wiki {
                vec![Path::new(&entry.root).join(&file_target), relative]
            } else {
                vec![relative]
            };
            let candidates: Vec<_> = candidates
                .iter()
                .filter_map(|path| normalized(path))
                .collect();
            let mut matches = candidates
                .iter()
                .find_map(|path| files.get(path).map(|i| vec![*i]))
                .unwrap_or_default();
            let basename = Path::new(&target)
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or("");
            let stem = if is_markdown(&target) {
                &basename[..basename.len() - 3]
            } else {
                basename
            };
            if matches.is_empty() && wiki && !target.contains('/') {
                matches = stems.get(stem).cloned().unwrap_or_default();
            }
            if matches.is_empty() {
                matches = candidates
                    .iter()
                    .find_map(|path| folded_files.get(&path.to_lowercase()).cloned())
                    .unwrap_or_default();
            }
            if matches.is_empty() && wiki {
                matches = stems
                    .get(stem)
                    .or_else(|| folded_stems.get(&stem.to_lowercase()))
                    .cloned()
                    .unwrap_or_default();
            }
            match matches.as_slice() {
                [dest] => {
                    if source != *dest {
                        links.insert((source, *dest));
                    }
                }
                [] if embed
                    && Path::new(&target).extension().is_some()
                    && !is_markdown(&target) =>
                {
                    report.skipped_embeds += 1;
                }
                [] => report.unresolved_links.push(LinkIssue {
                    source_root: entry.root.clone(),
                    source: file.clone(),
                    target,
                }),
                _ => report.ambiguous_links.push(LinkIssue {
                    source_root: entry.root.clone(),
                    source: file.clone(),
                    target,
                }),
            }
        }
    }
    links
}

pub(super) fn discover(dirs: &[PathBuf]) -> Result<Discovery> {
    if dirs.is_empty() {
        return Err(Error::engine("at least one source directory is required"));
    }
    let mut report = Report {
        dry_run: false,
        ..Report::default()
    };
    let mut roots = BTreeSet::new();
    let mut entries = Vec::new();
    for dir in dirs {
        let root = std::fs::canonicalize(dir)?;
        if !root.is_dir() {
            return Err(Error::engine(format!(
                "not a directory: {}",
                root.display()
            )));
        }
        let Some(root_text) = root.to_str().map(str::to_owned) else {
            report
                .unreadable_files
                .push(root.to_string_lossy().into_owned());
            continue;
        };
        if roots.contains(&root_text) {
            continue;
        }
        for other in &roots {
            let other_path = Path::new(other);
            if root.starts_with(other_path) || other_path.starts_with(&root) {
                return Err(Error::engine(format!(
                    "overlapping source roots: {} and {}; supply disjoint directories",
                    root.display(),
                    other_path.display()
                )));
            }
        }
        roots.insert(root_text);
    }
    for root in &roots {
        let root = Path::new(root);
        scan(root, root, None, &mut entries, &mut report)?;
    }
    let links = resolve(&entries, &mut report);
    Ok(Discovery {
        roots,
        entries,
        links,
        report,
    })
}

pub(super) struct Discovery {
    pub(super) roots: BTreeSet<String>,
    pub(super) entries: Vec<Entry>,
    pub(super) links: BTreeSet<(usize, usize)>,
    pub(super) report: Report,
}

pub async fn import(options: &Options) -> Result<Report> {
    import_inner(options, None).await
}

pub async fn import_with_enrichment(options: &Options, sidecar: &Path) -> Result<Report> {
    import_inner(options, Some(sidecar)).await
}

async fn import_inner(options: &Options, sidecar: Option<&Path>) -> Result<Report> {
    let Discovery {
        roots,
        mut entries,
        links,
        mut report,
    } = discover(&options.dirs)?;
    report.dry_run = options.dry_run;
    let enrichment = match sidecar {
        Some(path) => ImportPlan::load(path, &roots, &entries)?,
        None => ImportPlan::default(),
    };
    report.stale_enrichment.clone_from(&enrichment.stale);
    report
        .supersession_candidates
        .clone_from(&enrichment.candidates);
    for (index, note) in &enrichment.notes {
        note.add_facets(&mut entries[*index].facets);
    }
    // A separate physically read-only connection avoids migrations, owner resolution,
    // registry read capture, and database creation during a dry run.
    let pool = if options.db.exists() {
        Some(
            SqlitePool::connect_with(
                SqliteConnectOptions::new()
                    .filename(std::path::absolute(&options.db)?)
                    .read_only(true)
                    .create_if_missing(false),
            )
            .await?,
        )
    } else {
        None
    };
    let existing = match &pool {
        Some(pool) => bindings(pool, &roots).await?,
        None => BTreeMap::new(),
    };
    let mut existing_links = BTreeMap::new();
    if let Some(pool) = &pool {
        for row in sqlx::query("SELECT source_id,target_id,relationship,note FROM links")
            .fetch_all(pool)
            .await?
        {
            existing_links.insert(
                (
                    row.try_get::<String, _>("source_id")?,
                    row.try_get::<String, _>("target_id")?,
                    row.try_get::<String, _>("relationship")?,
                ),
                row.try_get::<Option<String>, _>("note")?,
            );
        }
    }
    if let Some(pool) = pool {
        pool.close().await;
    }
    let keys: BTreeSet<_> = entries.iter().map(Entry::key).collect();
    for (key, old) in &existing {
        let source = Path::new(&key.0).join(&key.1);
        if report
            .unreadable_files
            .iter()
            .any(|path| source.starts_with(path))
        {
            continue;
        }
        if !keys.contains(key) {
            report.disappeared.push(format!("{}/{}", key.0, key.1));
        } else if let Some(file) = old.facets.get("source_file").and_then(Value::as_str) {
            if !Path::new(&key.0).join(file).is_file() {
                report.disappeared.push(format!("{}/{file}", key.0));
            }
        }
    }
    let db = if options.dry_run {
        None
    } else {
        if let Some(parent) = options.db.parent().filter(|p| !p.as_os_str().is_empty()) {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(parent)?;
        }
        let path = text(&options.db)?;
        Some(if options.db.exists() {
            crate::open_existing_database(&path).await?
        } else {
            crate::create_database(&path).await?
        })
    };
    let outcome = apply(
        &entries,
        &existing,
        &links,
        &existing_links,
        &enrichment,
        db.as_ref(),
        &mut report,
    )
    .await;
    if let Some(db) = db {
        db.close().await;
    }
    outcome?;
    Ok(report)
}
async fn apply(
    entries: &[Entry],
    existing: &BTreeMap<Binding, Existing>,
    links: &BTreeSet<(usize, usize)>,
    existing_links: &BTreeMap<(String, String, String), Option<String>>,
    enrichment: &ImportPlan,
    db: Option<&crate::db::Db>,
    report: &mut Report,
) -> Result<()> {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry)?;
    register_surface_tools(&mut registry)?;
    let caller = if let Some(db) = db {
        Some(super::sqlite_owner_caller(
            crate::identity::resolve_stdio_account_identity(db, None).await?,
        ))
    } else {
        None
    };
    let mut ids = Vec::new();
    let mut folder_ids = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let old = existing.get(&entry.key());
        let mut facets = entry.facets.clone();
        // A disappeared folder note is still imported content: retain it just
        // like a disappeared standalone note, while reporting the missing file.
        let missing_folder_note = entry.folder
            && entry.file.is_none()
            && old.is_some_and(|o| o.facets.contains_key("source_file"));
        let body = if missing_folder_note {
            let old = old.expect("bound folder note");
            for (key, value) in &old.facets {
                if key.starts_with("fm.") || key == "source_file" || key == "file_modified_at" {
                    facets.insert(key.clone(), value.clone());
                }
            }
            &old.body
        } else {
            &entry.body
        };
        if let Some(old) = old {
            // Only importer-owned keys are replaced. User/agent facets survive re-import.
            for key in old
                .facets
                .keys()
                .filter(|k| k.starts_with("fm.") || k.as_str() == "source_file")
            {
                if !facets.contains_key(key) {
                    facets.insert(key.clone(), Value::Null);
                }
            }
        }
        let changed = old.is_none_or(|old| {
            old.name != entry.name
                || old.body != *body
                || facets
                    .iter()
                    .filter(|(k, _)| k.as_str() != "file_modified_at")
                    .any(|(k, v)| {
                        if v.is_null() {
                            old.facets.contains_key(k)
                        } else {
                            old.facets.get(k) != Some(v)
                        }
                    })
        });
        if !changed {
            if let Some(value) = old.and_then(|old| old.facets.get("file_modified_at")) {
                facets.insert("file_modified_at".into(), value.clone());
            }
        }
        let count = if entry.folder {
            &mut report.folders
        } else {
            &mut report.notes
        };
        if old.is_none() {
            count.created += 1;
        } else if changed {
            count.updated += 1;
        } else {
            count.unchanged += 1;
        }
        let home = entry
            .parent
            .as_ref()
            .and_then(|p| folder_ids.get(&(entry.root.clone(), p.clone())))
            .cloned()
            .unwrap_or_else(|| crate::schema::ROOT_RECORD_ID.to_owned());
        let mut id = old
            .map(|o| o.id.clone())
            .unwrap_or_else(|| format!("planned:{}", ids.len()));
        if changed {
            if let (Some(db), Some(caller)) = (db, &caller) {
                // Structural folders remain folders, including folders with a body note.
                let note = enrichment.notes.get(&index).filter(|_| !entry.folder);
                let mut args = if let Some(old) = old {
                    json!({"id":id,"name":entry.name,"body_set":body,"if_unmodified_since":old.updated_at,"facets":facets,"reason":"Re-import Markdown source"})
                } else {
                    let record_type =
                        note.map(|n| n.record_type.as_str())
                            .unwrap_or(if entry.folder {
                                "Collection"
                            } else {
                                "Document"
                            });
                    let kind = note.map(|n| n.kind.as_str()).unwrap_or(if entry.folder {
                        "folder"
                    } else {
                        "note"
                    });
                    let kind = if record_type == "Document" && kind == "attachment" {
                        "captured-source"
                    } else {
                        kind
                    };
                    let mut args = json!({"type":record_type,"kind":kind,"name":entry.name,"body":body,"facets":facets,"home_id":home,"confirm":true,"reason":"Import distinct Markdown source path"});
                    if note.is_some() {
                        args["id"] = json!(uuid::Uuid::new_v4().to_string());
                    }
                    if record_type == "WorkItem" {
                        args["lifecycle"] =
                            json!(note.and_then(|n| n.lifecycle.as_deref()).unwrap_or("open"));
                        args["facets"]["lifecycle_inferred"] = json!("agent");
                    }
                    args
                };
                let result = call(
                    &registry,
                    db,
                    caller,
                    if old.is_some() {
                        "update_record"
                    } else {
                        "create_record"
                    },
                    args.clone(),
                )
                .await;
                let result = match result {
                    Err(Error::Engine(ref refusal))
                        if old.is_none()
                            && note.is_some()
                            && (args["type"] != "Document" || args["kind"] != "note") =>
                    {
                        // A caller-chosen ID lets us prove a refused write created nothing
                        // before falling back. Never retry an uncertain committed write.
                        let exists: bool =
                            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM records WHERE id=?)")
                                .bind(args["id"].as_str().expect("enriched create ID"))
                                .fetch_one(db.pool())
                                .await?;
                        if exists {
                            result
                        } else {
                            report.enrichment_fallbacks.push(format!(
                                "{}: {}/{} refused ({refusal}); used Document/note",
                                entry.display(),
                                args["type"].as_str().unwrap_or(""),
                                args["kind"].as_str().unwrap_or("")
                            ));
                            args["type"] = json!("Document");
                            args["kind"] = json!("note");
                            args.as_object_mut().unwrap().remove("lifecycle");
                            args["facets"]
                                .as_object_mut()
                                .unwrap()
                                .remove("lifecycle_inferred");
                            call(&registry, db, caller, "create_record", args).await
                        }
                    }
                    other => other,
                }
                .map_err(|e| {
                    Error::engine(format!(
                        "{}: {e}; earlier writes may have committed; re-run to resume",
                        entry.display()
                    ))
                })?;
                if old.is_none() {
                    id = result["id"]
                        .as_str()
                        .ok_or_else(|| Error::engine("create_record returned no id"))?
                        .into();
                }
            }
        }
        if entry.folder {
            folder_ids.insert(entry.key(), id.clone());
        }
        ids.push(id);
    }
    let mut planned_links = BTreeMap::new();
    for &(source, target) in links {
        let enriched = enrichment.links.get(&(source, target));
        let relationship = enriched
            .map(|l| l.relationship.as_str())
            .unwrap_or("relates_to");
        planned_links.insert(
            (source, target, relationship.to_owned()),
            enriched.and_then(|l| l.evidence.clone()),
        );
    }
    for (&(source, target), evidence) in &enrichment.amends {
        planned_links.insert((source, target, "amends".into()), Some(evidence.clone()));
    }
    let typed = |relationship: &str| ["part_of", "implements", "amends"].contains(&relationship);
    let pair = |s: usize, t: usize| if s < t { (s, t) } else { (t, s) };
    let indices: BTreeMap<_, _> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let mut typed_pairs: BTreeSet<_> = planned_links
        .keys()
        .filter(|(_, _, r)| typed(r))
        .map(|(s, t, _)| pair(*s, *t))
        .collect();
    for (s, t, _) in existing_links.keys().filter(|(_, _, r)| typed(r)) {
        if let (Some(s), Some(t)) = (indices.get(s.as_str()), indices.get(t.as_str())) {
            typed_pairs.insert(pair(*s, *t));
        }
    }
    planned_links.retain(|(s, t, r), _| r != "relates_to" || !typed_pairs.contains(&pair(*s, *t)));
    for ((source, target, relationship), evidence) in planned_links {
        if existing_links.contains_key(&(
            ids[source].clone(),
            ids[target].clone(),
            relationship.clone(),
        )) {
            report.links.unchanged += 1;
            continue;
        }
        if let (Some(db), Some(caller)) = (db, &caller) {
            let mut args = json!({"action":"add","source_id":ids[source],"target_id":ids[target],"relationship":relationship});
            if relationship == "relates_to" {
                args["note"] = json!(IMPORT_LINK_NOTE);
            } else if let Some(evidence) = evidence {
                args["note"] = json!(evidence);
            }
            call(&registry, db, caller, "manage_links", args).await?;
        }
        report.links.created += 1;
    }
    // Remove only explicitly marked importer links, after typed additions succeed.
    // Older unmarked links have no reliable writer provenance and are preserved.
    for ((source, target, relationship), note) in existing_links {
        if relationship != "relates_to" || note.as_deref() != Some(IMPORT_LINK_NOTE) {
            continue;
        }
        let (Some(&s), Some(&t)) = (indices.get(source.as_str()), indices.get(target.as_str()))
        else {
            continue;
        };
        if !typed_pairs.contains(&pair(s, t)) {
            continue;
        }
        if let (Some(db), Some(caller)) = (db, &caller) {
            call(&registry,db,caller,"manage_links",json!({"action":"remove","source_id":source,"target_id":target,"relationship":"relates_to"})).await?;
        }
        report.removed_plain_links += 1;
    }
    Ok(())
}
async fn call(
    registry: &ToolRegistry,
    db: &crate::db::Db,
    caller: &Caller,
    tool: &str,
    args: Value,
) -> Result<Value> {
    // Box the large tool-dispatch future, as other in-process callers do.
    Box::pin(registry.call(db.clone(), caller.clone(), tool, args)).await
}
