//! Standalone, descriptor-relative inspection. This does not open a publisher,
//! take its writer lock, initialize directories, or contact the home.
use super::check::{self, Diagnostic, FileReport, FileState, LinkIndex, LinkTarget, Severity};
use super::publisher::{digest, list, open, parts, State};
use crate::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

#[derive(Serialize)]
pub(crate) struct Report {
    schema: &'static str,
    origin: String,
    published_act: Option<i64>,
    generation: String,
    /// The catalog is the authorized projection, not a fresh home query.
    catalog_basis: &'static str,
    link_resolution_provisional: bool,
    freshness: Freshness,
    files: Vec<FileReport>,
}

#[derive(Default, Serialize)]
struct Freshness {
    age_seconds: Option<i64>,
    target_rpo_seconds: Option<i64>,
    fresh: bool,
    observed_at: Option<String>,
    diagnostics: Option<Value>,
}

fn clean(value: &str) -> String {
    value.chars().flat_map(|c| c.escape_default()).collect()
}

impl Report {
    pub(crate) fn exit_code(&self) -> u8 {
        u8::from(
            self.files
                .iter()
                .any(|f| f.diagnostics.iter().any(|d| d.severity == Severity::Error)),
        )
    }

    pub(crate) fn human(&self, all: bool) -> String {
        let mut out = format!(
            "Vault check: read-only; nothing sent.\nCatalog: projected vault, age {}, freshness {}.\n",
            self.freshness.age_seconds.map(|a| format!("{a}s")).unwrap_or_else(|| "unknown".into()),
            if self.freshness.fresh { "within RPO" } else { "stale or unknown (link checks provisional)" },
        );
        if self.link_resolution_provisional {
            out.push_str("Link resolution is provisional: catalog freshness or completeness is not established.\n");
        }
        let mut counts = BTreeMap::<String, usize>::new();
        for file in &self.files {
            let state = serde_json::to_value(&file.state)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            *counts.entry(state.clone()).or_default() += 1;
            if all || file.state != FileState::Unchanged || !file.diagnostics.is_empty() {
                out.push_str(&format!("{state}  {}\n", clean(&file.path)));
                for intent in &file.intents {
                    // Bodies can be large and contain terminal controls; details stay in JSON.
                    let value = serde_json::to_value(intent).unwrap();
                    out.push_str(&format!(
                        "  would propose {}\n",
                        value["kind"].as_str().unwrap_or("change")
                    ));
                }
                for d in &file.diagnostics {
                    out.push_str(&format!(
                        "  {}:{}:{}: {}: {} Next: {}\n",
                        clean(&d.path),
                        d.line,
                        d.column,
                        clean(&d.code),
                        clean(&d.message),
                        clean(&d.next_step)
                    ));
                }
            }
        }
        out.push_str(&format!(
            "{}\n",
            counts
                .iter()
                .map(|(s, n)| format!("{n} {s}"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out
    }
}

fn root_fd(path: &Path) -> Result<File> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut dir = File::open("/")?;
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                dir = open(
                    &dir,
                    name.to_str()
                        .ok_or_else(|| Error::engine("vault path must be UTF-8"))?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
            }
            _ => {
                return Err(Error::engine(
                    "vault path must not contain parent traversal",
                ))
            }
        }
    }
    Ok(dir)
}

fn read(root: &File, path: &str, limit: u64) -> Result<Option<Vec<u8>>> {
    let components = parts(path)?;
    let result = (|| -> Result<Vec<u8>> {
        let mut dir = root.try_clone()?;
        for part in &components[..components.len() - 1] {
            dir = open(&dir, part, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        }
        let file = open(
            &dir,
            components.last().unwrap(),
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > limit {
            return Err(Error::engine(
                "vault entry must be a regular single-link file within the read budget",
            ));
        }
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(Error::engine("vault entry exceeded the read budget"));
        }
        Ok(bytes)
    })();
    match result {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn diagnostic(path: &str, code: &str, message: &str, next: &str) -> Diagnostic {
    Diagnostic {
        path: path.into(),
        line: 1,
        column: 1,
        severity: Severity::Error,
        code: code.into(),
        message: message.into(),
        next_step: next.into(),
    }
}

fn problem(path: &str, code: &str, message: &str, next: &str) -> FileReport {
    FileReport {
        path: path.into(),
        state: FileState::ModifiedInvalid,
        record_id: None,
        diagnostics: vec![diagnostic(path, code, message, next)],
        intents: vec![],
    }
}

fn property(text: &str, key: &str) -> Option<String> {
    if !text.starts_with("---\n") {
        return None;
    }
    for line in text[4..].lines().take_while(|line| *line != "---") {
        let Some((k, v)) = line.split_once(": ") else {
            continue;
        };
        let k = serde_json::from_str::<String>(k).unwrap_or_else(|_| k.to_owned());
        if k == key {
            return serde_json::from_str::<String>(v).ok();
        }
    }
    None
}

fn artifact_companion(text: &str) -> bool {
    matches!(
        property(text, "facet.runtime")
            .or_else(|| property(text, "facet.artifact_runtime"))
            .as_deref(),
        Some("native.html.v1" | "native.mdx.v2" | "native.board.v1")
    )
}

fn freshness(status: Option<&[u8]>) -> Freshness {
    let Some(text) = status.and_then(|b| std::str::from_utf8(b).ok()) else {
        return Freshness::default();
    };
    let Some(raw) = text
        .lines()
        .find_map(|line| line.strip_prefix("Freshness and refresh diagnostics: "))
    else {
        return Freshness::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Freshness::default();
    };
    let observed = value["observed_at"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
    let elapsed =
        observed.map(|t| (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds());
    let age = value["freshness"]["age_seconds"]
        .as_i64()
        .filter(|n| *n >= 0)
        .zip(elapsed.filter(|n| *n >= 0))
        .map(|(age, elapsed)| age.saturating_add(elapsed));
    let rpo = value["freshness"]["target_rpo_seconds"]
        .as_i64()
        .filter(|n| *n > 0);
    let fresh = text.contains("Availability: authorized copy available\n")
        && value["freshness"]["state"] == "fresh"
        && age.zip(rpo).is_some_and(|(a, r)| a <= r);
    Freshness {
        age_seconds: age,
        target_rpo_seconds: rpo,
        fresh,
        observed_at: observed.map(|d| d.to_rfc3339()),
        diagnostics: Some(value),
    }
}

pub(crate) fn inspect(path: &Path) -> Result<Report> {
    let root = root_fd(path)?;
    let state_bytes = read(&root, ".native/state.json", 512 * 1024 * 1024)?
        .ok_or_else(|| Error::engine("no published vault state here; pass --vault <directory>"))?;
    let state = State::from_bytes(&state_bytes)?;
    #[cfg(feature = "v2-kernel-probe")]
    if state.member_revoked {
        return Err(Error::engine("vault member access ended"));
    }
    let status = read(&root, ".native/STATUS.md", 2 * 1024 * 1024)?;
    let status_trusted = status.as_ref().is_some_and(|bytes| {
        state.files.get(".native/STATUS.md").is_some_and(|entry| {
            let hash = digest(bytes);
            hash == entry.digest
                || entry.pending_digest.as_ref() == Some(&hash)
                || entry.prior_digests.contains(&hash)
        })
    });
    let freshness = freshness(status.as_deref().filter(|_| status_trusted));
    let catalog_incomplete = state
        .files
        .iter()
        .filter(|(path, _)| path.as_str() != ".native/STATUS.md")
        .any(|(_, e)| {
            e.pending_digest.is_some()
                || !e.prior_digests.is_empty()
                || e.latest_rendered_absent
                || e.latest_rendered_digest
                    .as_ref()
                    .is_some_and(|latest| latest != &e.digest)
        });
    let mut index = LinkIndex {
        entries: vec![],
        fresh: freshness.fresh && !catalog_incomplete,
    };
    let mut contents = BTreeMap::new();
    let mut failures = BTreeMap::new();
    for (path, entry) in &state.files {
        if path == ".native/STATUS.md" {
            continue;
        }
        match read(&root, path, 32 * 1024 * 1024) {
            Ok(bytes) => {
                contents.insert(path.clone(), bytes);
            }
            Err(err) => {
                failures.insert(path.clone(), problem(path, "unsafe_or_unreadable", &err.to_string(), "Keep the entry as a regular file within the vault; do not follow symlinks."));
            }
        }
        let unsettled = entry.pending_digest.is_some() || !entry.prior_digests.is_empty();
        if unsettled {
            continue;
        }
        let trusted = entry.base.as_ref().map(|b| b.text.as_str()).or_else(|| {
            let bytes = contents.get(path)?.as_ref()?;
            (digest(bytes) == entry.digest)
                .then(|| std::str::from_utf8(bytes).ok())
                .flatten()
        });
        if trusted.is_none()
            && path.ends_with(".md")
            && path != "README.md"
            && !path.starts_with("Messages/")
        {
            index.fresh = false;
        }
        if let Some(text) = trusted {
            if let Some(id) = property(text, "id") {
                index.entries.push(LinkTarget {
                    record_id: id,
                    path: path.clone(),
                    name: property(text, "name").unwrap_or_default(),
                });
            }
        }
    }
    let mut files = Vec::new();
    for (path, entry) in &state.files {
        if path == ".native/STATUS.md" {
            continue;
        }
        if let Some(failure) = failures.remove(path) {
            files.push(failure);
            continue;
        }
        let Some(bytes) = contents.get(path).and_then(Option::as_ref) else {
            files.push(problem(
                path,
                "missing_file",
                "A managed file was deleted, renamed or moved; no archive or move is inferred.",
                "Restore its published path or use Native MCP for structural changes.",
            ));
            continue;
        };
        if entry.pending_digest.is_some() || !entry.prior_digests.is_empty() {
            files.push(problem(
                path,
                "publication_incomplete",
                "Publication has an unsettled crash-recovery journal; the base is not established.",
                "Let the node reconcile publication, then check again.",
            ));
            continue;
        }
        let hash = digest(bytes);
        if hash == entry.digest {
            // Exercise parsing even on unchanged ordinary notes; opaque companions
            // and aggregates are intentionally read-only in grammar v0.
            if let Ok(text) = std::str::from_utf8(bytes) {
                if property(text, "id").is_some() && !artifact_companion(text) {
                    files.push(check::check_file(path, text, text, &index));
                    continue;
                }
            }
            files.push(FileReport {
                path: path.clone(),
                state: FileState::Unchanged,
                record_id: None,
                diagnostics: vec![],
                intents: vec![],
            });
            continue;
        }
        let Some(base) = &entry.base else {
            files.push(problem(path,"base_unavailable","This edited legacy file has no retained published text; a digest cannot recover its original body.","Keep your edit. Use Native MCP to make the intended change; do not discard it to initialize a base."));
            continue;
        };
        if !path.ends_with(".md")
            || property(&base.text, "id").is_none()
            || artifact_companion(&base.text)
        {
            files.push(problem(path,"unsupported_format","This generated file is an aggregate, artifact companion or support file; grammar v0 does not translate its edits.","Use Native MCP for this change."));
            continue;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            files.push(problem(
                path,
                "encoding",
                "Note is not UTF-8.",
                "Save the note as UTF-8.",
            ));
            continue;
        };
        let mut report = check::check_file(path, &base.text, text, &index);
        if entry.latest_rendered_absent
            || entry
                .latest_rendered_digest
                .as_ref()
                .is_some_and(|latest| latest != &entry.digest)
        {
            if report.state != FileState::ModifiedInvalid {
                report.state = FileState::BaseMovedOn;
            }
            let mut d = diagnostic(path,"base_moved_on","The latest rendered Native projection differs from this edit's published base; acceptance needs a future home merge.","Keep the local edit and review the proposed changes; this checker cannot determine merge acceptance.");
            d.severity = Severity::Warning;
            report.diagnostics.push(d);
        }
        files.push(report);
    }
    if status.is_some() && !status_trusted {
        files.push(problem(
            ".native/STATUS.md",
            "status_modified",
            "STATUS does not match its publication ledger; catalog freshness is unknown.",
            "Do not edit generated STATUS; use Native MCP for changes.",
        ));
    }
    discover_local(&root, "", &state, &mut files, 0)?;
    if read(&root, ".native/state.json", 512 * 1024 * 1024)?.as_deref()
        != Some(state_bytes.as_slice())
    {
        return Err(Error::engine(
            "vault publication changed during inspection; run the command again",
        ));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Report {
        schema: "native.vault-check.v1",
        origin: state.origin,
        published_act: state.successful_act,
        generation: state.successful_generation,
        catalog_basis: "authorized_vault_projection",
        link_resolution_provisional: !index.fresh,
        freshness,
        files,
    })
}

fn discover_local(
    dir: &File,
    prefix: &str,
    state: &State,
    files: &mut Vec<FileReport>,
    depth: usize,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::engine("vault directory nesting exceeds 64"));
    }
    for name in list(dir)? {
        if name.starts_with('.') {
            continue;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if state.files.contains_key(&path) {
            continue;
        }
        match open(dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(child) => discover_local(&child, &path, state, files, depth + 1)?,
            Err(_) => {
                let mut report = FileReport {
                    path: path.clone(),
                    state: FileState::LocalOnly,
                    record_id: None,
                    diagnostics: vec![],
                    intents: vec![],
                };
                let mut d = diagnostic(&path,"local_only","Native did not publish this file; no create, rename or move is inferred, including in Inbox/.","Keep the file; use Native MCP to create a record explicitly.");
                d.severity = Severity::Warning;
                report.diagnostics.push(d);
                files.push(report);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::markdown_vault::{Publisher, SourceRecord, SourceSnapshot};
    use serde_json::json;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> (tempfile::TempDir, Publisher, SourceSnapshot, String) {
        let dir = tempfile::tempdir().unwrap();
        let mut source = SourceSnapshot {
            origin: "origin".into(),
            account: "alice".into(),
            act: 1,
            generation: "generation".into(),
            ..Default::default()
        };
        source.records.insert(
            "native:root".into(),
            SourceRecord {
                id: "native:root".into(),
                record_type: "Collection".into(),
                kind: Some("folder".into()),
                name: Some("Workspace".into()),
                ..Default::default()
            },
        );
        source.records.insert(
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            SourceRecord {
                id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                record_type: "Document".into(),
                kind: Some("note".into()),
                name: Some("Note".into()),
                body: Some("Original body".into()),
                home_id: Some("native:root".into()),
                ..Default::default()
            },
        );
        let root = dir.path().join("vault");
        let mut publisher = Publisher::open(&root).unwrap();
        publisher.cycle(&source).unwrap();
        let bytes = std::fs::read(root.join(".native/state.json")).unwrap();
        let state = State::from_bytes(&bytes).unwrap();
        let note = state
            .files
            .iter()
            .find(|(_, e)| {
                e.base.as_ref().is_some_and(|b| {
                    property(&b.text, "id").as_deref()
                        == Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
                })
            })
            .unwrap()
            .0
            .clone();
        (dir, publisher, source, note)
    }
    fn edit(root: &Path, path: &str, text: &str) {
        std::fs::set_permissions(root.join(path), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(root.join(path), text).unwrap();
    }
    #[test]
    fn inspection_previews_body_without_changing_files_or_writer_lock() {
        let (dir, _publisher, _source, note) = fixture();
        let root = dir.path().join("vault");
        let state_before = std::fs::read(root.join(".native/state.json")).unwrap();
        let original = std::fs::read_to_string(root.join(&note)).unwrap();
        let changed = original.replace("Original body", "Edited body");
        edit(&root, &note, &changed);
        let report = inspect(&root).unwrap();
        assert_eq!(report.exit_code(), 0);
        let file = report.files.iter().find(|f| f.path == note).unwrap();
        assert_eq!(file.state, FileState::ModifiedValid);
        assert_eq!(file.intents.len(), 1);
        assert_eq!(std::fs::read_to_string(root.join(&note)).unwrap(), changed);
        assert_eq!(
            std::fs::read(root.join(".native/state.json")).unwrap(),
            state_before
        );
    }
    #[test]
    fn deleted_managed_and_new_root_files_have_distinct_diagnostics() {
        let (dir, _publisher, _source, note) = fixture();
        let root = dir.path().join("vault");
        std::fs::set_permissions(
            root.join(&note).parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::remove_file(root.join(&note)).unwrap();
        std::fs::write(root.join("new.md"), "local draft").unwrap();
        let report = inspect(&root).unwrap();
        assert_eq!(report.exit_code(), 1);
        assert!(report
            .files
            .iter()
            .any(|f| f.path == note && f.diagnostics[0].code == "missing_file"));
        assert!(report.files.iter().any(|f| f.path == "new.md"
            && f.state == FileState::LocalOnly
            && f.intents.is_empty()));
    }
    #[test]
    fn symlinked_note_is_not_read_and_root_symlink_is_refused() {
        let (dir, _publisher, _source, note) = fixture();
        let root = dir.path().join("vault");
        std::fs::set_permissions(
            root.join(&note).parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::remove_file(root.join(&note)).unwrap();
        let secret = dir.path().join("outside");
        std::fs::write(&secret, "secret").unwrap();
        symlink(&secret, root.join(&note)).unwrap();
        let report = inspect(&root).unwrap();
        assert_eq!(report.exit_code(), 1);
        assert!(report
            .files
            .iter()
            .any(|f| f.path == note && f.diagnostics[0].code == "unsafe_or_unreadable"));
        let alias = dir.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(inspect(&alias).is_err());
    }
    #[test]
    fn moved_base_and_invalid_edit_keep_error_and_no_intents() {
        let (dir, mut publisher, mut source, note) = fixture();
        let root = dir.path().join("vault");
        let original = std::fs::read_to_string(root.join(&note)).unwrap();
        edit(
            &root,
            &note,
            &original.replace("\"name\": \"Note\"", "\"id\": \"forged\""),
        );
        source.act = 2;
        source
            .records
            .get_mut("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .unwrap()
            .body = Some("New canonical body".into());
        publisher.cycle(&source).unwrap();
        let report = inspect(&root).unwrap();
        let file = report.files.iter().find(|f| f.path == note).unwrap();
        assert_eq!(file.state, FileState::ModifiedInvalid);
        assert!(file.intents.is_empty());
        assert!(file.diagnostics.iter().any(|d| d.code == "base_moved_on"));
    }
    #[test]
    fn freshness_ages_observation_and_unknown_never_means_fresh() {
        let old = (chrono::Utc::now() - chrono::Duration::seconds(400)).to_rfc3339();
        let status = format!(
            "Availability: authorized copy available\nFreshness and refresh diagnostics: {}\n",
            json!({"observed_at":old,"freshness":{"state":"fresh","age_seconds":0,"target_rpo_seconds":300}})
        );
        let observed = freshness(Some(status.as_bytes()));
        assert!(!observed.fresh);
        assert!(observed.age_seconds.unwrap() >= 400);
        assert!(!freshness(None).fresh);
    }
    #[test]
    fn unsettled_plan_refuses_even_when_old_file_is_unchanged() {
        let (dir, mut publisher, mut source, note) = fixture();
        source.act = 2;
        source
            .records
            .get_mut("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .unwrap()
            .body = Some("New canonical body".into());
        super::super::publisher::FAIL_AFTER_PLAN.with(|flag| flag.set(true));
        assert!(publisher.cycle(&source).is_err());
        let report = inspect(&dir.path().join("vault")).unwrap();
        assert_eq!(report.exit_code(), 1);
        assert!(report
            .files
            .iter()
            .any(|f| f.path == note && f.diagnostics[0].code == "publication_incomplete"));
    }
    #[test]
    fn fresh_published_catalog_rejects_new_unresolved_body_link() {
        let (dir, mut publisher, mut source, note) = fixture();
        source.freshness = json!({"observed_at":chrono::Utc::now().to_rfc3339(),"freshness":{"state":"fresh","age_seconds":0,"target_rpo_seconds":300}});
        publisher.cycle(&source).unwrap();
        let root = dir.path().join("vault");
        let original = std::fs::read_to_string(root.join(&note)).unwrap();
        edit(
            &root,
            &note,
            &original.replace("Original body", "Edited [[No such record]]"),
        );
        let report = inspect(&root).unwrap();
        assert!(!report.link_resolution_provisional);
        assert_eq!(report.exit_code(), 1);
        assert!(report
            .files
            .iter()
            .find(|f| f.path == note)
            .unwrap()
            .diagnostics
            .iter()
            .any(|d| d.code == "unresolved_link" && d.severity == Severity::Error));
    }
    #[test]
    fn authored_open_artifact_link_is_ordinary_body_content() {
        let (dir, _publisher, _source, note) = fixture();
        let root = dir.path().join("vault");
        let original = std::fs::read_to_string(root.join(&note)).unwrap();
        edit(
            &root,
            &note,
            &original.replace("Original body", "[Open artifact](<example.html>)"),
        );
        let report = inspect(&root).unwrap();
        let file = report.files.iter().find(|f| f.path == note).unwrap();
        assert_eq!(file.state, FileState::ModifiedValid);
        assert_eq!(file.intents.len(), 1);
    }
}
