//! Bounded headless CLI calls, validated partial results, and resumable cache.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use super::spec;
use crate::native_cli::enrichment::{Agent, Usage};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub(super) enum Pass {
    A,
    B,
    C,
}
impl Pass {
    pub(super) fn brief(self) -> &'static str {
        match self {
            Self::A => spec::BRIEF_A,
            Self::B => spec::BRIEF_B,
            Self::C => spec::BRIEF_C,
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::A => spec::SCHEMA_A,
            Self::B => spec::SCHEMA_B,
            Self::C => spec::SCHEMA_C,
        }
    }
    fn field(self) -> &'static str {
        match self {
            Self::A => "notes",
            Self::B => "links",
            Self::C => "pairs",
        }
    }
    fn row_key(self, row: &Value) -> Option<String> {
        match self {
            Self::A => row["id"].as_str().map(str::to_owned),
            Self::B => Some(link_key(row["source"].as_str()?, row["target"].as_str()?)),
            Self::C => row["pair"].as_u64().map(|n| n.to_string()),
        }
    }
    fn admissible(self, row: &Value) -> bool {
        match self {
            Self::A => {
                ["Document", "WorkItem", "Resolution", "Entity", "Collection"]
                    .contains(&row["type"].as_str().unwrap_or(""))
                    && row["kind"].as_str().is_some_and(|s| !s.trim().is_empty())
                    && (row["lifecycle"].is_null()
                        || ["open", "in_progress", "blocked", "completed", "closed"]
                            .contains(&row["lifecycle"].as_str().unwrap_or("")))
            }
            Self::B => {
                let relationship = row["relationship"].as_str().unwrap_or("");
                relationship == "relates_to"
                    || (["part_of", "implements"].contains(&relationship) && has_evidence(row))
            }
            Self::C => row["verdict"] == "independent" || has_evidence(row),
        }
    }
}
fn has_evidence(row: &Value) -> bool {
    row["evidence"]
        .as_str()
        .is_some_and(|s| !s.trim().is_empty())
}
pub(super) fn link_key(source: &str, target: &str) -> String {
    format!("{source}\0{target}")
}

pub(super) struct Batch {
    pub(super) pass: Pass,
    pub(super) prompt: String,
    pub(super) expected: BTreeSet<String>,
    // Full file hashes invalidate cached answers even for changes beyond truncation.
    pub(super) signatures: Vec<(String, String)>,
}
#[derive(Serialize, Deserialize, Default)]
struct Cached {
    rows: BTreeMap<String, Value>,
}
pub(super) struct Answer {
    pub(super) rows: BTreeMap<String, Value>,
    pub(super) missing: Vec<String>,
    pub(super) usage: Usage,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct CodexIsolation {
    pub disabled: Vec<String>,
    pub remaining: Vec<String>,
}
fn agentic_feature(name: &str) -> bool {
    // Keep permission/approval guardrails and auditing enabled; these are not
    // execution capabilities even if their names mention exec or images.
    if ["approval", "guardian", "trust", "metadata"]
        .iter()
        .any(|token| name.contains(token))
    {
        return false;
    }
    [
        "apps",
        "hooks",
        "skill_search",
        "sleep_tool",
        "workspace_dependencies",
    ]
    .contains(&name)
        || [
            "shell",
            "exec",
            "agent",
            "browser",
            "computer",
            "code_mode",
            "image",
            "plugin",
            "mcp",
            "local_automation",
        ]
        .iter()
        .any(|token| name.contains(token))
}
fn codex_overrides(command: &mut tokio::process::Command, disabled: &[String]) {
    command.args([
        "-c",
        "mcp_servers={}",
        "-c",
        "web_search=\"disabled\"",
        "-c",
        "project_doc_max_bytes=0",
    ]);
    for feature in disabled {
        command.args(["--disable", feature]);
    }
}
async fn probe_codex(
    executable: &Path,
    model: Option<&str>,
    disabled: &[String],
) -> Result<BTreeMap<String, bool>> {
    let cwd = tempfile::tempdir()?;
    let home = tempfile::tempdir()?;
    let mut command = tokio::process::Command::new(executable);
    // `features list` has no --ignore-user-config flag. An empty temporary
    // CODEX_HOME gives the diagnostic the same absence of user configuration
    // as exec --ignore-user-config, without copying or reading credentials.
    command
        .current_dir(cwd.path())
        .env("CODEX_HOME", home.path())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    if let Some(model) = model {
        command.args(["-m", model]);
    }
    codex_overrides(&mut command, disabled);
    command.args(["features", "list"]);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .map_err(|_| Error::engine("Codex feature diagnostics timed out; use --agent claude"))??;
    if !output.status.success() {
        return Err(Error::engine(format!(
            "cannot inspect Codex isolation features: {}; use --agent claude",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(400)
                .collect::<String>()
        )));
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| Error::engine("Codex feature diagnostics are not UTF-8"))?;
    let mut features = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        let value = match fields.last().copied() {
            Some("true") => true,
            Some("false") => false,
            _ => {
                return Err(Error::engine(
                    "unrecognized Codex feature diagnostics; use --agent claude",
                ))
            }
        };
        if fields.len() < 3
            || !fields[0]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ['_', '.', '-'].contains(&c))
            || features.insert(fields[0].to_owned(), value).is_some()
        {
            return Err(Error::engine(
                "unrecognized Codex feature diagnostics; use --agent claude",
            ));
        }
    }
    if features.is_empty() {
        return Err(Error::engine(
            "empty Codex feature diagnostics; use --agent claude",
        ));
    }
    Ok(features)
}
pub(super) async fn codex_isolation(
    executable: &Path,
    model: Option<&str>,
) -> Result<CodexIsolation> {
    let initial = probe_codex(executable, model, &[]).await?;
    let disabled: Vec<_> = initial
        .iter()
        .filter(|(name, enabled)| **enabled && agentic_feature(name))
        .map(|(name, _)| name.clone())
        .collect();
    let effective = probe_codex(executable, model, &disabled).await?;
    if initial.keys().any(|name| !effective.contains_key(name)) {
        return Err(Error::engine(
            "incomplete Codex feature diagnostics; use --agent claude",
        ));
    }
    let remaining = effective
        .into_iter()
        .filter(|(name, enabled)| *enabled && agentic_feature(name))
        .map(|(name, _)| name)
        .collect();
    Ok(CodexIsolation {
        disabled,
        remaining,
    })
}
#[derive(Clone)]
pub(super) struct Runner {
    pub(super) executable: PathBuf,
    pub(super) agent: Agent,
    pub(super) cache: PathBuf,
    pub(super) jobs: usize,
    pub(super) codex: Option<CodexIsolation>,
}
impl Runner {
    fn note_cache_path(&self, hash: &str) -> std::path::PathBuf {
        let mut fingerprint = json!({"version":"v3-note-json-isolated-1","brief":spec::BRIEF_A,"schema":spec::SCHEMA_A,"agent":self.agent,"content_sha256":hash});
        if let Some(codex) = &self.codex {
            fingerprint["codex_isolation"] = json!(codex);
        }
        self.cache.join(format!(
            "note-{:x}.json",
            Sha256::digest(fingerprint.to_string().as_bytes())
        ))
    }
    pub(super) fn cached_note(&self, key: &str, hash: &str) -> Option<Value> {
        let mut row: Value =
            serde_json::from_slice(&std::fs::read(self.note_cache_path(hash)).ok()?).ok()?;
        row.as_object_mut()?.insert("id".into(), json!(key));
        let schema: Value = serde_json::from_str(spec::SCHEMA_A).expect("embedded schema");
        let validator = jsonschema::validator_for(&schema["properties"]["notes"]["items"])
            .expect("item schema");
        (validator.is_valid(&row) && Pass::A.admissible(&row)).then_some(row)
    }
    fn cache_note(&self, hash: &str, row: &Value) -> Result<()> {
        let mut row = row.clone();
        row.as_object_mut().expect("validated note").remove("id");
        write_json(&self.note_cache_path(hash), &row)
    }

    pub(super) async fn run(&self, batches: Vec<Batch>) -> Vec<Answer> {
        // Preserve batch order for deterministic key/pair mapping despite concurrency.
        let mut answers: Vec<_> = stream::iter(
            batches
                .into_iter()
                .enumerate()
                .map(|(i, batch)| async move { (i, self.batch(batch).await) }),
        )
        .buffer_unordered(self.jobs)
        .collect()
        .await;
        answers.sort_by_key(|(i, _)| *i);
        answers.into_iter().map(|(_, answer)| answer).collect()
    }
    async fn batch(&self, batch: Batch) -> Answer {
        let mut fingerprint = json!({"version":"v3-json-isolated-1","pass":batch.pass,"brief":batch.pass.brief(),"schema":batch.pass.schema(),"agent":self.agent,"prompt":batch.prompt,"files":batch.signatures});
        if let Some(codex) = &self.codex {
            fingerprint["codex_isolation"] = json!(codex);
        }
        let hash = format!("{:x}", Sha256::digest(fingerprint.to_string().as_bytes()));
        let path = self.cache.join(format!("{hash}.json"));
        let schema: Value = serde_json::from_str(batch.pass.schema()).expect("embedded schema");
        let validator =
            jsonschema::validator_for(&schema["properties"][batch.pass.field()]["items"])
                .expect("embedded item schema");
        let valid = |key: &str, row: &Value| {
            batch.expected.contains(key)
                && batch.pass.row_key(row).as_deref() == Some(key)
                && validator.is_valid(row)
                && batch.pass.admissible(row)
        };
        let mut rows = if batch.pass == Pass::A {
            BTreeMap::new()
        } else {
            std::fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Cached>(&bytes).ok())
                .unwrap_or_default()
                .rows
        };
        rows.retain(|key, row| valid(key, row));
        let mut usage = Usage::default();
        if !rows.is_empty() {
            usage.cached_calls = 1;
        }
        for _ in 0..2 {
            if rows.len() == batch.expected.len() {
                break;
            }
            usage.calls += 1;
            usage.input_chars += batch.prompt.chars().count();
            match self.invoke(&batch).await {
                Ok((output, cost)) => {
                    if let Some(cost) = cost {
                        *usage.cost_usd.get_or_insert(0.0) += cost;
                    }
                    if let Some(items) = output[batch.pass.field()].as_array() {
                        let mut duplicates = BTreeSet::new();
                        let mut seen = BTreeSet::new();
                        for row in items {
                            if let Some(key) = batch.pass.row_key(row) {
                                if !seen.insert(key.clone()) {
                                    duplicates.insert(key);
                                }
                            }
                        }
                        for row in items {
                            if let Some(key) = batch.pass.row_key(row) {
                                if !duplicates.contains(&key) && valid(&key, row) {
                                    rows.entry(key).or_insert_with(|| row.clone());
                                }
                            }
                        }
                    }
                    if batch.pass == Pass::A {
                        for (key, row) in &rows {
                            if let Some((_, hash)) =
                                batch.signatures.iter().find(|(id, _)| id == key)
                            {
                                if let Err(error) = self.cache_note(hash, row) {
                                    eprintln!("native enrich: cache unavailable; retaining result in memory: {error}");
                                }
                            }
                        }
                    } else if let Err(error) = write_json(&path, &Cached { rows: rows.clone() }) {
                        eprintln!(
                            "native enrich: cache unavailable; retaining result in memory: {error}"
                        );
                    }
                }
                Err(error) => eprintln!("native enrich: batch attempt failed: {error}"),
            }
        }
        let missing = batch
            .expected
            .difference(&rows.keys().cloned().collect())
            .cloned()
            .collect();
        Answer {
            rows,
            missing,
            usage,
        }
    }
    async fn invoke(&self, batch: &Batch) -> Result<(Value, Option<f64>)> {
        let cwd = tempfile::tempdir()?;
        let control = tempfile::tempdir()?;
        let mut command = tokio::process::Command::new(&self.executable);
        command
            .current_dir(cwd.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if self.agent.cli == "claude" {
            command.arg("-p");
            if let Some(model) = &self.agent.model {
                command.args(["--model", model]);
            }
            command.args([
                "--tools",
                "",
                "--strict-mcp-config",
                "--disable-slash-commands",
                "--no-session-persistence",
                "--setting-sources",
                "",
                "--output-format",
                "json",
                "--json-schema",
                batch.pass.schema(),
            ]);
            command.env("ENABLE_CLAUDEAI_MCP_SERVERS", "false");
        } else {
            let mut schema: Value = serde_json::from_str(batch.pass.schema())?;
            strict_schema(&mut schema);
            let schema_path = control.path().join("schema.json");
            std::fs::write(&schema_path, serde_json::to_vec(&schema)?)?;
            command.args([
                "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "-s",
                "read-only",
                "--ignore-user-config",
                "--ignore-rules",
            ]);
            let isolation = self
                .codex
                .as_ref()
                .ok_or_else(|| Error::engine("Codex isolation diagnostics are missing"))?;
            codex_overrides(&mut command, &isolation.disabled);
            if let Some(model) = &self.agent.model {
                command.args(["-m", model]);
            }
            command
                .arg("--output-schema")
                .arg(&schema_path)
                .arg("-o")
                .arg(control.path().join("answer.json"))
                .arg("-");
        }
        let execution = async {
            let mut child = command.spawn()?;
            let mut stdin = child.stdin.take().expect("piped stdin");
            stdin.write_all(batch.prompt.as_bytes()).await?;
            drop(stdin);
            let output = child.wait_with_output().await?;
            if !output.status.success() {
                return Err(Error::engine(format!(
                    "{} exited {}; {}",
                    self.agent.cli,
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                        .chars()
                        .take(400)
                        .collect::<String>()
                )));
            }
            if self.agent.cli == "claude" {
                let envelope: Value = serde_json::from_slice(&output.stdout)?;
                if envelope["is_error"] == true {
                    return Err(Error::engine("Claude reported an error"));
                }
                let result = if envelope["structured_output"].is_object() {
                    envelope["structured_output"].clone()
                } else {
                    serde_json::from_str(envelope["result"].as_str().ok_or_else(|| {
                        Error::engine("Claude returned no structured_output or result")
                    })?)?
                };
                Ok((result, envelope["total_cost_usd"].as_f64()))
            } else {
                Ok((
                    serde_json::from_slice(&std::fs::read(control.path().join("answer.json"))?)?,
                    None,
                ))
            }
        };
        tokio::time::timeout(Duration::from_secs(900), execution)
            .await
            .map_err(|_| Error::engine("agent call timed out after 900 seconds"))?
    }
}
fn strict_schema(schema: &mut Value) {
    if schema["type"] == "object" {
        schema["additionalProperties"] = json!(false);
        if let Some(properties) = schema["properties"].as_object_mut() {
            let required: Vec<_> = properties.keys().cloned().collect();
            for child in properties.values_mut() {
                strict_schema(child);
            }
            schema["required"] = json!(required);
        }
    }
    if let Some(items) = schema.get_mut("items") {
        strict_schema(items);
    }
}
pub(super) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(file.as_file_mut(), value)?;
    file.persist(path)
        .map_err(|error| Error::engine(format!("cannot write {}: {error}", path.display())))?;
    Ok(())
}

/// Probe the nearest existing ancestor without creating output directories.
fn probe_directory(path: &Path) -> Result<()> {
    let mut ancestor = std::path::absolute(path)?;
    loop {
        match std::fs::metadata(&ancestor) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(Error::engine(format!(
                        "{} is not a directory",
                        ancestor.display()
                    )));
                }
                tempfile::NamedTempFile::new_in(&ancestor)?.close()?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !ancestor.pop() {
                    return Err(error.into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}
/// Fail before consent/provider use, leaving no sidecar/cache directories.
pub(super) fn preflight(out: &Path, cache: &Path) -> Result<()> {
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if out.exists() {
        if !out.is_file() {
            return Err(Error::engine("sidecar path is not a regular file"));
        }
        std::fs::OpenOptions::new().write(true).open(out)?;
    }
    probe_directory(parent)?;
    probe_directory(cache)?;
    Ok(())
}
pub(super) fn prepare_output(out: &Path, cache: &Path) -> Result<()> {
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    builder.create(cache)?;
    Ok(())
}
