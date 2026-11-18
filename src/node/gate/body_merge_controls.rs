//! Owner-local recovery controls and crash-resumable account-boundary erasure.
use super::*;
use crate::node::unmerged::RecoveryState;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

const FORGET: &str = "body-merge-forget.json";
const ACCOUNT: &str = "body-merge-account.json";
const MAX_CONTROL_BYTES: u64 = 64 * 1024;

pub(in crate::node) fn is_tool(name: &str) -> bool {
    matches!(
        name,
        "node_unmerged"
            | "node_unmerged_dismiss"
            | "node_lineage_retire"
            | "node_body_merge_forget"
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ForgetMarker {
    version: u32,
    reason: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccountBinding {
    version: u32,
    account: Value,
}

fn bad(message: &str) -> Error {
    Error::engine(message)
}
fn arguments(message: &Value) -> Result<serde_json::Map<String, Value>> {
    match message.pointer("/params/arguments") {
        None => Ok(serde_json::Map::new()),
        Some(Value::Object(args)) => Ok(args.clone()),
        _ => Err(bad("arguments must be an object")),
    }
}
fn allowed(args: &serde_json::Map<String, Value>, names: &[&str]) -> Result<()> {
    if args.keys().any(|key| !names.contains(&key.as_str())) {
        return Err(bad("unknown local body-merge argument"));
    }
    Ok(())
}
fn optional_string<'a>(
    args: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<&'a str>> {
    match args.get(name) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        _ => Err(bad(&format!("{name} must be a non-empty string"))),
    }
}
fn required_string<'a>(args: &'a serde_json::Map<String, Value>, name: &str) -> Result<&'a str> {
    optional_string(args, name)?.ok_or_else(|| bad(&format!("{name} is required")))
}
fn optional_bool(args: &serde_json::Map<String, Value>, name: &str) -> Result<bool> {
    match args.get(name) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(bad(&format!("{name} must be boolean"))),
    }
}
fn read_private(path: &Path) -> Result<Option<Vec<u8>>> {
    validate_credential_path(path, "body merge control file")?;
    let input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = input.metadata()?;
    check_owned(&meta, 0o600)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_CONTROL_BYTES {
        return Err(bad("invalid body merge control file"));
    }
    let mut bytes = Vec::new();
    input.take(MAX_CONTROL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err(bad("body merge control file exceeds bound"));
    }
    Ok(Some(bytes))
}
fn atomic_private(path: &Path, value: &impl Serialize) -> Result<()> {
    validate_credential_path(path, "body merge control file")?;
    let directory = path
        .parent()
        .ok_or_else(|| bad("control file has no parent"))?;
    check_owned(&fs::symlink_metadata(directory)?, 0o700)?;
    // A damaged existing control file is never overwritten silently.
    let _ = read_private(path)?;
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() as u64 > MAX_CONTROL_BYTES {
        return Err(bad("body merge control file exceeds bound"));
    }
    let temporary = directory.join(format!("body-merge-control-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
fn remove_private(path: &Path) -> Result<()> {
    validate_credential_path(path, "body merge control file")?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            check_owned(&meta, 0o600)?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(bad("invalid body merge control file"));
            }
            fs::remove_file(path)?;
            File::open(
                path.parent()
                    .ok_or_else(|| bad("control file has no parent"))?,
            )?
            .sync_all()?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

impl WriteGate {
    /// Presence is conservative, including an unreadable/forged marker.
    pub(super) fn body_merge_forget_pending(&self) -> bool {
        !matches!(fs::symlink_metadata(self.socket_directory.join(FORGET)),
            Err(error) if error.kind() == io::ErrorKind::NotFound)
    }

    /// Caller serializes with merge admission. Account identity comes from
    /// node configuration, never from an MCP argument.
    pub(super) fn ensure_account_binding(&self) -> Result<()> {
        if self.body_merge_forget_pending() {
            return Err(bad(
                "body merge account erasure is pending; finish it before using drafts or recovery",
            ));
        }
        let Some(account) = &self.config.account_binding else {
            return Ok(());
        };
        if !account
            .get("account_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.trim().is_empty())
        {
            return Err(bad("body merge requires a verified account_id; sign in before saving drafts or reading recovery"));
        }
        let path = self.socket_directory.join(ACCOUNT);
        match read_private(&path)? {
            Some(bytes) => {
                let binding: AccountBinding = serde_json::from_slice(&bytes)?;
                if binding.version != 2 || binding.account != *account {
                    return Err(bad("body merge data belongs to another account; explicitly confirm node_body_merge_forget for account_switch before continuing"));
                }
            }
            None => atomic_private(
                &path,
                &AccountBinding {
                    version: 2,
                    account: account.clone(),
                },
            )?,
        }
        Ok(())
    }

    /// Startup calls this before any draft can be admitted or forwarded.
    /// A durable marker is prior explicit consent, not a new confirmation.
    pub(super) fn resume_body_merge_forget(&self) -> Result<()> {
        let path = self.socket_directory.join(FORGET);
        let Some(bytes) = read_private(&path)? else {
            return Ok(());
        };
        let marker: ForgetMarker = serde_json::from_slice(&bytes)?;
        if marker.version != 2 || !matches!(marker.reason.as_str(), "sign_out" | "account_switch") {
            return Err(bad("invalid body merge account-erasure marker"));
        }
        self.journal.forget_merges()?;
        self.lineages.clear()?;
        self.unmerged.wipe()?;
        let legacy = self.socket_directory.join("body-merge-recovery");
        validate_credential_path(&legacy, "legacy body merge recovery directory")?;
        match fs::symlink_metadata(&legacy) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(bad("invalid legacy recovery directory"));
                }
                check_owned(&meta, 0o700)?;
                let mut paths = Vec::new();
                for entry in fs::read_dir(&legacy)? {
                    let path = entry?.path();
                    let meta = fs::symlink_metadata(&path)?;
                    check_owned(&meta, 0o600)?;
                    if !meta.is_file() || meta.nlink() != 1 {
                        return Err(bad("invalid legacy recovery file"));
                    }
                    paths.push(path);
                }
                for path in paths {
                    fs::remove_file(path)?;
                }
                File::open(&legacy)?.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        remove_private(&self.socket_directory.join(ACCOUNT))?;
        // This is the commit point: any earlier failure leaves the marker.
        remove_private(&path)?;
        Ok(())
    }

    pub(in crate::node) async fn body_merge_control(&self, message: &Value) -> Option<String> {
        let name = message.pointer("/params/name").and_then(Value::as_str)?;
        if !is_tool(name) {
            return None;
        }
        let parsed = arguments(message);
        let answer = if name == "node_unmerged" {
            let _drain = self.drain_lock.read().await;
            let _admission = self.merge_admission.lock().expect("merge admission");
            parsed.and_then(|args| self.read_unmerged_control(&args))
        } else {
            let _drain = self.drain_lock.write().await;
            let _admission = self.merge_admission.lock().expect("merge admission");
            parsed.and_then(|args| self.mutate_merge_control(name, &args))
        };
        let (body, is_error) = match answer {
            Ok(body) => (body, false),
            Err(error) => (json!({"error":error.to_string(),"local":true}), true),
        };
        crate::node::tool_reply(
            message.get("id"),
            json!({"content":[{"type":"text","text":body.to_string()}],"structuredContent":body,"isError":is_error}),
            crate::mcp::is_modern_request(message),
        )
    }

    fn read_unmerged_control(&self, args: &serde_json::Map<String, Value>) -> Result<Value> {
        allowed(
            args,
            &[
                "id",
                "record_id",
                "editor",
                "state",
                "include_text",
                "limit",
            ],
        )?;
        let id = optional_string(args, "id")?;
        let record = optional_string(args, "record_id")?;
        let editor = optional_string(args, "editor")?;
        let state = match optional_string(args, "state")?.unwrap_or("open") {
            "open" => Some(RecoveryState::Open),
            "dismissed" => Some(RecoveryState::Dismissed),
            "all" => None,
            _ => return Err(bad("state must be open, dismissed, or all")),
        };
        let text = optional_bool(args, "include_text")?;
        let limit = match args.get("limit") {
            None => 100,
            Some(value) => value
                .as_u64()
                .filter(|n| (1..=100).contains(n))
                .ok_or_else(|| bad("limit must be an integer from 1 to 100"))?
                as usize,
        };
        self.ensure_account_binding()?;
        self.unmerged.prune()?;
        let mut items = self.unmerged.list(record, state, text)?;
        items.retain(|item| {
            id.is_none_or(|id| item.id == id) && editor.is_none_or(|editor| item.editor == editor)
        });
        let total = items.len();
        items.truncate(limit);
        Ok(json!({"items":items,"total":total,"truncated":total > limit,"local":true}))
    }

    fn mutate_merge_control(
        &self,
        name: &str,
        args: &serde_json::Map<String, Value>,
    ) -> Result<Value> {
        match name {
            "node_unmerged_dismiss" => {
                allowed(args, &["id"])?;
                let id = required_string(args, "id")?;
                self.ensure_account_binding()?;
                let item = self.unmerged.dismiss(id)?;
                Ok(
                    json!({"id":item.id,"state":item.state,"dismissed_at":item.dismissed_at,"local":true}),
                )
            }
            "node_lineage_retire" => {
                allowed(args, &["editor", "record_id"])?;
                let editor = required_string(args, "editor")?;
                let record = optional_string(args, "record_id")?;
                self.ensure_account_binding()?;
                let mut records = self
                    .lineages
                    .list()?
                    .into_iter()
                    .filter(|lineage| {
                        lineage.editor == editor && record.is_none_or(|r| lineage.record_id == r)
                    })
                    .map(|lineage| lineage.record_id)
                    .collect::<std::collections::BTreeSet<_>>();
                // A first accepted save has custody before send-time lineage
                // preparation. It still belongs to the editor being retired.
                // Seed only the oldest queued base per missing record; later
                // queued bases must not reset an already established lineage.
                let mut pending = self.journal.merge_entries();
                pending.sort_by_key(|entry| entry.seq);
                let open = self.unmerged.open_ids()?.into_iter().collect();
                for entry in pending.iter().filter(|entry| entry.merge_open()) {
                    let Some(intent) = &entry.merge_intent else {
                        continue;
                    };
                    let Some(queued_record) = entry.record_id.as_deref() else {
                        continue;
                    };
                    if intent.editor != editor
                        || !record.is_none_or(|r| queued_record == r)
                        || !records.insert(queued_record.to_owned())
                    {
                        continue;
                    }
                    if self.lineages.load(queued_record, editor)?.is_none() {
                        let version = crate::mcp::tools::merge_body::parse_base_version(
                            &intent.declared_base_version,
                        )
                        .ok_or_else(|| bad("invalid queued declared base version"))?
                            as u64;
                        self.lineages.prepare(
                            queued_record,
                            editor,
                            &entry.id,
                            crate::node::lineage::CommittedBody {
                                version,
                                text: intent.declared_base_text.clone(),
                            },
                            &intent.draft_text,
                            &open,
                        )?;
                    }
                }
                for record in &records {
                    self.lineages.retire(record, editor)?;
                    self.lineages.drain_retired(
                        record,
                        editor,
                        self.journal.has_open_merge(record, editor),
                    )?;
                }
                Ok(json!({"editor":editor,"retired":records.len(),"local":true}))
            }
            "node_body_merge_forget" => {
                allowed(args, &["confirm", "reason"])?;
                let confirm = optional_bool(args, "confirm")?;
                let reason = optional_string(args, "reason")?.unwrap_or("sign_out");
                if !matches!(reason, "sign_out" | "account_switch") {
                    return Err(bad("reason must be sign_out or account_switch"));
                }
                if !confirm {
                    let counts = self.unmerged.counts()?;
                    let lineages = self.lineages.list()?.len();
                    let status = self.journal.status_for(&StatusFilter::default());
                    return Ok(
                        json!({"requires_confirmation":true,"warning":"This permanently deletes all local body-merge drafts, lineage, recovery texts, saved-key history and dismissal history. It cannot undo writes already committed at home.","reason":reason,"recovery_counts":counts,"lineages":lineages,"pending_merges":status["merge_body_nonterminal_count"],"forget_pending":self.body_merge_forget_pending(),"local":true}),
                    );
                }
                if !self.body_merge_forget_pending() {
                    atomic_private(
                        &self.socket_directory.join(FORGET),
                        &ForgetMarker {
                            version: 2,
                            reason: reason.into(),
                        },
                    )?;
                }
                self.resume_body_merge_forget()?;
                Ok(json!({"forgotten":true,"reason":reason,"local":true}))
            }
            _ => Err(bad("unknown local body merge control")),
        }
    }
}

#[cfg(test)]
mod tests;
