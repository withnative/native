//! Wizard subprocesses use child-only fake CLIs and a PTY for scripted prompts.
use super::Fixture;
use serde_json::{json, Value};
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

const PTY: &str = r#"
import os,pty,subprocess,sys
master,slave=pty.openpty()
p=subprocess.Popen(sys.argv[2:],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
os.close(slave)
os.write(master,sys.argv[1].encode())
a,b=p.communicate(timeout=90)
os.close(master)
sys.stdout.buffer.write(a);sys.stderr.buffer.write(b);sys.exit(p.returncode)
"#;
struct Wizard {
    f: Fixture,
}
impl Wizard {
    fn new() -> Self {
        let f = Fixture::new();
        let fake=super::FAKE.replace("assert not list(Path.cwd().iterdir()), 'agent cwd must be empty'",r#"
if args and args[0]=='mcp':
    with open(os.environ['FAKE_LOG']+'.connect','a') as f: f.write(json.dumps(args)+'\n')
    state=Path(os.environ['FAKE_LOG']+'.'+Path(sys.argv[0]).name)
    if args[1]=='get':
        if not state.exists(): print('No MCP server named native-local');sys.exit(1)
        cmd=json.loads(state.read_text())
        if Path(sys.argv[0]).name=='codex': print(json.dumps({'name':'native-local','transport':{'type':'stdio','command':cmd[0],'args':cmd[1:]}}))
        else: print('Scope: User config\nType: stdio\nCommand: '+cmd[0]+'\nArgs: '+' '.join(cmd[1:]))
    elif args[1]=='add': state.write_text(json.dumps(args[args.index('--')+1:]))
    sys.exit(0)
assert not list(Path.cwd().iterdir()), 'agent cwd must be empty'
"#).replace("'type':'Resolution' if n['path'].startswith('Decision') else 'Document'", "'type':'WorkItem' if n['path'].startswith('Task') else ('Resolution' if n['path'].startswith('Decision') else 'Document')")
        .replace("'kind':'decision' if n['path'].startswith('Decision') else 'note'", "'kind':'task' if n['path'].startswith('Task') else ('decision' if n['path'].startswith('Decision') else 'note')")
        .replace("'lifecycle':None", "'lifecycle':'in_progress' if n['path'].startswith('Task') else None")
        .replace("'date':None", "'date':'2026-10-22'")
        .replace("answer={field:rows}", "if field=='notes' and os.environ.get('FAKE_CHANGE_NOTE'): Path(os.environ['FAKE_CHANGE_NOTE']).write_text('Changed during enrichment')\nanswer={field:rows}");
        for cli in ["claude", "codex"] {
            let path = f.bin.join(cli);
            std::fs::write(&path, &fake).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { f }
    }
    fn db(&self) -> std::path::PathBuf {
        self.f.temp.path().join("local.db")
    }
    fn sidecar_path(&self) -> std::path::PathBuf {
        self.f.root.join(".native/enrichment.json")
    }
    fn sidecar(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.sidecar_path()).unwrap()).unwrap()
    }
    fn command(&self, replies: Option<&str>) -> Command {
        let mut command = if let Some(replies) = replies {
            let mut c = Command::new("/usr/bin/python3");
            c.args(["-c", PTY, replies, env!("CARGO_BIN_EXE_native")]);
            c
        } else {
            Command::new(env!("CARGO_BIN_EXE_native"))
        };
        command
            .arg("init")
            .args(["--db", self.db().to_str().unwrap(), "--json"])
            .env("PATH", &self.f.bin)
            .env("HOME", self.f.temp.path())
            .env("FAKE_LOG", &self.f.log)
            .env(
                "FAKE_FEATURE_LOG",
                self.f.log.with_extension("features.jsonl"),
            )
            .stdin(std::process::Stdio::null());
        command
    }
    fn run(&self, args: &[&str], replies: Option<&str>) -> Value {
        let output = self
            .command(replies)
            .args(args)
            .arg(&self.f.root)
            .output()
            .unwrap();
        parse(&output)
    }
    fn ids(&self) -> Vec<String> {
        self.run(&["--yes", "--review-supersession"], None)["supersession"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_owned())
            .collect()
    }
    fn seed(&self) {
        self.f.write("Task.md", "Ship the feature [[Decision v1]]");
        self.f
            .write("Decision v1.md", "Old approach [[Decision v2]]");
        self.f.write("Decision v2.md", "Replaces [[Decision v1]]");
    }
    fn two_candidates(&self) {
        self.f.write("A.md", "Old");
        self.f.write("B.md", "New");
        self.f.write("C.md", "Other");
        let types = [
            ("A.md", "Document", "note", None),
            ("B.md", "Document", "note", None),
            ("C.md", "Document", "note", None),
        ];
        let mut value = serde_json::to_value(super::sidecar(&self.f, &types)).unwrap();
        value["supersession_candidates"] = json!([
            {"pair":[self.f.key("A.md"),self.f.key("B.md")],"newer":self.f.key("B.md"),"older":self.f.key("A.md"),"explicit":true,"confidence":"high","evidence":"B replaces A","score":5},
            {"pair":[self.f.key("A.md"),self.f.key("C.md")],"newer":self.f.key("C.md"),"older":self.f.key("A.md"),"explicit":false,"confidence":"medium","evidence":"C may replace A","score":2}
        ]);
        std::fs::create_dir_all(self.sidecar_path().parent().unwrap()).unwrap();
        std::fs::write(self.sidecar_path(), serde_json::to_vec(&value).unwrap()).unwrap();
        self.run(&["--yes", "--no-enrich", "--no-connect"], None);
    }
}
fn parse(output: &Output) -> Value {
    Fixture::assert_ok(output);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "strict JSON: {e}; {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    assert!(value.is_object());
    value
}
#[test]
fn init_requires_yes_without_tty_and_help_is_stdout() {
    let w = Wizard::new();
    w.f.write("One.md", "One");
    let output = w.command(None).arg(&w.f.root).output().unwrap();
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(error["error"].as_str().unwrap().contains("--yes"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--yes"));
    assert!(!w.db().exists());
    assert!(w.f.calls().is_empty());
    let output = w.command(None).arg("--help").output().unwrap();
    Fixture::assert_ok(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("usage: native init"));
}
#[test]
fn init_vault_discovery_args_cwd_and_obsidian_selection() {
    let explicit = Wizard::new();
    explicit.f.write("One.md", "One");
    let out = explicit.run(&["--yes", "--no-enrich", "--no-connect"], None);
    assert_eq!(out["discovery"]["notes"], 1);
    let cwd = Wizard::new();
    cwd.f.write("nested/One.md", "One");
    let out = cwd
        .command(Some("y\n"))
        .current_dir(&cwd.f.root)
        .args(["--no-enrich", "--no-connect"])
        .output()
        .unwrap();
    assert_eq!(parse(&out)["discovery"]["notes"], 1);
    let obsidian = Wizard::new();
    obsidian.f.write("One.md", "One");
    let config = if cfg!(target_os = "macos") {
        obsidian
            .f
            .temp
            .path()
            .join("Library/Application Support/obsidian/obsidian.json")
    } else {
        obsidian
            .f
            .temp
            .path()
            .join(".config/obsidian/obsidian.json")
    };
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        config,
        serde_json::to_vec(&json!({"vaults":{"one":{"path":obsidian.f.root}}})).unwrap(),
    )
    .unwrap();
    let empty = obsidian.f.temp.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = obsidian
        .command(Some("1\n"))
        .current_dir(empty)
        .args(["--no-enrich", "--no-connect"])
        .output()
        .unwrap();
    assert_eq!(parse(&out)["discovery"]["notes"], 1);
}
#[test]
fn init_refuses_overlapping_roots_before_agent_or_database_writes() {
    let w = Wizard::new();
    w.f.write("sub/One.md", "One");
    let out = w
        .command(None)
        .args(["--yes"])
        .arg(&w.f.root)
        .arg(w.f.root.join("sub"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("overlapping"));
    assert!(!w.db().exists());
    assert!(w.f.calls().is_empty());
}
#[test]
fn init_decline_enrichment_and_missing_agent_both_import_plain_notes() {
    let w = Wizard::new();
    w.f.write("One.md", "One");
    let value = w.run(&["--no-connect"], Some("n\n"));
    assert_eq!(value["enrich"]["status"], "declined");
    assert_eq!(value["import"]["notes"]["created"], 1);
    assert!(w.f.calls().is_empty());
    assert!(!w.sidecar_path().exists());
    let missing = Wizard::new();
    missing.f.write("One.md", "One");
    std::fs::remove_file(missing.f.bin.join("claude")).unwrap();
    let value = missing.run(&["--yes", "--no-connect"], None);
    assert_eq!(value["enrich"]["status"], "agent_missing");
    assert_eq!(value["import"]["notes"]["created"], 1);
    assert!(missing.f.calls().is_empty()); // never implicitly chooses the fake Codex
}
#[test]
fn init_full_flow_fake_agents_json_payoff_cache_and_idempotent_rerun() {
    for cli in ["claude", "codex"] {
        let w = Wizard::new();
        w.seed();
        let value = w.run(&["--yes", "--agent", cli], None);
        assert_eq!(value["enrich"]["status"], "completed");
        assert_eq!(value["enrich"]["estimate"]["agent"]["cli"], cli);
        assert_eq!(value["import"]["notes"]["created"], 3);
        assert_eq!(value["payoff"]["tasks"]["count"], 1);
        assert_eq!(value["payoff"]["tasks"]["items"][0]["title"], "Task");
        assert_eq!(value["payoff"]["decisions"]["count"], 2);
        assert_eq!(value["payoff"]["confirmed_supersessions"], 0);
        assert!(value["supersession"]["pending"].as_u64().unwrap() > 0);
        assert!(value["supersession"]["decisions"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(!w.f.root.join("AGENTS.md").exists());
        assert!(!w.f.root.join("CLAUDE.md").exists());
        let clients = value["connect"]["registration"]["clients"]
            .as_object()
            .unwrap();
        assert!(clients.values().all(|c| c["status"] == "registered"));
        let calls = w.f.calls().len();
        let rerun = w.run(&["--yes", "--agent", cli], None);
        assert_eq!(rerun["import"]["notes"]["created"], 0);
        assert_eq!(rerun["import"]["notes"]["updated"], 0);
        assert_eq!(rerun["import"]["notes"]["unchanged"], 3);
        assert_eq!(w.f.calls().len(), calls);
        assert_eq!(rerun["enrich"]["usage"]["cached_notes"], 3);
    }
}
#[test]
fn init_interactive_supersession_accepts_explicit_rejects_other_and_never_reasks() {
    let w = Wizard::new();
    w.two_candidates();
    let value = w.run(&["--review-supersession"], Some("reject-rest\n"));
    assert_eq!(
        value["supersession"]["decisions"].as_array().unwrap().len(),
        2
    );
    assert_eq!(value["payoff"]["confirmed_supersessions"], 1);
    let saved = w.sidecar();
    let decisions = saved["supersession_decisions"].as_object().unwrap();
    assert_eq!(decisions.len(), 2);
    assert!(decisions
        .values()
        .all(|d| d["decided_at"].as_str().is_some()));
    assert_eq!(
        decisions
            .values()
            .filter(|d| d["decision"] == "accepted")
            .count(),
        1
    );
    let again = w.run(&["--review-supersession"], Some("unused\n"));
    assert!(again["supersession"]["candidates"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(again["payoff"]["confirmed_supersessions"], 1);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let db=sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(w.db()).read_only(true)).await.unwrap();
        let (source,target):(String,String)=sqlx::query_as("SELECT s.name,t.name FROM links l JOIN records s ON s.id=l.source_id JOIN records t ON t.id=l.target_id WHERE l.relationship='supersedes'").fetch_one(&db).await.unwrap();
        assert_eq!((source,target),("B".into(),"A".into()));db.close().await;
    });
}
#[test]
fn init_noninteractive_accept_reject_are_explicit_and_validate_all_ids_first() {
    let w = Wizard::new();
    w.two_candidates();
    let ids = w.ids();
    let out = w
        .command(None)
        .args([
            "--yes",
            "--review-supersession",
            "--accept",
            &ids[0],
            "--reject",
            "unknown",
        ])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(w.sidecar().get("supersession_decisions").is_none());
    let value = w.run(
        &[
            "--yes",
            "--review-supersession",
            "--accept",
            &ids[0],
            "--reject",
            &ids[1],
        ],
        None,
    );
    assert_eq!(value["payoff"]["confirmed_supersessions"], 1);
    assert_eq!(value["supersession"]["pending"], 0);
    assert_eq!(
        w.sidecar()["supersession_decisions"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}
#[test]
fn init_interactive_skip_leaves_candidates_and_pointer_consent_is_separate() {
    let w = Wizard::new();
    w.two_candidates();
    let value = w.run(&["--review-supersession"], Some("skip\n"));
    assert_eq!(value["supersession"]["pending"], 2);
    assert!(w.sidecar().get("supersession_decisions").is_none());
    let pointer = Wizard::new();
    pointer.f.write("One.md", "One");
    pointer.run(&["--no-enrich"], Some("n\n"));
    assert!(!pointer.f.root.join("AGENTS.md").exists());
    pointer.run(&["--no-enrich"], Some("y\n"));
    for file in ["AGENTS.md", "CLAUDE.md"] {
        assert!(std::fs::read_to_string(pointer.f.root.join(file))
            .unwrap()
            .contains("<!-- native:begin -->"));
    }
}
#[test]
fn init_changed_content_requires_review_again_and_unknown_direction_cannot_be_accepted() {
    let w = Wizard::new();
    w.two_candidates();
    let ids = w.ids().join(",");
    w.run(&["--yes", "--review-supersession", "--reject", &ids], None);
    w.f.write("A.md", "Changed");
    let stale = w.run(&["--yes", "--review-supersession"], None);
    assert_eq!(stale["supersession"]["pending"], 0);
    assert_eq!(
        stale["supersession"]["stale_enrichment"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let mut data = w.sidecar();
    data["notes"][w.f.key("A.md")]["content_sha256"] =
        json!(format!("{:x}", sha2::Sha256::digest(b"Changed")));
    data["supersession_candidates"][0]["newer"] = Value::Null;
    data["supersession_candidates"][0]["older"] = Value::Null;
    std::fs::write(w.sidecar_path(), serde_json::to_vec(&data).unwrap()).unwrap();
    let ids = w.ids();
    let output = w
        .command(None)
        .args(["--yes", "--review-supersession", "--accept", &ids[0]])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown direction"));
}

#[test]
fn init_decisions_survive_standalone_enrichment_and_cached_wizard_reruns() {
    let w = Wizard::new();
    w.seed();
    let first = w.run(&["--yes", "--no-connect"], None);
    assert!(first["supersession"]["pending"].as_u64().unwrap() > 0);
    let id = first["supersession"]["candidates"][0]["id"]
        .as_str()
        .unwrap();
    let reviewed = w.run(&["--yes", "--review-supersession", "--accept", id], None);
    assert_eq!(reviewed["payoff"]["confirmed_supersessions"], 1);
    let decisions = w.sidecar()["supersession_decisions"].clone();
    let calls = w.f.calls().len();
    let output =
        w.f.command()
            .env("PATH", &w.f.bin)
            .args(["enrich", "--yes", "--json", "--out"])
            .arg(w.sidecar_path())
            .arg(&w.f.root)
            .output()
            .unwrap();
    parse(&output);
    assert_eq!(w.sidecar()["supersession_decisions"], decisions);
    let rerun = w.run(&["--yes", "--no-connect"], None);
    assert!(rerun["supersession"]["candidates"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(rerun["import"]["notes"]["unchanged"], 3);
    assert_eq!(rerun["payoff"]["confirmed_supersessions"], 1);
    assert_eq!(w.sidecar()["supersession_decisions"], decisions);
    assert_eq!(w.f.calls().len(), calls);
}

#[test]
fn init_unreadable_previous_decisions_refuse_before_agent_calls() {
    for content in ["not JSON", "{}"] {
        let w = Wizard::new();
        w.f.write("One.md", "One");
        std::fs::create_dir_all(w.sidecar_path().parent().unwrap()).unwrap();
        let content = if content.starts_with('{') {
            serde_json::to_vec(
                &json!({"sources":[w.f.root.canonicalize().unwrap()], "supersession_decisions":[]}),
            )
            .unwrap()
        } else {
            content.as_bytes().to_vec()
        };
        std::fs::write(w.sidecar_path(), &content).unwrap();
        let out = w
            .command(None)
            .args(["--yes", "--no-connect"])
            .arg(&w.f.root)
            .output()
            .unwrap();
        assert!(!out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(report["error"].is_string());
        assert!(w.f.calls().is_empty());
        assert!(!w.db().exists());
        assert_eq!(std::fs::read(w.sidecar_path()).unwrap(), content);
    }
}

#[test]
fn init_review_uses_only_import_validated_keys_not_stale_legacy_aliases() {
    let w = Wizard::new();
    w.two_candidates();
    let mut data = w.sidecar();
    let alias = format!("{}::A.md", w.f.root.canonicalize().unwrap().display());
    data["notes"][&alias] = data["notes"][w.f.key("A.md")].clone();
    data["notes"][&alias]["content_sha256"] = json!("stale");
    data["supersession_candidates"][0]["older"] = json!(alias);
    std::fs::write(w.sidecar_path(), serde_json::to_vec(&data).unwrap()).unwrap();
    let report = w.run(&["--yes", "--review-supersession"], None);
    assert_eq!(report["supersession"]["pending"], 1);
    assert_eq!(report["supersession"]["candidates"][0]["newer_title"], "C");
    assert_eq!(report["payoff"]["confirmed_supersessions"], 0);
}

#[test]
fn init_interactive_full_flow_keeps_enrichment_review_and_pointer_choices_separate() {
    let w = Wizard::new();
    w.seed();
    let report = w.run(&[], Some("y\nskip\nn\n"));
    assert_eq!(report["enrich"]["status"], "completed");
    assert!(!w.f.calls().is_empty());
    assert_eq!(report["import"]["notes"]["created"], 3);
    assert!(report["supersession"]["pending"].as_u64().unwrap() > 0);
    assert_eq!(report["payoff"]["confirmed_supersessions"], 0);
    assert!(w.sidecar().get("supersession_decisions").is_none());
    assert_eq!(
        report["connect"]["registration"]["clients"]["claude"]["status"],
        "registered"
    );
    assert!(!w.f.root.join("AGENTS.md").exists());
    assert!(!w.f.root.join("CLAUDE.md").exists());
}

#[test]
fn init_reviews_current_files_after_enrichment_and_excludes_stale_candidates() {
    let w = Wizard::new();
    w.seed();
    let output = w
        .command(None)
        .env("FAKE_CHANGE_NOTE", w.f.root.join("Decision v1.md"))
        .args(["--yes", "--no-connect"])
        .arg(&w.f.root)
        .output()
        .unwrap();
    let report = parse(&output);
    assert_eq!(
        report["import"]["stale_enrichment"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        report["supersession"]["stale_enrichment"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(report["supersession"]["pending"], 0);
    assert_eq!(report["payoff"]["confirmed_supersessions"], 0);
}

#[test]
fn init_refuses_confirmation_if_a_note_changes_while_the_review_prompt_is_open() {
    use std::io::{BufRead, Read};
    struct ChangingInput {
        input: std::io::Cursor<Vec<u8>>,
        path: std::path::PathBuf,
    }
    impl Read for ChangingInput {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl BufRead for ChangingInput {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            self.input.fill_buf()
        }
        fn consume(&mut self, amount: usize) {
            self.input.consume(amount);
        }
        fn read_line(&mut self, line: &mut String) -> std::io::Result<usize> {
            std::fs::write(&self.path, "Changed while reviewing")?;
            self.input.read_line(line)
        }
    }
    let w = Wizard::new();
    w.two_candidates();
    let mut input = ChangingInput {
        input: std::io::Cursor::new(b"1\n".to_vec()),
        path: w.f.root.join("A.md"),
    };
    let mut human = Vec::new();
    let mut io = native_ce::native_cli::init::Interaction {
        interactive: true,
        input: &mut input,
        human: &mut human,
    };
    let options = native_ce::native_cli::init::Options::parse(&[
        "--review-supersession".into(),
        "--db".into(),
        w.db().to_str().unwrap().into(),
        w.f.root.to_str().unwrap().into(),
    ])
    .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let error = runtime
        .block_on(native_ce::native_cli::init::run(options, &mut io))
        .unwrap_err();
    assert!(error.to_string().contains("notes changed during review"));
    assert!(w.sidecar().get("supersession_decisions").is_none());
    runtime.block_on(async {
        let pool = sqlx::SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(w.db())
                .read_only(true),
        )
        .await
        .unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE relationship='supersedes'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
        pool.close().await;
    });
}

#[test]
fn init_candidate_ids_are_stable_across_decisions_and_changed_hashes_refuse_old_ids() {
    let w = Wizard::new();
    w.two_candidates();
    let old = w.ids();
    assert_eq!(old, w.ids());
    assert!(old.iter().all(|id| id.starts_with("s-") && id.len() == 18));
    w.run(
        &["--yes", "--review-supersession", "--reject", &old[0]],
        None,
    );
    assert_eq!(w.ids(), vec![old[1].clone()]);
    let refused = w
        .command(None)
        .args(["--yes", "--review-supersession", "--accept", &old[0]])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let report: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert!(report["error"].as_str().unwrap().contains("re-list"));
    assert_eq!(
        w.sidecar()["supersession_decisions"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    w.f.write("C.md", "Changed content");
    let mut sidecar = w.sidecar();
    sidecar["notes"][w.f.key("C.md")]["content_sha256"] =
        json!(format!("{:x}", sha2::Sha256::digest(b"Changed content")));
    std::fs::write(w.sidecar_path(), serde_json::to_vec(&sidecar).unwrap()).unwrap();
    assert_ne!(w.ids()[0], old[1]);
    let stale = w
        .command(None)
        .args(["--yes", "--review-supersession", "--accept", &old[1]])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("unknown or stale candidate id"));
    assert_eq!(
        w.sidecar()["supersession_decisions"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn init_enter_and_numeric_selection_leave_unchecked_candidates_undecided() {
    for reply in ["\n", "2\n"] {
        let w = Wizard::new();
        w.two_candidates();
        let report = w.run(&["--review-supersession"], Some(reply));
        assert_eq!(report["supersession"]["pending"], 1);
        let saved = w.sidecar();
        let decisions = saved["supersession_decisions"].as_object().unwrap();
        assert_eq!(decisions.len(), 1);
        assert!(decisions.values().all(|d| d["decision"] == "accepted"));
        let remaining = w.run(&["--review-supersession"], Some("reject 1\n"));
        assert_eq!(remaining["supersession"]["pending"], 0);
    }
}

#[test]
fn init_cwd_requires_confirmation_or_explicit_path_and_summary_precedes_consent() {
    let w = Wizard::new();
    w.f.write("One.md", "One");
    let refused = w
        .command(None)
        .current_dir(&w.f.root)
        .args(["--yes", "--no-connect"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("explicit vault path"));
    assert!(w.f.calls().is_empty());
    assert!(!w.db().exists());
    let declined = w
        .command(Some("n\n"))
        .current_dir(&w.f.root)
        .args(["--no-connect"])
        .output()
        .unwrap();
    assert!(!declined.status.success());
    assert!(!w.db().exists());
    let output = w
        .command(Some("y\nn\n"))
        .current_dir(&w.f.root)
        .args(["--no-connect"])
        .output()
        .unwrap();
    let report = parse(&output);
    assert_eq!(report["import"]["notes"]["created"], 1);
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains(&format!("Use {} (1 notes)? [y/N]", w.f.root.display())));
    let source = text
        .find(&format!("Source folder: {}", w.f.root.display()))
        .unwrap();
    assert!(source < text.find("Enrich these notes?").unwrap());
}

#[test]
fn init_obsidian_selection_precedes_cwd_and_bad_vault_numbers_reprompt() {
    let w = Wizard::new();
    w.f.write("Code.md", "Do not sweep this repository");
    let vault = w.f.temp.path().join("known-vault");
    std::fs::create_dir(&vault).unwrap();
    std::fs::write(vault.join("Note.md"), "Note").unwrap();
    let config = if cfg!(target_os = "macos") {
        w.f.temp
            .path()
            .join("Library/Application Support/obsidian/obsidian.json")
    } else {
        w.f.temp.path().join(".config/obsidian/obsidian.json")
    };
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        config,
        serde_json::to_vec(&json!({"vaults":{"known":{"path":vault}}})).unwrap(),
    )
    .unwrap();
    let output = w
        .command(Some("bad\n99\n1\n"))
        .current_dir(&w.f.root)
        .args(["--no-enrich", "--no-connect"])
        .output()
        .unwrap();
    let report = parse(&output);
    assert_eq!(report["sources"], json!([vault]));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("Invalid choice:")
            .count(),
        2
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(&format!("Use {} (", w.f.root.display()))
    );
}

#[test]
fn init_bad_confirmations_and_review_choices_reprompt_up_to_three_attempts() {
    let w = Wizard::new();
    w.f.write("One.md", "One");
    let output = w
        .command(Some("maybe\nn\n"))
        .args(["--no-connect"])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert_eq!(parse(&output)["enrich"]["status"], "declined");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("Enrich these notes?")
            .count(),
        2
    );
    assert!(w.f.calls().is_empty());
    let review = Wizard::new();
    review.two_candidates();
    let output = review
        .command(Some("oops\n99\n\n"))
        .arg("--review-supersession")
        .arg(&review.f.root)
        .output()
        .unwrap();
    let report = parse(&output);
    assert_eq!(
        report["supersession"]["decisions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("Supersession: Enter")
            .count(),
        3
    );
}

#[test]
fn init_prompt_failure_after_import_prints_one_partial_json_object_with_completed_steps() {
    let w = Wizard::new();
    w.f.write("One.md", "One");
    let output = w
        .command(Some("bad\nbad\nbad\n"))
        .arg("--no-enrich")
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.is_object());
    assert!(report["error"].as_str().unwrap().contains("3 attempts"));
    assert_eq!(report["import"]["status"], "completed");
    assert_eq!(report["import"]["notes"]["created"], 1);
    assert_eq!(
        report["connect"]["registration"]["clients"]["claude"]["status"],
        "registered"
    );
    assert!(!w.f.root.join("AGENTS.md").exists());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .matches("Invalid choice:")
            .count(),
        3
    );
    assert_eq!(
        w.run(&["--yes", "--no-enrich", "--no-connect"], None)["import"]["notes"]["unchanged"],
        1
    );
}

#[test]
fn init_refuses_existing_reverse_supersession_without_recording_a_decision() {
    let w = Wizard::new();
    w.two_candidates();
    let ids = w.ids();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        use native_ce::mcp::{register_builtin_tools, register_surface_tools, ToolRegistry};
        let db = native_ce::open_existing_database(w.db().to_str().unwrap())
            .await
            .unwrap();
        let caller = native_ce::native_cli::sqlite_owner_caller(
            native_ce::identity::resolve_stdio_account_identity(&db, None)
                .await
                .unwrap(),
        );
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        let a: String = sqlx::query_scalar("SELECT id FROM records WHERE name='A'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let b: String = sqlx::query_scalar("SELECT id FROM records WHERE name='B'")
            .fetch_one(db.pool())
            .await
            .unwrap();
        Box::pin(registry.call(
            db.clone(),
            caller,
            "manage_links",
            json!({"action":"add","source_id":a,"target_id":b,"relationship":"supersedes"}),
        ))
        .await
        .unwrap();
        db.close().await;
    });
    let output = w
        .command(None)
        .args(["--yes", "--review-supersession", "--accept", &ids[0]])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("reverse supersedes link already exists"));
    assert!(w.sidecar().get("supersession_decisions").is_none());
    assert_eq!(
        w.run(&["--yes", "--review-supersession"], None)["payoff"]["confirmed_supersessions"],
        1
    );
}

#[test]
fn init_yes_requires_an_explicit_path_even_for_one_known_obsidian_vault() {
    for count in [1, 2] {
        let w = Wizard::new();
        let mut vaults = serde_json::Map::new();
        let mut paths = Vec::new();
        for n in 0..count {
            let dir = w.f.temp.path().join(format!("known-{n}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("Note.md"), "Note").unwrap();
            vaults.insert(n.to_string(), json!({"path":dir}));
            paths.push(dir);
        }
        let config = if cfg!(target_os = "macos") {
            w.f.temp
                .path()
                .join("Library/Application Support/obsidian/obsidian.json")
        } else {
            w.f.temp.path().join(".config/obsidian/obsidian.json")
        };
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(
            config,
            serde_json::to_vec(&json!({"vaults":vaults})).unwrap(),
        )
        .unwrap();
        let output = w
            .command(None)
            .arg("--yes")
            .current_dir(&w.f.root)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let error = report["error"].as_str().unwrap();
        assert!(error.contains("explicit vault path"));
        for path in paths {
            assert!(error.contains(path.to_str().unwrap()));
        }
        assert!(!w.db().exists());
        assert!(w.f.calls().is_empty());
    }
}

#[test]
fn init_json_errors_before_import_are_exactly_one_object() {
    let w = Wizard::new();
    for args in [vec!["--unknown"], vec!["--yes"], vec![]] {
        let output = w
            .command(None)
            .args(args)
            .current_dir(&w.f.root)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report.is_object());
        assert!(report["error"].is_string());
        assert!(!w.db().exists());
        assert!(w.f.calls().is_empty());
    }
}

#[test]
fn init_picker_offers_cwd_after_obsidian_when_it_has_markdown() {
    let w = Wizard::new();
    w.f.write("Current.md", "Use this directory");
    let known = w.f.temp.path().join("known");
    std::fs::create_dir(&known).unwrap();
    std::fs::write(known.join("Known.md"), "Known vault").unwrap();
    let config = if cfg!(target_os = "macos") {
        w.f.temp
            .path()
            .join("Library/Application Support/obsidian/obsidian.json")
    } else {
        w.f.temp.path().join(".config/obsidian/obsidian.json")
    };
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        config,
        serde_json::to_vec(&json!({"vaults":{"one":{"path":known}}})).unwrap(),
    )
    .unwrap();
    let output = w
        .command(Some("2\n"))
        .args(["--no-enrich", "--no-connect"])
        .current_dir(&w.f.root)
        .output()
        .unwrap();
    let report = parse(&output);
    assert_eq!(report["sources"], json!([w.f.root.canonicalize().unwrap()]));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains(&format!("1. {}", known.display())));
    assert!(text.contains(&format!("2. {}", w.f.root.display())));
}

#[test]
fn init_accept_and_reject_ids_resolve_beyond_the_displayed_top_fifteen() {
    let w = Wizard::new();
    w.f.write("A.md", "Original");
    let mut paths = vec!["A.md".to_owned()];
    for n in 0..17 {
        let path = format!("N{n:02}.md");
        w.f.write(&path, "New note");
        paths.push(path);
    }
    let types: Vec<_> = paths
        .iter()
        .map(|p| (p.as_str(), "Document", "note", None))
        .collect();
    let mut data = serde_json::to_value(super::sidecar(&w.f, &types)).unwrap();
    data["supersession_candidates"]=json!((0..17).map(|n| {
        let newer=w.f.key(&format!("N{n:02}.md"));let older=w.f.key("A.md");
        json!({"pair":[newer,older],"newer":newer,"older":older,"explicit":false,"confidence":"low","evidence":"Replacement","score":1})
    }).collect::<Vec<_>>());
    std::fs::create_dir_all(w.sidecar_path().parent().unwrap()).unwrap();
    std::fs::write(w.sidecar_path(), serde_json::to_vec(&data).unwrap()).unwrap();
    w.run(&["--yes", "--no-enrich", "--no-connect"], None);
    let old = w.ids();
    assert_eq!(old.len(), 15);
    // Promote the other fifteen pairs. The first two ids are still current,
    // but now sit outside the display cap.
    for candidate in data["supersession_candidates"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .skip(2)
    {
        candidate["explicit"] = json!(true);
        candidate["confidence"] = json!("high");
    }
    std::fs::write(w.sidecar_path(), serde_json::to_vec(&data).unwrap()).unwrap();
    let current = w.ids();
    assert!(!current.contains(&old[0]));
    assert!(!current.contains(&old[1]));
    let report = w.run(
        &[
            "--yes",
            "--review-supersession",
            "--accept",
            &old[0],
            "--reject",
            &old[1],
        ],
        None,
    );
    assert_eq!(report["supersession"]["pending"], 15);
    assert_eq!(
        report["supersession"]["decisions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(report["payoff"]["confirmed_supersessions"], 1);
    let unknown = w
        .command(None)
        .args(["--yes", "--review-supersession", "--accept", &old[0]])
        .arg(&w.f.root)
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    let error: Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert!(error["error"]
        .as_str()
        .unwrap()
        .contains("unknown or stale"));
}

#[test]
fn init_passes_effective_claude_model_to_enrichment() {
    for model in ["sonnet", "opus"] {
        let w = Wizard::new();
        w.f.write("One.md", "One");
        let mut args = vec!["--yes", "--no-connect"];
        if model == "opus" {
            args.extend(["--model", model]);
        }
        let report = w.run(&args, None);
        assert_eq!(report["enrich"]["estimate"]["agent"]["model"], model);
        assert_eq!(w.sidecar()["agent"]["model"], model);
        assert!(!w.f.calls().is_empty());
        for call in w.f.calls() {
            assert!(call["args"]
                .as_array()
                .unwrap()
                .windows(2)
                .any(|pair| pair[0] == "--model" && pair[1] == model));
        }
    }
}
