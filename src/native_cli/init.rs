//! A local setup wizard. Import, enrichment and client registration own their work.
mod review;

use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::{connect, enrich, import};
use crate::{Error, Result};

pub const FIRST_PROMPT: &str = "Use Native to tell me what's live in my notes: current work, open decisions, and anything stale.";
pub fn usage() -> &'static str {
    "usage: native init [<vault>...] [--db <path>] [--agent claude|codex] [--model <m>] [--yes] [--no-enrich] [--no-connect] [--review-supersession] [--accept <id,id>] [--reject <id,id>] [--json]\n\nSet up a local Native workspace from Markdown vaults. Files stay unchanged,\nexcept optional AGENTS.md/CLAUDE.md pointers asked about separately.\nEnrichment sends note text to the selected provider; Claude with Sonnet is the default (--model overrides).\n--yes consents to enrichment and client registration; it never accepts\nsupersession or writes vault pointers. Without a TTY, --yes is required.\n--review-supersession reviews an existing import without enriching/importing\nor connecting. --accept/--reject select stable candidate ids from that review.\n--json prints exactly one JSON object; human text goes to stderr.\n"
}
#[derive(Default)]
pub struct Options {
    pub dirs: Vec<PathBuf>,
    pub db: Option<PathBuf>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub yes: bool,
    pub no_enrich: bool,
    pub no_connect: bool,
    pub review_supersession: bool,
    pub accept: Vec<String>,
    pub reject: Vec<String>,
    pub json: bool,
}
impl Options {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Self::default();
        let mut args = args.iter();
        let mut positional = false;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--" if !positional => positional = true,
                "--yes" if !positional => opts.yes = true,
                "--no-enrich" if !positional => opts.no_enrich = true,
                "--no-connect" if !positional => opts.no_connect = true,
                "--json" if !positional => opts.json = true,
                "--review-supersession" if !positional => opts.review_supersession = true,
                "--db" | "--agent" | "--model" | "--accept" | "--reject" if !positional => {
                    let value = args
                        .next()
                        .ok_or_else(|| Error::engine(format!("{arg} needs a value")))?;
                    match arg.as_str() {
                        "--db" => opts.db = Some(value.into()),
                        "--agent" => {
                            if !["claude", "codex"].contains(&value.as_str()) {
                                return Err(Error::engine("--agent must be claude or codex"));
                            }
                            opts.agent = Some(value.clone());
                        }
                        "--model" => opts.model = Some(value.clone()),
                        "--accept" => opts.accept = ids(value)?,
                        _ => opts.reject = ids(value)?,
                    }
                }
                flag if !positional && flag.starts_with('-') => {
                    return Err(Error::engine(format!("unknown option {flag}")))
                }
                _ => opts.dirs.push(arg.into()),
            }
        }
        if (!opts.accept.is_empty() || !opts.reject.is_empty()) && !opts.review_supersession {
            return Err(Error::engine(
                "--accept/--reject require --review-supersession",
            ));
        }
        if opts.accept.iter().any(|n| opts.reject.contains(n)) {
            return Err(Error::engine(
                "a candidate cannot be both accepted and rejected",
            ));
        }
        Ok(opts)
    }
}
fn ids(value: &str) -> Result<Vec<String>> {
    value.split(',').map(|id| {
        let id = id.trim();
        if id.is_empty() { Err(Error::engine("expected comma-separated candidate ids; re-list with --review-supersession --yes --json")) }
        else { Ok(id.to_owned()) }
    }).collect()
}
fn numbers(value: &str) -> Result<Vec<usize>> {
    value
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| {
                    Error::engine("expected comma-separated candidate numbers starting at 1")
                })
        })
        .collect()
}
/// Explicit I/O makes the same interactive flow testable with scripted input.
pub struct Interaction<'a> {
    pub interactive: bool,
    pub input: &'a mut dyn BufRead,
    pub human: &'a mut dyn Write,
}
impl Interaction<'_> {
    fn say(&mut self, text: &str) -> Result<()> {
        writeln!(self.human, "{text}")?;
        self.human.flush()?;
        Ok(())
    }
    fn reply(&mut self, prompt: &str) -> Result<String> {
        write!(self.human, "{prompt}")?;
        self.human.flush()?;
        let mut reply = String::new();
        if self.input.read_line(&mut reply)? == 0 {
            return Err(Error::engine(
                "input ended; no further choices were accepted",
            ));
        }
        Ok(reply.trim().to_owned())
    }
    fn choose<T>(&mut self, prompt: &str, mut parse: impl FnMut(&str) -> Result<T>) -> Result<T> {
        for _ in 0..3 {
            let reply = self.reply(prompt)?;
            match parse(&reply) {
                Ok(value) => return Ok(value),
                Err(error) => self.say(&format!("Invalid choice: {error}"))?,
            }
        }
        Err(Error::engine(
            "too many invalid answers (3 attempts); re-run to resume",
        ))
    }
    fn confirm(&mut self, prompt: &str) -> Result<bool> {
        self.choose(prompt, |reply| match reply.to_ascii_lowercase().as_str() {
            "y" | "yes" => Ok(true),
            "" | "n" | "no" => Ok(false),
            _ => Err(Error::engine("answer y or n")),
        })
    }
}
pub fn run_cli(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let mut report = json!({});
    let json_output = args.iter().any(|a| a == "--json");
    let result = (|| -> Result<()> {
        let opts = Options::parse(args)?;
        let json = opts.json;
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let mut human: Box<dyn Write> = if json {
            Box::new(std::io::stderr())
        } else {
            Box::new(std::io::stdout())
        };
        let mut io = Interaction {
            interactive: stdin.is_terminal() && !opts.yes,
            input: &mut input,
            human: &mut human,
        };
        tokio::runtime::Runtime::new()?.block_on(run_into(opts, &mut io, &mut report))
    })();
    if let Err(error) = &result {
        if report["import"]["status"] == "in_progress" {
            report["import"]["status"] = json!("failed");
        }
        eprintln!("native init: {error}");
        report["error"] = json!(error.to_string());
    }
    if result.is_ok() && report["connect"]["has_failures"] == true {
        report["error"] =
            json!("client registration or vault pointers need attention; inspect connect statuses");
    }
    let failed = result.is_err() || report["connect"]["has_failures"] == true;
    let partial = report["import"]
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|s| s != "skipped");
    if json_output {
        println!("{}", report);
    } else if failed && partial {
        println!(
            "Partial setup report:\n{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn obsidian_config() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support/obsidian/obsidian.json"))
    } else {
        Some(home.join(".config/obsidian/obsidian.json"))
    }
}
fn find_vaults(
    args: &[PathBuf],
    cwd: &Path,
    config: Option<&Path>,
    io: &mut Interaction<'_>,
) -> Result<Vec<PathBuf>> {
    if !args.is_empty() {
        return Ok(args.to_vec());
    }
    let data: Value = match config.filter(|p| p.is_file()) {
        Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
        None => Value::Null,
    };
    let mut vaults: Vec<PathBuf> = data["vaults"]
        .as_object()
        .into_iter()
        .flat_map(|v| v.values())
        .filter_map(|v| v["path"].as_str().map(PathBuf::from))
        .filter(|p| p.is_dir())
        .collect();
    vaults.sort();
    vaults.dedup();
    if !vaults.is_empty() {
        if !io.interactive {
            let found = vaults
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::engine(format!("Obsidian vaults found: {found}; --yes requires an explicit vault path: native init --yes <vault>")));
        }
        let cwd = std::fs::canonicalize(cwd)?;
        let cwd_has_notes = import::discover(std::slice::from_ref(&cwd))?
            .entries
            .iter()
            .any(|e| e.file.is_some());
        if cwd_has_notes
            && !vaults
                .iter()
                .any(|p| std::fs::canonicalize(p).is_ok_and(|p| p == cwd))
        {
            // Obsidian vaults retain their leading positions; cwd is an explicit choice.
            vaults.push(cwd);
        }
        for (n, path) in vaults.iter().enumerate() {
            io.say(&format!("{}. {}", n + 1, path.display()))?;
        }
        return io.choose("Choose vault number(s), comma-separated: ", |reply| {
            numbers(reply)?
                .into_iter()
                .map(|n| {
                    vaults
                        .get(n - 1)
                        .cloned()
                        .ok_or_else(|| Error::engine("vault number out of range"))
                })
                .collect()
        });
    }
    if !io.interactive {
        return Err(Error::engine("no Obsidian vault found; --yes requires an explicit vault path: native init --yes <vault>"));
    }
    let cwd = std::fs::canonicalize(cwd)?;
    let count = import::discover(std::slice::from_ref(&cwd))?
        .entries
        .iter()
        .filter(|e| e.file.is_some())
        .count();
    if count > 0 && io.confirm(&format!("Use {} ({count} notes)? [y/N] ", cwd.display()))? {
        return Ok(vec![cwd]);
    }
    Err(Error::engine(
        "no Markdown vault selected; pass its directory: native init --yes <vault>",
    ))
}
pub async fn run(opts: Options, io: &mut Interaction<'_>) -> Result<Value> {
    let mut report = json!({});
    run_into(opts, io, &mut report).await?;
    Ok(report)
}
async fn run_into(mut opts: Options, io: &mut Interaction<'_>, report: &mut Value) -> Result<()> {
    if !io.interactive && !opts.yes {
        return Err(Error::engine("native init requires --yes without an interactive TTY; this consents to provider enrichment unless --no-enrich is given"));
    }
    // --yes is deliberately non-interactive even for library callers.
    io.interactive &= !opts.yes;
    opts.dirs = find_vaults(
        &opts.dirs,
        &std::env::current_dir()?,
        obsidian_config().as_deref(),
        io,
    )?;
    let discovered = import::discover(&opts.dirs)?;
    let mut canonical = Vec::new();
    for dir in &opts.dirs {
        let dir = std::fs::canonicalize(dir)?;
        if dir.to_str().is_some_and(|s| discovered.roots.contains(s)) && !canonical.contains(&dir) {
            canonical.push(dir);
        }
    }
    opts.dirs = canonical;
    if opts.dirs.is_empty() {
        return Err(Error::engine("no readable source roots"));
    }
    let db = std::path::absolute(
        opts.db
            .as_deref()
            .unwrap_or(&super::default_local_db_path()),
    )?;
    let agents: Vec<_> = ["claude", "codex"]
        .into_iter()
        .filter(|a| connect::find_on_path(a).is_some())
        .collect();
    let notes = discovered
        .entries
        .iter()
        .filter(|e| e.file.is_some())
        .count();
    let folders = discovered.entries.iter().filter(|e| e.folder).count();
    io.say(&format!(
        "{notes} Markdown notes, {folders} folders. Database: {}. Agent CLIs found: {}.",
        db.display(),
        if agents.is_empty() {
            "none".into()
        } else {
            agents.join(", ")
        }
    ))?;
    if opts.review_supersession {
        io.say("Reviewing supersession candidates for this existing import. Accepted pairs add a supersedes link; Markdown files stay unchanged.")?;
    } else {
        io.say("Native will enrich (if you consent), import, and connect your vault. Markdown files are not modified, except optional AGENTS.md/CLAUDE.md pointers asked about separately.")?;
    }
    for root in &opts.dirs {
        io.say(&format!("Source folder: {}", root.display()))?;
    }
    let sidecar_path = opts.dirs[0].join(".native/enrichment.json");
    *report = json!({"sources":opts.dirs,"database":db,"discovery":{"notes":notes,"folders":folders,"agent_clis":agents},"enrich":{"status":"skipped"},"import":{"status":"skipped"},"connect":{"status":"skipped"}});
    if !opts.review_supersession {
        let cli = opts.agent.as_deref().unwrap_or("claude");
        if !opts.no_enrich && connect::find_on_path(cli).is_some() {
            let mut estimate = Value::Null;
            let enriched = enrich::for_wizard(
                opts.dirs.clone(),
                opts.agent.clone(),
                opts.model.clone(),
                &mut |value, summary| {
                    estimate = value.clone();
                    io.say(summary)?;
                    if opts.yes {
                        Ok(true)
                    } else {
                        io.confirm("Enrich these notes? [y/N] ")
                    }
                },
            )
            .await?;
            report["enrich"] = match enriched {
                Some(value) => {
                    json!({"status":"completed","estimate":estimate,"usage":value["usage"],"unenriched":value["unenriched"],"sidecar":sidecar_path})
                }
                None => json!({"status":"declined","estimate":estimate}),
            };
        } else if !opts.no_enrich {
            report["enrich"] = json!({"status":"agent_missing","agent":cli});
        }
        let enriched = report["enrich"]["status"] == "completed";
        if !enriched {
            io.say(
                "Continuing with plain import. Enrichment can be run later with native init again.",
            )?;
        }
        let options = import::Options {
            db: db.clone(),
            dry_run: false,
            dirs: opts.dirs.clone(),
        };
        report["import"] = json!({"status":"in_progress","writes_may_have_committed":true});
        let imported = if enriched {
            import::import_with_enrichment(&options, &sidecar_path).await?
        } else {
            import::import(&options).await?
        };
        report["import"] = serde_json::to_value(&imported)?;
        report["import"]["status"] = json!("completed");
        io.say(&imported.human())?;
    } else if !db.is_file() || !sidecar_path.is_file() {
        return Err(Error::engine("supersession review needs an existing import and <first vault>/.native/enrichment.json"));
    }
    if opts.review_supersession {
        report["import"] = json!({"status":"existing"});
    }
    // Enrichment and interactive consent can take minutes. Review the current
    // files, just as import does, rather than trusting the initial summary scan.
    let current = import::discover(&opts.dirs)?;
    review::run(
        &opts,
        &current,
        &db,
        &sidecar_path,
        io,
        &mut report["supersession"],
    )
    .await?;
    if !opts.no_connect && !opts.review_supersession {
        let deps = connect::Deps {
            current_exe: std::env::current_exe()?,
            run: &connect::run_command,
            find_on_path: &connect::find_on_path,
        };
        let mut options = connect::Options {
            db: Some(db.clone()),
            ..Default::default()
        };
        let registered = connect::run(&options, &deps).map_err(Error::engine)?;
        report["connect"] = json!({"registration":serde_json::from_str::<Value>(&connect::render_json(&registered))?,"pointers":[],"has_failures":connect::has_failures(&registered)});
        io.say(&connect::render_text(&registered))?;
        let mut failures = connect::has_failures(&registered);
        let mut pointers = Vec::new();
        for root in &opts.dirs {
            if io.interactive
                && io.confirm(&format!(
                    "Write a Native pointer to {}/AGENTS.md and CLAUDE.md? [y/N] ",
                    root.display()
                ))?
            {
                options.vault = Some(root.clone());
                options.clients.clear();
                let pointer = connect::run(&options, &deps).map_err(Error::engine)?;
                failures |= connect::has_failures(&pointer);
                io.say(&connect::render_text(&pointer))?;
                pointers.push(serde_json::from_str::<Value>(&connect::render_json(
                    &pointer,
                ))?);
                report["connect"]["pointers"] = json!(pointers);
                report["connect"]["has_failures"] = json!(failures);
            }
        }
        report["connect"] = json!({"registration":serde_json::from_str::<Value>(&connect::render_json(&registered))?,"pointers":pointers,"has_failures":failures});
    }
    report["payoff"] = review::payoff(&db, &discovered).await?;
    let payoff = &report["payoff"];
    io.say(&format!(
        "Open/in-progress tasks: {}. Decisions: {}. Confirmed supersessions: {}.",
        payoff["tasks"]["count"], payoff["decisions"]["count"], payoff["confirmed_supersessions"]
    ))?;
    for label in ["tasks", "decisions"] {
        for item in payoff[label]["items"].as_array().into_iter().flatten() {
            io.say(&format!("  {}", item["title"].as_str().unwrap_or("")))?;
        }
    }
    io.say(&format!(
        "Open Claude Code/Codex in your vault and paste:\n{FIRST_PROMPT}"
    ))?;
    report["suggested_prompt"] = json!(FIRST_PROMPT);
    Ok(())
}
