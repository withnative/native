//! Read-only inspection of the node's generated Markdown vault.
use std::path::PathBuf;
use std::process::ExitCode;

pub const HELP: &str = "usage: native vault check|status [--vault <directory>] [--json] [--all]\n\nExplain saved vault edits and the typed changes they would propose. Sends nothing,\nchanges no files, and never chmods a note. check and status are aliases.\n\n--vault <directory>  vault to inspect (default: current directory)\n--json               native.vault-check.v1 report, including unchanged files\n--all                include unchanged files in human output\n\nExit codes: 0 no invalid edits; 1 invalid edits or unsupported operations;\n2 inspection unavailable (bad arguments, unsafe paths, publication changed).\n\nGrammar v0: body text, name and summary scalars, and additions to existing\nrelationship properties. Facets, generated sections, deletes, renames and moves\nare read-only. New files are local-only; no create is inferred. A modified file\nfrom an older vault may lack a recoverable published base: keep the edit and\nuse Native MCP for the change. Local validity does not establish authorization\nor guarantee that the home will accept a future write.";

pub fn run_cli(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    let Some("check" | "status") = args.first().map(String::as_str) else {
        eprintln!("{HELP}");
        return ExitCode::from(2);
    };
    let mut root = None;
    let mut json = false;
    let mut all = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--all" => all = true,
            "--vault" if root.is_none() => {
                i += 1;
                let Some(value) = args.get(i).filter(|s| !s.starts_with('-')) else {
                    eprintln!("native vault: --vault needs a directory");
                    return ExitCode::from(2);
                };
                root = Some(PathBuf::from(value));
            }
            other => {
                eprintln!("native vault: unexpected argument {other:?}\n{HELP}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let root = match root {
        Some(root) => root,
        None => match std::env::current_dir() {
            Ok(root) => root,
            Err(err) => {
                eprintln!("native vault: {err}");
                return ExitCode::from(2);
            }
        },
    };
    match crate::markdown_vault::inspect::inspect(&root) {
        Ok(report) => {
            let code = report.exit_code();
            if json {
                println!(
                    "{}",
                    serde_json::to_string(&report).expect("serializable report")
                );
            } else {
                print!("{}", report.human(all));
            }
            ExitCode::from(code)
        }
        Err(err) => {
            // Paths and error strings may contain terminal controls.
            eprintln!(
                "native vault: {}",
                crate::markdown_vault::diag_field(&err, 500)
            );
            ExitCode::from(2)
        }
    }
}
