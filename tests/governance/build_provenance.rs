#![cfg(unix)]

//! The provenance stamp's contract (task 142e0d2, revised by task 1205e69):
//! resolved from the environment only, never from git.
//!
//! The first revision of `build.rs` interrogated git and watched HEAD and the
//! branch ref, so every commit changed the stamped value — and because
//! `src/lib.rs` consumes the stamp through `env!`, every commit invalidated
//! the entire root library with zero source change. These tests pin the
//! replacement contract, and in particular its load-bearing negative: builds
//! inside a git repository do NOT rerun the stamp when sources change or
//! commits land.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
}

struct Build {
    output: Output,
    revision: String,
}

impl Fixture {
    fn new(initialize_git: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();

        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"provenance-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n",
        )
        .unwrap();
        fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"{}\", env!(\"NATIVE_CE_GIT_SHA\")); }\n",
        )
        .unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("build.rs"),
            root.join("build.rs"),
        )
        .unwrap();
        fs::write(root.join(".gitignore"), "target/\n").unwrap();

        let fixture = Self {
            _directory: directory,
            root,
        };
        if initialize_git {
            fixture.git(&["init", "--initial-branch", "main"]);
            fixture.git(&["config", "user.email", "provenance@example.test"]);
            fixture.git(&["config", "user.name", "Provenance Test"]);
            fixture.git(&["add", "."]);
            fixture.git(&["commit", "-m", "fixture"]);
        }
        fixture
    }

    fn git(&self, args: &[&str]) -> Output {
        let output = git(&self.root, args);
        assert_success(&output);
        output
    }

    fn build(&self) -> Build {
        build(&self.root, &[])
    }

    fn build_with_env(&self, env: &[(&str, &str)]) -> Build {
        build(&self.root, env)
    }
}

fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}

fn build(root: &Path, env: &[(&str, &str)]) -> Build {
    let mut command = Command::new(option_env!("CARGO").unwrap_or("cargo"));
    command
        .args(["build", "--verbose"])
        .current_dir(root)
        // This is a nested fixture build. The parent test runner may isolate
        // its own artifacts with CARGO_TARGET_DIR, but inheriting that path
        // would put the fixture binary outside `root/target` below and make
        // independent test jobs interfere with one another.
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("NATIVE_CE_GIT_SHA")
        .env_remove("RAILWAY_GIT_COMMIT_SHA")
        // A rustc wrapper (sccache) can serve compiles from cache, which
        // changes which verbose lines appear. The fixture is tiny; compile it
        // plainly so the rerun detector below reads a stable signal.
        .env("RUSTC_WRAPPER", "")
        .env("CARGO_TERM_COLOR", "never")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert_success(&output);

    let binary = root.join("target/debug").join(format!(
        "provenance-fixture{}",
        std::env::consts::EXE_SUFFIX
    ));
    let revision_output = Command::new(binary).output().unwrap();
    assert_success(&revision_output);

    Build {
        output,
        revision: String::from_utf8(revision_output.stdout)
            .unwrap()
            .trim()
            .to_string(),
    }
}

/// Whether the build EXECUTED the provenance script — as opposed to merely
/// recompiling the crate. `cargo build --verbose` prints a
/// ``Running `…/build-script-build` `` line only when the script itself runs,
/// so this stays false on a rebuild caused by a source edit, which is exactly
/// the discrimination the no-rerun tests need. (The previous suite keyed on
/// cargo's `Dirty` lines, which a plain recompile also emits.)
fn build_script_reran(build: &Build) -> bool {
    String::from_utf8_lossy(&build.output.stderr)
        .lines()
        .any(|line| line.contains("build-script-build"))
}

fn append(path: &Path, text: &str) {
    let mut contents = fs::read_to_string(path).unwrap_or_default();
    contents.push_str(text);
    fs::write(path, contents).unwrap();
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The headline property, and the reason the contract changed: inside a git
/// repository, neither a source edit nor a commit reruns the stamp. The crate
/// itself recompiles when its source changes — that is cargo doing its job —
/// but the stamp stays put, so a commit alone invalidates nothing.
#[test]
fn source_edits_and_commits_do_not_rerun_the_stamp() {
    let fixture = Fixture::new(true);
    let first = fixture.build();
    assert!(
        build_script_reran(&first),
        "first build must run the script"
    );
    assert_eq!(first.revision, "dev");

    // A no-op rebuild stays a no-op.
    let unchanged = fixture.build();
    assert!(!build_script_reran(&unchanged));

    // Edit a real source file: the crate recompiles, the script does not run.
    append(&fixture.root.join("src/main.rs"), "// trailing comment\n");
    let edited = fixture.build();
    assert!(
        !build_script_reran(&edited),
        "a source edit reran the provenance script"
    );
    assert_eq!(edited.revision, "dev");

    // Commit it: HEAD and the branch ref move, and nothing rebuilds at all.
    fixture.git(&["add", "."]);
    fixture.git(&["commit", "-m", "absorb the edit"]);
    let committed = fixture.build();
    assert!(
        !build_script_reran(&committed),
        "a commit reran the provenance script — the env-only contract is broken"
    );
    assert_eq!(committed.revision, "dev");
}

/// Local builds stamp `"dev"` even when a repository (and therefore a real
/// revision) is right there to interrogate. That abstinence is the contract:
/// the repository, not the binary, is the authority on local provenance.
#[test]
fn a_git_repository_is_deliberately_ignored() {
    let fixture = Fixture::new(true);
    assert_eq!(fixture.build().revision, "dev");
}

/// A source tree with no git and no env still builds, and says what it is.
#[test]
fn a_bare_source_tree_stamps_dev() {
    let fixture = Fixture::new(false);
    assert_eq!(fixture.build().revision, "dev");
}

/// The deploy-path variables are honoured in order, trimmed, truncated to 12
/// characters when they look like a sha, and passed through intact otherwise.
#[test]
fn env_variables_stamp_in_resolution_order() {
    let fixture = Fixture::new(false);

    let explicit = fixture.build_with_env(&[(
        "NATIVE_CE_GIT_SHA",
        "0123456789abcdef0123456789abcdef01234567",
    )]);
    assert!(build_script_reran(&explicit));
    assert_eq!(explicit.revision, "0123456789ab");

    // NATIVE_CE_GIT_SHA wins over RAILWAY_GIT_COMMIT_SHA.
    let both = fixture.build_with_env(&[
        ("NATIVE_CE_GIT_SHA", "explicit-value"),
        (
            "RAILWAY_GIT_COMMIT_SHA",
            "fedcba9876543210fedcba9876543210fedcba98",
        ),
    ]);
    assert_eq!(both.revision, "explicit-value");

    let railway = fixture.build_with_env(&[(
        "RAILWAY_GIT_COMMIT_SHA",
        "fedcba9876543210fedcba9876543210fedcba98",
    )]);
    assert_eq!(railway.revision, "fedcba987654");

    // Whitespace-only means unset, exactly as it did before the revision.
    let blank = fixture.build_with_env(&[("NATIVE_CE_GIT_SHA", "   ")]);
    assert_eq!(blank.revision, "dev");
}
