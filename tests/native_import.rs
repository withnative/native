use chrono::DateTime;
use native_ce::native_cli::import::{import, Options};
use serde_json::{Map, Value};
use sqlx::{sqlite::SqliteConnectOptions, Row, SqlitePool};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn text(path: &Path) -> Result<String, std::io::Error> {
    Ok(path.to_str().unwrap().to_owned())
}
struct Existing {
    id: String,
    name: String,
    body: String,
    facets: Map<String, Value>,
}
async fn bindings(
    pool: &SqlitePool,
    roots: &BTreeSet<String>,
) -> Result<BTreeMap<(String, String), Existing>, Box<dyn std::error::Error>> {
    let mut found = BTreeMap::new();
    for row in sqlx::query("SELECT r.id,r.name,r.body,s.value AS root,p.value AS path FROM records r JOIN facet_values s ON s.record_id=r.id AND s.key='source_root' JOIN facet_values p ON p.record_id=r.id AND p.key='source_path' WHERE r.deleted_at IS NULL").fetch_all(pool).await? {
        let root: String = row.try_get("root")?;
        if !roots.contains(&root) { continue; }
        let path: String = row.try_get("path")?;
        let id: String = row.try_get("id")?;
        let mut facets = Map::new();
        for facet in sqlx::query("SELECT key,value FROM facet_values WHERE record_id=?").bind(&id).fetch_all(pool).await? {
            facets.insert(facet.try_get("key")?,Value::String(facet.try_get("value")?));
        }
        found.insert((root,path), Existing { id, name:row.try_get("name")?, body:row.try_get::<Option<String>,_>("body")?.unwrap_or_default(), facets });
    }
    Ok(found)
}

fn write(root: &Path, path: &str, body: &str) {
    let file = root.join(path);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, body).unwrap();
}
async fn read_pool(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path).read_only(true))
        .await
        .unwrap()
}

#[tokio::test]
async fn vault_import_round_trip_and_dry_run() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let source = "---\ntitle: Source title\ntags: [one, 'two, three']\nauthors:\n  - Alice\n  - Bob\n---\n[[Target]] [[Target|alias]] [[Target#heading]] [[sub/Local.md]]\n[local](sub/Local.md) [[sub/sub]] [[Missing]] [[Twin]] [[Source]]\n";
    write(&root, "vault.md", "Root folder body\n");
    write(&root, "Source.md", source);
    write(&root, "Target.md", "Target body\n");
    write(
        &root,
        "sub/sub.md",
        "---\ntitle: Ignored folder title\n---\nFolder body [[Target]]\n",
    );
    write(&root, "sub/Local.md", "[up](../Target.md)\n");
    write(&root, "a/Twin.md", "First twin\n");
    write(&root, "b/Twin.md", "Second twin\n");
    let bad = "---\ntitle: [broken\n---\nKeep this whole file\n";
    write(&root, "bad.md", bad);
    write(&root, ".obsidian/ignored.md", "hidden");
    write(&root, ".hidden.md", "hidden");
    write(&root, "image.png", "image");
    write(&root, "stuff.txt", "text");
    write(&root, "LICENSE", "no extension");
    let db_path = temp.path().join("data/local.db");
    let mut options = Options {
        db: db_path.clone(),
        dry_run: true,
        dirs: vec![root.clone(), root.clone()],
    };
    let preview = import(&options).await.unwrap();
    assert!(!db_path.parent().unwrap().exists());
    assert_eq!(preview.folders.created, 4);
    assert_eq!(preview.notes.created, 6);
    assert_eq!(preview.links.created, 5);
    assert_eq!(preview.unresolved_links.len(), 1);
    assert_eq!(preview.unresolved_links[0].target, "Missing");
    assert_eq!(preview.ambiguous_links.len(), 1);
    assert_eq!(preview.ambiguous_links[0].target, "Twin");
    assert_eq!(preview.skipped_hidden_entries, 2);
    assert_eq!(
        preview.skipped_files,
        BTreeMap::from([("png".into(), 1), ("txt".into(), 1), ("(none)".into(), 1)])
    );
    assert_eq!(preview.not_faithfully_converted.len(), 1);

    options.dry_run = false;
    let first = import(&options).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(db_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(first.notes.created, 6);
    assert_eq!(first.links.created, 5);
    let roots = BTreeSet::from([text(&std::fs::canonicalize(&root).unwrap()).unwrap()]);
    let source_root = roots.first().unwrap();
    let pool = read_pool(&db_path).await;
    let before = bindings(&pool, &roots).await.unwrap();
    assert_eq!(before.len(), 10);
    let get = |path: &str| &before[&(source_root.clone(), path.to_owned())];
    let source_record = get("Source.md");
    assert_eq!(source_record.name, "Source title");
    assert_eq!(
        source_record.body,
        source
            .split_once("---\n[[")
            .map(|(_, tail)| format!("[[{tail}"))
            .unwrap()
    );
    assert_eq!(source_record.facets["fm.tags"], "one, two, three");
    assert_eq!(source_record.facets["fm.authors"], "Alice, Bob");
    DateTime::parse_from_rfc3339(source_record.facets["file_modified_at"].as_str().unwrap())
        .unwrap();
    assert_eq!(get("sub/").name, "sub");
    assert_eq!(get("sub/").body, "Folder body [[Target]]\n");
    assert_eq!(get(".").body, "Root folder body\n");
    assert_eq!(get("bad.md").body, bad);
    let home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
        .bind(&get("sub/Local.md").id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(home, get("sub/").id);
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;

    // Existing-database preview leaves bytes and history alone.
    let bytes = std::fs::read(&db_path).unwrap();
    options.dry_run = true;
    let preview = import(&options).await.unwrap();
    assert_eq!(preview.notes.unchanged, 6);
    assert_eq!(preview.links.unchanged, 5);
    assert_eq!(std::fs::read(&db_path).unwrap(), bytes);
    options.dry_run = false;
    let second = import(&options).await.unwrap();
    assert_eq!(second.notes.created + second.notes.updated, 0);
    assert_eq!(second.folders.created + second.folders.updated, 0);
    assert_eq!(second.links.created, 0);
    let pool = read_pool(&db_path).await;
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(events_before, events_after);
    pool.close().await;

    write(
        &root,
        "Source.md",
        "---\ntitle: Changed title\n---\nChanged body [[Target]]\n",
    );
    let third = import(&options).await.unwrap();
    assert_eq!(third.notes.created, 0);
    assert_eq!(third.notes.updated, 1);
    assert_eq!(third.notes.unchanged, 5);
    assert_eq!(third.folders.updated, 0);
    let pool = read_pool(&db_path).await;
    let after = bindings(&pool, &roots).await.unwrap();
    let changed = &after[&(source_root.clone(), "Source.md".into())];
    assert_eq!(changed.id, source_record.id);
    assert_eq!(changed.name, "Changed title");
    assert_eq!(changed.body, "Changed body [[Target]]\n");
    assert!(!changed.facets.contains_key("fm.tags"));
    assert!(!changed.facets.contains_key("fm.authors"));
    pool.close().await;

    std::fs::remove_file(root.join("Target.md")).unwrap();
    std::fs::remove_file(root.join("sub/sub.md")).unwrap();
    let removed = import(&options).await.unwrap();
    assert!(removed
        .disappeared
        .contains(&format!("{source_root}/Target.md")));
    assert!(removed
        .disappeared
        .contains(&format!("{source_root}/sub/sub.md")));
    let pool = read_pool(&db_path).await;
    let retained = bindings(&pool, &roots).await.unwrap();
    assert_eq!(retained.len(), 10);
    assert_eq!(
        retained[&(source_root.clone(), "sub/".into())].body,
        "Folder body [[Target]]\n"
    );
    pool.close().await;
}

#[test]
fn command_help_and_json_preview() {
    let binary = env!("CARGO_BIN_EXE_native");
    let help = std::process::Command::new(binary)
        .args(["import", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(help.stderr.is_empty());
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("usage: native import"));
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root,"a.md","---\r\ntitle: \"A: title\"\r\ntags: [a, \"b, c\"]\r\npeople:\r\n- 'O''Brien'\r\n---\r\nBody\r\n");
    for (i, bad) in [
        "---\nkey: |\n  body\n---\n",
        "---\nkey: {nested: value}\n---\n",
        "---\ntitle: hi\n",
        "---\nx: a\nx: b\n---\n",
        "---\nx:\n  nested: y\n---\n",
    ]
    .iter()
    .enumerate()
    {
        write(&root, &format!("bad{i}.md"), bad);
    }
    let path = temp.path().join("absent/local.db");
    let output = std::process::Command::new(binary)
        .args(["import", "--json", "--dry-run", "--db"])
        .arg(&path)
        .arg(&root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["notes"]["created"], 6);
    assert_eq!(
        report["not_faithfully_converted"].as_array().unwrap().len(),
        5
    );
    assert!(!path.parent().unwrap().exists());
}

#[tokio::test]
async fn multiple_roots_resolve_unique_stems_and_skip_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    write(&first, "A.md", "[[B]] [B](../second/B.md)\n");
    write(&second, "B.md", "[[A|alias]]\n");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&first, first.join("loop")).unwrap();
        std::os::unix::fs::symlink(second.join("B.md"), first.join("outside.md")).unwrap();
    }
    let options = Options {
        db: temp.path().join("absent.db"),
        dry_run: true,
        dirs: vec![first, second],
    };
    let report = import(&options).await.unwrap();
    assert_eq!(report.notes.created, 2);
    assert_eq!(report.folders.created, 2);
    assert_eq!(report.links.created, 2);
    assert_eq!(report.unresolved_links.len(), 0);
    #[cfg(unix)]
    assert_eq!(report.skipped_symlinks, 2);
    assert!(!options.db.exists());
}

#[tokio::test]
async fn overlapping_roots_are_refused_in_either_order_before_writing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root, "sub/note.md", "body");
    for dirs in [
        vec![root.clone(), root.join("sub")],
        vec![root.join("sub/.."), root.join("sub")],
        vec![root.join("sub"), root.clone()],
    ] {
        let options = Options {
            db: temp.path().join("absent/local.db"),
            dry_run: false,
            dirs,
        };
        let error = import(&options).await.unwrap_err().to_string();
        assert!(error.contains("overlapping source roots"), "{error}");
        assert!(!options.db.parent().unwrap().exists());
    }
}

#[tokio::test]
async fn plain_frontmatter_allows_internal_yaml_indicators() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root,"a.md","---\ntitle: Don't panic\nquestion: Q&A\ntags: c#\nother: a\"b&c*d!e|f>g[h]i{j}\nlist: [Don't panic, Q&A, c#]\n---\nBody");
    write(&root, "b.md", "---\ntitle: Q&A\n---\nBody");
    let options = Options {
        db: temp.path().join("local.db"),
        dry_run: false,
        dirs: vec![root.clone()],
    };
    let report = import(&options).await.unwrap();
    assert!(report.not_faithfully_converted.is_empty());
    let pool = read_pool(&options.db).await;
    let roots = BTreeSet::from([text(&std::fs::canonicalize(root).unwrap()).unwrap()]);
    let records = bindings(&pool, &roots).await.unwrap();
    let source = roots.first().unwrap();
    let note = &records[&(source.clone(), "a.md".into())];
    assert_eq!(note.name, "Don't panic");
    assert_eq!(note.body, "Body");
    assert_eq!(note.facets["fm.question"], "Q&A");
    assert_eq!(note.facets["fm.tags"], "c#");
    assert_eq!(note.facets["fm.other"], "a\"b&c*d!e|f>g[h]i{j}");
    assert_eq!(note.facets["fm.list"], "Don't panic, Q&A, c#");
    assert_eq!(records[&(source.clone(), "b.md".into())].name, "Q&A");
    pool.close().await;
}

#[tokio::test]
async fn utf8_bom_is_removed_before_frontmatter_and_body_loading() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root, "a.md", "\u{feff}---\ntitle: BOM title\n---\nBody");
    write(&root, "b.md", "\u{feff}Plain body");
    let options = Options {
        db: temp.path().join("local.db"),
        dry_run: false,
        dirs: vec![root.clone()],
    };
    let report = import(&options).await.unwrap();
    assert!(report.not_faithfully_converted.is_empty());
    let pool = read_pool(&options.db).await;
    let roots = BTreeSet::from([text(&std::fs::canonicalize(root).unwrap()).unwrap()]);
    let records = bindings(&pool, &roots).await.unwrap();
    let source = roots.first().unwrap();
    assert_eq!(records[&(source.clone(), "a.md".into())].name, "BOM title");
    assert_eq!(records[&(source.clone(), "a.md".into())].body, "Body");
    assert_eq!(records[&(source.clone(), "b.md".into())].body, "Plain body");
    pool.close().await;
}

#[tokio::test]
async fn mtime_changes_do_not_write_but_content_changes_refresh_the_facet() {
    use std::time::{Duration, SystemTime};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root, "a.md", "---\ntitle: Original\n---\nBody");
    let options = Options {
        db: temp.path().join("local.db"),
        dry_run: false,
        dirs: vec![root.clone()],
    };
    import(&options).await.unwrap();
    let roots = BTreeSet::from([text(&std::fs::canonicalize(&root).unwrap()).unwrap()]);
    let pool = read_pool(&options.db).await;
    let before = bindings(&pool, &roots).await.unwrap();
    let history: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;
    let touch = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for path in [root.clone(), root.join("a.md")] {
        std::fs::File::open(path)
            .unwrap()
            .set_modified(touch)
            .unwrap();
    }
    let report = import(&options).await.unwrap();
    assert_eq!(report.notes.updated, 0);
    assert_eq!(report.folders.updated, 0);
    let pool = read_pool(&options.db).await;
    let after = bindings(&pool, &roots).await.unwrap();
    for (key, old) in &before {
        assert_eq!(
            old.facets["file_modified_at"],
            after[key].facets["file_modified_at"]
        );
    }
    assert_eq!(
        history,
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    pool.close().await;
    write(&root, "a.md", "---\ntitle: Changed\n---\nNew body");
    std::fs::File::open(root.join("a.md"))
        .unwrap()
        .set_modified(touch)
        .unwrap();
    let report = import(&options).await.unwrap();
    assert_eq!(report.notes.updated, 1);
    assert_eq!(report.folders.updated, 0);
    let pool = read_pool(&options.db).await;
    let after = bindings(&pool, &roots).await.unwrap();
    let key = (roots.first().unwrap().clone(), "a.md".into());
    assert_ne!(
        before[&key].facets["file_modified_at"],
        after[&key].facets["file_modified_at"]
    );
    pool.close().await;
}

#[tokio::test]
async fn non_utf8_contents_and_names_are_reported_and_skipped() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root, "good.md", "Good body");
    write(&root, "bad.md", "old body");
    let options = Options {
        db: temp.path().join("local.db"),
        dry_run: false,
        dirs: vec![root.clone()],
    };
    import(&options).await.unwrap();
    std::fs::write(root.join("bad.md"), [0xff, 0xfe]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let filename = std::ffi::OsString::from_vec(b"bad-\xff.md".to_vec());
        std::fs::write(root.join(filename), "bad filename").unwrap();
    }
    let report = import(&options).await.unwrap();
    assert!(report
        .unreadable_files
        .iter()
        .any(|s| s.ends_with("bad.md")));
    #[cfg(unix)]
    assert_eq!(report.unreadable_files.len(), 2);
    assert_eq!(report.notes.unchanged, 1);
    assert!(report.disappeared.is_empty());
    let roots = BTreeSet::from([text(&std::fs::canonicalize(root).unwrap()).unwrap()]);
    let pool = read_pool(&options.db).await;
    let records = bindings(&pool, &roots).await.unwrap();
    assert_eq!(
        records[&(roots.first().unwrap().clone(), "bad.md".into())].body,
        "old body"
    );
    pool.close().await;
}

#[tokio::test]
async fn links_fall_back_to_case_insensitive_paths_and_stems_and_skip_media_embeds() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(&root,"Source.md","[[folder/target.MD]] [target](FOLDER/TARGET.md) [[unique]] [[CASE]] [[exact]] [[Exact]] [[CASEONLY]] [[CaseOnly]] ![[photo.PNG|photo]] ![[guide.pdf#page=2]] ![[Unique.md]]");
    write(&root, "Folder/Target.md", "target");
    write(&root, "Other/Unique.md", "unique");
    write(&root, "one/Case.md", "one");
    write(&root, "two/case.md", "two");
    write(&root, "a/exact.md", "exact");
    write(&root, "b/Exact.md", "different case");
    write(&root, "CaseOnly.md", "first path case");
    write(&root, "caseonly.md", "second path case");
    let distinct_case_paths = std::fs::canonicalize(root.join("CaseOnly.md")).unwrap()
        != std::fs::canonicalize(root.join("caseonly.md")).unwrap();
    let report = import(&Options {
        db: temp.path().join("absent.db"),
        dry_run: true,
        dirs: vec![root],
    })
    .await
    .unwrap();
    assert_eq!(report.links.created, 5);
    assert_eq!(report.skipped_embeds, 2);
    assert!(report.unresolved_links.is_empty());
    assert_eq!(
        report.ambiguous_links.len(),
        if distinct_case_paths { 2 } else { 1 }
    );
    assert_eq!(report.ambiguous_links[0].target, "CASE");
    if distinct_case_paths {
        assert_eq!(report.ambiguous_links[1].target, "CASEONLY");
    }
    assert_eq!(report.ambiguous_links[0].source, "Source.md");
}

#[test]
fn human_output_limits_link_examples_and_keeps_source_paths_relative() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    let mut body = String::new();
    for i in 0..12 {
        body.push_str(&format!("[[missing{i}]] "));
    }
    body.push_str("[[Twin]]");
    write(&root, "Source.md", &body);
    write(&root, "a/Twin.md", "one");
    write(&root, "b/Twin.md", "two");
    let command = |json: bool| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_native"));
        command
            .args(["import", "--dry-run", "--db"])
            .arg(temp.path().join("absent.db"));
        if json {
            command.arg("--json");
        }
        command.arg(&root).output().unwrap()
    };
    let output = command(false);
    assert!(output.status.success());
    let human = String::from_utf8(output.stdout).unwrap();
    assert!(human.contains("Unresolved links: 12; ambiguous links: 1"));
    assert_eq!(
        human
            .lines()
            .filter(|s| s.starts_with("Unresolved:") || s.starts_with("Ambiguous:"))
            .count(),
        10
    );
    assert!(human.contains("… and 3 more (use --json for all)"));
    assert!(human.contains("Unresolved: Source.md -> missing0"));
    assert!(!human.contains(root.to_str().unwrap()));
    let output = command(true);
    assert!(output.status.success());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["unresolved_links"].as_array().unwrap().len(), 12);
    assert_eq!(json["ambiguous_links"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn dotted_note_embeds_resolve_before_media_classification() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(
        &root,
        "Source.md",
        "![[2024.01.15]] ![[v1.2|version]] ![[AMBIG.1]] ![[photo.png]] ![[guide.pdf]]",
    );
    write(&root, "2024.01.15.md", "date note");
    write(&root, "other/v1.2.md", "version note");
    write(&root, "a/ambig.1.md", "first");
    write(&root, "b/ambig.1.md", "second");
    let report = import(&Options {
        db: temp.path().join("absent.db"),
        dry_run: true,
        dirs: vec![root],
    })
    .await
    .unwrap();
    assert_eq!(report.links.created, 2);
    assert_eq!(report.skipped_embeds, 2);
    assert!(report.unresolved_links.is_empty());
    assert_eq!(report.ambiguous_links.len(), 1);
    assert_eq!(report.ambiguous_links[0].target, "AMBIG.1");
}

#[tokio::test]
async fn explicit_folder_paths_prefer_folded_paths_over_unrelated_exact_stems() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    write(
        &root,
        "Source.md",
        "[[notes/Foo]] [[notes/foo]] [[notes/Foo.md]] [[NOTES/FOO]]",
    );
    write(&root, "Bare.md", "[[Foo]]");
    write(&root, "notes/foo.md", "specified folder");
    write(&root, "other/Foo.md", "exact bare stem");
    let options = Options {
        db: temp.path().join("local.db"),
        dry_run: false,
        dirs: vec![root.clone()],
    };
    let report = import(&options).await.unwrap();
    // All four explicit paths choose notes/foo; the bare name chooses other/Foo.
    assert_eq!(report.links.created, 2);
    assert!(report.unresolved_links.is_empty());
    assert!(report.ambiguous_links.is_empty());
    let roots = BTreeSet::from([text(&std::fs::canonicalize(root).unwrap()).unwrap()]);
    let pool = read_pool(&options.db).await;
    let records = bindings(&pool, &roots).await.unwrap();
    let source = roots.first().unwrap();
    let source_id = &records[&(source.clone(), "Source.md".into())].id;
    let targets:Vec<String>=sqlx::query_scalar("SELECT target_id FROM links WHERE source_id=? AND relationship='relates_to' ORDER BY target_id").bind(source_id).fetch_all(&pool).await.unwrap();
    assert!(targets.contains(&records[&(source.clone(), "notes/foo.md".into())].id));
    assert_eq!(targets.len(), 1);
    let bare_target: String = sqlx::query_scalar(
        "SELECT target_id FROM links WHERE source_id=? AND relationship='relates_to'",
    )
    .bind(&records[&(source.clone(), "Bare.md".into())].id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        bare_target,
        records[&(source.clone(), "other/Foo.md".into())].id
    );
    pool.close().await;
}

#[tokio::test]
async fn empty_frontmatter_titles_fall_back_to_the_file_stem() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("vault");
    for (file, value) in [
        ("Empty.md", ""),
        ("Quoted.md", "\"\""),
        ("Whitespace.md", "\"   \""),
    ] {
        write(&root, file, &format!("---\ntitle: {value}\n---\nBody"));
    }
    let options = Options {
        db: temp.path().join("local.db"),
        dry_run: false,
        dirs: vec![root.clone()],
    };
    let report = import(&options).await.unwrap();
    assert_eq!(report.notes.created, 3);
    assert!(report.not_faithfully_converted.is_empty());
    let roots = BTreeSet::from([text(&std::fs::canonicalize(root).unwrap()).unwrap()]);
    let pool = read_pool(&options.db).await;
    let records = bindings(&pool, &roots).await.unwrap();
    for name in ["Empty", "Quoted", "Whitespace"] {
        let note = &records[&(roots.first().unwrap().clone(), format!("{name}.md"))];
        assert_eq!(note.name, name);
        assert_eq!(note.body, "Body");
        assert!(note.facets.contains_key("fm.title"));
    }
    pool.close().await;
}
