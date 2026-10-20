//! `cargo run --release --features v2-kernel-probe --example v2-import -- ...`
use native_ce::v1_import::{run, Options};
use std::path::PathBuf;
#[tokio::main]
async fn main() {
    if execute().await.is_err() {
        // Do not print engine errors: validators can quote private source values.
        eprintln!("Import refused; inspect the JSON report if produced. Check paths, source schema, target identity and --resume.");
        std::process::exit(1);
    }
}
async fn execute() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut source = None;
    let mut target = None;
    let mut report = None;
    let mut sanitized_report = None;
    let mut seeds = Vec::new();
    let mut resume = false;
    let mut all = false;
    let mut history = false;
    let mut capture_only = false;
    let mut members_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source" => source = args.next().map(PathBuf::from),
            "--target" => target = args.next().map(PathBuf::from),
            "--report" => report = args.next().map(PathBuf::from),
            "--sanitized-report" => sanitized_report = args.next().map(PathBuf::from),
            "--seed" => seeds.push(args.next().ok_or("missing seed")?),
            "--seed-file" => seeds.extend(
                std::fs::read_to_string(args.next().ok_or("missing seed file")?)?
                    .lines()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| s.trim().to_string()),
            ),
            "--resume" => resume = true,
            "--all" => all = true,
            "--history" => history = true,
            "--capture-only" => capture_only = true,
            "--members-file" => {
                members_file = Some(PathBuf::from(args.next().ok_or("missing members file")?))
            }
            _ => return Err("unknown argument".into()),
        }
    }
    let report = report.ok_or("--report required")?;
    let source = source.ok_or("--source required")?;
    let target = target.ok_or("--target required")?;
    // Reserve a new report before importing. Exclusive creation prevents symlink,
    // hard-link and lexical path aliases from truncating either database.
    let mut report_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&report)?;
    let mut sanitized_file = sanitized_report
        .map(|path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
        })
        .transpose()?;
    if seeds.is_empty() && !all {
        return Err("at least one seed or --all required".into());
    }
    if capture_only && !(all && history && resume) {
        return Err("--capture-only requires --all --history --resume".into());
    }
    let initial_source_digest = if all && history && !capture_only {
        Some(native_ce::v1_import::cutover::snapshot_digest(&source).await?)
    } else {
        None
    };
    let receipt_source = source.clone();
    let receipt_target = target.clone();
    let outcome = run(Options {
        source,
        target,
        seeds,
        all,
        history,
        resume,
        members_file,
    })
    .await;
    use std::io::Write;
    let result = match outcome {
        Ok(result) => result,
        Err(_) => {
            report_file.write_all(br#"{"refusals":[{"reason":"import aborted during source/target validation or kernel admission; target may be partial; resume only with the same source"}]}"#)?;
            return Err("import aborted".into());
        }
    };
    let value = if capture_only {
        native_ce::v1_import::cutover::capture_report(
            &result,
            &receipt_source,
            all,
            history,
            resume,
        )
        .await?
    } else if let Some(digest) = initial_source_digest {
        match native_ce::v1_import::cutover::attach_receipt(
            &result,
            &receipt_source,
            &receipt_target,
            &digest,
            all,
            history,
            resume,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                let reason = if error.to_string().contains("source changed during import") {
                    "source changed during import"
                } else {
                    "cutover receipt verification failed"
                };
                let mut failed = serde_json::to_value(&result)?;
                failed["capture_complete"] = serde_json::json!(false);
                failed["failure"] =
                    serde_json::json!({"reason": reason, "target_may_be_partial": true});
                report_file.write_all(&serde_json::to_vec_pretty(&failed)?)?;
                report_file.sync_all()?;
                write_sanitized(&mut sanitized_file, &failed)?;
                return Err(reason.into());
            }
        }
    } else {
        serde_json::to_value(&result)?
    };
    report_file.write_all(&serde_json::to_vec_pretty(&value)?)?;
    write_sanitized(&mut sanitized_file, &value)?;
    if let Some(change) = &result.roster_change {
        eprintln!("Import refused: members roster differs from frozen target; added account ids: {}; removed account ids: {}",
            serde_json::to_string(&change.added)?, serde_json::to_string(&change.removed)?);
    }

    println!(
        "{}",
        serde_json::json!({"history":result.history,"created":result.created,"unchanged":result.unchanged,"verified":result.verified,"refusals":result.refusals.len(),"review":result.review.len()})
    );
    if !result.refusals.is_empty()
        || !result.review.is_empty()
        || !result.app_state.capture_complete
    {
        return Err("review required".into());
    }
    Ok(())
}

fn write_sanitized(
    file: &mut Option<std::fs::File>,
    report: &serde_json::Value,
) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(file) = file {
        file.write_all(&serde_json::to_vec_pretty(
            &native_ce::v1_import::refusal_breakdown::sanitized_report(report),
        )?)?;
        file.sync_all()?;
    }
    Ok(())
}
