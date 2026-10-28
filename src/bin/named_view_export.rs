//! No-effect local copy exporter. No hosted connection or emission gate.
use std::{
    io::{Read, Write},
    path::Path,
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("named-view-export: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .ok_or("usage: named-view-export OFFLINE_COPY.db < selector.json > candidate.json")?;
    if args.next().is_some() {
        return Err("expected exactly one literal database filename".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        return Err("selector exceeds 16 KiB".into());
    }
    let request = serde_json::from_slice(&bytes)?;
    let candidate = native_ce::named_view_export::export_file(Path::new(&path), request).await?;
    let mut out = std::io::stdout().lock();
    out.write_all(&candidate)?;
    out.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
#[path = "named_view_export/tests.rs"]
mod tests;
