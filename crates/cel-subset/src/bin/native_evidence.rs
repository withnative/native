//! Explicit native evidence tool. Output paths are caller-owned artifacts.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args
        .next()
        .ok_or("usage: cel-native-evidence MODE CANDIDATE COUNT OUTPUT")?;
    let candidate = args.next().ok_or("missing candidate")?;
    let candidate = if candidate == "p1" {
        usize::MAX
    } else {
        candidate.parse()?
    };
    let count = args.next().ok_or("missing count")?.parse()?;
    let output = args.next().ok_or("missing output")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let report = cel::native_evidence(&mode, candidate, count)?;
    std::fs::write(output, &report)?;
    let report: serde_json::Value = serde_json::from_str(&report)?;
    if let Some(counts) = report["counts"].as_object() {
        let n = |key| counts.get(key).and_then(|n| n.as_u64()).unwrap_or(0);
        if n("failures") != 0
            || n("canonical_missing") != 0
            || (mode == "generated"
                && count >= 10_000
                && (n("admitted_distinct") < 10_000 || n("exercised_distinct") < 10_000))
        {
            return Err(
                "public native proof gate failed; complete report retained at output".into(),
            );
        }
    }
    if mode == "regex"
        && report["cases"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|case| case["searches"].as_array().into_iter().flatten())
            .any(|search| search["ok_bool"] != true || search["within_bound"] != true)
    {
        return Err(
            "admitted public regex search failed; complete report retained at output".into(),
        );
    }
    Ok(())
}
