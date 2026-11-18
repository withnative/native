//! Per-phase wall time of one standby delta attempt.

/// Wall time of each sequential phase of one v2 delta attempt. Phases are
/// recorded as laps (time since the previous lap), so they sum to the attempt's
/// wall time and a failed attempt still reports the phases it reached.
/// Cloning shares the same record; the lock is never held across an await.
#[derive(Clone, Debug)]
pub(crate) struct PhaseTimings(std::sync::Arc<std::sync::Mutex<PhaseTimingsInner>>);

#[derive(Debug)]
struct PhaseTimingsInner {
    last: std::time::Instant,
    laps: Vec<(&'static str, u64)>,
    /// `(table, rows, micros)` for each projection table digested.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    tables: Vec<(String, u64, u64)>,
    /// What the set-digest path did on this attempt (`kernel-replay.json`).
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    set_path: Option<serde_json::Value>,
    /// When this attempt began its whole-database scan, and the ordinal of the
    /// receipt it wrote: the evidence a full-scan apply publishes as an audit
    /// record, once (and only once) its transaction has committed.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    full_scan: (Option<chrono::DateTime<chrono::Utc>>, Option<i64>),
}

impl Default for PhaseTimings {
    fn default() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(
            PhaseTimingsInner {
                last: std::time::Instant::now(),
                laps: Vec::new(),
                #[cfg(any(test, feature = "v2-kernel-probe"))]
                tables: Vec::new(),
                #[cfg(any(test, feature = "v2-kernel-probe"))]
                set_path: None,
                #[cfg(any(test, feature = "v2-kernel-probe"))]
                full_scan: (None, None),
            },
        )))
    }
}

impl PhaseTimings {
    /// Close the phase that has just finished, `name`, and start the next.
    pub(crate) fn lap(&self, name: &'static str) {
        let mut inner = self.0.lock().expect("phase timings lock");
        let now = std::time::Instant::now();
        let millis = now.duration_since(inner.last).as_millis() as u64;
        inner.last = now;
        inner.laps.push((name, millis));
    }

    /// Diagnostic: one projection table's digest cost.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn table(&self, name: &str, rows: u64, elapsed: std::time::Duration) {
        self.0.lock().expect("phase timings lock").tables.push((
            name.to_owned(),
            rows,
            elapsed.as_micros() as u64,
        ));
    }

    /// The whole-database scan begins now (its start is the conservative time
    /// at which the scanned state was current).
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn mark_full_scan(&self) {
        self.0.lock().expect("phase timings lock").full_scan.0 = Some(chrono::Utc::now());
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn note_receipt_ordinal(&self, ordinal: i64) {
        self.0.lock().expect("phase timings lock").full_scan.1 = Some(ordinal);
    }

    /// `(scan start, receipt ordinal)` when this attempt scanned the whole
    /// database and wrote a receipt.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn full_scan_evidence(&self) -> Option<(chrono::DateTime<chrono::Utc>, i64)> {
        let inner = self.0.lock().expect("phase timings lock");
        Some((inner.full_scan.0?, inner.full_scan.1?))
    }

    /// Record what the set-digest path did on this attempt.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn set_set_path(&self, report: serde_json::Value) {
        self.0.lock().expect("phase timings lock").set_path = Some(report);
    }

    /// The set-digest path's report for this attempt, or `null` when the
    /// attempt never reached it.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn set_path_json(&self) -> serde_json::Value {
        self.0
            .lock()
            .expect("phase timings lock")
            .set_path
            .clone()
            .unwrap_or(serde_json::Value::Null)
    }

    /// Per-table digest costs, slowest first, for `kernel-replay.json`.
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn tables_json(&self) -> serde_json::Value {
        let mut tables = self.0.lock().expect("phase timings lock").tables.clone();
        tables.sort_by_key(|table| std::cmp::Reverse(table.2));
        serde_json::Value::Array(
            tables
                .into_iter()
                .map(|(name, rows, micros)| {
                    serde_json::json!({"table": name, "rows": rows, "micros": micros})
                })
                .collect(),
        )
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn laps(&self) -> Vec<(&'static str, u64)> {
        self.0.lock().expect("phase timings lock").laps.clone()
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    /// Phase name to milliseconds, in order, for `kernel-replay.json`.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Array(
            self.laps()
                .into_iter()
                .map(|(name, millis)| serde_json::json!({"phase": name, "millis": millis}))
                .collect(),
        )
    }
}
