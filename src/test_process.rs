//! Test-only isolation for fixtures that own exceptional process-global state.

const CHILD: &str = "NATIVE_ROOT_FIXTURE_CHILD";

fn current_test() -> String {
    std::thread::current()
        .name()
        .expect("named libtest fixture")
        .to_owned()
}

fn child_marker(name: &str, marker: Option<&std::ffi::OsStr>) -> Result<bool, &'static str> {
    match marker {
        None => Ok(false),
        Some(marker) if marker == std::ffi::OsStr::new(name) => Ok(true),
        Some(_) => Err("isolated fixture sentinel mismatch; refusing recursive spawn"),
    }
}

fn is_child(name: &str) -> bool {
    child_marker(name, std::env::var_os(CHILD).as_deref()).expect("root fixture child sentinel")
}

fn one_successful_case(success: bool, name: &str, stdout: &str) -> bool {
    let summaries: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect();
    if !success
        || stdout
            .lines()
            .filter(|line| *line == "running 1 test")
            .count()
            != 1
        || summaries.len() != 1
    {
        return false;
    }
    let cases: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("test ") && !line.starts_with("test result:"))
        .collect();
    if cases != [format!("test {name} ... ok")] {
        return false;
    }
    // --exact delegates one ordinary outer case. Its full library binary
    // intentionally reports the other N-1 cases as filtered, not as executed.
    let Some(tail) =
        summaries[0].strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
    else {
        return false;
    };
    let Some((filtered, _)) = tail.split_once(" filtered out;") else {
        return false;
    };
    filtered.parse::<usize>().is_ok()
}

/// Run this exact fixture once in a fresh process; return true in its parent.
/// Call BEFORE taking any fixture/global guard. The child owns its own guards,
/// and the parent awaits/reaps it without holding a lock the child could need.
/// A failure or nonexecution fails the original case; nothing is retried.
/// No new deadline: the enclosing test-binary deadline and process group apply.
/// Only an absent sentinel may spawn; an exact-name sentinel executes the body,
/// and any other sentinel refuses before spawning. Delegation has one child
/// level and produces no independent suite/ledger authority.
pub(crate) async fn run_isolated_if_parent() -> bool {
    let name = current_test();
    if is_child(&name) {
        return false;
    }
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &name,
            "--test-threads=1",
            "--format=pretty",
            "--color=never",
        ])
        .env(CHILD, &name)
        .kill_on_drop(true)
        .output()
        .await
        .expect("run isolated root fixture");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        one_successful_case(output.status.success(), &name, &stdout),
        "isolated fixture {name} failed or did not execute exactly once: status={} stdout={stdout} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_receipt_requires_one_successful_delegated_case() {
        let valid = "running 1 test\ntest example ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4361 filtered out; finished in 0.01s\n";
        assert!(one_successful_case(true, "example", valid));
        assert!(!one_successful_case(false, "example", valid));
        assert!(one_successful_case(
            true,
            "example",
            &valid.replace("4361 filtered", "0 filtered")
        ));
        for invalid in [
            valid.replace("1 passed", "0 passed"),
            valid.replace("0 ignored", "1 ignored"),
            valid.replace("4361 filtered out", "-1 filtered out"),
            valid.replace("running 1 test", "running 0 tests"),
            valid.replace("test example ... ok\n", ""),
            valid.replace("test example ... ok", "test foreign ... ok"),
            valid.replace(
                "test example ... ok",
                "test example ... ok\ntest example ... ok",
            ),
            format!("{valid}{valid}"),
        ] {
            assert!(!one_successful_case(true, "example", &invalid), "{invalid}");
        }
        assert_eq!(child_marker("example", None), Ok(false));
        assert_eq!(
            child_marker("example", Some(std::ffi::OsStr::new("example"))),
            Ok(true)
        );
        assert!(child_marker("example", Some(std::ffi::OsStr::new("different"))).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            assert!(child_marker("example", Some(std::ffi::OsStr::from_bytes(b"\xff"))).is_err());
        }
    }

    #[tokio::test]
    async fn child_does_not_inherit_parent_process_state() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static PARENT_ONLY: AtomicBool = AtomicBool::new(false);
        if !is_child(&current_test()) {
            PARENT_ONLY.store(true, Ordering::SeqCst);
        }
        if run_isolated_if_parent().await {
            assert!(PARENT_ONLY.load(Ordering::SeqCst));
            return;
        }
        assert!(!PARENT_ONLY.load(Ordering::SeqCst));
    }
}
