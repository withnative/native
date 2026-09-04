use std::process::Command;

#[test]
fn source_boundary_fixtures_pass() {
    let status = Command::new("python3")
        .arg("scripts/release/test_source_boundary.py")
        .status()
        .expect("python3 must be available to run source-boundary fixtures");

    assert!(status.success(), "source-boundary fixtures failed");
}
