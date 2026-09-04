//! CI guard for the authoritative relationship write funnel.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn relationship_writes_are_confined_to_the_kernel_projector_and_data_movement_seams() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&root, &mut files);
    let mutation = Regex::new(
        r"(?is)\b(?:insert(?:\s+or\s+\w+)?\s+into|update|delete\s+from)\s+(?:relationship_events|relationships|relationship_endpoints|relationship_assertion_heads|relationship_local_admissions|effective_relationships|relationship_endpoint_activity)\b",
    )
    .unwrap();
    let allowed = [
        // Canonical logical export/import and its round-trip fixture.
        Path::new("src/interchange.rs"),
        // Sealed compatibility migration and authenticated federation import.
        Path::new("src/relationship/legacy.rs"),
        Path::new("src/relationship/federation.rs"),
        // The sole event append seam and synchronous minimal projector.
        Path::new("src/relationship/persistence.rs"),
        Path::new("src/relationship/projector.rs"),
        // Narrow in-module corruption/append-only fixtures only.
        Path::new("src/relationship/kernel_tests.rs"),
    ];
    let mut violations = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap();
        let source = fs::read_to_string(&path).unwrap();
        if mutation.is_match(&source) && !allowed.contains(&relative) {
            violations.push(relative.display().to_string());
        }
    }
    assert!(
        violations.is_empty(),
        "relationship writes bypass the governed funnel: {violations:#?}"
    );
}
