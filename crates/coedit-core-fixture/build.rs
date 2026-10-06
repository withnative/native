use sha2::{Digest, Sha256};

fn main() {
    // These are the same source files included by main.rs, not a copied model.
    for (path, name, bytes) in [
        (
            "../../src/coedit/registry.rs",
            "COEDIT_REGISTRY_SHA256",
            include_bytes!("../../src/coedit/registry.rs").as_slice(),
        ),
        (
            "../../src/coedit/refusal.rs",
            "COEDIT_REFUSAL_SHA256",
            include_bytes!("../../src/coedit/refusal.rs").as_slice(),
        ),
    ] {
        println!("cargo:rerun-if-changed={path}");
        println!("cargo:rustc-env={name}={:x}", Sha256::digest(bytes));
    }
}
