//! This verifier never invokes Cargo. Guest build is an explicit prior step.
mod embedding;
use sha2::{Digest, Sha256};
use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=embedding.rs");
    for key in [
        "RUSTC",
        "CARGO_BUILD_RUSTC",
        "RUSTUP_TOOLCHAIN",
        "CARGO_HOME",
        "RUSTC_BOOTSTRAP",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../..");
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "scripts/build-package-cel-guest.py",
        ".cargo/config.toml",
        "crates/cel-subset",
        "crates/package-cel-wire",
        "crates/package-cel-guest",
        "target/package-cel-guest/build.json",
        "target/package-cel-guest/guest.wasm",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    let result = Command::new("python3")
        .arg(root.join("scripts/build-package-cel-guest.py"))
        .arg("--compiler")
        .arg(env::var_os("RUSTC").expect("Cargo supplies effective RUSTC to the host verifier"))
        .arg("--embed-out")
        .arg(env::var_os("OUT_DIR").unwrap())
        .current_dir(&root)
        .output()
        .expect("development guest verifier needs python3");
    assert!(
        result.status.success(),
        "fresh pinned development guest required; run scripts/build-package-cel-guest.py first: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let pins: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("pins.json")).unwrap()).unwrap();
    for path in pins["CARGO_CONFIG_FILES"]
        .as_array()
        .expect("verified config inventory")
    {
        println!(
            "cargo:rerun-if-changed={}",
            path.as_str().expect("config path")
        );
    }
    let data = std::fs::read(out.join("guest.wasm")).unwrap();
    assert_eq!(pins["GUEST_LENGTH"].as_u64(), Some(data.len() as u64));
    assert_eq!(
        pins["GUEST_MODULE_SHA256"].as_str(),
        Some(format!("{:x}", Sha256::digest(&data)).as_str())
    );
    for key in [
        "BUILD_MANIFEST_SHA256",
        "GUEST_SOURCE_SHA256",
        "GUEST_MODULE_SHA256",
        "GUEST_ROOT_LOCK_SHA256",
    ] {
        let value = pins[key].as_str().unwrap();
        assert!(value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()));
        println!("cargo:rustc-env={key}={value}");
    }
    assert_eq!(
        pins["GUEST_ABI"].as_str(),
        Some("native.cel-scalar-guest/2")
    );
    println!("cargo:rustc-env=GUEST_ABI=native.cel-scalar-guest/2");
    println!("cargo:rustc-env=GUEST_LENGTH={}", data.len());
    let identity = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        pins["GUEST_ABI"].as_str().unwrap(),
        pins["GUEST_MODULE_SHA256"].as_str().unwrap(),
        pins["GUEST_SOURCE_SHA256"].as_str().unwrap(),
        pins["BUILD_MANIFEST_SHA256"].as_str().unwrap(),
        pins["GUEST_ROOT_LOCK_SHA256"].as_str().unwrap(),
        data.len()
    );
    println!(
        "cargo:rustc-env=GUEST_IDENTITY_SHA256={:x}",
        Sha256::digest(identity.as_bytes())
    );
    let config = embedding::target(
        &env::var("CARGO_CFG_TARGET_OS").unwrap(),
        &env::var("CARGO_CFG_TARGET_ARCH").unwrap(),
        &env::var("CARGO_CFG_TARGET_ENDIAN").unwrap(),
    )
    .expect("unsupported TARGET for development guest data object");
    let bytes =
        embedding::encode(&data, config).expect("verified data object generation/readback failed");
    let object = out.join("native_cel_verified.o");
    std::fs::write(&object, bytes).unwrap();
    // cc selects the TARGET archiver; no C compiler or host-architecture object is used.
    cc::Build::new()
        .object(object)
        .compile("native_cel_verified");
}
