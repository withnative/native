//! Optional development-only trusted guest host. Normal/build graph has no CEL.
mod audit;
mod codec;
mod runtime;
use native_package_cel_wire::Request;
pub use runtime::{Failure, Outcome, Phase, Stop, Ticket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, OnceLock,
};
pub const BUILD_MANIFEST_SHA256: &str = env!("BUILD_MANIFEST_SHA256");
pub const GUEST_SOURCE_SHA256: &str = env!("GUEST_SOURCE_SHA256");
pub const GUEST_MODULE_SHA256: &str = env!("GUEST_MODULE_SHA256");
const fn length(value: &str) -> usize {
    let bytes = value.as_bytes();
    let mut i = 0;
    let mut n = 0usize;
    while i < bytes.len() {
        assert!(bytes[i] >= b'0' && bytes[i] <= b'9');
        n = match n.checked_mul(10) {
            Some(v) => v,
            None => panic!("guest length overflow"),
        };
        n = match n.checked_add((bytes[i] - b'0') as usize) {
            Some(v) => v,
            None => panic!("guest length overflow"),
        };
        i += 1;
    }
    assert!(n > 0);
    n
}
const GUEST_LENGTH: usize = length(env!("GUEST_LENGTH"));
extern "C" {
    #[link_name = "native_package_cel_guest_v2_verified_data_7e43a1"]
    static VERIFIED_GUEST: [u8; GUEST_LENGTH];
}
// SAFETY: build.rs emits a unique, strong, read-only data symbol in a private
// static archive. Its exact extent equals the verifier's validated GUEST_LENGTH;
// object readback checks bytes/target/alignment/extent before archiving. The
// symbol name is reserved by this trusted build/link closure; no replacement
// or collision is supported. Duplicate definitions fail only when both enter
// the link. Hashing cannot make an undersized substituted symbol safe. The
// symbol lives for the process lifetime.
const GUEST: &[u8] = unsafe { &VERIFIED_GUEST };
fn verify_identity(
    abi: &str,
    module: &str,
    source: &str,
    manifest: &str,
    lock: &str,
    size: usize,
) -> bool {
    use sha2::{Digest, Sha256};
    abi == native_package_cel_wire::ABI
        && [module, source, manifest, lock]
            .iter()
            .all(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        && format!(
            "{:x}",
            Sha256::digest(
                format!("{abi}\n{module}\n{source}\n{manifest}\n{lock}\n{size}").as_bytes()
            )
        ) == env!("GUEST_IDENTITY_SHA256")
}
fn verify_embedded(data: &[u8], expected_length: usize, digest: &str) -> Result<(), Failure> {
    use sha2::{Digest, Sha256};
    if data.len() != expected_length
        || format!("{:x}", Sha256::digest(data)) != digest
        || !verify_identity(
            env!("GUEST_ABI"),
            digest,
            GUEST_SOURCE_SHA256,
            BUILD_MANIFEST_SHA256,
            env!("GUEST_ROOT_LOCK_SHA256"),
            expected_length,
        )
    {
        return Err(Failure::new(Phase::Module, Stop::Contract));
    }
    Ok(())
}
pub const INTERPRETER: &str = "cel-subset@0.14.5/wasmtime-checked-dev/1";
pub const RUNTIME: &str = "wasmtime@49.0.1";
pub const CONFIGURATION: &str = runtime::CONFIG_ID;

/// A scoped host can be shut down explicitly; the application singleton is process-lived.
/// Compilation/host allocation are outside invocation resource caps.
pub struct Host {
    runtime: runtime::Runtime,
}
impl Host {
    pub fn embedded() -> Result<Self, Failure> {
        verify_embedded(GUEST, GUEST_LENGTH, GUEST_MODULE_SHA256)?;
        Ok(Self {
            runtime: runtime::Runtime::new(runtime::Compiled::new(GUEST)?)?,
        })
    }
    pub fn submit(&self, request: &Request) -> Result<Ticket, Failure> {
        self.runtime.submit(request)
    }
    pub fn shutdown(&mut self) -> Result<(), Failure> {
        self.runtime.shutdown()
    }
    pub fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"stack_audit":self.runtime.compiled.audit,"exports":self.runtime.compiled.exports,"module_sha256":self.runtime.compiled.sha})
    }
    pub fn live_threads(&self) -> usize {
        self.runtime.live_threads()
    }
}
static GLOBAL: OnceLock<Result<Arc<Host>, Failure>> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);
/// One startup compilation, outside all invocation deadlines. Concurrent startup refuses Busy.
/// Cancellation of the first awaiting caller does not abandon/repeat compilation.
pub async fn global() -> Result<&'static Host, Failure> {
    if let Some(result) = GLOBAL.get() {
        return result.as_ref().map(Arc::as_ref).map_err(|e| *e);
    }
    if STARTED.swap(true, Ordering::AcqRel) {
        return Err(Failure::new(Phase::Module, Stop::Busy));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    let spawn = std::thread::Builder::new()
        .name("cel-guest-compile".into())
        .stack_size(runtime::HOST_STACK)
        .spawn(move || {
            let result = Host::embedded().map(Arc::new);
            let _ = GLOBAL.set(result);
            let _ = tx.send(());
        });
    if spawn.is_err() {
        let _ = GLOBAL.set(Err(Failure::new(Phase::Module, Stop::Worker)));
    } else {
        rx.await
            .map_err(|_| Failure::new(Phase::Module, Stop::Worker))?;
    }
    GLOBAL
        .get()
        .ok_or(Failure::new(Phase::Module, Stop::Worker))?
        .as_ref()
        .map(Arc::as_ref)
        .map_err(|e| *e)
}
pub fn limits() -> serde_json::Value {
    serde_json::json!({"fuel":runtime::FUEL,"memory_bytes":runtime::MEMORY_BYTES,"table_elements":runtime::TABLE_ELEMENTS,"wasm_call_stack_bytes":runtime::WASM_STACK,"host_worker_stack_bytes":runtime::HOST_STACK,"workers":2,"tick_ms":runtime::TICK_MS,"deadline_ms":runtime::DEADLINE_MS,"request_bytes":native_package_cel_wire::MAX_REQUEST,"response_bytes":native_package_cel_wire::MAX_RESPONSE,"host_compilation_and_native_allocations_guest_bounded":false})
}

#[cfg(test)]
#[path = "../embedding.rs"]
mod embedding;
#[cfg(test)]
mod tests;
