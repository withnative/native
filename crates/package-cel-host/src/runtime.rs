//! Standalone development boundary. Trusted embedded guest; test modules are cfg(test) only.
use crate::{audit, codec};
use native_package_cel_wire::{Report, Request, ABI_VERSION, MAX_REQUEST, MAX_RESPONSE};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use wasmtime::{
    Config, Engine, ExternType, Instance, Module, ResourceLimiter, Store, Trap, UpdateDeadline,
    ValType,
};

pub(crate) const MEMORY_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const TABLE_ELEMENTS: usize = 16_384;
pub(crate) const FUEL: u64 = 50_000_000;
pub(crate) const WASM_STACK: usize = 1024 * 1024;
pub(crate) const HOST_STACK: usize = 8 * 1024 * 1024;
pub(crate) const TICK_MS: u64 = 10;
pub(crate) const DEADLINE_MS: u64 = 1000;
pub(crate) const CONFIG_ID: &str = "native.cel-guest-dev-host/3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Phase {
    Module,
    Admission,
    Encode,
    Instantiate,
    Version,
    Allocate,
    Write,
    Evaluate,
    Decode,
    Deliver,
    Shutdown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Stop {
    Module,
    Contract,
    StackLayout,
    Busy,
    Closed,
    Cancelled,
    Deadline,
    Shutdown,
    Fuel,
    MemoryLimit,
    TableLimit,
    CallStack,
    MemoryBounds,
    Trap,
    Input,
    Pointer,
    Length,
    Utf8,
    Json,
    ReportScalar,
    ReportMetadata,
    Worker,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Failure {
    pub phase: Phase,
    pub stop: Stop,
}
impl Failure {
    pub fn new(phase: Phase, stop: Stop) -> Self {
        Self { phase, stop }
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}:{:?}", self.phase, self.stop)
    }
}
impl std::error::Error for Failure {}
#[derive(Debug, Serialize)]
pub struct Outcome {
    pub report: Option<Report>,
    pub failure: Option<Failure>,
    pub fuel_used: u64,
    pub module_sha256: String,
    pub config: &'static str,
    pub phase: Phase,
    pub delivery_stop: Option<Stop>,
    pub fuel_budget: u64,
    pub deadline_ms: u64,
    pub test_controls: bool,
}
impl Outcome {
    fn failed(f: Failure, fuel_used: u64, job: &Job) -> Self {
        Self {
            report: None,
            failure: Some(f),
            fuel_used,
            module_sha256: job.sha.clone(),
            config: CONFIG_ID,
            phase: f.phase,
            delivery_stop: None,
            fuel_budget: job.fuel,
            deadline_ms: job.timeout_ms,
            test_controls: job.test_controls,
        }
    }
}

pub(crate) struct Compiled {
    pub engine: Engine,
    pub module: Module,
    pub sha: String,
    pub audit: audit::StackAudit,
    pub exports: Vec<String>,
    active_runtime: AtomicBool,
}
impl Compiled {
    pub fn new(bytes: &[u8]) -> Result<Arc<Self>, Failure> {
        let audit = audit::stack_first(bytes)
            .map_err(|_| Failure::new(Phase::Module, Stop::StackLayout))?;
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(WASM_STACK)
            .wasm_memory64(false)
            .wasm_multi_memory(false);
        let engine = Engine::new(&config).map_err(|_| Failure::new(Phase::Module, Stop::Module))?;
        // Trusted compilation is ONCE, before job deadlines; its host allocations are not guest-limited.
        let module =
            Module::new(&engine, bytes).map_err(|_| Failure::new(Phase::Module, Stop::Module))?;
        validate(&module)?;
        let exports = module.exports().map(|e| e.name().to_owned()).collect();
        Ok(Arc::new(Self {
            engine,
            module,
            sha: format!("{:x}", Sha256::digest(bytes)),
            audit,
            exports,
            active_runtime: AtomicBool::new(false),
        }))
    }
}
fn validate(module: &Module) -> Result<(), Failure> {
    let fail = Failure::new(Phase::Module, Stop::Contract);
    if module.imports().next().is_some() || module.exports().len() != 4 {
        return Err(fail);
    }
    for export in module.exports() {
        let (params, results): (&[u8], &[u8]) = match export.name() {
            "memory" => {
                match export.ty() {
                    ExternType::Memory(m)
                        if !m.is_64()
                            && !m.is_shared()
                            && m.page_size_log2() == 16
                            && m.minimum() <= 1024 => {}
                    _ => return Err(fail),
                };
                continue;
            }
            "guest_abi_version" => (&[], &[32]),
            "guest_allocate" => (&[32], &[32]),
            "guest_evaluate" => (&[32, 32], &[64]),
            _ => return Err(fail),
        };
        let ExternType::Func(f) = export.ty() else {
            return Err(fail);
        };
        let kind = |v: ValType| match v {
            ValType::I32 => 32,
            ValType::I64 => 64,
            _ => 0,
        };
        if f.params().map(kind).collect::<Vec<_>>() != params
            || f.results().map(kind).collect::<Vec<_>>() != results
        {
            return Err(fail);
        }
    }
    let r = module.resources_required();
    if r.num_memories != 1
        || r.num_tables > 1
        || r.max_initial_table_size
            .is_some_and(|n| n > TABLE_ELEMENTS as u64)
    {
        return Err(fail);
    }
    Ok(())
}
struct Limits {
    denied: Option<Stop>,
    instantiated: bool,
}
impl ResourceLimiter for Limits {
    fn memory_growing(
        &mut self,
        _: usize,
        desired: usize,
        _: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > MEMORY_BYTES {
            self.denied = Some(Stop::MemoryLimit);
            return Err(wasmtime::Error::msg("guest memory limit"));
        }
        Ok(true)
    }
    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        _: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > TABLE_ELEMENTS || (self.instantiated && desired > current) {
            self.denied = Some(Stop::TableLimit);
            return Err(wasmtime::Error::msg("guest table limit"));
        }
        Ok(true)
    }
    fn instances(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
}
struct StoreData {
    limits: Limits,
    stop: Option<Stop>,
    phase: Phase,
}
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct Hooks {
    pub epoch: Option<Arc<Gate>>,
    pub before_drop: Option<Arc<Gate>>,
    pub dropped: Option<Arc<AtomicBool>>,
}
#[cfg(test)]
pub(crate) struct Gate {
    entered: Mutex<bool>,
    entered_cv: Condvar,
    released: Mutex<bool>,
    release_cv: Condvar,
    timed_out: AtomicBool,
}
#[cfg(test)]
impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Mutex::new(false),
            entered_cv: Condvar::new(),
            released: Mutex::new(false),
            release_cv: Condvar::new(),
            timed_out: AtomicBool::new(false),
        })
    }
    pub fn pause(&self) -> bool {
        *self.entered.lock().unwrap() = true;
        self.entered_cv.notify_all();
        let released = self.released.lock().unwrap();
        let (released, t) = self
            .release_cv
            .wait_timeout_while(released, Duration::from_secs(5), |v| !*v)
            .unwrap();
        if !*released || t.timed_out() {
            self.timed_out.store(true, Ordering::Release);
            false
        } else {
            true
        }
    }
    pub fn entered(&self) {
        let guard = self.entered.lock().unwrap();
        let (guard, t) = self
            .entered_cv
            .wait_timeout_while(guard, Duration::from_secs(5), |v| !*v)
            .unwrap();
        assert!(*guard && !t.timed_out(), "test phase not reached");
    }
    pub fn assert_no_timeout(&self) {
        assert!(
            !self.timed_out.load(Ordering::Acquire),
            "test hook timed out"
        );
    }
    pub fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release_cv.notify_all();
    }
}
struct Job {
    bytes: Vec<u8>,
    module: Module,
    sha: String,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
    timeout_ms: u64,
    mode: Option<native_package_cel_wire::Mode>,
    test_controls: bool,
    reply: Option<tokio::sync::oneshot::Sender<Outcome>>,
    _permit: Permit,
    fuel: u64,
    #[cfg(test)]
    hooks: Hooks,
}
struct SlotState {
    job: Option<Job>,
    busy: bool,
    cancel: Option<Arc<AtomicBool>>,
    stop: bool,
}
struct Slot {
    state: Mutex<SlotState>,
    cv: Condvar,
}
struct Permit {
    slot: Arc<Slot>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut s = self.slot.state.lock().unwrap();
        s.busy = false;
        s.cancel = None;
        self.slot.cv.notify_all();
    }
}
pub struct Ticket {
    rx: Option<tokio::sync::oneshot::Receiver<Outcome>>,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
    shutdown: Arc<AtomicBool>,
    #[cfg(test)]
    slot: Arc<Slot>,
}
impl Ticket {
    #[cfg(test)]
    pub(crate) fn probe(&self) -> SlotProbe {
        SlotProbe(self.slot.clone())
    }
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
    pub fn wait(mut self) -> Result<Outcome, Failure> {
        let result = self
            .rx
            .take()
            .unwrap()
            .blocking_recv()
            .map_err(|_| Failure::new(Phase::Deliver, Stop::Worker))?;
        Ok(self.deliver(result))
    }
    pub async fn wait_async(mut self) -> Result<Outcome, Failure> {
        let result = (self.rx.as_mut().unwrap())
            .await
            .map_err(|_| Failure::new(Phase::Deliver, Stop::Worker))?;
        Ok(self.deliver(result))
    }
    fn deliver(&self, mut result: Outcome) -> Outcome {
        let stop = if self.shutdown.load(Ordering::Acquire) {
            Some(Stop::Shutdown)
        } else if self.cancel.load(Ordering::Acquire) {
            Some(Stop::Cancelled)
        } else if Instant::now() >= self.deadline {
            Some(Stop::Deadline)
        } else {
            None
        };
        if let Some(stop) = stop {
            result.report = None;
            result.delivery_stop = Some(stop);
            if result.failure.is_none() {
                result.failure = Some(Failure::new(Phase::Deliver, stop));
            }
        }
        result
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.cancel();
    }
}
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestModule {
    module: Module,
    sha: String,
}
#[cfg(test)]
pub(crate) struct SlotProbe(Arc<Slot>);
#[cfg(test)]
impl SlotProbe {
    pub fn busy(&self) -> bool {
        self.0.state.lock().unwrap().busy
    }
    pub fn wait_released(&self) {
        let s = self.0.state.lock().unwrap();
        let (s, t) = self
            .0
            .cv
            .wait_timeout_while(s, Duration::from_secs(5), |s| s.busy)
            .unwrap();
        assert!(!s.busy && !t.timed_out(), "slot leaked");
    }
}
struct Ticker {
    control: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}
impl Ticker {
    fn new(engine: Engine, live: Arc<AtomicUsize>) -> Result<Self, Failure> {
        let control = Arc::new((Mutex::new(false), Condvar::new()));
        let c = control.clone();
        let (ready, started) = mpsc::sync_channel(0);
        let thread = thread::Builder::new()
            .name("cel-epoch".into())
            .spawn(move || {
                live.fetch_add(1, Ordering::SeqCst);
                let _ = ready.send(());
                let (stop, cv) = (&c.0, &c.1);
                let mut guard = stop.lock().unwrap();
                loop {
                    let (g, _) = cv
                        .wait_timeout(guard, Duration::from_millis(TICK_MS))
                        .unwrap();
                    guard = g;
                    if *guard {
                        break;
                    }
                    engine.increment_epoch();
                }
                live.fetch_sub(1, Ordering::SeqCst);
            })
            .map_err(|_| Failure::new(Phase::Module, Stop::Worker))?;
        started
            .recv()
            .map_err(|_| Failure::new(Phase::Module, Stop::Worker))?;
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }
    fn stop(&mut self) -> bool {
        *self.control.0.lock().unwrap() = true;
        self.control.1.notify_all();
        self.thread.take().is_none_or(|t| t.join().is_ok())
    }
}
impl Drop for Ticker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
struct ExecutionLimits {
    fuel: u64,
    timeout: Duration,
}

pub(crate) struct Runtime {
    pub compiled: Arc<Compiled>,
    slots: Vec<Arc<Slot>>,
    workers: Vec<JoinHandle<()>>,
    ticker: Ticker,
    shutdown: Arc<AtomicBool>,
    live: Arc<AtomicUsize>,
    closed: bool,
}
impl Runtime {
    pub fn new(compiled: Arc<Compiled>) -> Result<Self, Failure> {
        if compiled.active_runtime.swap(true, Ordering::AcqRel) {
            return Err(Failure::new(Phase::Module, Stop::Busy));
        }
        let live = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let ticker = match Ticker::new(compiled.engine.clone(), live.clone()) {
            Ok(v) => v,
            Err(e) => {
                compiled.active_runtime.store(false, Ordering::Release);
                return Err(e);
            }
        };
        let mut rt = Self {
            compiled,
            slots: Vec::new(),
            workers: Vec::new(),
            ticker,
            shutdown,
            live,
            closed: false,
        };
        for n in 0..2 {
            let slot = Arc::new(Slot {
                state: Mutex::new(SlotState {
                    job: None,
                    busy: false,
                    cancel: None,
                    stop: false,
                }),
                cv: Condvar::new(),
            });
            let s = slot.clone();
            let engine = rt.compiled.engine.clone();
            let shutdown = rt.shutdown.clone();
            let live = rt.live.clone();
            let (ready, started) = mpsc::sync_channel(0);
            let worker = thread::Builder::new()
                .name(format!("cel-guest-{n}"))
                .stack_size(HOST_STACK)
                .spawn(move || {
                    live.fetch_add(1, Ordering::SeqCst);
                    let _ = ready.send(());
                    loop {
                        let mut job = {
                            let mut state = s.state.lock().unwrap();
                            while state.job.is_none() && !state.stop {
                                state = s.cv.wait(state).unwrap();
                            }
                            match state.job.take() {
                                Some(job) => job,
                                None => break,
                            }
                        };
                        let outcome = execute(&engine, &shutdown, &job);
                        if let Some(reply) = job.reply.take() {
                            let _ = reply.send(outcome);
                        }
                        drop(job); // includes job-owned permit, after decoding and Store destruction
                    }
                    live.fetch_sub(1, Ordering::SeqCst);
                })
                .map_err(|_| Failure::new(Phase::Module, Stop::Worker))?;
            rt.slots.push(slot);
            rt.workers.push(worker);
            started
                .recv()
                .map_err(|_| Failure::new(Phase::Module, Stop::Worker))?;
        }
        Ok(rt)
    }
    pub fn submit(&self, request: &Request) -> Result<Ticket, Failure> {
        self.dispatch(
            codec::encode(request)?,
            self.compiled.module.clone(),
            self.compiled.sha.clone(),
            ExecutionLimits {
                fuel: FUEL,
                timeout: Duration::from_millis(DEADLINE_MS),
            },
            false,
            #[cfg(test)]
            Hooks::default(),
        )
    }
    fn dispatch(
        &self,
        bytes: Vec<u8>,
        module: Module,
        sha: String,
        limits: ExecutionLimits,
        test_controls: bool,
        #[cfg(test)] hooks: Hooks,
    ) -> Result<Ticket, Failure> {
        let ExecutionLimits { fuel, timeout } = limits;
        if bytes.is_empty() || bytes.len() > MAX_REQUEST {
            return Err(Failure::new(Phase::Encode, Stop::Input));
        }
        if self.closed || self.shutdown.load(Ordering::Acquire) {
            return Err(Failure::new(Phase::Admission, Stop::Closed));
        }
        for slot in &self.slots {
            let Ok(mut state) = slot.state.try_lock() else {
                continue;
            };
            if state.busy || state.stop {
                continue;
            }
            let cancel = Arc::new(AtomicBool::new(false));
            let deadline = Instant::now() + timeout;
            let (tx, rx) = tokio::sync::oneshot::channel();
            state.busy = true;
            state.cancel = Some(cancel.clone());
            let mode = serde_json::from_slice::<Request>(&bytes)
                .ok()
                .map(|r| r.mode());
            state.job = Some(Job {
                bytes,
                module,
                sha,
                cancel: cancel.clone(),
                deadline,
                mode,
                timeout_ms: timeout.as_millis().min(u64::MAX as u128) as u64,
                test_controls,
                reply: Some(tx),
                _permit: Permit { slot: slot.clone() },
                fuel,
                #[cfg(test)]
                hooks,
            });
            slot.cv.notify_one();
            return Ok(Ticket {
                rx: Some(rx),
                cancel,
                deadline,
                shutdown: self.shutdown.clone(),
                #[cfg(test)]
                slot: slot.clone(),
            });
        }
        Err(Failure::new(Phase::Admission, Stop::Busy))
    }
    pub fn shutdown(&mut self) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.shutdown.store(true, Ordering::Release);
        for slot in &self.slots {
            let mut s = slot.state.lock().unwrap();
            s.stop = true;
            if let Some(c) = &s.cancel {
                c.store(true, Ordering::Release)
            }
            slot.cv.notify_all();
        }
        let mut failed = false;
        for thread in self.workers.drain(..) {
            failed |= thread.join().is_err();
        }
        // Epochs remain live until all workers/Stores have stopped.
        failed |= !self.ticker.stop();
        self.compiled.active_runtime.store(false, Ordering::Release);
        if failed {
            Err(Failure::new(Phase::Shutdown, Stop::Worker))
        } else {
            Ok(())
        }
    }
    pub fn live_threads(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
    #[cfg(test)]
    pub fn trusted_test_module(&self) -> TestModule {
        TestModule {
            module: self.compiled.module.clone(),
            sha: self.compiled.sha.clone(),
        }
    }
    #[cfg(test)]
    pub fn flags(&self) -> (Arc<AtomicBool>, Arc<AtomicUsize>) {
        (self.shutdown.clone(), self.live.clone())
    }
    #[cfg(test)]
    pub fn test_module(&self, bytes: &[u8]) -> Result<TestModule, Failure> {
        let m = Module::new(&self.compiled.engine, bytes)
            .map_err(|_| Failure::new(Phase::Module, Stop::Module))?;
        validate(&m)?;
        Ok(TestModule {
            module: m,
            sha: format!("{:x}", Sha256::digest(bytes)),
        })
    }
    #[cfg(test)]
    pub fn test_submit(
        &self,
        module: TestModule,
        bytes: Vec<u8>,
        fuel: u64,
        timeout: Duration,
        hooks: Hooks,
    ) -> Result<Ticket, Failure> {
        self.dispatch(
            bytes,
            module.module,
            module.sha,
            ExecutionLimits { fuel, timeout },
            true,
            hooks,
        )
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
fn stopped(shutdown: &AtomicBool, job: &Job) -> Option<Stop> {
    if shutdown.load(Ordering::Acquire) {
        Some(Stop::Shutdown)
    } else if job.cancel.load(Ordering::Acquire) {
        Some(Stop::Cancelled)
    } else if Instant::now() >= job.deadline {
        Some(Stop::Deadline)
    } else {
        None
    }
}
fn classify(e: &wasmtime::Error, phase: Phase, store: &Store<StoreData>) -> Failure {
    let stop = store
        .data()
        .limits
        .denied
        .or(store.data().stop)
        .unwrap_or_else(|| match e.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => Stop::Fuel,
            Some(Trap::StackOverflow) => Stop::CallStack,
            Some(Trap::MemoryOutOfBounds) => Stop::MemoryBounds,
            _ => Stop::Trap,
        });
    Failure::new(phase, stop)
}
fn execute(engine: &Engine, shutdown: &Arc<AtomicBool>, job: &Job) -> Outcome {
    if let Some(stop) = stopped(shutdown, job) {
        return Outcome::failed(Failure::new(Phase::Instantiate, stop), 0, job);
    }
    let mut store = Store::new(
        engine,
        StoreData {
            limits: Limits {
                denied: None,
                instantiated: false,
            },
            stop: None,
            phase: Phase::Instantiate,
        },
    );
    store.limiter(|s| &mut s.limits);
    let cancel = job.cancel.clone();
    let shutdown_flag = shutdown.clone();
    let deadline = job.deadline;
    #[cfg(test)]
    let hook = job.hooks.epoch.clone();
    store.epoch_deadline_callback(move |mut context| {
        #[cfg(test)]
        if let Some(h) = &hook {
            if context.data().phase == Phase::Evaluate && !h.pause() {
                context.data_mut().stop = Some(Stop::Worker);
                return Ok(UpdateDeadline::Interrupt);
            }
        }
        let stop = if shutdown_flag.load(Ordering::Acquire) {
            Some(Stop::Shutdown)
        } else if cancel.load(Ordering::Acquire) {
            Some(Stop::Cancelled)
        } else if Instant::now() >= deadline {
            Some(Stop::Deadline)
        } else {
            None
        };
        if let Some(stop) = stop {
            context.data_mut().stop = Some(stop);
            Ok(UpdateDeadline::Interrupt)
        } else {
            Ok(UpdateDeadline::Continue(1))
        }
    });
    store.set_epoch_deadline(1);
    let result = (|| -> Result<Report, Failure> {
        store
            .set_fuel(job.fuel)
            .map_err(|_| Failure::new(Phase::Instantiate, Stop::Worker))?;
        let instance = Instance::new(&mut store, &job.module, &[])
            .map_err(|e| classify(&e, Phase::Instantiate, &store))?;
        store.data_mut().limits.instantiated = true;
        store.data_mut().phase = Phase::Version;
        let version = instance
            .get_typed_func::<(), u32>(&mut store, "guest_abi_version")
            .map_err(|_| Failure::new(Phase::Version, Stop::Contract))?;
        if version
            .call(&mut store, ())
            .map_err(|e| classify(&e, Phase::Version, &store))?
            != ABI_VERSION
        {
            return Err(Failure::new(Phase::Version, Stop::Contract));
        }
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(Failure::new(Phase::Allocate, Stop::Contract))?;
        let allocate = instance
            .get_typed_func::<u32, u32>(&mut store, "guest_allocate")
            .map_err(|_| Failure::new(Phase::Allocate, Stop::Contract))?;
        store.data_mut().phase = Phase::Allocate;
        let ptr = allocate
            .call(&mut store, job.bytes.len() as u32)
            .map_err(|e| classify(&e, Phase::Allocate, &store))?;
        let range = codec::span(ptr, job.bytes.len(), memory.data_size(&store), MAX_REQUEST)
            .map_err(|f| Failure::new(Phase::Write, f.stop))?;
        memory
            .write(&mut store, range.start, &job.bytes)
            .map_err(|_| Failure::new(Phase::Write, Stop::Pointer))?;
        let eval = instance
            .get_typed_func::<(u32, u32), u64>(&mut store, "guest_evaluate")
            .map_err(|_| Failure::new(Phase::Evaluate, Stop::Contract))?;
        store.data_mut().phase = Phase::Evaluate;
        let packed = eval
            .call(&mut store, (ptr, job.bytes.len() as u32))
            .map_err(|e| classify(&e, Phase::Evaluate, &store))?;
        let range = codec::span(
            packed as u32,
            (packed >> 32) as usize,
            memory.data_size(&store),
            MAX_RESPONSE,
        )?;
        let report = codec::decode(&memory.data(&store)[range])?;
        if job.mode.is_some_and(|mode| mode != report.mode) {
            return Err(Failure::new(Phase::Decode, Stop::ReportMetadata));
        }
        Ok(report)
    })();
    let fuel = job
        .fuel
        .saturating_sub(store.get_fuel().unwrap_or(job.fuel));
    #[cfg(test)]
    let result = match &job.hooks.before_drop {
        Some(h) if !h.pause() => Err(Failure::new(Phase::Decode, Stop::Worker)),
        _ => result,
    };
    drop(store);
    #[cfg(test)]
    if let Some(flag) = &job.hooks.dropped {
        flag.store(true, Ordering::Release);
    }
    let mut out = match result {
        Ok(report) => Outcome {
            report: Some(report),
            failure: None,
            fuel_used: fuel,
            module_sha256: job.sha.clone(),
            config: CONFIG_ID,
            phase: Phase::Deliver,
            delivery_stop: None,
            fuel_budget: job.fuel,
            deadline_ms: job.timeout_ms,
            test_controls: job.test_controls,
        },
        Err(f) => Outcome::failed(f, fuel, job),
    };
    if let Some(stop) = stopped(shutdown, job) {
        out.report = None;
        out.delivery_stop = Some(stop);
        if out.failure.is_none() {
            out.failure = Some(Failure::new(Phase::Deliver, stop));
        }
    }
    out
}
