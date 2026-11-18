//! A dedicated thread for request dispatch.
//!
//! Request futures are large (`dispatch_with_request_port` notes it), and a
//! request that dispatches an inner one, such as an executor envelope, nests
//! two of them. On a Mac the process main thread has an 8 MiB stack, and the
//! local node aborted there with "stack overflow" at a bounded depth (two
//! dispatch frames, about 110-130 frames in total; Native task 0666dc0).

/// Stack reserved for the thread that runs node and MCP request dispatch. The
/// standby handoff worker and the repository tests already reserve this bound.
/// It is virtual address space; only touched pages are committed.
pub const DISPATCH_STACK_BYTES: usize = 64 * 1024 * 1024;

/// Run `work` on a dedicated thread with [`DISPATCH_STACK_BYTES`] of stack and
/// return its result. A panic resumes on the caller unchanged, so process exit
/// behaviour matches running `work` directly.
pub fn run_with_dispatch_stack<T, F>(name: &str, work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(DISPATCH_STACK_BYTES)
        .spawn(work)
        .unwrap_or_else(|err| panic!("cannot start the {name} thread: {err}"));
    match handle.join() {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_work_result_on_a_named_thread() {
        let name = run_with_dispatch_stack("dispatch-test", || {
            std::thread::current().name().map(str::to_owned)
        });
        assert_eq!(name.as_deref(), Some("dispatch-test"));
    }

    #[test]
    fn has_room_for_more_than_an_eight_mebibyte_main_thread() {
        // About 16 MiB of live frames (1024 x 16 KiB, each kept in place by
        // reference): twice what a Mac main thread holds.
        #[inline(never)]
        fn deep(levels: usize) -> u64 {
            let frame = [levels as u8; 16 * 1024];
            std::hint::black_box(&frame);
            if levels == 0 {
                return 1;
            }
            deep(levels - 1) + u64::from(frame[1] & 1)
        }
        let total = run_with_dispatch_stack("dispatch-deep", || deep(1024));
        assert!(total > 0);
    }

    #[test]
    fn a_panic_resumes_on_the_caller() {
        let outcome = std::panic::catch_unwind(|| {
            run_with_dispatch_stack("dispatch-panic", || -> () { panic!("boom") })
        });
        let payload = outcome.expect_err("the panic must reach the caller");
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"boom"));
    }
}
