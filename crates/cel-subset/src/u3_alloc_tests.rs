//! U3 tests (design §1.3, §7.2 "U3").
//!
//! A counting allocator proves that `rows.size()` and `v in rows` over
//! 5,000 rows allocate no copy of `rows`, and a registry check proves
//! the subset's built-ins are served as borrowed overloads rather than
//! through the legacy `dyn Val → Value` magic path.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ON.try_with(Cell::get).unwrap_or(false) {
            let _ = BYTES.try_with(|b| b.set(b.get().wrapping_add(layout.size())));
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ON.try_with(Cell::get).unwrap_or(false) {
            let _ = BYTES.try_with(|b| b.set(b.get().wrapping_add(new_size)));
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::Budget;
    use crate::{Context, Program, ResolveResult};

    /// Run `src` on this thread under an unbounded budget, returning the
    /// result and the bytes allocated during the call.
    fn measure(src: &str, ctx: &Context) -> (ResolveResult, usize) {
        let program = Program::compile(src).expect("compiles");
        ON.with(|on| on.set(true));
        BYTES.with(|b| b.set(0));
        let (result, _) = program.execute_budgeted(
            ctx,
            Budget {
                work: u64::MAX,
                memory: u64::MAX,
            },
        );
        ON.with(|on| on.set(false));
        (result, BYTES.with(|b| b.get()))
    }

    #[test]
    fn size_and_in_do_not_copy_rows() {
        let mut ctx = Context::default();
        ctx.add_variable_from_value("rows", (0..5000i64).collect::<Vec<_>>());
        ctx.add_variable_from_value("v", 1i64);

        // Baseline: an evaluation that does not touch `rows` still pays
        // for the result's own allocation.
        let (base_result, base) = measure("true", &ctx);
        assert!(base_result.is_ok(), "{base_result:?}");

        let (size_result, size_bytes) = measure("rows.size()", &ctx);
        assert_eq!(size_result.unwrap(), crate::Value::Int(5000));
        assert!(
            size_bytes < base + 4096,
            "rows.size() allocated {size_bytes} bytes (baseline {base}); a copy of \
             5,000 rows is tens of kilobytes"
        );

        let (in_result, in_bytes) = measure("v in rows", &ctx);
        assert_eq!(in_result.unwrap(), crate::Value::Bool(true));
        assert!(
            in_bytes < base + 4096,
            "v in rows allocated {in_bytes} bytes (baseline {base})"
        );
    }

    /// An error raised once per iteration and absorbed (`all`, review
    /// E4) must not deep-copy its operands: a large operand's payload
    /// is a bounded description, so the per-iteration allocation is a
    /// small constant, not O(size) each time.
    #[test]
    fn absorbed_error_payload_is_bounded_per_iteration() {
        let mut ctx = Context::default();
        ctx.add_variable_from_value("rows", (0..5000i64).collect::<Vec<_>>());
        // A 100 KB bytes operand, bound (not a literal, which the parse
        // cap would refuse).
        ctx.add_variable_from_value("big", vec![0u8; 100_000]);

        let program = Program::compile("rows.all(r, big + r > 0)").expect("compiles");
        ON.with(|on| on.set(true));
        BYTES.with(|b| b.set(0));
        let (result, _) = program.execute_budgeted(
            &ctx,
            Budget {
                work: u64::MAX,
                memory: u64::MAX,
            },
        );
        ON.with(|on| on.set(false));
        let bytes = BYTES.with(|b| b.get());

        assert!(
            matches!(
                result,
                Err(crate::ExecutionError::UnsupportedBinaryOperator(..))
            ),
            "expected a binary-operator error, got {result:?}"
        );
        // 5,000 iterations, each building a bounded description. A deep
        // copy of `big` would be ~500 MB; require well under 1 KB per
        // iteration.
        assert!(
            bytes < 5000 * 1024,
            "allocated {bytes} bytes over 5,000 absorbed errors (a copy of big is ~100 KB/iter)"
        );
    }

    /// F10: comprehension exit moves the accumulator instead of
    /// deep-copying it. Mapping 2,000 4 KiB strings allocates ~25 MB
    /// (item bind, element ownership and result emission each copy
    /// the ~8 MB result once); an exit copy would add a fourth copy
    /// (~33 MB).
    #[test]
    fn map_exit_does_not_copy_accumulator() {
        let mut ctx = Context::default();
        let rows: Vec<String> = (0..2000).map(|i| format!("{i:>4096}")).collect();
        ctx.add_variable_from_value("rows", rows);
        let (result, bytes) = measure("rows.map(r, r)", &ctx);
        assert!(result.is_ok(), "{result:?}");
        assert!(
            bytes < 29_000_000,
            "map exit allocated {bytes} bytes; an exit copy adds ~8 MB"
        );
    }

    /// A built-in reached through `get_function` would round-trip its
    /// receiver and arguments through `Value` (the legacy U3 path). The
    /// subset registry serves every built-in as an overload — a
    /// `fn(Vec<Cow<dyn Val>>)` — so `get_function` must be empty for
    /// them; this fails if one is ever registered as a magic function.
    #[test]
    fn subset_builtins_are_overloads_not_magic() {
        let ctx = Context::default();
        for name in [
            "size",
            "contains",
            "startsWith",
            "endsWith",
            "matches",
            "int",
            "uint",
            "double",
            "string",
            "bytes",
        ] {
            assert!(
                ctx.get_function(name).is_none(),
                "{name} is registered as a magic (Value-based) function"
            );
        }
    }
}
