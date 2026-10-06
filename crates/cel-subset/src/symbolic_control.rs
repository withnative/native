//! Native check auxiliary control, separate from runtime W/H and load metrics.
//! Counts cumulative construction/table cells, so live storage cannot exceed
//! these counts. Refusal is sticky and checked before each controlled allocation.
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub(crate) struct Counts {
    pub nodes: u64,
    pub visits: u64,
    pub cells: u64,
    pub shapes: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum Resource {
    Nodes,
    Visits,
    Cells,
    Shapes,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Refusal {
    pub cap: &'static str,
    pub measured: u64,
    pub limit: u64,
}
#[derive(Clone, Copy)]
struct State {
    counts: Counts,
    limits: Counts,
    refusal: Option<Refusal>,
}
// Provisional native candidates; these bound check control, not CEL resource costs.
// Table cells include traversal/memo entries AND copied affine coefficients.
const LIMITS: Counts = Counts {
    nodes: 250_000,
    visits: 1_000_000,
    cells: 1_000_000,
    shapes: 16_384,
};
#[cfg(any(test, feature = "native-proof-tools"))]
pub(crate) fn limits() -> Counts {
    LIMITS
}
thread_local! { static STATE: RefCell<Option<State>> = const { RefCell::new(None) }; }
pub(crate) fn spend(resource: Resource, amount: usize) -> bool {
    STATE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(state) = slot.as_mut() else {
            return true;
        };
        if state.refusal.is_some() {
            return false;
        }
        let (count, limit, cap) = match resource {
            Resource::Nodes => (
                &mut state.counts.nodes,
                state.limits.nodes,
                "symbolic_nodes",
            ),
            Resource::Visits => (
                &mut state.counts.visits,
                state.limits.visits,
                "symbolic_visits",
            ),
            Resource::Cells => (
                &mut state.counts.cells,
                state.limits.cells,
                "symbolic_cells",
            ),
            Resource::Shapes => (
                &mut state.counts.shapes,
                state.limits.shapes,
                "symbolic_shapes",
            ),
        };
        let measured = count.saturating_add(amount as u64);
        if measured > limit {
            state.refusal = Some(Refusal {
                cap,
                measured,
                limit,
            });
            false
        } else {
            *count = measured;
            true
        }
    })
}
pub(crate) fn refusal() -> Option<Refusal> {
    STATE.with(|slot| slot.borrow().as_ref().and_then(|s| s.refusal))
}
pub(crate) fn account<R>(f: impl FnOnce() -> R) -> (R, Counts, Option<Refusal>) {
    account_limits(LIMITS, f)
}
pub(crate) fn account_limits<R>(
    limits: Counts,
    f: impl FnOnce() -> R,
) -> (R, Counts, Option<Refusal>) {
    struct Restore(Option<State>);
    impl Drop for Restore {
        fn drop(&mut self) {
            STATE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let previous = STATE.with(|slot| {
        slot.replace(Some(State {
            counts: Counts::default(),
            limits,
            refusal: None,
        }))
    });
    let _restore = Restore(previous);
    let result = f();
    let state = STATE.with(|slot| slot.borrow().expect("active symbolic account"));
    (result, state.counts, state.refusal)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_refuse_before_allocation_and_restore_the_outer_account() {
        let (_, counts, refusal) = account_limits(
            Counts {
                nodes: 2,
                visits: 2,
                cells: 2,
                shapes: 2,
            },
            || {
                assert!(spend(Resource::Nodes, 2));
                assert!(!spend(Resource::Nodes, 1));
                assert!(!spend(Resource::Cells, 1));
                let (_, nested, _) = account(|| assert!(spend(Resource::Cells, 1)));
                assert_eq!(nested.cells, 1);
                assert!(!spend(Resource::Visits, 1));
            },
        );
        assert_eq!(counts.nodes, 2);
        assert_eq!(counts.cells, 0);
        assert_eq!(refusal.unwrap().cap, "symbolic_nodes");
        assert!(spend(Resource::Nodes, usize::MAX)); // outside check: semantic helpers
    }
}
