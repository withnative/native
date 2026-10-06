//! Charge table (PR 1a, design §1.3).
//!
//! Every built-in and operator declares its cost **once**, as a pure
//! function from operand *metrics* (nodes, bytes, lengths) to a
//! [`Cost`] of `(wu, mb)`. No evaluation state is read here, so
//! increment 1b's static estimator can call the same functions with
//! bounds. The weights are policy, pinned by `policy_version`; 1b
//! calibrates them.
//!
//! Rows are shared by execution and symbolic estimation. All arithmetic
//! saturates; an abstract u64::MAX is an admission refusal sentinel.
//! Memory is the deterministic scoped logical construction level, not actual
//! allocator bytes. Native input/source/regex loads have separate accounts;
//! guest allocator coupling and the hosted save⇒eval invariant remain PR 2.

/// Per-element / per-entry allocation estimates (bytes). These are
/// deterministic estimates, not allocator truth: a list slot holds a
/// boxed trait object, a map entry holds key + value + hash
/// overhead. Determinism and monotonicity matter, not exactness.
pub(crate) const LIST_ELEM_BYTES: u64 = 32;
pub(crate) const MAP_ENTRY_BYTES: u64 = 64;
/// Byte divisor for size-dependent work rows (design §1.3).
pub(crate) const BYTE_DIVISOR: u64 = 64;

/// A cost: work units and retained-memory bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cost<Q = u64> {
    pub work: Q,
    pub memory: Q,
}

impl Cost {
    pub(crate) const ZERO: Cost = Cost { work: 0, memory: 0 };
}
impl<Q> Cost<Q> {
    pub(crate) const fn new(work: Q, memory: Q) -> Self {
        Cost { work, memory }
    }
}

/// A row's `work` includes the operation's own node visit (the
/// table's leading `1`). The meter charges that visit globally in
/// `enter_node`, so at an operation site this strips it to leave the
/// size-dependent charge.
pub(crate) fn excluding_node_visit(cost: Cost) -> Cost {
    Cost {
        work: if cost.work == u64::MAX {
            u64::MAX
        } else {
            cost.work.saturating_sub(node_visit().work)
        },
        memory: cost.memory,
    }
}

/// Monotone arithmetic used by the SAME rows for runtime integers and symbolic
/// per-row quantities. Symbolic summation can retain ceil rounding and copy
/// multiplicities rather than multiplying every row by the largest possible row.
pub(crate) trait Quantity: Clone {
    fn constant(value: u64) -> Self;
    fn saturating_add(self, other: Self) -> Self;
    fn saturating_mul(self, other: Self) -> Self;
    fn saturating_sub(self, value: u64) -> Self;
    fn min_quantity(self, other: Self) -> Self;
    fn ceil_div(self, divisor: u64) -> Self;
}
impl Quantity for u64 {
    fn constant(value: u64) -> Self {
        value
    }
    fn saturating_add(self, other: Self) -> Self {
        u64::saturating_add(self, other)
    }
    fn saturating_mul(self, other: Self) -> Self {
        if self == u64::MAX || other == u64::MAX {
            u64::MAX
        } else {
            u64::saturating_mul(self, other)
        }
    }
    fn saturating_sub(self, value: u64) -> Self {
        if self == u64::MAX {
            self
        } else {
            u64::saturating_sub(self, value)
        }
    }
    fn min_quantity(self, other: Self) -> Self {
        if self == u64::MAX || other == u64::MAX {
            u64::MAX
        } else {
            Ord::min(self, other)
        }
    }
    fn ceil_div(self, divisor: u64) -> Self {
        if self == u64::MAX {
            u64::MAX
        } else if self == 0 {
            0
        } else {
            (self - 1) / divisor + 1
        }
    }
}
fn ceil_div<Q: Quantity>(a: Q, b: u64) -> Q {
    a.ceil_div(b)
}

// --- §1.3 table rows --------------------------------------------------

/// Any node visit: 1 wu and 8 logical bytes, covering bounded scalar construction.
pub(crate) fn node_visit() -> Cost {
    Cost::new(1, 8)
}

/// string or bytes literal: 1 wu, `len` bytes.
pub(crate) fn string_or_bytes_literal<Q: Quantity>(len: Q) -> Cost<Q> {
    Cost::new(Q::constant(1), len)
}

/// `a == b`, `a != b` on aggregates: 1 + min(nodes a, nodes b) +
/// ⌈(bytes a + bytes b)/64⌉ wu (map equality hashes left-side keys;
/// nested maps inherit this traversal). The deep compare also walks
/// string payloads).
pub(crate) fn equality_aggregate<Q: Quantity>(
    nodes_a: Q,
    bytes_a: Q,
    nodes_b: Q,
    bytes_b: Q,
) -> Cost<Q> {
    Cost::new(
        Q::constant(1)
            .saturating_add(nodes_a.min_quantity(nodes_b))
            .saturating_add(ceil_div(bytes_a.saturating_add(bytes_b), BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `a == b`, `a != b` on scalar strings or bytes: 1 +
/// ⌈min(len a, len b)/64⌉ wu (F4: the compare is O(len)).
pub(crate) fn equality_text<Q: Quantity>(len_a: Q, len_b: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(len_a.min_quantity(len_b), BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `<` … `>=` on strings or bytes: 1 + ⌈min(len a, len b)/64⌉ wu.
pub(crate) fn string_or_bytes_order<Q: Quantity>(len_a: Q, len_b: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(len_a.min_quantity(len_b), BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `x in list`, `list.contains(x)`: 1 + nodes(list) +
/// ⌈bytes(list)/64⌉ wu (F4: the scan compares string payloads).
pub(crate) fn containment_in_list<Q: Quantity>(nodes: Q, bytes: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1)
            .saturating_add(nodes)
            .saturating_add(ceil_div(bytes, BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `k in map`, `m[k]`, `m.k`, `map.contains(k)`: 1 + ⌈len(k)/64⌉ wu.
pub(crate) fn map_key_lookup<Q: Quantity>(key_len: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(key_len, BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `s.contains(t)`, `startsWith`, `endsWith`: 1 + ⌈(len s + len t)/64⌉ wu.
pub(crate) fn string_contains<Q: Quantity>(len_s: Q, len_t: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(len_s.saturating_add(len_t), BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `s + t` (strings or bytes): 1 + ⌈(len s + len t)/64⌉ wu,
/// `len s + len t` bytes.
pub(crate) fn string_concat<Q: Quantity>(len_s: Q, len_t: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(
            len_s.clone().saturating_add(len_t.clone()),
            BYTE_DIVISOR,
        )),
        len_s.saturating_add(len_t),
    )
}

/// `l + r`, fresh list: 1 + nodes(l) + nodes(r) wu,
/// bytes(l) + bytes(r).
pub(crate) fn list_concat<Q: Quantity>(nodes_l: Q, bytes_l: Q, nodes_r: Q, bytes_r: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1)
            .saturating_add(nodes_l)
            .saturating_add(nodes_r)
            .saturating_add(ceil_div(
                bytes_l.clone().saturating_add(bytes_r.clone()),
                BYTE_DIVISOR,
            )),
        bytes_l.saturating_add(bytes_r),
    )
}

/// `@result + [e]` in `map`/`filter`, in place: 1 + nodes(e) wu,
/// bytes(e) + [`LIST_ELEM_BYTES`], including copied payload work.
pub(crate) fn list_append_in_place<Q: Quantity>(nodes_e: Q, bytes_e: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1)
            .saturating_add(nodes_e)
            .saturating_add(ceil_div(bytes_e.clone(), BYTE_DIVISOR)),
        bytes_e.saturating_add(Q::constant(LIST_ELEM_BYTES)),
    )
}

/// list literal: 1 per element + nodes of each copied element;
/// [`LIST_ELEM_BYTES`] per element + bytes of the values.
pub(crate) fn list_literal<Q: Quantity>(
    element_count: Q,
    elements_nodes: Q,
    elements_bytes: Q,
) -> Cost<Q> {
    Cost::new(
        element_count.clone().saturating_add(elements_nodes),
        Q::constant(LIST_ELEM_BYTES)
            .saturating_mul(element_count)
            .saturating_add(elements_bytes),
    )
}

/// map literal from a constructed map's rollup: `nodes` counts the
/// map's own node, `bytes` the entry slots + keys + values. Work is
/// `1 per entry + nodes of each copied value` (rollup nodes − 1).
pub(crate) fn map_literal_rollup<Q: Quantity>(entry_count: Q, nodes: Q, bytes: Q) -> Cost<Q> {
    Cost::new(entry_count.saturating_add(nodes.saturating_sub(1)), bytes)
}

/// Classified macro reference binding: one bind and one fixed pointer slot.
/// The range retains its payload; this row performs no payload copy.
pub(crate) fn comprehension_item_bind_ref() -> Cost {
    Cost::new(1, 8)
}

/// comprehension item bind: `1` (the bind; a reference once U9's
/// borrowing lands) + nodes(item) while it still deep-copies +
/// ⌈bytes(item)/64⌉ (F4: the copy is O(len) for strings).
pub(crate) fn comprehension_item_bind<Q: Quantity>(nodes: Q, bytes: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1)
            .saturating_add(nodes)
            .saturating_add(ceil_div(bytes.clone(), BYTE_DIVISOR)),
        bytes,
    )
}

/// `size(string)`: 1 + ⌈len/64⌉ wu (F4: the code-point count walks
/// the payload). Other `size` shapes are O(1) and charge nothing
/// beyond the node visit.
pub(crate) fn size_string<Q: Quantity>(len: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(len, BYTE_DIVISOR)),
        Q::constant(0),
    )
}

/// `string(x)` / `bytes(x)` conversions: 1 + ⌈bytes(arg)/64⌉ wu
/// (F4: the result copy and string parses are O(len)).
pub(crate) fn string_or_bytes_conversion<Q: Quantity>(arg_bytes: Q, output_bytes: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1)
            .saturating_add(ceil_div(arg_bytes, BYTE_DIVISOR))
            .saturating_add(ceil_div(output_bytes.clone(), BYTE_DIVISOR)),
        output_bytes,
    )
}
pub(crate) fn string_parse<Q: Quantity>(arg_bytes: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(arg_bytes, BYTE_DIVISOR)),
        Q::constant(8),
    )
}
pub(crate) fn payload_copy<Q: Quantity>(nodes: Q, bytes: Q) -> Cost<Q> {
    Cost::new(
        nodes.saturating_add(ceil_div(bytes.clone(), BYTE_DIVISOR)),
        bytes,
    )
}
pub(crate) fn list_extremum<Q: Quantity>(len: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(len.saturating_mul(Q::constant(2))),
        Q::constant(0),
    )
}
pub(crate) fn extremum_result() -> Cost {
    payload_copy(1, 8)
}
pub(crate) fn regex_search<Q: Quantity>(len: Q, tier: Q, k: u64) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(len.saturating_mul(tier), k.max(1))),
        Q::constant(0),
    )
}
pub(crate) fn regex_compile<Q: Quantity>(tier: Q) -> Cost<Q> {
    Cost::new(tier.clone(), tier)
}

/// Payload bytes copied into a list or map literal (F4 remainder,
/// round 3): ⌈bytes/64⌉ wu, charged alongside the U8 literal row
/// before the copies, from the elements' already-cached byte metrics
/// (O(1)) — so strings nested inside an element are charged, not
/// just top-level text. The U8 row's memory column already covers
/// the payload bytes; this adds only the work term.
pub(crate) fn literal_text_payload<Q: Quantity>(text_bytes: Q) -> Cost<Q> {
    Cost::new(ceil_div(text_bytes, BYTE_DIVISOR), Q::constant(0))
}

/// select or index owning a copy of a string or bytes payload: 1 +
/// ⌈len/64⌉ wu (F4b: the copy is O(len)). A borrowed operand costs
/// only the node visit, per U6.
pub(crate) fn aggregate_select_text<Q: Quantity>(len: Q) -> Cost<Q> {
    Cost::new(
        Q::constant(1).saturating_add(ceil_div(len.clone(), BYTE_DIVISOR)),
        len,
    )
}

/// select or index returning an aggregate: `nodes(v)` while it still
/// copies; zero once the select borrows (U6).
pub(crate) fn aggregate_select<Q: Quantity>(nodes: Q, bytes: Q) -> Cost<Q> {
    payload_copy(nodes, bytes)
}

/// Result emission: nodes + rounded payload work; deep output bytes.
pub(crate) fn result_emission<Q: Quantity>(nodes: Q, bytes: Q) -> Cost<Q> {
    payload_copy(nodes, bytes)
}

/// input decode (load phase): nodes decoded + ⌈bytes/64⌉ wu, into a
/// separate input account. Wired in PR 1b (input contract) / PR 2
/// (guest codec); this crate's `evaluate` takes already-decoded
/// bindings, so it is not called here (U13).
#[allow(dead_code)]
pub(crate) fn input_decode<Q: Quantity>(nodes: Q, bytes: Q) -> Cost<Q> {
    payload_copy(nodes, bytes)
}

/// Bounded diagnostics include a temporary Double Display (up to 344 bytes)
/// plus the retained <=64-byte descriptor; 448 prices overlapping payloads.
pub(crate) const RETAINED_ERROR_BYTES: u64 = 1024;

pub(crate) fn diagnostic() -> Cost {
    payload_copy(1, 448)
}

/// Source/load work is a separate phase, never an evaluation allowance.
pub(crate) fn source_compile<Q: Quantity>(bytes: Q) -> Cost<Q> {
    Cost::new(bytes.clone(), bytes.saturating_mul(Q::constant(64)))
}

/// U11 retention mechanism: charge a retained value's deep bytes at a
/// bind or slot. Not a §1.3 row of its own — it is what makes the
/// literal/concat rows O(1) until the specific rows (U3/U9) land.
pub(crate) fn retention<Q: Quantity>(bytes: Q) -> Cost<Q> {
    Cost::new(Q::constant(0), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn symbolic_rows_saturate_without_panicking() {
        for a in [0, u64::MAX - 1, u64::MAX] {
            for b in [0, u64::MAX - 1, u64::MAX] {
                let rows = [
                    equality_aggregate(a, b, a, b),
                    equality_text(a, b),
                    string_or_bytes_order(a, b),
                    containment_in_list(a, b),
                    map_key_lookup(a),
                    string_contains(a, b),
                    string_concat(a, b),
                    list_concat(a, b, a, b),
                    list_append_in_place(a, b),
                    list_literal(a, b, a),
                    map_literal_rollup(a, b, a),
                    comprehension_item_bind(a, b),
                    size_string(a),
                    string_or_bytes_conversion(a, b),
                    payload_copy(a, b),
                    list_extremum(a),
                    regex_search(a, b, 1),
                    result_emission(a, b),
                ];
                for row in rows {
                    assert!(row.work > 0 || a == 0 && b == 0);
                }
                if a == u64::MAX {
                    assert_eq!(list_extremum(a).work, u64::MAX);
                }
            }
        }
    }
}

#[cfg(test)]
mod overflow_tests {
    use super::*;
    #[test]
    fn overflow_sentinel_survives_reductions_and_rounding() {
        assert_eq!(Quantity::saturating_mul(u64::MAX, 0), u64::MAX);
        assert_eq!(Quantity::saturating_mul(0, u64::MAX), u64::MAX);
        assert_eq!(Quantity::saturating_mul(0, u64::MAX - 1), 0);
        assert_eq!(regex_search(u64::MAX, 16384, 64).work, u64::MAX);
        assert_eq!(regex_search(u64::MAX / 16384 + 1, 16384, 64).work, u64::MAX);
        assert_eq!(string_contains(u64::MAX, u64::MAX).work, u64::MAX);
        assert_eq!(string_contains(u64::MAX - 1, 2).work, u64::MAX);
        assert_eq!(excluding_node_visit(Cost::new(u64::MAX, 0)).work, u64::MAX);
        assert_eq!(map_literal_rollup(0, u64::MAX, 0).work, u64::MAX);
        assert_eq!(
            Quantity::ceil_div(u64::MAX - 1, 64),
            (u64::MAX - 2) / 64 + 1
        );
        assert_eq!(regex_search(64, 64, 64).work, 65);
        assert_eq!(regex_search(65, 64, 64).work, 66);
    }
}
