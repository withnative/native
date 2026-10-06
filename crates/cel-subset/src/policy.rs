//! Measured native CEL subset policy (PR 1b, design §7.3).
//!
//! A `Policy` names one whole-evaluation budget. Every entry point
//! takes a `&Policy`, so there is no unbudgeted path: `Policy` has
//! no `Default`. [`Policy::P1`] is the measured native PR 1b entry;
//! hosted save-to-evaluate evidence waits for PR 2.
//!
//! The limits map onto the two meters ([`crate::meter::Budget`]):
//! `work_limit` is the work budget in wu and `mem_limit_bytes` is the
//! memory budget in mb. Depth is not a budget knob (design §1.3).
//!
//! Construction is closed (review F5): the fields are private and
//! the only values are the named policy constants below, so no
//! caller can forge a budget, a regex tier ladder or `interim:
//! false`. This doctest fails to compile — and so passes — exactly
//! while that holds:
//!
//! <!-- native-doctest-id: cel-subset-policy-no-struct-literal -->
//! ```compile_fail
//! # use cel::Policy;
//! // `Policy` fields are private: no forged policy can be built.
//! let _ = Policy {
//!     id: "cel-subset@1/p1",
//!     interim: false,
//!     work_limit: u64::MAX,
//!     mem_limit_bytes: u64::MAX,
//!     regex_size_tiers: &[usize::MAX],
//!     regex_nest_limit: u32::MAX,
//!     regex_k_re: u64::MAX,
//!     regex_max_pattern_bytes: usize::MAX,
//! };
//! ```

use crate::meter::Budget;

/// One named whole-evaluation budget.
///
/// Fields are private: a `Policy` can only come from the named
/// constant [`Policy::P1`]. Read-only getters
/// expose the values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Entry id, `"cel-subset@1/p1"` in production builds.
    id: &'static str,
    /// Interim entries make no save⇒eval claim; PR 4's adapter must
    /// refuse to issue evidence under one (design §7.1).
    interim: bool,
    /// Work budget in work units (wu).
    work_limit: u64,
    /// Memory budget in bytes (mb); enforced as the scoped
    /// high-water mark.
    mem_limit_bytes: u64,
    /// `matches` NFA size-tier ladder in bytes (design §1.3/§2.3): the
    /// smallest tier at which a literal pattern compiles is its `t(p)`.
    ///
    /// Native candidates were measured against counted repetition, alternation,
    /// nesting and search adversaries. Absolute guest fuel calibration is PR 2.
    regex_size_tiers: &'static [usize],
    /// Native `RegexBuilder::nest_limit` (N), pinned at 32 for P1.
    regex_nest_limit: u32,
    /// `matches` reference NFA size (K_re in §1.3): the search charge is
    /// `1 + ⌈len(s) × t(p) / regex_k_re⌉`. Native relative scaling is 64;
    /// this is not a guest fuel ratio.
    regex_k_re: u64,
    /// Largest admitted `matches` literal pattern: 256 bytes (§2.3 L1).
    regex_max_pattern_bytes: usize,
    input_count_max: usize,
    string_bytes_max: usize,
    guard_work_limit: u64,
    guard_mem_limit: u64,
}

impl Policy {
    /// Measured native policy `cel-subset@1/p1`. Native estimator/meter proof
    /// is separate from guest fuel, allocator memory and stack compositions.
    /// `interim` stays true until PR 2; hosted validation evidence is unavailable.
    pub const P1: Policy = Policy {
        id: "cel-subset@1/p1",
        interim: true,
        work_limit: 16_000_000,
        mem_limit_bytes: 384 * 1024 * 1024,
        regex_size_tiers: &[256, 1024, 4096],
        regex_nest_limit: 32,
        regex_k_re: 64,
        regex_max_pattern_bytes: 256,
        input_count_max: 16,
        string_bytes_max: 4096,
        guard_work_limit: 16_000_000,
        guard_mem_limit: 1024 * 1024,
    };
    /// The single PR 1a entry (`cel-subset@1/p0-interim`): W =
    /// 2,000,000 wu, M = 8 MiB, `interim: true` (design §7.1).
    ///
    /// This is the spike's per-clause calibration, applied here to
    /// one whole rule per [`crate::evaluate`] call. In the guest it
    /// stays per-execution until PR 2 (review N2); the evaluation
    /// report says so.
    #[cfg(any(test, feature = "native-proof-tools"))]
    pub(crate) const P0_INTERIM: Policy = Policy {
        id: "cel-subset@1/p0-interim",
        interim: true,
        work_limit: 2_000_000,
        mem_limit_bytes: 8 * 1024 * 1024,
        // Provisional (design §1.3/§2.3): 1, 4 and 16 KiB placeholders,
        // a generous nest limit, and the 256-byte pattern cap. PR 1b
        // measures the ladder and N from the adversarial set.
        regex_size_tiers: &[1024, 4096, 16384],
        // regex-lite's own default nest limit is 50 (hir::Config::default).
        regex_nest_limit: 50,
        regex_k_re: 64,
        regex_max_pattern_bytes: 256,
        input_count_max: 32,
        string_bytes_max: 1024 * 1024,
        guard_work_limit: 2_000_000,
        guard_mem_limit: 8 * 1024 * 1024,
    };

    /// Test-only second entry: same budgets, a different id, so
    /// `evaluate`'s policy-mismatch refusal has something to refuse.
    #[cfg(test)]
    pub(crate) const P_TEST_OTHER: Policy = Policy {
        id: "cel-subset@1/p-test-other",
        interim: true,
        work_limit: 2_000_000,
        mem_limit_bytes: 8 * 1024 * 1024,
        regex_size_tiers: &[1024, 4096, 16384],
        regex_nest_limit: 50,
        regex_k_re: 64,
        regex_max_pattern_bytes: 256,
        input_count_max: 32,
        string_bytes_max: 1024 * 1024,
        guard_work_limit: 2_000_000,
        guard_mem_limit: 8 * 1024 * 1024,
    };

    // Private named measurement domains, not frozen P1 entries. Runtime and
    // admission use these same candidate ceilings; final values follow evidence.
    #[cfg(any(test, feature = "native-proof-tools"))]
    pub(crate) const MEASUREMENT_CANDIDATES: [Self; 5] = [
        Self {
            id: "cel-subset@1/measure-s1024-i8",
            input_count_max: 8,
            string_bytes_max: 1024,
            work_limit: 8_000_000,
            mem_limit_bytes: 128 * 1024 * 1024,
            guard_work_limit: 8_000_000,
            guard_mem_limit: 128 * 1024 * 1024,
            ..Self::P0_INTERIM
        },
        Self {
            id: "cel-subset@1/measure-s4096-i16",
            input_count_max: 16,
            string_bytes_max: 4096,
            work_limit: 8_000_000,
            mem_limit_bytes: 128 * 1024 * 1024,
            guard_work_limit: 8_000_000,
            guard_mem_limit: 128 * 1024 * 1024,
            ..Self::P0_INTERIM
        },
        Self {
            id: "cel-subset@1/measure-s16384-i32",
            input_count_max: 32,
            string_bytes_max: 16384,
            work_limit: 8_000_000,
            mem_limit_bytes: 128 * 1024 * 1024,
            guard_work_limit: 8_000_000,
            guard_mem_limit: 128 * 1024 * 1024,
            ..Self::P0_INTERIM
        },
        // Alternative regex/control sweeps. M follows the measured conservative
        // three-copy whole-row envelope; H remains logical scoped accounting.
        // Neither entry is a frozen production policy.
        Self {
            id: "cel-subset@1/measure-s4096-i16-re256-n32-k64",
            input_count_max: 16,
            string_bytes_max: 4096,
            work_limit: 16_000_000,
            mem_limit_bytes: 384 * 1024 * 1024,
            guard_work_limit: 16_000_000,
            guard_mem_limit: 1024 * 1024,
            regex_size_tiers: &[256, 1024, 4096],
            regex_nest_limit: 32,
            regex_k_re: 64,
            ..Self::P0_INTERIM
        },
        Self {
            id: "cel-subset@1/measure-s4096-i16-re512-n24-k128",
            input_count_max: 16,
            string_bytes_max: 4096,
            work_limit: 32_000_000,
            mem_limit_bytes: 384 * 1024 * 1024,
            guard_work_limit: 32_000_000,
            guard_mem_limit: 1024 * 1024,
            regex_size_tiers: &[512, 2048, 8192],
            regex_nest_limit: 24,
            regex_k_re: 128,
            ..Self::P0_INTERIM
        },
    ];
    /// Entry id, `"cel-subset@1/p1"` in production builds.
    pub fn id(&self) -> &'static str {
        self.id
    }

    /// Interim entries make no save⇒eval claim.
    pub fn interim(&self) -> bool {
        self.interim
    }

    /// Work budget in work units (wu).
    pub fn work_limit(&self) -> u64 {
        self.work_limit
    }

    /// Memory budget in bytes (mb).
    pub fn mem_limit_bytes(&self) -> u64 {
        self.mem_limit_bytes
    }

    /// `matches` NFA size-tier ladder in bytes.
    pub fn regex_size_tiers(&self) -> &'static [usize] {
        self.regex_size_tiers
    }

    /// `matches` `RegexBuilder::nest_limit` (N).
    pub fn regex_nest_limit(&self) -> u32 {
        self.regex_nest_limit
    }

    /// `matches` reference NFA size (K_re in §1.3).
    pub fn regex_k_re(&self) -> u64 {
        self.regex_k_re
    }

    /// Largest admitted `matches` literal pattern in bytes.
    pub fn regex_max_pattern_bytes(&self) -> usize {
        self.regex_max_pattern_bytes
    }

    /// Row-input declaration ceiling: measured P1 or a private evidence candidate.
    pub(crate) fn input_count_candidate(&self) -> usize {
        self.input_count_max
    }
    /// Scalar string ceiling: measured P1 or a private evidence candidate.
    pub(crate) fn string_bytes_candidate(&self) -> usize {
        self.string_bytes_max
    }

    /// Separate bounded native load account derived from B: E <= B/5, row slots <=
    /// 32*5000*Imax, and map payload <=72E+B. Separate from W/M.
    pub(crate) fn input_load_budget(&self) -> Budget {
        Budget {
            work: 8 * crate::input::TOTAL_INPUT_BYTES,
            memory: 32 * crate::input::TOTAL_INPUT_BYTES,
        }
    }
    /// Bounded L0 source and attempted regex tiers; measured separately.
    pub(crate) fn check_load_budget(&self) -> Budget {
        Budget {
            work: 32 * 1024 * 1024,
            memory: 32 * 1024 * 1024,
        }
    }

    /// Separate native guard account; rules and guards never share counters.
    pub(crate) fn guard_budget(self) -> Budget {
        Budget {
            work: self.guard_work_limit,
            memory: self.guard_mem_limit,
        }
    }
    pub fn guard_work_limit(&self) -> u64 {
        self.guard_budget().work
    }
    pub fn guard_mem_limit_bytes(&self) -> u64 {
        self.guard_budget().memory
    }

    /// The meter budget this policy enforces (crate-visible).
    pub(crate) fn to_budget(self) -> Budget {
        Budget {
            work: self.work_limit,
            memory: self.mem_limit_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{check, evaluate, Bindings, ExecutionError};

    #[test]
    fn private_named_domains_use_public_gates_and_runtime_rows() {
        use crate::{api, Declarations, InputDecl, InputKind, Value};
        for policy in Policy::MEASUREMENT_CANDIDATES {
            let d = Declarations::new(
                [
                    InputDecl {
                        name: "rows".into(),
                        kind: InputKind::Many,
                    },
                    InputDecl {
                        name: "one".into(),
                        kind: InputKind::One,
                    },
                ],
                &policy,
            )
            .unwrap();
            let one = Value::from(indexmap::IndexMap::from([
                ("n".to_string(), Value::Int(1)),
                (
                    "body".to_string(),
                    Value::from("x".repeat(policy.string_bytes_candidate())),
                ),
            ]));
            let row = Value::from(indexmap::IndexMap::from([("n".to_string(), Value::Int(1))]));
            let mut b = Bindings::empty(&d, &policy);
            b.insert("one", &one).unwrap();
            b.insert("rows", &Value::from(vec![row; 5000])).unwrap();
            for source in [
                "rows.all(r,true)",
                "min(rows.map(r,r.n))",
                "rows.map(r,r.n).max()",
                "(true?one:0).body",
                "[(true?one:0).body].map(x,bytes(string(x)))",
                "(true?one:0).body.matches('x')",
                "[]+one",
            ] {
                let p = api::check(source, &d, &policy).result.unwrap();
                let r = evaluate(&p, &b, &policy);
                assert!(
                    r.cost.work <= p.bound().work && r.cost.memory <= p.bound().memory,
                    "{} {source}: {:?} {:?}",
                    policy.id(),
                    r.cost,
                    p.bound()
                );
                if let Ok(value) = r.result {
                    let (nodes, bytes) = crate::load::metrics(&value);
                    assert!(nodes <= p.bound().result_nodes && bytes <= p.bound().result_bytes);
                } else {
                    assert_eq!(source, "[]+one");
                    assert!(matches!(r.result, Err(ExecutionError::NoSuchOverload)));
                }
            }
            let product = api::check("rows.all(r,rows.all(t,true))", &d, &policy)
                .result
                .unwrap_err();
            assert!(product.to_string().contains("cross_product"));
            let larger = Declarations::new(
                (0..32).map(|i| InputDecl {
                    name: format!("in{i}"),
                    kind: InputKind::One,
                }),
                &Policy::P0_INTERIM,
            )
            .unwrap();
            if policy.input_count_candidate() < 32 {
                assert!(api::check("true", &larger, &policy).result.is_err());
            }
        }
    }
    /// `evaluate` refuses a `Prepared` checked under a different
    /// policy, and accepts one checked under the same policy.
    #[test]
    fn evaluate_refuses_policy_mismatch() {
        let under_p0 = check("1 + 1", &Policy::P0_INTERIM).result.expect("check");
        let report = evaluate(&under_p0, &Bindings::new(), &Policy::P_TEST_OTHER);
        assert!(
            matches!(report.result, Err(ExecutionError::PolicyMismatch(_))),
            "mismatched policy must be refused, got {:?}",
            report.result
        );

        let under_other = check("1 + 1", &Policy::P_TEST_OTHER).result.expect("check");
        let report = evaluate(&under_other, &Bindings::new(), &Policy::P0_INTERIM);
        assert!(
            matches!(report.result, Err(ExecutionError::PolicyMismatch(_))),
            "mismatched policy must be refused, got {:?}",
            report.result
        );

        let report = evaluate(&under_p0, &Bindings::new(), &Policy::P0_INTERIM);
        assert!(
            report.result.is_ok(),
            "same policy must pass: {:?}",
            report.result
        );
    }
}
