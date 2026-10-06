//! Payload-before-copy regression checks; no unbudgeted public escape hatch.
use crate::meter::Budget;
use crate::{Context, ExecutionError, Program};

#[test]
fn long_payload_copies_refuse_before_body() {
    for source in [
        "body",
        "string(body)",
        "bytes(body)",
        "rows + rows",
        "rows.map(r,r.body)",
        "{body: 0}",
    ] {
        let mut context = Context::default();
        context.add_variable_from_value("body", "x".repeat(4096));
        context.add_variable_from_value(
            "rows",
            vec![indexmap::IndexMap::from([("body", "x".repeat(4096))])],
        );
        let p = Program::compile(source).unwrap();
        crate::meter::reset_body_runs();
        let (result, _) = p.execute_budgeted(
            &context,
            Budget {
                work: 20,
                memory: 20,
            },
        );
        assert!(
            matches!(
                result,
                Err(ExecutionError::WorkBudgetExceeded(_) | ExecutionError::MemoryBudgetExceeded(_))
            ),
            "{source}: {result:?}"
        );
        assert_eq!(
            crate::meter::op_bodies(),
            u64::from(source == "rows.map(r,r.body)"),
            "{source}: only the empty accumulator initialization may run"
        );
    }
}

#[test]
fn aggregate_map_keys_are_rejected_without_cloning() {
    use crate::common::types::{Type, LIST_TYPE};
    use crate::common::value::Val;
    use std::fmt::Debug;
    #[derive(Debug)]
    struct NoClone;
    impl Val for NoClone {
        fn get_type(&self) -> &Type {
            &LIST_TYPE
        }
        fn clone_as_boxed(&self) -> Box<dyn Val> {
            panic!("invalid key was cloned")
        }
    }
    for source in ["rows in {}", "{}[rows]", "{rows: 1/0}", "{}.contains(rows)"] {
        let mut context = Context::default();
        context.add_variable_as_val("rows", Box::new(NoClone));
        let (result, _) = Program::compile(source).unwrap().execute_budgeted(
            &context,
            Budget {
                work: 1000,
                memory: 1000,
            },
        );
        assert!(
            matches!(
                result,
                Err(ExecutionError::UnsupportedKeyType(_) | ExecutionError::NoSuchOverload)
            ),
            "{source}: {result:?}"
        );
    }
}

#[test]
fn numeric_formatter_bound_covers_internal_double_extremes() {
    for value in [
        f64::MIN_POSITIVE,
        f64::from_bits(1),
        f64::MAX,
        -f64::MAX,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        -0.0,
    ] {
        assert!(value.to_string().len() <= 344);
        let mut context = Context::default();
        context.add_variable_from_value("x", value);
        let (result, cost) = Program::compile("string(x)").unwrap().execute_budgeted(
            &context,
            Budget {
                work: 1000,
                memory: 1000,
            },
        );
        assert!(result.is_ok());
        assert!(cost.memory >= 344);
    }
}

#[test]
fn aggregate_equality_prices_long_left_keys_with_two_entry_rhs() {
    for source in [
        "one == {'x':0,'y':0}",
        "one != {'x':0,'y':0}",
        "[one] == [{'x':0,'y':0}]",
    ] {
        let mut context = Context::default();
        context.add_variable_from_value(
            "one",
            indexmap::IndexMap::from([("q".repeat(4096), 0i64), ("y".into(), 0)]),
        );
        let (result, cost) = Program::compile(source).unwrap().execute_budgeted(
            &context,
            Budget {
                work: u64::MAX,
                memory: u64::MAX,
            },
        );
        assert!(result.is_ok());
        assert!(
            cost.work >= 64,
            "{source}: left-key hashing not priced: {cost:?}"
        );
    }
}
#[test]
fn conversion_and_bad_index_error_payloads_are_precharged() {
    for source in [
        "uint(-1)",
        "int(18446744073709551615u)",
        "[1][true]",
        "[1][0.5]",
    ] {
        let p = Program::compile(source).unwrap();
        let (result, cost) = p.execute_budgeted(
            &Context::default(),
            Budget {
                work: u64::MAX,
                memory: u64::MAX,
            },
        );
        assert!(result.is_err());
        assert!(
            cost.memory >= crate::charges::diagnostic().memory,
            "{source}: {cost:?}"
        );
        let (result, _) = p.execute_budgeted(
            &Context::default(),
            Budget {
                work: u64::MAX,
                memory: 128,
            },
        );
        assert!(
            matches!(result, Err(ExecutionError::MemoryBudgetExceeded(_))),
            "{source}: {result:?}"
        );
    }
}
#[test]
fn owned_list_select_preserves_index_and_remainder_is_discarded() {
    for index in ["0", "1u", "2.0"] {
        let source = format!("[10,20,30][{index}]");
        let expected = match index {
            "0" => 10,
            "1u" => 20,
            _ => 30,
        };
        let (result, _) = Program::compile(&source).unwrap().execute_budgeted(
            &Context::default(),
            Budget {
                work: 1000,
                memory: 1000,
            },
        );
        assert_eq!(result, Ok(crate::Value::Int(expected)));
    }
}

#[test]
fn macro_bindings_and_singleton_ranges_borrow_without_payload_clone() {
    use crate::common::traits::Sizer;
    use crate::common::types::{CelInt, Type, MAP_TYPE};
    use crate::common::value::Val;
    #[derive(Debug)]
    struct NoClone;
    impl Sizer for NoClone {
        fn size(&self) -> CelInt {
            CelInt::from(10_000)
        }
    }
    impl Val for NoClone {
        fn get_type(&self) -> &Type {
            &MAP_TYPE
        }
        fn as_sizer(&self) -> Option<&dyn Sizer> {
            Some(self)
        }
        fn cached_nodes(&self) -> u64 {
            10_001
        }
        fn cached_bytes(&self) -> u64 {
            1_000_000
        }
        fn clone_as_boxed(&self) -> Box<dyn Val> {
            panic!("unobservable payload was cloned")
        }
    }
    let mut ctx = Context::default();
    ctx.add_variable_as_val("one", Box::new(NoClone));
    ctx.add_variable_from_value("rows", vec![1, 2, 3]);
    for source in [
        "[one].all(q,size(q)==10000)",
        "[one].exists(q,size(q)==10000)",
        "[one].exists_one(q,size(q)==10000)",
        "[one].map(q,size(q))",
        "rows.map(r,[one].all(q,size(q)==10000))",
    ] {
        let (r, cost) = Program::compile(source).unwrap().execute_budgeted(
            &ctx,
            Budget {
                work: 1000,
                memory: 10000,
            },
        );
        assert!(r.is_ok(), "{source}: {r:?}");
        assert!(cost.work < 1000 && cost.memory < 10000);
    }
    // A kept result STILL copies payload, and refuses before that clone hook.
    for source in ["[one].map(q,q)", "[one].filter(q,true)"] {
        let (r, _) = Program::compile(source).unwrap().execute_budgeted(
            &ctx,
            Budget {
                work: 1000,
                memory: 10000,
            },
        );
        assert!(
            matches!(
                r,
                Err(ExecutionError::WorkBudgetExceeded(_) | ExecutionError::MemoryBudgetExceeded(_))
            ),
            "{source}: {r:?}"
        );
    }
    assert_eq!(
        crate::charges::comprehension_item_bind_ref(),
        crate::charges::Cost::new(1, 8)
    );
}
