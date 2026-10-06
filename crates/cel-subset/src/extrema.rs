//! Homogeneous numeric list extrema; mixed-kind error takes precedence over NaN.
use crate::common::types::{CelDouble, CelList, Kind, LIST_TYPE};
use crate::common::value::Val;
use crate::{Env, ExecutionError};
use std::borrow::Cow;
use std::cmp::Ordering;

fn extremum<'a>(
    args: Vec<Cow<'a, dyn Val>>,
    maximum: bool,
) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    let list = args
        .first()
        .and_then(|v| v.downcast_ref::<CelList>())
        .ok_or(ExecutionError::NoSuchOverload)?;
    crate::meter::charge_cost(crate::charges::list_extremum(list.len() as u64))?;
    crate::meter::note_op_body();
    let Some(first) = list.inner().first() else {
        return Err(ExecutionError::function_error(
            if maximum { "max" } else { "min" },
            "empty numeric list",
        ));
    };
    let kind = first.get_type().kind();
    let mut mixed = !matches!(kind, Kind::Int | Kind::UInt | Kind::Double);
    let mut nan = false;
    let mut winner = first.as_ref();
    // Inspect all kinds/NaNs even after an invalid item. This pins mixed before
    // NaN, independent of order/likely winner, without copying any payload.
    for value in list.inner() {
        mixed |= value.get_type().kind() != kind;
        let is_nan = value
            .downcast_ref::<CelDouble>()
            .is_some_and(|n| n.inner().is_nan());
        nan |= is_nan;
        if !mixed && !nan {
            let order = value
                .as_comparer()
                .ok_or(ExecutionError::NoSuchOverload)?
                .compare(winner)?;
            if order
                == if maximum {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            {
                winner = value.as_ref();
            }
        }
    }
    if mixed {
        return Err(ExecutionError::NoSuchOverload);
    }
    if nan {
        return Err(ExecutionError::function_error(
            if maximum { "max" } else { "min" },
            "unordered NaN in numeric list",
        ));
    }
    crate::meter::charge_cost(crate::charges::extremum_result())?;
    crate::meter::note_op_body();
    Ok(Cow::Owned(winner.clone_as_boxed()))
}
fn min<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    extremum(args, false)
}
fn max<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    extremum(args, true)
}
pub(crate) fn stdlib(env: &mut Env) {
    for (name, op) in [
        ("min", min as crate::common::functions::Function),
        ("max", max as crate::common::functions::Function),
    ] {
        env.add_overload(name, &format!("{name}_list"), vec![LIST_TYPE], op)
            .expect("unique extrema");
        env.add_member_overload(name, &format!("list_{name}"), LIST_TYPE, vec![], op)
            .expect("unique extrema");
    }
}

#[cfg(test)]
mod tests {
    use crate::{check, evaluate, Bindings, Context, ExecutionError, Policy, Program, Value};
    #[test]
    fn numeric_extrema_semantics() {
        for (src, expected) in [
            ("min([3,1,2])", Value::Int(1)),
            ("[3u,1u].max()", Value::UInt(3)),
            ("min([0.0,-0.0])", Value::Float(0.0)),
        ] {
            let p = check(src, &Policy::P0_INTERIM).result.unwrap();
            assert_eq!(
                evaluate(&p, &Bindings::new(), &Policy::P0_INTERIM).result,
                Ok(expected)
            );
        }
    }
    #[test]
    fn empty_mixed_wrong_overload_are_typed() {
        for src in [
            "min([])",
            "min([1,2.0])",
            "max(['s'])",
            "min(1)",
            "min([1],2)",
        ] {
            let p = check(src, &Policy::P0_INTERIM).result.unwrap();
            let r = evaluate(&p, &Bindings::new(), &Policy::P0_INTERIM).result;
            assert!(r.is_err());
            assert!(!matches!(r, Err(ExecutionError::UndeclaredReference(_))));
        }
    }
    #[test]
    fn refusal_precedes_scan() {
        let p = Program::compile("min(xs)").unwrap();
        let mut c = Context::default();
        c.add_variable_from_value("xs", (0..5000).collect::<Vec<i64>>());
        crate::meter::reset_body_runs();
        let (r, _) = p.execute_budgeted(
            &c,
            crate::meter::Budget {
                work: 20,
                memory: 1000,
            },
        );
        assert!(matches!(r, Err(ExecutionError::WorkBudgetExceeded(_))));
        assert_eq!(crate::meter::op_bodies(), 0);
    }
}

#[cfg(test)]
mod boundary_tests {
    use crate::{api, Bindings, Declarations, ExecutionError, InputDecl, InputKind, Policy, Value};
    #[test]
    fn mapped_five_thousand_numeric_lists_global_and_receiver() {
        let policy = Policy::P0_INTERIM;
        let d = Declarations::new(
            [InputDecl {
                name: "rows".into(),
                kind: InputKind::Many,
            }],
            &policy,
        )
        .unwrap();
        let mut b = Bindings::empty(&d, &policy);
        let rows: Vec<Value> = (0..5000)
            .map(|i| indexmap::IndexMap::from([("n", i as i64)]).into())
            .collect();
        b.insert("rows", &Value::from(rows)).unwrap();
        for (source, expected) in [
            ("min(rows.map(r,r.n))", Value::Int(0)),
            ("rows.map(r,r.n).max()", Value::Int(4999)),
            ("max(rows.map(r,uint(r.n)))", Value::UInt(4999)),
            ("rows.map(r,double(r.n)).min()", Value::Float(0.0)),
        ] {
            let prepared = api::measure(source, &d, &policy).result.unwrap();
            let report = api::evaluate(&prepared, &b, &policy);
            assert_eq!(report.result, Ok(expected), "{source}");
            assert!(report.input_cost.work > 0);
        }
    }
    #[test]
    fn nan_mixed_precedence_infinities_and_first_signed_zero() {
        let policy = Policy::P0_INTERIM;
        for source in ["min([double('NaN'),1])", "min([1,double('NaN')])"] {
            let p = api::measure(source, &Declarations::empty(), &policy)
                .result
                .unwrap();
            assert_eq!(
                api::evaluate(
                    &p,
                    &Bindings::empty(&Declarations::empty(), &policy),
                    &policy
                )
                .result,
                Err(ExecutionError::NoSuchOverload)
            );
        }
        for source in ["min([double('NaN'),1.0])", "max([1.0,double('NaN')])"] {
            let p = api::measure(source, &Declarations::empty(), &policy)
                .result
                .unwrap();
            assert!(matches!(
                api::evaluate(
                    &p,
                    &Bindings::empty(&Declarations::empty(), &policy),
                    &policy
                )
                .result,
                Err(ExecutionError::FunctionError { .. })
            ));
        }
        for source in ["min([-0.0,0.0])", "max([-0.0,0.0])"] {
            let p = api::measure(source, &Declarations::empty(), &policy)
                .result
                .unwrap();
            let Value::Float(v) = api::evaluate(
                &p,
                &Bindings::empty(&Declarations::empty(), &policy),
                &policy,
            )
            .result
            .unwrap() else {
                panic!("winner type");
            };
            assert_eq!(v.to_bits(), (-0.0f64).to_bits());
        }
        let p = api::measure(
            "max([double('-inf'),double('inf')])",
            &Declarations::empty(),
            &policy,
        )
        .result
        .unwrap();
        assert_eq!(
            api::evaluate(
                &p,
                &Bindings::empty(&Declarations::empty(), &policy),
                &policy
            )
            .result,
            Ok(Value::Float(f64::INFINITY))
        );
    }
}
