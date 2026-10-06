use crate::common::traits::{Adder, Comparer, Subtractor, Zeroer};
use crate::common::types::{CelInt, CelString, Type};
use crate::common::value::Val;
use crate::ExecutionError;
use std::borrow::Cow;
use std::ops::Deref;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Duration(chrono::Duration);

impl Duration {
    pub fn into_inner(self) -> chrono::Duration {
        self.0
    }

    pub fn inner(&self) -> &chrono::Duration {
        &self.0
    }
}

impl Deref for Duration {
    type Target = chrono::Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Val for Duration {
    fn get_type(&self) -> &Type {
        &super::DURATION_TYPE
    }

    fn as_adder(&self) -> Option<&dyn Adder> {
        Some(self)
    }

    fn as_comparer(&self) -> Option<&dyn Comparer> {
        Some(self)
    }

    fn as_subtractor(&self) -> Option<&dyn Subtractor> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    fn equals(&self, other: &dyn Val) -> bool {
        other
            .downcast_ref::<Self>()
            .is_some_and(|other| self.0 == other.0)
    }

    fn clone_as_boxed(&self) -> Box<dyn Val> {
        Box::new(Duration(self.0))
    }
}

impl Adder for Duration {
    fn add<'a>(&'a self, rhs: &dyn Val) -> Result<Cow<'a, dyn Val>, crate::ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Duration>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(Duration(
                self.0.checked_add(&rhs.0).ok_or_else(|| {
                    ExecutionError::Overflow(
                        "add",
                        crate::val_desc::ValueDesc::of(self as &dyn Val),
                        crate::val_desc::ValueDesc::of(rhs as &dyn Val),
                    )
                })?,
            ))))
        } else {
            Err(crate::ExecutionError::UnsupportedBinaryOperator(
                "add",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Comparer for Duration {
    fn compare(&self, rhs: &dyn Val) -> Result<std::cmp::Ordering, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Duration>() {
            Ok(self.0.cmp(&rhs.0))
        } else {
            Err(ExecutionError::NoSuchOverload)
        }
    }
}

impl Subtractor for Duration {
    fn sub<'a>(&'a self, rhs: &'_ dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Duration>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(Duration(
                self.0.checked_sub(&rhs.0).ok_or_else(|| {
                    ExecutionError::Overflow(
                        "sub",
                        crate::val_desc::ValueDesc::of(self as &dyn Val),
                        crate::val_desc::ValueDesc::of(rhs as &dyn Val),
                    )
                })?,
            ))))
        } else {
            Err(ExecutionError::NoSuchOverload)
        }
    }
}

impl Zeroer for Duration {
    fn is_zero_value(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<chrono::Duration> for Duration {
    fn from(duration: chrono::Duration) -> Self {
        Self(duration)
    }
}

impl From<Duration> for chrono::Duration {
    fn from(duration: Duration) -> Self {
        duration.0
    }
}

impl TryFrom<Box<dyn Val>> for chrono::Duration {
    type Error = Box<dyn Val>;

    fn try_from(value: Box<dyn Val>) -> Result<Self, Self::Error> {
        if let Some(d) = value.downcast_ref::<Duration>() {
            return Ok(d.0);
        }
        Err(value)
    }
}

impl<'a> TryFrom<&'a dyn Val> for &'a chrono::Duration {
    type Error = &'a dyn Val;
    fn try_from(value: &'a dyn Val) -> Result<Self, Self::Error> {
        if let Some(d) = value.downcast_ref::<Duration>() {
            return Ok(&d.0);
        }
        Err(value)
    }
}

fn millis<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::DURATION_TYPE, |ts: &Duration| {
        Ok(Box::new(CelInt::from(ts.inner().num_milliseconds())))
    })
}

fn seconds<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::DURATION_TYPE, |ts: &Duration| {
        Ok(Box::new(CelInt::from(ts.inner().num_seconds())))
    })
}

fn minutes<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::DURATION_TYPE, |ts: &Duration| {
        Ok(Box::new(CelInt::from(ts.inner().num_minutes())))
    })
}

fn hours<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::DURATION_TYPE, |ts: &Duration| {
        Ok(Box::new(CelInt::from(ts.inner().num_hours())))
    })
}

fn duration<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    // F4 remainder: parsing is O(len); charge before parsing.
    super::charge_string_parse(args[0].as_ref())?;
    super::unary_fn(args, super::STRING_TYPE, |value: &CelString| {
        let (_, duration) = crate::duration::parse_duration(value.inner()).map_err(|_| {
            ExecutionError::function_error("duration", "invalid or out-of-range duration")
        })?;
        Ok(Box::new(Duration::from(duration)))
    })
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload(
        "duration",
        "string_to_duration",
        vec![super::STRING_TYPE],
        duration,
    )
    .expect("Must be unique");
    env.add_overload(
        "duration",
        "duration_to_duration",
        vec![super::DURATION_TYPE],
        super::noop,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getHours",
        "duration_to_hours",
        super::DURATION_TYPE,
        Vec::default(),
        hours,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getMinutes",
        "duration_to_minutes",
        super::DURATION_TYPE,
        Vec::default(),
        minutes,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getSeconds",
        "duration_to_seconds",
        super::DURATION_TYPE,
        Vec::default(),
        seconds,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getMilliseconds",
        "duration_to_millis",
        super::DURATION_TYPE,
        Vec::default(),
        millis,
    )
    .expect("Must be unique");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporal_duration_arithmetic_overflows_are_typed() {
        let max = Duration::from(chrono::Duration::MAX);
        let min = Duration::from(chrono::Duration::MIN);
        let tick = Duration::from(chrono::Duration::nanoseconds(1));
        assert!(matches!(
            max.add(&tick),
            Err(ExecutionError::Overflow("add", _, _))
        ));
        assert!(matches!(
            min.sub(&tick),
            Err(ExecutionError::Overflow("sub", _, _))
        ));
        assert!(matches!(
            max.add(&max),
            Err(ExecutionError::Overflow("add", _, _))
        ));
        assert!(matches!(
            min.sub(&max),
            Err(ExecutionError::Overflow("sub", _, _))
        ));
        assert_eq!(
            max.sub(&max)
                .unwrap()
                .downcast_ref::<Duration>()
                .unwrap()
                .inner(),
            &chrono::Duration::zero()
        );
    }

    #[test]
    fn temporal_duration_parse_errors_are_bounded_semantic_errors() {
        for input in ["1e99h".repeat(1000), format!("1s{}", "x".repeat(5000))] {
            let input = CelString::from(input);
            let result = duration(vec![Cow::Borrowed(&input)]);
            let error = result.unwrap_err();
            assert!(
                matches!(&error, ExecutionError::FunctionError { function, message }
                if function == "duration" && message == "invalid or out-of-range duration")
            );
            assert!(format!("{error:?}").len() < 128);
            assert!(error.to_string().len() < 128);
        }
    }

    #[test]
    fn temporal_runtime_duration_format_and_error_paths() {
        for expression in [
            "string(duration('-1s')) == '-1s'",
            "string(duration('-1ns')) == '-1ns'",
            "duration(string(duration('-1us'))) == duration('-1us')",
            "string(duration('9223372036854775807ms')) == '2562047788015h12m55.807s'",
            "duration(string(duration('-9223372036854775807ms'))) == duration('-9223372036854775807ms')",
        ] {
            assert_eq!(crate::tests::test_script(expression, None), Ok(true.into()), "{expression}");
        }
        let source = "1e99h".repeat(1000);
        let mut context = crate::context::Context::default();
        context.add_variable("source", source).unwrap();
        let error =
            crate::tests::test_script("string(duration(source))", Some(context)).unwrap_err();
        assert!(
            matches!(&error, ExecutionError::FunctionError { function, .. } if function == "duration")
        );
        assert!(format!("{error:?}").len() < 128);
    }
}
