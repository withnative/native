use crate::common::traits::{Adder, Comparer, Divider, Multiplier, Negator, Subtractor, Zeroer};
use crate::common::types::{CelInt, CelString, CelUInt, Kind, Type};
use crate::common::value::Val;
use crate::ExecutionError;
use std::borrow::Cow;
use std::cmp::Ordering;
use std::ops::Deref;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Double(f64);

impl Double {
    pub fn into_inner(self) -> f64 {
        self.0
    }

    pub fn inner(&self) -> &f64 {
        &self.0
    }
}

impl Deref for Double {
    type Target = f64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Val for Double {
    fn get_type(&self) -> &Type {
        &super::DOUBLE_TYPE
    }

    fn as_adder(&self) -> Option<&dyn Adder> {
        Some(self)
    }

    fn as_comparer(&self) -> Option<&dyn Comparer> {
        Some(self)
    }

    fn as_divider(&self) -> Option<&dyn Divider> {
        Some(self)
    }

    fn as_multiplier(&self) -> Option<&dyn Multiplier> {
        Some(self)
    }

    fn as_negator(&self) -> Option<&dyn Negator> {
        Some(self)
    }

    fn as_subtractor(&self) -> Option<&dyn Subtractor> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    fn equals(&self, other: &dyn Val) -> bool {
        self.compare(other)
            .map(|r| r == Ordering::Equal)
            .unwrap_or(false)
    }

    fn clone_as_boxed(&self) -> Box<dyn Val> {
        Box::new(Double(self.0))
    }
}

impl Adder for Double {
    fn add<'a>(&'a self, rhs: &dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(other) = rhs.downcast_ref::<Self>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(Double(self.0 + other.0))))
        } else {
            Err(ExecutionError::UnsupportedBinaryOperator(
                "add",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Comparer for Double {
    fn compare(&self, rhs: &dyn Val) -> Result<Ordering, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Self>() {
            Ok(self
                .0
                .partial_cmp(&rhs.0)
                .ok_or(ExecutionError::NoSuchOverload)?)
        } else if let Some(rhs) = rhs.downcast_ref::<CelInt>() {
            Ok(self
                .0
                .partial_cmp(&(*rhs.inner() as f64))
                .ok_or(ExecutionError::NoSuchOverload)?)
        } else if let Some(rhs) = rhs.downcast_ref::<CelUInt>() {
            Ok(self
                .0
                .partial_cmp(&(*rhs.inner() as f64))
                .ok_or(ExecutionError::NoSuchOverload)?)
        } else {
            Err(ExecutionError::NoSuchOverload)
        }
    }
}

impl Divider for Double {
    fn div<'a>(&self, rhs: &'a dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Double>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(Double(self.0 / rhs.0))))
        } else {
            Err(ExecutionError::UnsupportedBinaryOperator(
                "div",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Multiplier for Double {
    fn mul<'a>(&self, rhs: &'a dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Double>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(Double(self.0 * rhs.0))))
        } else {
            Err(ExecutionError::UnsupportedBinaryOperator(
                "mul",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Negator for Double {
    fn negate(&self) -> Result<Box<dyn Val>, ExecutionError> {
        Ok(Box::new(Double(-self.0)))
    }
}

impl Subtractor for Double {
    fn sub<'a>(&'a self, rhs: &'_ dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Double>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(Double(self.0 - rhs.0))))
        } else {
            Err(ExecutionError::UnsupportedBinaryOperator(
                "sub",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Zeroer for Double {
    fn is_zero_value(&self) -> bool {
        self.0 == 0.0
    }
}

impl From<Double> for f64 {
    fn from(value: Double) -> Self {
        value.0
    }
}

impl From<f64> for Double {
    fn from(value: f64) -> Self {
        Self(value)
    }
}

impl TryFrom<Box<dyn Val>> for f64 {
    type Error = Box<dyn Val>;

    fn try_from(value: Box<dyn Val>) -> Result<Self, Self::Error> {
        if let Some(d) = value.downcast_ref::<Double>() {
            return Ok(d.0);
        }
        Err(value)
    }
}

impl<'a> TryFrom<&'a dyn Val> for &'a f64 {
    type Error = &'a dyn Val;

    fn try_from(value: &'a dyn Val) -> Result<Self, Self::Error> {
        if let Some(d) = value.downcast_ref::<Double>() {
            return Ok(&d.0);
        }
        Err(value)
    }
}

fn double<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    // U3 removal: borrow the argument; only the result is allocated.
    let arg: &dyn Val = args[0].as_ref();
    // F4 remainder: string parsing is O(len); charge before parsing.
    super::charge_string_parse(arg)?;
    let ret: Result<Box<Double>, ()> = match arg.get_type().kind() {
        Kind::Double => Ok(Box::new(Double::from(
            *arg.downcast_ref::<Double>().expect("kind double").inner(),
        ))),
        Kind::Int => Ok(Box::new(Double::from(
            *arg.downcast_ref::<CelInt>().expect("kind int").inner() as f64,
        ))),
        Kind::UInt => Ok(Box::new(Double::from(
            *arg.downcast_ref::<CelUInt>().expect("kind uint").inner() as f64,
        ))),
        Kind::String => match arg
            .downcast_ref::<CelString>()
            .expect("kind string")
            .inner()
            .parse::<f64>()
        {
            Ok(value) => Ok(Box::new(Double::from(value))),
            Err(e) => {
                return Err(ExecutionError::function_error(
                    "double",
                    format_args!("string parse error: {e}"),
                ))
            }
        },
        _ => Err(()),
    };

    match ret {
        Ok(ret) => Ok(Cow::<dyn Val>::Owned(ret)),
        Err(()) => Err(ExecutionError::FunctionError {
            function: "double".to_owned(),
            message: "unsupported numeric conversion".into(),
        }),
    }
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload(
        "double",
        "double_to_double",
        vec![super::DOUBLE_TYPE],
        double,
    )
    .expect("Must be unique id");
    env.add_overload("double", "int64_to_double", vec![super::INT_TYPE], double)
        .expect("Must be unique id");
    env.add_overload("double", "uint64_to_double", vec![super::UINT_TYPE], double)
        .expect("Must be unique id");
    env.add_overload(
        "double",
        "string_to_double",
        vec![super::STRING_TYPE],
        double,
    )
    .expect("Must be unique id");
}

#[cfg(test)]
mod tests {
    use crate::common::types::{CelDouble, CelInt, CelString, CelUInt};
    use crate::common::value::Val;

    #[test]
    fn test_equals() {
        let double = CelDouble::from(42.2);
        let round = CelDouble::from(42.0);
        assert!(double.equals(&double));
        assert!(!double.equals(&round));
        assert!(!double.equals(&CelInt::from(42)));
        assert!(round.equals(&CelInt::from(42)));
        assert!(!double.equals(&CelUInt::from(42)));
        assert!(round.equals(&CelUInt::from(42)));
        assert!(!double.equals(&CelString::from("42.2")));
        assert!(!round.equals(&CelString::from("42")));
        assert!(!round.equals(&CelDouble::from(f64::NAN)));
    }
}
