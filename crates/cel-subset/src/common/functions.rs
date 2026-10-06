use crate::common::value::Val;
use crate::ExecutionError;
use std::borrow::Cow;

pub type Function = for<'a> fn(Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError>;
