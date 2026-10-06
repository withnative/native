use crate::common::traits::{Sizer, Zeroer};
use crate::common::types::{CelInt, CelString, Type};
use crate::common::value::Val;
use crate::{common::traits, ExecutionError};
use std::borrow::Cow;
use std::ops::Deref;
use traits::{Adder, Comparer};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn inner(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl Val for Bytes {
    fn get_type(&self) -> &Type {
        &super::BYTES_TYPE
    }

    fn as_adder(&self) -> Option<&dyn Adder> {
        Some(self)
    }

    fn as_comparer(&self) -> Option<&dyn Comparer> {
        Some(self)
    }

    fn as_sizer(&self) -> Option<&dyn Sizer> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    fn cached_bytes(&self) -> u64 {
        self.inner().len() as u64
    }

    fn equals(&self, other: &dyn Val) -> bool {
        other
            .downcast_ref::<Self>()
            .is_some_and(|a| self.0.eq(&a.0))
    }

    fn clone_as_boxed(&self) -> Box<dyn Val> {
        Box::new(Bytes(self.0.clone()))
    }
}

impl Adder for Bytes {
    fn add<'a>(&'a self, other: &dyn Val) -> Result<Cow<'a, dyn Val>, crate::ExecutionError> {
        if let Some(bytes) = other.downcast_ref::<Bytes>() {
            // §1.3 `s + t` row, memory column (its wu is deferred to
            // increment 5).
            crate::meter::charge_cost(crate::charges::excluding_node_visit(
                crate::charges::string_concat(self.0.len() as u64, bytes.0.len() as u64),
            ))?;
            crate::meter::note_op_body();
            let mut result = Vec::with_capacity(self.0.len() + bytes.0.len());
            result.extend_from_slice(&self.0);
            result.extend_from_slice(&bytes.0);
            Ok(Cow::<dyn Val>::Owned(Box::new(Bytes(result))))
        } else {
            Err(crate::ExecutionError::UnsupportedBinaryOperator(
                "add",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(other),
            ))
        }
    }
}

impl Comparer for Bytes {
    fn compare(&self, other: &dyn Val) -> Result<std::cmp::Ordering, crate::ExecutionError> {
        if let Some(bytes) = other.downcast_ref::<Bytes>() {
            Ok(self.0.cmp(&bytes.0))
        } else {
            Err(crate::ExecutionError::NoSuchOverload)
        }
    }
}

impl Sizer for Bytes {
    fn size(&self) -> CelInt {
        (self.inner().len() as i64).into()
    }
}

impl Zeroer for Bytes {
    fn is_zero_value(&self) -> bool {
        self.inner().is_empty()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Bytes(value)
    }
}

impl From<Bytes> for Vec<u8> {
    fn from(value: Bytes) -> Self {
        value.0
    }
}

impl TryFrom<Box<dyn Val>> for Vec<u8> {
    type Error = Box<dyn Val>;

    fn try_from(value: Box<dyn Val>) -> Result<Self, Self::Error> {
        super::cast_boxed::<Bytes>(value).map(|b| b.into_inner())
    }
}

impl<'a> TryFrom<&'a dyn Val> for &'a [u8] {
    type Error = &'a dyn Val;

    fn try_from(value: &'a dyn Val) -> Result<Self, Self::Error> {
        if let Some(bytes) = value.downcast_ref::<Bytes>() {
            return Ok(bytes.inner());
        }
        Err(value)
    }
}

fn bytes_to_bytes<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    let mut args = args;
    Ok(args.remove(0))
}

fn string_to_bytes<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    // U3 removal: borrow the argument; only the result is allocated.
    let arg: &dyn Val = args[0].as_ref();
    // F4: the payload copy is O(len); charge before converting.
    crate::meter::charge_cost(crate::charges::excluding_node_visit(
        crate::charges::string_or_bytes_conversion(arg.cached_bytes(), arg.cached_bytes()),
    ))?;
    match arg.downcast_ref::<CelString>() {
        Some(string) => {
            crate::meter::note_op_body();
            let value = string.inner().as_bytes().to_vec();
            Ok(Cow::<dyn Val>::Owned(Box::new(Bytes::from(value))))
        }
        None => Err(ExecutionError::unexpected_type(
            arg.get_type().name(),
            "Bytes",
        )),
    }
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload(
        "bytes",
        "string_to_bytes",
        vec![super::STRING_TYPE],
        string_to_bytes,
    )
    .expect("Must be unique id");
    env.add_overload(
        "bytes",
        "bytes_to_bytes",
        vec![super::BYTES_TYPE],
        bytes_to_bytes,
    )
    .expect("Must be unique id");
    env.add_overload(
        "size",
        "size_bytes",
        vec![super::BYTES_TYPE],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
    env.add_member_overload(
        "size",
        "bytes_size",
        super::BYTES_TYPE,
        vec![],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
}
