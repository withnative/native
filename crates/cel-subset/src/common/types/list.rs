use crate::common::traits::{Adder, Container, Indexer, Iterable, Sizer, Zeroer};
use crate::common::types::{CelBool, CelDouble, CelInt, CelUInt, Kind, Type};
use crate::common::value::Val;
use crate::common::{traits, types};
use crate::metrics::{rollup_list, Metrics};
use crate::ExecutionError;
use std::any::Any;
use std::borrow::Cow;
use std::ops::Deref;

#[derive(Debug)]
pub struct DefaultList(Vec<Box<dyn Val>>, Metrics);

impl Default for DefaultList {
    fn default() -> Self {
        Self::from(Vec::new())
    }
}

impl DefaultList {
    pub fn into_inner(self) -> Vec<Box<dyn Val>> {
        self.0
    }

    pub fn inner(&self) -> &[Box<dyn Val>] {
        &self.0
    }

    /// In-place append with an incremental metrics update (design
    /// §1.3): only the new element's cached metrics are added. Used
    /// by `Adder` today; increment 6 reuses it for `@result`.
    pub(crate) fn push(&mut self, value: Box<dyn Val>) {
        self.1.nodes = self.1.nodes.saturating_add(value.cached_nodes());
        self.1.bytes = self
            .1
            .bytes
            .saturating_add(crate::charges::LIST_ELEM_BYTES)
            .saturating_add(value.cached_bytes());
        self.0.push(value);
    }

    fn clone(&self) -> Self {
        let mut vec = Vec::with_capacity(self.0.len());
        for i in self.0.iter().map(|i| i.clone_as_boxed()) {
            vec.push(i);
        }
        // Contents are identical, so the rollup carries over O(1).
        Self(vec, self.1)
    }
}

impl Deref for DefaultList {
    type Target = [Box<dyn Val>];

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl Val for DefaultList {
    fn get_type(&self) -> &Type {
        &types::LIST_TYPE
    }

    fn as_adder(&self) -> Option<&dyn Adder> {
        Some(self)
    }

    fn as_container(&self) -> Option<&dyn Container> {
        Some(self)
    }

    fn as_indexer(&self) -> Option<&dyn Indexer> {
        Some(self)
    }

    fn into_indexer(self: Box<Self>) -> Option<Box<dyn Indexer>> {
        Some(self)
    }

    fn as_iterable(&self) -> Option<&dyn Iterable> {
        Some(self)
    }

    fn as_sizer(&self) -> Option<&dyn Sizer> {
        Some(self)
    }

    fn as_zeroer(&self) -> Option<&dyn Zeroer> {
        Some(self)
    }

    fn cached_nodes(&self) -> u64 {
        self.1.nodes
    }

    fn cached_bytes(&self) -> u64 {
        self.1.bytes
    }

    fn equals(&self, other: &dyn Val) -> bool {
        other
            .downcast_ref::<Self>()
            .is_some_and(|other| self.0 == other.0)
    }

    fn clone_as_boxed(&self) -> Box<dyn Val> {
        Box::new(self.clone())
    }
}

impl Adder for DefaultList {
    fn add<'a>(&'a self, rhs: &dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        // CEL list addition accepts lists only. Validate the borrowed kind before
        // charging: invalid-kind ADD has only the bounded diagnostic prefix.
        let rhs = rhs
            .downcast_ref::<Self>()
            .ok_or(ExecutionError::NoSuchOverload)?;
        // U7: charge the whole concatenation before the deep copy —
        // work `nodes(l) + nodes(r)`, memory `bytes(l) + bytes(r)`.
        crate::meter::charge_cost(crate::charges::excluding_node_visit(
            crate::charges::list_concat(
                self.cached_nodes(),
                self.cached_bytes(),
                rhs.cached_nodes(),
                rhs.cached_bytes(),
            ),
        ))?;
        crate::meter::note_op_body();
        let mut rhs = rhs.iter();
        let mut list = self.clone();
        while let Some(other) = rhs.next() {
            list.push(other.clone_as_boxed());
        }
        Ok(Cow::<dyn Val>::Owned(Box::new(list)))
    }
}

impl Container for DefaultList {
    fn contains(&self, value: &dyn Val) -> Result<bool, ExecutionError> {
        for i in &self.0 {
            if i.equals(value) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Indexer for DefaultList {
    fn get<'a>(&'a self, idx: &dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        match idx.get_type().kind() {
            Kind::Int => {
                let idx: i64 = *idx
                    .downcast_ref::<CelInt>()
                    .ok_or(ExecutionError::NoSuchOverload)?
                    .inner();
                Ok(Cow::Borrowed(
                    self.0
                        .get(idx as usize)
                        .ok_or_else(|| ExecutionError::IndexOutOfBounds(idx.into()))?
                        .as_ref(),
                ))
            }
            Kind::UInt => {
                let idx: u64 = *idx
                    .downcast_ref::<CelUInt>()
                    .ok_or(ExecutionError::NoSuchOverload)?
                    .inner();
                Ok(Cow::Borrowed(
                    self.0
                        .get(idx as usize)
                        .ok_or_else(|| ExecutionError::IndexOutOfBounds(idx.into()))?
                        .as_ref(),
                ))
            }
            // Fork fix: conformance `zero_based_double` — a whole-number
            // double index converts to int; fractional/NaN stays an error.
            Kind::Double => {
                let idx = whole_double_index(idx)?;
                Ok(Cow::Borrowed(
                    self.0
                        .get(idx as usize)
                        .ok_or_else(|| ExecutionError::IndexOutOfBounds(idx.into()))?
                        .as_ref(),
                ))
            }
            _ => Err(ExecutionError::unexpected_type(
                &idx.get_type().runtime_type_name,
                "int|uint|double",
            )),
        }
    }

    fn steal(self: Box<Self>, idx: &dyn Val) -> Result<Box<dyn Val>, ExecutionError> {
        let mut list = self;
        match idx.get_type().kind() {
            Kind::Int => {
                let idx: i64 = *idx
                    .downcast_ref::<CelInt>()
                    .ok_or(ExecutionError::NoSuchOverload)?
                    .inner();
                if idx < 0 || idx as usize >= list.0.len() {
                    return Err(ExecutionError::IndexOutOfBounds(idx.into()));
                }
                Ok(list.0.swap_remove(idx as usize))
            }
            Kind::UInt => {
                let idx: u64 = *idx
                    .downcast_ref::<CelUInt>()
                    .ok_or(ExecutionError::NoSuchOverload)?
                    .inner();
                if idx as usize >= list.0.len() {
                    return Err(ExecutionError::IndexOutOfBounds(idx.into()));
                }
                Ok(list.0.swap_remove(idx as usize))
            }
            Kind::Double => {
                let idx = whole_double_index(idx)?;
                if idx < 0 || idx as usize >= list.0.len() {
                    return Err(ExecutionError::IndexOutOfBounds(idx.into()));
                }
                Ok(list.0.swap_remove(idx as usize))
            }
            _ => Err(ExecutionError::unexpected_type(
                &idx.get_type().runtime_type_name,
                "int|uint|double",
            )),
        }
    }
}

/// Whole-number double → i64 list index (fork fix for
/// `Kind::Double` arms above). Fractional doubles, NaN and infinities
/// are not indices; out-of-range wholes are out of bounds.
fn whole_double_index(idx: &dyn Val) -> Result<i64, ExecutionError> {
    let f: f64 = *idx
        .downcast_ref::<CelDouble>()
        .ok_or(ExecutionError::NoSuchOverload)?
        .inner();
    if !f.is_finite() || f.fract() != 0.0 {
        return Err(ExecutionError::unexpected_type(
            &idx.get_type().runtime_type_name,
            "whole-number double index",
        ));
    }
    if f < i64::MIN as f64 || f > i64::MAX as f64 {
        return Err(ExecutionError::IndexOutOfBounds(
            crate::objects::Value::Float(f),
        ));
    }
    Ok(f as i64)
}

impl Iterable for DefaultList {
    fn iter<'a>(&'a self) -> Box<dyn super::traits::Iterator<'a> + 'a> {
        Box::new(SliceIterator::new(self.0.as_slice()))
    }
}

impl Sizer for DefaultList {
    fn size(&self) -> CelInt {
        (self.inner().len() as i64).into()
    }
}

impl Zeroer for DefaultList {
    fn is_zero_value(&self) -> bool {
        self.inner().is_empty()
    }
}

impl From<Vec<Box<dyn Val>>> for DefaultList {
    fn from(v: Vec<Box<dyn Val>>) -> Self {
        let metrics = rollup_list(&v);
        Self(v, metrics)
    }
}

impl TryFrom<Box<dyn Val>> for Vec<Box<dyn Val>> {
    type Error = Box<dyn Val>;

    fn try_from(value: Box<dyn Val>) -> Result<Self, Self::Error> {
        super::cast_boxed::<DefaultList>(value).map(|l| l.into_inner())
    }
}

impl<'a> TryFrom<&'a dyn Val> for &'a [Box<dyn Val>] {
    type Error = &'a dyn Val;

    fn try_from(value: &'a dyn Val) -> Result<Self, Self::Error> {
        if let Some(list) = <dyn Any>::downcast_ref::<DefaultList>(value) {
            return Ok(list.inner());
        }
        Err(value)
    }
}

pub struct SliceIterator<'a> {
    list: &'a [Box<dyn Val>],
    pos: usize,
}

impl<'a> SliceIterator<'a> {
    fn new(list: &'a [Box<dyn Val>]) -> Self {
        Self { list, pos: 0 }
    }
}

impl<'a> traits::Iterator<'a> for SliceIterator<'a> {
    fn next(&mut self) -> Option<&'a dyn Val> {
        if self.pos >= self.list.len() {
            None
        } else {
            let r = &self.list[self.pos];
            self.pos += 1;
            Some(r.as_ref())
        }
    }
}

/// `list.contains(x)` (§1.3 subset): a borrowed overload over the
/// receiver and argument, so no `Value` round-trip copies the list.
/// The per-scan work is charged by the caller's containment row
/// before this body runs.
fn list_contains<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    let target = &args[0];
    let arg = &args[1];
    match target.downcast_ref::<DefaultList>() {
        None => Err(ExecutionError::unexpected_type(
            target.get_type().name(),
            super::LIST_TYPE.name(),
        )),
        Some(list) => Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(
            list.contains(arg.as_ref())?,
        )))),
    }
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload(
        "size",
        "size_list",
        vec![super::LIST_TYPE],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
    env.add_member_overload(
        "size",
        "list_size",
        super::LIST_TYPE,
        vec![],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
    env.add_member_overload(
        "contains",
        "contains_list",
        super::LIST_TYPE,
        vec![super::DYN_TYPE],
        list_contains,
    )
    .expect("Must be unique id");
}

#[cfg(test)]
pub mod tests {
    use crate::common::traits::Indexer;
    use crate::common::types::list::DefaultList;
    use crate::common::types::{CelInt, CelString};
    use crate::common::value::Val;
    use crate::ExecutionError::{IndexOutOfBounds, UnexpectedType};
    use std::borrow::Cow;

    #[test]
    fn list_has_indexer() {
        let list = Box::new(DefaultList::from(vec![]));
        assert!(list.as_indexer().is_some());
        assert!(list.into_indexer().is_some());
    }

    #[test]
    fn errs_out_of_index() {
        let list = DefaultList::from(vec![]);
        let idx: CelInt = 1.into();
        assert_eq!(
            Indexer::get(&list, &idx).err(),
            Some(IndexOutOfBounds(1.into()))
        );
        assert_eq!(
            Indexer::steal(list.into(), &idx).err(),
            Some(IndexOutOfBounds(1.into()))
        );
    }

    #[test]
    fn errs_unexpected_type() {
        let list = DefaultList::from(vec![]);
        let idx: CelString = "foo".into();
        // Fork change (spike 2a5becdb2): whole-number double indices
        // convert to int, so the accepted index types — and the
        // UnexpectedType message — now include double.
        assert_eq!(
            Indexer::get(&list, &idx).err(),
            Some(UnexpectedType {
                got: "string".to_string(),
                want: "int|uint|double".to_string(),
            })
        );
        assert_eq!(
            Indexer::steal(list.into(), &idx).err(),
            Some(UnexpectedType {
                got: "string".to_string(),
                want: "int|uint|double".to_string(),
            })
        );
    }

    #[test]
    fn get() {
        let val: CelString = "cel".into();
        let val: Box<dyn Val> = Box::new(val.clone());
        let list = DefaultList::from(vec![val]);
        let idx: CelInt = 0.into();
        let expected = Cow::<dyn Val>::Owned(Box::new(Into::<CelString>::into("cel")));
        assert_eq!(Indexer::get(&list, &idx), Ok(expected));
    }

    #[test]
    fn steal() {
        let val: CelString = "cel".into();
        let val: Box<dyn Val> = Box::new(val.clone());
        let list = DefaultList::from(vec![val]);
        let idx: CelInt = 0.into();
        let expected: Box<dyn Val> = Box::new(Into::<CelString>::into("cel"));
        assert_eq!(Indexer::steal(list.into(), &idx), Ok(expected));
    }

    #[test]
    fn try_into_vec() {
        let v1: Box<dyn Val> = Box::new(Into::<CelString>::into("cel"));
        let v2: Box<dyn Val> = Box::new(Into::<CelString>::into("rust"));
        let list: Box<dyn Val> = Box::new(DefaultList::from(vec![v1, v2]));
        let list: Vec<Box<dyn Val>> = list.try_into().unwrap();
        assert_eq!(list[0].downcast_ref::<CelString>().unwrap().inner(), "cel");
        assert_eq!(list[1].downcast_ref::<CelString>().unwrap().inner(), "rust");
    }

    #[test]
    fn try_into_slice() {
        let v1: Box<dyn Val> = Box::new(Into::<CelString>::into("cel"));
        let v2: Box<dyn Val> = Box::new(Into::<CelString>::into("rust"));
        let list: Box<dyn Val> = Box::new(DefaultList::from(vec![v1, v2]));
        let list: &[Box<dyn Val>] = list.as_ref().try_into().unwrap();
        assert_eq!(list[0].downcast_ref::<CelString>().unwrap().inner(), "cel");
        assert_eq!(list[1].downcast_ref::<CelString>().unwrap().inner(), "rust");
    }
}
