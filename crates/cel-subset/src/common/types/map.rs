use crate::common::traits::{Container, Indexer, Iterable, Sizer, Zeroer};
use crate::common::types::{CelBool, CelInt, CelString, CelUInt, Kind, Type};
use crate::common::value::Val;
use crate::common::{traits, types};
use crate::metrics::{rollup_map, Metrics};
use crate::ExecutionError;
use crate::ExecutionError::NoSuchOverload;
use indexmap::map::Keys;
use indexmap::IndexMap;
use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::Arc;

/// Insertion-ordered CEL map (D1): iteration — `map`/`all`/`exists`/
/// `filter`, equality and serialisation — follows insertion order;
/// equality itself stays order-insensitive (`IndexMap` compares as a
/// map).
#[derive(Debug)]
pub struct DefaultMap(IndexMap<Key, Box<dyn Val>>, Metrics);

impl Default for DefaultMap {
    fn default() -> Self {
        Self::from(IndexMap::new())
    }
}

impl DefaultMap {
    pub fn inner(&self) -> &IndexMap<Key, Box<dyn Val>> {
        &self.0
    }
}

impl Deref for DefaultMap {
    type Target = IndexMap<Key, Box<dyn Val>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Val for DefaultMap {
    fn get_type(&self) -> &Type {
        &types::MAP_TYPE
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
        let mut map = IndexMap::with_capacity(self.0.len());
        for (k, v) in self.0.iter() {
            map.insert(k.clone(), v.clone_as_boxed());
        }
        // Contents are identical, so the rollup carries over O(1).
        Box::new(Self(map, self.1))
    }
}

impl Container for DefaultMap {
    fn contains(&self, key: &dyn Val) -> Result<bool, ExecutionError> {
        validate_key(key)?;
        // Fork fix: same int/uint cross-representation rule as `get`.
        let alt = alt_numeric_key(key);
        if let Some(s) = key.downcast_ref::<CelString>() {
            Ok(self.0.contains_key(s as &dyn AsKeyRef))
        } else if let Some(i) = key.downcast_ref::<CelInt>() {
            Ok(self.0.contains_key(i as &dyn AsKeyRef)
                || alt.as_ref().is_some_and(|a| self.0.contains_key(a)))
        } else if let Some(u) = key.downcast_ref::<CelUInt>() {
            Ok(self.0.contains_key(u as &dyn AsKeyRef)
                || alt.as_ref().is_some_and(|a| self.0.contains_key(a)))
        } else if let Some(b) = key.downcast_ref::<CelBool>() {
            Ok(self.0.contains_key(b as &dyn AsKeyRef))
        } else {
            Err(NoSuchOverload)
        }
    }
}

/// Reject invalid key kinds by borrow, before any clone or ownership conversion.
pub(crate) fn validate_key(key: &dyn Val) -> Result<(), ExecutionError> {
    if matches!(
        key.get_type().kind(),
        Kind::Boolean | Kind::Int | Kind::UInt | Kind::String
    ) {
        Ok(())
    } else {
        Err(ExecutionError::UnsupportedKeyType(
            crate::val_desc::ValueDesc::of(key),
        ))
    }
}
pub(crate) fn charge_key_copy(key: &dyn Val) -> Result<(), ExecutionError> {
    validate_key(key)?;
    crate::meter::charge_cost(crate::charges::payload_copy(1, key.cached_bytes()))?;
    crate::meter::note_op_body();
    Ok(())
}

pub(crate) fn missing_key(key: &dyn Val) -> ExecutionError {
    if let Err(error) = crate::meter::charge_cost(crate::charges::payload_copy(1, 256)) {
        return error;
    }
    crate::meter::note_op_body();
    // A diagnostic owns at most 64 characters; it never clones the full key.
    let name = if let Some(s) = key.downcast_ref::<CelString>() {
        s.inner().chars().take(64).collect()
    } else if let Some(i) = key.downcast_ref::<CelInt>() {
        i.inner().to_string()
    } else if let Some(u) = key.downcast_ref::<CelUInt>() {
        u.inner().to_string()
    } else if let Some(b) = key.downcast_ref::<CelBool>() {
        b.inner().to_string()
    } else {
        "invalid key".into()
    };
    ExecutionError::NoSuchKey(Arc::new(name))
}

/// Alternate numeric map key for cross int/uint lookup (fork fix):
/// `Int(n)` also probes `UInt(n)` when `n >= 0`, and vice versa when
/// the uint fits in i64. Returns `None` for non-numeric keys or when
/// no alternate representation exists.
fn alt_numeric_key(key: &dyn Val) -> Option<Key> {
    if let Some(i) = key.downcast_ref::<CelInt>() {
        u64::try_from(*i.inner()).ok().map(|u| Key::UInt(u.into()))
    } else if let Some(u) = key.downcast_ref::<CelUInt>() {
        i64::try_from(*u.inner()).ok().map(|i| Key::Int(i.into()))
    } else {
        None
    }
}

impl Indexer for DefaultMap {
    fn get<'a>(&'a self, key: &dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        validate_key(key)?;
        let k = if let Some(s) = key.downcast_ref::<CelString>() {
            s as &dyn AsKeyRef
        } else if let Some(i) = key.downcast_ref::<CelInt>() {
            i as &dyn AsKeyRef
        } else if let Some(u) = key.downcast_ref::<CelUInt>() {
            u as &dyn AsKeyRef
        } else if let Some(b) = key.downcast_ref::<CelBool>() {
            b as &dyn AsKeyRef
        } else {
            return Err(NoSuchOverload);
        };

        // Fork fix: int/uint keys match across representations when
        // numerically equal (`{1u:.., 2:..}[2u]` → the `2` entry).
        let alt = alt_numeric_key(key);
        self.0
            .get(k)
            .or_else(|| alt.as_ref().and_then(|a| self.0.get(a)))
            .map(|v| Cow::Borrowed(v.as_ref()))
            .ok_or_else(|| missing_key(key))
    }

    fn steal(mut self: Box<Self>, key: &dyn Val) -> Result<Box<dyn Val>, ExecutionError> {
        validate_key(key)?;
        // Move the selected value out using a borrowed key. No key payload copy.
        let k: &dyn AsKeyRef = if let Some(s) = key.downcast_ref::<CelString>() {
            s
        } else if let Some(i) = key.downcast_ref::<CelInt>() {
            i
        } else if let Some(u) = key.downcast_ref::<CelUInt>() {
            u
        } else if let Some(b) = key.downcast_ref::<CelBool>() {
            b
        } else {
            return Err(NoSuchOverload);
        };
        let alt = alt_numeric_key(key);
        self.0
            .swap_remove(k)
            .or_else(|| alt.and_then(|a| self.0.swap_remove(&a)))
            .ok_or_else(|| missing_key(key))
    }
}

impl Iterable for DefaultMap {
    fn iter<'a>(&'a self) -> Box<dyn super::traits::Iterator<'a> + 'a> {
        Box::new(MapKeyIterator::new(self.0.keys()))
    }
}

impl Sizer for DefaultMap {
    fn size(&self) -> CelInt {
        (self.inner().len() as i64).into()
    }
}

impl Zeroer for DefaultMap {
    fn is_zero_value(&self) -> bool {
        self.inner().is_empty()
    }
}

impl From<IndexMap<Key, Box<dyn Val>>> for DefaultMap {
    fn from(value: IndexMap<Key, Box<dyn Val>>) -> Self {
        let metrics = rollup_map(&value);
        Self(value, metrics)
    }
}

#[derive(Debug, Eq, Clone)]
pub enum Key {
    Bool(CelBool),
    Int(CelInt),
    String(CelString),
    UInt(CelUInt),
}

impl Hash for Key {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_keyref().hash(state);
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.as_keyref() == other.as_keyref()
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_keyref().cmp(&other.as_keyref())
    }
}

impl Key {
    pub fn inner(&self) -> &dyn Val {
        match self {
            Key::Bool(b) => b,
            Key::Int(i) => i,
            Key::String(s) => s,
            Key::UInt(u) => u,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum KeyRef<'a> {
    Int(i64),
    Uint(u64),
    Bool(bool),
    String(&'a str),
}

/// Trait for converting to a borrowed [`KeyRef`] for efficient lookups.
pub trait AsKeyRef {
    fn as_keyref(&self) -> KeyRef<'_>;
}

impl AsKeyRef for Key {
    fn as_keyref(&self) -> KeyRef<'_> {
        match self {
            Key::Int(i) => KeyRef::Int(*i.inner()),
            Key::UInt(u) => KeyRef::Uint(*u.inner()),
            Key::Bool(b) => KeyRef::Bool(*b.inner()),
            Key::String(s) => KeyRef::String(s.inner()),
        }
    }
}

impl AsKeyRef for CelString {
    fn as_keyref(&self) -> KeyRef<'_> {
        KeyRef::String(self.inner())
    }
}

impl AsKeyRef for CelInt {
    fn as_keyref(&self) -> KeyRef<'_> {
        KeyRef::Int(*self.inner())
    }
}

impl AsKeyRef for CelUInt {
    fn as_keyref(&self) -> KeyRef<'_> {
        KeyRef::Uint(*self.inner())
    }
}

impl AsKeyRef for CelBool {
    fn as_keyref(&self) -> KeyRef<'_> {
        KeyRef::Bool(*self.inner())
    }
}

impl<'a> AsKeyRef for KeyRef<'a> {
    fn as_keyref(&self) -> KeyRef<'a> {
        *self
    }
}

/// Trait object implementations for `dyn AsKeyRef` to enable hashing and comparison.
impl<'a> PartialEq for dyn AsKeyRef + 'a {
    fn eq(&self, other: &Self) -> bool {
        self.as_keyref().eq(&other.as_keyref())
    }
}

impl<'a> Eq for dyn AsKeyRef + 'a {}

impl<'a> Hash for dyn AsKeyRef + 'a {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_keyref().hash(state)
    }
}

impl<'a> PartialOrd for dyn AsKeyRef + 'a {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for dyn AsKeyRef + 'a {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_keyref().cmp(&other.as_keyref())
    }
}

/// Implement `Borrow<dyn AsKeyRef>` for `Key` to enable efficient lookups.
impl<'a> Borrow<dyn AsKeyRef + 'a> for Key {
    fn borrow(&self) -> &(dyn AsKeyRef + 'a) {
        self
    }
}

impl From<bool> for Key {
    fn from(value: bool) -> Self {
        Key::Bool(value.into())
    }
}

impl From<i64> for Key {
    fn from(value: i64) -> Self {
        Key::Int(value.into())
    }
}

impl From<String> for Key {
    fn from(value: String) -> Self {
        Key::String(value.into())
    }
}

impl From<&str> for Key {
    fn from(value: &str) -> Self {
        Key::String(value.into())
    }
}

impl From<u64> for Key {
    fn from(value: u64) -> Self {
        Key::UInt(value.into())
    }
}

impl TryFrom<Box<dyn Val>> for Key {
    type Error = ExecutionError;

    fn try_from(value: Box<dyn Val>) -> Result<Self, Self::Error> {
        let key = match value.get_type().kind() {
            Kind::Boolean => value
                .downcast_ref::<CelBool>()
                .copied()
                .map(Key::Bool)
                .ok_or_else(|| {
                    ExecutionError::UnsupportedKeyType(crate::val_desc::ValueDesc::of(
                        value.as_ref(),
                    ))
                })?,
            Kind::Int => value
                .downcast_ref::<CelInt>()
                .copied()
                .map(Key::Int)
                .ok_or_else(|| {
                    ExecutionError::UnsupportedKeyType(crate::val_desc::ValueDesc::of(
                        value.as_ref(),
                    ))
                })?,
            Kind::String => {
                let s = super::cast_boxed::<CelString>(value).map_err(|v| {
                    ExecutionError::UnsupportedKeyType(crate::val_desc::ValueDesc::of(v.as_ref()))
                })?;
                Key::String(s.into_inner().into())
            }
            Kind::UInt => value
                .downcast_ref::<CelUInt>()
                .copied()
                .map(Key::UInt)
                .ok_or_else(|| {
                    ExecutionError::UnsupportedKeyType(crate::val_desc::ValueDesc::of(
                        value.as_ref(),
                    ))
                })?,
            _ => {
                return Err(ExecutionError::UnsupportedKeyType(
                    crate::val_desc::ValueDesc::of(value.as_ref()),
                ))
            }
        };
        Ok(key)
    }
}

pub struct MapKeyIterator<'a> {
    keys: Keys<'a, Key, Box<dyn Val>>,
}

impl<'a> MapKeyIterator<'a> {
    fn new(keys: Keys<'a, Key, Box<dyn Val>>) -> Self {
        Self { keys }
    }
}

impl<'a> traits::Iterator<'a> for MapKeyIterator<'a> {
    fn next(&mut self) -> Option<&'a dyn Val> {
        self.keys.next().map(|k| k.inner())
    }
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload(
        "size",
        "size_map",
        vec![super::MAP_TYPE],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
    env.add_member_overload(
        "size",
        "map_size",
        super::MAP_TYPE,
        vec![],
        traits::adapter::sizer_size,
    )
    .expect("Must be unique id");
}
