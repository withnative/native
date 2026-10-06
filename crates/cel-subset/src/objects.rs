use crate::common::ast::{operators, CallExpr, ComprehensionExpr, EntryExpr, Expr};
use crate::common::types::bool::Bool;
use crate::common::types::*;
use crate::common::value::{Downcast, Val};
use crate::comprehension::{absorbing_fold, append_step, is_accu_ident, AbsorbingFold, AppendStep};
use crate::context::Context;
use crate::ExecutionError::NoSuchOverload;
use crate::{ExecutionError, Expression, FunctionContext};
use chrono::TimeZone;
use std::any::Any;
use std::borrow::{Borrow, Cow};
use std::cmp::Ordering;
use std::convert::{Infallible, TryFrom, TryInto};
use std::fmt::{Debug, Display, Formatter};
use std::ops;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::LazyLock;

/// Timestamp values are limited to the range of values which can be serialized as a string:
/// `["0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z"]`. Since the max is a smaller
/// and the min is a larger timestamp than what is possible to represent with
/// [`chrono::DateTime`], we need to perform our own spec-compliant overflow checks.
///
/// <https://github.com/google/cel-spec/blob/master/doc/langdef.md#overflow>
static MAX_TIMESTAMP: LazyLock<chrono::DateTime<chrono::FixedOffset>> = LazyLock::new(|| {
    let naive = chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
        .unwrap()
        .and_hms_nano_opt(23, 59, 59, 999_999_999)
        .unwrap();
    chrono::FixedOffset::east_opt(0)
        .unwrap()
        .from_utc_datetime(&naive)
});

static MIN_TIMESTAMP: LazyLock<chrono::DateTime<chrono::FixedOffset>> = LazyLock::new(|| {
    let naive = chrono::NaiveDate::from_ymd_opt(1, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    chrono::FixedOffset::east_opt(0)
        .unwrap()
        .from_utc_datetime(&naive)
});

#[derive(Debug, PartialEq, Clone)]
pub struct Map {
    /// Insertion-ordered (D1); `IndexMap` equality is order-insensitive.
    pub map: Arc<indexmap::IndexMap<Key, Value>>,
}

impl PartialOrd for Map {
    fn partial_cmp(&self, _: &Self) -> Option<Ordering> {
        None
    }
}

impl Map {
    /// Returns a reference to the value corresponding to the key. Implicitly converts between int
    /// and uint keys.
    pub fn get(&self, key: &(dyn AsKeyRef + '_)) -> Option<&Value> {
        self.map.get(key).or_else(|| {
            // Also check keys that are cross type comparable.
            let keyref = key.as_keyref();
            match keyref {
                KeyRef::Int(k) => {
                    let converted = u64::try_from(k).ok()?;
                    self.map.get(&Key::Uint(converted))
                }
                KeyRef::Uint(k) => {
                    let converted = i64::try_from(k).ok()?;
                    self.map.get(&Key::Int(converted))
                }
                _ => None,
            }
        })
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Ord, Clone, PartialOrd)]
pub enum Key {
    Int(i64),
    Uint(u64),
    Bool(bool),
    String(Arc<String>),
}

impl From<CelMapKey> for Key {
    fn from(value: CelMapKey) -> Self {
        match value {
            CelMapKey::Bool(b) => b.into_inner().into(),
            CelMapKey::Int(i) => i.into_inner().into(),
            CelMapKey::String(s) => s.into_inner().into(),
            CelMapKey::UInt(u) => u.into_inner().into(),
        }
    }
}

impl From<Key> for CelMapKey {
    fn from(key: Key) -> Self {
        match key {
            Key::Int(i) => CelMapKey::from(i),
            Key::Uint(u) => CelMapKey::from(u),
            Key::Bool(b) => CelMapKey::from(b),
            Key::String(s) => CelMapKey::from(s.as_str()),
        }
    }
}

/// A borrowed version of [`Key`] that avoids allocating for lookups.
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
            Key::Int(i) => KeyRef::Int(*i),
            Key::Uint(u) => KeyRef::Uint(*u),
            Key::Bool(b) => KeyRef::Bool(*b),
            Key::String(s) => KeyRef::String(s.as_str()),
        }
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

impl<'a> std::hash::Hash for dyn AsKeyRef + 'a {
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

/// Implement conversions from primitive types to [`Key`]
impl From<String> for Key {
    fn from(v: String) -> Self {
        Key::String(v.into())
    }
}

impl From<Arc<String>> for Key {
    fn from(v: Arc<String>) -> Self {
        Key::String(v)
    }
}

impl<'a> From<&'a str> for Key {
    fn from(v: &'a str) -> Self {
        Key::String(Arc::new(v.into()))
    }
}

impl From<bool> for Key {
    fn from(v: bool) -> Self {
        Key::Bool(v)
    }
}

impl From<i64> for Key {
    fn from(v: i64) -> Self {
        Key::Int(v)
    }
}

impl From<i32> for Key {
    fn from(v: i32) -> Self {
        Key::Int(v as i64)
    }
}

impl From<u64> for Key {
    fn from(v: u64) -> Self {
        Key::Uint(v)
    }
}

impl From<u32> for Key {
    fn from(v: u32) -> Self {
        Key::Uint(v as u64)
    }
}

impl serde::Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Key::Int(v) => v.serialize(serializer),
            Key::Uint(v) => v.serialize(serializer),
            Key::Bool(v) => v.serialize(serializer),
            Key::String(v) => v.serialize(serializer),
        }
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Key::Int(v) => write!(f, "{v}"),
            Key::Uint(v) => write!(f, "{v}"),
            Key::Bool(v) => write!(f, "{v}"),
            Key::String(v) => write!(f, "{v}"),
        }
    }
}

/// Implement conversions from [`Key`] into [`Value`]
impl TryInto<Key> for Value {
    type Error = Value;

    #[inline(always)]
    fn try_into(self) -> Result<Key, Self::Error> {
        match self {
            Value::Int(v) => Ok(Key::Int(v)),
            Value::UInt(v) => Ok(Key::Uint(v)),
            Value::String(v) => Ok(Key::String(v)),
            Value::Bool(v) => Ok(Key::Bool(v)),
            _ => Err(self),
        }
    }
}

/// Implement conversions from [`KeyRef`] into [`Value`]
impl<'a> TryFrom<&'a Value> for KeyRef<'a> {
    type Error = Value;

    fn try_from(value: &'a Value) -> Result<Self, Self::Error> {
        match value {
            Value::Int(v) => Ok(KeyRef::Int(*v)),
            Value::UInt(v) => Ok(KeyRef::Uint(*v)),
            Value::String(v) => Ok(KeyRef::String(v.as_str())),
            Value::Bool(v) => Ok(KeyRef::Bool(*v)),
            _ => Err(value.clone()),
        }
    }
}

// Implement conversion from an insertion-ordered IndexMap into CelMap.
impl<K: Into<Key>, V: Into<Value>> From<indexmap::IndexMap<K, V>> for Map {
    fn from(map: indexmap::IndexMap<K, V>) -> Self {
        let new_map = map.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        Map {
            map: Arc::new(new_map),
        }
    }
}

/// Equality helper for [`Opaque`] values.
///
/// Implementors define how two values of the same runtime type compare for
/// equality when stored as [`Value::Opaque`].
///
/// You normally don't implement this trait manually. It is automatically
/// provided for any `T: Eq + PartialEq + Any + Opaque` (see the blanket impl
/// below). The runtime will first ensure the two values have the same
/// [`Opaque::runtime_type_name`], and only then attempt a downcast and call
/// `Eq::eq`.
pub trait OpaqueEq {
    /// Compare with another [`Opaque`] erased value.
    ///
    /// Implementations should return `false` if `other` does not have the same
    /// runtime type, or if it cannot be downcast to the concrete type of `self`.
    fn opaque_eq(&self, other: &dyn Opaque) -> bool;
}

impl<T> OpaqueEq for T
where
    T: Eq + PartialEq + Any + Opaque,
{
    fn opaque_eq(&self, other: &dyn Opaque) -> bool {
        if self.runtime_type_name() != other.runtime_type_name() {
            return false;
        }
        if let Some(other) = other.downcast_ref::<T>() {
            self.eq(other)
        } else {
            false
        }
    }
}

/// Helper trait to obtain a `&dyn Debug` view.
///
/// This is auto-implemented for any `T: Debug` and is used by the runtime to
/// format [`Opaque`] values without knowing their concrete type.
pub trait AsDebug {
    /// Returns `self` as a `&dyn Debug` trait object.
    fn as_debug(&self) -> &dyn Debug;
}

impl<T> AsDebug for T
where
    T: Debug,
{
    fn as_debug(&self) -> &dyn Debug {
        self
    }
}

/// Trait for user-defined opaque values stored inside [`Value::Opaque`].
///
/// Implement this trait for types that should participate in CEL evaluation as
/// opaque/user-defined values. An opaque value:
/// - must report a stable runtime type name via [`Opaque::runtime_type_name`];
/// - participates in equality via the blanket [`OpaqueEq`] implementation;
/// - can be formatted via [`AsDebug`];
/// - must be thread-safe (`Send + Sync`).
///
/// When the `json` feature is enabled you may optionally provide a JSON
/// representation for diagnostics, logging or interop. Returning `None` keeps the
/// value non-serializable for JSON.
///
/// Example
/// ```text
/// use std::fmt::{Debug, Formatter, Result as FmtResult};
/// use std::sync::Arc;
/// use cel::objects::{Opaque, Value};
///
/// #[derive(Eq, PartialEq)]
/// struct MyId(u64);
///
/// impl Debug for MyId {
///     fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult { write!(f, "MyId({})", self.0) }
/// }
///
/// impl Opaque for MyId {
///     fn runtime_type_name(&self) -> &str { "example.MyId" }
/// }
///
/// // Values of `MyId` can now be wrapped in `Value::Opaque` and compared.
/// let a = Value::Opaque(Arc::new(MyId(7)));
/// let b = Value::Opaque(Arc::new(MyId(7)));
/// assert_eq!(a, b);
/// ```
pub trait Opaque: Any + OpaqueEq + AsDebug + Send + Sync {
    /// Returns a stable, fully-qualified type name for this value's runtime type.
    ///
    /// This name is used to check type compatibility before attempting downcasts
    /// during equality checks and other operations. It should be stable across
    /// versions and unique within your application or library (e.g., a package
    /// qualified name like `my.pkg.Type`).
    fn runtime_type_name(&self) -> &str;

    /// Optional JSON representation (requires the `json` feature).
    ///
    /// The default implementation returns `None`, indicating that the value
    /// cannot be represented as JSON.
    #[cfg(feature = "json")]
    fn json(&self) -> Option<serde_json::Value> {
        None
    }
}

impl dyn Opaque {
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        let any: &dyn Any = self;
        any.downcast_ref()
    }
}

struct OpaqueVal {
    r#type: Type,
    val: Arc<dyn Opaque>,
}

impl Debug for OpaqueVal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpaqueVal<{}>", self.val.runtime_type_name())
    }
}

impl Val for OpaqueVal {
    fn get_type(&self) -> &Type {
        &self.r#type
    }

    fn equals(&self, other: &dyn Val) -> bool {
        if other.get_type() != self.get_type() {
            false
        } else {
            match other.downcast_ref::<OpaqueVal>() {
                None => false,
                Some(other) => self.val.opaque_eq(other.val.deref()),
            }
        }
    }

    fn clone_as_boxed(&self) -> Box<dyn Val> {
        Box::new(Self {
            r#type: Type::new_opaque_type(self.val.runtime_type_name().to_owned()),
            val: self.val.clone(),
        })
    }
}

impl OpaqueVal {
    fn new(val: Arc<dyn Opaque>) -> Self {
        Self {
            r#type: Type::new_opaque_type(val.runtime_type_name().to_owned()),
            val,
        }
    }

    fn clone_inner(&self) -> Arc<dyn Opaque> {
        self.val.clone()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OptionalValue {
    value: Option<Value>,
}

impl OptionalValue {
    pub fn of(value: Value) -> Self {
        OptionalValue { value: Some(value) }
    }
    pub fn none() -> Self {
        OptionalValue { value: None }
    }
    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub(crate) fn inner(&self) -> Option<&Value> {
        self.value.as_ref()
    }
}

impl Opaque for OptionalValue {
    fn runtime_type_name(&self) -> &str {
        "optional_type"
    }
}

impl From<OptionalValue> for Option<Value> {
    fn from(value: OptionalValue) -> Self {
        value.value
    }
}

impl<'a> TryFrom<&'a Value> for &'a OptionalValue {
    type Error = ExecutionError;

    fn try_from(value: &'a Value) -> Result<Self, Self::Error> {
        match value {
            Value::Opaque(opaque) if opaque.runtime_type_name() == "optional_type" => opaque
                .downcast_ref::<OptionalValue>()
                .ok_or_else(|| ExecutionError::function_error("optional", "failed to downcast")),
            Value::Opaque(opaque) => Err(ExecutionError::UnexpectedType {
                got: opaque.runtime_type_name().to_string(),
                want: "optional_type".to_string(),
            }),
            v => Err(ExecutionError::UnexpectedType {
                got: v.type_of().to_string(),
                want: "optional_type".to_string(),
            }),
        }
    }
}

pub trait TryIntoValue {
    type Error: std::error::Error + 'static + Send + Sync;
    fn try_into_value(self) -> Result<Value, Self::Error>;
}

impl<T: serde::Serialize> TryIntoValue for T {
    type Error = crate::ser::SerializationError;
    fn try_into_value(self) -> Result<Value, Self::Error> {
        crate::ser::to_value(self)
    }
}
impl TryIntoValue for Value {
    type Error = Infallible;
    fn try_into_value(self) -> Result<Value, Self::Error> {
        Ok(self)
    }
}

#[derive(Clone)]
pub enum Value {
    List(Arc<Vec<Value>>),
    Map(Map),

    Function(Arc<String>, Option<Box<Value>>),

    // Atoms
    Int(i64),
    UInt(u64),
    Float(f64),
    String(Arc<String>),
    Bytes(Arc<Vec<u8>>),
    Bool(bool),
    Duration(chrono::Duration),
    Timestamp(chrono::DateTime<chrono::FixedOffset>),
    Opaque(Arc<dyn Opaque>),
    #[cfg(feature = "structs")]
    Struct(Arc<CelStruct>),
    Null,
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::List(l) => write!(f, "List({:?})", l),
            Value::Map(m) => write!(f, "Map({:?})", m),
            Value::Function(name, func) => write!(f, "Function({:?}, {:?})", name, func),
            Value::Int(i) => write!(f, "Int({:?})", i),
            Value::UInt(u) => write!(f, "UInt({:?})", u),
            Value::Float(d) => write!(f, "Float({:?})", d),
            Value::String(s) => write!(f, "String({:?})", s),
            Value::Bytes(b) => write!(f, "Bytes({:?})", b),
            Value::Bool(b) => write!(f, "Bool({:?})", b),
            Value::Duration(d) => write!(f, "Duration({:?})", d),
            Value::Timestamp(t) => write!(f, "Timestamp({:?})", t),
            Value::Opaque(o) => write!(f, "Opaque<{}>({:?})", o.runtime_type_name(), o.as_debug()),
            Value::Null => write!(f, "Null"),
            #[cfg(feature = "structs")]
            Value::Struct(s) => write!(f, "{} {{}}", s.name()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ValueType {
    List,
    Map,
    Function,
    Int,
    UInt,
    Float,
    String,
    Bytes,
    Bool,
    Duration,
    Timestamp,
    Opaque,
    Null,
    #[cfg(feature = "structs")]
    Struct,
}

impl Display for ValueType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueType::List => write!(f, "list"),
            ValueType::Map => write!(f, "map"),
            ValueType::Function => write!(f, "function"),
            ValueType::Int => write!(f, "int"),
            ValueType::UInt => write!(f, "uint"),
            ValueType::Float => write!(f, "float"),
            ValueType::String => write!(f, "string"),
            ValueType::Bytes => write!(f, "bytes"),
            ValueType::Bool => write!(f, "bool"),
            ValueType::Opaque => write!(f, "opaque"),
            ValueType::Duration => write!(f, "duration"),
            ValueType::Timestamp => write!(f, "timestamp"),
            ValueType::Null => write!(f, "null"),
            #[cfg(feature = "structs")]
            ValueType::Struct => write!(f, "struct"),
        }
    }
}

impl Value {
    pub fn type_of(&self) -> ValueType {
        match self {
            Value::List(_) => ValueType::List,
            Value::Map(_) => ValueType::Map,
            Value::Function(_, _) => ValueType::Function,
            Value::Int(_) => ValueType::Int,
            Value::UInt(_) => ValueType::UInt,
            Value::Float(_) => ValueType::Float,
            Value::String(_) => ValueType::String,
            Value::Bytes(_) => ValueType::Bytes,
            Value::Bool(_) => ValueType::Bool,
            Value::Opaque(_) => ValueType::Opaque,
            Value::Duration(_) => ValueType::Duration,
            Value::Timestamp(_) => ValueType::Timestamp,
            Value::Null => ValueType::Null,
            #[cfg(feature = "structs")]
            Value::Struct(_) => ValueType::Struct,
        }
    }

    pub fn is_zero(&self) -> bool {
        match self {
            Value::List(v) => v.is_empty(),
            Value::Map(v) => v.map.is_empty(),
            Value::Int(0) => true,
            Value::UInt(0) => true,
            Value::Float(f) => *f == 0.0,
            Value::String(v) => v.is_empty(),
            Value::Bytes(v) => v.is_empty(),
            Value::Bool(false) => true,
            Value::Duration(v) => v.is_zero(),
            Value::Null => true,
            _ => false,
        }
    }

    pub fn error_expected_type(&self, expected: ValueType) -> ExecutionError {
        ExecutionError::UnexpectedType {
            got: self.type_of().to_string(),
            want: expected.to_string(),
        }
    }
}

impl From<&Value> for Value {
    fn from(value: &Value) -> Self {
        value.clone()
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Map(a), Value::Map(b)) => a == b,
            (Value::List(a), Value::List(b)) => a == b,
            (Value::Function(a1, a2), Value::Function(b1, b2)) => a1 == b1 && a2 == b2,
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::UInt(a), Value::UInt(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            (Value::Duration(a), Value::Duration(b)) => a == b,
            (Value::Timestamp(a), Value::Timestamp(b)) => a == b,
            // Allow different numeric types to be compared without explicit casting.
            (Value::Int(a), Value::UInt(b)) => a
                .to_owned()
                .try_into()
                .map(|a: u64| a == *b)
                .unwrap_or(false),
            (Value::Int(a), Value::Float(b)) => (*a as f64) == *b,
            (Value::UInt(a), Value::Int(b)) => a
                .to_owned()
                .try_into()
                .map(|a: i64| a == *b)
                .unwrap_or(false),
            (Value::UInt(a), Value::Float(b)) => (*a as f64) == *b,
            (Value::Float(a), Value::Int(b)) => *a == (*b as f64),
            (Value::Float(a), Value::UInt(b)) => *a == (*b as f64),
            (Value::Opaque(a), Value::Opaque(b)) => a.opaque_eq(b.deref()),
            (_, _) => false,
        }
    }
}

impl Eq for Value {}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
            (Value::UInt(a), Value::UInt(b)) => Some(a.cmp(b)),
            (Value::Float(a), Value::Float(b)) => a.partial_cmp(b),
            (Value::String(a), Value::String(b)) => Some(a.cmp(b)),
            (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
            (Value::Null, Value::Null) => Some(Ordering::Equal),
            (Value::Duration(a), Value::Duration(b)) => Some(a.cmp(b)),
            (Value::Timestamp(a), Value::Timestamp(b)) => Some(a.cmp(b)),
            // Allow different numeric types to be compared without explicit casting.
            (Value::Int(a), Value::UInt(b)) => Some(
                a.to_owned()
                    .try_into()
                    .map(|a: u64| a.cmp(b))
                    // If the i64 doesn't fit into a u64 it must be less than 0.
                    .unwrap_or(Ordering::Less),
            ),
            (Value::Int(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
            (Value::UInt(a), Value::Int(b)) => Some(
                a.to_owned()
                    .try_into()
                    .map(|a: i64| a.cmp(b))
                    // If the u64 doesn't fit into a i64 it must be greater than i64::MAX.
                    .unwrap_or(Ordering::Greater),
            ),
            (Value::UInt(a), Value::Float(b)) => (*a as f64).partial_cmp(b),
            (Value::Float(a), Value::Int(b)) => a.partial_cmp(&(*b as f64)),
            (Value::Float(a), Value::UInt(b)) => a.partial_cmp(&(*b as f64)),
            _ => None,
        }
    }
}

impl From<&Key> for Value {
    fn from(value: &Key) -> Self {
        match value {
            Key::Int(v) => Value::Int(*v),
            Key::Uint(v) => Value::UInt(*v),
            Key::Bool(v) => Value::Bool(*v),
            Key::String(v) => Value::String(v.clone()),
        }
    }
}

impl From<Key> for Value {
    fn from(value: Key) -> Self {
        match value {
            Key::Int(v) => Value::Int(v),
            Key::Uint(v) => Value::UInt(v),
            Key::Bool(v) => Value::Bool(v),
            Key::String(v) => Value::String(v),
        }
    }
}

impl From<&Key> for Key {
    fn from(key: &Key) -> Self {
        key.clone()
    }
}

// Convert Vec<T> to Value
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::List(v.into_iter().map(|v| v.into()).collect::<Vec<_>>().into())
    }
}

// Convert Vec<u8> to Value
impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v.into())
    }
}

#[cfg(feature = "bytes")]
// Convert Bytes to Value
impl From<::bytes::Bytes> for Value {
    fn from(v: ::bytes::Bytes) -> Self {
        Value::Bytes(v.to_vec().into())
    }
}

#[cfg(feature = "bytes")]
// Convert &Bytes to Value
impl From<&::bytes::Bytes> for Value {
    fn from(v: &::bytes::Bytes) -> Self {
        Value::Bytes(v.to_vec().into())
    }
}

// Convert String to Value
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::String(v.into())
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(v.to_string().into())
    }
}

// Convert Option<T> to Value
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}

// Convert an insertion-ordered IndexMap<K, V> to Value (D1).
impl<K: Into<Key>, V: Into<Value>> From<indexmap::IndexMap<K, V>> for Value {
    fn from(v: indexmap::IndexMap<K, V>) -> Self {
        Value::Map(v.into())
    }
}

impl From<ExecutionError> for ResolveResult {
    fn from(value: ExecutionError) -> Self {
        Err(value)
    }
}

pub type ResolveResult = Result<Value, ExecutionError>;

impl From<Value> for ResolveResult {
    fn from(value: Value) -> Self {
        Ok(value)
    }
}

/// The error returned when a `dyn Val` has no `Value` representation.
fn no_value_repr(v: &dyn Val) -> ExecutionError {
    ExecutionError::unexpected_type(v.get_type().name(), "a type representable as `Value`")
}

/// Downcasts a `dyn Val` to the built-in type its [`Kind`] implies.
///
/// `Val` is public and not sealed, so a foreign implementation may report a
/// `Kind` without being the built-in value that carries it - a custom lazy list
/// reports `Kind::List` but is not a [`CelList`]. Those reach `Value` as an
/// error, not a panic.
fn built_in<T: Val>(v: &dyn Val) -> Result<&T, ExecutionError> {
    v.downcast_ref::<T>().ok_or_else(|| no_value_repr(v))
}

impl TryFrom<&dyn Val> for Value {
    type Error = ExecutionError;
    fn try_from(v: &dyn Val) -> Result<Self, Self::Error> {
        match v.get_type().kind() {
            Kind::Boolean => Ok(Value::Bool(*built_in::<CelBool>(v)?.inner())),
            Kind::Int => Ok(Value::Int(*built_in::<CelInt>(v)?.inner())),
            Kind::UInt => Ok(Value::UInt(*built_in::<CelUInt>(v)?.inner())),
            Kind::Double => Ok(Value::Float(*built_in::<CelDouble>(v)?.inner())),
            Kind::String => Ok(Value::String(Arc::new(
                built_in::<CelString>(v)?.inner().to_string(),
            ))),
            Kind::NullType => Ok(Value::Null),
            Kind::Bytes => Ok(Value::Bytes(Arc::new(
                built_in::<CelBytes>(v)?.inner().to_vec(),
            ))),
            Kind::Duration => Ok(Value::Duration(*built_in::<CelDuration>(v)?.inner())),
            Kind::Timestamp => Ok(Value::Timestamp(*built_in::<CelTimestamp>(v)?.inner())),
            Kind::List => {
                let list = built_in::<CelList>(v)?.inner();
                let items = list
                    .iter()
                    .map(|i| Value::try_from(i.as_ref()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Value::List(Arc::new(items)))
            }
            Kind::Map => {
                let map = built_in::<CelMap>(v)?.inner();
                let entries = map
                    .iter()
                    .map(|(k, v)| Ok((Key::from(k.clone()), Value::try_from(v.as_ref())?)))
                    .collect::<Result<indexmap::IndexMap<_, _>, ExecutionError>>()?;
                Ok(Value::Map(Map {
                    map: Arc::new(entries),
                }))
            }
            Kind::Type => Ok(Value::String(Arc::new(
                built_in::<CelType>(v)?.name().to_string(),
            ))),
            Kind::Opaque => Ok(Value::Opaque(match v.downcast_ref::<CelOptional>() {
                None => built_in::<OpaqueVal>(v)?.clone_inner(),
                // A present optional whose value has no `Value` representation is
                // an error, not an absent one.
                Some(opt) => match opt.option() {
                    None => Arc::new(OptionalValue::none()),
                    Some(v) => Arc::new(OptionalValue::of(Value::try_from(v)?)),
                },
            })),
            _ => {
                #[cfg(feature = "structs")]
                {
                    if let Some(v) = v.downcast_ref::<CelStruct>() {
                        use crate::common::value::Downcast;

                        return match v.clone_as_boxed().downcast::<CelStruct>() {
                            Ok(v) => Ok(Value::Struct(Arc::new(*v))),
                            Err(v) => Err(ExecutionError::InternalError(format!(
                                "Not a Struct: `{v:?}`"
                            ))),
                        };
                    }
                }
                if let Some(opaque) = v.downcast_ref::<OpaqueVal>() {
                    Ok(Value::Opaque(opaque.val.clone()))
                } else {
                    Err(no_value_repr(v))
                }
            }
        }
    }
}

impl TryFrom<Value> for Box<dyn Val> {
    type Error = ExecutionError;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(b) => Ok(Box::new(CelBool::from(b))),
            Value::Int(i) => Ok(Box::new(CelInt::from(i))),
            Value::UInt(u) => Ok(Box::new(CelUInt::from(u))),
            Value::Float(f) => Ok(Box::new(CelDouble::from(f))),
            Value::String(s) => Ok(Box::new(CelString::from(s.as_str()))),
            Value::Null => Ok(Box::new(CelNull)),
            Value::Bytes(b) => Ok(Box::new(CelBytes::from(b.as_slice().to_vec()))),
            Value::Duration(d) => Ok(Box::new(CelDuration::from(d))),
            Value::Timestamp(ts) => Ok(Box::new(CelTimestamp::from(ts))),
            Value::List(l) => {
                let result: Result<Vec<Box<dyn Val>>, ExecutionError> =
                    (*l).clone().into_iter().map(|i| i.try_into()).collect();
                Ok(Box::new(CelList::from(result?)))
            }
            Value::Map(map) => {
                // D1: preserve the source map's insertion order.
                let result: Result<indexmap::IndexMap<CelMapKey, Box<dyn Val>>, ExecutionError> =
                    (*map.map)
                        .clone()
                        .into_iter()
                        .map(|(k, v)| {
                            v.clone()
                                .try_into()
                                .map(|v| (CelMapKey::from(k.clone()), v))
                        })
                        .collect();
                Ok(Box::new(CelMap::from(result?)))
            }
            Value::Opaque(o) => {
                let v: Box<dyn Val> = if let Some(value) = o.downcast_ref::<OptionalValue>() {
                    match value.inner() {
                        None => Box::new(CelOptional::none()),
                        Some(v) => Box::new(CelOptional::of(v.clone().try_into()?)),
                    }
                } else {
                    Box::new(OpaqueVal::new(o))
                };
                Ok(v)
            }
            #[cfg(feature = "structs")]
            Value::Struct(s) => Ok(Arc::try_unwrap(s)
                .map(|s| Box::new(s) as Box<dyn Val>)
                .unwrap_or_else(|arc| arc.clone_as_boxed())),
            _ => Err(ExecutionError::UnsupportedTargetType {
                target: crate::val_desc::ValueDesc::from(value),
            }),
        }
    }
}

/// Retain the non-list comprehension accumulator using O(1) cached metrics.
///
/// The closed production macro classifier reaches this branch only for
/// exists_one's Int accumulator (one node, eight metric bytes). Map/filter use
/// their shared list construction rows; other fold macros use their own rows.
/// Private raw-comprehension semantic tests can reach this with arbitrary values.
/// This defensive node check is not a general admitted output-size contract:
/// production output bounds come from construction rows and the estimator.
pub(crate) fn charge_value(v: &dyn Val) -> Result<(), ExecutionError> {
    // Legacy raw-comprehension protection; exists_one never approaches this.
    // Keep its refusal sticky, like every resource refusal.
    const MAX_MEASURABLE_NODES: u64 = 2_000_000;
    if v.cached_nodes() > MAX_MEASURABLE_NODES {
        return Err(crate::meter::latch(ExecutionError::MemoryBudgetExceeded(
            "memory_budget: value exceeds measurable size".to_string(),
        )));
    }
    crate::meter::charge_cost(crate::charges::retention(v.cached_bytes()))
}

/// Payload length of a string or bytes value, else the key length
/// estimate used by the map-key row (0 for non-text keys).
fn text_len(v: &dyn Val) -> u64 {
    match v.get_type().kind() {
        Kind::String => v
            .downcast_ref::<CelString>()
            .map(|s| s.inner().len() as u64)
            .unwrap_or(0),
        Kind::Bytes => v
            .downcast_ref::<CelBytes>()
            .map(|b| b.inner().len() as u64)
            .unwrap_or(0),
        _ => 0,
    }
}

/// U1: charge aggregate `==`/`!=` before the deep compare
/// (`1 + min(nodes) + ⌈min(bytes)/64⌉`; the node visit is charged
/// globally, so this site adds the size term when either operand is
/// a list or map). Scalar strings/bytes charge their O(len) compare
/// through the `equality_text` row (F4).
fn charge_equality(a: &dyn Val, b: &dyn Val) -> Result<(), ExecutionError> {
    let ak = a.get_type().kind();
    let bk = b.get_type().kind();
    if matches!(ak, Kind::List | Kind::Map) || matches!(bk, Kind::List | Kind::Map) {
        crate::meter::charge_cost(crate::charges::excluding_node_visit(
            crate::charges::equality_aggregate(
                a.cached_nodes(),
                a.cached_bytes(),
                b.cached_nodes(),
                b.cached_bytes(),
            ),
        ))?;
    } else if matches!(ak, Kind::String | Kind::Bytes) || matches!(bk, Kind::String | Kind::Bytes) {
        crate::meter::charge_cost(crate::charges::excluding_node_visit(
            crate::charges::equality_text(text_len(a), text_len(b)),
        ))?;
    }
    Ok(())
}

/// U6: charge a select/index that must deep-copy an aggregate result
/// (`nodes(v)`); a borrow charges nothing here. A select/index that
/// must own a copy of a string or bytes payload charges ⌈len/64⌉
/// (F4b); other scalars are O(1) and charge nothing here.
fn charge_aggregate_copy(v: &dyn Val) -> Result<(), ExecutionError> {
    match v.get_type().kind() {
        Kind::List | Kind::Map => {
            crate::meter::charge_cost(crate::charges::aggregate_select(
                v.cached_nodes(),
                v.cached_bytes(),
            ))?;
            crate::meter::note_op_body();
        }
        Kind::String | Kind::Bytes => {
            crate::meter::charge_cost(crate::charges::excluding_node_visit(
                crate::charges::aggregate_select_text(text_len(v)),
            ))?;
            crate::meter::note_op_body();
        }
        _ => {}
    }
    Ok(())
}

/// The error a failed select/index raises: a missing map key is
/// `NoSuchKey`, anything else is `NoSuchOverload`.
fn select_key_error(container: &dyn Val, key: &CelString) -> ExecutionError {
    match container.get_type().kind() {
        Kind::Map => crate::common::types::map::missing_key(key),
        _ => ExecutionError::NoSuchOverload,
    }
}

/// U4: charge `contains` / `startsWith` / `endsWith` before the call
/// body, from the receiver and argument metrics.
fn charge_named_call(
    func_name: &str,
    args: &[std::borrow::Cow<'_, dyn Val>],
) -> Result<(), ExecutionError> {
    let Some(target) = args.first() else {
        return Ok(());
    };
    let t = target.as_ref();
    let arg_len = || args.get(1).map(|a| text_len(a.as_ref())).unwrap_or(0);
    let ex = crate::charges::excluding_node_visit;
    let cost = match func_name {
        "contains" => match t.get_type().kind() {
            Kind::List => Some(ex(crate::charges::containment_in_list(
                t.cached_nodes(),
                t.cached_bytes(),
            ))),
            Kind::Map => Some(ex(crate::charges::map_key_lookup(arg_len()))),
            Kind::String | Kind::Bytes => {
                Some(ex(crate::charges::string_contains(text_len(t), arg_len())))
            }
            _ => None,
        },
        "startsWith" | "endsWith" => {
            Some(ex(crate::charges::string_contains(text_len(t), arg_len())))
        }
        _ => None,
    };
    if let Some(cost) = cost {
        crate::meter::charge_cost(cost)?;
    }
    Ok(())
}

/// The macro-generated append step (design §1.3, U10): `@result + [e]`
/// for `map`, or `cond ? @result + [x] : @result` for `filter`.
/// Charge the U10 append increment (`1 + nodes(e)` wu, `bytes(e) +
/// 32` mb) from the borrowed element, before it is owned (F3), so a
/// refused element is never copied. The borrow ends at the caller's
/// `into_owned`, before the mutable push below.
fn charge_append(e: &dyn Val) -> Result<(), ExecutionError> {
    crate::meter::charge_cost(crate::charges::list_append_in_place(
        e.cached_nodes(),
        e.cached_bytes(),
    ))
}

/// Append an already-charged owned `e` to the `@result` accumulator
/// **in place**: take it from the context, push (O(1) incremental
/// metrics), rebind — no copy and no re-walk.
fn push_charged_in_place<'a>(
    ctx: &mut Context<'a>,
    accu_var: &str,
    e: Box<dyn Val>,
) -> Result<(), ExecutionError> {
    let boxed = ctx
        .take_variable(accu_var)
        .ok_or(ExecutionError::NoSuchOverload)?;
    let mut list: Box<CelList> = boxed
        .downcast::<CelList>()
        .map_err(|_| ExecutionError::NoSuchOverload)?;
    list.push(e);
    ctx.add_variable_as_val(accu_var, list);
    Ok(())
}

/// Map-key hashing (`m[k]`, `m.k`, `k in m`, `m.contains(k)`): charge
/// `1 + ⌈len(k)/64⌉` before the hash lookup. No-op on non-maps.
fn charge_map_key(container: &dyn Val, key: &dyn Val) -> Result<(), ExecutionError> {
    if container.get_type().kind() == Kind::Map {
        crate::meter::charge_cost(crate::charges::excluding_node_visit(
            crate::charges::map_key_lookup(text_len(key)),
        ))?;
    }
    Ok(())
}

/// U14: charge `<`…`>=` on strings or bytes before the O(len) compare.
fn charge_text_ordering(a: &dyn Val, b: &dyn Val) -> Result<(), ExecutionError> {
    let ak = a.get_type().kind();
    let bk = b.get_type().kind();
    if matches!(ak, Kind::String | Kind::Bytes) || matches!(bk, Kind::String | Kind::Bytes) {
        crate::meter::charge_cost(crate::charges::excluding_node_visit(
            crate::charges::string_or_bytes_order(text_len(a), text_len(b)),
        ))?;
    }
    Ok(())
}

impl Value {
    pub fn resolve_all(expr: &[Expression], ctx: &Context) -> ResolveResult {
        let mut res = Vec::with_capacity(expr.len());
        for expr in expr {
            res.push(Value::resolve(expr, ctx)?);
        }
        Ok(Value::List(res.into()))
    }

    pub fn resolve(expr: &Expression, ctx: &Context) -> ResolveResult {
        let v = Self::resolve_val(expr, ctx)?;
        // U12: result emission charges `nodes(result)` before the deep
        // conversion to `Value`.
        crate::meter::charge_cost(crate::charges::result_emission(
            v.as_ref().cached_nodes(),
            v.as_ref().cached_bytes(),
        ))?;
        crate::meter::note_op_body();
        v.as_ref().try_into()
    }

    /// U5 `matches`: literal-only, compile-once. The pattern must be a
    /// string literal (checked at `check`); the prepared regex is
    /// looked up and the search charged before it runs.
    fn resolve_matches<'a>(
        call: &CallExpr,
        ctx: &'a Context<'a>,
    ) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        let (receiver, pattern_expr) = match (&call.target, call.args.len()) {
            (Some(t), 1) => (Value::resolve_val(t, ctx)?, &call.args[0]),
            (None, 2) => (Value::resolve_val(&call.args[0], ctx)?, &call.args[1]),
            _ => return Err(ExecutionError::NoSuchOverload),
        };
        let pattern = Value::resolve_val(pattern_expr, ctx)?;
        let pattern = pattern
            .as_ref()
            .downcast_ref::<CelString>()
            .ok_or(ExecutionError::NoSuchOverload)?
            .inner();
        let receiver = receiver
            .as_ref()
            .downcast_ref::<CelString>()
            .ok_or(ExecutionError::NoSuchOverload)?
            .inner();
        Ok(bool(crate::regexes::is_match(pattern, receiver)?))
    }

    /// Fold an `all`/`exists` predicate with error absorption: a
    /// determining element short-circuits (absorbing any remembered
    /// error); element errors are remembered and replayed only when
    /// no determining element exists. Matches cel-spec `&&`/`||`
    /// combination semantics; empty input yields the neutral value.
    fn resolve_absorbing_fold<'a>(
        comprehension: &'a ComprehensionExpr,
        kind: AbsorbingFold,
        pred: &'a Expression,
        ctx: &'a Context<'a>,
    ) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        let (determining, neutral) = match kind {
            AbsorbingFold::All => (false, true),
            AbsorbingFold::Exists => (true, false),
        };
        let singleton = crate::comprehension::singleton_range(comprehension);
        let iter = Value::resolve_val(singleton.unwrap_or(&comprehension.iter_range), ctx)?;
        let mut ctx = ctx.new_inner_scope();
        let mut items: Box<dyn crate::common::traits::Iterator<'_> + '_> = if singleton.is_some() {
            Box::new(SingletonIterator(Some(iter.as_ref())))
        } else {
            iter.as_iterable()
                .ok_or(ExecutionError::NoSuchOverload)?
                .iter()
        };
        let mut remembered: Option<ExecutionError> = None;
        let mut error_bytes = 0u64;
        // Comprehension exit restores to the entry level + result bytes
        // (design §1.3). `all`/`exists` return a bool, so their exits —
        // the determining short-circuit and the error propagation path
        // — drop every iteration's temporaries by restoring here.
        let entry_level = crate::meter::level();
        while let Some(item) = items.next() {
            // Scoped memory (design §1.3): snapshot the level at the
            // iteration start, then drop the iteration's temporaries
            // at its end. `all`/`exists` keep no accumulator, so the
            // level returns to the snapshot.
            // U9: item bind is work (`1 + nodes + ⌈bytes/64⌉` while
            // it deep-copies; F4 adds the payload term for strings).
            let borrowed = crate::comprehension::classify(comprehension).is_some();
            crate::meter::charge_cost(if borrowed {
                crate::charges::comprehension_item_bind_ref()
            } else {
                crate::charges::comprehension_item_bind(item.cached_nodes(), item.cached_bytes())
            })?;
            crate::meter::charge_cost(crate::charges::payload_copy(
                1,
                comprehension.iter_var.len() as u64,
            ))?;
            crate::meter::note_op_body();
            if borrowed {
                ctx.bind_borrowed(&comprehension.iter_var, item);
            } else {
                ctx.add_variable_as_val(&comprehension.iter_var, item.clone_as_boxed());
            }
            match Value::resolve_val(pred, &ctx) {
                Ok(v) => match v.downcast_ref::<CelBool>() {
                    Some(b) if *b.inner() == determining => {
                        drop(ctx.take_variable(&comprehension.iter_var));
                        crate::meter::set_level(entry_level);
                        return Ok(bool(determining));
                    }
                    Some(_) => {}
                    None => {
                        drop(ctx.take_variable(&comprehension.iter_var));
                        crate::meter::set_level(entry_level);
                        return Err(ExecutionError::NoSuchOverload);
                    }
                },
                Err(e) => {
                    // The error is absorbed; the iteration still ends,
                    // so the level is restored below exactly as on the
                    // success path.
                    if remembered.is_none() {
                        crate::meter::charge_memory(crate::charges::RETAINED_ERROR_BYTES)?;
                        error_bytes = crate::charges::RETAINED_ERROR_BYTES;
                        remembered = Some(e);
                    }
                }
            }
            drop(ctx.take_variable(&comprehension.iter_var));
            crate::meter::set_level(entry_level.saturating_add(error_bytes));
        }
        crate::meter::set_level(entry_level.saturating_add(error_bytes));
        match remembered {
            Some(e) => Err(e),
            None => Ok(bool(neutral)),
        }
    }

    #[inline(always)]
    pub fn resolve_val<'a>(
        expr: &'a Expression,
        ctx: &'a Context<'a>,
    ) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        // Meter hook: charge the node visit (1 wu) and one depth level
        // *before* the node's work, so a refused node never runs. Zero
        // behaviour change when no budget is installed.
        let _node = crate::meter::enter_node()?;
        crate::meter::note_body_ran();
        match &expr.expr {
            Expr::Literal(literal) => {
                // Charge literal materialisation (string / bytes
                // payload bytes; scalars cost nothing extra) through
                // the §1.3 `string or bytes literal` row (memory
                // column; its wu is the node visit above).
                match literal {
                    crate::common::ast::LiteralValue::String(s) => {
                        crate::meter::charge_cost(crate::charges::excluding_node_visit(
                            crate::charges::string_or_bytes_literal(s.inner().len() as u64),
                        ))?;
                    }
                    crate::common::ast::LiteralValue::Bytes(b) => {
                        crate::meter::charge_cost(crate::charges::excluding_node_visit(
                            crate::charges::string_or_bytes_literal(b.inner().len() as u64),
                        ))?;
                    }
                    _ => {}
                }
                Ok(literal.to_val())
            }
            Expr::Call(call) => {
                // U5: `matches` is literal-only and compile-once; handle
                // it here so the prepared pattern is used and charged.
                if call.func_name == "matches" {
                    return Self::resolve_matches(call, ctx);
                }
                // START OF SPECIAL CASES FOR operators::...
                if call.args.len() == 3 && call.func_name == operators::CONDITIONAL {
                    let cond = Value::resolve_val(&call.args[0], ctx);
                    return if try_bool(cond)? {
                        Value::resolve_val(&call.args[1], ctx)
                    } else {
                        Value::resolve_val(&call.args[2], ctx)
                    };
                }
                if call.args.len() == 2 {
                    match call.func_name.as_str() {
                        operators::LOGICAL_OR => {
                            let left = try_bool(Value::resolve_val(&call.args[0], ctx));
                            return if Ok(true) == left {
                                Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(true))))
                            } else {
                                let right = Value::resolve_val(&call.args[1], ctx)?
                                    .downcast_ref::<CelBool>()
                                    .map(|b| *b.inner());
                                match (left, right) {
                                    (Ok(false), Some(right)) => {
                                        Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(right))))
                                    }
                                    (Err(_), Some(true)) => {
                                        Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(true))))
                                    }
                                    (left, _) => Err(left.err().unwrap_or(NoSuchOverload)),
                                }
                            };
                        }
                        operators::LOGICAL_AND => {
                            let left = try_bool(Value::resolve_val(&call.args[0], ctx));
                            return if Ok(false) == left {
                                Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(false))))
                            } else {
                                let right = Value::resolve_val(&call.args[1], ctx)?
                                    .downcast_ref::<CelBool>()
                                    .map(|b| *b.inner());
                                match (left, right) {
                                    (Ok(true), Some(right)) => {
                                        Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(right))))
                                    }
                                    (Err(_), Some(false)) => {
                                        Ok(Cow::<dyn Val>::Owned(Box::new(CelBool::from(false))))
                                    }
                                    (left, _) => Err(left.err().unwrap_or(NoSuchOverload)),
                                }
                            };
                        }
                        operators::EQUALS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            charge_equality(lhs.as_ref(), rhs.as_ref())?;
                            crate::meter::note_op_body();
                            return Ok(bool(lhs.as_ref().equals(rhs.as_ref())));
                        }
                        operators::NOT_EQUALS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            charge_equality(lhs.as_ref(), rhs.as_ref())?;
                            crate::meter::note_op_body();
                            return Ok(bool(!lhs.as_ref().equals(rhs.as_ref())));
                        }
                        operators::INDEX | operators::OPT_INDEX => {
                            let mut is_optional = call.func_name == operators::OPT_INDEX;
                            let value = Value::resolve_val(&call.args[0], ctx)?;

                            let value = if let Some(opt) = value.downcast_ref::<CelOptional>() {
                                is_optional = true;
                                match opt.inner() {
                                    // todo try to keep this borrowed
                                    Some(v) => Cow::Owned(v.clone_as_boxed()),
                                    None => {
                                        return Ok(Cow::<dyn Val>::Owned(Box::new(
                                            CelOptional::none(),
                                        )))
                                    }
                                }
                            } else {
                                value
                            };

                            let idx = Self::resolve_val(&call.args[1], ctx)?;
                            let result = match value {
                                Cow::Borrowed(val) => {
                                    charge_map_key(val, idx.as_ref())?;
                                    val.as_indexer()
                                        .ok_or(ExecutionError::NoSuchOverload)?
                                        .get(idx.as_ref())
                                }
                                Cow::Owned(val) => {
                                    charge_map_key(val.as_ref(), idx.as_ref())?;
                                    val.into_indexer()
                                        .ok_or(ExecutionError::NoSuchOverload)?
                                        .steal(idx.as_ref())
                                        .map(Cow::Owned)
                                }
                            };
                            return if is_optional {
                                Ok(match result {
                                    Ok(val) => {
                                        // The wrap copies the value into
                                        // the optional; charge an owned
                                        // copy (F4b covers text).
                                        charge_aggregate_copy(val.as_ref())?;
                                        Cow::<dyn Val>::Owned(Box::new(CelOptional::from(
                                            val.clone_as_boxed(),
                                        )))
                                    }
                                    Err(_) => Cow::<dyn Val>::Owned(Box::new(CelOptional::none())),
                                })
                            } else {
                                result
                            };
                        }
                        operators::OPT_SELECT => {
                            let operand = Value::resolve_val(&call.args[0], ctx)?;
                            let field_literal = Value::resolve_val(&call.args[1], ctx)?;
                            let field = match field_literal.get_type().kind() {
                                Kind::String => field_literal
                                    .downcast_ref::<CelString>()
                                    .expect("field must be string"),
                                _ => {
                                    return Err(ExecutionError::function_error(
                                        "_?._",
                                        "field must be string",
                                    ))
                                }
                            };
                            // Unwrap outer optional if present — a `None`
                            // short-circuits to `Optional::none()`. Otherwise
                            // the operand is the target itself. A missing
                            // key/field maps to `Optional::none()` per
                            // cel-spec (mirrors OPT_INDEX semantics).
                            let target: Option<&dyn Val> =
                                if let Some(opt) = operand.downcast_ref::<CelOptional>() {
                                    opt.option()
                                } else {
                                    Some(operand.as_ref())
                                };
                            if let Some(v) = target {
                                charge_map_key(v, field)?;
                            }
                            let result = match target.and_then(|v| v.as_indexer()) {
                                Some(indexer) => match indexer.get(field) {
                                    Ok(v) => {
                                        charge_aggregate_copy(v.as_ref())?;
                                        CelOptional::of(v.clone_as_boxed())
                                    }
                                    Err(_) => CelOptional::none(),
                                },
                                None => CelOptional::none(),
                            };
                            return Ok(Cow::<dyn Val>::Owned(Box::new(result)));
                        }
                        // END OF SPECIAL CASES

                        // all below is NOT special in the interpreter
                        operators::ADD => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(Cow::Owned(
                                lhs.as_ref()
                                    .as_adder()
                                    .ok_or_else(|| {
                                        ExecutionError::UnsupportedBinaryOperator(
                                            "add",
                                            crate::val_desc::ValueDesc::of(lhs.as_ref()),
                                            crate::val_desc::ValueDesc::of(rhs.as_ref()),
                                        )
                                    })?
                                    .add(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::SUBSTRACT => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(Cow::Owned(
                                lhs.as_subtractor()
                                    .ok_or_else(|| {
                                        ExecutionError::UnsupportedBinaryOperator(
                                            "sub",
                                            crate::val_desc::ValueDesc::of(lhs.as_ref()),
                                            crate::val_desc::ValueDesc::of(rhs.as_ref()),
                                        )
                                    })?
                                    .sub(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::DIVIDE => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(Cow::Owned(
                                lhs.as_divider()
                                    .ok_or_else(|| {
                                        ExecutionError::UnsupportedBinaryOperator(
                                            "div",
                                            crate::val_desc::ValueDesc::of(lhs.as_ref()),
                                            crate::val_desc::ValueDesc::of(rhs.as_ref()),
                                        )
                                    })?
                                    .div(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::MULTIPLY => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(Cow::Owned(
                                lhs.as_multiplier()
                                    .ok_or_else(|| {
                                        ExecutionError::UnsupportedBinaryOperator(
                                            "mul",
                                            crate::val_desc::ValueDesc::of(lhs.as_ref()),
                                            crate::val_desc::ValueDesc::of(rhs.as_ref()),
                                        )
                                    })?
                                    .mul(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::MODULO => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            return Ok(Cow::Owned(
                                lhs.as_modder()
                                    .ok_or_else(|| {
                                        ExecutionError::UnsupportedBinaryOperator(
                                            "rem",
                                            crate::val_desc::ValueDesc::of(lhs.as_ref()),
                                            crate::val_desc::ValueDesc::of(rhs.as_ref()),
                                        )
                                    })?
                                    .modulo(rhs.as_ref())?
                                    .into_owned(),
                            ));
                        }
                        operators::LESS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            charge_text_ordering(lhs.as_ref(), rhs.as_ref())?;
                            // Fork fix: NaN poisons ordering — all four
                            // comparison operators are false with a NaN
                            // operand (IEEE 754 / cel-spec), not errors.
                            if either_nan(lhs.as_ref(), rhs.as_ref()) {
                                return Ok(bool(false));
                            }
                            return Ok(bool(
                                lhs.as_comparer()
                                    .ok_or(ExecutionError::NoSuchOverload)?
                                    .compare(rhs.as_ref())?
                                    == Ordering::Less,
                            ));
                        }
                        operators::LESS_EQUALS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            charge_text_ordering(lhs.as_ref(), rhs.as_ref())?;
                            if either_nan(lhs.as_ref(), rhs.as_ref()) {
                                return Ok(bool(false));
                            }
                            return if lhs
                                .as_comparer()
                                .ok_or(ExecutionError::NoSuchOverload)?
                                .compare(rhs.as_ref())?
                                == Ordering::Greater
                            {
                                Ok(bool(false))
                            } else {
                                Ok(bool(true))
                            };
                        }
                        operators::GREATER => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            charge_text_ordering(lhs.as_ref(), rhs.as_ref())?;
                            if either_nan(lhs.as_ref(), rhs.as_ref()) {
                                return Ok(bool(false));
                            }
                            return Ok(bool(
                                lhs.as_comparer()
                                    .ok_or(ExecutionError::NoSuchOverload)?
                                    .compare(rhs.as_ref())?
                                    == Ordering::Greater,
                            ));
                        }
                        operators::GREATER_EQUALS => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            charge_text_ordering(lhs.as_ref(), rhs.as_ref())?;
                            if either_nan(lhs.as_ref(), rhs.as_ref()) {
                                return Ok(bool(false));
                            }
                            return if lhs
                                .as_comparer()
                                .ok_or(ExecutionError::NoSuchOverload)?
                                .compare(rhs.as_ref())?
                                == Ordering::Less
                            {
                                Ok(bool(false))
                            } else {
                                Ok(bool(true))
                            };
                        }
                        operators::IN => {
                            let lhs = Value::resolve_val(&call.args[0], ctx)?;
                            let rhs = Value::resolve_val(&call.args[1], ctx)?;
                            // U2/U4 + map-key hashing, before the scan.
                            match rhs.get_type().kind() {
                                Kind::List => {
                                    crate::meter::charge_cost(
                                        crate::charges::excluding_node_visit(
                                            crate::charges::containment_in_list(
                                                rhs.cached_nodes(),
                                                rhs.cached_bytes(),
                                            ),
                                        ),
                                    )?;
                                }
                                Kind::Map => {
                                    crate::meter::charge_cost(
                                        crate::charges::excluding_node_visit(
                                            crate::charges::map_key_lookup(text_len(lhs.as_ref())),
                                        ),
                                    )?;
                                }
                                _ => {}
                            }
                            return if let Some(container) = rhs.as_container() {
                                crate::meter::note_op_body();
                                Ok(bool(container.contains(lhs.as_ref())?))
                            } else {
                                Err(ExecutionError::NoSuchOverload)
                            };
                        }
                        _ => (),
                    }
                }
                if call.args.len() == 1 {
                    match call.func_name.as_str() {
                        operators::LOGICAL_NOT => {
                            let expr = Value::resolve_val(&call.args[0], ctx)?;
                            return expr
                                .downcast_ref::<CelBool>()
                                .map(Bool::negate)
                                .ok_or(ExecutionError::NoSuchOverload)
                                .map(|b| bool(b.into_inner()));
                        }
                        operators::NEGATE => {
                            let val = Value::resolve_val(&call.args[0], ctx)?;
                            return Ok(Cow::<dyn Val>::Owned(
                                val.as_negator()
                                    .ok_or(ExecutionError::NoSuchOverload)?
                                    .negate()?,
                            ));
                        }
                        operators::NOT_STRICTLY_FALSE => {
                            return Ok(bool(
                                try_bool(Value::resolve_val(&call.args[0], ctx)).unwrap_or(true),
                            ));
                        }
                        _ => (),
                    }
                }
                match &call.target {
                    None => {
                        // TODO: Optimize for the 1 and 2 arg cases and avoid the Vec altogether
                        let args: Result<Vec<Cow<dyn Val>>, ExecutionError> = call
                            .args
                            .iter()
                            .map(|a| Value::resolve_val(a, ctx))
                            .collect();
                        let args = args?;
                        charge_named_call(&call.func_name, &args)?;
                        if let Some(op) = ctx.env().find_overload(&call.func_name, &args) {
                            return op(args);
                        }
                        if ctx.env().has_function(&call.func_name) {
                            return Err(ExecutionError::NoSuchOverload);
                        }
                        let func = ctx.get_function(call.func_name.as_str()).ok_or_else(|| {
                            ExecutionError::UndeclaredReference(call.func_name.clone().into())
                        })?;
                        let mut ctx = FunctionContext::new(&call.func_name, None, ctx, args);
                        let v = (func)(&mut ctx)?;
                        Ok(Cow::<dyn Val>::Owned(TryInto::<Box<dyn Val>>::try_into(v)?))
                    }
                    Some(target) => {
                        let args: Result<Vec<Cow<dyn Val>>, ExecutionError> = call
                            .args
                            .iter()
                            .map(|a| Value::resolve_val(a, ctx))
                            .collect();
                        let args = args?;
                        let qualified_func = match &target.expr {
                            Expr::Ident(prefix) => {
                                let qualified_name = format!("{prefix}.{}", call.func_name);
                                if let Some(op) = ctx.env().find_overload(&qualified_name, &args) {
                                    return op(args);
                                }
                                ctx.get_function(&qualified_name)
                            }
                            _ => None,
                        };
                        let (target, func, args) = match qualified_func {
                            None => {
                                let target = Value::resolve_val(target, ctx)?;
                                let mut args = args;
                                args.insert(0, target);
                                charge_named_call(&call.func_name, &args)?;
                                if let Some(op) =
                                    ctx.env().find_member_overload(&call.func_name, &args)
                                {
                                    return op(args);
                                }
                                if ctx.env().has_function(&call.func_name) {
                                    return Err(ExecutionError::NoSuchOverload);
                                }
                                let target = args.remove(0);
                                let func =
                                    ctx.get_function(call.func_name.as_str()).ok_or_else(|| {
                                        ExecutionError::UndeclaredReference(
                                            call.func_name.clone().into(),
                                        )
                                    })?;
                                (Some(target), func, args)
                            }
                            Some(func) => (None, func, args),
                        };
                        let mut ctx = FunctionContext::new(&call.func_name, target, ctx, args);
                        // todo fix this to _not_ use `Value`
                        let v = (func)(&mut ctx)?;
                        Ok(Cow::<dyn Val>::Owned(TryInto::<Box<dyn Val>>::try_into(v)?))
                    }
                }
            }
            Expr::Ident(name) => Ok(ctx
                .get_variable(name)
                .ok_or_else(|| ExecutionError::UndeclaredReference(Arc::new(name.to_string())))?),
            Expr::Select(select) => {
                let left = Value::resolve_val(select.operand.deref(), ctx)?;
                crate::meter::charge_cost(crate::charges::payload_copy(
                    1,
                    select.field.len() as u64,
                ))?;
                crate::meter::note_op_body();
                let key: CelString = select.field.as_str().into();

                // Plain `.field` on an `Optional` propagates optional-ness
                // per cel-spec — matches cel-go `applyQualifiers` at
                // `interpreter/attributes.go:1259` where an initial optional
                // operand makes the whole qualifier chain optional. `has()`
                // (test=true) on the same shape returns Bool(false) when the
                // chain is empty.
                if let Some(opt) = left.downcast_ref::<CelOptional>() {
                    // Optional::none() short-circuits — the chain stops.
                    // Otherwise unwrap and access the field. A missing key on
                    // a real container maps to Optional::none(); a field
                    // access on a value that isn't a container at all
                    // (Null, Int, …) is an error, matching cel-go's
                    // `errorOnBadPresenceTest=true` mode which the cel-spec
                    // conformance runner enables (see
                    // `interpreter/attributes.go:1382` and
                    // `conformance/conformance_test.go:87`).
                    return match opt.option() {
                        None => {
                            if select.test {
                                Ok(bool(false))
                            } else {
                                Ok(Cow::<dyn Val>::Owned(Box::new(CelOptional::none())))
                            }
                        }
                        Some(inner) => {
                            let indexer = inner.as_indexer().ok_or_else(|| {
                                ExecutionError::NoSuchKey(Arc::new(key.inner().to_string()))
                            })?;
                            if select.test {
                                Ok(bool(indexer.get(&key).is_ok()))
                            } else {
                                let result = match indexer.get(&key) {
                                    Ok(v) => {
                                        charge_aggregate_copy(v.as_ref())?;
                                        CelOptional::of(v.clone_as_boxed())
                                    }
                                    Err(_) => CelOptional::none(),
                                };
                                Ok(Cow::<dyn Val>::Owned(Box::new(result)))
                            }
                        }
                    };
                }

                if select.test {
                    match left.get_type().kind() {
                        Kind::Map => {
                            charge_map_key(left.as_ref(), &key)?;
                            Ok(bool(
                                left.as_container()
                                    .ok_or_else(|| {
                                        ExecutionError::NoSuchKey(Arc::new(key.inner().to_string()))
                                    })?
                                    .contains(&key)?,
                            ))
                        }
                        #[cfg(feature = "structs")]
                        Kind::Struct => {
                            if let Some(indexer) = left.as_indexer() {
                                Ok(bool(indexer.get(&key).is_ok()))
                            } else {
                                Ok(bool(false))
                            }
                        }
                        _ => {
                            charge_map_key(left.as_ref(), &key)?;
                            let v = left
                                .as_indexer()
                                .ok_or_else(|| ExecutionError::NoSuchOverload)?
                                .get(&key)?;
                            charge_aggregate_copy(v.as_ref())?;
                            Ok(Cow::<dyn Val>::Owned(v.into_owned()))
                        }
                    }
                } else {
                    // U6: borrow the field when the operand is itself
                    // borrowed (context-owned, e.g. `inputs.rows`), and
                    // deep-copy — charging `nodes` — only when the
                    // operand is a temporary we must own past.
                    match left {
                        Cow::Borrowed(inner) => {
                            charge_map_key(inner, &key)?;
                            let indexer = inner
                                .as_indexer()
                                .ok_or_else(|| select_key_error(inner, &key))?;
                            Ok(indexer.get(&key)?)
                        }
                        Cow::Owned(inner) => {
                            charge_map_key(inner.as_ref(), &key)?;
                            let indexer = inner
                                .as_indexer()
                                .ok_or_else(|| select_key_error(inner.as_ref(), &key))?;
                            let v = indexer.get(&key)?;
                            charge_aggregate_copy(v.as_ref())?;
                            Ok(Cow::Owned(v.into_owned()))
                        }
                    }
                }
            }
            Expr::List(list_expr) => {
                // F3: resolve every element as a borrow first, charge
                // from the cached metrics, then copy — a refused
                // literal's elements are never copied.
                let values = list_expr
                    .elements
                    .iter()
                    .map(|element| Value::resolve_val(element, ctx))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut nodes = 0u64;
                let mut bytes = 0u64;
                let mut text = 0u64;
                for v in &values {
                    nodes = nodes.saturating_add(v.as_ref().cached_nodes());
                    bytes = bytes.saturating_add(v.as_ref().cached_bytes());
                    // Round 3: cached bytes, not just top-level text,
                    // so strings nested inside an element are charged.
                    text = text.saturating_add(v.as_ref().cached_bytes());
                }
                // U8: charge the literal's work and memory before the
                // slots are built. F4 remainder: payload bytes copied
                // into the literal add ⌈bytes/64⌉ work, from the cached
                // metrics (O(1)).
                crate::meter::charge_cost(crate::charges::list_literal(
                    values.len() as u64,
                    nodes,
                    bytes,
                ))?;
                crate::meter::charge_cost(crate::charges::literal_text_payload(text))?;
                crate::meter::note_op_body();
                let mut list = Vec::with_capacity(values.len());
                for (idx, value) in values.into_iter().enumerate() {
                    if list_expr.optional_indices.contains(&idx) {
                        if let Some(opt_val) = value.as_ref().downcast_ref::<CelOptional>() {
                            if let Some(inner) = opt_val.inner() {
                                list.push(inner.clone_as_boxed());
                            }
                        } else {
                            list.push(value.into_owned());
                        }
                    } else {
                        list.push(value.into_owned());
                    }
                }
                Ok(Cow::<dyn Val>::Owned(Box::new(CelList::from(list))))
            }
            Expr::Map(map_expr) => {
                // D1: insertion order follows source order.
                // F3: resolve keys and values as borrows first, charge
                // from the cached metrics, then copy — a refused
                // literal's values are never copied.
                let mut resolved = Vec::with_capacity(map_expr.entries.len());
                for entry in map_expr.entries.iter() {
                    let (k, v, is_optional) = match &entry.expr {
                        EntryExpr::StructField(_) => panic!("WAT?"),
                        EntryExpr::MapEntry(e) => (&e.key, &e.value, e.optional),
                    };
                    let key = Value::resolve_val(k, ctx)?;
                    // N1: check the key's type before evaluating its
                    // value, restoring the old error precedence
                    // (`{3.3: 1/0}` reports the bad key, not the
                    // value's error). The charge still waits until
                    // all entries are resolved; keys are scalars.
                    crate::common::types::map::validate_key(key.as_ref())?;
                    if matches!(key, Cow::Borrowed(_)) {
                        crate::common::types::map::charge_key_copy(key.as_ref())?;
                    }
                    let key: CelMapKey = key.into_owned().try_into()?;
                    let value = Value::resolve_val(v, ctx)?;
                    resolved.push((key, value, is_optional));
                }
                // U8: charge the literal's work and memory before the
                // map is built (rollup includes slots, keys, values).
                let mut nodes = 1u64;
                let mut bytes =
                    crate::charges::MAP_ENTRY_BYTES.saturating_mul(resolved.len() as u64);
                let mut text = 0u64;
                for (key, value, _) in &resolved {
                    nodes = nodes.saturating_add(value.as_ref().cached_nodes());
                    bytes = bytes
                        .saturating_add(crate::metrics::key_bytes(key))
                        .saturating_add(value.as_ref().cached_bytes());
                    // Round 3: value bytes include nested payloads;
                    // keys are scalars, so the key length is exact.
                    text = text
                        .saturating_add(match key {
                            CelMapKey::String(s) => s.inner().len() as u64,
                            _ => 0,
                        })
                        .saturating_add(value.as_ref().cached_bytes());
                }
                crate::meter::charge_cost(crate::charges::map_literal_rollup(
                    resolved.len() as u64,
                    nodes,
                    bytes,
                ))?;
                crate::meter::charge_cost(crate::charges::literal_text_payload(text))?;
                crate::meter::note_op_body();
                let mut map = indexmap::IndexMap::with_capacity(resolved.len());
                for (key, value, is_optional) in resolved {
                    // todo do not clone if not needed!
                    let value = value.into_owned();
                    if is_optional {
                        if let Some(opt_val) = value.as_ref().downcast_ref::<CelOptional>() {
                            if let Some(inner) = opt_val.inner() {
                                map.insert(key, inner.clone_as_boxed());
                            }
                        } else {
                            map.insert(key, value);
                        }
                    } else {
                        map.insert(key, value);
                    }
                }
                let map: Box<CelMap> = CelMap::from(map).into();
                Ok(Cow::<dyn Val>::Owned(map))
            }
            Expr::Comprehension(comprehension) => {
                // Fork fix: `all`/`exists` combine predicates with
                // `&&`/`||`, so a determining element absorbs another
                // element's error (cel-spec). The generic fold below
                // aborts the loop on the first step error via `?`
                // before a later determining element is visited.
                if let Some((kind, pred)) = absorbing_fold(comprehension) {
                    return Self::resolve_absorbing_fold(comprehension, kind, pred, ctx);
                }
                let accu_init = Value::resolve_val(&comprehension.accu_init, ctx)?;
                let singleton = crate::comprehension::singleton_range(comprehension);
                let iter = Value::resolve_val(singleton.unwrap_or(&comprehension.iter_range), ctx)?;
                let mut ctx = ctx.new_inner_scope();
                // Scoped memory (design §1.3): the accumulator's
                // initial bytes are retained; `entry_level` excludes
                // them, and comprehension exit restores to
                // `entry_level + bytes(result)`.
                let entry_level = crate::meter::level();
                let mut accu_bytes = accu_init.cached_bytes();
                crate::meter::charge_memory(accu_bytes)?;
                crate::meter::charge_work(
                    crate::charges::payload_copy(
                        accu_init.cached_nodes(),
                        accu_init.cached_bytes(),
                    )
                    .work,
                )?;
                crate::meter::note_op_body();
                ctx.add_variable_as_val(&comprehension.accu_var, accu_init.clone_as_boxed());

                let mut items: Box<dyn crate::common::traits::Iterator<'_> + '_> =
                    if singleton.is_some() {
                        Box::new(SingletonIterator(Some(iter.as_ref())))
                    } else {
                        iter.as_iterable()
                            .ok_or(ExecutionError::NoSuchOverload)?
                            .iter()
                    };
                while let Some(item) = items.next() {
                    let iter_start = crate::meter::level();
                    if !try_bool(Value::resolve_val(&comprehension.loop_cond, &ctx))? {
                        crate::meter::set_level(iter_start);
                        break;
                    }
                    // Iteration start: the level already includes the
                    // previous accumulator. At iteration end the level
                    // becomes `iter_start + Δbytes(accumulator)`, so
                    // the iteration's temporaries are dropped but the
                    // accumulator's growth persists.
                    // U9: item bind is work (`1 + nodes +
                    // ⌈bytes/64⌉`; F4 adds the payload term).
                    let borrowed = crate::comprehension::classify(comprehension).is_some();
                    crate::meter::charge_cost(if borrowed {
                        crate::charges::comprehension_item_bind_ref()
                    } else {
                        crate::charges::comprehension_item_bind(
                            item.cached_nodes(),
                            item.cached_bytes(),
                        )
                    })?;
                    crate::meter::charge_cost(crate::charges::payload_copy(
                        1,
                        comprehension.iter_var.len() as u64,
                    ))?;
                    crate::meter::note_op_body();
                    if borrowed {
                        ctx.bind_borrowed(&comprehension.iter_var, item);
                    } else {
                        ctx.add_variable_as_val(&comprehension.iter_var, item.clone_as_boxed());
                    }
                    match append_step(comprehension) {
                        // U10: the macro append is linear — take the
                        // accumulator, push the (owned) element in
                        // place, rebind; charge only the increment.
                        Some(AppendStep::Map(element)) => {
                            let e = Value::resolve_val(element, &ctx)?;
                            charge_append(e.as_ref())?;
                            crate::meter::note_op_body();
                            let e = e.into_owned();
                            push_charged_in_place(&mut ctx, &comprehension.accu_var, e)?;
                        }
                        Some(AppendStep::Filter { condition, element }) => {
                            if try_bool(Value::resolve_val(condition, &ctx))? {
                                let e = Value::resolve_val(element, &ctx)?;
                                charge_append(e.as_ref())?;
                                crate::meter::note_op_body();
                                let e = e.into_owned();
                                push_charged_in_place(&mut ctx, &comprehension.accu_var, e)?;
                            }
                        }
                        None => {
                            let accu = Value::resolve_val(&comprehension.loop_step, &ctx)?;
                            // Non-append shapes (e.g. `exists_one`) keep
                            // the retention charge.
                            charge_value(accu.as_ref())?;
                            crate::meter::charge_work(
                                crate::charges::payload_copy(
                                    accu.cached_nodes(),
                                    accu.cached_bytes(),
                                )
                                .work,
                            )?;
                            crate::meter::note_op_body();
                            ctx.add_variable_as_val(&comprehension.accu_var, accu.clone_as_boxed());
                        }
                    }
                    let new_accu_bytes = ctx
                        .get_variable(&comprehension.accu_var)
                        .map(|v| v.cached_bytes())
                        .unwrap_or(0);
                    if comprehension.accu_var == "@result" {
                        drop(ctx.take_variable(&comprehension.iter_var));
                    }
                    crate::meter::set_level(
                        iter_start
                            .saturating_add(new_accu_bytes)
                            .saturating_sub(accu_bytes),
                    );
                    accu_bytes = new_accu_bytes;
                }
                // F10: when the result is the accumulator itself
                // (`map`/`filter`), move it out of the iteration scope
                // instead of deep-copying it.
                let result: Box<dyn Val> =
                    if is_accu_ident(&comprehension.result, &comprehension.accu_var) {
                        ctx.take_variable(&comprehension.accu_var)
                            .ok_or(ExecutionError::NoSuchOverload)?
                    } else {
                        let result = Value::resolve_val(&comprehension.result, &ctx)?;
                        if matches!(result, Cow::Borrowed(_)) {
                            crate::meter::charge_cost(crate::charges::payload_copy(
                                result.cached_nodes(),
                                result.cached_bytes(),
                            ))?;
                            crate::meter::note_op_body();
                        }
                        result.into_owned()
                    };
                crate::meter::set_level(entry_level.saturating_add(result.cached_bytes()));
                Ok(Cow::<dyn Val>::Owned(result))
            }
            Expr::Struct(strct) => {
                let name = strct.type_name.clone();
                #[cfg(not(feature = "structs"))]
                {
                    Err(ExecutionError::InternalError(format!(
                        "Found struct {name}, feature not enabled!"
                    )))
                }
                #[cfg(feature = "structs")]
                {
                    let struct_def =
                        ctx.env()
                            .find_struct(&name)
                            .ok_or(ExecutionError::UnexpectedType {
                                got: name.to_owned(),
                                want: "known struct".to_owned(),
                            })?;
                    let mut fields = std::collections::BTreeMap::new();
                    for entry in &strct.entries {
                        match &entry.expr {
                            EntryExpr::StructField(expr) => {
                                let f = expr.field.clone();
                                fields.insert(f, Value::resolve_val(&expr.value, ctx)?);
                            }
                            EntryExpr::MapEntry(entry) => {
                                return Err(ExecutionError::InternalError(format!(
                                    "Expected struct_field_expr, got {entry:?}"
                                )))
                            }
                        }
                    }
                    let s = struct_def.new_struct(fields)?;
                    Ok(Cow::<dyn Val>::Owned(Box::new(s)))
                }
            }
            Expr::Unspecified => panic!("Can't evaluate Unspecified Expr"),
        }
    }
}

struct SingletonIterator<'a>(Option<&'a dyn Val>);
impl<'a> crate::common::traits::Iterator<'a> for SingletonIterator<'a> {
    fn next(&mut self) -> Option<&'a dyn Val> {
        self.0.take()
    }
}

fn bool<'a>(boolean: bool) -> Cow<'a, dyn Val> {
    Cow::<dyn Val>::Owned(Box::new(CelBool::from(boolean)))
}

fn try_bool(val: Result<Cow<dyn Val>, ExecutionError>) -> Result<bool, ExecutionError> {
    match val {
        Ok(val) => val
            .downcast_ref::<CelBool>()
            .map(|b| *b.inner())
            .ok_or(ExecutionError::NoSuchOverload),
        Err(err) => Result::Err(err),
    }
}

/// True when either ordering operand is a NaN double (fork fix;
/// only doubles can be NaN, so one downcast per side suffices).
fn either_nan(lhs: &dyn Val, rhs: &dyn Val) -> bool {
    [lhs, rhs].iter().any(|v| {
        v.downcast_ref::<CelDouble>()
            .is_some_and(|d| d.inner().is_nan())
    })
}

impl ops::Add<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn add(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => l
                .checked_add(r)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::Int),

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_add(r)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l + r).into(),

            (Value::List(mut l), Value::List(mut r)) => {
                {
                    // If this is the only reference to `l`, we can append to it in place.
                    // `l` is replaced with a clone otherwise.
                    let l = Arc::make_mut(&mut l);

                    // Likewise, if this is the only reference to `r`, we can move its values
                    // instead of cloning them.
                    match Arc::get_mut(&mut r) {
                        Some(r) => l.append(r),
                        None => l.extend(r.iter().cloned()),
                    }
                }

                Ok(Value::List(l))
            }
            (Value::String(mut l), Value::String(r)) => {
                // If this is the only reference to `l`, we can append to it in place.
                // `l` is replaced with a clone otherwise.
                Arc::make_mut(&mut l).push_str(&r);
                Ok(Value::String(l))
            }
            (Value::Duration(l), Value::Duration(r)) => l
                .checked_add(&r)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::Duration),
            (Value::Timestamp(l), Value::Duration(r)) => checked_op(TsOp::Add, &l, &r),
            (Value::Duration(l), Value::Timestamp(r)) => r
                .checked_add_signed(l)
                .ok_or_else(|| ExecutionError::Overflow("add", l.into(), r.into()))
                .map(Value::Timestamp),
            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "add",
                left.into(),
                right.into(),
            )),
        }
    }
}

impl ops::Sub<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn sub(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => l
                .checked_sub(r)
                .ok_or_else(|| ExecutionError::Overflow("sub", l.into(), r.into()))
                .map(Value::Int),

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_sub(r)
                .ok_or_else(|| ExecutionError::Overflow("sub", l.into(), r.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l - r).into(),

            (Value::Duration(l), Value::Duration(r)) => l
                .checked_sub(&r)
                .ok_or_else(|| ExecutionError::Overflow("sub", l.into(), r.into()))
                .map(Value::Duration),
            (Value::Timestamp(l), Value::Duration(r)) => checked_op(TsOp::Sub, &l, &r),
            (Value::Timestamp(l), Value::Timestamp(r)) => {
                Value::Duration(l.signed_duration_since(r)).into()
            }
            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "sub",
                left.into(),
                right.into(),
            )),
        }
    }
}

impl ops::Div<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn div(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => {
                if r == 0 {
                    Err(ExecutionError::DivisionByZero(l.into()))
                } else {
                    l.checked_div(r)
                        .ok_or_else(|| ExecutionError::Overflow("div", l.into(), r.into()))
                        .map(Value::Int)
                }
            }

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_div(r)
                .ok_or_else(|| ExecutionError::DivisionByZero(l.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l / r).into(),

            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "div",
                left.into(),
                right.into(),
            )),
        }
    }
}

impl ops::Mul<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn mul(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => l
                .checked_mul(r)
                .ok_or_else(|| ExecutionError::Overflow("mul", l.into(), r.into()))
                .map(Value::Int),

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_mul(r)
                .ok_or_else(|| ExecutionError::Overflow("mul", l.into(), r.into()))
                .map(Value::UInt),

            (Value::Float(l), Value::Float(r)) => Value::Float(l * r).into(),

            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "mul",
                left.into(),
                right.into(),
            )),
        }
    }
}

impl ops::Rem<Value> for Value {
    type Output = ResolveResult;

    #[inline(always)]
    fn rem(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Int(l), Value::Int(r)) => {
                if r == 0 {
                    Err(ExecutionError::RemainderByZero(l.into()))
                } else {
                    l.checked_rem(r)
                        .ok_or_else(|| ExecutionError::Overflow("rem", l.into(), r.into()))
                        .map(Value::Int)
                }
            }

            (Value::UInt(l), Value::UInt(r)) => l
                .checked_rem(r)
                .ok_or_else(|| ExecutionError::RemainderByZero(l.into()))
                .map(Value::UInt),

            (left, right) => Err(ExecutionError::UnsupportedBinaryOperator(
                "rem",
                left.into(),
                right.into(),
            )),
        }
    }
}

/// Op represents a binary arithmetic operation supported on a timestamp
///
enum TsOp {
    Add,
    Sub,
}

impl TsOp {
    fn str(&self) -> &'static str {
        match self {
            TsOp::Add => "add",
            TsOp::Sub => "sub",
        }
    }
}

/// Performs a checked arithmetic operation [`TsOp`] on a timestamp and a duration and ensures that
/// the resulting timestamp does not overflow the data type internal limits, as well as the timestamp
/// limits defined in the cel-spec. See [`MAX_TIMESTAMP`] and [`MIN_TIMESTAMP`] for more details.
fn checked_op(
    op: TsOp,
    lhs: &chrono::DateTime<chrono::FixedOffset>,
    rhs: &chrono::Duration,
) -> ResolveResult {
    // Add lhs and rhs together, checking for data type overflow
    let result = match op {
        TsOp::Add => lhs.checked_add_signed(*rhs),
        TsOp::Sub => lhs.checked_sub_signed(*rhs),
    }
    .ok_or_else(|| ExecutionError::Overflow(op.str(), (*lhs).into(), (*rhs).into()))?;

    // Check for cel-spec limits
    if result > *MAX_TIMESTAMP || result < *MIN_TIMESTAMP {
        Err(ExecutionError::Overflow(
            op.str(),
            (*lhs).into(),
            (*rhs).into(),
        ))
    } else {
        Value::Timestamp(result).into()
    }
}

#[cfg(test)]
mod tests {
    use crate::common::traits::Sizer;
    use crate::common::types::{CelInt, Type, LIST_TYPE};
    use crate::common::value::Val;
    use crate::{objects::Key, Context, ExecutionError, Program, ResolveResult, Value};
    use std::sync::Arc;

    #[test]
    fn test_indexed_map_access() {
        let mut context = Context::default();
        let mut headers = indexmap::IndexMap::new();
        headers.insert("Content-Type", "application/json".to_string());
        context.add_variable_from_value("headers", headers);

        let program = Program::compile("headers[\"Content-Type\"]").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, "application/json".into());
    }

    #[test]
    fn test_numeric_map_access() {
        let mut context = Context::default();
        let mut numbers = indexmap::IndexMap::new();
        numbers.insert(Key::Uint(1), "one".to_string());
        context.add_variable_from_value("numbers", numbers);

        let program = Program::compile("numbers[1u]").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, "one".into());
    }

    #[test]
    fn test_heterogeneous_compare() {
        let context = Context::default();

        let program = Program::compile("1 < uint(2)").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, true.into());

        let program = Program::compile("1 < 1.1").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, true.into());

        let program = Program::compile("uint(0) > -10").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(
            value,
            true.into(),
            "negative signed ints should be less than uints"
        );
    }

    #[test]
    fn test_float_compare() {
        let context = Context::default();

        let program = Program::compile("1.0 > 0.0").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, true.into());

        let program = Program::compile("double('NaN') == double('NaN')").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, false.into(), "NaN should not equal itself");

        // Fork change (spike d3deaa772): NaN poisons ordering — the four
        // comparison operators return false with a NaN operand per
        // IEEE 754 / cel-spec, instead of erroring NoSuchOverload.
        let program = Program::compile("1.0 > double('NaN')").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(
            value,
            false.into(),
            "NaN inequality comparisons are false, not errors"
        );
    }

    #[test]
    fn test_invalid_compare() {
        let context = Context::default();

        let program = Program::compile("{} == []").unwrap();
        let value = program.execute(&context).unwrap();
        assert_eq!(value, false.into());
    }

    #[test]
    fn test_size_fn_var() {
        let program = Program::compile("size(requests) + size == 5").unwrap();
        let mut context = Context::default();
        let requests = vec![Value::Int(42), Value::Int(42)];
        context
            .add_variable("requests", Value::List(Arc::new(requests)))
            .unwrap();
        context.add_variable("size", Value::Int(3)).unwrap();
        assert_eq!(program.execute(&context).unwrap(), Value::Bool(true));
    }

    fn test_execution_error(program: &str, expected: ExecutionError) {
        let program = Program::compile(program).unwrap();
        let result = program.execute(&Context::default());
        assert_eq!(result.unwrap_err(), expected);
    }

    #[test]
    fn test_invalid_sub() {
        test_execution_error(
            "'foo' - 10",
            ExecutionError::UnsupportedBinaryOperator("sub", "foo".into(), 10.into()),
        );
    }

    #[test]
    fn test_invalid_add() {
        test_execution_error(
            "'foo' + 10",
            ExecutionError::UnsupportedBinaryOperator("add", "foo".into(), 10.into()),
        );
    }

    #[test]
    fn test_invalid_div() {
        test_execution_error(
            "'foo' / 10",
            ExecutionError::UnsupportedBinaryOperator("div", "foo".into(), 10.into()),
        );
    }

    #[test]
    fn test_invalid_rem() {
        test_execution_error(
            "'foo' % 10",
            ExecutionError::UnsupportedBinaryOperator("rem", "foo".into(), 10.into()),
        );
    }

    #[test]
    fn out_of_bound_list_access() {
        let program = Program::compile("list[10]").unwrap();
        let mut context = Context::default();
        context
            .add_variable("list", Value::List(Arc::new(vec![])))
            .unwrap();
        let result = program.execute(&context);
        assert_eq!(
            result,
            Err(ExecutionError::IndexOutOfBounds(Value::Int(10)))
        );
    }

    #[test]
    fn out_of_bound_list_access_negative() {
        let program = Program::compile("list[-1]").unwrap();
        let mut context = Context::default();
        context
            .add_variable("list", Value::List(Arc::new(vec![])))
            .unwrap();
        let result = program.execute(&context);
        assert_eq!(
            result,
            Err(ExecutionError::IndexOutOfBounds(Value::Int(-1)))
        );
    }

    #[test]
    fn list_access_uint() {
        let program = Program::compile("list[1u]").unwrap();
        let mut context = Context::default();
        context
            .add_variable("list", Value::List(Arc::new(vec![1.into(), 2.into()])))
            .unwrap();
        let result = program.execute(&context);
        assert_eq!(result, Ok(Value::Int(2.into())));
    }

    #[test]
    fn reference_to_value() {
        let test = "example".to_string();
        let direct: Value = test.as_str().into();
        assert_eq!(direct, Value::String(Arc::new(String::from("example"))));

        let vec = vec![test.as_str()];
        let indirect: Value = vec.into();
        assert_eq!(
            indirect,
            Value::List(Arc::new(vec![Value::String(Arc::new(String::from(
                "example"
            )))]))
        );
    }

    #[test]
    fn test_short_circuit_and() {
        let mut context = Context::default();
        let data: indexmap::IndexMap<String, String> = indexmap::IndexMap::new();
        context.add_variable_from_value("data", data);

        let program = Program::compile("has(data.x) && data.x.startsWith(\"foo\")").unwrap();
        let value = program.execute(&context);
        println!("{value:?}");
        assert!(
            value.is_ok(),
            "The AND expression should support short-circuit evaluation."
        );
    }

    #[test]
    fn test_or_ignores_err_when_short_circuiting() {
        let mut context = Context::default();
        context.add_variable_from_value("foo", 42);
        context.add_variable_from_value("bar", 42);
        let program = Program::compile("foo || bar > 0").unwrap();
        let value = program.execute(&context);
        assert_eq!(value, Ok(true.into()));

        let program = Program::compile("foo || bar < 0").unwrap();
        let value = program.execute(&context);
        assert!(value.is_err());
    }

    #[test]
    fn test_and_ignores_err_when_short_circuiting() {
        let mut context = Context::default();
        context.add_variable_from_value("foo", 42);
        context.add_variable_from_value("bar", 42);
        let program = Program::compile("foo && bar < 0").unwrap();
        let value = program.execute(&context);
        assert_eq!(value, Ok(false.into()));

        let program = Program::compile("foo && bar > 0").unwrap();
        let value = program.execute(&context);
        assert!(value.is_err());
    }

    #[test]
    fn invalid_int_math() {
        use ExecutionError::*;

        let cases = [
            ("1 / 0", DivisionByZero(1.into())),
            ("1 % 0", RemainderByZero(1.into())),
            (
                &format!("{} + 1", i64::MAX),
                Overflow("add", i64::MAX.into(), 1.into()),
            ),
            (
                &format!("{} - 1", i64::MIN),
                Overflow("sub", i64::MIN.into(), 1.into()),
            ),
            (
                &format!("{} * 2", i64::MAX),
                Overflow("mul", i64::MAX.into(), 2.into()),
            ),
            (
                &format!("{} / -1", i64::MIN),
                Overflow("div", i64::MIN.into(), (-1).into()),
            ),
            (
                &format!("{} % -1", i64::MIN),
                Overflow("rem", i64::MIN.into(), (-1).into()),
            ),
        ];

        for (expr, err) in cases {
            test_execution_error(expr, err);
        }
    }

    #[test]
    fn invalid_uint_math() {
        use ExecutionError::*;

        let cases = [
            ("1u / 0u", DivisionByZero(1u64.into())),
            ("1u % 0u", RemainderByZero(1u64.into())),
            (
                &format!("{}u + 1u", u64::MAX),
                Overflow("add", u64::MAX.into(), 1u64.into()),
            ),
            ("0u - 1u", Overflow("sub", 0u64.into(), 1u64.into())),
            (
                &format!("{}u * 2u", u64::MAX),
                Overflow("mul", u64::MAX.into(), 2u64.into()),
            ),
        ];

        for (expr, err) in cases {
            test_execution_error(expr, err);
        }
    }

    #[test]
    fn test_index_missing_map_key() {
        let mut ctx = Context::default();
        let mut map = indexmap::IndexMap::new();
        map.insert("a".to_string(), Value::Int(1));
        ctx.add_variable_from_value("mymap", map);

        let p = Program::compile(r#"mymap["missing"]"#).expect("Must compile");
        let result = p.execute(&ctx);

        assert!(result.is_err(), "Should error on missing map key");
    }

    mod opaque {
        use crate::objects::{Map, Opaque, OpaqueVal, OptionalValue};
        use crate::parser::Parser;
        use crate::{Context, ExecutionError, FunctionContext, Program, Value};
        use serde::Serialize;
        use std::fmt::Debug;
        use std::ops::Deref;
        use std::sync::Arc;

        #[derive(Debug, Eq, PartialEq, Serialize)]
        struct MyStruct {
            field: String,
        }

        impl Opaque for MyStruct {
            fn runtime_type_name(&self) -> &str {
                "my_struct"
            }

            #[cfg(feature = "json")]
            fn json(&self) -> Option<serde_json::Value> {
                Some(serde_json::to_value(self).unwrap())
            }
        }

        #[test]
        fn test_opaque_fn() {
            pub fn my_fn(ftx: &FunctionContext) -> Result<Value, ExecutionError> {
                if let Some(Some(opaque)) = ftx.this.as_ref().map(|v| v.downcast_ref::<OpaqueVal>())
                {
                    if opaque.val.runtime_type_name() == "my_struct" {
                        Ok(opaque
                            .val
                            .deref()
                            .downcast_ref::<MyStruct>()
                            .unwrap()
                            .field
                            .clone()
                            .into())
                    } else {
                        Err(ExecutionError::UnexpectedType {
                            got: opaque.val.runtime_type_name().to_string(),
                            want: "my_struct".to_string(),
                        })
                    }
                } else {
                    Err(ExecutionError::UnexpectedType {
                        got: format!("{:?}", ftx.this),
                        want: "Value::Opaque".to_string(),
                    })
                }
            }

            let value = Arc::new(MyStruct {
                field: String::from("value"),
            });

            let mut ctx = Context::default();
            ctx.add_variable_from_value("mine", Value::Opaque(value.clone()));
            ctx.add_function("myFn", my_fn);
            let prog = Program::compile("mine.myFn()").unwrap();
            assert_eq!(
                Ok(Value::String(Arc::new("value".into()))),
                prog.execute(&ctx)
            );
        }

        #[test]
        fn opaque_eq() {
            let value_1 = Arc::new(MyStruct {
                field: String::from("1"),
            });
            let value_2 = Arc::new(MyStruct {
                field: String::from("2"),
            });

            let mut ctx = Context::default();
            ctx.add_variable_from_value("v1", Value::Opaque(value_1.clone()));
            ctx.add_variable_from_value("v1b", Value::Opaque(value_1));
            ctx.add_variable_from_value("v2", Value::Opaque(value_2));
            assert_eq!(
                Program::compile("v2 == v1").unwrap().execute(&ctx),
                Ok(false.into())
            );
            assert_eq!(
                Program::compile("v1 == v1b").unwrap().execute(&ctx),
                Ok(true.into())
            );
            assert_eq!(
                Program::compile("v2 == v2").unwrap().execute(&ctx),
                Ok(true.into())
            );
        }

        #[test]
        fn test_value_holder_dbg() {
            let opaque = Arc::new(MyStruct {
                field: "not so opaque".to_string(),
            });
            let opaque = Value::Opaque(opaque);
            assert_eq!(
                "Opaque<my_struct>(MyStruct { field: \"not so opaque\" })",
                format!("{:?}", opaque)
            );
        }

        // `cfg` before `#[test]`: the test-gate scanner only reads
        // attributes above the `#[test]` line.
        #[cfg(feature = "json")]
        #[test]
        fn test_json() {
            let value = Arc::new(MyStruct {
                field: String::from("value"),
            });
            let cel_value = Value::Opaque(value);
            let mut map = serde_json::Map::new();
            map.insert(
                "field".to_string(),
                serde_json::Value::String("value".to_string()),
            );
            assert_eq!(
                cel_value.json().expect("Must convert"),
                serde_json::Value::Object(map)
            );
        }

        #[test]
        fn test_optional() {
            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none()")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::none())))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(1)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::of(Value::Int(1)))))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.ofNonZeroValue(0)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::none())))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.ofNonZeroValue(1)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::of(Value::Int(1)))))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(1).value()")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(1))
            );
            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().value()")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Err(ExecutionError::FunctionError {
                    function: "value".to_string(),
                    message: "optional.none() dereference".to_string()
                })
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(1).hasValue()")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Bool(true))
            );
            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().hasValue()")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Bool(false))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(1).or(optional.of(2))")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::of(Value::Int(1)))))
            );
            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().or(optional.of(2))")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::of(Value::Int(2)))))
            );
            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().or(optional.none())")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Opaque(Arc::new(OptionalValue::none())))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(1).orValue(5)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(1))
            );
            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().orValue(5)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(5))
            );

            let mut ctx = Context::default();
            ctx.add_variable_from_value("msg", indexmap::IndexMap::from([("field", "value")]));

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("msg.?field")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &ctx),
                Ok(Value::Opaque(Arc::new(OptionalValue::of(Value::String(
                    Arc::new("value".to_string())
                )))))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(msg).?field")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &ctx),
                Ok(Value::Opaque(Arc::new(OptionalValue::of(Value::String(
                    Arc::new("value".to_string())
                )))))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().?field")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &ctx),
                Ok(Value::Opaque(Arc::new(OptionalValue::none())))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of(msg).?field.orValue('default')")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &ctx),
                Ok(Value::String(Arc::new("value".to_string())))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none().?field.orValue('default')")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &ctx),
                Ok(Value::String(Arc::new("default".to_string())))
            );

            let mut map_ctx = Context::default();
            let mut map = indexmap::IndexMap::new();
            map.insert("a".to_string(), Value::Int(1));
            map_ctx.add_variable_from_value("mymap", map);

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"mymap[?"missing"].orValue(99)"#)
                .expect("Must parse");
            assert_eq!(Value::resolve(&expr, &map_ctx), Ok(Value::Int(99)));

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"mymap[?"missing"].hasValue()"#)
                .expect("Must parse");
            assert_eq!(Value::resolve(&expr, &map_ctx), Ok(Value::Bool(false)));

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"mymap[?"a"].orValue(99)"#)
                .expect("Must parse");
            assert_eq!(Value::resolve(&expr, &map_ctx), Ok(Value::Int(1)));

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"mymap[?"a"].hasValue()"#)
                .expect("Must parse");
            assert_eq!(Value::resolve(&expr, &map_ctx), Ok(Value::Bool(true)));

            let mut list_ctx = Context::default();
            list_ctx.add_variable_from_value(
                "mylist",
                vec![Value::Int(1), Value::Int(2), Value::Int(3)],
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("mylist[?10].orValue(99)")
                .expect("Must parse");
            assert_eq!(Value::resolve(&expr, &list_ctx), Ok(Value::Int(99)));

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("mylist[?1].orValue(99)")
                .expect("Must parse");
            assert_eq!(Value::resolve(&expr, &list_ctx), Ok(Value::Int(2)));

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of([1, 2, 3])[1].orValue(99)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(2))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of([1, 2, 3])[4].orValue(99)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(99))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.none()[1].orValue(99)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(99))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("optional.of([1, 2, 3])[?1].orValue(99)")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Int(2))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("[1, 2, ?optional.of(3), 4]")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::List(Arc::new(vec![
                    Value::Int(1),
                    Value::Int(2),
                    Value::Int(3),
                    Value::Int(4)
                ])))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("[1, 2, ?optional.none(), 4]")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::List(Arc::new(vec![
                    Value::Int(1),
                    Value::Int(2),
                    Value::Int(4)
                ])))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("[?optional.of(1), ?optional.none(), ?optional.of(3)]")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::List(Arc::new(vec![Value::Int(1), Value::Int(3)])))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"[1, ?mymap[?"missing"], 3]"#)
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &map_ctx),
                Ok(Value::List(Arc::new(vec![Value::Int(1), Value::Int(3)])))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"[1, ?mymap[?"a"], 3]"#)
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &map_ctx),
                Ok(Value::List(Arc::new(vec![
                    Value::Int(1),
                    Value::Int(1),
                    Value::Int(3)
                ])))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse("[?optional.none(), ?optional.none()]")
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::List(Arc::new(vec![])))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"{"a": 1, "b": 2, ?"c": optional.of(3)}"#)
                .expect("Must parse");
            let mut expected_map = indexmap::IndexMap::new();
            expected_map.insert("a".into(), Value::Int(1));
            expected_map.insert("b".into(), Value::Int(2));
            expected_map.insert("c".into(), Value::Int(3));
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Map(Map {
                    map: Arc::new(expected_map.into_iter().collect())
                }))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"{"a": 1, "b": 2, ?"c": optional.none()}"#)
                .expect("Must parse");
            let mut expected_map = indexmap::IndexMap::new();
            expected_map.insert("a".into(), Value::Int(1));
            expected_map.insert("b".into(), Value::Int(2));
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Map(Map {
                    map: Arc::new(expected_map.into_iter().collect())
                }))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"{"a": 1, ?"b": optional.none(), ?"c": optional.of(3)}"#)
                .expect("Must parse");
            let mut expected_map = indexmap::IndexMap::new();
            expected_map.insert("a".into(), Value::Int(1));
            expected_map.insert("c".into(), Value::Int(3));
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Map(Map {
                    map: Arc::new(expected_map.into_iter().collect())
                }))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"{"a": 1, ?"b": mymap[?"missing"]}"#)
                .expect("Must parse");
            let mut expected_map = indexmap::IndexMap::new();
            expected_map.insert("a".into(), Value::Int(1));
            assert_eq!(
                Value::resolve(&expr, &map_ctx),
                Ok(Value::Map(Map {
                    map: Arc::new(expected_map.into_iter().collect())
                }))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"{"x": 10, ?"y": mymap[?"a"]}"#)
                .expect("Must parse");
            let mut expected_map = indexmap::IndexMap::new();
            expected_map.insert("x".into(), Value::Int(10));
            expected_map.insert("y".into(), Value::Int(1));
            assert_eq!(
                Value::resolve(&expr, &map_ctx),
                Ok(Value::Map(Map {
                    map: Arc::new(expected_map.into_iter().collect())
                }))
            );

            let expr = Parser::default()
                .enable_optional_syntax(true)
                .parse(r#"{?"a": optional.none(), ?"b": optional.none()}"#)
                .expect("Must parse");
            assert_eq!(
                Value::resolve(&expr, &Context::default()),
                Ok(Value::Map(Map {
                    map: Arc::new(indexmap::IndexMap::new())
                }))
            );
        }
    }

    #[cfg(feature = "structs")]
    mod structs {
        use std::borrow::Cow;
        use std::sync::Arc;

        use crate::{
            common::{
                types::{self, CelBool, CelInt, CelString, CelStruct},
                value::Val,
            },
            env::StructDef,
            Context, Env, ExecutionError, Program, Value,
        };

        #[test]
        fn test_empty_struct() {
            let mut env = Env::stdlib();
            env.add_struct(StructDef::new(String::from("cel.MyStruct")));
            let program = Program::compile("cel.MyStruct {}").unwrap();
            let value = program.execute(&Context::with_env(Arc::new(env))).unwrap();
            match value {
                Value::Struct(s) => assert_eq!(s.name(), "cel.MyStruct"),
                _ => panic!("This can't be!"),
            }
        }

        #[test]
        fn test_struct() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.Problem"))
                    .add_field(String::from("solved"), types::BOOL_TYPE)
                    .add_field(String::from("answer"), types::INT_TYPE),
            );
            let program =
                Program::compile("cel.Problem { solved: 0 != null, answer: 21 * 2 }").unwrap();
            let value = program.execute(&Context::with_env(Arc::new(env))).unwrap();
            match value {
                Value::Struct(s) => {
                    assert_eq!(s.name(), "cel.Problem");
                    assert_eq!(
                        s.field_value("solved"),
                        Some(&CelBool::from(true) as &dyn Val)
                    );
                    assert_eq!(s.field_value("answer"), Some(&CelInt::from(42) as &dyn Val));
                    assert_eq!(s.field_values().len(), 2);
                    assert_eq!(
                        s.field_values().get("solved").cloned(),
                        Some(Arc::new(CelBool::from(true)) as Arc<dyn Val>)
                    );
                    assert_eq!(
                        s.field_values().get("answer").cloned(),
                        Some(Arc::new(CelInt::from(42)) as Arc<dyn Val>)
                    );
                }
                _ => panic!("This can't be!"),
            }
        }

        #[test]
        fn test_struct_field_access() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("some".into(), types::STRING_TYPE),
            );
            let program = Program::compile("cel.MyStruct { some: 'value' }.some").unwrap();
            let value = program.execute(&Context::with_env(env.into())).unwrap();
            assert_eq!(value, Value::String(Arc::new("value".to_owned())));
        }

        #[test]
        fn test_struct_no_such_field() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("some".into(), types::STRING_TYPE),
            );
            let program = Program::compile("cel.MyStruct { not_here: 'value' }").unwrap();
            let result = program.execute(&Context::with_env(env.into()));
            assert_eq!(
                result,
                Err(ExecutionError::NoSuchKey(
                    String::from("field `not_here` on struct `cel.MyStruct`").into()
                ))
            );
        }

        #[test]
        fn test_struct_with_default() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("some".into(), types::STRING_TYPE)
                    .add_field_with_default("here".into(), Box::new(CelString::from("yes"))),
            );
            let program = Program::compile("cel.MyStruct { some: 'value' }.here").unwrap();
            let result = program.execute(&Context::with_env(env.into()));
            assert_eq!(result, Ok(Value::String(Arc::new(String::from("yes")))));
        }

        #[test]
        fn test_struct_with_default_overwritten() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("some".into(), types::STRING_TYPE)
                    .add_field_with_default("here".into(), Box::new(CelString::from("yes"))),
            );
            let program =
                Program::compile("cel.MyStruct { some: 'value', here: 'totally' }.here").unwrap();
            let result = program.execute(&Context::with_env(env.into()));
            assert_eq!(result, Ok(Value::String(Arc::new(String::from("totally")))));
        }

        #[test]
        fn test_struct_has_macro() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("name".into(), types::STRING_TYPE)
                    .add_field("value".into(), types::INT_TYPE),
            );

            let mut my_struct = CelStruct::new("cel.MyStruct".to_owned());
            my_struct.add_field_value(
                "name".to_owned(),
                Cow::<dyn Val>::Owned(Box::new(CelString::from("test"))),
            );
            my_struct.add_field_value(
                "value".to_owned(),
                Cow::<dyn Val>::Owned(Box::new(CelInt::from(42))),
            );

            let mut context = Context::with_env(Arc::new(env));
            context
                .add_variable("my_var", Value::Struct(Arc::new(my_struct)))
                .unwrap();

            let program = Program::compile("has(my_var.name)").unwrap();
            let result = program.execute(&context).unwrap();
            assert_eq!(result, Value::Bool(true));

            let program = Program::compile("has(my_var.missing)").unwrap();
            let result = program.execute(&context).unwrap();
            assert_eq!(result, Value::Bool(false));

            let program =
                Program::compile("has(cel.MyStruct{name: 'foo', value: 1}.name)").unwrap();
            let result = program.execute(&context).unwrap();
            assert_eq!(result, Value::Bool(true));

            let program = Program::compile("has(cel.MyStruct{}.name)").unwrap();
            let result = program.execute(&context).unwrap();
            assert_eq!(result, Value::Bool(false));
        }

        #[test]
        fn test_struct_no_such_field_access() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("some".into(), types::STRING_TYPE),
            );
            let program = Program::compile("cel.MyStruct { some: 'value' }.not_here").unwrap();
            let result = program.execute(&Context::with_env(env.into()));
            assert_eq!(
                result,
                Err(ExecutionError::NoSuchKey(String::from("not_here").into()))
            );
        }

        #[test]
        fn unknown_struct() {
            let program = Program::compile("cel.MyStruct { some: 'value' }.not_here").unwrap();
            let result = program.execute(&Context::default());
            assert_eq!(
                result,
                Err(ExecutionError::UnexpectedType {
                    got: String::from("cel.MyStruct"),
                    want: String::from("known struct")
                })
            );
        }

        #[test]
        fn add_struct_variable_to_context() {
            let mut env = Env::stdlib();
            env.add_struct(
                StructDef::new(String::from("cel.MyStruct"))
                    .add_field("name".into(), types::STRING_TYPE)
                    .add_field("value".into(), types::INT_TYPE),
            );

            let mut my_struct = CelStruct::new("cel.MyStruct".to_owned());
            my_struct.add_field_value(
                "name".to_owned(),
                Cow::<dyn Val>::Owned(Box::new(CelString::from("test"))),
            );
            my_struct.add_field_value(
                "value".to_owned(),
                Cow::<dyn Val>::Owned(Box::new(CelInt::from(42))),
            );

            let mut context = Context::with_env(Arc::new(env));
            context
                .add_variable("my_var", Value::Struct(Arc::new(my_struct)))
                .unwrap();

            let program = Program::compile("my_var.name + ' ' + string(my_var.value)").unwrap();
            let result = program.execute(&context).unwrap();
            assert_eq!(result, Value::String(Arc::new("test 42".to_owned())));
        }
    }
    /// A custom type on the `dyn Val` path, as `Type::new_opaque_type` invites.
    #[derive(Debug)]
    struct Ip(Type, String);

    impl Ip {
        fn new(addr: &str) -> Self {
            Ip(Type::new_opaque_type("net.IP"), addr.to_owned())
        }
    }

    impl Val for Ip {
        fn get_type(&self) -> &Type {
            &self.0
        }

        fn equals(&self, other: &dyn Val) -> bool {
            other.downcast_ref::<Ip>().is_some_and(|o| o.1 == self.1)
        }

        fn clone_as_boxed(&self) -> Box<dyn Val> {
            Box::new(Ip::new(&self.1))
        }
    }

    /// A list whose contents are resolved on access rather than materialized,
    /// the shape `Context::add_variable_as_val` was made public for.
    #[derive(Debug)]
    struct LazyList(Vec<i64>);

    impl Sizer for LazyList {
        fn size(&self) -> CelInt {
            CelInt::from(self.0.len() as i64)
        }
    }

    impl Val for LazyList {
        fn get_type(&self) -> &Type {
            &LIST_TYPE
        }

        fn as_sizer(&self) -> Option<&dyn Sizer> {
            Some(self)
        }

        fn clone_as_boxed(&self) -> Box<dyn Val> {
            Box::new(LazyList(self.0.clone()))
        }
    }

    fn context_with_custom_vals() -> Context<'static> {
        let mut context = Context::default();
        context.add_variable_as_val("ip", Box::new(Ip::new("1.2.3.4")));
        context.add_variable_as_val("lazy", Box::new(LazyList(vec![1, 2])));
        context
    }

    fn execute(expr: &str) -> ResolveResult {
        Program::compile(expr)
            .unwrap()
            .execute(&context_with_custom_vals())
    }

    /// A `Val` a caller implemented has no `Value` representation. Reaching the
    /// result of `Program::execute` it must be reported through the `Result`
    /// that call already returns.
    #[test]
    fn custom_val_as_result_is_an_error() {
        for expr in [
            "ip",
            "[ip]",
            "[[ip]]",
            "{'k': ip}",
            "lazy",
            "optional.of(ip)",
        ] {
            assert!(
                matches!(execute(expr), Err(ExecutionError::UnexpectedType { .. })),
                "`{expr}` should report an unexpected type, got {:?}",
                execute(expr)
            );
        }
    }

    /// ... while the same values stay usable within an expression, which is the
    /// whole point of implementing `Val`.
    #[test]
    fn custom_val_within_an_expression_still_evaluates() {
        assert_eq!(execute("ip == ip"), Ok(Value::Bool(true)));
        assert_eq!(execute("size(lazy)"), Ok(Value::Int(2)));
        assert_eq!(execute("optional.of(ip).hasValue()"), Ok(Value::Bool(true)));
        assert_eq!(
            execute("optional.of(ip).value() == ip"),
            Ok(Value::Bool(true))
        );
    }
}
