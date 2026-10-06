use crate::common::traits::{Adder, Comparer, Subtractor, Zeroer};
use crate::common::types::{CelDuration, CelInt, CelString, Type};
use crate::common::value::Val;
use crate::ExecutionError;
use chrono::Datelike;
use chrono::{TimeZone, Timelike};
use std::borrow::Cow;
use std::cmp::Ordering;
use std::sync::LazyLock;

#[derive(Clone, Debug, PartialEq)]
pub struct Timestamp(chrono::DateTime<chrono::FixedOffset>);

impl Timestamp {
    pub fn into_inner(self) -> chrono::DateTime<chrono::FixedOffset> {
        self.0
    }

    pub fn inner(&self) -> &chrono::DateTime<chrono::FixedOffset> {
        &self.0
    }
}

impl Val for Timestamp {
    fn get_type(&self) -> &Type {
        &super::TIMESTAMP_TYPE
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
        Box::new(Timestamp(self.0))
    }
}

/// Timestamp values are limited to the range of values which can be serialized as a string:
/// `["0001-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z"]`. Since the max is a smaller
/// and the min is a larger timestamp than what is possible to represent with
/// [`chrono::DateTime`],
/// we need to perform our own spec-compliant overflow checks.
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

impl Adder for Timestamp {
    fn add<'a>(&'a self, rhs: &dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<CelDuration>() {
            let result = self.0.checked_add_signed(*rhs.inner()).ok_or_else(|| {
                ExecutionError::Overflow(
                    "add",
                    crate::val_desc::ValueDesc::of(self as &dyn Val),
                    crate::val_desc::ValueDesc::of(rhs as &dyn Val),
                )
            })?;
            if result > *MAX_TIMESTAMP || result < *MIN_TIMESTAMP {
                return Err(ExecutionError::Overflow(
                    "add",
                    crate::val_desc::ValueDesc::of(self as &dyn Val),
                    crate::val_desc::ValueDesc::of(rhs as &dyn Val),
                ));
            }
            Ok(Cow::<dyn Val>::Owned(Box::new(Self(result))))
        } else {
            Err(ExecutionError::UnsupportedBinaryOperator(
                "add",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Comparer for Timestamp {
    fn compare(&self, rhs: &dyn Val) -> Result<Ordering, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<Self>() {
            Ok(self.0.cmp(&rhs.0))
        } else {
            Err(ExecutionError::NoSuchOverload)
        }
    }
}

impl Subtractor for Timestamp {
    fn sub<'a>(&'a self, rhs: &'_ dyn Val) -> Result<Cow<'a, dyn Val>, ExecutionError> {
        if let Some(rhs) = rhs.downcast_ref::<CelDuration>() {
            let result = self.0.checked_sub_signed(*rhs.inner()).ok_or_else(|| {
                ExecutionError::Overflow(
                    "sub",
                    crate::val_desc::ValueDesc::of(self as &dyn Val),
                    crate::val_desc::ValueDesc::of(rhs as &dyn Val),
                )
            })?;
            if result > *MAX_TIMESTAMP || result < *MIN_TIMESTAMP {
                return Err(ExecutionError::Overflow(
                    "sub",
                    crate::val_desc::ValueDesc::of(self as &dyn Val),
                    crate::val_desc::ValueDesc::of(rhs as &dyn Val),
                ));
            }
            Ok(Cow::<dyn Val>::Owned(Box::new(Self(result))))
        } else if let Some(rhs) = rhs.downcast_ref::<Self>() {
            Ok(Cow::<dyn Val>::Owned(Box::new(CelDuration::from(
                self.0.signed_duration_since(rhs.inner()),
            ))))
        } else {
            Err(ExecutionError::UnsupportedBinaryOperator(
                "sub",
                crate::val_desc::ValueDesc::of(self as &dyn Val),
                crate::val_desc::ValueDesc::of(rhs),
            ))
        }
    }
}

impl Zeroer for Timestamp {
    fn is_zero_value(&self) -> bool {
        self.0.timestamp_nanos_opt().is_some_and(|ns| ns == 0)
    }
}

impl From<chrono::DateTime<chrono::FixedOffset>> for Timestamp {
    fn from(system_time: chrono::DateTime<chrono::FixedOffset>) -> Self {
        Self(system_time)
    }
}

impl From<Timestamp> for chrono::DateTime<chrono::FixedOffset> {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}

impl TryFrom<Box<dyn Val>> for chrono::DateTime<chrono::FixedOffset> {
    type Error = Box<dyn Val>;

    fn try_from(value: Box<dyn Val>) -> Result<Self, Self::Error> {
        if let Some(ts) = value.downcast_ref::<Timestamp>() {
            return Ok(ts.0);
        }
        Err(value)
    }
}

impl<'a> TryFrom<&'a dyn Val> for &'a chrono::DateTime<chrono::FixedOffset> {
    type Error = &'a dyn Val;

    fn try_from(value: &'a dyn Val) -> Result<Self, Self::Error> {
        if let Some(ts) = value.downcast_ref::<Timestamp>() {
            return Ok(&ts.0);
        }
        Err(value)
    }
}

fn millis<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(
            ts.inner().timestamp_subsec_millis() as i64
        )))
    })
}

fn seconds<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().second() as i64)))
    })
}

fn minutes<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().minute() as i64)))
    })
}

fn hours<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().hour() as i64)))
    })
}

fn day_of_week<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(
            ts.inner().weekday().num_days_from_sunday() as i64,
        )))
    })
}

fn date<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().day() as i64)))
    })
}

fn day_of_month<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().day0() as i64)))
    })
}

fn day_of_year<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().ordinal0() as i64)))
    })
}

fn month<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().month0() as i64)))
    })
}

fn full_year<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    super::unary_fn(args, super::TIMESTAMP_TYPE, |ts: &Timestamp| {
        Ok(Box::new(CelInt::from(ts.inner().year() as i64)))
    })
}

fn timestamp<'a>(args: Vec<Cow<'a, dyn Val>>) -> Result<Cow<'a, dyn Val>, ExecutionError> {
    // F4 remainder: parsing is O(len); charge before parsing.
    super::charge_string_parse(args[0].as_ref())?;
    super::unary_fn(args, super::STRING_TYPE, |value: &CelString| {
        Ok(Box::new(Timestamp::from(
            chrono::DateTime::parse_from_rfc3339(value.inner())
                // chrono 0.4.45 ParseError contains only a kind; its Display
                // selects a fixed message (at most 44 bytes), never input text.
                .map_err(|e| ExecutionError::function_error("timestamp", e))?,
        )))
    })
}

pub(crate) fn stdlib(env: &mut crate::Env) {
    env.add_overload(
        "timestamp",
        "string_to_timestamp",
        vec![super::STRING_TYPE],
        timestamp,
    )
    .expect("Must be unique");
    env.add_overload(
        "timestamp",
        "timestamp_to_timestamp",
        vec![super::TIMESTAMP_TYPE],
        super::noop,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getFullYear",
        "timestamp_to_year",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        full_year,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getMonth",
        "timestamp_to_month",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        month,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getDayOfYear",
        "timestamp_to_day_of_year",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        day_of_year,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getDayOfMonth",
        "timestamp_to_day_of_month",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        day_of_month,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getDate",
        "timestamp_to_day_of_month_1_based",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        date,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getDayOfWeek",
        "timestamp_to_day_of_week",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        day_of_week,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getHours",
        "timestamp_to_hours",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        hours,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getMinutes",
        "timestamp_to_minutes",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        minutes,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getSeconds",
        "timestamp_to_seconds",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        seconds,
    )
    .expect("Must be unique");
    env.add_member_overload(
        "getMilliseconds",
        "timestamp_to_millis",
        super::TIMESTAMP_TYPE,
        Vec::default(),
        millis,
    )
    .expect("Must be unique");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temporal_timestamp_checked_chrono_and_cel_ranges() {
        let origin =
            Timestamp::from(chrono::DateTime::parse_from_rfc3339("2000-01-01T00:00:00Z").unwrap());
        for duration in [chrono::Duration::MAX, chrono::Duration::MIN] {
            let rhs = CelDuration::from(duration);
            let add = origin.add(&rhs).unwrap_err();
            let sub = origin.sub(&rhs).unwrap_err();
            assert!(matches!(add, ExecutionError::Overflow("add", _, _)));
            assert!(matches!(sub, ExecutionError::Overflow("sub", _, _)));
            assert!(format!("{add:?}").len() < 128);
            assert!(format!("{sub:?}").len() < 128);
        }
        let max = Timestamp::from(*MAX_TIMESTAMP);
        let min = Timestamp::from(*MIN_TIMESTAMP);
        let tick = CelDuration::from(chrono::Duration::nanoseconds(1));
        let negative_tick = CelDuration::from(chrono::Duration::nanoseconds(-1));
        assert!(matches!(
            max.add(&tick),
            Err(ExecutionError::Overflow("add", _, _))
        ));
        assert!(matches!(
            min.sub(&tick),
            Err(ExecutionError::Overflow("sub", _, _))
        ));
        assert!(matches!(
            min.add(&negative_tick),
            Err(ExecutionError::Overflow("add", _, _))
        ));
        assert!(matches!(
            max.sub(&negative_tick),
            Err(ExecutionError::Overflow("sub", _, _))
        ));
        assert_eq!(
            max.sub(&tick)
                .unwrap()
                .downcast_ref::<Timestamp>()
                .unwrap()
                .inner(),
            &(*MAX_TIMESTAMP - chrono::Duration::nanoseconds(1))
        );
        assert_eq!(
            min.add(&tick)
                .unwrap()
                .downcast_ref::<Timestamp>()
                .unwrap()
                .inner(),
            &(*MIN_TIMESTAMP + chrono::Duration::nanoseconds(1))
        );
        let zero = CelDuration::from(chrono::Duration::zero());
        assert_eq!(
            max.add(&zero).unwrap().downcast_ref::<Timestamp>().unwrap(),
            &max
        );
        assert_eq!(
            min.sub(&zero).unwrap().downcast_ref::<Timestamp>().unwrap(),
            &min
        );
        assert_eq!(
            max.sub(&min)
                .unwrap()
                .downcast_ref::<CelDuration>()
                .unwrap()
                .inner(),
            &MAX_TIMESTAMP.signed_duration_since(*MIN_TIMESTAMP)
        );
        // Even host-constructed timestamps outside CEL's range cannot panic.
        let chrono_max = Timestamp::from(chrono::DateTime::<chrono::Utc>::MAX_UTC.fixed_offset());
        let chrono_min = Timestamp::from(chrono::DateTime::<chrono::Utc>::MIN_UTC.fixed_offset());
        assert!(matches!(
            chrono_max.add(&tick),
            Err(ExecutionError::Overflow("add", _, _))
        ));
        assert!(matches!(
            chrono_min.sub(&tick),
            Err(ExecutionError::Overflow("sub", _, _))
        ));
    }

    #[test]
    fn temporal_timestamp_parse_error_and_calendar_boundaries() {
        let input = CelString::from("x".repeat(5000));
        let error = timestamp(vec![Cow::Borrowed(&input)]).unwrap_err();
        assert!(
            matches!(&error, ExecutionError::FunctionError { function, message }
            if function == "timestamp" && message == "input contains invalid characters")
        );
        assert!(format!("{error:?}").len() < 128);
        for (source, ordinal) in [
            ("2000-12-31T12:00:00Z", 365),
            ("2001-12-31T12:00:00Z", 364),
            ("0001-01-01T00:00:00Z", 0),
        ] {
            let ts = Timestamp::from(chrono::DateTime::parse_from_rfc3339(source).unwrap());
            let result = day_of_year(vec![Cow::Borrowed(&ts)]).unwrap();
            assert_eq!(*result.downcast_ref::<CelInt>().unwrap().inner(), ordinal);
        }
        let ts = Timestamp::from(chrono::DateTime::<chrono::Utc>::MIN_UTC.fixed_offset());
        assert!(day_of_year(vec![Cow::Borrowed(&ts)]).is_ok());
    }

    #[test]
    fn temporal_runtime_timestamp_overflow_paths() {
        for expression in [
            "timestamp('2000-01-01T00:00:00Z') + duration('9223372036854775807ms')",
            "timestamp('2000-01-01T00:00:00Z') - duration('9223372036854775807ms')",
            "timestamp('2000-01-01T00:00:00Z') + duration('-9223372036854775807ms')",
            "timestamp('2000-01-01T00:00:00Z') - duration('-9223372036854775807ms')",
        ] {
            let error = crate::tests::test_script(expression, None).unwrap_err();
            assert!(
                matches!(error, ExecutionError::Overflow(_, _, _)),
                "{error:?}"
            );
        }
    }
}
