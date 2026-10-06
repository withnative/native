//! Typed time values: the foundation for dates and zoned event time (task
//! fef3469, design proposal D2 slice T1).
//!
//! There are three distinct kinds, and they are never silently converted into
//! one another:
//!
//! - [`TimeValue::Date`] is a floating calendar day, `YYYY-MM-DD`. It has no
//!   zone and is never shifted: `2026-10-05` means the 5th wherever it is read.
//! - [`TimeValue::Instant`] is a point on the UTC timeline. It is written as
//!   RFC 3339 with an offset or `Z`, and normalised to UTC with millisecond
//!   precision, the same normalisation facet-observation `as_of` uses.
//! - [`TimeValue::Zoned`] is a local wall time plus an IANA zone, such as
//!   `{"local":"2026-10-05T10:00","tz":"Europe/London"}`. The engine resolves
//!   the UTC offset from the bundled tz database and stores it alongside.
//!
//! # DST gaps and overlaps
//!
//! A local wall time can fall in a DST gap (it never happens: in London,
//! 2026-03-29T01:30 is skipped) or an overlap (it happens twice: in London,
//! 2026-10-25T01:30 happens at +01:00 and again at +00:00). Resolution is
//! always explicit, through [`Disambiguation`]:
//!
//! - [`Disambiguation::Compatible`] follows the Temporal and RFC 5545 rule.
//!   In an overlap it picks the earlier instant. In a gap it moves the wall
//!   time forward by the length of the gap, so London 01:30 on 2026-03-29
//!   becomes `02:30+01:00`. The *normalised* local time is then the moved
//!   one, so a stored value always names a wall time that exists.
//! - [`Disambiguation::Reject`] refuses both, naming the gap or the candidate
//!   offsets so the caller can choose.
//!
//! A caller-supplied `offset` always wins over the disambiguation rule when
//! it is one of the valid offsets for that wall time. That is how a caller
//! picks the later occurrence in an overlap. An offset that is not valid for
//! that wall time and zone is refused, never adjusted.
//!
//! # Supported range and the tz database
//!
//! `date` and `instant` values cover the years 0000 to 9999, and an instant
//! must stay inside that range once normalised to UTC.
//!
//! `zoned` values are refused when their local date is after
//! [`LAST_ZONED_YEAR`] (2099-12-31). chrono-tz's generated transition tables
//! end in 2099. After that, every zone would silently keep its last offset,
//! so London in July 2100 would resolve to +00:00. A far-future event needs
//! an `instant`, or a `date` if it is all-day.
//!
//! The tz database is compiled in and fixed by the chrono-tz version pinned in
//! `Cargo.lock`, currently IANA 2025b ([`TZDB_VERSION`]). A chrono-tz update
//! can change the offset that the same `local` and `tz` resolve to, when a
//! government changes its zone's rules. So every persisted zoned value
//! records the version it was resolved with: the stored form is
//! `{ "local", "tz", "offset", "tzdb" }` ([`ZonedTime::to_stored_json`]), and
//! the `facet_times` row carries it as `tzdb_version`. Nothing recomputes a
//! stored offset implicitly. The projection reads the persisted offset, never
//! the tz database, so replay is stable across chrono-tz upgrades. After an
//! upgrade, rows whose `tzdb_version` differs from [`TZDB_VERSION`] name
//! exactly the future zoned values to re-resolve (by writing the value back,
//! which re-stamps it) and to report if their instant moved.
//!
//! # Typed time facets
//!
//! A schema shape can declare a facet `type` of `date`, `instant`, `zoned` or
//! `when` ([`TimeFacetType`]). Writers validate and normalise the value with
//! [`normalise_facet_value`], and the content projector folds the persisted
//! value into a `facet_times` row with [`project_facet_value`]. A `when` is
//! all-day over floating dates or timed over instants and zoned times, with
//! an exclusive end or an RFC 5545 duration resolved to one ([`When`]).
//!
//! # Ordering
//!
//! [`TimeValue::compare`] orders dates as calendar days and timed values
//! (instant or zoned) by their instant. A floating date has no position on
//! the timeline, so comparing a date with a timed value is refused rather
//! than inventing a zone for the date.

use std::cmp::Ordering;
use std::fmt;

use chrono::{
    DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveDateTime, Offset, SecondsFormat,
    TimeZone, Timelike, Utc,
};
use chrono_tz::Tz;
use serde_json::{Map, Value};

/// The IANA tz database version compiled in through chrono-tz.
pub const TZDB_VERSION: &str = chrono_tz::IANA_TZDB_VERSION;

/// The last year whose zone rules chrono-tz's generated tables carry. Zoned
/// values with a later local date are refused rather than resolved wrongly.
pub const LAST_ZONED_YEAR: i32 = 2099;

/// The three typed time kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeKind {
    Date,
    Instant,
    Zoned,
}

impl TimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TimeKind::Date => "date",
            TimeKind::Instant => "instant",
            TimeKind::Zoned => "zoned",
        }
    }
}

impl fmt::Display for TimeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How to resolve a zoned wall time that DST skips or repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Disambiguation {
    /// The earlier instant in an overlap, and the wall time moved forward by
    /// the gap in a gap. This is Temporal's `compatible`, and RFC 5545's rule.
    #[default]
    Compatible,
    /// Refuse a wall time that is skipped or repeated.
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimeValueError {
    #[error("'{0}' is not a date: expected a calendar day as YYYY-MM-DD, for example 2026-10-05")]
    InvalidDate(String),
    #[error(
        "'{0}' is not an instant: expected an RFC 3339 date-time with an offset or Z, for example 2026-10-05T09:00:00Z"
    )]
    InvalidInstant(String),
    #[error(
        "'{0}' has a leap second (:60). Leap seconds are not supported: use :59 or the following :00"
    )]
    LeapSecond(String),
    #[error(
        "'{0}' falls outside the years 0000 to 9999 once normalised to UTC, so it cannot be stored"
    )]
    OutOfRange(String),
    #[error(
        "'{0}' is not a local date-time: expected YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS with no offset, for example 2026-10-05T10:00"
    )]
    InvalidLocal(String),
    #[error(
        "'{0}' is not a known IANA time zone: use a tz database name such as Europe/London or America/New_York"
    )]
    UnknownZone(String),
    #[error(
        "'{0}' is not a UTC offset: expected +HH:MM or -HH:MM, or +HH:MM:SS for historical local mean time, for example +01:00"
    )]
    InvalidOffset(String),
    #[error(
        "a zoned value must be an object with string 'local' and 'tz' and an optional string 'offset'{0}"
    )]
    InvalidZonedShape(String),
    #[error(
        "{local} does not exist in {tz}: clocks skip it at a DST change. Pick a wall time outside the gap, or resolve with compatible disambiguation"
    )]
    SkippedLocalTime { local: String, tz: String },
    #[error(
        "{local} happens twice in {tz} at a DST change, at {earlier} and at {later}. Supply the intended offset, or resolve with compatible disambiguation"
    )]
    AmbiguousLocalTime {
        local: String,
        tz: String,
        earlier: String,
        later: String,
    },
    #[error(
        "{local} in {tz} is after 2099-12-31: zone rules are unavailable beyond 2099, so its offset cannot be resolved. Use an instant, or a date for an all-day value"
    )]
    ZoneRulesUnavailable { local: String, tz: String },
    #[error("offset {offset} is not valid for {local} in {tz}; valid: {valid}")]
    OffsetMismatch {
        local: String,
        tz: String,
        offset: String,
        valid: String,
    },
    #[error(
        "cannot order a {0} against a {1}: a floating date has no position on the timeline, so it is only comparable with another date"
    )]
    IncomparableKinds(TimeKind, TimeKind),
    #[error("a when value {0}")]
    InvalidWhen(String),
    #[error(
        "'{0}' is not a duration: expected an RFC 5545 duration such as PT30M, PT1H30M, P1D, P1DT2H or P2W, with no sign"
    )]
    InvalidDuration(String),
    #[error("a when value cannot end before it starts: end {end} is before start {start}")]
    EndBeforeStart { start: String, end: String },
    #[error(
        "an all-day when must cover at least one day: end {end} is exclusive, so it must be after start {start}"
    )]
    EmptyAllDay { start: String, end: String },
    #[error(
        "a when value does not accept '{0}' yet: recurrence (RFC 5545 RRULE, RDATE and EXDATE) arrives in a later release"
    )]
    RecurrenceNotSupported(String),
    #[error(
        "'{0}' is the last supported day: an all-day value covering it would end after 9999-12-31"
    )]
    NoFollowingDay(String),
}

/// A local wall time in an IANA zone, with its engine-resolved UTC offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZonedTime {
    local: NaiveDateTime,
    tz: Tz,
    offset: FixedOffset,
}

impl ZonedTime {
    /// Resolve a local wall time in `tz`, refusing or adjusting DST gaps and
    /// overlaps as `disambiguation` says. See the module docs.
    pub fn resolve(
        local: &str,
        tz: &str,
        offset: Option<&str>,
        disambiguation: Disambiguation,
    ) -> Result<Self, TimeValueError> {
        let local = parse_local(local)?;
        let tz = parse_zone(tz)?;
        let requested = offset.map(parse_offset).transpose()?;
        let unavailable = |local: NaiveDateTime| TimeValueError::ZoneRulesUnavailable {
            local: format_local(local),
            tz: tz.name().into(),
        };
        if local.year() > LAST_ZONED_YEAR {
            return Err(unavailable(local));
        }
        let resolved = Self::resolve_parts(local, tz, requested, disambiguation)?;
        if resolved.local.year() > LAST_ZONED_YEAR {
            return Err(unavailable(resolved.local));
        }
        if resolved.instant().year() < 0 {
            return Err(TimeValueError::OutOfRange(format!(
                "{} {}",
                format_local(resolved.local),
                tz.name()
            )));
        }
        Ok(resolved)
    }

    /// Parse the JSON object form `{ "local", "tz", "offset"? }`.
    ///
    /// A `tzdb` member, as the stored form carries, is accepted and ignored:
    /// the value is resolved again against the compiled tz database, so a
    /// stored value can be written back unchanged.
    pub fn from_json(
        value: &Value,
        disambiguation: Disambiguation,
    ) -> Result<Self, TimeValueError> {
        let object = value
            .as_object()
            .ok_or_else(|| TimeValueError::InvalidZonedShape(String::new()))?;
        if let Some(unknown) = object
            .keys()
            .find(|key| !matches!(key.as_str(), "local" | "tz" | "offset" | "tzdb"))
        {
            return Err(TimeValueError::InvalidZonedShape(format!(
                "; unknown member '{unknown}'"
            )));
        }
        let member = |name: &str| -> Result<Option<&str>, TimeValueError> {
            match object.get(name) {
                None => Ok(None),
                Some(Value::String(text)) => Ok(Some(text)),
                Some(_) => Err(TimeValueError::InvalidZonedShape(format!(
                    "; '{name}' must be a string"
                ))),
            }
        };
        let (Some(local), Some(tz)) = (member("local")?, member("tz")?) else {
            return Err(TimeValueError::InvalidZonedShape(
                "; 'local' and 'tz' are required".into(),
            ));
        };
        member("tzdb")?;
        Self::resolve(local, tz, member("offset")?, disambiguation)
    }

    /// The same instant in `tz`. An instant has exactly one wall time in a
    /// zone, so no disambiguation is needed.
    pub fn from_instant(instant: DateTime<Utc>, tz: Tz) -> Result<Self, TimeValueError> {
        let offset = tz.offset_from_utc_datetime(&instant.naive_utc()).fix();
        let local = instant.naive_utc() + offset;
        if local.year() > LAST_ZONED_YEAR {
            return Err(TimeValueError::ZoneRulesUnavailable {
                local: format_local(local),
                tz: tz.name().into(),
            });
        }
        Ok(Self { local, tz, offset })
    }

    fn resolve_parts(
        local: NaiveDateTime,
        tz: Tz,
        requested: Option<FixedOffset>,
        disambiguation: Disambiguation,
    ) -> Result<Self, TimeValueError> {
        let candidates: Vec<FixedOffset> = match tz.from_local_datetime(&local) {
            chrono::LocalResult::Single(at) => vec![at.offset().fix()],
            chrono::LocalResult::Ambiguous(earlier, later) => {
                vec![earlier.offset().fix(), later.offset().fix()]
            }
            chrono::LocalResult::None => Vec::new(),
        };
        if let Some(requested) = requested {
            if candidates.contains(&requested) {
                return Ok(Self {
                    local,
                    tz,
                    offset: requested,
                });
            }
            return Err(TimeValueError::OffsetMismatch {
                local: format_local(local),
                tz: tz.name().into(),
                offset: format_offset(requested),
                valid: if candidates.is_empty() {
                    "none, because clocks skip this wall time".into()
                } else {
                    candidates
                        .iter()
                        .map(|offset| format_offset(*offset))
                        .collect::<Vec<_>>()
                        .join(" or ")
                },
            });
        }
        match (candidates.as_slice(), disambiguation) {
            ([offset], _) => Ok(Self {
                local,
                tz,
                offset: *offset,
            }),
            ([earlier, later], Disambiguation::Reject) => Err(TimeValueError::AmbiguousLocalTime {
                local: format_local(local),
                tz: tz.name().into(),
                earlier: format_offset(*earlier),
                later: format_offset(*later),
            }),
            ([earlier, _], Disambiguation::Compatible) => Ok(Self {
                local,
                tz,
                offset: *earlier,
            }),
            (_, Disambiguation::Reject) => Err(TimeValueError::SkippedLocalTime {
                local: format_local(local),
                tz: tz.name().into(),
            }),
            (_, Disambiguation::Compatible) => {
                // Interpret the wall time with the offset in force just
                // before the gap, then read it back in the zone. That lands
                // after the transition, moved forward by the gap's length.
                // One day before is safely before the transition (offsets are
                // within ±24h) and after any earlier one (tz database zones do
                // not change offset twice within a day).
                let before = tz
                    .offset_from_utc_datetime(&(local - Duration::days(1)))
                    .fix();
                let instant = local - before;
                let offset = tz.offset_from_utc_datetime(&instant).fix();
                Ok(Self {
                    local: instant + offset,
                    tz,
                    offset,
                })
            }
        }
    }

    pub fn local(&self) -> NaiveDateTime {
        self.local
    }

    pub fn tz(&self) -> Tz {
        self.tz
    }

    pub fn offset(&self) -> FixedOffset {
        self.offset
    }

    pub fn instant(&self) -> DateTime<Utc> {
        (self.local - self.offset).and_utc()
    }

    /// The normalised JSON form, `{ "local", "tz", "offset" }`.
    pub fn to_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("local".into(), Value::String(format_local(self.local)));
        object.insert("tz".into(), Value::String(self.tz.name().into()));
        object.insert("offset".into(), Value::String(format_offset(self.offset)));
        Value::Object(object)
    }

    /// The persisted form: [`Self::to_json`] plus the tz database version the
    /// offset was resolved with, `{ "local", "tz", "offset", "tzdb" }`. A
    /// later chrono-tz upgrade can find values resolved under an older
    /// version and recompute them. See [`TZDB_VERSION`].
    pub fn to_stored_json(&self) -> Value {
        let mut value = self.to_json();
        value["tzdb"] = Value::String(TZDB_VERSION.into());
        value
    }
}

/// One validated typed time value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeValue {
    Date(NaiveDate),
    Instant(DateTime<Utc>),
    Zoned(ZonedTime),
}

impl TimeValue {
    /// Validate and normalise a JSON value as `kind`. `date` and `instant`
    /// are JSON strings; `zoned` is the object form.
    pub fn parse(
        kind: TimeKind,
        value: &Value,
        disambiguation: Disambiguation,
    ) -> Result<Self, TimeValueError> {
        match kind {
            TimeKind::Date => {
                let text = value
                    .as_str()
                    .ok_or_else(|| TimeValueError::InvalidDate(value.to_string()))?;
                parse_date(text).map(TimeValue::Date)
            }
            TimeKind::Instant => {
                let text = value
                    .as_str()
                    .ok_or_else(|| TimeValueError::InvalidInstant(value.to_string()))?;
                parse_instant(text).map(TimeValue::Instant)
            }
            TimeKind::Zoned if value.is_string() => Err(TimeValueError::InvalidZonedShape(
                format!("; got the string {value}"),
            )),
            TimeKind::Zoned => ZonedTime::from_json(value, disambiguation).map(TimeValue::Zoned),
        }
    }

    pub fn kind(&self) -> TimeKind {
        match self {
            TimeValue::Date(_) => TimeKind::Date,
            TimeValue::Instant(_) => TimeKind::Instant,
            TimeValue::Zoned(_) => TimeKind::Zoned,
        }
    }

    /// The normalised JSON form. Parsing it again yields the same value.
    pub fn to_json(&self) -> Value {
        match self {
            TimeValue::Date(date) => Value::String(format_date(*date)),
            TimeValue::Instant(instant) => Value::String(format_instant(*instant)),
            TimeValue::Zoned(zoned) => zoned.to_json(),
        }
    }

    /// Order two values: dates as calendar days, timed values by instant.
    /// A date against a timed value is refused.
    pub fn compare(&self, other: &Self) -> Result<Ordering, TimeValueError> {
        match (self, other) {
            (TimeValue::Date(left), TimeValue::Date(right)) => Ok(left.cmp(right)),
            (TimeValue::Date(_), _) | (_, TimeValue::Date(_)) => {
                Err(TimeValueError::IncomparableKinds(self.kind(), other.kind()))
            }
            _ => Ok(self.timed_instant().cmp(&other.timed_instant())),
        }
    }

    fn timed_instant(&self) -> Option<DateTime<Utc>> {
        match self {
            TimeValue::Date(_) => None,
            TimeValue::Instant(instant) => Some(*instant),
            TimeValue::Zoned(zoned) => Some(zoned.instant()),
        }
    }
}

/// Parse a floating calendar day, strictly `YYYY-MM-DD`.
pub fn parse_date(value: &str) -> Result<NaiveDate, TimeValueError> {
    let invalid = || TimeValueError::InvalidDate(value.into());
    if !has_digit_shape(value, "dddd-dd-dd") {
        return Err(invalid());
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| invalid())
}

/// Parse an RFC 3339 date-time with an offset or `Z`, normalised to UTC and
/// truncated to milliseconds.
///
/// The date and time must be separated by `T` or `t`. RFC 3339 lets an
/// application also accept a space, and chrono does; this kind does not, so
/// one instant has one spelling. Leap seconds (`:60`) are refused, real or
/// invented, because the normalised form cannot represent them. The UTC
/// result must stay within the years 0000 to 9999, so an offset cannot push
/// `0000-01-01` or `9999-12-31` outside the four-digit range.
pub fn parse_instant(value: &str) -> Result<DateTime<Utc>, TimeValueError> {
    if !matches!(value.as_bytes().get(10), Some(b'T' | b't')) {
        return Err(TimeValueError::InvalidInstant(value.into()));
    }
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| TimeValueError::InvalidInstant(value.into()))?;
    // Chrono represents a :60 second as a nanosecond count past one second.
    if parsed.nanosecond() >= 1_000_000_000 {
        return Err(TimeValueError::LeapSecond(value.into()));
    }
    let parsed = parsed.with_timezone(&Utc);
    if !(0..=9999).contains(&parsed.year()) {
        return Err(TimeValueError::OutOfRange(value.into()));
    }
    let millis = parsed.nanosecond() / 1_000_000 * 1_000_000;
    Ok(parsed.with_nanosecond(millis).unwrap_or(parsed))
}

pub fn format_date(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

pub fn format_instant(instant: DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_local(value: &str) -> Result<NaiveDateTime, TimeValueError> {
    let invalid = || TimeValueError::InvalidLocal(value.into());
    let format = if has_digit_shape(value, "dddd-dd-ddTdd:dd") {
        "%Y-%m-%dT%H:%M"
    } else if has_digit_shape(value, "dddd-dd-ddTdd:dd:dd") && !value.ends_with(":60") {
        "%Y-%m-%dT%H:%M:%S"
    } else {
        return Err(invalid());
    };
    NaiveDateTime::parse_from_str(value, format).map_err(|_| invalid())
}

fn parse_zone(value: &str) -> Result<Tz, TimeValueError> {
    value
        .parse::<Tz>()
        .map_err(|_| TimeValueError::UnknownZone(value.into()))
}

fn parse_offset(value: &str) -> Result<FixedOffset, TimeValueError> {
    let invalid = || TimeValueError::InvalidOffset(value.into());
    let sign = match value.as_bytes().first() {
        Some(b'+') => 1,
        Some(b'-') => -1,
        _ => return Err(invalid()),
    };
    // Seconds appear only in historical local mean time, such as Paris's
    // +00:09:21 before 1911, and only when they are non-zero.
    let with_seconds = has_digit_shape(&value[1..], "dd:dd:dd");
    if !with_seconds && !has_digit_shape(&value[1..], "dd:dd") {
        return Err(invalid());
    }
    let field = |range: std::ops::Range<usize>| -> i32 {
        value[range].parse().expect("digit shape checked")
    };
    let (hours, minutes) = (field(1..3), field(4..6));
    let seconds = if with_seconds { field(7..9) } else { 0 };
    if minutes >= 60 || seconds >= 60 || (with_seconds && seconds == 0) {
        return Err(invalid());
    }
    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60 + seconds)).ok_or_else(invalid)
}

fn format_local(local: NaiveDateTime) -> String {
    if local.second() == 0 {
        local.format("%Y-%m-%dT%H:%M").to_string()
    } else {
        local.format("%Y-%m-%dT%H:%M:%S").to_string()
    }
}

fn format_offset(offset: FixedOffset) -> String {
    let seconds = offset.local_minus_utc();
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.abs();
    let (hours, minutes, seconds) = (seconds / 3600, seconds % 3600 / 60, seconds % 60);
    if seconds == 0 {
        format!("{sign}{hours:02}:{minutes:02}")
    } else {
        format!("{sign}{hours:02}:{minutes:02}:{seconds:02}")
    }
}

/// True when `value` matches `shape`, where `d` is any ASCII digit and every
/// other byte must match exactly. Chrono's own parsers accept unpadded and
/// signed fields, which the typed kinds do not.
fn has_digit_shape(value: &str, shape: &str) -> bool {
    value.len() == shape.len()
        && value
            .bytes()
            .zip(shape.bytes())
            .all(|(byte, expected)| match expected {
                b'd' => byte.is_ascii_digit(),
                _ => byte == expected,
            })
}

// ---------------------------------------------------------------------------
// Typed time facets (D2 slice T2)
// ---------------------------------------------------------------------------

/// A declared facet type that carries typed time. The first three are the
/// scalar [`TimeKind`]s; `when` is the event-time object that combines them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeFacetType {
    Date,
    Instant,
    Zoned,
    When,
}

impl TimeFacetType {
    /// Every typed-time declared facet type name, in documentation order.
    pub const NAMES: [&'static str; 4] = ["date", "instant", "zoned", "when"];

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "date" => Some(Self::Date),
            "instant" => Some(Self::Instant),
            "zoned" => Some(Self::Zoned),
            "when" => Some(Self::When),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Date => "date",
            Self::Instant => "instant",
            Self::Zoned => "zoned",
            Self::When => "when",
        }
    }
}

impl fmt::Display for TimeFacetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An RFC 5545 duration (section 3.3.6): whole nominal days, where a week
/// counts as seven, plus an exact time part. Nominal days keep the wall time
/// across a DST change; the time part is elapsed time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventDuration {
    days: i64,
    seconds: i64,
}

impl EventDuration {
    /// Parse `PnW`, `PnD`, `PnDT...` or `PT...`, where the time part is
    /// `nH`, `nM` and `nS` in that order, each optional but at least one
    /// present. Signs and fractions are refused: an end never precedes its
    /// start, and the stored form is the resolved `end`, not the duration.
    pub fn parse(value: &str) -> Result<Self, TimeValueError> {
        let invalid = || TimeValueError::InvalidDuration(value.into());
        // Every valid duration is ASCII. Refusing anything else first makes
        // each byte offset below a character boundary, so slicing cannot
        // panic on multi-byte input such as "Pé".
        if !value.is_ascii() {
            return Err(invalid());
        }
        let rest = value.strip_prefix('P').ok_or_else(invalid)?;
        if rest.is_empty() {
            return Err(invalid());
        }
        let (date_part, time_part) = match rest.split_once('T') {
            Some((date, time)) if !time.is_empty() => (date, Some(time)),
            Some(_) => return Err(invalid()),
            None => (rest, None),
        };
        let mut days = 0i64;
        if !date_part.is_empty() {
            let (count, unit) = split_duration_field(date_part).ok_or_else(invalid)?;
            days = match (unit, time_part) {
                ("W", None) => count.checked_mul(7).ok_or_else(invalid)?,
                ("D", _) => count,
                _ => return Err(invalid()),
            };
        }
        let mut seconds = 0i64;
        if let Some(mut time) = time_part {
            let mut last_rank = 0;
            while !time.is_empty() {
                let end = time
                    .find(|c: char| !c.is_ascii_digit())
                    .ok_or_else(invalid)?;
                let (count, unit) = split_duration_field(&time[..=end]).ok_or_else(invalid)?;
                let (rank, scale) = match unit {
                    "H" => (1, 3600),
                    "M" => (2, 60),
                    "S" => (3, 1),
                    _ => return Err(invalid()),
                };
                if rank <= last_rank {
                    return Err(invalid());
                }
                last_rank = rank;
                seconds = count
                    .checked_mul(scale)
                    .and_then(|part| seconds.checked_add(part))
                    .ok_or_else(invalid)?;
                time = &time[end + 1..];
            }
        }
        // Bound the span so date arithmetic below cannot overflow. Ten
        // thousand years exceeds every representable value anyway.
        const MAX_DAYS: i64 = 10_000 * 366;
        if days > MAX_DAYS || seconds > MAX_DAYS * 86_400 {
            return Err(TimeValueError::OutOfRange(value.into()));
        }
        Ok(Self { days, seconds })
    }

    fn has_time(&self) -> bool {
        self.seconds != 0
    }
}

/// One `digits` + `unit` field. The unit is a single ASCII letter.
fn split_duration_field(field: &str) -> Option<(i64, &str)> {
    let unit_at = field.len().checked_sub(1)?;
    let (digits, unit) = field.split_at(unit_at);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if digits.len() > 12 {
        return None;
    }
    Some((digits.parse().ok()?, unit))
}

/// A `when` facet value: when something happens.
///
/// An all-day `when` spans floating dates, and its `end` is exclusive: the
/// 5th to the 6th inclusive is `{ "all_day": true, "start": "2026-10-05",
/// "end": "2026-10-07" }`. A timed `when` starts and ends at an `instant` or a
/// `zoned` time, and start and end may use different zones (a flight from
/// London to New York). A caller may give an RFC 5545 `duration` instead of
/// `end`; the engine resolves it and stores `end`. Recurrence members are
/// reserved for a later release and refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct When {
    all_day: bool,
    start: TimeValue,
    end: TimeValue,
}

impl When {
    pub fn from_json(
        value: &Value,
        disambiguation: Disambiguation,
    ) -> Result<Self, TimeValueError> {
        let object = value.as_object().ok_or_else(|| {
            TimeValueError::InvalidWhen(
                "must be an object with all_day, start, and end or duration".into(),
            )
        })?;
        for key in object.keys() {
            match key.as_str() {
                "all_day" | "start" | "end" | "duration" => {}
                "rrule" | "rdate" | "exdate" | "recurrence" | "recurrence_id" => {
                    return Err(TimeValueError::RecurrenceNotSupported(key.clone()))
                }
                other => {
                    return Err(TimeValueError::InvalidWhen(format!(
                        "has unknown member '{other}': expected all_day, start, and end or duration"
                    )))
                }
            }
        }
        let all_day = match object.get("all_day") {
            Some(Value::Bool(all_day)) => *all_day,
            Some(_) => {
                return Err(TimeValueError::InvalidWhen(
                    "needs all_day as true or false".into(),
                ))
            }
            None => {
                return Err(TimeValueError::InvalidWhen(
                    "needs all_day: true for dates, false for an instant or zoned time".into(),
                ))
            }
        };
        let start = object
            .get("start")
            .ok_or_else(|| TimeValueError::InvalidWhen("needs a start".into()))?;
        let start = Self::endpoint(all_day, "start", start, disambiguation)?;
        let end = match (object.get("end"), object.get("duration")) {
            (Some(end), None) => Self::endpoint(all_day, "end", end, disambiguation)?,
            (None, Some(Value::String(duration))) => Self::end_after(
                all_day,
                &start,
                EventDuration::parse(duration)?,
                disambiguation,
            )?,
            (None, Some(other)) => return Err(TimeValueError::InvalidDuration(other.to_string())),
            (Some(_), Some(_)) => {
                return Err(TimeValueError::InvalidWhen(
                    "takes end or duration, not both".into(),
                ))
            }
            (None, None) => {
                return Err(TimeValueError::InvalidWhen(
                    "needs an end or a duration".into(),
                ))
            }
        };
        let order = start.compare(&end)?;
        let describe = |value: &TimeValue| match value.to_json() {
            Value::String(text) => text,
            other => other.to_string(),
        };
        if order == Ordering::Greater {
            return Err(TimeValueError::EndBeforeStart {
                start: describe(&start),
                end: describe(&end),
            });
        }
        if all_day && order == Ordering::Equal {
            return Err(TimeValueError::EmptyAllDay {
                start: describe(&start),
                end: describe(&end),
            });
        }
        Ok(Self {
            all_day,
            start,
            end,
        })
    }

    fn endpoint(
        all_day: bool,
        name: &str,
        value: &Value,
        disambiguation: Disambiguation,
    ) -> Result<TimeValue, TimeValueError> {
        if all_day {
            if !value.is_string() {
                return Err(TimeValueError::InvalidWhen(format!(
                    "with all_day: true needs {name} as a date such as 2026-10-05"
                )));
            }
            return TimeValue::parse(TimeKind::Date, value, disambiguation);
        }
        match value {
            Value::String(text) if parse_date(text).is_ok() => Err(TimeValueError::InvalidWhen(
                format!("with all_day: false needs {name} as an instant or a zoned time, not the date {text}; use all_day: true for dates"),
            )),
            Value::String(_) => TimeValue::parse(TimeKind::Instant, value, disambiguation),
            Value::Object(_) => TimeValue::parse(TimeKind::Zoned, value, disambiguation),
            _ => Err(TimeValueError::InvalidWhen(format!(
                "needs {name} as an instant string or a zoned object"
            ))),
        }
    }

    fn end_after(
        all_day: bool,
        start: &TimeValue,
        duration: EventDuration,
        disambiguation: Disambiguation,
    ) -> Result<TimeValue, TimeValueError> {
        let span = |days: i64| {
            Duration::try_days(days).ok_or(TimeValueError::OutOfRange(format!("P{days}D")))
        };
        match start {
            TimeValue::Date(date) => {
                if all_day && duration.has_time() {
                    return Err(TimeValueError::InvalidWhen(
                        "with all_day: true needs a duration in whole days or weeks, such as P1D or P1W".into(),
                    ));
                }
                let end = date
                    .checked_add_signed(span(duration.days)?)
                    .filter(|end| end.year() <= 9999)
                    .ok_or_else(|| TimeValueError::OutOfRange(format_date(*date)))?;
                Ok(TimeValue::Date(end))
            }
            TimeValue::Instant(instant) => {
                let end = instant
                    .checked_add_signed(span(duration.days)?)
                    .and_then(|end| end.checked_add_signed(Duration::seconds(duration.seconds)))
                    .filter(|end| end.year() <= 9999)
                    .ok_or_else(|| TimeValueError::OutOfRange(format_instant(*instant)))?;
                Ok(TimeValue::Instant(end))
            }
            TimeValue::Zoned(zoned) => {
                // Nominal days move the wall time and resolve it again, so a
                // 10:00 start plus P1D ends at 10:00 across a DST change. The
                // time part is then elapsed time from that point. With no
                // nominal days the resolved start is kept as it is: resolving
                // its wall time again would lose the occurrence the caller
                // chose in a DST overlap (the later 01:30 would become the
                // earlier one) or refuse it under `reject`.
                let out_of_range = || TimeValueError::OutOfRange(format_local(zoned.local));
                let moved = if duration.days == 0 {
                    *zoned
                } else {
                    let local = zoned
                        .local
                        .checked_add_signed(span(duration.days)?)
                        .ok_or_else(out_of_range)?;
                    ZonedTime::resolve_local(local, zoned.tz, disambiguation)?
                };
                let instant = moved
                    .instant()
                    .checked_add_signed(Duration::seconds(duration.seconds))
                    .ok_or_else(out_of_range)?;
                Ok(TimeValue::Zoned(ZonedTime::from_instant(
                    instant, zoned.tz,
                )?))
            }
        }
    }

    /// The persisted form: `{ "all_day", "start", "end" }`, with dates and
    /// instants normalised and each zoned endpoint in its persisted form.
    pub fn to_stored_json(&self) -> Value {
        let mut object = Map::new();
        object.insert("all_day".into(), Value::Bool(self.all_day));
        object.insert("start".into(), stored_endpoint(&self.start));
        object.insert("end".into(), stored_endpoint(&self.end));
        Value::Object(object)
    }
}

fn stored_endpoint(value: &TimeValue) -> Value {
    match value {
        TimeValue::Zoned(zoned) => zoned.to_stored_json(),
        other => other.to_json(),
    }
}

impl ZonedTime {
    /// [`Self::resolve`] for an already parsed wall time.
    fn resolve_local(
        local: NaiveDateTime,
        tz: Tz,
        disambiguation: Disambiguation,
    ) -> Result<Self, TimeValueError> {
        Self::resolve(&format_local(local), tz.name(), None, disambiguation)
    }
}

/// Validate a facet value declared as `facet_type` and return its persisted
/// JSON form. Dates and instants persist as their normalised strings, zoned
/// values as `{ local, tz, offset, tzdb }`, and `when` values as
/// `{ all_day, start, end }`. Every accepted value is also projectable, so
/// the `facet_times` fold cannot refuse what a writer accepted.
pub fn normalise_facet_value(
    facet_type: TimeFacetType,
    value: &Value,
    disambiguation: Disambiguation,
) -> Result<Value, TimeValueError> {
    let stored = match facet_type {
        TimeFacetType::Date => TimeValue::parse(TimeKind::Date, value, disambiguation)?.to_json(),
        TimeFacetType::Instant => {
            TimeValue::parse(TimeKind::Instant, value, disambiguation)?.to_json()
        }
        TimeFacetType::Zoned => match TimeValue::parse(TimeKind::Zoned, value, disambiguation)? {
            TimeValue::Zoned(zoned) => zoned.to_stored_json(),
            _ => unreachable!("a zoned parse yields a zoned value"),
        },
        TimeFacetType::When => When::from_json(value, disambiguation)?.to_stored_json(),
    };
    project_facet_value(facet_type, &stored)?;
    Ok(stored)
}

/// One row of the `facet_times` projection: a typed time facet value on the
/// timeline, in the columns governed SQL can range-query without date
/// functions.
///
/// All-day rows (`date`, and an all-day `when`) fill `start_date` and the
/// exclusive `end_date`, and leave the millisecond columns NULL: a floating
/// day has no position on the timeline until a viewer's zone is applied.
/// Timed rows fill `start_ms` and `end_ms` (UTC epoch milliseconds, end
/// exclusive, equal to start for a single instant or zoned value) and leave
/// the date columns NULL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FacetTimeRow {
    pub kind: TimeFacetType,
    pub all_day: bool,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub start_ms: Option<i64>,
    pub end_ms: Option<i64>,
    /// The IANA zone of a zoned start, else of a zoned end.
    pub tz: Option<String>,
    /// The tz database version the zoned offsets were resolved with.
    pub tzdb_version: Option<String>,
}

/// Project a persisted typed time facet value into its `facet_times` row.
///
/// This reads the persisted offsets and never the tz database, so replaying
/// the same event gives the same row whichever chrono-tz version runs it. A
/// tz database upgrade therefore never moves a stored value silently: the
/// row keeps its `tzdb_version`, and recomputation is an explicit rewrite.
pub fn project_facet_value(
    facet_type: TimeFacetType,
    stored: &Value,
) -> Result<FacetTimeRow, TimeValueError> {
    let mut row = FacetTimeRow {
        kind: facet_type,
        all_day: false,
        start_date: None,
        end_date: None,
        start_ms: None,
        end_ms: None,
        tz: None,
        tzdb_version: None,
    };
    match facet_type {
        TimeFacetType::Date => {
            let text = stored
                .as_str()
                .ok_or_else(|| TimeValueError::InvalidDate(stored.to_string()))?;
            let date = parse_date(text)?;
            let next = date
                .succ_opt()
                .filter(|next| next.year() <= 9999)
                .ok_or_else(|| TimeValueError::NoFollowingDay(text.into()))?;
            row.all_day = true;
            row.start_date = Some(format_date(date));
            row.end_date = Some(format_date(next));
        }
        TimeFacetType::Instant => {
            let text = stored
                .as_str()
                .ok_or_else(|| TimeValueError::InvalidInstant(stored.to_string()))?;
            let at = parse_instant(text)?.timestamp_millis();
            row.start_ms = Some(at);
            row.end_ms = Some(at);
        }
        TimeFacetType::Zoned => {
            let zoned = StoredZoned::parse(stored)?;
            row.start_ms = Some(zoned.millis);
            row.end_ms = Some(zoned.millis);
            row.tz = Some(zoned.tz);
            row.tzdb_version = zoned.tzdb;
        }
        TimeFacetType::When => {
            let object = stored
                .as_object()
                .ok_or_else(|| TimeValueError::InvalidWhen("must be an object".into()))?;
            let member = |name: &str| {
                object.get(name).ok_or_else(|| {
                    TimeValueError::InvalidWhen(format!("stored value lacks '{name}'"))
                })
            };
            if member("all_day")?.as_bool() == Some(true) {
                let date = |name: &str| -> Result<NaiveDate, TimeValueError> {
                    let value = member(name)?;
                    parse_date(
                        value
                            .as_str()
                            .ok_or_else(|| TimeValueError::InvalidDate(value.to_string()))?,
                    )
                };
                row.all_day = true;
                row.start_date = Some(format_date(date("start")?));
                row.end_date = Some(format_date(date("end")?));
            } else {
                let mut zones = Vec::new();
                let mut endpoint = |name: &str| -> Result<i64, TimeValueError> {
                    match member(name)? {
                        Value::String(text) => Ok(parse_instant(text)?.timestamp_millis()),
                        other => {
                            let zoned = StoredZoned::parse(other)?;
                            zones.push((zoned.tz, zoned.tzdb));
                            Ok(zoned.millis)
                        }
                    }
                };
                row.start_ms = Some(endpoint("start")?);
                row.end_ms = Some(endpoint("end")?);
                if let Some((tz, tzdb)) = zones.into_iter().next() {
                    row.tz = Some(tz);
                    row.tzdb_version = tzdb;
                }
            }
        }
    }
    Ok(row)
}

/// A persisted zoned value read by its stored offset alone.
struct StoredZoned {
    millis: i64,
    tz: String,
    tzdb: Option<String>,
}

impl StoredZoned {
    fn parse(value: &Value) -> Result<Self, TimeValueError> {
        let shape = |detail: &str| TimeValueError::InvalidZonedShape(format!("; {detail}"));
        let object = value
            .as_object()
            .ok_or_else(|| shape("a stored zoned value must be an object"))?;
        let text = |name: &str| -> Result<Option<&str>, TimeValueError> {
            match object.get(name) {
                None => Ok(None),
                Some(Value::String(text)) => Ok(Some(text)),
                Some(_) => Err(shape(&format!("'{name}' must be a string"))),
            }
        };
        let (Some(local), Some(tz), Some(offset)) = (text("local")?, text("tz")?, text("offset")?)
        else {
            return Err(shape(
                "a stored zoned value needs 'local', 'tz' and 'offset'",
            ));
        };
        if tz.is_empty() {
            return Err(TimeValueError::UnknownZone(tz.into()));
        }
        let instant = (parse_local(local)? - parse_offset(offset)?).and_utc();
        Ok(Self {
            millis: instant.timestamp_millis(),
            tz: tz.into(),
            tzdb: text("tzdb")?.map(String::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn zoned(
        local: &str,
        tz: &str,
        disambiguation: Disambiguation,
    ) -> Result<ZonedTime, TimeValueError> {
        ZonedTime::resolve(local, tz, None, disambiguation)
    }

    #[test]
    fn date_round_trips_unchanged() {
        let value =
            TimeValue::parse(TimeKind::Date, &json!("2026-10-05"), Disambiguation::Reject).unwrap();
        assert_eq!(value.to_json(), json!("2026-10-05"));
        assert_eq!(
            value,
            TimeValue::Date(NaiveDate::from_ymd_opt(2026, 10, 5).unwrap())
        );
        assert!(parse_date("2028-02-29").is_ok(), "leap day");
    }

    #[test]
    fn invalid_dates_are_refused() {
        for bad in [
            "2026-1-5",
            "2026-02-30",
            "2027-02-29",
            "2026-13-01",
            "+2026-10-05",
            " 2026-10-05",
            "2026-10-05T00:00:00Z",
            "05/10/2026",
            "",
        ] {
            assert_eq!(
                parse_date(bad),
                Err(TimeValueError::InvalidDate(bad.into())),
                "{bad:?}"
            );
        }
        assert!(
            TimeValue::parse(TimeKind::Date, &json!(20261005), Disambiguation::Reject).is_err()
        );
    }

    #[test]
    fn instants_normalise_to_utc_milliseconds() {
        for (input, expected) in [
            ("2026-10-05T09:00:00Z", "2026-10-05T09:00:00.000Z"),
            ("2026-10-05T10:00:00+01:00", "2026-10-05T09:00:00.000Z"),
            ("2026-10-05T04:30:00.1239-04:30", "2026-10-05T09:00:00.123Z"),
        ] {
            let value =
                TimeValue::parse(TimeKind::Instant, &json!(input), Disambiguation::Reject).unwrap();
            assert_eq!(value.to_json(), json!(expected), "{input}");
            assert_eq!(
                TimeValue::parse(TimeKind::Instant, &value.to_json(), Disambiguation::Reject)
                    .unwrap(),
                value,
                "normalised form re-parses to the same value"
            );
        }
    }

    #[test]
    fn invalid_instants_are_refused() {
        for bad in [
            "2026-10-05",
            "2026-10-05T09:00:00",
            "2026-10-05T09:00",
            "2026-10-05T25:00:00Z",
            "2026-10-05T09:00:00+25:00",
            "2026-10-05 09:00:00Z",
            "not a time",
        ] {
            assert_eq!(
                parse_instant(bad),
                Err(TimeValueError::InvalidInstant(bad.into())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn zoned_resolves_offset_and_round_trips() {
        let summer = zoned("2026-07-01T10:00", "Europe/London", Disambiguation::Reject).unwrap();
        assert_eq!(
            summer.to_json(),
            json!({ "local": "2026-07-01T10:00", "tz": "Europe/London", "offset": "+01:00" })
        );
        assert_eq!(format_instant(summer.instant()), "2026-07-01T09:00:00.000Z");
        let winter = zoned(
            "2026-12-01T10:00:30",
            "Europe/London",
            Disambiguation::Reject,
        )
        .unwrap();
        assert_eq!(winter.to_json()["offset"], json!("+00:00"));
        assert_eq!(winter.to_json()["local"], json!("2026-12-01T10:00:30"));

        let kolkata = zoned("2026-10-05T10:00", "Asia/Kolkata", Disambiguation::Reject).unwrap();
        assert_eq!(kolkata.to_json()["offset"], json!("+05:30"));
        let st_johns = zoned(
            "2026-12-01T10:00",
            "America/St_Johns",
            Disambiguation::Reject,
        )
        .unwrap();
        assert_eq!(st_johns.to_json()["offset"], json!("-03:30"));

        let value = TimeValue::Zoned(summer);
        assert_eq!(
            TimeValue::parse(TimeKind::Zoned, &value.to_json(), Disambiguation::Reject).unwrap(),
            value
        );
    }

    #[test]
    fn invalid_zoned_values_are_refused() {
        assert_eq!(
            zoned(
                "2026-10-05T10:00",
                "Europe/Atlantis",
                Disambiguation::Compatible
            ),
            Err(TimeValueError::UnknownZone("Europe/Atlantis".into()))
        );
        assert!(
            zoned(
                "2026-10-05T10:00",
                "europe/london",
                Disambiguation::Compatible
            )
            .is_err(),
            "zone names are case-sensitive"
        );
        for bad_local in [
            "2026-10-05",
            "2026-10-05T10:00Z",
            "2026-10-05T10:00+01:00",
            "2026-10-05T24:00",
            "2026-10-05T10:00:60",
            "2026-10-05T10:00:00.5",
            "2026-10-05 10:00",
        ] {
            assert_eq!(
                zoned(bad_local, "Europe/London", Disambiguation::Compatible),
                Err(TimeValueError::InvalidLocal(bad_local.into())),
                "{bad_local:?}"
            );
        }
        for bad in [
            json!("2026-10-05T10:00"),
            json!({ "local": "2026-10-05T10:00" }),
            json!({ "local": "2026-10-05T10:00", "tz": 1 }),
            json!({ "local": "2026-10-05T10:00", "tz": "Europe/London", "zone": "x" }),
        ] {
            assert!(
                matches!(
                    TimeValue::parse(TimeKind::Zoned, &bad, Disambiguation::Compatible),
                    Err(TimeValueError::InvalidZonedShape(_))
                ),
                "{bad}"
            );
        }
        assert_eq!(
            ZonedTime::resolve(
                "2026-10-05T10:00",
                "Europe/London",
                Some("+1:00"),
                Disambiguation::Compatible
            ),
            Err(TimeValueError::InvalidOffset("+1:00".into()))
        );
        let mismatch = ZonedTime::resolve(
            "2026-07-01T10:00",
            "Europe/London",
            Some("+00:00"),
            Disambiguation::Compatible,
        )
        .unwrap_err();
        assert_eq!(
            mismatch.to_string(),
            "offset +00:00 is not valid for 2026-07-01T10:00 in Europe/London; valid: +01:00"
        );
    }

    /// 2026-03-29T01:30 does not exist in London: clocks go from 01:00 GMT
    /// straight to 02:00 BST.
    #[test]
    fn dst_gap_is_moved_forward_under_compatible_and_refused_under_reject() {
        let resolved = zoned(
            "2026-03-29T01:30",
            "Europe/London",
            Disambiguation::Compatible,
        )
        .unwrap();
        assert_eq!(
            resolved.to_json(),
            json!({ "local": "2026-03-29T02:30", "tz": "Europe/London", "offset": "+01:00" })
        );
        assert_eq!(
            format_instant(resolved.instant()),
            "2026-03-29T01:30:00.000Z"
        );

        let refused =
            zoned("2026-03-29T01:30", "Europe/London", Disambiguation::Reject).unwrap_err();
        assert_eq!(
            refused,
            TimeValueError::SkippedLocalTime {
                local: "2026-03-29T01:30".into(),
                tz: "Europe/London".into(),
            }
        );
        assert!(refused
            .to_string()
            .contains("does not exist in Europe/London"));

        let with_offset = ZonedTime::resolve(
            "2026-03-29T01:30",
            "Europe/London",
            Some("+00:00"),
            Disambiguation::Compatible,
        )
        .unwrap_err();
        assert!(
            with_offset.to_string().contains("valid: none"),
            "an explicit offset never rescues a skipped wall time: {with_offset}"
        );

        // Either side of the gap resolves without disambiguation.
        assert_eq!(
            zoned("2026-03-29T00:59", "Europe/London", Disambiguation::Reject)
                .unwrap()
                .offset(),
            FixedOffset::east_opt(0).unwrap()
        );
        assert_eq!(
            zoned("2026-03-29T02:00", "Europe/London", Disambiguation::Reject)
                .unwrap()
                .offset(),
            FixedOffset::east_opt(3600).unwrap()
        );
    }

    /// 2026-10-25T01:30 happens twice in London: first in BST (+01:00), then
    /// again in GMT (+00:00) after clocks go back at 02:00 BST.
    #[test]
    fn dst_overlap_picks_earlier_under_compatible_and_is_refused_under_reject() {
        let resolved = zoned(
            "2026-10-25T01:30",
            "Europe/London",
            Disambiguation::Compatible,
        )
        .unwrap();
        assert_eq!(
            resolved.to_json(),
            json!({ "local": "2026-10-25T01:30", "tz": "Europe/London", "offset": "+01:00" })
        );
        assert_eq!(
            format_instant(resolved.instant()),
            "2026-10-25T00:30:00.000Z"
        );

        let refused =
            zoned("2026-10-25T01:30", "Europe/London", Disambiguation::Reject).unwrap_err();
        assert_eq!(
            refused,
            TimeValueError::AmbiguousLocalTime {
                local: "2026-10-25T01:30".into(),
                tz: "Europe/London".into(),
                earlier: "+01:00".into(),
                later: "+00:00".into(),
            }
        );

        // An explicit offset selects either occurrence, under either rule.
        let later = ZonedTime::resolve(
            "2026-10-25T01:30",
            "Europe/London",
            Some("+00:00"),
            Disambiguation::Reject,
        )
        .unwrap();
        assert_eq!(format_instant(later.instant()), "2026-10-25T01:30:00.000Z");
        let later = TimeValue::Zoned(later);
        assert_eq!(
            TimeValue::parse(TimeKind::Zoned, &later.to_json(), Disambiguation::Reject).unwrap(),
            later,
            "the stored offset keeps the later occurrence on re-parse"
        );
        assert_eq!(
            TimeValue::Zoned(resolved).compare(&later),
            Ok(Ordering::Less)
        );
    }

    #[test]
    fn dates_order_as_calendar_days_and_never_against_timed_values() {
        let date = |text: &str| TimeValue::Date(parse_date(text).unwrap());
        assert_eq!(
            date("2026-10-05").compare(&date("2026-10-06")),
            Ok(Ordering::Less)
        );
        assert_eq!(
            date("2026-10-05").compare(&date("2026-10-05")),
            Ok(Ordering::Equal)
        );
        assert_eq!(
            date("2026-12-31").compare(&date("2026-01-01")),
            Ok(Ordering::Greater)
        );

        let instant = TimeValue::Instant(parse_instant("2026-10-05T00:00:00Z").unwrap());
        assert_eq!(
            date("2026-10-05").compare(&instant),
            Err(TimeValueError::IncomparableKinds(
                TimeKind::Date,
                TimeKind::Instant
            ))
        );
        let zoned_value = TimeValue::Zoned(
            zoned("2026-10-05T10:00", "Europe/London", Disambiguation::Reject).unwrap(),
        );
        assert!(zoned_value.compare(&date("2026-10-05")).is_err());

        // Zoned and instant values share the timeline.
        let nine_utc = TimeValue::Instant(parse_instant("2026-10-05T09:00:00Z").unwrap());
        assert_eq!(zoned_value.compare(&nine_utc), Ok(Ordering::Equal));
        let new_york = TimeValue::Zoned(
            zoned(
                "2026-10-05T05:00",
                "America/New_York",
                Disambiguation::Reject,
            )
            .unwrap(),
        );
        assert_eq!(new_york.compare(&zoned_value), Ok(Ordering::Equal));
    }

    fn round_trips(value: &TimeValue) {
        let json = value.to_json();
        let kind = value.kind();
        assert_eq!(
            TimeValue::parse(kind, &json, Disambiguation::Reject).as_ref(),
            Ok(value),
            "{json} re-parses to the same value"
        );
    }

    /// Before standard time, zones used local mean time, whose offsets have
    /// seconds. They must survive serialisation.
    #[test]
    fn historical_offsets_keep_their_seconds_and_round_trip() {
        for (local, tz, offset) in [
            ("1900-01-01T12:00", "Europe/Paris", "+00:09:21"),
            ("1919-06-01T12:00", "Asia/Kathmandu", "+05:41:16"),
            ("1900-01-01T12:00", "America/New_York", "-05:00"),
        ] {
            let value = TimeValue::Zoned(zoned(local, tz, Disambiguation::Reject).unwrap());
            assert_eq!(value.to_json()["offset"], json!(offset), "{local} {tz}");
            round_trips(&value);
            assert!(
                ZonedTime::resolve(local, tz, Some(offset), Disambiguation::Reject).is_ok(),
                "{offset} is accepted as input"
            );
        }
        for bad in ["+00:09:60", "+00:09:00", "+00:9:21", "+00:09:21:00"] {
            assert_eq!(
                parse_offset(bad),
                Err(TimeValueError::InvalidOffset(bad.into())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn instants_require_a_t_separator() {
        assert!(
            parse_instant("2026-10-05t09:00:00z").is_ok(),
            "RFC 3339 allows lower case"
        );
        assert_eq!(
            parse_instant("2026-10-05 09:00:00Z"),
            Err(TimeValueError::InvalidInstant(
                "2026-10-05 09:00:00Z".into()
            ))
        );
    }

    #[test]
    fn leap_seconds_are_refused_whether_real_or_invented() {
        // 2016-12-31T23:59:60Z was a real leap second; 2026-10-05T09:00:60Z
        // never happened. Neither is representable once normalised.
        for leap in ["2016-12-31T23:59:60Z", "2026-10-05T09:00:60Z"] {
            let error = parse_instant(leap).unwrap_err();
            assert_eq!(error, TimeValueError::LeapSecond(leap.into()));
            assert!(error.to_string().contains("Leap seconds are not supported"));
        }
    }

    #[test]
    fn instants_stay_within_four_digit_years_after_normalisation() {
        for (input, expected) in [
            ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00.000Z"),
            ("0000-01-01T00:00:00-01:00", "0000-01-01T01:00:00.000Z"),
            ("9999-12-31T23:59:59.999Z", "9999-12-31T23:59:59.999Z"),
            ("9999-12-31T23:59:59+01:00", "9999-12-31T22:59:59.000Z"),
        ] {
            let value = TimeValue::Instant(parse_instant(input).unwrap());
            assert_eq!(value.to_json(), json!(expected), "{input}");
            round_trips(&value);
        }
        for outside in ["0000-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"] {
            let error = parse_instant(outside).unwrap_err();
            assert_eq!(error, TimeValueError::OutOfRange(outside.into()));
            assert!(error.to_string().contains("outside the years 0000 to 9999"));
        }
    }

    /// chrono-tz's tables end in 2099. Inside the range, DST still applies at
    /// the boundary; past it, the value is refused rather than resolved to a
    /// zone's last offset.
    #[test]
    fn zoned_values_after_2099_are_refused() {
        for (local, tz, offset) in [
            ("2099-07-01T12:00", "Europe/London", "+01:00"),
            ("2099-12-31T23:59", "Europe/London", "+00:00"),
            ("2099-12-31T12:00", "Australia/Sydney", "+11:00"),
        ] {
            let value = zoned(local, tz, Disambiguation::Reject).unwrap();
            assert_eq!(value.to_json()["offset"], json!(offset), "{local} {tz}");
        }
        for local in ["2100-01-01T00:00", "2100-07-01T12:00"] {
            let error = zoned(local, "Europe/London", Disambiguation::Compatible).unwrap_err();
            assert_eq!(
                error,
                TimeValueError::ZoneRulesUnavailable {
                    local: local.into(),
                    tz: "Europe/London".into()
                }
            );
            assert!(error
                .to_string()
                .contains("zone rules are unavailable beyond 2099"));
        }
        // Dates and instants are not limited by zone rules.
        assert!(parse_date("2100-07-01").is_ok());
        assert!(parse_instant("2100-07-01T12:00:00Z").is_ok());
    }

    #[test]
    fn zoned_instants_stay_within_four_digit_years() {
        // Paris local mean time is +00:09:21, so local midnight on 0000-01-01
        // is in year -1 in UTC. New York's is -04:56:02, which stays in 0000.
        assert!(matches!(
            zoned("0000-01-01T00:00", "Europe/Paris", Disambiguation::Reject),
            Err(TimeValueError::OutOfRange(_))
        ));
        let new_york = zoned(
            "0000-01-01T00:00",
            "America/New_York",
            Disambiguation::Reject,
        );
        round_trips(&TimeValue::Zoned(new_york.unwrap()));
    }

    /// Resolved offsets depend on the bundled tz database. This pin makes a
    /// chrono-tz update that changes it a deliberate, reviewed change: stored
    /// zoned values may need their offsets recomputed (see the module docs).
    #[test]
    fn tz_database_version_is_pinned() {
        assert_eq!(TZDB_VERSION, "2025b");
    }

    /// Gaps of other lengths than an hour, so a hard-coded one-hour shift
    /// would fail.
    #[test]
    fn dst_gaps_move_forward_by_their_own_length() {
        for (local, tz, moved, offset) in [
            // Lord Howe springs forward 30 minutes, 02:00 +10:30 to 02:30 +11:00.
            (
                "2026-10-04T02:15",
                "Australia/Lord_Howe",
                "2026-10-04T02:45",
                "+11:00",
            ),
            // Samoa skipped 30 December 2011 entirely, -10:00 to +14:00.
            (
                "2011-12-30T12:00",
                "Pacific/Apia",
                "2011-12-31T12:00",
                "+14:00",
            ),
            (
                "2011-12-30T00:00",
                "Pacific/Apia",
                "2011-12-31T00:00",
                "+14:00",
            ),
        ] {
            let resolved = zoned(local, tz, Disambiguation::Compatible).unwrap();
            assert_eq!(
                resolved.to_json(),
                json!({ "local": moved, "tz": tz, "offset": offset }),
                "{local} {tz}"
            );
            round_trips(&TimeValue::Zoned(resolved));
            assert!(
                matches!(
                    zoned(local, tz, Disambiguation::Reject),
                    Err(TimeValueError::SkippedLocalTime { .. })
                ),
                "{local} {tz}"
            );
        }
        // The last second before Samoa's jump still exists.
        assert_eq!(
            zoned(
                "2011-12-29T23:59:59",
                "Pacific/Apia",
                Disambiguation::Reject
            )
            .unwrap()
            .to_json()["offset"],
            json!("-10:00")
        );
    }

    /// Overlaps in the southern hemisphere, in April, and of 30 minutes.
    #[test]
    fn dst_overlaps_pick_the_earlier_occurrence_everywhere() {
        for (local, tz, earlier, later) in [
            // Sydney falls back at 03:00 +11:00 to 02:00 +10:00.
            ("2026-04-05T02:30", "Australia/Sydney", "+11:00", "+10:00"),
            // Lord Howe falls back 30 minutes, 02:00 +11:00 to 01:30 +10:30.
            (
                "2026-04-05T01:45",
                "Australia/Lord_Howe",
                "+11:00",
                "+10:30",
            ),
        ] {
            let resolved = zoned(local, tz, Disambiguation::Compatible).unwrap();
            assert_eq!(
                resolved.to_json(),
                json!({ "local": local, "tz": tz, "offset": earlier }),
                "{local} {tz}"
            );
            round_trips(&TimeValue::Zoned(resolved));
            let second =
                ZonedTime::resolve(local, tz, Some(later), Disambiguation::Reject).unwrap();
            round_trips(&TimeValue::Zoned(second));
            assert_eq!(
                TimeValue::Zoned(resolved).compare(&TimeValue::Zoned(second)),
                Ok(Ordering::Less)
            );
            assert_eq!(
                zoned(local, tz, Disambiguation::Reject),
                Err(TimeValueError::AmbiguousLocalTime {
                    local: local.into(),
                    tz: tz.into(),
                    earlier: earlier.into(),
                    later: later.into(),
                })
            );
        }
    }

    // -- Typed time facets (T2) ---------------------------------------------

    fn stored(facet_type: TimeFacetType, value: Value) -> Value {
        normalise_facet_value(facet_type, &value, Disambiguation::Compatible).unwrap()
    }

    fn ms(instant: &str) -> i64 {
        parse_instant(instant).unwrap().timestamp_millis()
    }

    #[test]
    fn facet_type_names_parse_and_display() {
        for name in TimeFacetType::NAMES {
            assert_eq!(TimeFacetType::parse(name).unwrap().as_str(), name);
        }
        assert_eq!(TimeFacetType::parse("datetime"), None);
        assert_eq!(TimeFacetType::parse("Date"), None);
    }

    #[test]
    fn durations_follow_rfc_5545() {
        let duration = |text: &str| EventDuration::parse(text).map(|d| (d.days, d.seconds));
        assert_eq!(duration("PT30M"), Ok((0, 1800)));
        assert_eq!(duration("PT1H30M"), Ok((0, 5400)));
        assert_eq!(duration("PT1H30M15S"), Ok((0, 5415)));
        assert_eq!(duration("PT0S"), Ok((0, 0)));
        assert_eq!(duration("P1D"), Ok((1, 0)));
        assert_eq!(duration("P1DT2H"), Ok((1, 7200)));
        assert_eq!(duration("P2W"), Ok((14, 0)));
        for bad in [
            "", "P", "PT", "1H", "-PT1H", "+PT1H", "P1DT", "PT1M1H", "PT1H1H", "P1W2D", "P1WT1H",
            "P1M", "P1Y", "PT1.5H", "pt1h", "P T1H", "PTH", "P1D1D",
        ] {
            assert!(
                matches!(
                    EventDuration::parse(bad),
                    Err(TimeValueError::InvalidDuration(_))
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            EventDuration::parse("P99999999D"),
            Err(TimeValueError::OutOfRange(_))
        ));
        // Multi-byte input is refused, never sliced mid-character.
        for bad in ["Pé", "PT1é", "P1💥", "PT💥", "é", "P1DTé"] {
            assert!(
                matches!(
                    EventDuration::parse(bad),
                    Err(TimeValueError::InvalidDuration(_))
                ),
                "{bad:?}"
            );
        }
    }

    /// Every other parser here slices only after an ASCII shape check or at
    /// an index just past an ASCII byte; pin that multi-byte input is refused
    /// rather than panicking.
    #[test]
    fn multi_byte_input_is_refused_by_every_parser() {
        for bad in [
            "é",
            "2026-10-0é",
            "2026-10-05T10:0é",
            "+0é:00",
            "é1:00",
            "+01:0💥",
            "💥",
        ] {
            assert!(parse_date(bad).is_err(), "{bad:?}");
            assert!(parse_instant(bad).is_err(), "{bad:?}");
            assert!(parse_local(bad).is_err(), "{bad:?}");
            assert!(parse_offset(bad).is_err(), "{bad:?}");
            assert!(parse_zone(bad).is_err(), "{bad:?}");
        }
        assert!(ZonedTime::resolve(
            "2026-10-05T10:00",
            "Europe/London",
            Some("+01:0é"),
            Disambiguation::Compatible
        )
        .is_err());
        assert!(project_facet_value(
            TimeFacetType::Zoned,
            &json!({ "local": "2026-10-05T10:0é", "tz": "Europe/London", "offset": "+0é:00" })
        )
        .is_err());
    }

    /// London's clocks go back at 02:00 BST on 2026-10-25, so 01:30 happens
    /// at +01:00 (00:30Z) and again at +00:00 (01:30Z). An elapsed duration
    /// runs from the occurrence the start resolved to, whichever policy
    /// resolved it; only nominal days re-resolve the wall time.
    #[test]
    fn elapsed_durations_keep_the_chosen_dst_occurrence() {
        let when = |start: Value, duration: &str, disambiguation| {
            normalise_facet_value(
                TimeFacetType::When,
                &json!({ "all_day": false, "start": start, "duration": duration }),
                disambiguation,
            )
        };
        let span = |stored: &Value| {
            let row = project_facet_value(TimeFacetType::When, stored).unwrap();
            (row.start_ms.unwrap(), row.end_ms.unwrap())
        };
        let earlier =
            json!({ "local": "2026-10-25T01:30", "tz": "Europe/London", "offset": "+01:00" });
        let later =
            json!({ "local": "2026-10-25T01:30", "tz": "Europe/London", "offset": "+00:00" });
        let unspecified = json!({ "local": "2026-10-25T01:30", "tz": "Europe/London" });
        for policy in [Disambiguation::Compatible, Disambiguation::Reject] {
            for (start, start_at) in [
                (&earlier, "2026-10-25T00:30:00Z"),
                (&later, "2026-10-25T01:30:00Z"),
            ] {
                for (duration, minutes) in [("PT1H", 60), ("PT30M", 30)] {
                    let stored = when(start.clone(), duration, policy)
                        .unwrap_or_else(|error| panic!("{start} {duration} {policy:?}: {error}"));
                    let (from, to) = span(&stored);
                    assert_eq!(from, ms(start_at), "{start} {duration} {policy:?}");
                    assert_eq!(to - from, minutes * 60_000, "{start} {duration} {policy:?}");
                    assert_eq!(stored["start"]["offset"], start["offset"]);
                }
            }
        }
        // The later occurrence plus an hour ends at 02:30 GMT on the wall.
        let stored = when(later.clone(), "PT1H", Disambiguation::Reject).unwrap();
        assert_eq!(stored["end"]["local"], json!("2026-10-25T02:30"));
        assert_eq!(stored["end"]["offset"], json!("+00:00"));
        // The earlier occurrence plus an hour is the later 01:30.
        let stored = when(earlier.clone(), "PT1H", Disambiguation::Compatible).unwrap();
        assert_eq!(
            stored["end"],
            json!({ "local": "2026-10-25T01:30", "tz": "Europe/London", "offset": "+00:00", "tzdb": TZDB_VERSION })
        );
        // With no offset, compatible picks the earlier occurrence and reject
        // refuses the start itself.
        let stored = when(unspecified.clone(), "PT30M", Disambiguation::Compatible).unwrap();
        assert_eq!(span(&stored).0, ms("2026-10-25T00:30:00Z"));
        assert!(matches!(
            when(unspecified, "PT30M", Disambiguation::Reject),
            Err(TimeValueError::AmbiguousLocalTime { .. })
        ));

        // A start in the spring gap: compatible moves 01:30 to 02:30 BST,
        // and elapsed time runs from there.
        let gap = json!({ "local": "2026-03-29T01:30", "tz": "Europe/London" });
        let stored = when(gap.clone(), "PT1H", Disambiguation::Compatible).unwrap();
        assert_eq!(stored["start"]["local"], json!("2026-03-29T02:30"));
        assert_eq!(stored["end"]["local"], json!("2026-03-29T03:30"));
        assert_eq!(
            span(&stored),
            (ms("2026-03-29T01:30:00Z"), ms("2026-03-29T02:30:00Z"))
        );
        assert!(matches!(
            when(gap, "PT1H", Disambiguation::Reject),
            Err(TimeValueError::SkippedLocalTime { .. })
        ));

        // Nominal days do re-resolve: a day after 01:30 on the 24th lands on
        // the ambiguous 01:30, the earlier one under compatible, refused under
        // reject.
        let day_before = json!({ "local": "2026-10-24T01:30", "tz": "Europe/London" });
        let stored = when(day_before.clone(), "P1D", Disambiguation::Compatible).unwrap();
        assert_eq!(stored["end"]["offset"], json!("+01:00"));
        assert!(matches!(
            when(day_before, "P1D", Disambiguation::Reject),
            Err(TimeValueError::AmbiguousLocalTime { .. })
        ));
    }

    #[test]
    fn scalar_facets_persist_normalised_and_zoned_records_the_tz_database() {
        assert_eq!(
            stored(TimeFacetType::Date, json!("2026-10-05")),
            json!("2026-10-05")
        );
        assert_eq!(
            stored(TimeFacetType::Instant, json!("2026-10-05T10:00:00+01:00")),
            json!("2026-10-05T09:00:00.000Z")
        );
        let zoned = stored(
            TimeFacetType::Zoned,
            json!({ "local": "2026-10-05T10:00", "tz": "Europe/London" }),
        );
        assert_eq!(
            zoned,
            json!({ "local": "2026-10-05T10:00", "tz": "Europe/London", "offset": "+01:00", "tzdb": TZDB_VERSION })
        );
        // The persisted form is accepted back unchanged, even when it names
        // another tz database version: the value is resolved again.
        assert_eq!(stored(TimeFacetType::Zoned, zoned.clone()), zoned);
        let mut older = zoned.clone();
        older["tzdb"] = json!("2019c");
        assert_eq!(stored(TimeFacetType::Zoned, older), zoned);
        assert!(normalise_facet_value(
            TimeFacetType::Zoned,
            &json!({ "local": "2026-10-05T10:00", "tz": "Europe/London", "tzdb": 2025 }),
            Disambiguation::Compatible
        )
        .is_err());
        for (facet_type, bad) in [
            (TimeFacetType::Date, json!("5 Oct 2026")),
            (TimeFacetType::Date, json!(20261005)),
            (TimeFacetType::Instant, json!("2026-10-05T10:00")),
            (TimeFacetType::Zoned, json!("2026-10-05T10:00")),
            (
                TimeFacetType::Zoned,
                json!({ "local": "2026-10-05T10:00", "tz": "Mars/Olympus" }),
            ),
        ] {
            assert!(
                normalise_facet_value(facet_type, &bad, Disambiguation::Compatible).is_err(),
                "{facet_type} {bad}"
            );
        }
    }

    #[test]
    fn scalar_facets_project_onto_the_timeline() {
        let date = project_facet_value(TimeFacetType::Date, &json!("2026-10-05")).unwrap();
        assert!(date.all_day);
        assert_eq!(date.start_date.as_deref(), Some("2026-10-05"));
        assert_eq!(date.end_date.as_deref(), Some("2026-10-06"));
        assert_eq!((date.start_ms, date.end_ms), (None, None));
        assert_eq!(
            normalise_facet_value(
                TimeFacetType::Date,
                &json!("9999-12-31"),
                Disambiguation::Compatible
            ),
            Err(TimeValueError::NoFollowingDay("9999-12-31".into()))
        );

        let instant =
            project_facet_value(TimeFacetType::Instant, &json!("2026-10-05T09:00:00.000Z"))
                .unwrap();
        assert!(!instant.all_day);
        assert_eq!(instant.start_ms, Some(ms("2026-10-05T09:00:00Z")));
        assert_eq!(instant.end_ms, instant.start_ms);
        assert_eq!((instant.tz, instant.tzdb_version), (None, None));

        let zoned = stored(
            TimeFacetType::Zoned,
            json!({ "local": "2026-10-25T01:30", "tz": "Europe/London" }),
        );
        let row = project_facet_value(TimeFacetType::Zoned, &zoned).unwrap();
        assert_eq!(
            row.start_ms,
            Some(ms("2026-10-25T00:30:00Z")),
            "overlap: earlier"
        );
        assert_eq!(row.tz.as_deref(), Some("Europe/London"));
        assert_eq!(row.tzdb_version.as_deref(), Some(TZDB_VERSION));
    }

    /// The projection reads the persisted offset, not the tz database, so a
    /// tz database upgrade never moves a row during replay.
    #[test]
    fn projection_trusts_the_persisted_offset() {
        let row = project_facet_value(
            TimeFacetType::Zoned,
            &json!({ "local": "2026-07-01T10:00", "tz": "Europe/London", "offset": "+00:00", "tzdb": "1999a" }),
        )
        .unwrap();
        assert_eq!(row.start_ms, Some(ms("2026-07-01T10:00:00Z")));
        assert_eq!(row.tzdb_version.as_deref(), Some("1999a"));
    }

    #[test]
    fn all_day_when_spans_floating_dates_with_an_exclusive_end() {
        let value = stored(
            TimeFacetType::When,
            json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-07" }),
        );
        assert_eq!(
            value,
            json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-07" })
        );
        let row = project_facet_value(TimeFacetType::When, &value).unwrap();
        assert!(row.all_day);
        assert_eq!(row.start_date.as_deref(), Some("2026-10-05"));
        assert_eq!(row.end_date.as_deref(), Some("2026-10-07"));
        assert_eq!((row.start_ms, row.end_ms, row.tz), (None, None, None));
        assert_eq!(
            stored(
                TimeFacetType::When,
                json!({ "all_day": true, "start": "2026-10-05", "duration": "P1W" }),
            ),
            json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-12" })
        );
        for (bad, expected) in [
            (
                json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-05" }),
                "must be after start",
            ),
            (
                json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-04" }),
                "cannot end before it starts",
            ),
            (
                json!({ "all_day": true, "start": "2026-10-05", "duration": "PT2H" }),
                "whole days or weeks",
            ),
            (
                json!({ "all_day": true, "start": "2026-10-05T10:00:00Z", "end": "2026-10-06" }),
                "not a date",
            ),
            (
                json!({ "all_day": true, "start": "2026-10-05", "end": "9999-12-31", "duration": "P1D" }),
                "not both",
            ),
        ] {
            let error =
                normalise_facet_value(TimeFacetType::When, &bad, Disambiguation::Compatible)
                    .unwrap_err()
                    .to_string();
            assert!(error.contains(expected), "{bad}: {error}");
        }
    }

    #[test]
    fn timed_when_accepts_instants_and_zones_and_resolves_durations() {
        let instant = stored(
            TimeFacetType::When,
            json!({ "all_day": false, "start": "2026-10-05T09:00:00Z", "duration": "PT30M" }),
        );
        assert_eq!(
            instant,
            json!({ "all_day": false, "start": "2026-10-05T09:00:00.000Z", "end": "2026-10-05T09:30:00.000Z" })
        );
        let row = project_facet_value(TimeFacetType::When, &instant).unwrap();
        assert!(!row.all_day);
        assert_eq!(row.start_ms, Some(ms("2026-10-05T09:00:00Z")));
        assert_eq!(row.end_ms, Some(ms("2026-10-05T09:30:00Z")));
        assert_eq!((row.start_date, row.end_date, row.tz), (None, None, None));

        // A flight: start and end in their own zones.
        let flight = stored(
            TimeFacetType::When,
            json!({
                "all_day": false,
                "start": { "local": "2026-10-05T10:00", "tz": "Europe/London" },
                "end": { "local": "2026-10-05T13:00", "tz": "America/New_York" },
            }),
        );
        let row = project_facet_value(TimeFacetType::When, &flight).unwrap();
        assert_eq!(row.end_ms.unwrap() - row.start_ms.unwrap(), 8 * 3_600_000);
        assert_eq!(row.tz.as_deref(), Some("Europe/London"));
        assert_eq!(row.tzdb_version.as_deref(), Some(TZDB_VERSION));
        assert_eq!(flight["end"]["tzdb"], json!(TZDB_VERSION));
        // A zero-length timed when is a point in time.
        stored(
            TimeFacetType::When,
            json!({ "all_day": false, "start": "2026-10-05T09:00:00Z", "end": "2026-10-05T09:00:00Z" }),
        );
    }

    /// London leaves summer time at 02:00 BST on 2026-10-25. A nominal day
    /// keeps the wall time, so it lasts 25 hours; 24 elapsed hours end an
    /// hour earlier on the wall clock.
    #[test]
    fn timed_when_durations_keep_the_wall_time_across_dst() {
        let start = json!({ "local": "2026-10-24T10:00", "tz": "Europe/London" });
        let day = stored(
            TimeFacetType::When,
            json!({ "all_day": false, "start": start, "duration": "P1D" }),
        );
        assert_eq!(day["end"]["local"], json!("2026-10-25T10:00"));
        assert_eq!(day["end"]["offset"], json!("+00:00"));
        let row = project_facet_value(TimeFacetType::When, &day).unwrap();
        assert_eq!(row.end_ms.unwrap() - row.start_ms.unwrap(), 25 * 3_600_000);

        let hours = stored(
            TimeFacetType::When,
            json!({ "all_day": false, "start": start, "duration": "PT24H" }),
        );
        assert_eq!(hours["end"]["local"], json!("2026-10-25T09:00"));
        let row = project_facet_value(TimeFacetType::When, &hours).unwrap();
        assert_eq!(row.end_ms.unwrap() - row.start_ms.unwrap(), 24 * 3_600_000);

        // An explicit end across the change: 01:30 happens twice, and the
        // compatible rule takes the earlier (BST) occurrence.
        let across = stored(
            TimeFacetType::When,
            json!({
                "all_day": false,
                "start": { "local": "2026-10-25T00:30", "tz": "Europe/London" },
                "end": { "local": "2026-10-25T02:30", "tz": "Europe/London" },
            }),
        );
        let row = project_facet_value(TimeFacetType::When, &across).unwrap();
        assert_eq!(row.start_ms, Some(ms("2026-10-24T23:30:00Z")));
        assert_eq!(row.end_ms, Some(ms("2026-10-25T02:30:00Z")));
        // Under reject, a start in the spring gap is refused.
        assert!(matches!(
            normalise_facet_value(
                TimeFacetType::When,
                &json!({
                    "all_day": false,
                    "start": { "local": "2026-03-29T01:30", "tz": "Europe/London" },
                    "duration": "PT1H",
                }),
                Disambiguation::Reject,
            ),
            Err(TimeValueError::SkippedLocalTime { .. })
        ));
    }

    #[test]
    fn timed_when_refuses_end_before_start_dates_and_recurrence() {
        assert_eq!(
            normalise_facet_value(
                TimeFacetType::When,
                &json!({
                    "all_day": false,
                    "start": { "local": "2026-10-05T10:00", "tz": "Europe/London" },
                    "end": "2026-10-05T08:59:59Z",
                }),
                Disambiguation::Compatible,
            ),
            Err(TimeValueError::EndBeforeStart {
                start: json!({ "local": "2026-10-05T10:00", "tz": "Europe/London", "offset": "+01:00" })
                    .to_string(),
                end: "2026-10-05T08:59:59.000Z".into(),
            })
        );
        for (bad, expected) in [
            (
                json!({ "all_day": false, "start": "2026-10-05", "end": "2026-10-06" }),
                "not the date 2026-10-05",
            ),
            (
                json!({ "start": "2026-10-05T09:00:00Z", "end": "2026-10-05T10:00:00Z" }),
                "needs all_day",
            ),
            (
                json!({ "all_day": "no", "start": "2026-10-05T09:00:00Z", "duration": "PT1H" }),
                "true or false",
            ),
            (
                json!({ "all_day": false, "start": "2026-10-05T09:00:00Z" }),
                "needs an end or a duration",
            ),
            (
                json!({ "all_day": false, "end": "2026-10-05T09:00:00Z" }),
                "needs a start",
            ),
            (
                json!({ "all_day": false, "start": "2026-10-05T09:00:00Z", "duration": 30 }),
                "not a duration",
            ),
            (
                json!({ "all_day": false, "start": "2026-10-05T09:00:00Z", "duration": "PT1H", "title": "x" }),
                "unknown member 'title'",
            ),
            (
                json!({ "all_day": false, "start": "2026-10-05T09:00:00Z", "duration": "PT1H", "rrule": "FREQ=WEEKLY" }),
                "recurrence",
            ),
            (
                json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-06", "exdate": ["2026-10-19"] }),
                "recurrence",
            ),
            (json!("2026-10-05"), "must be an object"),
        ] {
            let error =
                normalise_facet_value(TimeFacetType::When, &bad, Disambiguation::Compatible)
                    .unwrap_err()
                    .to_string();
            assert!(error.contains(expected), "{bad}: {error}");
        }
    }
}
