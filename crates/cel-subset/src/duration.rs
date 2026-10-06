use chrono::Duration;
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::character::complete::char;
use nom::combinator::map;
use nom::error::{Error, ErrorKind};
use nom::number::complete::recognize_float;
use nom::IResult;

// Constants representing time units in nanoseconds
const SECOND: u128 = 1_000_000_000;
const MILLISECOND: u128 = 1_000_000;
const MICROSECOND: u128 = 1_000;

/// Parses a duration string into a [`Duration`]. Duration strings support the
/// following grammar:
///
/// DurationString -> Sign? Number Unit String?
/// Sign           -> '-'
/// Number         -> Digit+ ('.' Digit+)?
/// Digit          -> '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9'
/// Unit           -> 'h' | 'm' | 's' | 'ms' | 'us' | 'µs' | 'ns'
/// String         -> DurationString
///
/// Decimal/exponent notation and signed components are accepted as by nom's
/// number grammar. Each component truncates toward zero at nanosecond precision.
/// The complete input must be valid; component and accumulated values must fit
/// chrono's full duration range. Parsing uses constant auxiliary space.
///
/// # Examples
/// - `1h` parses as 1 hour
/// - `1.5h` parses as 1 hour and 30 minutes
/// - `1h30m` parses as 1 hour and 30 minutes
/// - `1h30m1s` parses as 1 hour, 30 minutes, and 1 second
/// - `1ms` parses as 1 millisecond
/// - `1.5ms` parses as 1 millisecond and 500 microseconds
/// - `1ns` parses as 1 nanosecond
/// - `1.5ns` parses as 1 nanosecond (sub-nanosecond durations not supported)
pub fn parse_duration(i: &str) -> IResult<&str, Duration> {
    let (mut remaining, negative) = match i.strip_prefix('-') {
        Some(rest) => (rest, true),
        None => (i, false),
    };
    if remaining == "0" {
        return Ok(("", Duration::zero()));
    }
    if remaining.is_empty() {
        return Err(parse_error(ErrorKind::Digit));
    }
    let mut duration = Duration::zero();
    while !remaining.is_empty() {
        let (rest, number) =
            recognize_float::<_, Error<_>>(remaining).map_err(|_| parse_error(ErrorKind::Float))?;
        let (rest, unit) = parse_unit(rest).map_err(|_| parse_error(ErrorKind::Tag))?;
        let piece = to_duration(number, unit).ok_or_else(|| parse_error(ErrorKind::TooLarge))?;
        duration = duration
            .checked_add(&piece)
            .ok_or_else(|| parse_error(ErrorKind::TooLarge))?;
        remaining = rest;
    }
    if negative {
        duration = Duration::zero()
            .checked_sub(&duration)
            .ok_or_else(|| parse_error(ErrorKind::TooLarge))?;
    }
    Ok((remaining, duration))
}

// Keep the public nom signature, but never retain source text in errors. Both
// Display and Debug of the error are bounded independently of input length.
fn parse_error(kind: ErrorKind) -> nom::Err<Error<&'static str>> {
    nom::Err::Failure(Error::new("", kind))
}

enum Unit {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
    Minute,
    Hour,
}

impl Unit {
    // Nanoseconds per unit = multiplier * 10^power. Factoring this way lets
    // decimal multiplication carry across arbitrarily long fractional input
    // without a float, a growing coefficient, or an intermediate allocation.
    fn scale(&self) -> (u32, i128) {
        match self {
            Unit::Nanosecond => (1, 0),
            Unit::Microsecond => (1, 3),
            Unit::Millisecond => (1, 6),
            Unit::Second => (1, 9),
            Unit::Minute => (6, 10),
            Unit::Hour => (36, 11),
        }
    }
}

fn parse_unit(i: &str) -> IResult<&str, Unit> {
    alt((
        map(tag("ms"), |_| Unit::Millisecond),
        map(tag("us"), |_| Unit::Microsecond),
        map(tag("µs"), |_| Unit::Microsecond),
        map(tag("ns"), |_| Unit::Nanosecond),
        map(char('h'), |_| Unit::Hour),
        map(char('m'), |_| Unit::Minute),
        map(char('s'), |_| Unit::Second),
    ))(i)
}

fn to_duration(number: &str, unit: Unit) -> Option<Duration> {
    let negative = number.starts_with('-');
    let number = number.trim_start_matches(['-', '+']);
    let (mantissa, exponent) = match number.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => {
            // Only the magnitude of an extreme exponent matters. Saturation
            // here classifies it as tiny/huge; it never saturates the duration.
            let negative = exponent.starts_with('-');
            let magnitude =
                exponent
                    .trim_start_matches(['-', '+'])
                    .bytes()
                    .fold(0i128, |acc, digit| {
                        acc.saturating_mul(10)
                            .saturating_add((digit - b'0') as i128)
                    });
            (mantissa, if negative { -magnitude } else { magnitude })
        }
        None => (number, 0),
    };
    let fractional_digits = mantissa
        .split_once('.')
        .map_or(0, |(_, fraction)| fraction.len());
    let (multiplier, power) = unit.scale();
    let mut place = exponent
        .saturating_sub(fractional_digits as i128)
        .saturating_add(power);
    let mut carry = 0;
    let mut nanos = 0u128;
    for digit in mantissa.bytes().rev().filter(|digit| *digit != b'.') {
        let product = (digit - b'0') as u32 * multiplier + carry;
        add_decimal_digit(&mut nanos, product % 10, place)?;
        carry = product / 10;
        place = place.saturating_add(1);
    }
    while carry != 0 {
        add_decimal_digit(&mut nanos, carry % 10, place)?;
        carry /= 10;
        place = place.saturating_add(1);
    }
    let nanos = if negative {
        -(nanos as i128)
    } else {
        nanos as i128
    };
    // Euclidean splitting matches chrono's nonnegative stored nanoseconds,
    // including negative subsecond values. The full representable range is
    // +/- i64::MAX milliseconds, not merely +/- i64::MAX nanoseconds.
    Duration::new(
        i64::try_from(nanos.div_euclid(SECOND as i128)).ok()?,
        nanos.rem_euclid(SECOND as i128) as u32,
    )
}

fn add_decimal_digit(nanos: &mut u128, digit: u32, place: i128) -> Option<()> {
    const MAX_NANOS: u128 = i64::MAX as u128 * MILLISECOND;
    if digit == 0 || place < 0 {
        return Some(());
    }
    // MAX_NANOS has 25 digits, so higher nonzero places cannot be represented.
    if place > 24 {
        return None;
    }
    *nanos += digit as u128 * 10u128.pow(place as u32);
    (*nanos <= MAX_NANOS).then_some(())
}

/// Formats a [`Duration`] into a string. String returns a string representing the
/// duration in the form "72h3m0.5s". Leading zero units are omitted. As a special
/// case, durations less than one second format use a smaller unit (milli-, micro-,
/// or nanoseconds) to ensure that the leading digit is non-zero. The zero duration
/// formats as 0s.
///
/// This is a direct port of the Go version of the time.Duration(0).String() function.
pub fn format_duration(d: &Duration) -> String {
    // At most 13 hour digits (2_562_047_788_015h), two minute and second
    // digits each, nine fractional digits, three unit letters, a decimal
    // point and a sign: 13 + 2 + 2 + 9 + 3 + 1 + 1 = 31 bytes.
    // Subsecond output is at most 13 bytes, including the two-byte µ.
    let buf = &mut [0u8; 32];
    let mut w = buf.len();

    // num_seconds() and subsec_nanos() have the same sign and reconstruct
    // the exact duration. Its magnitude is <= i64::MAX * 1_000_000 nanos,
    // well inside u128. Never cast a signed duration directly to unsigned.
    let nanos = d.num_seconds() as i128 * SECOND as i128 + d.subsec_nanos() as i128;
    let neg = nanos < 0;
    let mut u = nanos.unsigned_abs();

    if u < SECOND {
        // Special case: if duration is smaller than a second,
        // use smaller units, like 1.2ms
        let mut _prec = 0;
        w -= 1;
        buf[w] = b's';
        w -= 1;

        if u == 0 {
            return "0s".to_string();
        } else if u < MICROSECOND {
            _prec = 0;
            buf[w] = b'n';
        } else if u < MILLISECOND {
            _prec = 3;
            // U+00B5 'µ' micro sign == 0xC2 0xB5
            buf[w] = 0xB5;
            w -= 1;
            buf[w] = 0xC2;
        } else {
            _prec = 6;
            buf[w] = b'm';
        }
        (w, u) = format_float(&mut buf[..w], u, _prec);
        w = format_int(&mut buf[..w], u);
    } else {
        w -= 1;
        buf[w] = b's';
        (w, u) = format_float(&mut buf[..w], u, 9);

        // u is now integer number of seconds
        w = format_int(&mut buf[..w], u % 60);
        u /= 60;

        // u is now integer number of minutes
        if u > 0 {
            w -= 1;
            buf[w] = b'm';
            w = format_int(&mut buf[..w], u % 60);
            u /= 60;

            // u is now integer number of hours
            if u > 0 {
                w -= 1;
                buf[w] = b'h';
                w = format_int(&mut buf[..w], u);
            }
        }
    }

    if neg {
        w -= 1;
        buf[w] = b'-';
    }
    String::from_utf8_lossy(&buf[w..]).into_owned()
}

fn format_float(buf: &mut [u8], mut v: u128, prec: usize) -> (usize, u128) {
    let mut w = buf.len();
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            w -= 1;
            buf[w] = digit as u8 + b'0';
        }
        v /= 10;
    }
    if print {
        w -= 1;
        buf[w] = b'.';
    }
    (w, v)
}

fn format_int(buf: &mut [u8], mut v: u128) -> usize {
    let mut w = buf.len();
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = (v % 10) as u8 + b'0';
            v /= 10;
        }
    }
    w
}

#[cfg(test)]
mod tests {
    use crate::duration::{format_duration, parse_duration};
    use chrono::Duration;

    fn assert_duration(input: &str, expected: Duration) {
        let (_, duration) = parse_duration(input).unwrap();
        assert_eq!(duration, expected, "{input}");
    }

    fn assert_print_duration(input: Duration, expected: &str) {
        let actual = format_duration(&input);
        assert_eq!(actual, expected, "{input}");
    }

    #[test]
    fn test_durations() {
        assert_duration("1s", Duration::seconds(1));
        assert_duration("-1s", Duration::seconds(-1));
        assert_duration("1.1s", Duration::seconds(1) + Duration::milliseconds(100));
        assert_duration("1.5m", Duration::minutes(1) + Duration::seconds(30));
        assert_duration("1m1s", Duration::minutes(1) + Duration::seconds(1));
        assert_duration(
            "1h1m1s",
            Duration::hours(1) + Duration::minutes(1) + Duration::seconds(1),
        );
        assert_duration("1ms", Duration::milliseconds(1));
        assert_duration("1us", Duration::microseconds(1));
        assert_duration("1ns", Duration::nanoseconds(1));
        assert_duration("1.1ns", Duration::nanoseconds(1));
        assert_duration(
            "1.123us",
            Duration::microseconds(1) + Duration::nanoseconds(123),
        );
        assert_duration("0s", Duration::zero());
        assert_duration("0h0m0s", Duration::zero());
        assert_duration("0h0m1s", Duration::seconds(1));
        assert_duration("0", Duration::zero());
        assert_duration("-0", Duration::zero());
    }

    #[test]
    fn test_format_durations() {
        assert_print_duration(Duration::zero(), "0s");
        assert_print_duration(Duration::nanoseconds(1), "1ns");
        assert_print_duration(Duration::nanoseconds(1100), "1.1µs");
        assert_print_duration(Duration::microseconds(2200), "2.2ms");
        assert_print_duration(Duration::milliseconds(3300), "3.3s");
        assert_print_duration(Duration::minutes(4) + Duration::seconds(5), "4m5s");
        assert_print_duration(
            Duration::minutes(4) + Duration::milliseconds(5001),
            "4m5.001s",
        );
        assert_print_duration(
            Duration::hours(5) + Duration::minutes(6) + Duration::milliseconds(7001),
            "5h6m7.001s",
        );
        assert_print_duration(
            Duration::minutes(8) + Duration::nanoseconds(1),
            "8m0.000000001s",
        );
        assert_print_duration(Duration::nanoseconds(i64::MAX), "2562047h47m16.854775807s");
        assert_print_duration(Duration::nanoseconds(i64::MIN), "-2562047h47m16.854775808s");
    }

    #[test]
    fn temporal_negative_and_decimal_parsing() {
        for (source, nanos) in [
            ("-1ns", -1),
            ("-1s", -1_000_000_000),
            ("-1.25s", -1_250_000_000),
            ("-0.999ns", 0),
            ("1.9ns1.9ns", 2),
            ("1e-9s", 1),
            (".5s", 500_000_000),
            ("+1.s", 1_000_000_000),
            ("1s-0.5s", 500_000_000),
            ("0.000000000019h", 68),
            ("0.000000000099999999999999999999m", 5),
            ("0.0000000001m", 6),
            ("1.123µs", 1123),
            ("9223372036854775807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
        ] {
            assert_duration(source, Duration::nanoseconds(nanos));
        }
        assert_print_duration(Duration::seconds(-1), "-1s");
        assert_print_duration(Duration::nanoseconds(-1), "-1ns");
        assert_print_duration(Duration::microseconds(-1), "-1µs");
        assert_print_duration(Duration::milliseconds(-1), "-1ms");
        assert_print_duration(Duration::milliseconds(-1250), "-1.25s");
    }

    #[test]
    fn temporal_full_range_roundtrip_and_format_bound() {
        assert_duration("9223372036854775807ms", Duration::MAX);
        assert_duration("-9223372036854775807ms", Duration::MIN);
        // Chrono's range is symmetric: checked global negation succeeds even
        // at MIN, and a representable negation cannot overflow.
        assert_duration("-0s-9223372036854775807ms", Duration::MAX);
        assert_duration("9223372036854775.807s", Duration::MAX);
        assert_duration("-9223372036854775.807s", Duration::MIN);
        assert_duration("1e12h", Duration::hours(1_000_000_000_000));
        assert_duration("9223372036854775807000000ns", Duration::MAX);
        assert_duration(
            "1h30m0.000000001s",
            Duration::seconds(5400) + Duration::nanoseconds(1),
        );
        for value in [
            Duration::MAX,
            Duration::MIN,
            Duration::MAX - Duration::nanoseconds(1),
            Duration::MIN + Duration::nanoseconds(1),
            Duration::nanoseconds(i64::MAX),
            Duration::nanoseconds(i64::MIN),
            Duration::microseconds(i64::MAX),
            Duration::microseconds(i64::MIN),
            Duration::seconds(1_000_000_000_000),
            Duration::seconds(-1_000_000_000_000),
            Duration::zero(),
        ] {
            let formatted = format_duration(&value);
            assert!(formatted.len() <= 31, "{formatted}");
            assert_eq!(parse_duration(&formatted), Ok(("", value)), "{formatted}");
        }
        // The 31-byte proof is tight for negative durations near the extremum.
        let worst = Duration::MIN + Duration::nanoseconds(1);
        assert_eq!(format_duration(&worst).len(), 31);
        assert_print_duration(Duration::MAX, "2562047788015h12m55.807s");
        assert_print_duration(Duration::MIN, "-2562047788015h12m55.807s");
        // Sweep deterministic values spanning all subsecond unit boundaries and
        // the entire chrono range. This also checks exact fractional roundtrips.
        for index in 0..2000i64 {
            let millis = i64::MAX / 2000 * index;
            for sign in [-1, 1] {
                let value = Duration::milliseconds(sign * millis)
                    + Duration::nanoseconds(sign * (index * 7919 % 1_000_000));
                let formatted = format_duration(&value);
                assert!(formatted.len() <= 31);
                assert_eq!(parse_duration(&formatted), Ok(("", value)), "{formatted}");
            }
            let value = Duration::nanoseconds(index * 499_999 - 499_999_000);
            let formatted = format_duration(&value);
            assert_eq!(parse_duration(&formatted), Ok(("", value)), "{formatted}");
        }
    }

    #[test]
    fn temporal_parse_extremes_and_bounded_errors() {
        for source in [
            "",
            "-",
            "1",
            "1s garbage",
            "1sx",
            "1e+s",
            "NaNs",
            "infs",
            "1e99h",
            "-1e99h",
            "9223372036854775808ms",
            "-9223372036854775808ms",
            "9223372036854775807000001ns",
            "9223372036854775807ms1ns",
            "-9223372036854775807ms1ns",
            "0s-9223372036854775807ms-1ns",
            "-0s-9223372036854775807ms-1ns",
        ] {
            let error = parse_duration(source).unwrap_err();
            assert!(format!("{error:?}").len() < 100);
            assert!(error.to_string().len() < 100);
        }
        let large = "1e99h".repeat(1000);
        assert_eq!(large.len(), 5000);
        let error = parse_duration(&large).unwrap_err();
        assert!(!format!("{error:?}").contains("1e99h"));
        assert!(format!("{error:?}").len() < 100);
        let suffix = format!("1s{}", "x".repeat(5000));
        assert!(format!("{:?}", parse_duration(&suffix).unwrap_err()).len() < 100);
        let exponent = "9".repeat(5000);
        assert!(parse_duration(&format!("1e{exponent}h")).is_err());
        assert_duration(&format!("1e-{exponent}h"), Duration::zero());
        assert_duration(&format!("0e{exponent}h"), Duration::zero());
        // Long coefficients can be legitimate; do not impose a digit cap.
        assert_duration(
            &format!("1{}e-5000s", "0".repeat(5000)),
            Duration::seconds(1),
        );
        assert_duration(
            &format!("0.{}1e5001s", "0".repeat(5000)),
            Duration::seconds(1),
        );
        assert_duration(&"1ns".repeat(2000), Duration::nanoseconds(2000));
        assert_eq!(parse_duration("0"), Ok(("", Duration::zero())));
        assert_eq!(parse_duration("-0"), Ok(("", Duration::zero())));
    }
}
