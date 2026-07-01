//! Parser for conversions.
//! General structure:
//! ```text
//! date := YYYY-MM-DD
//! time := ((x:yy|xx:yy)(am|pm)?)|((x|xx)(am|pm))
//! pos_num allows commas, treats '.' as decimal
//! value := (time|date " " time|time " " date|pos_num)
//! i := (value " "? unit: (u8, u8)|unit " "? value)
//! conversion := i  " in " unit
//! ```

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::tag,
    character::{digit1, one_of},
    combinator::{complete, opt},
    multi::separated_list1,
};

use crate::conversions::{Date, Time, Value};

fn is_ascii_num(c: u8) -> bool {
    c >= ('0' as u8) && c <= ('9' as u8)
}

/// Parse ISO-date-order date YYYY-M(M?)-D(D?) where separator can be in " -_/"
fn parse_date(v: &str) -> IResult<&str, Date> {
    let (rem, (y_str, _, m_str, _, d_str)) = (
        digit1().map_res(|s: &str| if s.len() == 4 { Ok(s) } else { Err(()) }),
        one_of(" -_/"),
        digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) }),
        one_of(" -_/"),
        digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) }),
    )
        .parse_complete(v)?;

    Ok((
        rem,
        Date {
            y: y_str
                .parse()
                .expect("Already know it's just integers, must parse"),
            m: m_str
                .parse()
                .expect("Already know it's just integers, must parse"),
            d: d_str
                .parse()
                .expect("Already know it's just integers, must parse"),
        },
    ))
}

#[test]
fn test_parse_date() {
    let assert_eq_d = |str, d: (u16, u8, u8)| assert_eq!(parse_date(str), Ok(("", d.into())));

    assert_eq_d("2026-01-01", (2026, 1, 1));
    assert_eq_d("2026-1-01", (2026, 1, 1));
    assert_eq_d("2026 12/13", (2026, 12, 13));
    assert_eq_d("2026_10_10", (2026, 10, 10));
    // TODO need to figure out how to handle this
    assert_eq_d("2026 25 25", (2026, 25, 25));

    assert!(parse_date("December 2026").is_err());
}

fn parse_time(v: &str) -> IResult<&str, Time> {
    let (rem, h_str) = (digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) }))
        .parse_complete(v)?;

    let h: u8 = h_str
        .parse()
        .expect("Already know it's just integers, must parse");

    let m_match: IResult<&str, _> = (
        tag(":"),
        digit1().map_res(|s: &str| if s.len() == 2 { Ok(s) } else { Err(()) }),
        opt(complete((
            opt(tag(" ")),
            alt((tag("am"), tag("pm"), tag("AM"), tag("PM"))),
        ))),
    )
        .parse_complete(rem);
    let (rem, m, am_pm) = match m_match {
        Ok((rem, (_, m_str, am_pm))) => {
            // We got the full minute afterwards
            let m: u8 = m_str
                .parse()
                .expect("Already know it's just integers, must parse");
            (rem, m, am_pm.map(|(_, am_pm)| am_pm))
        }
        Err(_) => {
            // OK, try the no_minute parser
            let (rem, (_, am_pm)) = (
                opt(tag(" ")),
                alt((tag("am"), tag("pm"), tag("AM"), tag("PM"))),
            )
                .parse_complete(rem)?;
            (rem, 0, Some(am_pm))
        }
    };

    let h = match am_pm {
        // If we're in the AM, everything is parsed as normal, unless h = 12.
        // 11:59AM = 1159, 12:00AM = 0000
        // If someone types in 14:00AM, treat it as 1400
        Some("am") | Some("AM") => {
            if h == 12 {
                0
            } else {
                h
            }
        }
        // If we're in the PM, and the hour is before noon, shift it forward
        // e.g. 11PM = 2300, 11:59PM = 2359, 12:00PM = noon
        Some("pm") | Some("PM") => {
            if h < 12 {
                h + 12
            } else {
                h
            }
        }
        None => h,
        _ => unreachable!(),
    };

    Ok((rem, Time { h, m }))
}

#[test]
fn test_parse_time() {
    let assert_eq_t = |str, t: (u8, u8)| assert_eq!(parse_time(str), Ok(("", t.into())));

    // Plain hours without AM/PM should fail
    assert!(parse_time("05").is_err());
    assert!(parse_time("5").is_err());

    // Test plain hours in the AM
    assert_eq_t("05am", (5, 00));
    assert_eq_t("5am", (5, 00));
    assert_eq_t("05 am", (5, 00));
    assert_eq_t("5 am", (5, 00));

    // Test plain hours in the PM
    assert_eq_t("05pm", (17, 00));
    assert_eq_t("5pm", (17, 00));
    assert_eq_t("05 pm", (17, 00));
    assert_eq_t("5 pm", (17, 00));

    // AM plain hour wrapping - 12am = midnight, past that is wrong and just take 13
    assert_eq_t("10am", (10, 00));
    assert_eq_t("11am", (11, 00));
    assert_eq_t("12am", (0, 00));
    assert_eq_t("13am", (13, 00)); // Degenerate case

    // PM plain hour wrapping - 12pm = midday, past that is wrong and just take 13
    assert_eq_t("10pm", (22, 00));
    assert_eq_t("11pm", (23, 00));
    assert_eq_t("12pm", (12, 00));
    assert_eq_t("13pm", (13, 00)); // Degenerate case

    // Hour-minute pairs work without AM/PM
    assert_eq_t("05:38", (5, 38));
    assert_eq_t("5:38", (5, 38));
    assert_eq_t("17:38", (17, 38));

    // Test hour-minute pairs in the AM
    assert_eq_t("05:38am", (5, 38));
    assert_eq_t("5:38am", (5, 38));
    assert_eq_t("17:38am", (17, 38)); // Degenerate case
    assert_eq_t("05:38 am", (5, 38));
    assert_eq_t("5:38 am", (5, 38));
    assert_eq_t("17:38 am", (17, 38)); // Degenerate case

    // Test hour-minute pairs in the PM
    assert_eq_t("05:38pm", (17, 38));
    assert_eq_t("5:38pm", (17, 38));
    assert_eq_t("17:38pm", (17, 38)); // Degenerate case
    assert_eq_t("05:38 pm", (17, 38));
    assert_eq_t("5:38 pm", (17, 38));
    assert_eq_t("17:38 pm", (17, 38)); // Degenerate case

    // AM hour-minute wrapping - 12am = midnight, hours beyond that are wrong and just take 13
    assert_eq_t("11:58am", (11, 58));
    assert_eq_t("11:59am", (11, 59));
    assert_eq_t("12:00am", (0, 00));
    assert_eq_t("12:01am", (0, 1));
    assert_eq_t("12:59am", (0, 59));
    assert_eq_t("13:00am", (13, 00)); // Degenerate case

    // PM plain hour wrapping - 12pm = midday, past that is wrong and just take 13
    assert_eq_t("11:58pm", (23, 58));
    assert_eq_t("11:59pm", (23, 59));
    assert_eq_t("12:00pm", (12, 00));
    assert_eq_t("12:01pm", (12, 1));
    assert_eq_t("12:59pm", (12, 59));
    assert_eq_t("13:00pm", (13, 00)); // Degenerate case

    // TODO need to figure out how to handle this
    assert_eq_t("26:39", (26, 39));

    // Just a number on its own is wrong
    assert!(parse_time("1").is_err());
    // Minutes must be two-digit
    assert!(parse_time("1:1").is_err());
    // Just text doesn't work, by design, too much ambiguity
    assert!(parse_time("One o'clock").is_err());
}

fn parse_pos_num(v: &str) -> IResult<&str, f64> {
    let (rem, digit_seq) = separated_list1(one_of(" ,_"), digit1()).parse_complete(v)?;
    let n: u64 = digit_seq.into_iter().fold(0, |mut n, s: &str| {
        for i in 0..s.len() {
            n *= 10;
        }
        // TODO handle these errors if exceeds u64
        n + s.parse::<u64>().unwrap()
    });

    let mut f: f64 = n as f64;
    let (rem, opt_decimal) =
        opt((tag("."), separated_list1(one_of(" ,_"), digit1()))).parse_complete(rem)?;
    if let Some((_, digit_seq)) = opt_decimal {
        let (n_decimal, n_max) =
            digit_seq
                .into_iter()
                .fold((0u64, 1u64), |(mut n_decimal, mut n_max), s: &str| {
                    for i in 0..s.len() {
                        n_decimal *= 10;
                        n_max *= 10;
                    }
                    // TODO handle these errors if exceeds u64
                    (n_decimal + s.parse::<u64>().unwrap(), n_max)
                });
        let f_decimal = n_decimal as f64;
        let f_max = n_max as f64;
        let decimal = f_decimal / f_max;
        f += decimal;
    }

    // TODO exponent-numbers

    Ok((rem, f))
}

#[test]
fn test_parse_pos_num() {
    let assert_eq_f = |str, f| assert_eq!(parse_pos_num(str), Ok(("", f)));

    assert_eq_f("1000005", 1000005.0);
    assert_eq_f("10,00,00,5", 1000005.0);
    assert_eq_f("1,000,005", 1000005.0);
    assert_eq_f("1_000_005", 1000005.0);
    assert_eq_f("1_000 005", 1000005.0);
    assert_eq_f("5", 5.0);

    assert_eq_f("5.4321", 5.4321);
    assert_eq_f("1_000_005.4321", 1000005.4321);

    // TODO this will break if the suffix exceeds u64, in general I haven't tested on big numbers
    // assert_eq_f("1_000_005.4321237846239843297923874293498327498237", 1000005.4321);

    // Hex and binary don't work - this is sad,
    assert_eq!(parse_pos_num("0xabCDeF12").unwrap(), ("xabCDeF12", 0.0));
    assert_eq!(parse_pos_num("0b111011").unwrap(), ("b111011", 0.0));
    // Just text doesn't work, by design, too much ambiguity
    assert!(parse_pos_num("One point 2").is_err());
}

fn parse_value<'a>(v: &'a str) -> IResult<&'a str, Value> {
    let val_time_date = |v| {
        let (rem, (date, _, time)) = ((parse_date, tag(" "), parse_time)).parse_complete(v)?;

        Ok((rem, Value::Time(time, Some(date))))
    };
    let val_date_time = |v| {
        let (rem, (time, _, date)) = ((parse_time, tag(" "), parse_date)).parse_complete(v)?;

        Ok((rem, Value::Time(time, Some(date))))
    };
    let val_time = |v| {
        let (rem, time) = parse_time.parse_complete(v)?;

        Ok((rem, Value::Time(time, None)))
    };
    let val_pos_num = |v| {
        let (rem, f) = parse_pos_num.parse_complete(v)?;

        Ok((rem, Value::Number(f)))
    };

    alt((val_time_date, val_date_time, val_time, val_pos_num)).parse_complete(v)
}

#[test]
fn test_parse_value() {
    let assert_eq_t =
        |str, t: (u8, u8)| assert_eq!(parse_value(str), Ok(("", Value::Time(t.into(), None))));
    let assert_eq_dt = |str, d: (u16, u8, u8), t: (u8, u8)| {
        assert_eq!(
            parse_value(str),
            Ok(("", Value::Time(t.into(), Some(d.into()))))
        )
    };
    let assert_eq_f = |str, f| assert_eq!(parse_value(str), Ok(("", Value::Number(f))));

    // Date-then-time
    {
        assert_eq_dt("2026-01-01 12:59am", (2026, 1, 1), (00, 59));
        assert_eq_dt("2026-1-01 12:59am", (2026, 1, 1), (00, 59));
        assert_eq_dt("2026 12/13 12:59am", (2026, 12, 13), (00, 59));
        assert_eq_dt("2026_10_10 12:59am", (2026, 10, 10), (00, 59));
        // TODO need to figure out how to handle this
        assert_eq_dt("2026 25 25 99:70am", (2026, 25, 25), (99, 70));
        // If someone forgets one of the parts, what happens?
        assert_eq!(
            parse_value("2026 25 99:70am"),
            Ok((":70am", Value::Number(20262599.0)))
        );
    }

    // Time-then-date
    {
        assert_eq_dt("12:59am 2026-01-01", (2026, 1, 1), (00, 59));
        assert_eq_dt("12:59am 2026-1-01", (2026, 1, 1), (00, 59));
        assert_eq_dt("12:59am 2026 12/13", (2026, 12, 13), (00, 59));
        assert_eq_dt("12:59am 2026_10_10", (2026, 10, 10), (00, 59));
        // TODO need to figure out how to handle this
        assert_eq_dt("99:70am 2026 25 25", (2026, 25, 25), (99, 70));
        // If someone forgets one of the parts, what happens?
        assert_eq!(
            parse_value("99:70am 2026 25"),
            Ok((" 2026 25", Value::Time((99, 70).into(), None)))
        );
    }

    // Time
    {
        // Plain hours without AM/PM should become numbers
        assert_eq_f("05", 5.0);
        assert_eq_f("5", 5.0);

        // Test plain hours in the AM
        assert_eq_t("05am", (5, 00));
        assert_eq_t("5am", (5, 00));
        assert_eq_t("05 am", (5, 00));
        assert_eq_t("5 am", (5, 00));

        // Test plain hours in the PM
        assert_eq_t("05pm", (17, 00));
        assert_eq_t("5pm", (17, 00));
        assert_eq_t("05 pm", (17, 00));
        assert_eq_t("5 pm", (17, 00));

        // AM plain hour wrapping - 12am = midnight, past that is wrong and just take 13
        assert_eq_t("10am", (10, 00));
        assert_eq_t("11am", (11, 00));
        assert_eq_t("12am", (0, 00));
        assert_eq_t("13am", (13, 00)); // Degenerate case

        // PM plain hour wrapping - 12pm = midday, past that is wrong and just take 13
        assert_eq_t("10pm", (22, 00));
        assert_eq_t("11pm", (23, 00));
        assert_eq_t("12pm", (12, 00));
        assert_eq_t("13pm", (13, 00)); // Degenerate case

        // Hour-minute pairs work without AM/PM
        assert_eq_t("05:38", (5, 38));
        assert_eq_t("5:38", (5, 38));
        assert_eq_t("17:38", (17, 38));

        // Test hour-minute pairs in the AM
        assert_eq_t("05:38am", (5, 38));
        assert_eq_t("5:38am", (5, 38));
        assert_eq_t("17:38am", (17, 38)); // Degenerate case
        assert_eq_t("05:38 am", (5, 38));
        assert_eq_t("5:38 am", (5, 38));
        assert_eq_t("17:38 am", (17, 38)); // Degenerate case

        // Test hour-minute pairs in the PM
        assert_eq_t("05:38pm", (17, 38));
        assert_eq_t("5:38pm", (17, 38));
        assert_eq_t("17:38pm", (17, 38)); // Degenerate case
        assert_eq_t("05:38 pm", (17, 38));
        assert_eq_t("5:38 pm", (17, 38));
        assert_eq_t("17:38 pm", (17, 38)); // Degenerate case

        // AM hour-minute wrapping - 12am = midnight, hours beyond that are wrong and just take 13
        assert_eq_t("11:58am", (11, 58));
        assert_eq_t("11:59am", (11, 59));
        assert_eq_t("12:00am", (0, 00));
        assert_eq_t("12:01am", (0, 1));
        assert_eq_t("12:59am", (0, 59));
        assert_eq_t("13:00am", (13, 00)); // Degenerate case

        // PM plain hour wrapping - 12pm = midday, past that is wrong and just take 13
        assert_eq_t("11:58pm", (23, 58));
        assert_eq_t("11:59pm", (23, 59));
        assert_eq_t("12:00pm", (12, 00));
        assert_eq_t("12:01pm", (12, 1));
        assert_eq_t("12:59pm", (12, 59));
        assert_eq_t("13:00pm", (13, 00)); // Degenerate case

        // TODO need to figure out how to handle this
        assert_eq_t("26:39", (26, 39));

        // Minutes must be two-digit, otherwise they are parsed as values
        assert_eq!(parse_value("1:1"), Ok((":1", Value::Number(1.0))));
        // Just text doesn't work, by design, too much ambiguity
        assert!(parse_value("One o'clock").is_err());
    }

    // Number
    {
        assert_eq_f("1000005", 1000005.0);
        assert_eq_f("10,00,00,5", 1000005.0);
        assert_eq_f("1,000,005", 1000005.0);
        assert_eq_f("1_000_005", 1000005.0);
        assert_eq_f("1_000 005", 1000005.0);
        assert_eq_f("5", 5.0);

        assert_eq_f("5.4321", 5.4321);
        assert_eq_f("1_000_005.4321", 1000005.4321);

        // Hex and binary don't work - this is sad,
        assert_eq!(
            parse_value("0xabCDeF12"),
            Ok(("xabCDeF12", Value::Number(0.0))),
        );
        assert_eq!(parse_value("0b111011"), Ok(("b111011", Value::Number(0.0))));
        // Just text doesn't work, by design, too much ambiguity
        assert!(parse_value("One point 2").is_err());
    }

    // Dates on their own aren't parsed as dates, they're parsed as numbers and the rest is left off
    assert_eq!(
        parse_value("2026-01-01"),
        Ok(("-01-01", Value::Number(2026.0))),
    );
    // Not a valid date anyway
    assert!(parse_value("December 2026").is_err());
}

fn parse_i<'a>(i: &'a str) -> Result<(Value, &'a str), String> {
    // We assume that units contain NO numbers, and values ALWAYS start with a number.
    // Therefore we can assume that only place a value could start is the first number of the string.
    // The way UTF-8 works, we can also assume that this is the first *byte* which matches the ASCII num pattern.
    let first_value_byte = i
        .as_bytes()
        .iter()
        .position(|c| is_ascii_num(*c))
        .ok_or_else(|| format!("input string '{}' has no numbers", i))?;

    if first_value_byte == 0 {
        let (unit_str, value) =
            parse_value(i).map_err(|e| format!("input string '{i}' failed value parsing {e}"))?;

        Ok((value, unit_str))
    } else {
        let (unit_str, value_str) = i.split_at(first_value_byte);
        let (remaining_str, value) = parse_value(value_str)
            .map_err(|e| format!("input substring '{value_str}' failed value parsing {e}"))?;
        if !remaining_str.is_empty() {
            return Err(format!(
                "Parsed unit '{}' then value {:?} '{}' and had '{}' left over",
                unit_str, value, value_str, remaining_str
            ))?;
        }

        Ok((value, unit_str))
    }
}

pub fn parse_conversion(query: &str) -> Option<(Value, &str, &str)> {
    let query = query.trim();
    let (i, o) = query.split_once(" in ")?;
    let i = i.trim();
    let o = o.trim();

    // TODO early out if no numbers in the string at all, to avoid logspam from near-miss?

    let (i_val, i_unit) = {
        match parse_i(i) {
            Ok((i_val, i_unit)) => (i_val, i_unit),
            Err(e) => {
                log::debug!("Near miss parsing conversion: {}", e);
                return None;
            }
        }
    };

    let o_unit = {
        if o.is_empty() {
            return None;
        }
        o
    };

    Some((i_val, i_unit, o_unit))
}
