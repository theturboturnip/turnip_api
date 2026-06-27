use nom::{
    IResult, Parser,
    branch::alt,
    bytes::tag,
    character::{digit1, one_of},
    combinator::{map_res, opt},
    multi::separated_list1,
    sequence::tuple,
};

use crate::conversions::{Date, Time, Value};

fn is_ascii_num(c: u8) -> bool {
    c >= ('0' as u8) && c <= ('9' as u8)
}

fn parse_date(v: &str) -> IResult<&str, Date> {
    let (rem, (y_str, _, m_str, _, d_str)) = (
        digit1().map_res(|s: &str| if s.len() == 4 { Ok(s) } else { Err(()) }),
        one_of(" -_/"),
        digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) }),
        one_of(" -_/"),
        digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) }),
    )
        .parse(v)?;

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
fn parse_time(v: &str) -> IResult<&str, Time> {
    let (rem, h_str) =
        (digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) })).parse(v)?;

    let h: u8 = h_str
        .parse()
        .expect("Already know it's just integers, must parse");

    let m_match: IResult<&str, _> = (
        tag(":"),
        digit1().map_res(|s: &str| if s.len() <= 2 { Ok(s) } else { Err(()) }),
        opt(alt((tag("am"), tag("pm"), tag("AM"), tag("PM")))),
    )
        .parse(rem);
    let (rem, m, am_pm) = match m_match {
        Ok((rem, (_, m_str, am_pm))) => {
            // We got the full minute afterwards
            let m: u8 = m_str
                .parse()
                .expect("Already know it's just integers, must parse");
            (rem, m, am_pm)
        }
        Err(_) => {
            // OK, try the no_minute parser
            let (rem, am_pm) = alt((tag("am"), tag("pm"), tag("AM"), tag("PM"))).parse(rem)?;
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
            if h < 12 || (h == 12 && m == 0) {
                h + 12
            } else {
                h
            }
        }
        _ => unreachable!(),
    };

    Ok((rem, Time { h, m }))
}

fn parse_value<'a>(v: &'a str) -> IResult<&'a str, Value> {
    let val_time_date = |v| {
        let (rem, (date, _, time)) = ((parse_date, tag(" "), parse_time)).parse(v)?;

        Ok((rem, Value::Time(time, Some(date))))
    };
    let val_date_time = |v| {
        let (rem, (time, _, date)) = ((parse_time, tag(" "), parse_date)).parse(v)?;

        Ok((rem, Value::Time(time, Some(date))))
    };
    let val_time = |v| {
        let (rem, time) = parse_time.parse(v)?;

        Ok((rem, Value::Time(time, None)))
    };
    let val_pos_num = |v| {
        let (rem, digit_seq) = separated_list1(one_of(" ,_"), digit1()).parse(v)?;
        let n: u64 = digit_seq.into_iter().fold(0, |mut n, s: &str| {
            for i in 0..s.len() {
                n *= 10;
            }
            n + s.parse::<u64>().unwrap()
        });

        let mut f: f64 = n as f64;
        let (rem, opt_decimal) =
            opt((tag("."), separated_list1(one_of(" ,_"), digit1()))).parse(rem)?;
        if let Some((_, digit_seq)) = opt_decimal {
            let (n_decimal, n_max) =
                digit_seq
                    .into_iter()
                    .fold((0, 0), |(mut n_decimal, mut n_max), s: &str| {
                        for i in 0..s.len() {
                            n_decimal *= 10;
                            n_max *= 10;
                        }
                        (n_decimal + s.parse::<u64>().unwrap(), n_max)
                    });
            let f_decimal = n_decimal as f64;
            let f_max = n_max as f64;
            let decimal = f_decimal / f_max;
            f += decimal;
        }

        // TODO exponent-numbers

        Ok((rem, Value::Number(f)))
    };

    alt((val_time_date, val_date_time, val_time, val_pos_num)).parse(v)
}

// General structure:
// date := YYYY-MM-DD
// time := ((x:yy|xx:yy)(am|pm)?)|((x|xx)(am|pm))
// pos_num allows commas, treats '.' as decimal
// value := (time|date " " time|time " " date|pos_num)
// i := (value " "? unit|unit " "? value)
// conversion := i  " in " unit
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
