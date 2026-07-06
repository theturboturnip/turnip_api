//! Converts between timezones.
//!
//! timezones are parsed from the international TZ database via jiff.
//! https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
//!
//! Conversion is done as follows:
//! for the given input and output strings, find all related complex timezones.
//! This is precomputed at start-of-day:
//! - complex TZ names e.g. "US/Eastern" translate directly
//! - prefix/suffixes e.g. "US", "Eastern" translate to all complex TZs with that prefix/suffix e.g. ["US/Eastern", "US/Central"] and ["US/Eastern, "Canada/Eastern"]
//! - abbreviations e.g. "GMT", "EST" translate to all complex TZs that use them e.g. "Etc/GMT, GMT", "America/Indiana/Indianapolis"
//!
//! TODO use user location to prioritize which complex TZ is most important i.e. theirs?
//! then, compute the cartesian product of conversions between the candidate input/outputs.
//! (this technique means that if you specify EST, which maps to a bunch of US complex timezones, and all of then are actually using E*D*T on the date specified, only EDT will be returned. This is a feature! Either you specified a day where EDT was used, or you didn't specify a date and we assumed today/tomorrow (whichever puts the time in the future). If you actually *meant* the conversion for a specific date, you have to enter the date too. )
//!

use arrayvec::ArrayVec;
use fnv::FnvHashMap;
use smol_str::{SmolStr, StrExt, ToSmolStr};
use std::fmt::Write;
use turnip_api::util::{DebugError, IgnoreError};

use super::{
    Conversion,
    parser::{Date, Time, TimeRender},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NamedOffset {
    abbrev: SmolStr,
    offset_s: i32,
}
impl From<&jiff::Zoned> for NamedOffset {
    fn from(value: &jiff::Zoned) -> Self {
        let info = value.time_zone().to_offset_info(value.timestamp());
        Self {
            abbrev: info.abbreviation().to_smolstr(),
            offset_s: info.offset().seconds(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InternalConversion {
    in_dt: jiff::Zoned,
    in_z: NamedOffset,
    out_dt: jiff::Zoned,
    out_z: NamedOffset,
    date_relevant: bool,
}
impl InternalConversion {
    fn new(i: jiff::Zoned, o: jiff::Zoned, date_relevant: bool) -> Self {
        Self {
            in_z: (&i).into(),
            in_dt: i,
            out_z: (&o).into(),
            out_dt: o,
            date_relevant,
        }
    }
}

struct ComplexTz(SmolStr);
impl ComplexTz {
    fn of(dt: &jiff::Zoned) -> Self {
        Self(
            dt.time_zone()
                .iana_name()
                .expect("The only tzs that TimeCtx reasons about are those with iana_name")
                .to_smolstr(),
        )
    }
}

pub struct TimeCtx {
    candidate_tzs: FnvHashMap<SmolStr, Vec<jiff::tz::TimeZone>>,
}
impl TimeCtx {
    pub fn new() -> Self {
        let db = jiff::tz::db();

        let mut candidate_tzs = FnvHashMap::default();

        let complex_tzs = db
            .available()
            .filter_map(|name| {
                // Ignore the dedicated EST timezone abbrev
                if name.as_str() == "EST" {
                    return None;
                }
                let tz = db
                    .get(name.as_str())
                    .expect("The db said this is available, it must be so");
                if tz.iana_name().is_none() {
                    log::error!("Complex time-zone '{}' {:?} was referenced by the database but somehow doesn't have IANA identifier?", name, tz);
                    return None;
                }
                Some((name.as_str().to_ascii_lowercase_smolstr(), tz))
            })
            .collect::<Vec<_>>();
        for (name, tz) in complex_tzs.iter() {
            candidate_tzs
                .entry(name.clone())
                .or_insert_with(|| vec![])
                .push(tz.clone());
        }

        let now = jiff::Timestamp::now();
        // Allow suffixes to translate to relevant timezones
        // e.g. "Eastern" => Canada/Eastern and US/Eastern
        // Also translate suffixes to be typable
        // e.g. "El Aaiun" => Africa/El_Aaiun
        // Also allow prefixes to be used
        // e.g. "US" => "US/Eastern", "US/Pacific", etc.
        // Also allow abbreviations
        // e.g. EST -> US/Eastern, EDT -> US/Eastern
        complex_tzs
            .iter()
            .map(|(name, tz)| {
                if let Some((prefix, suffix)) = name.split_once("/") {
                    candidate_tzs
                        .entry(prefix.to_smolstr())
                        .or_insert_with(|| vec![])
                        .push(tz.clone());
                    candidate_tzs
                        .entry(suffix.to_smolstr())
                        .or_insert_with(|| vec![])
                        .push(tz.clone());
                    if suffix.contains("_") {
                        let suffix = suffix.replace_smolstr("_", " ");
                        candidate_tzs
                            .entry(suffix.to_smolstr())
                            .or_insert_with(|| vec![])
                            .push(tz.clone());
                    }
                }

                // For each unique TZ of the 5 transitions following now,
                // add this timezone to their options
                tz.following(now)
                    .take(5)
                    .map(|t| t.abbreviation().to_lowercase_smolstr())
                    .fold(ArrayVec::<_, 5>::new(), |mut v, t| {
                        if !v.contains(&t) {
                            v.push(t.clone());

                            candidate_tzs
                                .entry(t)
                                .or_insert_with(|| vec![])
                                .push(tz.clone());
                        }
                        v
                    });
            })
            .last();

        // TODO sort timezones in the vectors by importance?

        Self { candidate_tzs }
    }

    fn single_conversion(
        &self,
        input_time: jiff::civil::Time,
        input_date: Option<jiff::civil::Date>,
        now: jiff::Timestamp,

        in_tz: jiff::tz::TimeZone,
        out_tz: jiff::tz::TimeZone,
    ) -> Result<InternalConversion, IgnoreError> {
        // Given the plain time and date, interpret them in the input_tz. If no date, pick the nearest instance of this time in the future.
        let in_dt: jiff::Zoned = match input_date {
            Some(input_date) => jiff::civil::DateTime::new(
                input_date.year(),
                input_date.month(),
                input_date.day(),
                input_time.hour(),
                input_time.minute(),
                input_time.second(),
                input_time.subsec_nanosecond(),
            )?
            .to_zoned(in_tz)?,
            None => {
                let now = now.to_zoned(in_tz);
                // Either today with the given time, if that's in the future, or tomorrow with the given time.
                // This will be weird on dates without the given time (e.g. when daylight savings goes on/off, sometimes 1pm happens once or multiple times), but that's OK - this is for personal use.
                if input_time > now.time() {
                    now.with().time(input_time).build()?
                } else {
                    now.checked_add(jiff::Span::new().days(1))?
                        .with()
                        .time(input_time)
                        .build()?
                }
            }
        };

        let out_dt = in_dt.with_time_zone(out_tz);

        // Display the date for this transformation if it was directly specified
        let date_relevant = input_date.is_some();
        Ok(InternalConversion::new(in_dt, out_dt, date_relevant))
    }

    fn render_conversion(
        &self,
        conv: InternalConversion,
        relevant_out_tzs: Vec<ComplexTz>,
        render: TimeRender,
    ) -> Conversion {
        let mut c = if conv.date_relevant {
            format!(
                "{} {} {} in {} = {} {} {} (",
                Time::from((conv.in_dt.time(), render)),
                conv.in_z.abbrev,
                conv.in_dt.date(),
                conv.out_z.abbrev,
                // =
                Time::from((conv.out_dt.time(), render)),
                conv.out_z.abbrev,
                conv.out_dt.date(),
            )
        } else if conv.in_dt.date() != conv.out_dt.date() {
            let delta = conv.out_dt.date() - conv.in_dt.date();
            // This is in dates, not in other units, so days is the minimum
            let days = delta.get_days();

            if days == 1 {
                format!(
                    "{} {} in {} = {} {} next day (",
                    Time::from((conv.in_dt.time(), render)),
                    conv.in_z.abbrev,
                    conv.out_z.abbrev,
                    // =
                    Time::from((conv.out_dt.time(), render)),
                    conv.out_z.abbrev,
                )
            } else {
                format!(
                    "{} {} in {} = {} {} {:+} days (",
                    Time::from((conv.in_dt.time(), render)),
                    conv.in_z.abbrev,
                    conv.out_z.abbrev,
                    // =
                    Time::from((conv.out_dt.time(), render)),
                    conv.out_z.abbrev,
                    days,
                )
            }
        } else {
            format!(
                "{} {} in {} = {} {} (",
                Time::from((conv.in_dt.time(), render)),
                conv.in_z.abbrev,
                conv.out_z.abbrev,
                // =
                Time::from((conv.out_dt.time(), render)),
                conv.out_z.abbrev,
            )
        };

        if relevant_out_tzs.len() <= 2 {
            let mut first = true;
            for t in relevant_out_tzs {
                if !first {
                    c.push_str(", ");
                }
                c.push_str(&t.0);
                first = false;
            }
        } else {
            write!(
                c,
                "{}, {} more",
                relevant_out_tzs[0].0,
                relevant_out_tzs.len() - 1
            )
            .expect("std::fmt::Write for String does not error");
        }
        c.push_str(")");

        Conversion::DateTime(c)
    }

    pub fn attempt_conversion(
        &self,
        input_time: Time,
        input_date: Option<Date>,
        input_unit: &SmolStr,
        output_unit: &SmolStr,
        extend: &mut Vec<Conversion>,
    ) -> Result<(), DebugError> {
        let render_24hr = input_time.render;
        let input_time: jiff::civil::Time = input_time.try_into()?;
        let input_date: Option<jiff::civil::Date> = match input_date {
            Some(input_date) => Some(input_date.try_into()?),
            None => None,
        };
        let now = jiff::Timestamp::now();

        let input_tzs = self
            .candidate_tzs
            .get(input_unit)
            .ok_or("no input timezones")?;
        let output_tzs = self
            .candidate_tzs
            .get(output_unit)
            .ok_or("no output timezones")?;

        // Perform cartesian product of input and output tzs to do all of our conversions
        // TODO more sorting?
        let conversions = input_tzs
            .into_iter()
            .map(|i| {
                output_tzs
                    .iter()
                    .filter_map(|o| {
                        self.single_conversion(input_time, input_date, now, i.clone(), o.clone())
                            .ok()
                    })
                    // Deduplicate conversions with the same output tzoffset into single suggestions.
                    // Create a set of (conversion, relevant_output_tzs)
                    .fold(
                        vec![],
                        |mut v: Vec<(InternalConversion, Vec<ComplexTz>)>, c| {
                            let o_complex_dt = ComplexTz::of(&c.out_dt);
                            if let Some((prior_c, tzs)) =
                                v.iter_mut().find(|c2| c2.0.out_z == c.out_z)
                            {
                                prior_c.date_relevant |= c.date_relevant;
                                tzs.push(o_complex_dt);
                            } else {
                                v.push((c, vec![o_complex_dt]));
                            }
                            v
                        },
                    )
            })
            .flatten();

        extend.extend(
            conversions
                .into_iter()
                .map(|(conv, tzs)| self.render_conversion(conv, tzs, render_24hr)),
        );

        Ok(())
    }
}
