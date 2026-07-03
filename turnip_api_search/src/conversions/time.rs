//! timezones are parsed from the international TZ database
//! https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
//!
//! A token identifies a timezone IF it is an any-case variant of a 'candidate timezone name'.
//! The list of candidates is built as follows:
//! - If a country code has exactly one 'TZ Identifier' at boot time, or maps to exactly one unique SDT/DST pair, it is a candidate.
//!     - e.g. germany = DE = Europe/Berlin & Europe/Zurich but both map to (CET, CEST)
//!     - watch out for ambiguities e.g. "LA" = Lao, not Los Angeles.
//!         - For these cases, ensure that out_country uses a human-readable version of the TZ identifier - they will realise that Asia/Bangkok is not right.
//!         - also, this should
//! - For every TZ identifier for a canonical time zone, split on '/':
//!     - If the last component is unique in the set of candidates, it is a candidate
//! - Every time zone abbreviation is a candidate

use arrayvec::ArrayVec;
use fnv::FnvHashMap;
use jiff::tz;
use smol_str::{SmolStr, StrExt, ToSmolStr};
use std::fmt::Write;
use turnip_api::util::{DebugError, IgnoreError};

use crate::conversions::{
    Conversion,
    parser::{Date, Time},
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
impl std::fmt::Display for ComplexTz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

pub struct TimeCtx {
    db: &'static jiff::tz::TimeZoneDatabase,
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
                Some((
                    name.as_str().to_ascii_lowercase_smolstr(),
                    db.get(name.as_str()).unwrap(),
                ))
            })
            .collect::<Vec<_>>();
        for (name, tz) in complex_tzs.iter() {
            candidate_tzs
                .entry(name.clone())
                .or_insert_with(|| vec![])
                .push(tz.clone());
        }

        // Allow suffixes to translate to relevant timezones
        // e.g. "Eastern" => Canada/Eastern and US/Eastern
        // Also translate suffixes to be typable
        // e.g. "El Aaiun" => Africa/El_Aaiun
        // Also allow prefixes to be used
        // e.g. "US" => "US/Eastern", "US/Pacific", etc.
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
            })
            .last();

        let now = jiff::Timestamp::now();

        // Allow abbreviations
        // e.g. EST -> US/Eastern, EDT -> US/Eastern
        complex_tzs
            .iter()
            .map(|(name, tz)| {
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

        Self { db, candidate_tzs }
    }

    fn single_conversion(
        &self,
        input_time: jiff::civil::Time,
        input_date: Option<jiff::civil::Date>,
        now: jiff::Timestamp,

        in_tz: jiff::tz::TimeZone,
        out_tz: jiff::tz::TimeZone,
    ) -> Result<InternalConversion, DebugError> {
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

        // Display the date for this transformation if it was directly specified OR if we cross a date boundary
        let date_relevant = input_date.is_some() || (in_dt.date() != out_dt.date());
        Ok(InternalConversion::new(in_dt, out_dt, date_relevant))
    }

    fn render_conversion(
        &self,
        conv: InternalConversion,
        relevant_out_tzs: Vec<ComplexTz>,
    ) -> Conversion {
        let mut c = if conv.date_relevant {
            format!(
                "{:02}:{:02} {} {} in {} = {:02}:{:02} {} (",
                conv.in_dt.hour(),
                conv.in_dt.minute(),
                conv.in_dt.date(),
                conv.in_z.abbrev,
                conv.out_z.abbrev,
                conv.out_dt.hour(),
                conv.out_dt.minute(),
                conv.out_dt.date(),
            )
        } else {
            format!(
                "{:02}:{:02} {} in {} = {:02}:{:02} (",
                conv.in_dt.hour(),
                conv.in_dt.minute(),
                conv.in_z.abbrev,
                conv.out_z.abbrev,
                conv.out_dt.hour(),
                conv.out_dt.minute(),
            )
        };

        if relevant_out_tzs.len() > 2 {
            let mut first = true;
            for t in relevant_out_tzs {
                if !first {
                    c.push_str(", ");
                }
                c.push_str(&t.0);
                first = false;
            }
        } else {
            write!(c, "active in {}", relevant_out_tzs.len());
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
        let conversions = input_tzs
            .into_iter()
            .map(|i| {
                output_tzs.iter().filter_map(|o| {
                    self.single_conversion(input_time, input_date, now, i.clone(), o.clone())
                        .ok()
                })
            })
            .flatten();

        // TODO deduplicate and sort.
        let sorted_conversions = conversions;

        extend.extend(sorted_conversions.into_iter().map(|conv| {
            let tzs = vec![ComplexTz(
                conv.out_dt.time_zone().iana_name().unwrap().to_smolstr(),
            )];
            self.render_conversion(conv, tzs)
        }));

        Ok(())
    }
}
