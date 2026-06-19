//! Specification:
//! - ((time)|(date time)|(time date)) (timezone) in (timezone) => take time & date and convert from the given timezone to the given output timezone OR the given country code's output timezone
//!
//! times should be parseable as H:MM AM (H <= 12), HMM AM (H <= 12), H:MM PM (H <= 12), HMM PM (H <= 12), HHMM (H <= 23, assume 24hr)
//! dates should be parseable as YYYY-MM-DD, YYYY MM DD, DD m YYYY (where m = a month name or abbreviation march/mar), or a weekday (sunday|saturday|etc.) which is interpreted local to the current system clock in the input timezone.
//!     - see https://web.library.yale.edu/cataloging/months
//! 
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
//! 

use crate::placeholder_url::{PlaceholderEncoding, PlaceholderUrl};

enum IntermediateTimeToken<'a> {
    Space,
    Number(u64),
    Colon,
    Am,
    Pm,
    In,
    Text(&'a str),
}

enum TimeToken<'a> {
    // 24hr time representation
    Time {
        hour: u8,
        minute: u8,
    },
    Date {
        year: u64,
        month: u8,
        day: u8
    },
    Timezone(&'a str),
    Country(&'a str),
}

enum 

trait TimeQueryContext {
    fn is_timezone(&self, token: &str) -> bool; 
    fn is_country(&self, token: &str) -> bool; 
}

pub fn 

// pub struct TimeQuery {
//     in_date: Option<jiff::civil::Date>,
//     in_time: jiff::civil::Time,

// }

// https://www.worldtimebuddy.com/?qm=1&lid=2646057,360630,524901&h=524901&date=2026-1-30&sln=7.5-8&hf=1
// lid = location IDs, can't reverse
// h = "here" location ID (I think), can't reverse
// date = YYYY-MM-DD date
// sln = local time range in "here" location ID, therefore unreliable as long as h not reversed
// hf = 1 (unknown)
// qm = 1 (unknown)
const WORLD_TIME_BUDDY_PREFIX: &'static str = "https://www.worldtimebuddy.com/?qm=1&hf=1&date=";
const WORLD_TIME_BUDDY_SUFFIX: &'static str = "";
const WORLD_TIME_BUDDY_LOOKUP: PlaceholderUrl<'static> = PlaceholderUrl {
    prefix: WORLD_TIME_BUDDY_PREFIX,
    placeholder_encoding: PlaceholderEncoding::Plain,
    suffix: WORLD_TIME_BUDDY_SUFFIX
};

pub struct CompletedTimeQuery {
    /// Tuple (in_date, out_date)
    dates: Option<(jiff::civil::Date, jiff::civil::Date)>,
    /// Tuple (in_time, out_time)
    times: (jiff::civil::Time, jiff::civil::Time),

    in_country: Option<SmolStr>,
    in_timezone: SmolStr,

    out_country: Option<SmolStr>,
    out_timezone: SmolStr,
}
impl CompletedTimeQuery {
    pub fn named_url(&self) -> (String, String) {
        let name = match (self.dates, self.in_country, self.out_country) {

        };
        let url_date = match self.dates {
            Some((in_date, out_date)) => in_date,
            None => jiffy::civil::Date::now()
        };
        let url = format!("{}{:04}-{:02}-{:02}", WORLD_TIME_BUDDY_PREFIX, url_date.year(), url_date.month(), url_date.day());

        (name, url)
    }
}
