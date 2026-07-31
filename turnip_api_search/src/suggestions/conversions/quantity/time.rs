use strum::VariantArray;

use super::{NumUnitGroup, Strs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
pub enum TimeUnit {
    S,
    Ms,
    Us,
    Ns,
    Ps,
    Min,
    Hour,
    Day,
    Week,
    // Month, // Can't convert reliably
    Year,
}
impl NumUnitGroup for TimeUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            TimeUnit::S => (1.0, 0.0),
            TimeUnit::Ms => (1E-3, 0.0),
            TimeUnit::Us => (1E-6, 0.0),
            TimeUnit::Ns => (1E-9, 0.0),
            TimeUnit::Ps => (1E-12, 0.0),
            TimeUnit::Min => (60.0, 0.0),
            TimeUnit::Hour => (3600.0, 0.0),
            TimeUnit::Day => (3600.0 * 24.0, 0.0),
            TimeUnit::Week => (3600.0 * 24.0 * 7.0, 0.0),
            TimeUnit::Year => (3600.0 * 24.0 * 365.25, 0.0),
        }
    }

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[
        (TimeUnit::Day, 21.0, TimeUnit::Week, 3.0),
        (TimeUnit::Year, 3.0, TimeUnit::Day, 1095.75),
        (TimeUnit::Day, 3.0, TimeUnit::Hour, 72.0),
        (TimeUnit::Hour, 0.5, TimeUnit::Min, 30.0),
        (TimeUnit::Min, 0.5, TimeUnit::S, 30.0),
        (TimeUnit::Min, 0.5, TimeUnit::Ms, 30E3),
        (TimeUnit::Ms, 0.5, TimeUnit::Us, 500.0),
        (TimeUnit::Us, 0.5, TimeUnit::Ns, 500.0),
        (TimeUnit::Ns, 0.5, TimeUnit::Ps, 500.0),
    ];

    const STRS: &'static [(Self, Strs)] = &[
        (
            TimeUnit::S,
            Strs {
                name: "seconds",
                suffix: "s",
                mns: &[&["s", "second", "seconds"]],
            },
        ),
        (
            TimeUnit::Ms,
            Strs {
                name: "milliseconds",
                suffix: "ms",
                mns: &[&["ms", "millisecond", "milliseconds"]],
            },
        ),
        (
            TimeUnit::Us,
            Strs {
                name: "microseconds",
                suffix: "μs",
                mns: &[&["μs", "microsecond", "microseconds"]],
            },
        ),
        (
            TimeUnit::Ns,
            Strs {
                name: "nanoseconds",
                suffix: "ns",
                mns: &[&["ns", "nanosecond", "nanoseconds"]],
            },
        ),
        (
            TimeUnit::Ps,
            Strs {
                name: "picoseconds",
                suffix: "ps",
                mns: &[&["ps", "picosecond", "picoseconds"]],
            },
        ),
        (
            TimeUnit::Min,
            Strs {
                name: "minutes",
                suffix: "mins",
                mns: &[&["min", "mins", "minute", "minutes"]],
            },
        ),
        (
            TimeUnit::Hour,
            Strs {
                name: "hours",
                suffix: "hrs",
                mns: &[&["hr", "hrs", "hour", "hours"]],
            },
        ),
        (
            TimeUnit::Day,
            Strs {
                name: "days",
                suffix: " days",
                mns: &[&["dy", "dys", "day", "days"]],
            },
        ),
        (
            TimeUnit::Week,
            Strs {
                name: " weeks",
                suffix: "wks",
                mns: &[&["wk", "wks", "week", "weeks"]],
            },
        ),
        (
            TimeUnit::Year,
            Strs {
                name: " years",
                suffix: "yrs",
                mns: &[&["yr", "yrs", "year", "years"]],
            },
        ),
    ];
}
