use std::sync::RwLock;

use arrayvec::{ArrayString, ArrayVec};
use fnv::FnvHashMap;
use smol_str::SmolStr;

use crate::conversions::{
    Conversion,
    currency::{CURRENCIES, CURRENCY_PREFIXES, CurrencyCtx, CurrencyStr},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NumUnit {
    Length(LengthUnit),
    Temp(TempUnit),
    Time(TimeUnit),
    Currency(CurrencyStr),
    // TODO area, volume
    // ...
}

trait NumUnitGroup: std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::hash::Hash {
    /// Express the conversion of units in 'self' to units in 'base' as (x, y) where `base_unit = (self * x) + y`
    fn of_base(self) -> (f64, f64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum LengthUnit {
    Km,
    M,
    Cm,
    Mm,
    Um, // aka micrometer aka micron
    Nm,
    Pm,
    In,
    Ft,
    /// Stored as feet internally but converted to feet'inches'' for display
    FtIn,
    Yd,
    Mile,
    League,

    NauticalMile,
    NauticalLeague,
    Fathom,

    LightYear,
    Au,
    Parsec,

    Furlong,
}
impl NumUnitGroup for LengthUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            LengthUnit::Km => (10_000.0, 0.0),
            LengthUnit::M => (1.0, 0.0),
            LengthUnit::Cm => (1E-2, 0.0),
            LengthUnit::Mm => (1E-3, 0.0),
            LengthUnit::Um => (1E-6, 0.0),
            LengthUnit::Nm => (1E-9, 0.0),
            LengthUnit::Pm => (1E-12, 0.0),

            LengthUnit::In => (0.0254, 0.0),
            LengthUnit::Ft | LengthUnit::FtIn => (0.3048, 0.0),
            LengthUnit::Yd => (0.9144, 0.0),
            LengthUnit::Mile => (1609.344, 0.0),
            LengthUnit::League => (1609.344 * 3.0, 0.0), // three miles

            LengthUnit::NauticalMile => (1852.0, 0.0),
            LengthUnit::NauticalLeague => (1852.0 * 3.0, 0.0), // three nautical miles
            LengthUnit::Fathom => (1.8288, 0.0),

            LengthUnit::LightYear => (9460730472580.8 * 1E3, 0.0),
            LengthUnit::Au => (149597870700.0, 0.0),
            LengthUnit::Parsec => (30856775814913673.0, 0.0),

            LengthUnit::Furlong => (201.168, 0.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TempUnit {
    C,
    F,
    K,
}
impl NumUnitGroup for TempUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            TempUnit::C => (1.0, 0.0),                    // C = C * 1 + 0
            TempUnit::F => (5.0 / 9.0, 32.0 * 5.0 / 9.0), // F = C * 1.8 + 32, C = (F - 32) / 1.8 = F * 5/9 - (32*5)/9 =
            TempUnit::K => (1.0, 273.15),                 // K = C * 1 - 273.15, C = K * 1 + 273.15
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TimeUnit {
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
}

type NumberUnits = ArrayVec<NumUnit, 15>;

type NumberUnitStr = SmolStr;

macro_rules! basic_conv {
    ($i:expr, $o:expr, $val:expr) => {{
        let (ia, ib) = $i.of_base();
        let (oa, ob) = $o.of_base();
        $val * (ia / oa) + ((ob - ib) / oa)
    }};
}

struct InternalConversion {
    input_unit: NumUnit,
    output_unit: NumUnit,
    input_val: f64,
    output_val: f64,
}

pub struct QuantityCtx {
    str_to_num_unit: FnvHashMap<NumberUnitStr, NumberUnits>,
    num_unit_to_suffix: FnvHashMap<NumUnit, String>,
    num_unit_to_name: FnvHashMap<NumUnit, String>,

    input_formatter: numfmt::Formatter,
    small_formatter: numfmt::Formatter,
    large_formatter: numfmt::Formatter,
    huge_formatter: numfmt::Formatter,
}
impl QuantityCtx {
    pub fn new() -> Self {
        let mut str_to_num_unit = FnvHashMap::default();
        let mut num_unit_to_name = FnvHashMap::default();
        let mut num_unit_to_suffix = FnvHashMap::default();

        use LengthUnit::*;
        use NumUnit::*;
        use TempUnit::*;
        use TimeUnit::*;
        let mut basic_unit_suffix = |unit, name: &str, suffix: &str, parsers: &[&str]| {
            num_unit_to_name
                .entry(unit)
                .insert_entry(format!("{}", name));
            num_unit_to_suffix
                .entry(unit)
                .insert_entry(format!("{}", suffix));
            for s in parsers {
                str_to_num_unit
                    .entry(NumberUnitStr::from(*s))
                    .or_insert_with(NumberUnits::new)
                    .push(unit);
            }
        };
        basic_unit_suffix(
            Length(Km),
            "kilometers",
            "km",
            &["kilometer", "kilometre", "kilometers", "kilometres", "km"],
        );
        basic_unit_suffix(
            Length(M),
            "meters",
            "m",
            &["meter", "metre", "meters", "metres", "m"],
        );
        basic_unit_suffix(
            Length(Cm),
            "centimeters",
            "cm",
            &[
                "centimeter",
                "centimetre",
                "centimeters",
                "centimetres",
                "cm",
            ],
        );
        basic_unit_suffix(
            Length(Mm),
            "millimeters",
            "mm",
            &[
                "millimeter",
                "millimetre",
                "millimeters",
                "millimetres",
                "mm",
            ],
        );
        basic_unit_suffix(
            Length(Um),
            "micrometers",
            "μm",
            &[
                "micrometer",
                "micrometre",
                "micrometers",
                "micrometres",
                "um",
                "μm",
            ],
        );
        basic_unit_suffix(
            Length(Nm),
            "nanometers",
            "nm",
            &["nanometer", "nanometre", "nanometers", "nanometres", "nm"],
        );
        basic_unit_suffix(
            Length(Pm),
            "picometers",
            "pm",
            &["picometer", "picometre", "picometers", "picometres", "pm"],
        );
        basic_unit_suffix(
            Length(In),
            "inches",
            "in",
            &["inch", "inches", "inchs", "in"],
        );
        basic_unit_suffix(Length(Ft), "feet", "ft", &["foot", "feet", "ft"]);
        basic_unit_suffix(
            Length(FtIn),
            "feet and inches",
            "ft/in",
            &["foot", "feet", "ft"],
        );
        basic_unit_suffix(Length(Yd), "yds", " yards", &["yard", "yards", "yd", "yds"]);
        basic_unit_suffix(Length(Mile), "miles", " miles", &["mile", "miles"]);
        basic_unit_suffix(
            Length(League),
            "leagues",
            " leagues",
            &["league", "leagues"],
        );
        basic_unit_suffix(
            Length(NauticalMile),
            "nautical miles",
            " nautical miles",
            // If the user specifies the base, they may want this
            &[
                "mile",
                "miles",
                "nautical mile",
                "nautical miles",
                "nmi",
                "nmis",
            ],
        );
        basic_unit_suffix(
            Length(NauticalLeague),
            "nautical leagues",
            " nautical leagues",
            // If the user specifies the base, they may want this
            &["league", "leagues", "nautical league", "nautical leagues"],
        );
        basic_unit_suffix(
            Length(Fathom),
            "fathoms",
            " fathoms",
            &["fathom", "fathoms"],
        );

        basic_unit_suffix(
            Length(LightYear),
            "light years",
            "ly",
            &[
                "ly",
                "lys",
                "lyr",
                "lyrs",
                "light year",
                "light-year",
                "lightyear",
                "light years",
                "light-years",
                "lightyears",
            ],
        );
        basic_unit_suffix(
            Length(Au),
            "astronomical units",
            "au",
            &["au", "aus", "astronomical unit", "astronomical units"],
        );
        basic_unit_suffix(
            Length(Parsec),
            "parsecs",
            "pc",
            &["pc", "pcs", "parsec", "parsecs"],
        );
        basic_unit_suffix(
            Length(Furlong),
            "furlongs",
            "fur",
            &["fur", "furs", "furlong", "furlongs"],
        );

        basic_unit_suffix(
            Temp(C),
            "°C", // degree sign prefix renders better than dedicated degrees-C
            "°C",
            &[
                "celsius", //
                "c",       //
                "°c",      // degree sign prefix
                "˚c",      // 'ring above' prefix, for permissivity
                "∘c",      // 'ring operator' prefix, for permissivity
                "℃",       // dedicated "degrees-C" character
            ],
        );
        basic_unit_suffix(
            Temp(F),
            "°F", // degree sign prefix renders better than dedicated degrees-F
            "°F",
            &[
                "fahrenheit", //
                "f",          //
                "°f",         // degree sign prefix
                "˚f",         // 'ring above' prefix, for permissivity
                "∘f",         // 'ring operator' prefix, for permissivity
                "℉",          // dedicated "degrees-F" character
            ],
        );
        basic_unit_suffix(
            Temp(K),
            "kelvin",
            "K",
            &[
                "kelvin", //
                "k",      //
                "°k",     // degree sign prefix
                "˚k",     // 'ring above' prefix, for permissivity
                "∘k",     // 'ring operator' prefix, for permissivity
                          // there is no "degrees-K" character
            ],
        );

        basic_unit_suffix(Time(S), "seconds", "s", &["s", "second", "seconds"]);
        basic_unit_suffix(
            Time(Ms),
            "milliseconds",
            "ms",
            &["ms", "millisecond", "milliseconds"],
        );
        basic_unit_suffix(
            Time(Us),
            "microseconds",
            "μs",
            &["μs", "microsecond", "microseconds"],
        );
        basic_unit_suffix(
            Time(Ns),
            "nanoseconds",
            "ns",
            &["ns", "nanosecond", "nanoseconds"],
        );
        basic_unit_suffix(
            Time(Ps),
            "picoseconds",
            "ps",
            &["ps", "picosecond", "picoseconds"],
        );
        basic_unit_suffix(
            Time(Min),
            "minutes",
            "mins",
            &["min", "mins", "minute", "minutes"],
        );
        basic_unit_suffix(Time(Hour), "hours", "hrs", &["hr", "hrs", "hour", "hours"]);
        basic_unit_suffix(Time(Day), "days", " days", &["dy", "dys", "day", "days"]);
        basic_unit_suffix(Time(Week), " weeks", "wks", &["wk", "wks", "week", "weeks"]);
        basic_unit_suffix(Time(Year), " years", "yrs", &["yr", "yrs", "year", "years"]);

        for (currency_str, _currency_written) in CURRENCIES {
            let unit = Currency(CurrencyStr::from_str(currency_str).unwrap());

            str_to_num_unit
                .entry(NumberUnitStr::from(currency_str.to_ascii_lowercase()))
                .or_insert_with(NumberUnits::new)
                .push(unit);

            num_unit_to_suffix
                .entry(unit)
                .insert_entry(format!("{}", currency_str));

            num_unit_to_name
                .entry(unit)
                .insert_entry(format!("{}", currency_str));
        }
        for (currency_symb, currency_str) in CURRENCY_PREFIXES {
            let unit = Currency(CurrencyStr::from_str(currency_str).unwrap());
            let currency_symb_str: String = [currency_symb].into_iter().collect();

            str_to_num_unit
                .entry(NumberUnitStr::from(&currency_symb_str))
                .or_insert_with(NumberUnits::new)
                .push(unit);
        }

        Self {
            str_to_num_unit,
            num_unit_to_suffix,
            num_unit_to_name,

            input_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Unspecified),
            small_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Significance(4)),
            large_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Decimals(0)),
            huge_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Significance(4)),
        }
    }

    fn attempt_convert(
        &self,
        input_unit: NumUnit,
        val: f64,
        output_unit: NumUnit,
        currency: Option<&RwLock<CurrencyCtx>>,
    ) -> Option<f64> {
        use NumUnit::*;
        let o_val = match (input_unit, output_unit) {
            (Length(i), Length(o)) => basic_conv!(i, o, val),
            (Temp(i), Temp(o)) => basic_conv!(i, o, val),
            (Time(i), Time(o)) => basic_conv!(i, o, val),
            (Currency(i), Currency(o)) => currency.and_then(|state| {
                // Only unlock the state when we actually need to read it
                let state = state.read().unwrap();
                let i_from_usd = state.currencies_from_usd.get(&i)?;
                let o_from_usd = state.currencies_from_usd.get(&o)?;
                Some(val * o_from_usd / i_from_usd)
            })?,
            _ => return None,
        };
        Some(o_val)
    }

    fn render_conversion(&self, conv: InternalConversion) -> Option<Conversion> {
        match conv {
            InternalConversion {
                input_unit,
                output_unit,
                input_val,
                output_val,
            } => {
                if input_unit == output_unit {
                    return None;
                }

                let input_str = match input_unit {
                    NumUnit::Length(LengthUnit::FtIn) => return None, // TODO accept this as input??
                    _ => {
                        format!(
                            "{}{}",
                            self.input_formatter.fmt_string(input_val),
                            self.num_unit_to_suffix.get(&input_unit).or_else(|| {
                                log::error!("No suffix for unit {:?}", input_unit);
                                None
                            })?
                        )
                    }
                };
                let output_str = match output_unit {
                    NumUnit::Length(LengthUnit::FtIn) => format!(
                        "{:.0}\u{02032}{:.1}\u{02033}",
                        output_val.floor(),
                        self.attempt_convert(
                            NumUnit::Length(LengthUnit::Ft),
                            output_val.fract(),
                            NumUnit::Length(LengthUnit::In),
                            None,
                        )
                        .expect("Ft->In should never fail")
                    ),
                    _ => {
                        // TODO format with scientific 4sig-figs if <0.001 or >1E10, to 4sig-figs if <10_000, and rounded to integer otherwise
                        // This is a personal heuristic. It's non-exact for currency conversion but you can click through for that. I would round to 2d.p. for currency specifically but there are some currencies (e.g. yen) where that does not work
                        // Currently approximated with numfmt: <10_000 use a formatter with 4sf, which automatically kicks in scientific if <0.0001. (close enough for me).
                        // >=10_000, <1E11 (numfmt scientific starting point) = 0dp precision
                        // >= 1E11 = 4sf again.

                        let output_fmt = if output_val < 10_000.0 {
                            &self.small_formatter
                        } else if output_val < 1E11 {
                            &self.large_formatter
                        } else {
                            &self.huge_formatter
                        };

                        format!(
                            "{}{}",
                            output_fmt.fmt_string(output_val),
                            self.num_unit_to_suffix.get(&output_unit).or_else(|| {
                                log::error!("No suffix for unit {:?}", output_unit);
                                None
                            })?
                        )
                    }
                };

                let is_approx = matches!(input_unit, NumUnit::Currency(_))
                    || output_val > 1E11
                    || input_val > 1E11;
                let eq_char = if is_approx { '≈' } else { '=' };

                Some(Conversion::Number(format!(
                    "{} in {} {} {}",
                    input_str,
                    self.num_unit_to_name.get(&output_unit).or_else(|| {
                        log::error!("No name for unit {:?}", output_unit);
                        None
                    })?,
                    eq_char,
                    output_str
                )))
            }
        }
    }

    pub fn attempt_conversion(
        &self,
        input_val: f64,
        input_unit: &SmolStr,
        output_unit: &SmolStr,
        extend: &mut Vec<Conversion>,
        currency: &RwLock<CurrencyCtx>,
    ) -> Option<()> {
        let input_units = self.str_to_num_unit.get(input_unit)?;
        let output_units = self.str_to_num_unit.get(output_unit)?;

        log::debug!("{:?} in {:?} to {:?}", input_val, input_units, output_units);

        extend.extend(
            input_units
                .into_iter()
                .map(|i| {
                    output_units.iter().filter_map(|o| {
                        let v = self.attempt_convert(*i, input_val, *o, Some(currency))?;
                        self.render_conversion(InternalConversion {
                            input_unit: *i,
                            input_val,
                            output_unit: *o,
                            output_val: v,
                        })
                    })
                })
                .flatten(),
        );

        Some(())
    }
}
