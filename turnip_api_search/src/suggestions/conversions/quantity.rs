use arrayvec::ArrayVec;
use fnv::FnvHashMap;
use smol_str::SmolStr;
use std::sync::RwLock;
use strum::VariantArray;

use super::{
    Conversion,
    currency::{CURRENCIES, CURRENCY_PREFIXES, CurrencyCtx, CurrencyStr},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NumUnit {
    Length(LengthUnit),
    Area(AreaUnit),
    // TODO Volume(VolumeUnit),
    Temp(TempUnit),
    Time(TimeUnit),
    Weight(WeightUnit),
    Currency(CurrencyStr),
    // ...
}

#[cfg(test)]
mod tests {
    macro_rules! define_group_tests {
        ($p:ident, $t:ty) => {
            mod $p {
                use super::super::*;
                #[test]
                fn test_all_units_stringed() {
                    let stringed = <$t as NumUnitGroup>::STRS
                        .iter()
                        .map(|(u, _s)| *u)
                        .collect::<Vec<_>>();
                    for u in <$t as VariantArray>::VARIANTS {
                        assert!(stringed.contains(u), "Enum {:?} is not in STRS", u);
                    }
                }
            }
        };
    }

    define_group_tests!(length, LengthUnit);
    define_group_tests!(area, AreaUnit);
    // define_group_tests!(volume, VolumeUnit);
    define_group_tests!(temp, TempUnit);
    define_group_tests!(time, TimeUnit);
    define_group_tests!(weight, WeightUnit);
}

struct Strs {
    name: &'static str,
    suffix: &'static str,
    /// mnemonics
    mns: &'static [&'static str],
}

trait NumUnitGroup:
    std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::hash::Hash + 'static + VariantArray
{
    /// Express the conversion of units in 'self' to units in 'base' as (x, y) where `base_unit = (self * x) + y`
    fn of_base(self) -> (f64, f64);

    const STRS: &'static [(Self, Strs)];

    // #[cfg(test)]
    // const TEST_CASES: &'static [(Self, f64, Self, f64)];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
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
            LengthUnit::Km => (1E3, 0.0),
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

    const STRS: &'static [(Self, Strs)] = &[
        (
            LengthUnit::Km,
            Strs {
                name: "kilometers",
                suffix: "km",
                mns: &["kilometer", "kilometre", "kilometers", "kilometres", "km"],
            },
        ),
        (
            LengthUnit::M,
            Strs {
                name: "meters",
                suffix: "m",
                mns: &["meter", "metre", "meters", "metres", "m"],
            },
        ),
        (
            LengthUnit::Cm,
            Strs {
                name: "centimeters",
                suffix: "cm",
                mns: &[
                    "centimeter",
                    "centimetre",
                    "centimeters",
                    "centimetres",
                    "cm",
                ],
            },
        ),
        (
            LengthUnit::Mm,
            Strs {
                name: "millimeters",
                suffix: "mm",
                mns: &[
                    "millimeter",
                    "millimetre",
                    "millimeters",
                    "millimetres",
                    "mm",
                ],
            },
        ),
        (
            LengthUnit::Um,
            Strs {
                name: "micrometers",
                suffix: "μm",
                mns: &[
                    "micrometer",
                    "micrometre",
                    "micrometers",
                    "micrometres",
                    "um",
                    "μm",
                ],
            },
        ),
        (
            LengthUnit::Nm,
            Strs {
                name: "nanometers",
                suffix: "nm",
                mns: &["nanometer", "nanometre", "nanometers", "nanometres", "nm"],
            },
        ),
        (
            LengthUnit::Pm,
            Strs {
                name: "picometers",
                suffix: "pm",
                mns: &["picometer", "picometre", "picometers", "picometres", "pm"],
            },
        ),
        (
            LengthUnit::In,
            Strs {
                name: "inches",
                suffix: "in",
                mns: &["inch", "inches", "inchs", "in"],
            },
        ),
        (
            LengthUnit::Ft,
            Strs {
                name: "feet",
                suffix: "ft",
                mns: &["foot", "feet", "ft"],
            },
        ),
        (
            LengthUnit::FtIn,
            Strs {
                name: "feet and inches",
                suffix: "ft/in",
                mns: &["foot", "feet", "ft"],
            },
        ),
        (
            LengthUnit::Yd,
            Strs {
                name: "yds",
                suffix: " yards",
                mns: &["yard", "yards", "yd", "yds"],
            },
        ),
        (
            LengthUnit::Mile,
            Strs {
                name: "miles",
                suffix: " miles",
                mns: &["mile", "miles"],
            },
        ),
        (
            LengthUnit::League,
            Strs {
                name: "leagues",
                suffix: " leagues",
                mns: &["league", "leagues"],
            },
        ),
        (
            LengthUnit::NauticalMile,
            Strs {
                name: "nautical miles",
                suffix: " nautical miles",
                mns: &[
                    "mile",
                    "miles",
                    "nautical mile",
                    "nautical miles",
                    "nmi",
                    "nmis",
                ],
            },
        ),
        (
            LengthUnit::NauticalLeague,
            Strs {
                name: "nautical leagues",
                suffix: " nautical leagues",
                mns: &["league", "leagues", "nautical league", "nautical leagues"],
            },
        ),
        (
            LengthUnit::Fathom,
            Strs {
                name: "fathoms",
                suffix: " fathoms",
                mns: &["fathom", "fathoms"],
            },
        ),
        (
            LengthUnit::LightYear,
            Strs {
                name: "light years",
                suffix: "ly",
                mns: &[
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
            },
        ),
        (
            LengthUnit::Au,
            Strs {
                name: "astronomical units",
                suffix: "au",
                mns: &["au", "aus", "astronomical unit", "astronomical units"],
            },
        ),
        (
            LengthUnit::Parsec,
            Strs {
                name: "parsecs",
                suffix: "pc",
                mns: &["pc", "pcs", "parsec", "parsecs"],
            },
        ),
        (
            LengthUnit::Furlong,
            Strs {
                name: "furlongs",
                suffix: "fur",
                mns: &["fur", "furs", "furlong", "furlongs"],
            },
        ),
    ];
}

macro_rules! sq {
    ($x:expr) => {
        ($x * $x)
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
enum AreaUnit {
    Km2,
    M2,
    Cm2,
    Mm2,
    Um2, // aka micrometer aka micron
    Nm2,
    Pm2,
    In2,
    Ft2,
    Yd2,
    Mile2,

    Hectare,
    Acre,

    SurveyMile2,
    SurveyFt2,
    SurveyAcre,
}
impl NumUnitGroup for AreaUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            AreaUnit::Km2 => (1E3, 0.0),
            AreaUnit::M2 => (1.0, 0.0),
            AreaUnit::Cm2 => (1E-4, 0.0),
            AreaUnit::Mm2 => (1E-6, 0.0),
            AreaUnit::Um2 => (1E-12, 0.0),
            AreaUnit::Nm2 => (1E-18, 0.0),
            AreaUnit::Pm2 => (1E-24, 0.0),
            AreaUnit::In2 => (sq!(0.0254), 0.0),
            AreaUnit::Ft2 => (sq!(0.3048), 0.0),
            AreaUnit::Yd2 => (sq!(0.9144), 0.0),
            AreaUnit::Mile2 => (sq!(1609.344), 0.0),
            AreaUnit::Hectare => (10_000.0, 0.0),
            AreaUnit::Acre => todo!(),
            AreaUnit::SurveyMile2 => todo!(),
            AreaUnit::SurveyFt2 => todo!(),
            AreaUnit::SurveyAcre => todo!(),
        }
    }

    const STRS: &'static [(Self, Strs)] = &[];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
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

    const STRS: &'static [(Self, Strs)] = &[
        (
            TempUnit::C,
            Strs {
                name: "°C", // degree sign prefix renders better than dedicated degrees-C
                suffix: "°C",
                mns: &[
                    "celsius", //
                    "c",       //
                    "°c",      // degree sign prefix
                    "˚c",      // 'ring above' prefix, for permissivity
                    "∘c",      // 'ring operator' prefix, for permissivity
                    "℃",       // dedicated "degrees-C" character
                ],
            },
        ),
        (
            TempUnit::F,
            Strs {
                name: "°F", // degree sign prefix renders better than dedicated degrees-F
                suffix: "°F",
                mns: &[
                    "fahrenheit", //
                    "f",          //
                    "°f",         // degree sign prefix
                    "˚f",         // 'ring above' prefix, for permissivity
                    "∘f",         // 'ring operator' prefix, for permissivity
                    "℉",          // dedicated "degrees-F" character
                ],
            },
        ),
        (
            TempUnit::K,
            Strs {
                name: "kelvin",
                suffix: "K",
                mns: &[
                    "kelvin", //
                    "k",      //
                    "°k",     // degree sign prefix
                    "˚k",     // 'ring above' prefix, for permissivity
                    "∘k",     // 'ring operator' prefix, for permissivity
                              // there is no "degrees-K" character
                ],
            },
        ),
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
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

    const STRS: &'static [(Self, Strs)] = &[
        (
            TimeUnit::S,
            Strs {
                name: "seconds",
                suffix: "s",
                mns: &["s", "second", "seconds"],
            },
        ),
        (
            TimeUnit::Ms,
            Strs {
                name: "milliseconds",
                suffix: "ms",
                mns: &["ms", "millisecond", "milliseconds"],
            },
        ),
        (
            TimeUnit::Us,
            Strs {
                name: "microseconds",
                suffix: "μs",
                mns: &["μs", "microsecond", "microseconds"],
            },
        ),
        (
            TimeUnit::Ns,
            Strs {
                name: "nanoseconds",
                suffix: "ns",
                mns: &["ns", "nanosecond", "nanoseconds"],
            },
        ),
        (
            TimeUnit::Ps,
            Strs {
                name: "picoseconds",
                suffix: "ps",
                mns: &["ps", "picosecond", "picoseconds"],
            },
        ),
        (
            TimeUnit::Min,
            Strs {
                name: "minutes",
                suffix: "mins",
                mns: &["min", "mins", "minute", "minutes"],
            },
        ),
        (
            TimeUnit::Hour,
            Strs {
                name: "hours",
                suffix: "hrs",
                mns: &["hr", "hrs", "hour", "hours"],
            },
        ),
        (
            TimeUnit::Day,
            Strs {
                name: "days",
                suffix: " days",
                mns: &["dy", "dys", "day", "days"],
            },
        ),
        (
            TimeUnit::Week,
            Strs {
                name: " weeks",
                suffix: "wks",
                mns: &["wk", "wks", "week", "weeks"],
            },
        ),
        (
            TimeUnit::Year,
            Strs {
                name: " years",
                suffix: "yrs",
                mns: &["yr", "yrs", "year", "years"],
            },
        ),
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
enum WeightUnit {
    Tonne,
    Kg,
    G,
    Mg,
    Ug,

    Oz,
    Lb,
    Stone,

    // Grain,
    // Pennyweight,
    // Hundredweight,
    TroyOz,
    TroyLb,

    Carat,
}
impl NumUnitGroup for WeightUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            WeightUnit::Tonne => (1E6, 0.0),
            WeightUnit::Kg => (1E3, 0.0),
            WeightUnit::G => (1.0, 0.0),
            WeightUnit::Mg => (1E-3, 0.0),
            WeightUnit::Ug => (1E-6, 0.0),
            WeightUnit::Oz => (28.349523125, 0.0),
            WeightUnit::Lb => (453.59237, 0.0),
            WeightUnit::Stone => (453.59237 * 14.0, 0.0),
            WeightUnit::TroyOz => (31.1034768, 0.0),
            WeightUnit::TroyLb => (31.1034768 * 12.0, 0.0),
            WeightUnit::Carat => (0.2, 0.0),
        }
    }

    const STRS: &'static [(Self, Strs)] = &[];
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

        macro_rules! basic_unit_suffixes {
            ($con:expr, $unit:ty) => {
                for (u, s) in <$unit as NumUnitGroup>::STRS {
                    let unit = $con(*u);

                    num_unit_to_name
                        .entry(unit)
                        .insert_entry(format!("{}", s.name));
                    num_unit_to_suffix
                        .entry(unit)
                        .insert_entry(format!("{}", s.suffix));
                    for s in s.mns {
                        str_to_num_unit
                            .entry(NumberUnitStr::from(*s))
                            .or_insert_with(NumberUnits::new)
                            .push(unit);
                    }
                }
            };
        }

        basic_unit_suffixes!(NumUnit::Length, LengthUnit);
        basic_unit_suffixes!(NumUnit::Area, AreaUnit);
        basic_unit_suffixes!(NumUnit::Temp, TempUnit);
        basic_unit_suffixes!(NumUnit::Time, TimeUnit);
        basic_unit_suffixes!(NumUnit::Weight, WeightUnit);

        for (currency_str, _currency_written) in CURRENCIES {
            let unit = NumUnit::Currency(
                CurrencyStr::from_str(currency_str).expect("CURRENCIES currency_str not 3-chars"),
            );

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
            let unit = NumUnit::Currency(
                CurrencyStr::from_str(currency_str)
                    .expect("CURRENCY_PREFIXES currency_str not 3-chars"),
            );
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
                .expect("',' is single byte")
                .precision(numfmt::Precision::Unspecified),
            small_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .expect("',' is single byte")
                .precision(numfmt::Precision::Significance(4)),
            large_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .expect("',' is single byte")
                .precision(numfmt::Precision::Decimals(0)),
            huge_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .expect("',' is single byte")
                .precision(numfmt::Precision::Significance(4)),
        }
    }

    fn raw_convert(
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
                        self.raw_convert(
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
                        let v = self.raw_convert(*i, input_val, *o, Some(currency))?;
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
