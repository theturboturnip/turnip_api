#[cfg(test)]
use approx::assert_relative_eq;
use arrayvec::ArrayVec;
use fnv::FnvHashMap;
use smol_str::SmolStr;
use std::sync::RwLock;
use strum::VariantArray;

use super::{
    Conversion,
    currency::{CURRENCIES, CURRENCY_PREFIXES, CurrencyCtx, CurrencyStr},
};

mod area;
mod length;
mod temp;
mod time;
mod volume;
mod weight;

use {area::AreaUnit, length::LengthUnit, temp::TempUnit, time::TimeUnit, weight::WeightUnit};

/// Metadata for a unit: the long name, the short suffix, and various mnemonics that a user can type to associate with this unit
struct Strs {
    name: &'static str,
    suffix: &'static str,
    /// mnemonics that a user can type to associate with this unit
    mns: &'static [&'static [&'static str]],
}

trait NumUnitGroup:
    std::fmt::Debug + Clone + Copy + PartialEq + Eq + std::hash::Hash + 'static + VariantArray
{
    /// Express the conversion of units in 'self' to units in 'base' as (x, y) where `base_unit = (self * x) + y`
    fn of_base(self) -> (f64, f64);

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)];

    const STRS: &'static [(Self, Strs)];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NumUnit {
    Length(LengthUnit),
    Area(AreaUnit),
    // TODO Volume(VolumeUnit),
    Temp(TempUnit),
    Time(TimeUnit),
    Weight(WeightUnit),
    // This is just a string, separate from the other types. Don't need to compile-time enumerate all the currencies.
    Currency(CurrencyStr),
    // ...
}

#[cfg(test)]
mod tests {
    macro_rules! define_group_tests {
        ($p:ident, $con:expr, $t:ty) => {
            mod $p {
                use super::super::*;

                #[test]
                fn test_all_units_stringed() {
                    let stringed = <$t as NumUnitGroup>::STRS
                        .iter()
                        .map(|(u, _s)| *u)
                        .collect::<Vec<_>>();

                    let unstringed_variants = <$t as VariantArray>::VARIANTS
                        .into_iter()
                        .filter_map(|us| match stringed.iter().find(|u| *u == us) {
                            Some(_) => None,
                            None => Some(us),
                        })
                        .collect::<Vec<_>>();
                    if unstringed_variants.len() > 0 {
                        panic!("STRS didn't string variants {:?}", unstringed_variants);
                    }
                }

                #[test]
                fn test_unit_conversions() {
                    let mut tested_out = [false; <$t as VariantArray>::VARIANTS.len()];

                    let ctx = QuantityCtx::new();

                    for (ui, vi, uo, vo) in <$t as NumUnitGroup>::TEST_CASES {
                        let actual_vo = ctx.raw_convert($con(*ui), *vi, $con(*uo), None);
                        assert!(actual_vo.is_some());
                        assert_relative_eq!(actual_vo.unwrap(), *vo, max_relative = 0.001);

                        let actual_vi = ctx.raw_convert($con(*uo), *vo, $con(*ui), None);
                        assert!(actual_vi.is_some());
                        assert_relative_eq!(actual_vi.unwrap(), *vi, max_relative = 0.001);

                        tested_out[<$t as VariantArray>::VARIANTS
                            .iter()
                            .position(|u| *u == *uo)
                            .unwrap()] = true;

                        tested_out[<$t as VariantArray>::VARIANTS
                            .iter()
                            .position(|u| *u == *ui)
                            .unwrap()] = true;
                    }

                    let untested_variants = tested_out
                        .into_iter()
                        .enumerate()
                        .filter_map(|(i, b)| {
                            if b {
                                None
                            } else {
                                Some(<$t as VariantArray>::VARIANTS[i])
                            }
                        })
                        .collect::<Vec<_>>();
                    if untested_variants.len() > 0 {
                        panic!(
                            "TEST_CASES didn't test variants {:?} as conversion outputs",
                            untested_variants
                        );
                    }
                }
            }
        };
    }

    define_group_tests!(length, NumUnit::Length, LengthUnit);
    define_group_tests!(area, NumUnit::Area, AreaUnit);
    // define_group_tests!(volume, VolumeUnit);
    define_group_tests!(temp, NumUnit::Temp, TempUnit);
    define_group_tests!(time, NumUnit::Time, TimeUnit);
    define_group_tests!(weight, NumUnit::Weight, WeightUnit);
}

type NumberUnits = ArrayVec<NumUnit, 15>;

type NumberUnitStr = SmolStr;

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
                    for s in s.mns.into_iter().map(|slice| slice.into_iter()).flatten() {
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
        // basic_unit_suffixes!(NumUnit::Volume, VolumeUnit);
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
        macro_rules! basic_conv {
            ($i:expr, $o:expr) => {{
                let (ia, ib) = $i.of_base();
                let (oa, ob) = $o.of_base();
                val * (ia / oa) + ((ob - ib) / oa)
            }};
        }

        let o_val = match (input_unit, output_unit) {
            (Length(i), Length(o)) => basic_conv!(i, o),
            (Area(i), Area(o)) => basic_conv!(i, o),
            // (Volume(i), Volume(o)) => basic_conv!(i, o),
            (Temp(i), Temp(o)) => basic_conv!(i, o),
            (Time(i), Time(o)) => basic_conv!(i, o),
            (Weight(i), Weight(o)) => basic_conv!(i, o),
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
