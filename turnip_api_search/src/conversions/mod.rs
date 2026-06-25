use arrayvec::{ArrayString, ArrayVec};
use fnv::FnvHashMap;

enum Value {
    Number(f64),
    // Time,
    // TimeAndDate,
}

enum NumberUnit {
    Length(LengthUnit),
    Currency(ArrayString<3>),
    // ...
}

trait NumUnitGroup {
    // for (x, y) base_unit = (val * x) + y
    fn of_base(self) -> (f64, f64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LengthUnit {
    Km,
    M,
    Cm,
    Mm,
    In,
    Ft,
    FtIn,
    Miles,
    NauticalMiles,
    Yards,
}
impl NumUnitGroup for LengthUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            LengthUnit::Km => (10_000.0, 0.0),
            LengthUnit::M => (1.0, 0.0),
            LengthUnit::Cm => (0.01, 0.0),
            LengthUnit::Mm => (0.001, 0.0),
            LengthUnit::In => (0.0254, 0.0),
            LengthUnit::Ft | LengthUnit::FtIn => (0.3048, 0.0),
            LengthUnit::Miles => (1609.344, 0.0),
            LengthUnit::NauticalMiles => (1852.0, 0.0),
            LengthUnit::Yards => (0.9144, 0.0),
        }
    }
}

type NumberUnits = ArrayVec<NumberUnit, 15>;

type NumberUnitStr = ArrayString<15>;

struct Conversion {
    input_unit: NumberUnit,
    input_val: Value,
    output_unit: NumberUnit,
    output_val: Value,
}

macro_rules! basic_conv {
    ($i:expr, $o:expr, $val:expr) => {{
        let (ia, ib) = $i.of_base();
        let (oa, ob) = $o.of_base();
        $val * (ia / oa) + ((ib - ob) / oa)
    }};
}

struct ConversionCtx {
    str_to_num_unit: FnvHashMap<NumberUnitStr, NumberUnits>,
    num_unit_targets: FnvHashMap<NumberUnit, NumberUnits>,

    currencies_to_usd: FnvHashMap<ArrayString<3>, f64>,
}
impl ConversionCtx {
    const fn new() -> Self {
        let mut str_to_num_unit = FnvHashMap::new();
    }

    fn attempt_convert(
        &self,
        input_unit: NumberUnit,
        input_val: Value,
        output_unit: NumberUnit,
    ) -> Option<f64> {
        use NumberUnit::*;
        if let Value::Number(val) = input_val {
            let o_val = match (input_unit, output_unit) {
                (Length(i), Length(o)) => basic_conv!(i, o, val),
                (Currency(i), Currency(o)) => {
                    let i_to_usd = self.currencies_to_usd.get(&i)?;
                    let o_to_usd = self.currencies_to_usd.get(&o)?;
                    val * i_to_usd / o_to_usd
                }
                _ => return None,
            };
            Some(o_val)
        } else {
            None // TODO
        }
    }

    fn attempt_conversions(
        &self,
        input_unit: &str,
        input_val: Value,
        output_unit: &str,
    ) -> Vec<Conversion> {
    }
}

fn possible_num_units(input_unit: &str) -> Vec<NumberUnit>;

fn possible_num_conversions(
    possible_input_units: &[NumberUnit],
    output_unit: &str,
) -> Vec<(NumberUnit, NumberUnit)>;

mod currency;
mod quantity;
// mod timezone;
