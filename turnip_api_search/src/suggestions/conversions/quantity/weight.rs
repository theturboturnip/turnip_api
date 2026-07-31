use strum::VariantArray;

use super::{NumUnitGroup, Strs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
pub enum WeightUnit {
    Tonne,
    Kg,
    G,
    Mg,
    Ug,

    /// Avoirdupois Ounce
    Oz,
    /// Avoirdupois Pound
    Lb,
    Stone,

    Grain,
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
            WeightUnit::Grain => (64.79891E-3, 0.0),
            WeightUnit::TroyOz => (31.1034768, 0.0),
            WeightUnit::TroyLb => (31.1034768 * 12.0, 0.0),
            WeightUnit::Carat => (0.2, 0.0),
        }
    }

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[
        (WeightUnit::Tonne, 1.0, WeightUnit::Lb, 2204.6226),
        (WeightUnit::Tonne, 1.0, WeightUnit::Kg, 1000.0),
        (WeightUnit::Kg, 35.0, WeightUnit::Tonne, 0.035),
        (WeightUnit::Kg, 1.0, WeightUnit::G, 1000.0),
        (WeightUnit::Kg, 1.0, WeightUnit::Lb, 2.2046),
        (WeightUnit::Kg, 1.0, WeightUnit::Oz, 35.274),
        (WeightUnit::G, 1.0, WeightUnit::Oz, 0.0352740),
        (WeightUnit::G, 1.0, WeightUnit::Mg, 1_000.0),
        (WeightUnit::G, 1.0, WeightUnit::Ug, 1_000_000.0),
        (WeightUnit::Oz, 1.0, WeightUnit::G, 28.349523125),
        (WeightUnit::Lb, 1.0, WeightUnit::Kg, 0.45359237),
        (WeightUnit::Lb, 1.0, WeightUnit::Oz, 16.0),
        (WeightUnit::Lb, 14.0, WeightUnit::Stone, 1.0),
        (WeightUnit::Stone, 1.0, WeightUnit::Kg, 6.350),
        (WeightUnit::TroyLb, 1.0, WeightUnit::G, 373.24172),
        (WeightUnit::TroyOz, 1.0, WeightUnit::G, 31.10347680),
        (WeightUnit::Grain, 1.0, WeightUnit::Mg, 64.79891),
        (WeightUnit::Grain, 7000.0, WeightUnit::Lb, 1.0),
        (WeightUnit::Lb, 1.0, WeightUnit::Grain, 7000.0),
        (WeightUnit::Grain, 5760.0, WeightUnit::TroyLb, 1.0),
        (WeightUnit::Carat, 1.0, WeightUnit::Mg, 200.0),
        (WeightUnit::Carat, 1.0, WeightUnit::Oz, 0.00705),
        (WeightUnit::Carat, 1.0, WeightUnit::TroyOz, 0.00643),
        (WeightUnit::G, 1.0, WeightUnit::Carat, 5.0),
    ];

    const STRS: &'static [(Self, Strs)] = &[
        (
            WeightUnit::Tonne,
            Strs {
                name: "tonnes",
                suffix: "t",
                mns: &[&[
                    "ton",
                    "tons",
                    "tonne",
                    "tonnes",
                    "metric ton",
                    "metric tons",
                    "t",
                ]],
            },
        ),
        (
            WeightUnit::Kg,
            Strs {
                name: "kilograms",
                suffix: "kg",
                mns: &[&[
                    "kilogram",
                    "kilograms",
                    "kilogramme",
                    "kilogrammes",
                    "kg",
                    "kgs",
                    "kilos",
                    "kilo",
                ]],
            },
        ),
        (
            WeightUnit::G,
            Strs {
                name: "grams",
                suffix: "g",
                mns: &[&["gram", "grams", "gramme", "grammes", "g", "gs"]],
            },
        ),
        (
            WeightUnit::Mg,
            Strs {
                name: "milligrams",
                suffix: "mg",
                mns: &[&[
                    "milligram",
                    "milligrams",
                    "milligramme",
                    "milligrammes",
                    "mg",
                    "mgs",
                ]],
            },
        ),
        (
            WeightUnit::Ug,
            Strs {
                name: "micrograms",
                suffix: "μg",
                mns: &[&["microgram", "micrograms", "ug", "μg"]],
            },
        ),
        (
            WeightUnit::Oz,
            Strs {
                name: "ounces",
                suffix: "oz",
                mns: &[&["ounce", "ounces", "℥", "oz", "ozs", "avoirdupois ounce"]],
            },
        ),
        (
            WeightUnit::Lb,
            Strs {
                name: "pounds",
                suffix: "lb",
                mns: &[&[
                    "pound",
                    "pounds",
                    "lb",
                    "lbs",
                    "#",
                    "lbm",
                    "℔",
                    "″̶",
                    "avoirdupois pound",
                ]],
            },
        ),
        (
            WeightUnit::Stone,
            Strs {
                name: "stone",
                suffix: "st",
                mns: &[&["stone", "stones", "st"]],
            },
        ),
        (
            WeightUnit::Grain,
            Strs {
                name: "grain",
                suffix: "gr",
                mns: &[&["grain", "grains", "gr"]],
            },
        ),
        // (WeightUnit::Pennyweight, Strs { name: "", suffix: "", mns: &[&[]] }),
        // (WeightUnit::Hundredweight, Strs { name: "", suffix: "", mns: &[&[]] }),
        (
            WeightUnit::TroyOz,
            Strs {
                name: "troy ounces",
                suffix: " troy ounces",
                mns: &[&[
                    "troy",
                    "troy ounce",
                    "troy ounces",
                    "oz t",
                    "ounce",
                    "ounces",
                    "℥",
                    "oz",
                    "ozs",
                ]],
            },
        ),
        (
            WeightUnit::TroyLb,
            Strs {
                name: "troy pounds",
                suffix: " troy pounds",
                mns: &[&[
                    "troy",
                    "troy pound",
                    "troy pounds",
                    "lb t",
                    "pound",
                    "pounds",
                    "lb",
                    "lbs",
                    "#",
                    "lbm",
                    "℔",
                    "″̶",
                ]],
            },
        ),
        (
            WeightUnit::Carat,
            Strs {
                name: "carat",
                suffix: "ct",
                mns: &[&["carat", "carats", "ct", "cts"]],
            },
        ),
    ];
}
