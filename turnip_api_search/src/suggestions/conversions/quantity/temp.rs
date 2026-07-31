use strum::VariantArray;

use super::{NumUnitGroup, Strs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
pub enum TempUnit {
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

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[
        (Self::C, 100.0, Self::F, 211.999999),
        (Self::C, 0.0, Self::F, 32.0),
        (Self::K, 273.15, Self::C, 0.0),
        (Self::K, 273.14, Self::C, -0.01),
        (Self::K, 273.13, Self::C, -0.02),
        (Self::F, 50.0, Self::K, 285.15),
    ];

    const STRS: &'static [(Self, Strs)] = &[
        (
            TempUnit::C,
            Strs {
                name: "°C", // degree sign prefix renders better than dedicated degrees-C
                suffix: "°C",
                mns: &[&[
                    "celsius", //
                    "c",       //
                    "°c",      // degree sign prefix
                    "˚c",      // 'ring above' prefix, for permissivity
                    "∘c",      // 'ring operator' prefix, for permissivity
                    "℃",       // dedicated "degrees-C" character
                ]],
            },
        ),
        (
            TempUnit::F,
            Strs {
                name: "°F", // degree sign prefix renders better than dedicated degrees-F
                suffix: "°F",
                mns: &[&[
                    "fahrenheit", //
                    "f",          //
                    "°f",         // degree sign prefix
                    "˚f",         // 'ring above' prefix, for permissivity
                    "∘f",         // 'ring operator' prefix, for permissivity
                    "℉",          // dedicated "degrees-F" character
                ]],
            },
        ),
        (
            TempUnit::K,
            Strs {
                name: "kelvin",
                suffix: "K",
                mns: &[&[
                    "kelvin", //
                    "k",      //
                    "°k",     // degree sign prefix
                    "˚k",     // 'ring above' prefix, for permissivity
                    "∘k",     // 'ring operator' prefix, for permissivity
                              // there is no "degrees-K" character
                ]],
            },
        ),
    ];
}
