use strum::VariantArray;

use super::{NumUnitGroup, Strs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
pub enum WeightUnit {
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
