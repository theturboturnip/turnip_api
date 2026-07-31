use strum::VariantArray;

use super::{NumUnitGroup, Strs};

macro_rules! sq {
    ($x:expr) => {
        ($x * $x)
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
pub enum AreaUnit {
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

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[];

    const STRS: &'static [(Self, Strs)] = &[];
}
