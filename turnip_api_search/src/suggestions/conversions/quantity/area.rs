use strum::VariantArray;

use super::{NumUnitGroup, Strs};

macro_rules! sq {
    ($x:expr) => {
        ($x * $x)
    };
}

macro_rules! sq_text {
    ($x:literal) => {
        [
            concat!("square ", $x),
            concat!("sq ", $x),
            concat!("sq. ", $x),
            concat!($x, "2"),
            concat!($x, " 2"),
            concat!($x, "^2"),
            concat!($x, "²"),
            concat!($x, " ²"),
            concat!($x, "/-2"),
        ]
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
    // Actually, don't bother with this. They are almost identical.
    // SurveyFt2,
    // SurveyMile2,
    // SurveyAcre,
}
impl NumUnitGroup for AreaUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            AreaUnit::Km2 => (1E6, 0.0),
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
            AreaUnit::Acre => (4046.8564224, 0.0),
            // AreaUnit::SurveyMile2 => todo!(),
            // AreaUnit::SurveyFt2 => todo!(),
            // AreaUnit::SurveyAcre => todo!(),
        }
    }

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[
        (Self::Km2, 1.0, Self::M2, 1_000_000.0),
        (Self::Km2, 1.0, Self::Hectare, 100.0),
        (Self::Km2, 2.5899, Self::Mile2, 1.0),
        (Self::Km2, 1.0, Self::Acre, 247.1),
        (Self::Acre, 1.0, Self::Mile2, 1.0 / 640.0),
        (Self::Acre, 1.0, Self::Yd2, 4840.0),
        (Self::Acre, 1.0, Self::Ft2, 43560.0),
        (Self::Ft2, 1.0, Self::In2, 144.0),
        (Self::Ft2, 1.0, Self::Yd2, 0.1111),
        (Self::Ft2, 1.0, Self::Cm2, 929.0304),
        (Self::Cm2, 1.0, Self::Mm2, 10_0.0),
        (Self::Mm2, 1.0, Self::Um2, 1000_000.0),
        (Self::Um2, 1.0, Self::Nm2, 1000_000.0),
        (Self::Nm2, 1.0, Self::Pm2, 1000_000.0),
    ];

    const STRS: &'static [(Self, Strs)] = &[
        (
            AreaUnit::Km2,
            Strs {
                name: "sq kilometers",
                suffix: "km²",
                mns: &[
                    &sq_text!("kilometer"),
                    &sq_text!("kilometre"),
                    &sq_text!("kilometers"),
                    &sq_text!("kilometres"),
                    &sq_text!("km"),
                ],
            },
        ),
        (
            AreaUnit::M2,
            Strs {
                name: "sq meters",
                suffix: "m²",
                mns: &[
                    &sq_text!("meter"),
                    &sq_text!("metre"),
                    &sq_text!("meters"),
                    &sq_text!("metres"),
                    &sq_text!("m"),
                ],
            },
        ),
        (
            AreaUnit::Cm2,
            Strs {
                name: "sq centimeters",
                suffix: "cm²",
                mns: &[
                    &sq_text!("centimeter"),
                    &sq_text!("centimetre"),
                    &sq_text!("centimeters"),
                    &sq_text!("centimetres"),
                    &sq_text!("cm"),
                ],
            },
        ),
        (
            AreaUnit::Mm2,
            Strs {
                name: "sq millimeters",
                suffix: "mm²",
                mns: &[
                    &sq_text!("millimeter"),
                    &sq_text!("millimetre"),
                    &sq_text!("millimeters"),
                    &sq_text!("millimetres"),
                    &sq_text!("mm"),
                ],
            },
        ),
        (
            AreaUnit::Um2,
            Strs {
                name: "sq micrometers",
                suffix: "μm²",
                mns: &[
                    &sq_text!("micrometer"),
                    &sq_text!("micrometre"),
                    &sq_text!("micrometers"),
                    &sq_text!("micrometres"),
                    &sq_text!("micron"),
                    &sq_text!("microns"),
                    &sq_text!("um"),
                    &sq_text!("μm"),
                ],
            },
        ), // aka micrometer aka micron
        (
            AreaUnit::Nm2,
            Strs {
                name: "sq nanometers",
                suffix: "nm²",
                mns: &[
                    &sq_text!("nanometer"),
                    &sq_text!("nanometre"),
                    &sq_text!("nanometers"),
                    &sq_text!("nanometres"),
                    &sq_text!("nm"),
                ],
            },
        ),
        (
            AreaUnit::Pm2,
            Strs {
                name: "sq picometers",
                suffix: "pm²",
                mns: &[
                    &sq_text!("picometer"),
                    &sq_text!("picometre"),
                    &sq_text!("picometers"),
                    &sq_text!("picometres"),
                    &sq_text!("pm"),
                ],
            },
        ),
        (
            AreaUnit::In2,
            Strs {
                name: "sq inches",
                suffix: " sq in",
                mns: &[
                    &sq_text!("inch"),
                    &sq_text!("inches"),
                    &sq_text!("inchs"),
                    &sq_text!("in"),
                    &sq_text!("ins"),
                ],
            },
        ),
        (
            AreaUnit::Ft2,
            Strs {
                name: "sq feet",
                suffix: " sq ft",
                mns: &[&sq_text!("foot"), &sq_text!("feet"), &sq_text!("ft")],
            },
        ),
        (
            AreaUnit::Yd2,
            Strs {
                name: "sq yards",
                suffix: " sq yds",
                mns: &[
                    &sq_text!("yard"),
                    &sq_text!("yards"),
                    &sq_text!("yd"),
                    &sq_text!("yds"),
                ],
            },
        ),
        (
            AreaUnit::Mile2,
            Strs {
                name: "sq miles",
                suffix: " sq mi",
                mns: &[&sq_text!("mile"), &sq_text!("miles"), &sq_text!("mi")],
            },
        ),
        (
            AreaUnit::Hectare,
            Strs {
                name: "",
                suffix: "",
                mns: &[&["ha", "hectare", "hectares"]],
            },
        ),
        (
            AreaUnit::Acre,
            Strs {
                name: "acres",
                suffix: " acres",
                mns: &[&["acre", "acres", "ac"]],
            },
        ),
        // (
        //     AreaUnit::SurveyFt2,
        //     Strs {
        //         name: "hectares",
        //         suffix: " ha",
        //         mns: &[],
        //     },
        // ),
        // (
        //     AreaUnit::SurveyMile2,
        //     Strs {
        //         name: "",
        //         suffix: "",
        //         mns: &[],
        //     },
        // ),
        // (
        //     AreaUnit::SurveyAcre,
        //     Strs {
        //         name: "",
        //         suffix: "",
        //         mns: &[],
        //     },
        // ),
    ];
}
