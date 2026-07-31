use strum::VariantArray;

use super::{NumUnitGroup, Strs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, VariantArray)]
pub enum LengthUnit {
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

    #[cfg(test)]
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[];

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
