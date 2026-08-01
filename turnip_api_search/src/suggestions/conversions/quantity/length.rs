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
    const TEST_CASES: &'static [(Self, f64, Self, f64)] = &[
        (Self::In, 1.0, Self::Mm, 25.4),
        (Self::Yd, 1.0, Self::In, 36.0),
        (Self::Ft, 1.0, Self::In, 12.0),
        (Self::In, 12.0, Self::FtIn, 1.0),
        (Self::League, 1.0, Self::Mile, 3.0),
        (Self::NauticalLeague, 1.0, Self::NauticalMile, 3.0),
        (Self::NauticalMile, 1.0, Self::M, 1852.0),
        (Self::NauticalMile, 1.0, Self::Ft, 6076.11549),
        (Self::NauticalMile, 1.0, Self::Mile, 1.15078),
        (Self::League, 1.0, Self::Km, 4.83),
        (Self::Furlong, 1.0, Self::Ft, 660.0),
        (Self::Furlong, 1.0, Self::Yd, 220.0),
        (Self::Furlong, 1.0, Self::M, 201.168),
        (Self::Fathom, 1.0, Self::Ft, 6.0),
        (Self::Fathom, 1.0, Self::M, 1.8288),
        (Self::LightYear, 1.0, Self::M, 9.4607E15),
        (Self::LightYear, 1.0, Self::Mile, 5.8786E12),
        (Self::LightYear, 1.0, Self::Au, 63241.0),
        (Self::LightYear, 1.0, Self::Parsec, 0.3066),
        (Self::Cm, 1.0, Self::Mm, 10.0),
        (Self::Mm, 1.0, Self::Um, 1000.0),
        (Self::Um, 1.0, Self::Nm, 1000.0),
        (Self::Nm, 1.0, Self::Pm, 1000.0),
    ];

    const STRS: &'static [(Self, Strs)] = &[
        (
            LengthUnit::Km,
            Strs {
                name: "kilometers",
                suffix: "km",
                mns: &[&["kilometer", "kilometre", "kilometers", "kilometres", "km"]],
            },
        ),
        (
            LengthUnit::M,
            Strs {
                name: "meters",
                suffix: "m",
                mns: &[&["meter", "metre", "meters", "metres", "m"]],
            },
        ),
        (
            LengthUnit::Cm,
            Strs {
                name: "centimeters",
                suffix: "cm",
                mns: &[&[
                    "centimeter",
                    "centimetre",
                    "centimeters",
                    "centimetres",
                    "cm",
                ]],
            },
        ),
        (
            LengthUnit::Mm,
            Strs {
                name: "millimeters",
                suffix: "mm",
                mns: &[&[
                    "millimeter",
                    "millimetre",
                    "millimeters",
                    "millimetres",
                    "mm",
                ]],
            },
        ),
        (
            LengthUnit::Um,
            Strs {
                name: "micrometers",
                suffix: "μm",
                mns: &[&[
                    "micrometer",
                    "micrometre",
                    "micrometers",
                    "micrometres",
                    "micron",
                    "microns",
                    "um",
                    "μm",
                ]],
            },
        ),
        (
            LengthUnit::Nm,
            Strs {
                name: "nanometers",
                suffix: "nm",
                mns: &[&["nanometer", "nanometre", "nanometers", "nanometres", "nm"]],
            },
        ),
        (
            LengthUnit::Pm,
            Strs {
                name: "picometers",
                suffix: "pm",
                mns: &[&["picometer", "picometre", "picometers", "picometres", "pm"]],
            },
        ),
        (
            LengthUnit::In,
            Strs {
                name: "inches",
                suffix: "in",
                mns: &[&["inch", "inches", "inchs", "in", "ins"]],
            },
        ),
        (
            LengthUnit::Ft,
            Strs {
                name: "feet",
                suffix: "ft",
                mns: &[&["foot", "feet", "ft"]],
            },
        ),
        (
            LengthUnit::FtIn,
            Strs {
                name: "feet and inches",
                suffix: "ft/in",
                mns: &[&["foot", "feet", "ft"]],
            },
        ),
        (
            LengthUnit::Yd,
            Strs {
                name: "yards",
                suffix: "yds",
                mns: &[&["yard", "yards", "yd", "yds"]],
            },
        ),
        (
            LengthUnit::Mile,
            Strs {
                name: "miles",
                suffix: " miles",
                mns: &[&["mile", "miles", "mi"]],
            },
        ),
        (
            LengthUnit::League,
            Strs {
                name: "leagues",
                suffix: " leagues",
                mns: &[&["league", "leagues"]],
            },
        ),
        (
            LengthUnit::NauticalMile,
            Strs {
                name: "nautical miles",
                suffix: " nautical miles",
                mns: &[&[
                    "mile",
                    "miles",
                    "nautical mile",
                    "nautical miles",
                    "nmi",
                    "nmis",
                ]],
            },
        ),
        (
            LengthUnit::NauticalLeague,
            Strs {
                name: "nautical leagues",
                suffix: " nautical leagues",
                mns: &[&["league", "leagues", "nautical league", "nautical leagues"]],
            },
        ),
        (
            LengthUnit::Fathom,
            Strs {
                name: "fathoms",
                suffix: " fathoms",
                mns: &[&["fathom", "fathoms"]],
            },
        ),
        (
            LengthUnit::LightYear,
            Strs {
                name: "light years",
                suffix: "ly",
                mns: &[&[
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
                ]],
            },
        ),
        (
            LengthUnit::Au,
            Strs {
                name: "astronomical units",
                suffix: "au",
                mns: &[&["au", "aus", "astronomical unit", "astronomical units"]],
            },
        ),
        (
            LengthUnit::Parsec,
            Strs {
                name: "parsecs",
                suffix: "pc",
                mns: &[&["pc", "pcs", "parsec", "parsecs"]],
            },
        ),
        (
            LengthUnit::Furlong,
            Strs {
                name: "furlongs",
                suffix: "fur",
                mns: &[&["fur", "furs", "furlong", "furlongs"]],
            },
        ),
    ];
}
