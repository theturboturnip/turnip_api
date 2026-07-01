use arrayvec::{ArrayString, ArrayVec};
use fnv::FnvHashMap;
use smol_str::{SmolStr, StrExt};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Date {
    y: u16,
    m: u8,
    d: u8,
}
impl From<(u16, u8, u8)> for Date {
    fn from(value: (u16, u8, u8)) -> Self {
        Self {
            y: value.0,
            m: value.1,
            d: value.2,
        }
    }
}
impl From<jiff::civil::Date> for Date {
    fn from(value: jiff::civil::Date) -> Self {
        Self {
            y: value
                .year()
                .try_into()
                .expect("I don't expect to handle negative years"),
            m: value.month().try_into().unwrap(),
            d: value.day().try_into().unwrap(),
        }
    }
}
impl TryFrom<Date> for jiff::civil::Date {
    type Error = jiff::Error;

    fn try_from(value: Date) -> Result<Self, Self::Error> {
        Self::new(
            value.y.try_into().map_err(|e| {
                jiff::Error::from_args(format_args!("Year conv fail {:?} {}", value, e))
            })?,
            value.m.try_into().map_err(|e| {
                jiff::Error::from_args(format_args!("Month conv fail {:?} {}", value, e))
            })?,
            value.d.try_into().map_err(|e| {
                jiff::Error::from_args(format_args!("Day conv fail {:?} {}", value, e))
            })?,
        )
    }
}
/// 24-hour time, not validated - could produce invalid times like 80:80
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Time {
    h: u8,
    m: u8,
}
impl From<(u8, u8)> for Time {
    fn from(value: (u8, u8)) -> Self {
        Self {
            h: value.0,
            m: value.1,
        }
    }
}
/// Note: ignores seconds, nanoseconds
impl From<jiff::civil::Time> for Time {
    fn from(value: jiff::civil::Time) -> Self {
        Self {
            // Both guaranteed to never panic, jiff guarantees good ranges for both
            h: value.hour().try_into().unwrap(),
            m: value.minute().try_into().unwrap(),
        }
    }
}
impl TryFrom<Time> for jiff::civil::Time {
    type Error = jiff::Error;

    fn try_from(value: Time) -> Result<Self, Self::Error> {
        Self::new(
            value.h.try_into().map_err(|e| {
                jiff::Error::from_args(format_args!("Hour conv fail {:?} {}", value, e))
            })?,
            value.m.try_into().map_err(|e| {
                jiff::Error::from_args(format_args!("Minute conv fail {:?} {}", value, e))
            })?,
            0,
            0,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    Number(f64),
    Time(Time, Option<Date>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NumUnit {
    Length(LengthUnit),
    Currency(ArrayString<3>),
    // ...
}

trait NumUnitGroup {
    // for (x, y) base_unit = (val * x) + y
    fn of_base(self) -> (f64, f64);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    Mile,
    NauticalMile,
    Yd,
}
impl NumUnitGroup for LengthUnit {
    fn of_base(self) -> (f64, f64) {
        match self {
            LengthUnit::Km => (10_000.0, 0.0),
            LengthUnit::M => (1.0, 0.0),
            LengthUnit::Cm => (1E-2, 0.0),
            LengthUnit::Mm => (1E-3, 0.0),
            LengthUnit::Um => (1E-6, 0.0),
            LengthUnit::Nm => (1E-9, 0.0),
            LengthUnit::Pm => (1E-12, 0.0),
            LengthUnit::In => (0.0254, 0.0),
            LengthUnit::Ft | LengthUnit::FtIn => (0.3048, 0.0),
            LengthUnit::Mile => (1609.344, 0.0),
            LengthUnit::NauticalMile => (1852.0, 0.0),
            LengthUnit::Yd => (0.9144, 0.0),
        }
    }
}

type NumberUnits = ArrayVec<NumUnit, 15>;

type NumberUnitStr = SmolStr;

enum InternalConversion {
    Number {
        input_unit: NumUnit,
        output_unit: NumUnit,
        input_val: f64,
        output_val: f64,
    },
    DateTime {
        input_unit: NumUnit,
        output_unit: NumUnit,
        input_val: (Date, Time),
        output_val: (Date, Time),
    },
}

pub enum Conversion {
    Number(String),
    DateTime(String),
}

macro_rules! basic_conv {
    ($i:expr, $o:expr, $val:expr) => {{
        let (ia, ib) = $i.of_base();
        let (oa, ob) = $o.of_base();
        $val * (ia / oa) + ((ib - ob) / oa)
    }};
}

/// From <https://openexchangerates.org/api/currencies.json>
const CURRENCIES: [(&str, &str); 173] = [
    ("AED", "United Arab Emirates Dirham"),
    ("AFN", "Afghan Afghani"),
    ("ALL", "Albanian Lek"),
    ("AMD", "Armenian Dram"),
    ("ANG", "Netherlands Antillean Guilder"),
    ("AOA", "Angolan Kwanza"),
    ("ARS", "Argentine Peso"),
    ("AUD", "Australian Dollar"),
    ("AWG", "Aruban Florin"),
    ("AZN", "Azerbaijani Manat"),
    ("BAM", "Bosnia-Herzegovina Convertible Mark"),
    ("BBD", "Barbadian Dollar"),
    ("BDT", "Bangladeshi Taka"),
    ("BGN", "Bulgarian Lev"),
    ("BHD", "Bahraini Dinar"),
    ("BIF", "Burundian Franc"),
    ("BMD", "Bermudan Dollar"),
    ("BND", "Brunei Dollar"),
    ("BOB", "Bolivian Boliviano"),
    ("BRL", "Brazilian Real"),
    ("BSD", "Bahamian Dollar"),
    ("BTC", "Bitcoin"),
    ("BTN", "Bhutanese Ngultrum"),
    ("BWP", "Botswanan Pula"),
    ("BYN", "Belarusian Ruble"),
    ("BZD", "Belize Dollar"),
    ("CAD", "Canadian Dollar"),
    ("CDF", "Congolese Franc"),
    ("CHF", "Swiss Franc"),
    ("CLF", "Chilean Unit of Account (UF)"),
    ("CLP", "Chilean Peso"),
    ("CNH", "Chinese Yuan (Offshore)"),
    ("CNY", "Chinese Yuan"),
    ("COP", "Colombian Peso"),
    ("CRC", "Costa Rican Colón"),
    ("CUC", "Cuban Convertible Peso"),
    ("CUP", "Cuban Peso"),
    ("CVE", "Cape Verdean Escudo"),
    ("CZK", "Czech Republic Koruna"),
    ("DJF", "Djiboutian Franc"),
    ("DKK", "Danish Krone"),
    ("DOP", "Dominican Peso"),
    ("DZD", "Algerian Dinar"),
    ("EGP", "Egyptian Pound"),
    ("ERN", "Eritrean Nakfa"),
    ("ETB", "Ethiopian Birr"),
    ("EUR", "Euro"),
    ("FJD", "Fijian Dollar"),
    ("FKP", "Falkland Islands Pound"),
    ("GBP", "British Pound Sterling"),
    ("GEL", "Georgian Lari"),
    ("GGP", "Guernsey Pound"),
    ("GHS", "Ghanaian Cedi"),
    ("GIP", "Gibraltar Pound"),
    ("GMD", "Gambian Dalasi"),
    ("GNF", "Guinean Franc"),
    ("GTQ", "Guatemalan Quetzal"),
    ("GYD", "Guyanaese Dollar"),
    ("HKD", "Hong Kong Dollar"),
    ("HNL", "Honduran Lempira"),
    ("HRK", "Croatian Kuna"),
    ("HTG", "Haitian Gourde"),
    ("HUF", "Hungarian Forint"),
    ("IDR", "Indonesian Rupiah"),
    ("ILS", "Israeli New Shekel"),
    ("IMP", "Manx pound"),
    ("INR", "Indian Rupee"),
    ("IQD", "Iraqi Dinar"),
    ("IRR", "Iranian Rial"),
    ("ISK", "Icelandic Króna"),
    ("JEP", "Jersey Pound"),
    ("JMD", "Jamaican Dollar"),
    ("JOD", "Jordanian Dinar"),
    ("JPY", "Japanese Yen"),
    ("KES", "Kenyan Shilling"),
    ("KGS", "Kyrgystani Som"),
    ("KHR", "Cambodian Riel"),
    ("KMF", "Comorian Franc"),
    ("KPW", "North Korean Won"),
    ("KRW", "South Korean Won"),
    ("KWD", "Kuwaiti Dinar"),
    ("KYD", "Cayman Islands Dollar"),
    ("KZT", "Kazakhstani Tenge"),
    ("LAK", "Laotian Kip"),
    ("LBP", "Lebanese Pound"),
    ("LKR", "Sri Lankan Rupee"),
    ("LRD", "Liberian Dollar"),
    ("LSL", "Lesotho Loti"),
    ("LYD", "Libyan Dinar"),
    ("MAD", "Moroccan Dirham"),
    ("MDL", "Moldovan Leu"),
    ("MGA", "Malagasy Ariary"),
    ("MKD", "Macedonian Denar"),
    ("MMK", "Myanma Kyat"),
    ("MNT", "Mongolian Tugrik"),
    ("MOP", "Macanese Pataca"),
    ("MRU", "Mauritanian Ouguiya"),
    ("MUR", "Mauritian Rupee"),
    ("MVR", "Maldivian Rufiyaa"),
    ("MWK", "Malawian Kwacha"),
    ("MXN", "Mexican Peso"),
    ("MYR", "Malaysian Ringgit"),
    ("MZN", "Mozambican Metical"),
    ("NAD", "Namibian Dollar"),
    ("NGN", "Nigerian Naira"),
    ("NIO", "Nicaraguan Córdoba"),
    ("NOK", "Norwegian Krone"),
    ("NPR", "Nepalese Rupee"),
    ("NZD", "New Zealand Dollar"),
    ("OMR", "Omani Rial"),
    ("PAB", "Panamanian Balboa"),
    ("PEN", "Peruvian Nuevo Sol"),
    ("PGK", "Papua New Guinean Kina"),
    ("PHP", "Philippine Peso"),
    ("PKR", "Pakistani Rupee"),
    ("PLN", "Polish Zloty"),
    ("PYG", "Paraguayan Guarani"),
    ("QAR", "Qatari Rial"),
    ("RON", "Romanian Leu"),
    ("RSD", "Serbian Dinar"),
    ("RUB", "Russian Ruble"),
    ("RWF", "Rwandan Franc"),
    ("SAR", "Saudi Riyal"),
    ("SBD", "Solomon Islands Dollar"),
    ("SCR", "Seychellois Rupee"),
    ("SDG", "Sudanese Pound"),
    ("SEK", "Swedish Krona"),
    ("SGD", "Singapore Dollar"),
    ("SHP", "Saint Helena Pound"),
    ("SLE", "Sierra Leonean Leone"),
    ("SLL", "Sierra Leonean Leone (Old)"),
    ("SOS", "Somali Shilling"),
    ("SRD", "Surinamese Dollar"),
    ("SSP", "South Sudanese Pound"),
    ("STD", "São Tomé and Príncipe Dobra (pre-2018)"),
    ("STN", "São Tomé and Príncipe Dobra"),
    ("SVC", "Salvadoran Colón"),
    ("SYP", "Syrian Pound"),
    ("SZL", "Swazi Lilangeni"),
    ("THB", "Thai Baht"),
    ("TJS", "Tajikistani Somoni"),
    ("TMT", "Turkmenistani Manat"),
    ("TND", "Tunisian Dinar"),
    ("TOP", "Tongan Pa'anga"),
    ("TRY", "Turkish Lira"),
    ("TTD", "Trinidad and Tobago Dollar"),
    ("TWD", "New Taiwan Dollar"),
    ("TZS", "Tanzanian Shilling"),
    ("UAH", "Ukrainian Hryvnia"),
    ("UGX", "Ugandan Shilling"),
    ("USD", "United States Dollar"),
    ("UYU", "Uruguayan Peso"),
    ("UZS", "Uzbekistan Som"),
    ("VEF", "Venezuelan Bolívar Fuerte (Old)"),
    ("VES", "Venezuelan Bolívar Soberano"),
    ("VND", "Vietnamese Dong"),
    ("VUV", "Vanuatu Vatu"),
    ("WST", "Samoan Tala"),
    ("XAF", "CFA Franc BEAC"),
    ("XAG", "Silver Ounce"),
    ("XAU", "Gold Ounce"),
    ("XCD", "East Caribbean Dollar"),
    ("XCG", "Caribbean Guilder"),
    ("XDR", "Special Drawing Rights"),
    ("XOF", "CFA Franc BCEAO"),
    ("XPD", "Palladium Ounce"),
    ("XPF", "CFP Franc"),
    ("XPT", "Platinum Ounce"),
    ("YER", "Yemeni Rial"),
    ("ZAR", "South African Rand"),
    ("ZMW", "Zambian Kwacha"),
    ("ZWG", "Zimbabwean ZiG"),
    ("ZWL", "Zimbabwean Dollar"),
];
const CURRENCY_PREFIXES: [(char, &str); 3] = [('$', "USD"), ('£', "GBP"), ('€', "EUR")];

pub struct ConversionCtx {
    str_to_num_unit: FnvHashMap<NumberUnitStr, NumberUnits>,
    num_unit_to_suffix: FnvHashMap<NumUnit, String>,
    num_unit_to_name: FnvHashMap<NumUnit, String>,

    currencies_to_usd: FnvHashMap<ArrayString<3>, f64>,

    input_formatter: numfmt::Formatter,
    small_formatter: numfmt::Formatter,
    large_formatter: numfmt::Formatter,
    huge_formatter: numfmt::Formatter,
}
impl ConversionCtx {
    pub fn new() -> Self {
        let mut str_to_num_unit = FnvHashMap::default();
        let mut num_unit_to_name = FnvHashMap::default();
        let mut num_unit_to_suffix = FnvHashMap::default();

        use LengthUnit::*;
        use NumUnit::*;
        let mut basic_unit_suffix = |unit, name: &str, suffix: &str, parsers: &[&str]| {
            num_unit_to_name
                .entry(unit)
                .insert_entry(format!("{}", name));
            num_unit_to_suffix
                .entry(unit)
                .insert_entry(format!("{}", suffix));
            for s in parsers {
                str_to_num_unit
                    .entry(NumberUnitStr::from(*s))
                    .or_insert_with(NumberUnits::new)
                    .push(unit);
            }
        };
        basic_unit_suffix(
            Length(Km),
            "kilometers",
            "km",
            &["kilometer", "kilometre", "kilometers", "kilometres", "km"],
        );
        basic_unit_suffix(
            Length(M),
            "meters",
            "m",
            &["meter", "metre", "meters", "metres", "m"],
        );
        basic_unit_suffix(
            Length(Cm),
            "centimeters",
            "cm",
            &[
                "centimeter",
                "centimetre",
                "centimeters",
                "centimetres",
                "cm",
            ],
        );
        basic_unit_suffix(
            Length(Mm),
            "millimeters",
            "mm",
            &[
                "millimeter",
                "millimetre",
                "millimeters",
                "millimetres",
                "mm",
            ],
        );
        basic_unit_suffix(
            Length(Um),
            "micrometers",
            "μm",
            &[
                "micrometer",
                "micrometre",
                "micrometers",
                "micrometres",
                "um",
                "μm",
            ],
        );
        basic_unit_suffix(
            Length(Nm),
            "nanometers",
            "nm",
            &["nanometer", "nanometre", "nanometers", "nanometres", "nm"],
        );
        basic_unit_suffix(
            Length(Pm),
            "picometers",
            "pm",
            &["picometer", "picometre", "picometers", "picometres", "pm"],
        );
        basic_unit_suffix(
            Length(In),
            "inches",
            "in",
            &["inch", "inches", "inchs", "in"],
        );
        basic_unit_suffix(Length(Ft), "feet", "ft", &["foot", "feet", "ft"]);
        basic_unit_suffix(
            Length(FtIn),
            "feet and inches",
            "ft/in",
            &["foot", "feet", "ft"],
        );
        basic_unit_suffix(Length(Mile), "miles", " miles", &["mile", "miles"]);
        basic_unit_suffix(
            Length(NauticalMile),
            "nautical miles",
            " nautical miles",
            &["nautical mile", "nautical miles"],
        );
        basic_unit_suffix(Length(Yd), "yds", " yards", &["yard", "yards", "yd", "yds"]);

        for (currency_str, _currency_written) in CURRENCIES {
            let unit = Currency(ArrayString::from(currency_str).unwrap());

            str_to_num_unit
                .entry(NumberUnitStr::from(currency_str))
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
            let unit = Currency(ArrayString::from(currency_str).unwrap());
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
            currencies_to_usd: FnvHashMap::default(),

            input_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Unspecified),
            small_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Significance(4)),
            large_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Decimals(0)),
            huge_formatter: numfmt::Formatter::new()
                .scales(numfmt::Scales::none())
                .comma(false)
                .separator(',')
                .unwrap()
                .precision(numfmt::Precision::Significance(4)),
        }
    }

    fn attempt_convert(&self, input_unit: NumUnit, val: f64, output_unit: NumUnit) -> Option<f64> {
        use NumUnit::*;
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
    }

    fn render_conversion(&self, conv: InternalConversion) -> Option<Conversion> {
        match conv {
            InternalConversion::Number {
                input_unit,
                output_unit,
                input_val,
                output_val,
            } => {
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
                        self.attempt_convert(
                            NumUnit::Length(LengthUnit::Ft),
                            output_val.fract(),
                            NumUnit::Length(LengthUnit::In)
                        )
                        .expect("Ft->In should never fail")
                    ),
                    _ => {
                        // TODO format with scientific 4sig-figs if <0.001 or >1E10, to 4sig-figs if <10_000, and rounded to integer otherwise
                        // This is a personal heuristic.
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

                Some(Conversion::Number(format!(
                    "{} in {} = {}",
                    input_str,
                    self.num_unit_to_name.get(&output_unit).or_else(|| {
                        log::error!("No name for unit {:?}", output_unit);
                        None
                    })?,
                    output_str
                )))
            }
            InternalConversion::DateTime {
                input_unit,
                output_unit,
                input_val: (input_date, input_time),
                output_val: (output_date, output_time),
            } => return None, // TODO
        }
    }

    pub fn parse_and_convert(&self, query: &str) -> Option<Vec<Conversion>> {
        let (input_val, input_unit, output_unit) = parser::parse_conversion(query)?;

        let input_unit = &input_unit.to_ascii_lowercase_smolstr();
        let output_unit = &output_unit.to_ascii_lowercase_smolstr();

        match input_val {
            Value::Number(input_val) => {
                let input_units = self.str_to_num_unit.get(input_unit)?;
                let output_units = self.str_to_num_unit.get(output_unit)?;

                Some(
                    input_units
                        .into_iter()
                        .map(|i| {
                            output_units
                                .iter()
                                .filter_map(|o| {
                                    let v = self.attempt_convert(*i, input_val, *o)?;
                                    self.render_conversion(InternalConversion::Number {
                                        input_unit: *i,
                                        input_val,
                                        output_unit: *o,
                                        output_val: v,
                                    })
                                })
                                .collect::<Vec<_>>()
                        })
                        .flatten()
                        .collect::<Vec<_>>(),
                )
            }
            _ => None,
        }

        // Some(self.attempt_conversions(input_unit, input_val, output_unit))
    }
}

// fn possible_num_units(input_unit: &str) -> Vec<NumberUnit>;

// fn possible_num_conversions(
//     possible_input_units: &[NumberUnit],
//     output_unit: &str,
// ) -> Vec<(NumberUnit, NumberUnit)>;

// mod currency;
// mod quantity;
// mod timezone;

mod parser;
