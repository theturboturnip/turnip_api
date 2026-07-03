use fnv::FnvHashMap;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CurrencyStr([u8; 3]);
impl CurrencyStr {
    pub fn from_str(s: &str) -> Option<Self> {
        const ASCII_UPPER_TO_LOWER_MASK: u8 = 0b00100000;
        if s.len() >= 3 {
            let b = s.as_bytes();
            Some(Self([
                b[0] | ASCII_UPPER_TO_LOWER_MASK,
                b[1] | ASCII_UPPER_TO_LOWER_MASK,
                b[2] | ASCII_UPPER_TO_LOWER_MASK,
            ]))
        } else {
            None
        }
    }
    pub fn as_str(&self) -> &str {
        unsafe { str::from_utf8_unchecked(&self.0) }
    }
}
impl std::fmt::Debug for CurrencyStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // f.debug_tuple("CurrencyStr").field(&self.0).finish()
        write!(
            f,
            "CurrencyStr('{}', [{}, {}, {}])",
            self.as_str(),
            self.0[0],
            self.0[1],
            self.0[2]
        )
    }
}

#[derive(Debug)]
pub struct CurrencyCtx {
    pub currencies_from_usd: FnvHashMap<CurrencyStr, f64>,
    pub timestamp: jiff::Timestamp,
}
impl CurrencyCtx {
    pub fn from_json(open_currency_api_response: &serde_json::Value) -> Option<Self> {
        let timestamp = open_currency_api_response.get("timestamp")?.as_i64()?;
        let timestamp = jiff::Timestamp::from_second(timestamp).ok()?;

        let base = open_currency_api_response.get("base")?.as_str()?;
        if base != "USD" {
            return None;
        }

        let rates = open_currency_api_response
            .get("rates")?
            .as_object()?
            .into_iter()
            .filter_map(|entry| {
                let curr = CurrencyStr::from_str(entry.0)?;
                let val = entry.1.as_f64()?;

                Some((curr, val))
            })
            .collect::<FnvHashMap<CurrencyStr, f64>>();

        Some(CurrencyCtx {
            currencies_from_usd: rates,
            timestamp,
        })
    }
}
impl Default for CurrencyCtx {
    fn default() -> Self {
        Self {
            currencies_from_usd: Default::default(),
            timestamp: jiff::Timestamp::constant(0, 0),
        }
    }
}

/// From <https://openexchangerates.org/api/currencies.json>
pub const CURRENCIES: [(&str, &str); 173] = [
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
pub const CURRENCY_PREFIXES: [(char, &str); 16] = [
    ('$', "USD"),
    ('£', "GBP"),
    ('€', "EUR"),
    ('¥', "JPY"),
    ('￥', "JPY"),
    // ('₩', "KPW"), // irrelevant/difficult to measure
    ('₩', "KRW"),
    // ('￦', "KPW"), // irrelevant/difficult to measure
    ('￦', "KRW"),
    ('৳', "BDT"),
    ('⃀', "KGS"),
    ('₪', "ILS"),
    // ('₨', ""), // there are a lot of rupees, like a lot of dollars/pesos which use $, so don't put in a canonical one
    ('₹', "INR"),
    ('₽', "RUB"),
    ('៛', "KHR"),
    ('⃁', "SAR"),
    ('﷼', "IRR"),
    ('₱', "PHP"),
    // Got bored, didn't do the rest
];
