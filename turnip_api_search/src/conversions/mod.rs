use std::sync::RwLock;

use arrayvec::ArrayString;
use fnv::FnvHashMap;
use smol_str::StrExt;
use turnip_api::util::DebugError;

use crate::conversions::parser::Value;

mod currency;
mod parser;
mod quantity;
mod time;

#[derive(Debug)]
pub enum Conversion {
    Number(String),
    DateTime(String),
}

pub struct ConversionCtx {
    quantity: quantity::QuantityCtx,
    time: time::TimeCtx,
    currency: RwLock<currency::CurrencyCtx>,
}
impl ConversionCtx {
    pub fn new() -> Self {
        Self {
            quantity: quantity::QuantityCtx::new(),
            time: time::TimeCtx::new(),
            currency: RwLock::new(currency::CurrencyCtx::default()),
        }
    }
    pub fn currency_timestamp(&self) -> jiff::Timestamp {
        self.currency.read().unwrap().timestamp
    }
    pub fn update_currency(&self, open_currency_api_response: &serde_json::Value) -> Option<()> {
        let new_ctx = currency::CurrencyCtx::from_json(open_currency_api_response)?;

        let mut c = self.currency.write().unwrap();
        *c = new_ctx;

        Some(())
    }
    pub fn parse_and_convert(&self, query: &str) -> Option<Vec<Conversion>> {
        let (input_val, input_unit, output_unit) = parser::parse_conversion(query)?;

        let input_unit = &input_unit.trim().to_ascii_lowercase_smolstr();
        let output_unit = &output_unit.trim().to_ascii_lowercase_smolstr();

        let mut conversions = vec![];

        match input_val {
            Value::Number(input_val) => {
                self.quantity.attempt_conversion(
                    input_val,
                    input_unit,
                    output_unit,
                    &mut conversions,
                    &self.currency,
                ); // Ignore errors or early-outs here

                if conversions.is_empty() {
                    conversions.push(Conversion::Number(query.to_string()));
                }
            }
            Value::Time(input_time, input_date) => {
                let _ = self.time.attempt_conversion(
                    input_time,
                    input_date,
                    input_unit,
                    output_unit,
                    &mut conversions,
                ); // Ignore errors or early-outs here

                if conversions.is_empty() {
                    conversions.push(Conversion::DateTime(query.to_string()));
                }
            }
        }

        Some(conversions)
    }
}
