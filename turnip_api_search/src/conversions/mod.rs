use smol_str::StrExt;

use crate::conversions::parser::Value;

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
}
impl ConversionCtx {
    pub fn new() -> Self {
        Self {
            quantity: quantity::QuantityCtx::new(),
            time: time::TimeCtx::new(),
        }
    }
    // pub fn update_currencies(&self, curr_to_usd: FnvHashMap<SmolStr, f64>) {
    //     self.quantity.update_currencies(curr_to_usd);
    // }
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
