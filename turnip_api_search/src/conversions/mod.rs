use smol_str::StrExt;

use crate::conversions::parser::Value;

mod parser;
mod quantity;

#[derive(Debug)]
pub enum Conversion {
    Number(String),
    DateTime(String),
}

pub struct ConversionCtx {
    quantity: quantity::QuantityCtx,
}
impl ConversionCtx {
    pub fn new() -> Self {
        Self {
            quantity: quantity::QuantityCtx::new(),
        }
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
                );

                if conversions.is_empty() {
                    conversions.push(Conversion::Number(query.to_string()));
                }
            }
            Value::Time(time, date) => todo!(),
        }

        Some(conversions)
    }
}
