use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceholderEncoding {
    Plain,
    Url,
}

#[derive(Debug, Clone, Copy)]
pub struct PlaceholderUrl<'a> {
    pub prefix: &'a str,
    pub placeholder_encoding: PlaceholderEncoding,
    pub suffix: &'a str,
}

impl<'a> PlaceholderUrl<'a> {
    pub fn build<'p, P: Into<&'p str>>(self, placeholder: P) -> PlaceholderPendingUrl<'a, 'p> {
        PlaceholderPendingUrl {
            prefix: self.prefix,
            placeholder_encoding: self.placeholder_encoding,
            placeholder: placeholder.into(),
            suffix: self.suffix,
        }
    }
    pub fn to_string<'p, P: Into<&'p str>>(self, placeholder: P) -> String {
        format!("{}", self.build(placeholder))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PlaceholderPendingUrl<'a, 'p> {
    prefix: &'a str,
    placeholder_encoding: PlaceholderEncoding,
    placeholder: &'p str,
    suffix: &'a str,
}

impl<'a, 'p> Display for PlaceholderPendingUrl<'a, 'p> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.prefix)?;
        match self.placeholder_encoding {
            PlaceholderEncoding::Plain => write!(f, "{}", self.placeholder)?,
            PlaceholderEncoding::Url => write!(f, "{}", urlencoding::encode(self.placeholder))?,
        };
        write!(f, "{}", self.suffix)
    }
}
