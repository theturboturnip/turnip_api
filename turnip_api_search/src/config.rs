use crate::placeholder_url::PlaceholderUrl;

pub struct QueryConfig<'a> {
    convert_timezone: bool,
    convert_currency: bool,
    convert_static_quantity: bool,
    wikipedia: Option<WikipediaConfig<'a>>,
    basic_backing: PlaceholderUrl<'a>,
}

pub struct WikipediaConfig<'a> {
    max_query_length: u64,
    query_url: PlaceholderUrl<'a>,
}
