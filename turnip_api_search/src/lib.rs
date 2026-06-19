mod config;
mod conversions;
mod placeholder_url;

/// Returns a single URL
async fn query_to_redirect(query: &str) -> String {}

/// Returns a list of (name, URL) named links to use as suggestions
async fn query_suggestions(query: &str) -> Vec<(String, String)> {}
