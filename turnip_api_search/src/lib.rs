use futures::{StreamExt, stream::FuturesOrdered};
use turnip_api::{ExtApiResponse, ExternalApi, log_external_err, swallow_as_external_err};

use turnip_api::placeholder_url::PlaceholderUrl;

mod conversions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth;

pub struct Ctx<'a> {
    pub search_url: PlaceholderUrl<'a>,
    pub generic_suggest_api: Option<&'a dyn ExternalApi>,
    pub wikipedia_api: Option<&'a dyn ExternalApi>,
    pub tmdb_api: Option<&'a dyn ExternalApi>,
}
impl<'a> Ctx<'a> {
    /// Redirect to an actual search engine with a search term
    /// TODO: if it's an outcome of a suggestion, send it somewhere else?
    pub async fn search(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        let query = req
            .get_authed(Auth)?
            .query_param("q")
            .ok_or(turnip_api::ApiError::QueryMalformed)?;
        println!("Search Query {}", query);
        let redirect_to = self.search_url.to_string(query.as_ref());
        turnip_api::ApiResponse::r300_redirect(dbg!(&redirect_to))
    }

    /// Returns a list of words to use as suggestions.
    /// Should be formatted as JSON [original_query, [*suggestions]]
    pub async fn suggest(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        let query = req
            .get_authed(Auth)?
            .query_param("q")
            .ok_or(turnip_api::ApiError::QueryMalformed)?;
        println!("Suggest Query {}", query);

        let mut external_futures = FuturesOrdered::new();
        let mut external_future_tags = vec![];
        if let Some(wikipedia) = self.wikipedia_api {
            // /w/api.php
            // ?action=opensearch
            // &search=zyz          # Search query
            // &limit=1             # Return only the first result
            // &namespace=0         # Search only articles, ignoring Talk, Mediawiki, etc.
            // &format=json         # 'jsonfm' prints the JSON in HTML for debugging.
            // &profile=fuzzy-subphrases # Typo correction
            external_futures.push_back(wikipedia.make_get_request(
                "/w/api.php",
                &[
                    ("action", "opensearch"),
                    ("search", query.as_ref()),
                    ("limit", "2"),
                    ("namespace", "0"),
                    ("format", "json"),
                    ("profile", "fuzzy-subphrases"),
                ],
                None,
                &[],
            ));
            external_future_tags.push('w');
        }

        if let Some(tmdb) = self.tmdb_api {
            external_futures.push_back(tmdb.make_get_request(
                "/3/search/movie",
                &[("query", query.as_ref())],
                None,
                &[],
            ));
            external_future_tags.push('t');
        }

        if let Some(sugg) = self.generic_suggest_api {
            external_futures.push_back(sugg.make_get_request(
                "",
                &[("q", query.as_ref())],
                None,
                &[],
            ));
            external_future_tags.push('k');
        }

        let external_results: Vec<Result<ExtApiResponse, _>> = external_futures.collect().await;

        let mut suggestions = vec![];

        for (tag, result) in external_future_tags
            .into_iter()
            .zip(external_results.into_iter())
        {
            match (tag, result) {
                ('w', Ok(wiki_json)) if wiki_json.status().is_success() => {
                    // https://stackoverflow.com/a/27458013
                    serde_json::from_slice(wiki_json.body()).map_or_else(
                        swallow_as_external_err!("Failed to parse Wikipedia JSON"),
                        |wiki_json: serde_json::Value| {
                            wiki_json
                                .get(1)
                                .and_then(|arr| arr.as_array())
                                .and_then(|arr| {
                                    arr.into_iter()
                                        .map(|s| s.as_str())
                                        .collect::<Option<Vec<_>>>()
                                })
                                .map_or_else(
                                    log_external_err!("Wikipedia JSON had bad format"),
                                    |suggs| {
                                        suggestions.extend(suggs.into_iter().map(|s| {
                                            serde_json::Value::String(format!("wiki: {}", s))
                                        }));
                                    },
                                );
                        },
                    );
                }
                ('t', Ok(tmdb_json)) if tmdb_json.status().is_success() => {
                    serde_json::from_slice(tmdb_json.body()).map_or_else(
                        swallow_as_external_err!("Failed to parse TMDB JSON"),
                        |tmdb_json: serde_json::Value| {
                            tmdb_json
                                .get("results")
                                .and_then(|results| results.as_array())
                                .and_then(|results| {
                                    results
                                        .into_iter()
                                        .take(2)
                                        .map(|val| val.get("title").and_then(|t| t.as_str()))
                                        .collect::<Option<Vec<_>>>()
                                })
                                .map_or_else(
                                    log_external_err!("TMDB JSON had bad format"),
                                    |top_titles| {
                                        suggestions.extend(top_titles.into_iter().map(|title| {
                                            serde_json::Value::String(format!("tmdb: {}", title))
                                        }));
                                    },
                                );
                        },
                    );
                }
                ('k', Ok(sugg_json)) if sugg_json.status().is_success() => {
                    serde_json::from_slice(sugg_json.body()).map_or_else(
                        swallow_as_external_err!("Failed to parse generic suggestion JSON"),
                        |sugg_json: serde_json::Value| {
                            sugg_json
                                .get(1)
                                .and_then(|arr| arr.as_array())
                                .and_then(|arr| {
                                    arr.into_iter()
                                        .map(|s| s.as_str())
                                        .collect::<Option<Vec<_>>>()
                                })
                                .map_or_else(
                                    log_external_err!("Sugg JSON had bad format"),
                                    |suggs| {
                                        suggestions.extend(
                                            suggs
                                                .into_iter()
                                                .map(|s| serde_json::Value::String(s.to_string())),
                                        );
                                    },
                                );
                        },
                    );
                }
                (c, Ok(json)) => {
                    log::info!(
                        "Got fine response of kind {} back, status {}, left unhandled",
                        c,
                        json.status()
                    )
                }
                _ => {}
            }
        }

        suggestions.push(serde_json::Value::String(query.to_string()));

        turnip_api::ApiResponse::r200_json(serde_json::Value::Array(vec![
            serde_json::Value::String(query.to_string()),
            serde_json::Value::Array(suggestions),
        ]))
    }
}
