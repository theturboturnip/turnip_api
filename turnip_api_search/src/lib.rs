use futures::{StreamExt, stream::FuturesOrdered};
use jiff::{SignedDuration, ToSpan};
use turnip_api::{ExtApiResponse, ExternalApi, log_external_err, swallow_as_external_err};

use turnip_api::placeholder_url::PlaceholderUrl;

pub mod conversions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth;

const SUGG_SHORTCUT_PREFIX: &'static str = "~\u{200D}"; // 00A0 for NBSP, 200D for zero width joiner
enum SuggestionDst<'a> {
    /// For suggestions pulled from the Wikipedia search API
    Wikipedia,
    /// For suggestions pulled from the TMDB search API
    Tmdb { media_type: &'a str },
    /// For numeric calculations e.g. unit and currency conversions via WolframAlpha
    /// `https://www.wolframalpha.com/input/?i=1GBP+in+EUR`
    Calc,
    /// For time-zone conversions
    Time,
    /// All else
    Search,
}
impl<'a> SuggestionDst<'a> {
    fn tag(&self, sugg: &str) -> serde_json::Value {
        let s = match self {
            SuggestionDst::Wikipedia => format!("{}wiki: {}", SUGG_SHORTCUT_PREFIX, sugg),
            SuggestionDst::Tmdb { media_type } if *media_type == "movie" => {
                format!("{}movie: {}", SUGG_SHORTCUT_PREFIX, sugg)
            }
            SuggestionDst::Tmdb { media_type } if *media_type == "tv" => {
                format!("{}tv: {}", SUGG_SHORTCUT_PREFIX, sugg)
            }
            SuggestionDst::Tmdb { media_type } => {
                format!("{}tmdb-{}: {}", SUGG_SHORTCUT_PREFIX, media_type, sugg)
            }
            SuggestionDst::Calc => {
                format!("{}calc: {}", SUGG_SHORTCUT_PREFIX, sugg)
            }
            SuggestionDst::Time => {
                format!("{}time: {}", SUGG_SHORTCUT_PREFIX, sugg)
            }
            SuggestionDst::Search => sugg.to_string(), // no prefixing
        };
        serde_json::Value::String(s)
    }
    fn untag(query: &'a str) -> (SuggestionDst<'a>, &'a str) {
        let (prefix, sugg) = query
            .strip_prefix(SUGG_SHORTCUT_PREFIX)
            .and_then(|s| s.split_once(": "))
            .unwrap_or(("", query));

        if prefix == "wiki" {
            (SuggestionDst::Wikipedia, sugg)
        } else if prefix == "movie" {
            (SuggestionDst::Tmdb { media_type: prefix }, sugg)
        } else if prefix == "tv" {
            (SuggestionDst::Tmdb { media_type: prefix }, sugg)
        } else if let Some(tmdb_postfix) = prefix.strip_prefix("tmdb-") {
            (
                SuggestionDst::Tmdb {
                    media_type: tmdb_postfix,
                },
                sugg,
            )
        } else if prefix == "calc" {
            let sugg = if let Some((calc_request, _calc_result)) = sugg.split_once(" = ") {
                // Only pass through the request, don't include the result - might confuse it
                calc_request
            } else if let Some((calc_request, _calc_result)) = sugg.split_once(" ≈ ") {
                // Only pass through the request, don't include the result - might confuse it
                calc_request
            } else {
                sugg
            };
            (SuggestionDst::Calc, sugg)
        } else if prefix == "time" {
            let sugg = if let Some((calc_request, _calc_result)) = sugg.split_once(" = ") {
                // Only pass through the request, don't include the result - might confuse it
                calc_request
            } else {
                sugg
            };
            (SuggestionDst::Time, sugg)
        } else {
            (SuggestionDst::Search, sugg)
        }
    }
}

pub enum SearchSuggestApi<'a> {
    Google(&'a dyn ExternalApi),
    Kagi(&'a dyn ExternalApi),
    // DDG(&'a dyn ExternalApi), ?
}

pub struct Ctx<'a> {
    pub search_url: PlaceholderUrl<'a>,
    pub generic_suggest_api: Option<SearchSuggestApi<'a>>,

    pub wikipedia_search_url: PlaceholderUrl<'a>,
    pub wikipedia_api: Option<&'a dyn ExternalApi>,

    pub tmdb_search_url: PlaceholderUrl<'a>,
    pub tmdb_api: Option<&'a dyn ExternalApi>,

    pub wolfram_search_url: PlaceholderUrl<'a>,

    pub convs: conversions::ConversionCtx,
    pub currency_api: Option<&'a dyn ExternalApi>,
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
        // println!("Search Query {}", query);

        let (sugg_dst, sugg) = SuggestionDst::untag(&query);
        let redirect_to = match sugg_dst {
            SuggestionDst::Wikipedia => self.wikipedia_search_url,
            SuggestionDst::Tmdb { media_type } => self.tmdb_search_url,
            // Wolfram Alpha is not bad at time zones
            SuggestionDst::Calc | SuggestionDst::Time => self.wolfram_search_url,
            SuggestionDst::Search => self.search_url,
        }
        .to_string(sugg.as_ref());

        turnip_api::ApiResponse::r302_redirect(&redirect_to)
    }

    // Update currencies from external API
    pub async fn update_currencies(&self) {
        if let Some(currency_api) = self.currency_api {
            let resp = currency_api
                .make_get_request(
                    "/latest.json",
                    &[
                        ("base", "USD"),
                        ("prettyprint", "false"),
                        ("show_alternative", "true"),
                    ],
                    None,
                    &[],
                )
                .await;
            if let Ok(resp) = resp {
                if resp.status().is_success() {
                    serde_json::from_slice(resp.body()).map_or_else(swallow_as_external_err!("OpenCurrencyAPI serde failure"), |open_currency_api_response| {
                        self
                            .convs
                            .update_currency(&open_currency_api_response)
                            .unwrap_or_else(log_external_err!(
                                "OpenCurrencyAPI successfully parsed, but didn't update. JSON: {:?}",
                                open_currency_api_response
                            ))
                    })
                }
            };
        }
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
        // println!("Suggest Query {}", query);

        let num_items_per_provider: usize = req
            .get_authed(Auth)?
            .query_param("n")
            .and_then(|n| n.parse().ok())
            .unwrap_or(3);
        if num_items_per_provider > 10 {
            return Err(turnip_api::ApiError::QueryMalformed);
        }

        let mut external_futures = FuturesOrdered::new();
        let mut external_future_tags = vec![];

        let mut suggestions = vec![];
        if let Some(convs) = self.convs.parse_and_convert(query.as_ref()) {
            suggestions.extend(convs.into_iter().map(|conv| match conv {
                conversions::Conversion::Number(txt) => SuggestionDst::Calc.tag(&txt),
                conversions::Conversion::DateTime(txt) => SuggestionDst::Time.tag(&txt),
            }));
        } else {
            // If it's a conversion, don't bother search

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
                        ("limit", &format!("{}", num_items_per_provider)),
                        ("namespace", "0"),
                        ("format", "json"),
                        // ("profile", "fuzzy-subphrases"),
                    ],
                    None,
                    &[],
                ));

                // Alternate approach I have seen in https://github.com/goldsmith/Wikipedia
                // external_futures.push_back(wikipedia.make_get_request(
                //     "/w/api.php",
                //     &[
                //         ("action", "query"),
                //         ("list", "search"),
                //         ("srprop", ""),
                //         ("srsearch", query.as_ref()),
                //         ("srinfo", "suggestion"),
                //         ("srlimit", "2"),
                //         // ("limit", "2"),
                //         // ("namespace", "0"),
                //         ("format", "json"),
                //         // ("profile", "fuzzy-subphrases"),
                //     ],
                //     None,
                //     &[],
                // ));

                external_future_tags.push('w');
            }

            if let Some(tmdb) = self.tmdb_api {
                external_futures.push_back(tmdb.make_get_request(
                    "/3/search/multi",
                    &[("query", query.as_ref())],
                    None,
                    &[("accept", "application/json")],
                ));
                external_future_tags.push('t');
            }
        }

        match self.generic_suggest_api {
            Some(SearchSuggestApi::Google(sugg)) => {
                external_futures.push_back(sugg.make_get_request(
                    "",
                    &[("client", "firefox"), ("q", query.as_ref())],
                    None,
                    &[],
                ));
                // firefox-style suggestion format
                external_future_tags.push('k');
            }
            Some(SearchSuggestApi::Kagi(sugg)) => {
                external_futures.push_back(sugg.make_get_request(
                    "",
                    &[("q", query.as_ref())],
                    None,
                    &[],
                ));
                // firefox-style suggestion format
                external_future_tags.push('k');
            }
            None => todo!(),
        }

        let external_results: Vec<Result<ExtApiResponse, _>> = external_futures.collect().await;

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
                                        suggestions.extend(
                                            suggs
                                                .into_iter()
                                                .map(|sugg| SuggestionDst::Wikipedia.tag(sugg)),
                                        );
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
                                        .take(num_items_per_provider)
                                        .map(|val| {
                                            val.get("title")
                                                .or_else(|| val.get("name"))
                                                .and_then(|t| t.as_str())
                                                .map(|t| {
                                                    (
                                                        val.get("media_type")
                                                            .and_then(|ty| ty.as_str())
                                                            .unwrap_or("?"),
                                                        t,
                                                    )
                                                })
                                        })
                                        .collect::<Option<Vec<_>>>()
                                })
                                .map_or_else(
                                    log_external_err!("TMDB JSON had bad format"),
                                    |top_titles| {
                                        suggestions.extend(top_titles.into_iter().map(
                                            |(media_type, title)| {
                                                SuggestionDst::Tmdb { media_type }.tag(title)
                                            },
                                        ));
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
                                            suggs.into_iter().map(|s| SuggestionDst::Search.tag(s)),
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

        suggestions.push(SuggestionDst::Search.tag(&query));

        turnip_api::ApiResponse::r200_json(serde_json::Value::Array(vec![
            serde_json::Value::String(query.to_string()),
            serde_json::Value::Array(suggestions),
        ]))
    }
}
