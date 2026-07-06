use fnv::FnvHashMap;
use futures::{StreamExt, stream::FuturesOrdered};
use smol_str::{SmolStr, ToSmolStr};
use turnip_api::{ExtApiResponse, ExternalApi, log_external_err, swallow_as_external_err};

use crate::{PerSearch, SearchSuggestApi};

mod conversions;

pub(crate) enum SuggestionDst {
    /// For suggestions pulled from the Wikipedia search API
    Wikipedia,
    /// For suggestions pulled from the TMDB search API
    Tmdb { media_type: SmolStr },
    /// For numeric calculations e.g. unit and currency conversions via WolframAlpha
    /// `https://www.wolframalpha.com/input/?i=1GBP+in+EUR`
    Calc,
    /// For time-zone conversions
    Time,
    /// All else
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalApiTag {
    Wikipedia,
    Tmdb,
    /// for firefox-style suggestions, which I think are OpenSearch-compatible? But I'm not 100% sure.
    OpenSearchSuggestion,
}

pub struct Suggester<'a> {
    pub generic_suggestion_apis: PerSearch<&'a dyn ExternalApi>,
    pub wikipedia_api: Option<&'a dyn ExternalApi>,
    pub tmdb_api: Option<&'a dyn ExternalApi>,
    pub currency_api: Option<&'a dyn ExternalApi>,

    pub convs: conversions::ConversionCtx,
}
impl<'a> Suggester<'a> {
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

    pub(crate) async fn get_suggestions(
        &self,
        query: &str,
        num_items_per_provider: usize,
        backing: SearchSuggestApi,
    ) -> Result<Vec<(SuggestionDst, String)>, turnip_api::ApiError> {
        let mut external_futures = FuturesOrdered::new();
        let mut external_future_tags = vec![];

        let mut suggestions = vec![];
        if let Some(convs) = self.convs.parse_and_convert(query.as_ref()) {
            suggestions.extend(convs.into_iter().map(|conv| match conv {
                conversions::Conversion::Number(txt) => (SuggestionDst::Calc, txt),
                conversions::Conversion::DateTime(txt) => (SuggestionDst::Time, txt),
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

                external_future_tags.push(ExternalApiTag::Wikipedia);
            }

            if let Some(tmdb) = self.tmdb_api {
                external_futures.push_back(tmdb.make_get_request(
                    "/3/search/multi",
                    &[("query", query.as_ref())],
                    None,
                    &[("accept", "application/json")],
                ));
                external_future_tags.push(ExternalApiTag::Tmdb);
            }
        }

        match (backing, self.generic_suggestion_apis.get(backing)) {
            (SearchSuggestApi::Google, sugg) => {
                external_futures.push_back(sugg.make_get_request(
                    "",
                    &[("client", "firefox"), ("q", query.as_ref())],
                    None,
                    &[],
                ));
                // firefox-style suggestion format
                external_future_tags.push(ExternalApiTag::OpenSearchSuggestion);
            }
            (SearchSuggestApi::Kagi, sugg) => {
                external_futures.push_back(sugg.make_get_request(
                    "",
                    &[("q", query.as_ref())],
                    None,
                    &[],
                ));
                // firefox-style suggestion format
                external_future_tags.push(ExternalApiTag::OpenSearchSuggestion);
            }
        }

        let external_results: Vec<Result<ExtApiResponse, _>> = external_futures.collect().await;

        for (tag, result) in external_future_tags
            .into_iter()
            .zip(external_results.into_iter())
        {
            match (tag, result) {
                (ExternalApiTag::Wikipedia, Ok(wiki_json)) if wiki_json.status().is_success() => {
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
                                        suggestions.extend(suggs.into_iter().map(|sugg| {
                                            (SuggestionDst::Wikipedia, sugg.to_owned())
                                        }));
                                    },
                                );
                        },
                    );
                }
                (ExternalApiTag::Tmdb, Ok(tmdb_json)) if tmdb_json.status().is_success() => {
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
                                                (
                                                    SuggestionDst::Tmdb {
                                                        media_type: media_type.to_smolstr(),
                                                    },
                                                    title.to_owned(),
                                                )
                                            },
                                        ));
                                    },
                                );
                        },
                    );
                }
                (ExternalApiTag::OpenSearchSuggestion, Ok(sugg_json))
                    if sugg_json.status().is_success() =>
                {
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
                                                .map(|s| (SuggestionDst::Search, s.to_owned())),
                                        );
                                    },
                                );
                        },
                    );
                }
                (c, Ok(json)) => {
                    log::info!(
                        "Got fine response of kind {:?} back, status {}, left unhandled",
                        c,
                        json.status()
                    )
                }
                _ => {}
            }
        }

        suggestions.push((SuggestionDst::Search, query.to_owned()));

        Ok(suggestions)
    }
}
