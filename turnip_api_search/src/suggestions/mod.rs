use fnv::FnvHashMap;
use futures::{FutureExt, StreamExt, stream::FuturesOrdered};
use smol_str::{SmolStr, ToSmolStr};
use turnip_api::{ExtApiResponse, ExternalApi, log_external_err, swallow_as_external_err};

use crate::{PerSearch, SearchSuggestApi};

mod conversions;
mod external;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
            log::info!("Updating currencies...");
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
        } else {
            log::info!("Requested currency update but no currency API");
        }
    }

    pub(crate) async fn get_suggestions(
        &self,
        query: &str,
        num_items_per_provider: usize,
        backend: SearchSuggestApi,
    ) -> Result<Vec<(SuggestionDst, String)>, turnip_api::ApiError> {
        let mut suggestions = vec![];
        if let Some(convs) = self.convs.parse_and_convert(query.as_ref()) {
            suggestions.extend(convs.into_iter().map(|conv| match conv {
                conversions::Conversion::Number(txt) => (SuggestionDst::Calc, txt),
                conversions::Conversion::DateTime(txt) => (SuggestionDst::Time, txt),
            }));
        } else {
            // If it's a conversion, don't bother search
            let mut external_futures = FuturesOrdered::new();

            if let Some(wikipedia) = self.wikipedia_api {
                external_futures.push_back(external::wikipedia(wikipedia, query).boxed());
            }

            if let Some(tmdb) = self.tmdb_api {
                external_futures.push_back(external::tmdb(tmdb, query).boxed());
            }

            match (backend, self.generic_suggestion_apis.get(backend)) {
                (SearchSuggestApi::Google, google) => {
                    external_futures.push_back(external::google_suggestion(*google, query).boxed());
                }
                (SearchSuggestApi::Kagi, kagi) => {
                    external_futures.push_back(external::kagi_suggestion(*kagi, query).boxed());
                }
                (SearchSuggestApi::DuckDuckGo, ddg) => {
                    external_futures
                        .push_back(external::duckduckgo_suggestion(*ddg, query).boxed());
                }
            }

            let external_results: Vec<Result<_, _>> = external_futures.collect().await;

            suggestions.extend(
                external_results
                    .into_iter()
                    .filter_map(|r| r.ok())
                    .map(|v| v.into_iter().take(num_items_per_provider))
                    .flatten(),
            );
        }

        suggestions.push((SuggestionDst::Search, query.to_owned()));

        Ok(suggestions)
    }
}
