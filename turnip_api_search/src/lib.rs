use smol_str::ToSmolStr;
use std::str::FromStr;
use turnip_api::placeholder_url::PlaceholderUrl;

mod suggestions;
pub use crate::suggestions::Suggester;
use crate::suggestions::SuggestionDst;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SearchSuggestApi {
    Google,
    Kagi,
    DuckDuckGo,
}
impl FromStr for SearchSuggestApi {
    type Err = turnip_api::ApiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "goog" => Ok(SearchSuggestApi::Google),
            "kagi" => Ok(SearchSuggestApi::Kagi),
            "ddg" => Ok(SearchSuggestApi::DuckDuckGo),
            _ => Err(turnip_api::ApiError::QueryMalformed),
        }
    }
}

pub struct PerSearch<T>([T; 3]);
impl<T> PerSearch<T> {
    pub fn new(google: T, kagi: T, ddg: T) -> Self {
        Self([google, kagi, ddg])
    }
    fn get(&self, tag: SearchSuggestApi) -> &T {
        &self.0[tag as u8 as usize]
    }
}

pub struct Ctx<'a> {
    pub generic_search_urls: PerSearch<PlaceholderUrl<'a>>,
    pub wikipedia_search_url: PlaceholderUrl<'a>,
    pub tmdb_search_url: PlaceholderUrl<'a>,
    pub wolfram_search_url: PlaceholderUrl<'a>,

    pub suggs: suggestions::Suggester<'a>,
}

const SUGG_SHORTCUT_PREFIX: &'static str = "~\u{200D}"; // 00A0 for NBSP, 200D for zero width joiner

impl<'a> Ctx<'a> {
    fn tag(dst: SuggestionDst, sugg: &str) -> serde_json::Value {
        let s = match dst {
            SuggestionDst::Wikipedia => format!("{}wiki: {}", SUGG_SHORTCUT_PREFIX, sugg),
            SuggestionDst::Tmdb { media_type } if media_type == "movie" => {
                format!("{}movie: {}", SUGG_SHORTCUT_PREFIX, sugg)
            }
            SuggestionDst::Tmdb { media_type } if media_type == "tv" => {
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
    fn untag(query: &str) -> (SuggestionDst, &str) {
        let (prefix, sugg) = query
            .strip_prefix(SUGG_SHORTCUT_PREFIX)
            .and_then(|s| s.split_once(": "))
            .unwrap_or(("", query));

        if prefix == "wiki" {
            (SuggestionDst::Wikipedia, sugg)
        } else if prefix == "movie" {
            (
                SuggestionDst::Tmdb {
                    media_type: prefix.to_smolstr(),
                },
                sugg,
            )
        } else if prefix == "tv" {
            (
                SuggestionDst::Tmdb {
                    media_type: prefix.to_smolstr(),
                },
                sugg,
            )
        } else if let Some(tmdb_postfix) = prefix.strip_prefix("tmdb-") {
            (
                SuggestionDst::Tmdb {
                    media_type: tmdb_postfix.to_smolstr(),
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

    /// Redirect to an actual search engine with a search term, or if it's an outcome of a suggestion send it somewhere else.
    pub async fn search(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        let query = req
            .get_authed(Auth)?
            .query_param("q")
            .ok_or(turnip_api::ApiError::QueryMalformed)?;
        let backend = req
            .get_authed(Auth)?
            .query_param("backend")
            .map_or(Ok(SearchSuggestApi::DuckDuckGo), |b| b.parse())?;
        // println!("Search Query {}", query);

        let (sugg_dst, sugg) = Self::untag(&query);
        let redirect_to = match sugg_dst {
            SuggestionDst::Wikipedia => self.wikipedia_search_url,
            SuggestionDst::Tmdb { media_type } => self.tmdb_search_url,
            // Wolfram Alpha is not bad at time zones
            SuggestionDst::Calc | SuggestionDst::Time => self.wolfram_search_url,
            SuggestionDst::Search => *self.generic_search_urls.get(backend),
        }
        .to_string(sugg.as_ref());

        turnip_api::ApiResponse::r302_redirect(&redirect_to)
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
        let backend = req
            .get_authed(Auth)?
            .query_param("backend")
            .map_or(Ok(SearchSuggestApi::DuckDuckGo), |b| b.parse())?;
        // println!("Suggest Query {}", query);

        let num_items_per_provider: usize = req
            .get_authed(Auth)?
            .query_param("n")
            .and_then(|n| n.parse().ok())
            .unwrap_or(3);

        let suggestions = self
            .suggs
            .get_suggestions(&query, num_items_per_provider, backend)
            .await?;

        log::debug!("Responding with suggestions {:?}", &suggestions);

        turnip_api::ApiResponse::r200_json(serde_json::Value::Array(vec![
            serde_json::Value::String(query.to_string()),
            serde_json::Value::Array(
                suggestions
                    .into_iter()
                    .map(|(dst, sugg)| Self::tag(dst, &sugg))
                    .collect(),
            ),
        ]))
    }
}
