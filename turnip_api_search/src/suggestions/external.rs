use smol_str::ToSmolStr;
use turnip_api::{ApiError, ExternalApi, consume_as_external_err, option_into_external_err};

use crate::suggestions::SuggestionDst;

pub async fn wikipedia(
    wikipedia: &dyn ExternalApi,
    query: &str,
) -> Result<Vec<(SuggestionDst, String)>, ApiError> {
    // /w/api.php
    // ?action=opensearch
    // &search=zyz          # Search query
    // &limit=1             # Return only the first result
    // &namespace=0         # Search only articles, ignoring Talk, Mediawiki, etc.
    // &format=json         # 'jsonfm' prints the JSON in HTML for debugging.
    // &profile=fuzzy-subphrases # Typo correction on MediaWiki(?), but not supported in Wikipedia
    let wiki_json = wikipedia
        .make_get_request(
            "/w/api.php",
            &[
                ("action", "opensearch"),
                ("search", query),
                ("limit", "10"),
                ("namespace", "0"),
                ("format", "json"),
                // ("profile", "fuzzy-subphrases"),
            ],
            None,
            &[],
        )
        .await?;

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

    if wiki_json.status().is_success() {
        // https://stackoverflow.com/a/27458013
        let wiki_json: serde_json::Value = serde_json::from_slice(wiki_json.body())
            .map_err(consume_as_external_err!("Failed to parse Wikipedia JSON"))?;

        opensearch_suggestion(wiki_json, SuggestionDst::Wikipedia)
    } else {
        log::error!("Wikipedia returned status code {}", wiki_json.status());
        Err(ApiError::ExternalApiError)
    }
}
pub async fn tmdb(
    tmdb: &dyn ExternalApi,
    query: &str,
) -> Result<Vec<(SuggestionDst, String)>, ApiError> {
    let tmdb_json = tmdb
        .make_get_request(
            "/3/search/multi",
            &[("query", query.as_ref())],
            None,
            &[("accept", "application/json")],
        )
        .await?;

    if tmdb_json.status().is_success() {
        let tmdb_json: serde_json::Value = serde_json::from_slice(tmdb_json.body())
            .map_err(consume_as_external_err!("Failed to parse TMDB JSON"))?;

        let tmdb_arr = tmdb_json
            .get("results")
            .and_then(|results| results.as_array())
            .ok_or_else(option_into_external_err!(
                "TMDB JSON had bad format - ['results'] not array"
            ))?;

        let suggs = tmdb_arr
            .into_iter()
            .map(|val| {
                val.get("title")
                    .or_else(|| val.get("name"))
                    .and_then(|t| t.as_str())
                    .map(|t| {
                        let media_type = val
                            .get("media_type")
                            .and_then(|ty| ty.as_str())
                            .unwrap_or("?")
                            .to_smolstr();
                        let title = t.to_owned();
                        (SuggestionDst::Tmdb { media_type }, title.to_owned())
                    })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(option_into_external_err!(
                "TMDB JSON had bad format - non-string 'title'/'name' of ['results']"
            ))?;

        Ok(suggs)
    } else {
        log::error!("TMDB returned status code {}", tmdb_json.status());
        Err(ApiError::ExternalApiError)
    }
}
/// for firefox-style suggestions, which I think are the OpenSearch schema? But I'm not 100% sure.
fn opensearch_suggestion(
    sugg_json: serde_json::Value,
    dst: SuggestionDst,
) -> Result<Vec<(SuggestionDst, String)>, ApiError> {
    let sugg_arr =
        sugg_json
            .get(1)
            .and_then(|arr| arr.as_array())
            .ok_or_else(option_into_external_err!(
                "{:?} JSON had bad format - elem[1] not array",
                dst
            ))?;

    let suggs = sugg_arr
        .into_iter()
        .map(|s| {
            s.as_str()
                .and_then(|sugg| Some((dst.clone(), sugg.to_string())))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(option_into_external_err!(
            "{:?} JSON had bad format - non-string element of elem[1]",
            dst
        ))?;

    Ok(suggs)
}
pub async fn google_suggestion(
    google: &dyn ExternalApi,
    query: &str,
) -> Result<Vec<(SuggestionDst, String)>, ApiError> {
    let search_json = google
        .make_get_request(
            "",
            &[("client", "firefox"), ("q", query.as_ref())],
            None,
            &[],
        )
        .await?;

    if search_json.status().is_success() {
        // https://stackoverflow.com/a/27458013
        let search_json: serde_json::Value = serde_json::from_slice(search_json.body())
            .map_err(consume_as_external_err!("Failed to parse Google JSON"))?;

        opensearch_suggestion(search_json, SuggestionDst::Search)
    } else {
        log::error!("Google returned status code {}", search_json.status());
        Err(ApiError::ExternalApiError)
    }
}
pub async fn kagi_suggestion(
    kagi: &dyn ExternalApi,
    query: &str,
) -> Result<Vec<(SuggestionDst, String)>, ApiError> {
    let search_json = kagi
        .make_get_request("", &[("q", query)], None, &[])
        .await?;

    if search_json.status().is_success() {
        // https://stackoverflow.com/a/27458013
        let search_json: serde_json::Value = serde_json::from_slice(search_json.body())
            .map_err(consume_as_external_err!("Failed to parse Kagi JSON"))?;

        opensearch_suggestion(search_json, SuggestionDst::Search)
    } else {
        log::error!("Kagi returned status code {}", search_json.status());
        Err(ApiError::ExternalApiError)
    }
}
/// for the DuckDuckGo schema, which is [{"phrase": "x"}, {"phrase":"y"}, etc]
pub async fn duckduckgo_suggestion(
    ddg: &dyn ExternalApi,
    query: &str,
) -> Result<Vec<(SuggestionDst, String)>, ApiError> {
    let search_json = ddg.make_get_request("", &[("q", query)], None, &[]).await?;

    if search_json.status().is_success() {
        // https://stackoverflow.com/a/27458013
        let search_json: serde_json::Value = serde_json::from_slice(search_json.body())
            .map_err(consume_as_external_err!("Failed to parse DDG JSON"))?;

        search_json
            .as_array()
            .map(|arr| {
                arr.into_iter()
                    .filter_map(|s| {
                        s.get("phrase")
                            .and_then(|s| s.as_str())
                            .map(|s| (SuggestionDst::Search, s.to_owned()))
                    })
                    .collect::<Vec<_>>()
            })
            .ok_or_else(option_into_external_err!("DDG JSON had bad format"))
    } else {
        log::error!("DDG returned status code {}", search_json.status());
        Err(ApiError::ExternalApiError)
    }
}
