use std::pin::Pin;

use async_rate_limiter::RateLimiter;
use futures::FutureExt;
use http::uri::{Authority, Scheme};
use hyper::Uri;
use turnip_api::consume_as_external_err;

use turnip_api::util::AnyError;

pub struct BasicExternalApi {
    scheme: http::uri::Scheme,
    domain: http::uri::Authority,
    path_start: String, // = "/"
    basic_headers: Vec<(String, String)>,
    basic_query: Vec<(String, String)>,
    rate: RateLimiter,
    wait_for_rate: bool,
    client: reqwest::Client,
}
impl BasicExternalApi {
    fn prepare_get_request(
        &self,
        path: &str,
        query: &[(&str, &str)],
        frag: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(Uri, reqwest::Request), AnyError> {
        let path_and_query_str = {
            let mut p_q = self.path_start.clone();
            p_q.push_str(path);
            if !query.is_empty() {
                p_q.push('?');
            }
            let mut first = true;
            for (k, v) in self
                .basic_query
                .iter()
                .map(|(x, y)| (x.as_str(), y.as_str()))
                .chain(query.into_iter().copied())
            {
                if !first {
                    p_q.push('&');
                }
                p_q.push_str(k);
                p_q.push('=');
                for s in form_urlencoded::byte_serialize(v.as_bytes()) {
                    p_q.push_str(s);
                }
                first = false;
            }
            if let Some(frag) = frag {
                p_q.push('#');
                p_q.push_str(frag);
            }
            p_q
        };
        let url = Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.domain.clone())
            .path_and_query(path_and_query_str)
            .build()?;

        // Create the request upfront as well as the url
        let req = {
            let mut b = self.client.get(url.to_string());

            for (k, v) in self.basic_headers.iter() {
                b = b.header(k, v);
            }

            for (k, v) in headers {
                b = b.header(*k, *v);
            }

            b.body("").build()?
        };

        Ok((url, req))
    }

    async fn internal_get_request(
        &self,
        req: reqwest::Request,
    ) -> Result<turnip_api::ExtApiResponse, AnyError> {
        let res = self.client.execute(req).await?;
        let status = res.status();
        let body = res.bytes().await?;

        log::debug!("Got response {} {}", status, String::from_utf8_lossy(&body));

        Ok(turnip_api::ExtApiResponse::new(status, body))
    }
}

impl turnip_api::ExternalApi for BasicExternalApi {
    fn make_get_request<'s, 'args>(
        &'s self,
        path: &'args str,
        query: &'args [(&'args str, &'args str)],
        hash: Option<&'args str>,
        headers: &'args [(&'args str, &'args str)],
    ) -> Pin<
        Box<
            dyn core::future::Future<
                    Output = Result<turnip_api::ExtApiResponse, turnip_api::ApiError>,
                > + Send
                + 's,
        >,
    > {
        // Do this up front so that the lifetime of the arguments can expire
        let (url, req) = match self
            .prepare_get_request(path, query, hash, headers)
            .map_err(consume_as_external_err!("error constructing get request"))
        {
            Ok(ret) => ret,
            Err(e) => return Box::pin(async move { Err(e) }),
        };

        log::debug!("Requesting {:?}", &req);

        async move {
            if self.wait_for_rate {
                // We've done as much work as we can up front, now wait for permission
                self.rate.acquire().await;
            } else {
                self.rate
                    .try_acquire()
                    .map_err(|_| turnip_api::ApiError::InternallyRateLimited)?;
            }
            self.internal_get_request(req)
                .await
                .map_err(consume_as_external_err!(
                    "error evaluating get request for {}",
                    url
                ))
        }
        .boxed()
    }
}

fn user_agent() -> String {
    format!(
        "turnip_server/{} (theturboturnip.com, me@theturboturnip.com)",
        env!("CARGO_PKG_VERSION")
    )
}

fn rate_limiter_rate_burst(rate: usize, burst: usize) -> RateLimiter {
    let x = RateLimiter::new(rate);
    x.burst(burst);
    x
}

lazy_static::lazy_static! {

/// Wikipedia search
///
/// <https://www.mediawiki.org/wiki/API:Opensearch>
/// <https://stackoverflow.com/a/27458013>
///
/// ```
/// https://en.wikipedia.org/w/api.php
/// ?action=opensearch
/// &search=zyz          # Search query
/// &limit=1             # Return only the first result
/// &namespace=0         # Search only articles, ignoring Talk, Mediawiki, etc.
/// &format=json         # 'jsonfm' prints the JSON in HTML for debugging.
/// &profile=fuzzy-subphrases # Typo correction
/// ```
pub static ref WIKIPEDIA_API: BasicExternalApi =
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("en.wikipedia.org"),
        path_start: "".to_owned(),
        basic_headers: vec![
            // Bumps up rate limit <https://www.mediawiki.org/wiki/Wikimedia_APIs/Rate_limits>
            ("User-Agent".to_owned(), user_agent()),
            // more to come...?
        ],
        basic_query: vec![],
        // TODO dual bucket system?
        rate: rate_limiter_rate_burst(3, 20), // Wikimedia limits at 200/min ~= 3/second total. Assume ~1 search every 6 seconds => allow a theoretical single search to use 1/10th of the minute-limit in a burst.
        // if we exceed our burst, just skip using Wikipedia as a recommendation source. the user just needs to wait 1/3rd of a second to get a token back.
        // Wikipedia rate limits are applied at the level of minutes so this should be ok.
        wait_for_rate: false,
        client: reqwest::Client::new(),
    };


/// OpenSearch-style suggestions from the Google autosuggestion API.
///
/// `http://suggestqueries.google.com/complete/search?output=firefox&q=%s`
pub static ref GOOGLE_SUGG_API: BasicExternalApi =
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("suggestqueries.google.com"),
        path_start: "/complete/search".to_owned(),
        basic_headers: vec![
            ("User-Agent".to_owned(), user_agent()),
            // more to come...?
        ],
        basic_query: vec![],
        rate: RateLimiter::new(10000), // Assume no real rate limit here
        wait_for_rate: true,
        client: reqwest::Client::new(),
    };

/// OpenSearch-style suggestions from the Kagi autosuggestion API.
///
/// `https://kagisuggest.com/api/autosuggest?q=%s`
pub static ref KAGI_SUGG_API: BasicExternalApi =
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("kagisuggest.com"),
        path_start: "/api/autosuggest".to_owned(),
        basic_headers: vec![
            ("User-Agent".to_owned(), user_agent()),
            // more to come...?
        ],
        basic_query: vec![],
        rate: RateLimiter::new(10000), // Assume no real rate limit here
        wait_for_rate: true,
        client: reqwest::Client::new(),
    };

/// Search suggestions from the DuckDuckGo autosuggestion API.
///
/// Uses uk-en region i.e. united kingdom english <https://docs.rs/duckduckgo/latest/duckduckgo/params/enum.Region.html>
///
/// `https://duckduckgo.com/ac/?kl=uk-en&q=%s`
pub static ref DDG_SUGG_API: BasicExternalApi =
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("duckduckgo.com"),
        path_start: "/ac/".to_owned(),
        basic_headers: vec![
            ("User-Agent".to_owned(), user_agent()),
            // more to come...?
        ],
        basic_query: vec![
            ("kl".to_string(), "uk-en".to_string()),
        ],
        rate: RateLimiter::new(10000), // Assume no real rate limit here
        wait_for_rate: true,
        client: reqwest::Client::new(),
    };

/// API for searching for movies, TV shows, cast, and crew
///
/// e.g. <https://developer.themoviedb.org/docs/search-and-query-for-details>
///
/// `https://api.themoviedb.org/3/search/movie?query=Jack+Reacher`
pub static ref TMDB_API: Option<BasicExternalApi> = std::env::var("TMDB_KEY")
    .ok()
    .and_then(|key| match key.trim() {
        "" => None,
        trimmed => Some(trimmed.to_string())
    })
    .map(|access_token| BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("api.themoviedb.org"),
        path_start: "".to_owned(),
        basic_headers: vec![
            ("User-Agent".to_owned(), user_agent()),
            (
                "Authorization".to_owned(),
                format!("Bearer {}", access_token.to_owned()),
            ),
            // more to come...?
        ],
        basic_query: vec![],
        // https://developer.themoviedb.org/docs/rate-limiting
        rate: RateLimiter::new(35), // Twenty requests/second, right now I think they cap at 40?
        wait_for_rate: false,
        client: reqwest::Client::new(),
    });

/// API for retrieving currency exchange rates.
/// Only exists when the OPEN_EXCHANGE_RATES_KEY is provided at runtime
pub static ref OPEN_CURRENCY_API: Option<BasicExternalApi> = std::env::var("OPEN_EXCHANGE_RATES_KEY")
    .ok()
    .and_then(|key| match key.trim() {
        "" => None,
        trimmed => Some(trimmed.to_string())
    })
    .map(|api_key| BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("openexchangerates.org"),
        path_start: "/api".to_owned(),
        basic_headers: vec![],
        basic_query: vec![
            ("app_id".to_owned(), api_key.to_owned()),
            // more to come...?
        ],
        rate: RateLimiter::new(100), // One hundred requests/second - should never get there
        wait_for_rate: true, // Just wait it out, currency requests are not latency sensitive
        client: reqwest::Client::new(),
    });

}

/// Maybe this works, maybe it doesn't. it's a basic example.
pub fn youtube_api(api_key: String) -> BasicExternalApi {
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("www.googleapis.com"),
        path_start: "/youtube/v3".to_owned(),
        basic_headers: vec![
            ("User-Agent".to_owned(), user_agent()),
            ("X-Goog-Api-Client".to_owned(), user_agent()),
            ("Authorization".to_owned(), format!("Bearer {}", api_key)),
            // more to come...?
        ],
        basic_query: vec![],
        rate: RateLimiter::new(100), // One hundred requests/second
        wait_for_rate: true,         // these are important probably, come back to this later.
        client: reqwest::Client::new(),
    }
}
