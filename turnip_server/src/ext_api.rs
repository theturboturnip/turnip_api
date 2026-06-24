use std::pin::Pin;
use std::str::FromStr;

use async_rate_limiter::RateLimiter;
use http::uri::{Authority, Scheme};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Buf, Request};
use hyper::{body::Bytes, Uri};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::TcpStream;
use turnip_api::consume_as_external_err;

use crate::util::AnyError;

pub struct BasicExternalApi {
    scheme: http::uri::Scheme,
    domain: http::uri::Authority,
    path_start: String, // = "/"
    basic_headers: Vec<(String, String)>,
    rate: RateLimiter,
}
impl BasicExternalApi {
    pub fn new() {}

    fn prepare_get_request(
        &self,
        path: &str,
        query: &[(&str, &str)],
        frag: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Result<(Uri, String, Request<Empty<Bytes>>), AnyError> {
        let path_and_query_str = {
            let mut p_q = self.path_start.clone();
            p_q.push_str(path);
            if !query.is_empty() {
                p_q.push('?');
            }
            let mut first = true;
            for (k, v) in query {
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

        let host = &self.domain;
        let port = url.port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);
        let authority = &addr; // url.authority().unwrap().clone();

        // Create the request upfront as well as the url
        let req = {
            let mut b = hyper::Request::builder()
                .uri(url.clone())
                .header(hyper::header::HOST, authority.as_str());

            for (k, v) in self.basic_headers.iter() {
                b = b.header(k, v);
            }

            for (k, v) in headers {
                b = b.header(*k, *v);
            }

            b.body(Empty::<Bytes>::new())?
        };

        Ok((url, addr, req))
    }

    async fn internal_get_request(
        &self,
        url: Uri,
        addr: String,
        req: Request<Empty<Bytes>>,
    ) -> Result<turnip_api::ExtApiResponse, AnyError> {
        // We've done as much work as we can up front, now wait for permission
        self.rate.acquire().await;

        let stream = TcpStream::connect(addr).await?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        {
            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    log::error!("Connection to '{}' failed: {:?}", url, err);
                }
            });
        }

        let res = sender.send_request(req).await?;

        // asynchronously aggregate the chunks of the body
        let status = res.status();
        let body = res.collect().await?.to_bytes();

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
        let (url, addr, req) = match self
            .prepare_get_request(path, query, hash, headers)
            .map_err(consume_as_external_err!("error constructing get request"))
        {
            Ok(ret) => ret,
            Err(e) => return Box::pin(async move { Err(e) }),
        };

        Box::pin(async move {
            self.internal_get_request(url.clone(), addr, req)
                .await
                .map_err(consume_as_external_err!(
                    "error evaluating get request for {}",
                    url
                ))
        })
    }
}

fn user_agent() -> String {
    format!(
        "turnip_server/{} (theturboturnip.com, me@theturboturnip.com)",
        env!("CARGO_PKG_VERSION")
    )
}

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
pub fn wikipedia_api() -> BasicExternalApi {
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("en.wikipedia.org"),
        path_start: "".to_owned(),
        basic_headers: vec![
            // Bumps up rate limit <https://www.mediawiki.org/wiki/Wikimedia_APIs/Rate_limits>
            ("User-Agent".to_owned(), user_agent()),
            // more to come...?
        ],
        rate: RateLimiter::new(3), // Wikimedia limits at 200/min ~= 3/second
    }
}

/// e.g. <https://developer.themoviedb.org/docs/search-and-query-for-details>
/// ```
/// 'https://api.themoviedb.org/3/search/movie?query=Jack+Reacher'
/// ```
pub fn tmdb_api(access_token: String) -> BasicExternalApi {
    BasicExternalApi {
        scheme: Scheme::HTTPS,
        domain: Authority::from_static("api.themoviedb.org"),
        path_start: "".to_owned(),
        basic_headers: vec![
            ("User-Agent".to_owned(), user_agent()),
            (
                "Authorization".to_owned(),
                format!("Bearer {}", access_token),
            ),
            // more to come...?
        ],
        rate: RateLimiter::new(20), // Twenty requests/second, right now I think they cap at 40?
    }
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
        rate: RateLimiter::new(100), // One hundred requests/second
    }
}
