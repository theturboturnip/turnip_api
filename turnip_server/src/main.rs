//! Based on https://github.com/hyperium/hyper/blob/master/examples/hello-http2.rs - but doesn't use HTTP2 anymore

// use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request};
use hyper_util::rt::tokio::TokioIo;
use lazy_static;
use std::net::SocketAddr;
use std::ops::Deref;
use std::time::Duration;
use tokio::net::TcpListener;
use turnip_api::placeholder_url::{PlaceholderEncoding, PlaceholderUrl};
use turnip_api::{util::AnyError, ApiError, ApiRequest, ApiResponse, AuthedRequest, ExternalApi};

mod ext_api;

use crate::ext_api::BasicExternalApi;

#[derive(Clone)]
// An Executor that uses the tokio runtime.
pub struct TokioExecutor;

// Implement the `hyper::rt::Executor` trait for `TokioExecutor` so that it can be used to spawn
// tasks in the hyper runtime.
// An Executor allows us to manage execution of tasks which can help us improve the efficiency and
// scalability of the server.
impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut);
    }
}

pub struct ServerCtx<'a> {
    // keys: FnvHashMap<String, Auth>,
    ctx_weather: Option<turnip_api_weather::Ctx>,
    ctx_looper: Option<turnip_api_looper::Ctx>,
    ctx_search: Option<turnip_api_search::Ctx<'a>>,
}
// ServerCtx is inited at start-of-day, so can be sync
unsafe impl<'a> Sync for ServerCtx<'a> {}
impl<'a> ServerCtx<'a> {
    /// The search function doesn't require auth
    pub fn auth_search(
        &self,
        req: &'a Request<hyper::body::Incoming>,
    ) -> Result<AuthedRequest<'a, turnip_api_search::Auth>, ApiError> {
        let req = ApiRequest::new(&req)?;
        Ok(AuthedRequest::new(turnip_api_search::Auth, req))
    }

    pub fn poke(&self) {
        // Does nothing but forces lazy_static to come online
    }
}

async fn api_route(req: Request<hyper::body::Incoming>) -> Result<ApiResponse, ApiError> {
    match (req.method(), req.uri().path()) {
        // (&Method::GET, "/looper/search") => ctx.ctx_looper.search(ctx.auth_for_looper(req)),
        // (&Method::GET, "/looper/playlistItems") => ctx.ctx_looper.playlist_items(ctx.auth_for_looper(req)),
        // (&Method::GET, "/looper/channelDetails") => ctx.ctx_looper.channel_details(ctx.auth_for_looper(req)),
        (&Method::GET, "/search") => {
            ctx.ctx_search
                .as_ref()
                .ok_or(ApiError::NoSuchApp)?
                .search(ctx.auth_search(&req)?)
                .await
        }
        (&Method::GET, "/search/suggest") => {
            let search = ctx.ctx_search.as_ref().ok_or(ApiError::NoSuchApp)?;

            // Rudimentary debouncing - expect the request to be cancelled if the user types another character
            // 500ms is too long - this may also be too long, in practice...
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            search.suggest(ctx.auth_search(&req)?).await
        }
        _ => return Err(ApiError::NoSuchApp),
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>, AnyError> {
    let response = api_route(req).await;
    match response {
        Ok(resp) => {
            // println!("responding with {:?}", resp.0);
            Ok(resp.0)
        }
        Err(e) => {
            let code = match e {
                ApiError::NoSuchApp => 404,
                ApiError::WrongAuth => 403,
                ApiError::QueryMalformed => 422,
                ApiError::QueryTooLong => 414,
                ApiError::InternalError => 500,
                ApiError::ExternalApiError => 500,
            };
            let msg = format!("{}: {:?}", code, e);
            let resp = hyper::Response::builder()
                .status(code)
                .body(http_body_util::Full::new(Bytes::copy_from_slice(
                    msg.as_bytes(),
                )))?;
            Ok(resp)
        }
    }
}
lazy_static::lazy_static! {
    static ref ctx: ServerCtx<'static> = ServerCtx {
        ctx_weather: None,
        ctx_looper: None, // TODO
        ctx_search: Some(turnip_api_search::Ctx {
            generic_search_urls: turnip_api_search::PerSearch::new(
                PlaceholderUrl::from_url_prefix("https://google.com/search?q="),
                PlaceholderUrl::from_url_prefix("https://kagi.com/search?q="),
                PlaceholderUrl::from_url_prefix("https://duckduckgo.com/?q="),
            ),
            wikipedia_search_url:
                PlaceholderUrl::from_url_prefix("https://en.wikipedia.org/w/index.php?search="),
            tmdb_search_url:
                PlaceholderUrl::from_url_prefix("https://www.themoviedb.org/search?query="),
            wolfram_search_url:
                PlaceholderUrl::from_url_prefix("https://www.wolframalpha.com/input/?i="),

            suggs: turnip_api_search::Suggester {
                generic_suggestion_apis: turnip_api_search::PerSearch::new(
                    ext_api::GOOGLE_SUGG_API.deref() as &'static dyn ExternalApi,
                    ext_api::KAGI_SUGG_API.deref() as &'static dyn ExternalApi,
                    ext_api::DDG_SUGG_API.deref() as &'static dyn ExternalApi,
                ),

                wikipedia_api:
                    Some(ext_api::WIKIPEDIA_API.deref() as &'static dyn ExternalApi),
                tmdb_api:
                    ext_api::TMDB_API.as_ref().map(|x| x as &'static dyn ExternalApi),
                currency_api:
                    ext_api::OPEN_CURRENCY_API.as_ref().map(|x| x as &'static dyn ExternalApi),

                convs: Default::default(),
            }
        }),
    };
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    pretty_env_logger::init();

    // Make sure all the lazy-statics lazily statically initialize
    ctx.poke();

    // Bump the currencies
    match ctx.ctx_search.as_ref() {
        Some(search) => {
            tokio::task::spawn(async {
                let mut interval = tokio::time::interval(Duration::from_mins(120));

                loop {
                    interval.tick().await;
                    search.suggs.update_currencies().await;
                }
            });
        }
        None => log::info!("No search API..."),
    }

    // This address is localhost
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // Bind to the port and listen for incoming TCP connections
    let listener = TcpListener::bind(addr).await?;

    loop {
        // When an incoming TCP connection is received grab a TCP stream for
        // client-server communication.
        //
        // Note, this is a .await point, this loop will loop forever but is not a busy loop. The
        // .await point allows the Tokio runtime to pull the task off of the thread until the task
        // has work to do. In this case, a connection arrives on the port we are listening on and
        // the task is woken up, at which point the task is then put back on a thread, and is
        // driven forward by the runtime, eventually yielding a TCP stream.
        let (stream, _) = listener.accept().await?;
        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
        // current task without waiting for the processing of the connection we just received
        // to finish
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(move |req| handle(req)))
                .await
            {
                log::error!("Error serving connection: {}", err);
            }
        });
    }
}
