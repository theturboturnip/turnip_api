//! Based on https://github.com/hyperium/hyper/blob/master/examples/hello-http2.rs

// use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
// use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Method, Request};
use hyper_util::rt::tokio::TokioIo;
use lazy_static;
use std::net::SocketAddr;
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
            ctx.ctx_search
                .as_ref()
                .ok_or(ApiError::NoSuchApp)?
                .suggest(ctx.auth_search(&req)?)
                .await
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
    static ref GOOGLE_SUGG_API: BasicExternalApi = ext_api::google_sugg_api();
    static ref KAGI_SUGG_API: BasicExternalApi = ext_api::kagi_sugg_api();
    static ref WIKIPEDIA_API: BasicExternalApi = ext_api::wikipedia_api();
    static ref TMDB_API: Option<BasicExternalApi> = option_env!("TMDB_KEY").map(|key| ext_api::tmdb_api(key.to_owned()));
    static ref TMDB_API_GENERIC: Option<&'static dyn ExternalApi> = TMDB_API.as_ref().map(|x| x as &'static dyn ExternalApi);

    // TODO kagi autosuggest API?         // https://kagi.com/api/autosuggest?q=%s
    // probably needs cookie/auth
    // TODO ddg autosuggest API?     // https://duckduckgo.com/ac/?kl=wt-wt&q=
    // but handles things differently to Kagi!

    static ref ctx: ServerCtx<'static> = ServerCtx {
        ctx_weather: None,
        ctx_looper: None, // TODO
        ctx_search: Some(turnip_api_search::Ctx {
            search_url: PlaceholderUrl { prefix: "https://kagi.com/search?q=", placeholder_encoding: PlaceholderEncoding::Url, suffix: "" },

            // generic_suggest_api: Some(turnip_api_search::SearchSuggestApi::Google(&*GOOGLE_SUGG_API)),
            generic_suggest_api: Some(turnip_api_search::SearchSuggestApi::Kagi(&*KAGI_SUGG_API)),

            wikipedia_search_url: PlaceholderUrl { prefix: "https://en.wikipedia.org/w/index.php?search=",  placeholder_encoding: PlaceholderEncoding::Url, suffix: "" },
            wikipedia_api: Some(&(*WIKIPEDIA_API)),

            tmdb_search_url: PlaceholderUrl { prefix: "https://www.themoviedb.org/search?query=", placeholder_encoding: PlaceholderEncoding::Url, suffix: "" },
            tmdb_api: *TMDB_API_GENERIC,
        }),
    };
}

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    pretty_env_logger::init();

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
        // current task without waiting for the processing of the HTTP/2 connection we just received
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
