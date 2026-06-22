//! This

// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
// pub enum App {
//     Weather,
//     Looper,
//     Search,
// }

use hyper::body::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    NoSuchApp,
    WrongAuth,
    QueryMalformed,
    QueryTooLong,
    InternalError,
}

/// A bare-minimum struct holding everything a turnip_api needs as sanitized input.
/// Parsed from a URI:
/// - path is taken in as-is
/// - query must be formatted "key=value&key=value&..."
///     - "key=value=value" is QueryMalformed
///     - query > 1024 is assumed to be some sort of DOS, QueryTooLong
///     - duplicate keys are ignored, last value for given key is accepted
///         - e.g. "key=value1&key=value2" will always return .query_param("key") == Some("value2")
pub struct ApiRequest<'a> {
    path: &'a str,
    query: Vec<(&'a str, &'a str)>,
}
impl<'a> ApiRequest<'a> {
    pub fn new(req: &'a hyper::Request<hyper::body::Incoming>) -> Result<Self, ApiError> {
        let path = req.uri().path();
        let query = match req.uri().query() {
            Some(q) if q.len() > 1024 => Err(ApiError::QueryTooLong)?,
            Some(q) => q
                .split("&")
                .map(|pair| match pair.split_once("=") {
                    None => Err(ApiError::QueryMalformed),
                    Some((k, v)) if v.contains("=") => Err(ApiError::QueryMalformed),
                    Some((k, v)) => Ok((k, v)),
                })
                .collect::<Result<Vec<(&str, &str)>, ApiError>>()?,
            None => vec![],
        };
        Ok(Self { path, query })
    }
    pub fn path(&self) -> &str {
        self.path
    }
    pub fn query_param(&self, s: &str) -> Option<&str> {
        for (k, v) in self.query.iter().rev() {
            if *k == s {
                return Some(v);
            }
        }
        None
    }
}

pub struct ApiResponse(pub hyper::Response<http_body_util::Full<Bytes>>);
impl ApiResponse {
    pub fn r200_json<T: serde::Serialize + std::fmt::Debug>(value: T) -> Result<Self, ApiError> {
        let json = serde_json::to_vec(&value).map_err(|e| {
            log::error!("Failed to serialize response {:?} error {}", &value, e);
            ApiError::InternalError
        })?;
        let resp = hyper::Response::builder()
            .status(200)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(Bytes::from(json)))
            .map_err(|e| {
                log::error!("Failed to create resp from json, error {}", e);
                ApiError::InternalError
            })?;
        Ok(ApiResponse(resp))
    }
    pub fn r300_redirect(to: &str) -> Result<Self, ApiError> {
        let resp = hyper::Response::builder()
            .status(300)
            .header(hyper::header::LOCATION, to)
            .body(http_body_util::Full::new(Bytes::new()))
            .map_err(|e| {
                log::error!("Failed to create redirect {:?} error {}", &to, e);
                ApiError::InternalError
            })?;
        Ok(ApiResponse(resp))
    }
}

pub struct AuthedRequest<'a, TAuth: PartialEq>(TAuth, ApiRequest<'a>);
impl<'a, TAuth: PartialEq> AuthedRequest<'a, TAuth> {
    pub fn new(app: TAuth, req: ApiRequest<'a>) -> Self {
        Self(app, req)
    }
    pub fn get_authed(&'a self, auth_for: TAuth) -> Result<&'a ApiRequest<'a>, ApiError> {
        if self.0 == auth_for {
            Ok(&self.1)
        } else {
            Err(ApiError::WrongAuth)
        }
    }
}
