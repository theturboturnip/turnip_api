pub type HttpResponse<T> = Result<(T, http::StatusCode), HttpError>;

pub struct HttpError {
    pub status: http::StatusCode,
    pub debug_log: String,
}
