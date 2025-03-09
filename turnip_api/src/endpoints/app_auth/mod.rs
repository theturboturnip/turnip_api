use super::{ApiTarget, HttpError};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod jwt;

/// A 0-size struct that can only be constructed through [AppAuth::validate_request].
/// i.e. you can only receive this token with a successfully authorized token.
/// This means API endpoint functions can enforce authorization without calling into AppAuth themselves.
/// TODO: make this preserve ApiTarget info?
#[derive(Debug, Clone, Copy)]
pub struct IsAuthed(());
/// A pre-constructed IsAuthed token to be used ONLY IN UNIT TESTS
/// where the goal is to test the authorized API
#[cfg(test)]
pub const DUMMY_IS_AUTHED: IsAuthed = IsAuthed(());

pub trait AppAuth {
    fn from_config(params: AppAuthParams) -> Self;

    /// Given a JWT token, validate it against the App ID it claims to have
    /// and what ApiTarget endpoint it's been sent to, and increment the number of requests
    /// (assuming you aren't going over the request limit)
    fn validate_request(
        &self,
        token_str: &str,
        target: ApiTarget,
        utc_timestamp: u64,
    ) -> Result<IsAuthed, ValidateTokenError>;
    /// Given an App ID, generate a new token for it (if it has spare outstanding claims)
    fn generate_token(
        &self,
        app_id: &str,
        utc_timestamp: u64,
    ) -> Result<String, GenerateTokenError>;
    // TODO renew tokens?
}

#[derive(Debug, Clone)]
pub enum GenerateTokenError {
    JwtError(jsonwebtoken::errors::Error),
    BadAppId,
    AppHasTooManyOutstandingClaims,
}

impl From<GenerateTokenError> for HttpError {
    fn from(value: GenerateTokenError) -> Self {
        let status = match &value {
            GenerateTokenError::JwtError(_) => http::StatusCode::INTERNAL_SERVER_ERROR,
            GenerateTokenError::BadAppId => http::StatusCode::NOT_FOUND,
            GenerateTokenError::AppHasTooManyOutstandingClaims => {
                http::StatusCode::SERVICE_UNAVAILABLE
            }
        };
        HttpError {
            status,
            debug_log: format!("{:?}", value),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValidateTokenError {
    JwtError(jsonwebtoken::errors::Error),
    // Either the app doesn't exist or the app doesn't know about this claim
    ClaimHasInvalidAppId,
    ClaimHasExpired,
    ClaimHasBadAudience,
    ClaimTargetsIncorrectApi {
        api_claimed: ApiTarget,
        api_requested: ApiTarget,
    },
    ClaimExceedsUses,
}
impl From<ValidateTokenError> for HttpError {
    fn from(value: ValidateTokenError) -> Self {
        let status = match &value {
            ValidateTokenError::JwtError(_) => http::StatusCode::UNAUTHORIZED,
            ValidateTokenError::ClaimHasInvalidAppId => http::StatusCode::UNAUTHORIZED,
            ValidateTokenError::ClaimHasExpired => http::StatusCode::UNAUTHORIZED,
            ValidateTokenError::ClaimHasBadAudience => http::StatusCode::UNAUTHORIZED,
            ValidateTokenError::ClaimTargetsIncorrectApi { .. } => http::StatusCode::UNAUTHORIZED,
            ValidateTokenError::ClaimExceedsUses => http::StatusCode::TOO_MANY_REQUESTS,
        };
        HttpError {
            status,
            debug_log: format!("{:?}", value),
        }
    }
}

/// Top-level parameters structure used for initializing
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppAuthParams {
    /// The key used to generate and validate API claims with the HMAC-SHA-256 scheme
    key_base64: String,
    apps: HashMap<String, PerAppParams>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct PerAppParams {
    /// The API target this app can use
    api: ApiTarget,
    /// The maximum amount of claims we will generate for this app at this time
    max_outstanding_claims: usize,
    /// The maximum amount of uses we allow per claim, to avoid one claim starving out all the others
    max_requests_per_claim: u64,
    /// The duration of time (in seconds) that new claims are given before they time out
    claim_timeout_s: u64,
}
