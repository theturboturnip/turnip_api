use super::ApiTarget;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[cfg(test)]
pub mod dummy;
pub mod jwt;

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
    ) -> Result<(), ValidateTokenError>;
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
