#![cfg(test)]

use crate::endpoints::ApiTarget;

use super::{AppAuth, AppAuthParams, ValidateTokenError};

/// A dummy impl of AppAuth that does check app IDs against configured API targets, but
/// always succeeds in generating tokens (the returned token is just the app ID, outstanding_claims are not tracked)
/// and always succeeds in validating tokens so long as the app ID maps to the expected ApiTarget.
///
/// Only available in `#[cfg(test)]`
pub struct DummyAppAuth(AppAuthParams);
impl AppAuth for DummyAppAuth {
    fn from_config(params: AppAuthParams) -> Self {
        Self(params)
    }

    fn validate_request(
        &self,
        token_str: &str,
        target: ApiTarget,
        _utc_timestamp: u64,
    ) -> Result<(), ValidateTokenError> {
        match self.0.apps.get(token_str) {
            Some(app) if app.api == target => Ok(()),
            Some(app) => Err(ValidateTokenError::ClaimTargetsIncorrectApi {
                api_claimed: app.api,
                api_requested: target,
            }),
            None => Err(ValidateTokenError::ClaimHasInvalidAppId),
        }
    }

    fn generate_token(
        &self,
        app_id: &str,
        _utc_timestamp: u64,
    ) -> Result<String, super::GenerateTokenError> {
        Ok(app_id.to_string())
    }
}
