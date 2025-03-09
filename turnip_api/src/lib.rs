use endpoints::{
    jwt::JwtAppAuth,
    rundown_v1::{RundownV1Api, Weather},
    AppAuth, AppAuthParams, GenerateTokenError, HttpResponse,
};
use serde::{Deserialize, Serialize};

mod endpoints;
mod external;

#[derive(Debug, Serialize, Deserialize)]
pub struct TurnipApiParams {
    app_auth: AppAuthParams,
    // TODO include rate limit info
    met_office_global_spot_key: String,
    met_office_probabilistic_key: String,
}

pub struct TurnipApi {
    app_auth: JwtAppAuth,
    rundown_v1: RundownV1Api,
}

impl TurnipApi {
    pub fn from_config(params: TurnipApiParams) -> Self {
        Self {
            app_auth: AppAuth::from_config(params.app_auth),
            rundown_v1: RundownV1Api {},
        }
    }

    pub fn app_auth_generate_token(
        &self,
        app_id: &str,
        utc_timestamp: u64,
    ) -> HttpResponse<String> {
        let token = self.app_auth.generate_token(app_id, utc_timestamp)?;
        Ok((token, http::StatusCode::OK))
    }

    // pub async fn rundown_v1_met_office_weather(
    //     &self,
    //     token_str: &str,
    //     utc_timestamp: u64,
    // ) -> HttpResponse<Weather> {
    //     let is_authed = self.app_auth.validate_request(
    //         token_str,
    //         endpoints::ApiTarget::RundownV1,
    //         utc_timestamp,
    //     )?;
    //     self.rundown_v1
    //         .met_office_weather(is_authed, location)
    //         .await
    // }
}
