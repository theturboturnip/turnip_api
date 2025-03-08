use endpoints::{AppAuth, AppAuthParams};
use serde::{Deserialize, Serialize};

mod endpoints;
mod external;

#[derive(Debug, Serialize, Deserialize)]
pub struct TurnipApiParams {
    app_auth: AppAuthParams,
}

pub struct TurnipApi<A: AppAuth> {
    app_auth: A,
}

impl<A: AppAuth> TurnipApi<A> {
    pub fn from_config(params: TurnipApiParams) -> Self {
        Self {
            app_auth: AppAuth::from_config(params.app_auth),
        }
    }
}
