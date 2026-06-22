#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {}

/// Passes through access to three specific YouTube APIs.
/// Even if someone gets the turnip_api key for this, they can't get at the Google API key so can't do anything stupid with it.
pub struct Ctx {}
impl Ctx {
    pub async fn search(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        todo!()
    }
    pub async fn playlist_items(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        todo!()
    }
    pub async fn channel_items(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        todo!()
    }
}
