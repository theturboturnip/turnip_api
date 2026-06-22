#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {
    /// Mobile app version has higher privileges
    mobile: bool,
}

pub struct Ctx {}
impl Ctx {
    pub async fn get_weather(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        todo!()
    }
}
