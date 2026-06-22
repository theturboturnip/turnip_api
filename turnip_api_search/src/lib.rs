mod config;
mod conversions;
mod placeholder_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth;

pub struct Ctx {}
impl Ctx {
    /// Redirect to an actual search engine with a search term
    /// TODO: if it's an outcome of a suggestion, send it somewhere else?
    pub async fn search(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        todo!()
    }

    /// Returns a list of words to use as suggestions.
    /// Should be formatted as JSON [original_query, [*suggestions]]
    pub async fn suggest(
        &self,
        req: turnip_api::AuthedRequest<'_, Auth>,
    ) -> Result<turnip_api::ApiResponse, turnip_api::ApiError> {
        todo!()
    }
}
