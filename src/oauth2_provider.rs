
use async_trait::async_trait;
use oauth2::basic::BasicClient;
use reqwest::Response;

pub struct UserId(pub String);

#[async_trait]
pub trait Oauth2Provider:  Send + Sync {
    fn scopes(&self) -> Vec<String>;
    fn oauth_client(&self) -> &BasicClient;
    fn user_info_url(&self) -> &str;
    async fn upsert_user_from_response(&self, user_info: Response) -> Result<UserId, anyhow::Error>;
}