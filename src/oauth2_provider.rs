use anyhow::Context;
use async_trait::async_trait;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Response;

#[derive(Debug)]
pub struct UserId(pub String);

pub struct Oauth2Config {
    pub scopes: Vec<String>,
    pub oauth_client: BasicClient,
    pub user_info_url: String,
}
impl Oauth2Config {
    pub fn new(
        client_id: String,
        client_secret: String,
        auth_url: String,
        redirect_url: String,
        token_url: String,
        user_info_url: String,
        scopes: Vec<String>,
    ) -> Self {
        let oauth_client = oauth2::basic::BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(auth_url).unwrap(),
            Some(TokenUrl::new(token_url).unwrap()),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url)
                .context("failed to create new redirection URL")
                .unwrap(),
        );

        Self {
            scopes,
            oauth_client,
            user_info_url,
        }
    }
}

#[async_trait]
pub trait Oauth2Provider: Send + Sync {
    fn get_config(&self) -> &Oauth2Config;
    async fn authenticate_and_upsert(&self, user_info: Response) -> Result<UserId, anyhow::Error>;
    async fn get_user_info(&self, token: &str) -> Result<Response, anyhow::Error> {
        let client = reqwest::Client::new();
        let user_info = client
            .get(self.get_config().user_info_url.clone())
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to get user info")?;
        Ok(user_info)
    }
}
