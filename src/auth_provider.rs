use std::collections::HashMap;

use anyhow::Context;
use axum::async_trait;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Response;
use serde_json::{map::Values, Value};

pub struct UserId(pub String);
#[derive(Debug, Clone)]
pub enum AuthProviderConfig {
    OidcProvider {
        basic_client: BasicClient,
        user_info_url: String,
        user_info_headers: Option<HashMap<String, String>>,
        scopes: Vec<String>,
        secure_cookie: bool,
        
    },
}

pub enum EmailProvider {
    SendGrid {
        template_id: String,
        api_key: String,
    },
}
impl AuthProviderConfig {
    pub fn new_oidc_provider(
        client_id: String,
        client_secret: String,
        auth_url: String,
        redirect_url: String,
        token_url: String,
        user_info_url: String,
        scopes: Vec<String>,
        user_info_headers: Option<HashMap<String, String>>,
        secure_cookie: bool,
    ) -> Self {
        let basic_client = oauth2::basic::BasicClient::new(
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

        AuthProviderConfig::OidcProvider {
            basic_client,
            user_info_url,
            scopes,
            user_info_headers,
            secure_cookie,
        }
    }
}

#[async_trait]
pub trait Database: Send + Sync {
    async fn authenticate(
        &self,
        user_info: Value,
        state_params: HashMap<String, String>,
        merge_user_id: Option<UserId>,
    ) -> Result<UserId, anyhow::Error>;
    fn upsert_user(&self, user: Value) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

pub struct AuthProvider {
    pub is_native: bool,
    pub config: AuthProviderConfig,
    pub db: Box<dyn Database>,
}
