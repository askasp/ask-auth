use std::{collections::HashMap, sync::{Arc, Mutex}};

use anyhow::Context;
use ask_auth::{oauth2_provider::UserId, Oauth2Provider};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Response;
use serde::Deserialize;
use tracing::{event, Level};

use async_trait::async_trait;
pub struct VippsProvider {
    oauth_client: oauth2::basic::BasicClient,
    scopes: Vec<String>,
    user_info_url: String,
    database_client: Arc<Mutex<HashMap<String, String>>>,
}

impl VippsProvider {
    pub fn new(
        client_id: String,
        client_secret: String,
        auth_url: String,
        redirect_url: String,
        token_url: String,
        user_info_url: String,
        scopes: Vec<String>,
        database_client: Arc<Mutex<HashMap<String, String>>>,
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
            oauth_client,
            user_info_url,
            scopes,
            database_client: database_client.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct VippsUser {
    pub sub: String,
}

#[async_trait]
impl Oauth2Provider for VippsProvider {
    fn oauth_client(&self) -> &BasicClient {
        &self.oauth_client
    }
    fn scopes(&self) -> Vec<String> {
        self.scopes.clone()
    }
    fn user_info_url(&self) -> &str {
        &self.user_info_url
    }
    async fn upsert_user_from_response(
        &self,
        user_info: Response,
    ) -> Result<UserId, anyhow::Error> {
        let vipps_user: VippsUser = user_info.json::<VippsUser>().await.unwrap();
        event!(
            Level::INFO,
            "Trying to find user with nin {:?}",
            &vipps_user.sub
        );
        self.database_client
            .lock()
            .unwrap()
            .insert(vipps_user.sub.clone(), vipps_user.sub.clone());

        event!(Level::INFO, "INserting new session");
        Ok(UserId(vipps_user.sub.clone()))
    }
}
