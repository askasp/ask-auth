use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use ask_auth::{
    oauth2_provider::{Oauth2Config, UserId},
    Oauth2Provider,
};
use reqwest::Response;
use serde::Deserialize;
use tracing::{event, instrument, Level};

use async_trait::async_trait;
pub struct GithubProvider {
    oauth2_config: Oauth2Config,
    database_client: Arc<Mutex<HashMap<String, String>>>,
}

impl GithubProvider {
    pub fn new(
        oauth2_config: Oauth2Config,
        database_client: Arc<Mutex<HashMap<String, String>>>,
    ) -> Self {
        Self {
            oauth2_config,
            database_client: database_client.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct GithubUser {
    pub id: i32,
}

#[async_trait]
impl Oauth2Provider for GithubProvider {
    fn get_config(&self) -> &Oauth2Config {
        &self.oauth2_config
    }
    #[instrument(skip(self))]
    async fn authenticate_and_upsert(&self, user_info: Response, state_param: HashMap<String,String>) -> Result<UserId, anyhow::Error> {
        event!(Level::INFO, "Authenticating user got json");

        let vipps_user: GithubUser = user_info.json::<GithubUser>().await.unwrap();
        event!(
            Level::INFO,
            "Trying to find user with nin {:?}",
            &vipps_user.id
        );
        self.database_client.lock().unwrap().insert(
            vipps_user.id.clone().to_string(),
            vipps_user.id.clone().to_string(),
        );

        event!(Level::INFO, "INserting new session");
        Ok(UserId(vipps_user.id.clone().to_string()))
    }
    #[instrument(skip(self))]
    async fn get_user_info(&self, token: &str) -> Result<Response, anyhow::Error> {
        event!(Level::INFO, "Getting user info");
        let client = reqwest::Client::new();
        let user_info = client
            .get(self.get_config().user_info_url.clone())
            .header("token", token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "unified-health")
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to get user info")?;
        Ok(user_info)
    }
}
