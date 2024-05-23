use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use ask_auth::{
    oauth2_provider::{Oauth2Config, UserId},
    Oauth2Provider,
};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use reqwest::Response;
use serde::Deserialize;
use tracing::{event, Level};

use async_trait::async_trait;
pub struct VippsProvider {
    oauth2_config: Oauth2Config,
    database_client: Arc<Mutex<HashMap<String, String>>>,
}

impl VippsProvider {
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
pub struct VippsUser {
    pub sub: String,
}

#[async_trait]
impl Oauth2Provider for VippsProvider {
    fn get_config(&self) -> &Oauth2Config {
        &self.oauth2_config
    }
    async fn authenticate_and_upsert(&self, user_info: Response, state_param: HashMap<String,String>) -> Result<UserId, anyhow::Error> {
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

        Ok(UserId(vipps_user.sub.clone()))
    }
}
