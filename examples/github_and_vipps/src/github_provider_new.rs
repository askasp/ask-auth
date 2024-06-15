use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};

use ask_auth::auth_provider::{AuthProvider, AuthProviderConfig, Database, UserId};
use axum::async_trait;
use serde::Deserialize;
use serde_json::{map::Values, Value};
use tracing::event;

struct GithubAuthDb {
    database_client: Arc<Mutex<HashMap<String, String>>>,
}
#[derive(Debug, Deserialize)]
struct GithubUserInfo {
    id: i32,
}

#[async_trait]
impl Database for GithubAuthDb {
    async fn authenticate(
        &self,
        user_info: Value,
        _state_params: HashMap<String, String>,
        _merge_user_id: Option<UserId>,
    ) -> Result<UserId, anyhow::Error> {
        let user_info_deserialized: GithubUserInfo = serde_json::from_value(user_info)?;
        event!(
            tracing::Level::DEBUG,
            "Authenticating user got json {:?}",
            user_info_deserialized
        );

        self.database_client
            .lock()
            .unwrap()
            .insert(user_info_deserialized.id.to_string(), "true".to_string());

        Ok(UserId(user_info_deserialized.id.to_string()))
    }
}

pub fn create_github_provider() -> AuthProvider {
    let github_auth_db = GithubAuthDb {
        database_client: Arc::new(Mutex::new(HashMap::new())),
    };
    let github_client_secret = env::var("GITHUB_CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let github_client_id = env::var("GITHUB_CLIENT_ID").expect("Missing CLIENT_ID!");
    let github_redirect_url = env::var("GITHUB_REDIRECT_URL").expect("Missing REDIRECT_URL!");
    let github_auth_url = env::var("GITHUB_AUTH_URL").unwrap();
    let github_token_url = env::var("GITHUB_TOKEN_URL").unwrap();
    let github_user_info_url = env::var("GITHUB_USERINFO_URL").expect("Missing USER_INFO_URL!");
    let mut user_info_headers: HashMap<String, String> = HashMap::new();

    user_info_headers.insert(
        "Accept".to_string(),
        "application/vnd.github+json".to_string(),
    );
    user_info_headers.insert("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string());
    user_info_headers.insert("User-Agent".to_string(), "unified-health".to_string());

    let new_gh_client = AuthProviderConfig::new_oidc_provider(
        github_client_id,
        github_client_secret,
        github_auth_url,
        github_redirect_url,
        github_token_url,
        github_user_info_url,
        vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        Some(user_info_headers),
    );

    AuthProvider {
        is_native: false,
        config: new_gh_client,
        db: Box::new(github_auth_db),
    }
}
