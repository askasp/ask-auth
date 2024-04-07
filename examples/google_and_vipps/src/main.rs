use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};

use ask_auth::{
    oauth2_provider::{Oauth2Config, UserId},
    setup_routes, Oauth2Manager,
};
use axum::{response::Html, routing::get, Router};
use github_provider::GithubProvider;
use tower_cookies::CookieManagerLayer;
use tracing::event;

mod github_provider;
mod vipps_provider;
use crate::vipps_provider::VippsProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    event!(tracing::Level::INFO, "Starting server");

    let cookie_key_string = env::var("COOKIE_KEY").expect("Cookie key must be set");

    // Create vipps provider
    let vipps_client_secret = env::var("VIPPS_CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let vipps_client_id = env::var("VIPPS_CLIENT_ID").expect("Missing CLIENT_ID!");
    let vipps_redirect_url = env::var("VIPPS_REDIRECT_URL").expect("Missing REDIRECT_URL!");
    let vipps_auth_url = env::var("VIPPS_AUTH_URL").unwrap();
    let vipps_token_url = env::var("VIPPS_TOKEN_URL").unwrap();
    let vipps_user_info_url = env::var("VIPPS_USERINFO_URL").expect("Missing USER_INFO_URL!");

    let db: HashMap<String, String> = HashMap::new();
    let database = Arc::new(Mutex::new(db));
    let vipps_provider = VippsProvider::new(
        Oauth2Config::new(
            vipps_client_id.clone(),
            vipps_client_secret.clone(),
            vipps_auth_url.clone(),
            vipps_redirect_url.clone(),
            vipps_token_url.clone(),
            vipps_user_info_url.clone(),
            vec!["openid".to_string()],
        ),
        database.clone(),
    );

    let github_client_secret = env::var("GITHUB_CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let github_client_id = env::var("GITHUB_CLIENT_ID").expect("Missing CLIENT_ID!");
    let github_redirect_url = env::var("GITHUB_REDIRECT_URL").expect("Missing REDIRECT_URL!");
    let github_auth_url = env::var("GITHUB_AUTH_URL").unwrap();
    let github_token_url = env::var("GITHUB_TOKEN_URL").unwrap();
    let github_user_info_url = env::var("GITHUB_USERINFO_URL").expect("Missing USER_INFO_URL!");

    let github_provider = GithubProvider::new(
        Oauth2Config::new(
            github_client_id.clone(),
            github_client_secret.clone(),
            github_auth_url.clone(),
            github_redirect_url.clone(),
            github_token_url.clone(),
            github_user_info_url.clone(),
            vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        ),
        database.clone(),
    );

    let mut auth_manager = Oauth2Manager::new();

    auth_manager.add_provider("vipps".to_string(), vipps_provider);
    auth_manager.add_provider("github".to_string(), github_provider);
    let auth_manager = Arc::new(auth_manager);

    let routes = setup_routes(auth_manager, cookie_key_string);

    let app = Router::new()
        .nest("/auth", routes)
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5005").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
async fn protected(user_id: UserId) -> Html<&'static str> {
    Html("<h1>Hello, World protected site</h1>")
}
