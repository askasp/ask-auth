use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
};

use ask_auth::{
    auth_manager::AuthProviderManager,
    auth_provider::{AuthProvider, UserId},
    auth_router::auth_routes,
};
use axum::{response::Html, routing::get, Router};
use tower_cookies::CookieManagerLayer;
use tracing::event;

mod github_provider_new;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    event!(tracing::Level::INFO, "Starting server");

    let cookie_key_string = env::var("COOKIE_KEY").expect("Cookie key must be set");

    // Create vipps provider

    let db: HashMap<String, String> = HashMap::new();
    let mut auth_manager= AuthProviderManager::new();

    let gh_new = github_provider_new::create_github_provider();
    auth_manager.add_provider("github".to_string(), gh_new);

    let routes_dos = auth_routes(Arc::new(auth_manager), cookie_key_string.clone());

    let app = Router::new()
        .nest("/auth", routes_dos)
        // .nest("/auth", routes)
        .route("/protected", get(protected))
        .layer(CookieManagerLayer::new());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5005").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
async fn protected(user_id: UserId) -> Html<&'static str> {
    Html("<h1>Hello, World protected site</h1>")
}
