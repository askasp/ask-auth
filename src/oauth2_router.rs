use axum::{
    async_trait,
    extract::{FromRequestParts, Query},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Extension, Router,
};
use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use serde::Deserialize;

use std::sync::{Arc, OnceLock};
use tower_cookies::{cookie::time, Cookie, CookieManagerLayer, Cookies, Key};

use tracing::{event, instrument, Level};

use crate::oauth2_manager::Oauth2Manager;
use crate::oauth2_provider::UserId;


pub static KEY: OnceLock<Key> = OnceLock::new();
const USER_COOKIE_NAME: &str = "user_id_name";
const CSRF_TOKEN_NAME: &str = "CSRF_TOKEN";

pub fn setup_routes(auth_manager: Arc<Oauth2Manager>) -> Router {
    Router::new()
        .route("/:provider/start", get(oauth_start))
        .route("/:provider/callback", get(oauth_callback))
        .route("/protected", get(protected_route))
        .route("/logout", get(logout))
        .layer(CookieManagerLayer::new())
        .layer(Extension(auth_manager))
}
async fn logout(cookies: Cookies) -> impl IntoResponse {
    let key = KEY.get().unwrap();
    let private_cookies = cookies.private(key);
    let cookie = Cookie::build((USER_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .build();

    private_cookies.remove(cookie);

    Redirect::temporary("/").into_response()
}
#[instrument(skip_all)]
async fn oauth_start(
    Extension(auth_manager): Extension<Arc<Oauth2Manager>>,
    axum::extract::Path(provider_name): axum::extract::Path<String>,
    cookies: Cookies,
) -> impl IntoResponse {
    if let Some(provider) = auth_manager.get_provider(&provider_name) {
        let mut client_builder = provider.oauth_client().authorize_url(CsrfToken::new_random);
        for scope in provider.scopes().iter() {
            client_builder = client_builder.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, csrf_token) = client_builder.url();
        let cookie = Cookie::build((CSRF_TOKEN_NAME, csrf_token.secret().to_owned()))
            .path("/")
            .http_only(true)
            .secure(true)
            .build();
        cookies.add(cookie);

        event!(Level::INFO, "Redirecting to vipps {:?}", auth_url.as_str());
        Redirect::temporary(auth_url.as_str()).into_response()
    } else {
        (StatusCode::NOT_FOUND, "Provider not found").into_response()
    }
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]

struct AuthRequest2 {
    code: String,
    state: String,
}

async fn oauth_callback(
    Query(query): Query<AuthRequest2>,
    Extension(auth_manager): Extension<Arc<Oauth2Manager>>,
    cookies: Cookies,
    axum::extract::Path(provider_name): axum::extract::Path<String>,
) -> impl IntoResponse {
    let auth_manager = auth_manager.clone();
    let csrf_token_value = cookies
        .get(CSRF_TOKEN_NAME)
        .map(|cookie| cookie.value().to_owned());

    // Directly handle the missing or mismatched CSRF token case
    if csrf_token_value.is_none() || csrf_token_value != Some(query.state) {
        event!(Level::ERROR, "CSRF token mismatch or not found");
        return (
            StatusCode::UNAUTHORIZED,
            "CSRF token mismatch or not found try again",
        )
            .into_response();
    }
    if let Some(provider) = auth_manager.get_provider(&provider_name) {
        let oauth_client = provider.oauth_client();
        let token = oauth_client
            .exchange_code(AuthorizationCode::new(query.code.clone()))
            .request_async(async_http_client)
            .await
            .unwrap();

        event!(Level::DEBUG, "Token received");
        let client = reqwest::Client::new();
        let user_info = client
            .get(provider.user_info_url())
            .bearer_auth(token.access_token().secret())
            .send()
            .await
            .unwrap();

        let user_id = provider.upsert_user_from_response(user_info).await.unwrap();

        event!(Level::DEBUG, "user_id received by upserting {}", user_id.0);

        let key = KEY.get().unwrap();
        let private_cookies = cookies.private(key);
        let cookie = Cookie::build((USER_COOKIE_NAME, user_id.0))
            .path("/")
            .http_only(true)
            .expires(time::OffsetDateTime::now_utc() + time::Duration::days(1))
            .secure(true)
            .build();
        private_cookies.add(cookie);

        (StatusCode::OK, "User authenticated").into_response()
    } else {
        (StatusCode::NOT_FOUND, "Provider not found").into_response()
    }
}

async fn protected_route(user_id: UserId) -> impl IntoResponse {
    let user_id = user_id.0;
    (StatusCode::OK, format!("User authenticated: {:?}", user_id)).into_response()
}

pub struct AuthRedirect;
impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/vipps/start").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for UserId
where
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    #[instrument(skip_all)]
    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        event!(Level::INFO, "In from_request_parts");

        let cookies = Cookies::from_request_parts(req, state).await.unwrap();
        req.uri = req.uri.clone();

        let redirect_cookie = Cookie::build(("redirect_to", req.uri.to_string()))
            .path("/")
            .http_only(true)
            .secure(true)
            .build();

        cookies.add(redirect_cookie);
        event!(Level::INFO, "In from_request_parts got cookies");
        let another_one = cookies.get("anothername");
        event!(
            Level::INFO,
            "In from_request_parts got another one {:?}",
            another_one
        );
        let key = KEY.get().unwrap();
        event!(Level::INFO, "In from_request_parts got key ");
        let private_cookies = cookies.private(key);
        event!(Level::INFO, "In from_request_parts got private cookies");

        let user_id_cookie_res = private_cookies.get(USER_COOKIE_NAME);

        event!(
            Level::INFO,
            "In from_request_parts got user_id cookie {:?}",
            user_id_cookie_res
        );
        let temp_id = user_id_cookie_res.ok_or(AuthRedirect)?;
        event!(
            Level::INFO,
            "In from_request_parts got tempid {:?}",
            temp_id
        );
        let user_id_cookie = temp_id.value();
        event!(Level::INFO, "In parserd userid cookie got user_id");
        Ok(UserId(user_id_cookie.to_string()))
    }
}
