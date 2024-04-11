use crate::oauth2_provider::UserId;
use crate::{oauth2_manager::Oauth2Manager, Oauth2Provider};
use axum::{
    async_trait,
    extract::{FromRequestParts, Query},
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Extension, Json, Router,
};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthorizationCode, CsrfToken, EmptyExtraTokenFields, Scope, StandardTokenResponse,
    TokenResponse,
};
use serde::Deserialize;
use std::sync::{Arc, OnceLock};
use thiserror::Error;
use tower_cookies::{cookie::time, Cookie, CookieManagerLayer, Cookies, Key};
use tracing::{event, instrument, Level};

pub static KEY: OnceLock<Key> = OnceLock::new();
const USER_COOKIE_NAME: &str = "ask-auth-id";
const CSRF_TOKEN_NAME: &str = "CSRF_TOKEN";

pub fn setup_routes(auth_manager: Arc<Oauth2Manager>, cookie_key: String) -> Router {
    KEY.set(Key::derive_from(cookie_key.clone().as_bytes()))
        .ok();

    Router::new()
        .route("/:provider/start", get(oauth_start))
        .route("/:provider/callback", get(oauth_callback))
        .route("/protected", get(protected_route))
        .route("/logout", get(logout))
        .route("/login", get(login))
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
    let auth_manager = auth_manager.clone();
    if let Some(provider) = auth_manager.get_provider(&provider_name) {
        let config = provider.get_config();
        let mut client_builder = config.oauth_client.authorize_url(CsrfToken::new_random);
        for scope in config.scopes.iter() {
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

fn verify_csrf_token(cookies: &Cookies, csrf_token: &str) -> Result<(), AuthError> {
    let csrf_token_value = cookies
        .get(CSRF_TOKEN_NAME)
        .map(|cookie| cookie.value().to_owned());
    match !csrf_token_value.is_none() && csrf_token_value == Some(csrf_token.to_string()) {
        true => Ok(()),
        false => Err(AuthError::CsrfError),
    }
}

#[instrument(skip_all)]
async fn get_token(
    client: &BasicClient,
    code: AuthorizationCode,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
    client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            event!(Level::ERROR, "Failed to get token error {:?}", err);
            AuthError::TokenError
        })
}

async fn get_user_info(
    provider: &dyn Oauth2Provider,
    token: &str,
) -> Result<reqwest::Response, AuthError> {
    let res = provider.get_user_info(token).await.map_err(|err| {
        event!(Level::ERROR, "Failed to get user info error {:?}", err);
        AuthError::UserInfoError
    })?;

    match res.status().is_success() {
        true => Ok(res),
        false => {
            let error_details = res
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read response body".to_string());

            event!(
                Level::ERROR,
                "Failed to get user info error {:?}",
                error_details
            );

            Err(AuthError::UserInfoError)
        }
    }
}

async fn oauth_callback(
    Query(query): Query<AuthRequest2>,
    Extension(auth_manager): Extension<Arc<Oauth2Manager>>,
    cookies: Cookies,
    axum::extract::Path(provider_name): axum::extract::Path<String>,
) -> Result<impl IntoResponse, AuthError> {
    let auth_manager = auth_manager.clone();

    verify_csrf_token(&cookies, &query.state)?;
    // Retrieve the provider based on the provider name
    let provider = auth_manager
        .get_provider(&provider_name)
        .ok_or_else(|| AuthError::ProviderNotFound)?;

    let provider_config = provider.get_config();
    let token = get_token(
        &provider_config.oauth_client,
        AuthorizationCode::new(query.code.clone()),
    )
    .await?;

    let user_info = get_user_info(provider, token.access_token().secret()).await?;

    event!(Level::DEBUG, "User info received {:?}", user_info);

    let user_id = provider
        .authenticate_and_upsert(user_info)
        .await
        .map_err(|e| {
            event!(Level::ERROR, "Failed to authenticate user {:?}", e);
            AuthError::AutenticateError
        })?;

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

    Ok(Redirect::temporary("/").into_response())
}

async fn protected_route(user_id: UserId) -> impl IntoResponse {
    let user_id = user_id.0;
    (StatusCode::OK, format!("User authenticated: {:?}", user_id)).into_response()
}

pub struct AuthRedirect;
impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/login").into_response()
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
        let key = KEY.get().unwrap();
        let private_cookies = cookies.private(key);
        event!(Level::INFO, "In from_request_parts got private cookies");

        let user_id_cookie_res = private_cookies.get(USER_COOKIE_NAME);

        event!(
            Level::INFO,
            "In from_request_parts got user_id cookie {:?}",
            user_id_cookie_res
        );
        let temp_id = user_id_cookie_res.ok_or(AuthRedirect)?;
        let user_id_cookie = temp_id.value();
        event!(Level::INFO, "In parserd userid cookie got user_id");
        Ok(UserId(user_id_cookie.to_string()))
    }
}
#[derive(Error, Debug)]
enum AuthError {
    #[error("CSRF token mismatch or not found")]
    CsrfError,
    #[error("Internal Server Error")]
    ProviderNotFound, // You can add more error types as needed
    #[error("Failed to get token")]
    TokenError,
    #[error("Failed to get userinfo")]
    UserInfoError,
    #[error("Failed to authenticate user")]
    AutenticateError,
}
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match &self {
            AuthError::CsrfError => StatusCode::UNAUTHORIZED,
            AuthError::ProviderNotFound => StatusCode::BAD_REQUEST,
            AuthError::TokenError => StatusCode::UNAUTHORIZED,
            AuthError::UserInfoError => StatusCode::UNAUTHORIZED,
            AuthError::AutenticateError => StatusCode::UNAUTHORIZED,
        };

        let error_message = Json(serde_json::json!({ "error": self.to_string() }));
        (status, error_message).into_response()
    }
}
async fn login(
    Extension(auth_manager): Extension<Arc<Oauth2Manager>>,
    user_id: Option<UserId>,
) -> impl IntoResponse {
    let auth_manager = auth_manager.clone();
    let providers = auth_manager.get_providers(); // This function should return your providers hashmap

    // Generate the login buttons HTML
    let buttons_html = providers
        .iter()
        .map(|(name, _provider)| {
            format!(
                r#"<a href="/auth/{}/start" class="login-button">Sign in with {}</a>"#,
                name, name
            )
        })
        .collect::<Vec<String>>()
        .join("\n");

    // Full HTML with card and buttons
    let html_content = format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body, html {{
            height: 100%;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            background-color: #f9fafb;
            font-family: Arial, sans-serif;">

        }}
        .hr {{
            margin-top: 1em;
            margin-bottom: 1em;
            border: 0;
            border-top: 2px solid #e5e7eb;
        }}
        .card {{
            padding: 20px 20px 20px 20px;
            background-color: white;
            border-radius: 8px;
            min-width: 400px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .login-title {{
            margin-bottom: 5px;
            font-size: 1.5em;
            font-weight: 600;
            text-align: left;
            color: #333;
        }}
        
        .login-text{{
            margin-bottom: 0em;
            font-size: 0.9em;
            text-align: left;
            color: #333;
            opacity:0.8
        }}

        .login-button {{
            display: block;
            padding: 6px;
            margin-bottom: 10px;
            font-size: 1em;
            color: black;
            text-align: center;
            text-decoration: none;
            border-radius: 0.4em;
            border: 1px solid #e5e7eb;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="login-title">Welcome</div>
        <div class="login-text">Sign up/in with your preferred provider</div>
        <div class="hr"></div>

        {buttons_html}
    </div>
</body>
</html>
"#
    );

    match user_id {
        Some(_user_id) => Html("<p> You are logged in already</p>".to_string()),
        None => Html(html_content),
    }
}
