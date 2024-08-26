use crate::auth_manager::AuthProviderManager;
use crate::auth_provider::{self, UserId};
use anyhow::Context;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum::{
    async_trait,
    extract::{FromRequestParts, Query},
    http::{request::Parts, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Extension, Json, Router,
};
use magic_crypt::generic_array::typenum::{False, Same};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthorizationCode, CsrfToken, EmptyExtraTokenFields, Scope, StandardTokenResponse,
    TokenResponse,
};
use oauth2::{PkceCodeChallenge, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_cookies::cookie::SameSite;
use std::collections::HashMap;
use std::sync::{Arc, Once, OnceLock};
use thiserror::Error;
use tokio::sync::Mutex;
use tower_cookies::{cookie::time, Cookie, CookieManagerLayer, Cookies, Key};
use tracing::{event, instrument, Level};

pub static KEY: OnceLock<Key> = OnceLock::new();
pub static MC: OnceLock<MagicCrypt256> = OnceLock::new();
const USER_COOKIE_NAME: &str = "ask-auth-id";
const CSRF_TOKEN_NAME: &str = "CSRF_TOKEN";
const PKCE_CHALLENGE: &str = "PKCE_CHALLENGE";

const STATE_COOKE: &str = "state_cookie";
use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptTrait};

#[derive(Debug, Clone)]
struct AskAuthAppState2 {
    code_pairs: Arc<Mutex<HashMap<String, String>>>, // key: code_challenge, value: code_verifier
}
impl AskAuthAppState2 {
    fn new() -> Self {
        AskAuthAppState2 {
            code_pairs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Add a new code challenge and code verifier pair
    async fn add_pair(&self, code_challenge: String, code_verifier: String) {
        let mut map = self.code_pairs.lock().await;
        map.insert(code_challenge, code_verifier);
    }

    // Retrieve the code verifier for a given code challenge
    async fn get_verifier(&self, code_challenge: &str) -> Option<String> {
        let map = self.code_pairs.lock().await;
        map.get(code_challenge).cloned()
    }

    // Remove a code challenge and code verifier pair
    async fn remove_pair(&self, code_challenge: &str) -> Option<String> {
        let mut map = self.code_pairs.lock().await;
        map.remove(code_challenge)
    }
}

#[derive(Deserialize, Serialize)]
struct StateParam {
    state_params: Option<String>,
}

pub fn auth_routes(auth_manager: Arc<AuthProviderManager>, cookie_key: String) -> Router {
    KEY.set(Key::derive_from(cookie_key.clone().as_bytes()))
        .ok();

    MC.set(new_magic_crypt!(cookie_key, 256)).ok();

    let app_state = AskAuthAppState2::new();

    Router::new()
        .route("/:provider/start", get(auth_start))
        .route("/:provider/callback", get(auth_callback))
        .route("/protected", get(protected_route))
        .route("/logout", get(logout))
        .route("/login", get(login))
        .layer(CookieManagerLayer::new())
        .layer(Extension(auth_manager))
        .with_state(app_state)
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
async fn auth_start(
    Extension(auth_manager): Extension<Arc<AuthProviderManager>>,
    axum::extract::Path(provider_name): axum::extract::Path<String>,
    Query(state_param): Query<StateParam>,
    cookies: Cookies,
    State(app_state): State<AskAuthAppState2>,
) -> impl IntoResponse {
    let auth_manager = auth_manager.clone();
    let Some(provider) = auth_manager.get_provider(&provider_name) else {
        return (StatusCode::NOT_FOUND, "Provider not found").into_response();
    };

    match provider.config.clone() {
        auth_provider::AuthProviderConfig::OidcProvider {
            basic_client,
            scopes,
            secure_cookie,
            ..
            
            // user_info_headers,
        } => {
            let mut client_builder = basic_client.authorize_url(CsrfToken::new_random);
            for scope in scopes.iter() {
                client_builder = client_builder.add_scope(Scope::new(scope.clone()));
            }

            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            let pkce_challenge_clone = pkce_challenge.as_str().to_string();

            client_builder = client_builder.set_pkce_challenge(pkce_challenge);
            app_state
                .add_pair(
                    pkce_challenge_clone.clone(),
                    pkce_verifier.secret().to_owned(),
                )
                .await;

            let (auth_url, csrf_token) = client_builder.url();
            match provider.is_native {
                false => {
                    let cookie = Cookie::build((CSRF_TOKEN_NAME, csrf_token.secret().to_owned()))
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .build();

                    cookies.add(cookie);

                    let pkce_cookie = Cookie::build((PKCE_CHALLENGE, pkce_challenge_clone))
                        .path("/")
                        .http_only(true)
                        .secure(true)
                        .build();

                    cookies.add(pkce_cookie);

                    event!(
                        Level::WARN,
                        "State param writing to cookie is {:?}",
                        state_param.state_params
                    );
                    

                    if let Some(state_param_string) = state_param.state_params {
                        let state_cookie = Cookie::build((STATE_COOKE, state_param_string))
                            .path("/")
                            .http_only(true)
                            .secure(true)
                            .expires(time::OffsetDateTime::now_utc() + time::Duration::hours(1))
                            .finish();
                        cookies.add(state_cookie);
                    }

                    event!(Level::INFO, "Redirecting to vipps {:?}", auth_url.as_str());
                    Redirect::temporary(auth_url.as_str()).into_response()
                }
                true => {
                    event!(
                        Level::INFO,
                        "Returning auth url and pkce challenge to native app"
                    );
                    let json_response = json!({
                        "auth_url": auth_url.to_string(),
                        "pkce_challenge": pkce_challenge_clone,
                    });

                    (StatusCode::OK, axum::Json(json_response)).into_response()
                }
            }
        }
        _ => (StatusCode::NOT_FOUND, "Provider not found").into_response(),
    }
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]

struct AuthRequest2 {
    code: String,
    state: String,
    pkce_challenge: Option<String>,
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
    pkce_verifier: PkceCodeVerifier,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, AuthError> {
    client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            event!(Level::ERROR, "Failed to get token error {:?}", err);
            AuthError::TokenError
        })
}

#[instrument]
async fn get_user_info(
    user_info_url: &str,
    token: &str,
    headers: Option<HashMap<String, String>>,
) -> Result<reqwest::Response, AuthError> {
    let mut header_map = HeaderMap::new();
    header_map.insert(
        HeaderName::from_bytes("token".as_bytes()).unwrap(),
        HeaderValue::from_str(token).unwrap(),
    );

    event!(Level::ERROR, "In get_user_info");

    if let Some(h) = headers {
        for (key, value) in h {
            let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                event!(Level::ERROR, "Invalid header name {:?}", e);
                AuthError::UserInfoError
            })?;
            let header_value = HeaderValue::from_str(&value).map_err(|e| {
                event!(Level::ERROR, "Invalid header value {:?}", e);
                AuthError::UserInfoError
            })?;
            header_map.insert(header_name, header_value);
        }
    }

    let client = reqwest::Client::new();
    let res = client
        .get(user_info_url)
        .bearer_auth(token)
        .headers(header_map)
        .send()
        .await
        .map_err(|err| {
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

#[instrument(skip_all)]
async fn auth_callback(
    Query(query): Query<AuthRequest2>,
    Extension(auth_manager): Extension<Arc<AuthProviderManager>>,
    cookies: Cookies,
    axum::extract::Path(provider_name): axum::extract::Path<String>,
    State(app_state): State<AskAuthAppState2>,
) -> Result<impl IntoResponse, AuthError> {
    let auth_manager = auth_manager.clone();

    event!(Level::INFO, "In auth_callback");

    let provider = auth_manager
        .get_provider(&provider_name)
        .ok_or_else(|| AuthError::ProviderNotFound)?;

    if !provider.is_native {
        match verify_csrf_token(&cookies, &query.state) {
            Ok(_) => (),
            Err(e) => return Ok(Redirect::temporary("/").into_response()),
        }
    }

    match provider.config.clone() {
        auth_provider::AuthProviderConfig::OidcProvider {
            basic_client,
            user_info_url,
            user_info_headers,
            secure_cookie,
            ..
        } => {
            event!(
                Level::DEBUG,
                "oauthcallback fetching pkce challenge from query {:?} or cookie ",
                query
            );

            let pkce_challenge = match &query.pkce_challenge {
                Some(pkce_challenge) => pkce_challenge.clone(),
                None => cookies
                    .get(PKCE_CHALLENGE)
                    .map(|cookie| cookie.value().to_owned())
                    .ok_or(AuthError::PkceError)?,
            };

            event!(
                Level::DEBUG,
                "oauthcallback got pkce challenge {}",
                pkce_challenge
            );

            let pkce_verifier = PkceCodeVerifier::new(
                app_state
                    .get_verifier(&pkce_challenge)
                    .await
                    .ok_or(AuthError::PkceError)?,
            );
            event!(Level::INFO, "got pkce verifier {}", pkce_verifier.secret());

            // Retrieve the provider based on the provider name
            let token = get_token(
                &basic_client,
                AuthorizationCode::new(query.code.clone()),
                pkce_verifier,
            )
            .await?;

            event!(Level::INFO, "Token received {:?}", token);

            let state_cookie_string = cookies
                .get(STATE_COOKE)
                .map(|cookie| cookie.value().to_owned());

            event!(
                Level::DEBUG,
                "State cookie string {:?}",
                state_cookie_string
            );

            let state_map: HashMap<String, String> = match state_cookie_string {
                Some(state_cookie_string) => {
                    serde_json::from_str(&state_cookie_string).unwrap_or_default()
                }
                None => HashMap::new(),
            };
            let user_info_response = get_user_info(
                &user_info_url,
                token.access_token().secret(),
                user_info_headers,
            )
            .await?;
            let user_info = user_info_response.json::<Value>().await.map_err(|e| {
                event!(Level::ERROR, "Failed to get user info {:?}", e);
                AuthError::UserInfoError
            })?;

            event!(Level::ERROR, "info received {:?}", user_info);
            let user_id = provider
                .db
                .authenticate(user_info, state_map, None)
                .await
                .map_err(|e| {
                    event!(Level::ERROR, "Failed to authenticate the user {:?}", e);
                    AuthError::AutenticateError
                })?;

            event!(Level::DEBUG, "user_id received by upserting {}", user_id.0);
            
            match provider.is_native {
                false => {
                    let key = KEY.get().unwrap();
                    let private_cookies = cookies.private(key);
                    let cookie = Cookie::build((USER_COOKIE_NAME, user_id.0))
                        .path("/")
                        .http_only(true)
                        .expires(time::OffsetDateTime::now_utc() + time::Duration::days(30))
                        .secure(secure_cookie)
                        .build();
                    private_cookies.add(cookie);

                    Ok(Redirect::temporary("/").into_response())
                }
                true => {
                    let mc = MC.get().unwrap();
                    let user_token = mc.encrypt_str_to_base64(&user_id.0);
                    //return user_id as an encrypted token, with a short expiry time
                    let response_json = json!({ "access_token": user_token});
                    Ok((StatusCode::OK, axum::Json(response_json)).into_response())
                }
            }
        }
        _ => Err(AuthError::ProviderNotFound),
    }
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
        event!(Level::DEBUG, "In from_request_parts");
        // Check for the Authorization header

        // let auth_header = req.headers.get("Authorization");
        if let Some(auth_header) = req.headers.get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str["Bearer ".len()..];
                    event!(Level::INFO, "Found Authorization header: {}", token);
                    let mc = MC.get().unwrap();

                    // Decode the token (assuming JWT or similar)
                    let maybe_user_id = mc.decrypt_base64_to_string(token);
                    if let Ok(user_id) = maybe_user_id {
                        return Ok(UserId(user_id));
                    }
                }
            }
        }

        let cookies = Cookies::from_request_parts(req, state).await.unwrap();
        let key = KEY.get().unwrap();
        let private_cookies = cookies.private(key);
        event!(Level::DEBUG, "In from_request_parts got private cookies");

        let user_id_cookie_res = private_cookies.get(USER_COOKIE_NAME);

        event!(
            Level::DEBUG,
            "In from_request_parts got user_id cookie {:?}",
            user_id_cookie_res
        );
        let temp_id = user_id_cookie_res.ok_or(AuthRedirect)?;
        let user_id_cookie = temp_id.value();
        event!(Level::DEBUG, "In parserd userid cookie got user_id");
        Ok(UserId(user_id_cookie.to_string()))
    }
}
#[derive(Error, Debug)]
enum AuthError {
    #[error("CSRF token mismatch or not found")]
    CsrfError,
    #[error("PKCE Error")]
    PkceError,
    #[error("Provider not found")]
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
            AuthError::PkceError => StatusCode::UNAUTHORIZED,
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
    Extension(auth_manager): Extension<Arc<AuthProviderManager>>,
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


