# Simple OAuth2 Library for Rust

This library provides a straightforward way of adding login and auth to your axum backend. 
Its database agnostic and is designed for projects that require basic OAuth2 functionality with session management through client-side cookies.
I.e. no need for redis or other server side session management.

## Warning!

This is not production ready, there might still be parts of the oidc spec i'm not compliant with as of yet. Please open a issue if you see a bug or a security vulnerability.

## Features

- **Session Management:** Sessions are managed using HTTP cookies, ensuring that the session state is maintained securely on the client's browser.
- **Cookie Expiry:** Session cookies are set to expire after one day, providing a balance between convenience and security.

- **TOOD:** Custom cookie expiry
- **TOOD:** Access token auth

## Getting Started

### Prerequisites

Ensure that you have Rust and Cargo installed on your system. This library uses `axum` for web handling and oauth2 for the basic authentication pingponging with the oauth2 provider.

### Installation

Add this library as a dependency in your `Cargo.toml`:

```toml
[dependencies]
{ask-auth= git:"https://github.com/askasp/ask-auth/"}
```

### Usage

1. Define the type that your provider responds with from the userinfo endpoint 
```rust
struct GoogleUser{
    sub: String
    email: String
}
```

2. Create a struct implementing the Oauth2Provider trait. 

```rust
struct GoogleProvider{
    db_client: Arc<PrismaClient>
    oauth2_config: Oauth2Config,
}
impl Oauth2Provider for GoogleProvider{
    async fn authenticate_and_upsert(&self, user_info: Response) -> Result<UserId, anyhow::Error> {

        let google_user: GoogleUser = user_info.json::<GoogleUser>().await.unwrap();
        let db_user = self.prisma_client.upsert(google_user)
        Ok(UserId(db_user.id.clone().to_string()))
    }
}

```
Add this to your main function to get the login endpoints

```rust
    let mut auth_manager = Oauth2Manager::new();

    auth_manager.add_provider("google".to_string(), GoogleProvier::New());
    let auth_manager = Arc::new(auth_manager);
    let routes = setup_routes(auth_manager, cookie_key_string);

    let app = Router::new()
        .nest("/auth", routes)
        .route("/protected", get(protected))
    ...
```


Ensure the user is authenticated by checking adding UserId as bare of the handler
```rust
async fn protected(user_id: UserId) -> Html<&'static str> {
    Html("<h1>Hello, World protected site</h1>")
}
```
