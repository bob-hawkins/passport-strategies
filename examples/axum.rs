//!
//! This example showcases the Discord OAuth2 process using passport for requesting access to the the user's profile.
//!
//! Before running it, you'll need to generate your own Discord OAuth2 credentials.
//!

use std::sync::Arc;

use axum::{
    extract::Query,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Extension, Router,
};
use passport_strategies::{
    passport::{Choice, Passport},
    strategies::{
        DiscordStrategy, GithubStrategy, GoogleStrategy, MicrosoftStrategy, RedditStrategy,
    },
};

use tokio::sync::RwLock;
use tracing::info;

pub async fn discord(Extension(passport): Extension<Arc<RwLock<Passport>>>) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let url = auth.redirect_url(Choice::Discord);

    Redirect::temporary(&url)
}

pub async fn reddit(Extension(passport): Extension<Arc<RwLock<Passport>>>) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let url = auth.redirect_url(Choice::Reddit);

    Redirect::temporary(&url)
}

pub async fn google(Extension(passport): Extension<Arc<RwLock<Passport>>>) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let url = auth.redirect_url(Choice::Google);

    Redirect::temporary(&url)
}

pub async fn microsoft(Extension(passport): Extension<Arc<RwLock<Passport>>>) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let url = auth.redirect_url(Choice::Microsoft);

    Redirect::temporary(&url)
}

pub async fn github(Extension(passport): Extension<Arc<RwLock<Passport>>>) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let url = auth.redirect_url(Choice::Github);

    Redirect::temporary(&url)
}

/// With reddit, you still have to go an extra mile to get the user profile.
/// Passport only retrieves the access_token and refresh token for RedditStrategy unlike
/// the other strategies
/// The user profile can be accessed at (https://oauth.reddit.com/api/v1/me)
pub async fn authenticate_reddit(
    Extension(passport): Extension<Arc<RwLock<Passport>>>,
    Query(statecode): Query<passport_strategies::passport::StateCode>,
) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth.authenticate(Choice::Reddit, statecode, redirect).await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    Redirect::temporary(&url)
}

pub async fn authenticate_google(
    Extension(passport): Extension<Arc<RwLock<Passport>>>,
    Query(statecode): Query<passport_strategies::passport::StateCode>,
) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth.authenticate(Choice::Google, statecode, redirect).await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    Redirect::temporary(&url)
}

pub async fn authenticate_github(
    Extension(passport): Extension<Arc<RwLock<Passport>>>,
    Query(statecode): Query<passport_strategies::passport::StateCode>,
) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth.authenticate(Choice::Github, statecode, redirect).await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    Redirect::temporary(&url)
}

pub async fn authenticate_msft(
    Extension(passport): Extension<Arc<RwLock<Passport>>>,
    Query(statecode): Query<passport_strategies::passport::StateCode>,
) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth
        .authenticate(Choice::Microsoft, statecode, redirect)
        .await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    Redirect::temporary(&url)
}

pub async fn authenticate_discord(
    Extension(passport): Extension<Arc<RwLock<Passport>>>,
    Query(statecode): Query<passport_strategies::passport::StateCode>,
) -> impl IntoResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth
        .authenticate(Choice::Discord, statecode, redirect)
        .await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    Redirect::temporary(&url)
}

pub async fn signup_get() -> impl IntoResponse {
    let html = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Auth Demo</title>
    </head>
    <body>
        <a href="/discord">discord</a>
        <a href="/google">google</a>
        <a href="/reddit">reddit</a>
        <a href="/microsoft">microsoft</a>
        <a href="/github">github</a>
    </body>
    </html>
    "#;
    Html(html)
}

pub async fn success() -> impl IntoResponse {
    let html = r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Auth Demo</title>
    </head>
    <body>
        <h1>Authentication completed well :)</h1>
    </body>
    </html>
    "#;
    Html(html)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "debug");

    let passport = Passport::default()
        .redirect_urls(passport_strategies::passport::Redirect::new(
            "http://localhost:<redirect_url_port>/signup",
            "http://localhost:<redirect_url_port>/success",
        )?)
        .strategize(
            Choice::Discord,
            DiscordStrategy::new(
                "<client_id>",
                "<client_secret>",
                &["email", "identify"],
                "<redirect_url>",
            ),
        )?
        .strategize(
            Choice::Google,
            GoogleStrategy::new(
                "<client_id>",
                "<client_secret>",
                &["profile"],
                "<redirect_url>",
            ),
        )?
        .strategize(
            Choice::Reddit,
            RedditStrategy::new(
                "<client_id>",
                "<client_secret>",
                &["identity"],
                "<redirect_url>",
            ),
        )?
        .strategize(
            Choice::Microsoft,
            MicrosoftStrategy::new(
                "<client_id>",
                "<client_secret>",
                &["user.read"],
                "<redirect_url>",
            ),
        )?
        .strategize(
            Choice::Github,
            GithubStrategy::new(
                "<client_id>",
                "<client_secret>",
                &["profile"],
                "<redirect_url>",
            ),
        )?;

    let passport_clone = Arc::new(RwLock::new(passport));
    let app = Router::new()
        .route(
            "/<redirect_url_endpoint_for_discord>",
            get(authenticate_discord),
        )
        .route(
            "/<redirect_url_endpoint_for_google>",
            get(authenticate_google),
        )
        .route(
            "/<redirect_url_endpoint_for_microsoft>",
            get(authenticate_msft),
        )
        .route(
            "/<redirect_url_endpoint_for_github>",
            get(authenticate_github),
        )
        .route("/github", get(github))
        .route("/signup", get(signup_get))
        .route("/google", get(google))
        .route("/discord", get(discord))
        .route("/success", get(success))
        .route("/microsoft", get(microsoft))
        .route("/reddit", get(reddit))
        .route(
            "/<redirect_url_endpoint_for_reddit>",
            get(authenticate_reddit),
        )
        .layer(Extension(passport_clone));

    tracing_subscriber::fmt::init();

    info!("Starting server on http://127.0.0.1:<redirect_url_port>");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:<redirect_url_port>")
        .await
        .unwrap();
    axum::serve(listener, app).await?;

    Ok(())
}
