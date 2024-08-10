//!
//! This example showcases the Discord OAuth2 process using passport for requesting access to the the user's profile.
//!
//! Before running it, you'll need to generate your own Discord OAuth2 credentials.
//!

use actix_web::{
    http,
    middleware::Logger,
    web::{self, Data, Query},
    App, HttpResponse, HttpServer,
};

use passport_strategies::{
    passport::{Choice, Passport, Redirect, StateCode},
    strategies::{DiscordStrategy, GoogleStrategy, RedditStrategy},
};

use tokio::sync::RwLock;

pub async fn discord(passport: Data<RwLock<Passport>>) -> HttpResponse {
    let mut auth = passport.write().await;

    let url = auth.redirect_url(Choice::Discord);

    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url))
        .finish()
}

pub async fn reddit(passport: Data<RwLock<Passport>>) -> HttpResponse {
    let mut auth = passport.write().await;

    let url = auth.redirect_url(Choice::Reddit);

    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url))
        .finish()
}

pub async fn google(passport: Data<RwLock<Passport>>) -> HttpResponse {
    let mut auth = passport.write().await;

    let url = auth.redirect_url(Choice::Google);

    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url))
        .finish()
}

/// With reddit, you still have to go an extra mile to get the user profile.
/// Passport only retrieves the access_token and refresh token for RedditStrategy unlike
/// the other strategies
/// The user profile can be accessed at (https://oauth.reddit.com/api/v1/me)
pub async fn authenticate_reddit(
    Query(statecode): Query<StateCode>,
    passport: Data<RwLock<Passport>>,
) -> HttpResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth.authenticate(Choice::Reddit, statecode, redirect).await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url.to_string()))
        .finish()
}

pub async fn authenticate_google(
    Query(statecode): Query<StateCode>,
    passport: Data<RwLock<Passport>>,
) -> HttpResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth.authenticate(Choice::Google, statecode, redirect).await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url.to_string()))
        .finish()
}

pub async fn authenticate_discord(
    Query(statecode): Query<StateCode>,
    passport: Data<RwLock<Passport>>,
) -> HttpResponse {
    let mut auth = passport.write().await;
    let redirect = auth.redirects();
    let (_response, url) = auth
        .authenticate(Choice::Discord, statecode, redirect)
        .await;

    // You will receive the redirect url which is determined based on authentication status `failed` or `success`
    // and an `Oauth2ServerResponse` which contains the access_token, refresh_token and user profile.
    // You can go ahead and save the user profile in the database or use the tokens to request for more
    // data of the user.

    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url.to_string()))
        .finish()
}

pub async fn signup_get() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8" />
           <meta name="viewport" content="width=device-width, initial-scale=1.0" />
           <title>Auth Demo</title>
       </head>
           <a href="/discord">discord</a>
           <a href="/google">google</a>
           <a href="/reddit">reddit</a>
       </body>
       </html>
       "#;
    HttpResponse::Ok().body(html)
}

pub async fn success() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8" />
           <meta name="viewport" content="width=device-width, initial-scale=1.0" />
           <title>Auth Demo</title>
       </head>
           <h1>Success. Authentication completed well :)</h1>
       </body>
       </html>
       "#;
    HttpResponse::Ok().body(html)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "debug");

    tracing_subscriber::fmt::init();

    let passport = Passport::default()
        .redirect_urls(Redirect::new(
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
        )?;

    let passport_clone = Data::new(RwLock::new(passport));
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(passport_clone.clone())
            .route(
                "/<redirect_url_endpoint_for_discord>",
                web::get().to(authenticate_discord),
            )
            .route(
                "/<redirect_url_endpoint_for_google>",
                web::get().to(authenticate_google),
            )
            .route("/signup", web::get().to(signup_get))
            .route("/google", web::get().to(google))
            .route("/discord", web::get().to(discord))
            .route("/success", web::get().to(success))
            .route("/reddit", web::get().to(reddit))
            .route(
                "<redirect_url_endpoint_for_reddit>",
                web::get().to(authenticate_reddit),
            )
    })
    .bind("127.0.0.1:<redirect_url_port>")?
    .run()
    .await?;

    Ok(())
}
