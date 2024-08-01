//!
//! This example showcases the Google OAuth2 process using passport for requesting access to the the user's profile.
//!
//! Before running it, you'll need to generate your own Google OAuth2 credentials.
//!

use actix_web::{
    http,
    middleware::Logger,
    web::{self, Data, Query},
    App, HttpResponse, HttpServer,
};

use passport_strategies::{
    passport::{Choice, Passport, PassportResponse, StateCode},
    strategies::GoogleStrategy,
};

use tokio::sync::RwLock;

pub async fn google(passport: Data<RwLock<Passport>>) -> HttpResponse {
    let mut auth = passport.write().await;
    auth.authenticate(Choice::Google).unwrap();
    let url = auth.generate_redirect_url().unwrap();
    HttpResponse::SeeOther()
        .append_header((http::header::LOCATION, url))
        .finish()
}

pub async fn authenticate_google(
    auth: Data<RwLock<Passport>>,
    Query(authstate): Query<StateCode>,
) -> HttpResponse {
    let mut auth = auth.write().await;
    match auth.profile(authstate).await {
        Ok(profile) => match profile {
            PassportResponse::Profile(pr) => HttpResponse::Ok().json(pr),
            PassportResponse::FailureRedirect(f) => HttpResponse::SeeOther()
                .append_header((http::header::LOCATION, f.to_string()))
                .finish(),
        },
        Err(error) => HttpResponse::BadRequest().body(error.to_string()),
    }
}
pub async fn signup_get() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
       <html lang="en">
       <head>
           <meta charset="UTF-8" />
           <meta name="viewport" content="width=device-width, initial-scale=1.0" />
           <title>Auth Demo</title>
       </head>
           <a href="/google">google</a>
       </body>
       </html>
       "#;
    HttpResponse::Ok().body(html)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::env::set_var("RUST_LOG", "debug");

    let mut passport = Passport::default();
    passport.strategize(
        Choice::Google,
        GoogleStrategy::new(
            "<client_id>",
            "<client_secret>",
            vec!["profile"],
            "<redirect_url>",
            "http://localhost:<redirect_url_port>/signup",
        ),
    )?;

    let passport_clone = Data::new(RwLock::new(passport));
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(passport_clone.clone())
            .route("/signup", web::get().to(signup_get))
            .route("/google", web::get().to(google))
            .route("/auth/google", web::get().to(authenticate_google))
    })
    .bind("127.0.0.1:<redirect_url_port>")?
    .run()
    .await?;
    Ok(())
}