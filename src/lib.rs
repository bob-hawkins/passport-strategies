//!
//! # Contents
//!   * Getting Started
//!   * Examples
//! # Importing `passport-strategies`
//!
//! This library is a thin wrapper of [`oauth2`](https://crates.io/crates/oauth2) that simplifies the auth flow.
//! ```toml
//! passport-strategies = { version = "1" }
//! ```
//! # Example (Microsoft)
//! 
//! ```rust,no_run
//!  use passport_strategies::strategies::MicrosoftStrategy;
//!  use passport_strategies::basic_client::PassPortBasicClient;
//!  
//!  let mut passport = PassPortBasicClient::default();
//!   passport.using(
//!            "microsoft", // Whether it's all caps or not or just an abbreviation or any other word, it's still acceptable provided that you should use it in the passport.authenticate() function.
//!            MicrosoftStrategy::new(
//!                "<client_id>",
//!                "<client_secret>",
//!                vec!["<scope>"],
//!                "<redirect_url>",
//!            ),
//!        );
//! ```
//! 
//! # Example with (actix-web)
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use actix_web::{
//!        http,
//!        middleware::Logger,
//!        web::{self, Data},
//!        App, HttpResponse, HttpServer,
//!    };
//!
//!    use passport_strategies::{
//!        basic_client::{PassPortBasicClient, StateCode},
//!        strategies::MicrosoftStrategy,
//!    };
//!
//!    use tokio::sync::RwLock;
//!
//!    pub async fn msft(passport: Data<Arc<RwLock<PassPortBasicClient>>>) -> HttpResponse {
//!        let mut auth = passport.write().await;
//!        auth.authenticate("microsoft");
//!        let url = auth.generate_redirect_url();
//!        HttpResponse::SeeOther()
//!            .append_header((http::header::LOCATION, url))
//!            .finish()
//!    }
//!
//!    pub async fn authenticate_msft(
//!        auth: Data<Arc<RwLock<PassPortBasicClient>>>,
//!        authstate: web::Query<StateCode>,
//!    ) -> HttpResponse {
//!        let mut auth = auth.write().await;
//!        match auth.get_profile(authstate.0).await {
//!            /// The profile is a json value containing the user profile, access_token and refresh_token.
//!            /// At this point you can proceed to save the profile info in the database.
//!            Ok(profile) => HttpResponse::Ok().json(profile),
//!            Err(error) => HttpResponse::BadRequest().body(error.to_string()),
//!        }
//!    }
//!    pub async fn signup_get() -> HttpResponse {
//!        let html = r#"<!DOCTYPE html>
//!        <html lang="en">
//!        <head>
//!            <meta charset="UTF-8" />
//!            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
//!            <title>Auth Demo</title>
//!            />
//!        </head>
//!            <a href="/microsoft">microsoft</a>
//!        </body>
//!        </html>
//!        "#;
//!        HttpResponse::Ok().body(html)
//!    }
//!
//!    #[tokio::main]
//!    async fn main() -> std::io::Result<()> {
//!        std::env::set_var("RUST_LOG", "debug");
//!        pretty_env_logger::init();
//!
//!        let mut passport = PassPortBasicClient::default();
//!        passport.using(
//!            "microsoft",
//!            MicrosoftStrategy::new(
//!                "<client_id>",
//!                "<client_secret>",
//!                vec!["<scope>"],
//!                "<redirect_url>",
//!            ),
//!        );
//!        
//!        let passport_clone = Arc::new(RwLock::new(passport));
//!        HttpServer::new(move || {
//!            App::new()
//!                .wrap(Logger::default())
//!                .app_data(Data::new(passport_clone.clone()))
//!                .route("/signup", web::get().to(signup_get))
//!                .route("/microsoft", web::get().to(msft))
//!                .route("/auth/microsoft", web::get().to(authenticate_msft))
//!        })
//!        .bind("127.0.0.1:8080")?
//!        .run()
//!        .await?;
//!        Ok(())
//!   }
//! ```







// # Basic Client
/// Contains the `PassPortBasicClient` that holds the strategies.
pub mod basic_client;


// # Strategies
/// Contains all the basic strategies `GoogleStrategy`, `MicrosoftStrategy`, `GithubStrategy` and `FacebookStrategy`.
///  Other strategies will be added later.
pub mod strategies;


