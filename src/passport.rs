use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Error;
use crate::strategies::{PAccessToken, PRefreshToken, Strategy};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct StateCode {
    state: Option<CsrfToken>,
    code: Option<String>,
}

pub struct Redirect {
    failure_redirect: Url,
    success_redirect: Url,
}

impl Redirect {
    pub fn new(failure_redirect: &str, success_redirect: &str) -> Result<Self, Error> {
        let redirect = failure_redirect
            .parse::<reqwest::Url>()
            .map_err(Error::ParseError)
            .map(|r| r)?;
        let success = success_redirect
            .parse::<reqwest::Url>()
            .map_err(Error::ParseError)
            .map(|r| r)?;

        Ok(Self {
            failure_redirect: redirect,
            success_redirect: success,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub enum Choice {
    Github,
    Google,
    Microsoft,
    Facebook,
    Discord,
    FortyTwo,
    Reddit,
}

#[derive(Debug, Clone)]
pub struct Oauth2ServerResponse {
    pub access_token: PAccessToken,
    pub refresh_token: Option<PRefreshToken>,
    pub profile: Value,
}

#[derive(Serialize, Deserialize)]
struct Verifier(PkceCodeVerifier);

#[derive(Clone)]
pub struct Passport {
    strategies: HashMap<Choice, Arc<dyn Strategy>>,
    /// This stores each [`BasicClient`] associated with each [`Strategy`] which will be used to communicate
    /// with the respected provider oauth2 server.
    clients: HashMap<Choice, BasicClient>,
    /// [`CsrfToken`] and [`PkceCodeVerifier`]. We need to keep a track of the two which will be used
    /// in getting the [`AccessToken`] from the provider.
    /// Thereafter, be deleted from the storage since will no longer be needed.
    sessions: HashMap<String, String>,
    success_redirect: Option<Url>,
    failure_redirect: Option<Url>,
}

impl Default for Passport {
    fn default() -> Self {
        Self {
            strategies: HashMap::new(),
            clients: HashMap::new(),
            sessions: HashMap::new(),
            success_redirect: None,
            failure_redirect: None,
        }
    }
}

unsafe impl Send for Passport {}
unsafe impl Sync for Passport {}

impl Passport {
    const USER_AGENT: &'static str =
        "passport-strategies/1.0 (+https://crates.io/crates/passport-strategies)";

    pub fn redirect_urls(mut self, redirects: Redirect) -> Self {
        self.success_redirect = Some(redirects.success_redirect);
        self.failure_redirect = Some(redirects.failure_redirect);

        self
    }

    pub fn redirects(&self) -> Redirect {
        Redirect {
            failure_redirect: self.failure_redirect.as_ref().unwrap().clone(),
            success_redirect: self.success_redirect.as_ref().unwrap().clone(),
        }
    }

    pub fn strategize<T>(mut self, current: Choice, strategy: T) -> Result<Self, Error>
    where
        T: Strategy + Sync + Send + 'static,
    {
        let auth = match AuthUrl::new(strategy.auth_url().to_string()) {
            Ok(auth_uri) => auth_uri,
            Err(err) => return Err(Error::ParseError(err)),
        };

        let redirect_url = match RedirectUrl::new(strategy.redirect_url().to_string()) {
            Ok(uri) => uri,
            Err(err) => return Err(Error::ParseError(err)),
        };

        let client = BasicClient::new(
            ClientId::new(strategy.client_id().to_string()),
            Some(ClientSecret::new(strategy.client_secret().to_string())),
            auth,
            Some(strategy.token_url()?),
        )
        .set_redirect_uri(redirect_url);

        self.clients.insert(current.clone(), client);
        self.strategies.insert(current.clone(), Arc::new(strategy));

        Ok(self)
    }

    pub fn redirect_url(&mut self, choice: Choice) -> String {
        let (pkce_challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let strategy = self.strategies.get(&choice).unwrap();
        let scopes = strategy.scopes();
        let client = self.clients.get(&choice).unwrap();
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(scopes)
            .url();

        // We need to keep track of the `PkceVerifier` since it will be needed later to verify
        // the `Authorization Code` later sent from the provider server.
        // Tricky, `PkceVerifier` neither implements `Copy` nor `Clone`
        // but only implements `Serialize` and `Deserialize`. So, serializing it to a String then
        // storing it will enable us to work with its clone in
        // `Passport::profile` when setting a pkce verifier for the `Authorization Code`. This way, the compiler won't complain.
        let data = Verifier(verifier);
        let json_value = serde_json::to_string(&data).unwrap();

        self.sessions
            .insert(csrf_token.secret().to_string(), json_value);

        auth_url.to_string()
    }

    pub async fn authenticate(
        &mut self,
        choice: Choice,
        statecode: StateCode,
        redirects: Redirect,
    ) -> (Option<Oauth2ServerResponse>, String) {
        match self.profile(choice, statecode).await {
            Ok(value) => {
                info!("oauth2 authentication completed with no errors");

                (Some(value), redirects.success_redirect.to_string())
            }

            Err(error) => {
                warn!(?error);

                (None, redirects.failure_redirect.to_string())
            }
        }
    }

    async fn profile(
        &mut self,
        choice: Choice,
        statecode: StateCode,
    ) -> Result<Oauth2ServerResponse, Error> {
        if statecode.state.is_none() && statecode.code.is_none() {
            return Err(Error::MissingAuthorizationCodeAndCsrfToken);
        }

        if statecode.state.is_none() {
            return Err(Error::MissingCsrfToken);
        }

        if statecode.code.is_none() {
            return Err(Error::MissingAuthorizationCode);
        }

        let bind = &self.strategies;
        let strategy = bind.get(&choice).unwrap();

        match self
            .sessions
            .get(statecode.state.as_ref().unwrap().secret())
        {
            Some(verifier) => {
                let json_pkce: Verifier = serde_json::from_str(&verifier).unwrap();
                let clients = self.clients.get(&choice).unwrap();

                if let Choice::Reddit = choice {
                    let response = reqwest::Client::new()
                        .post(strategy.token_url()?.to_string())
                        .basic_auth(strategy.client_id(), Some(strategy.client_secret()))
                        .form(&[
                            ("grant_type", "authorization_code"),
                            ("code", statecode.code.clone().unwrap().as_str()),
                            ("redirect_uri", &strategy.redirect_url()),
                            ("code_verifier", &verifier),
                        ])
                        .header(reqwest::header::USER_AGENT, Self::USER_AGENT)
                        .send()
                        .await
                        .map_err(|e| Error::Reqwest(e.to_string()))
                        .map(|v| v)?;
                    
                    self.sessions.remove(statecode.state.unwrap().secret()); // Clearing the nolonger needed verifier from the memmory
                    if response.status().is_success() {
                        response
                            .json::<serde_json::Value>()
                            .await
                            .map_err(|error| Error::Reqwest(error.to_string()))
                            .map(|profile| async move {
                                let mut refresh_token = None;

                                let access_token =
                                    PAccessToken(profile["access_token"].to_string());

                                if profile["refresh_token"].is_string() {
                                    refresh_token =
                                        Some(PRefreshToken(profile["refresh_token"].to_string()));
                                };

                                return Ok(Oauth2ServerResponse {
                                    access_token,
                                    refresh_token,
                                    profile,
                                });
                            })?
                            .await
                    } else {
                        return Err(Error::Reqwest(response.text().await.unwrap()));
                    }
                } else {
                    match clients
                        .clone()
                        .exchange_code(AuthorizationCode::new(statecode.code.clone().unwrap()))
                        .set_pkce_verifier(json_pkce.0)
                        .request_async(async_http_client)
                        .await
                    {
                        Ok(token) => {
                            self.sessions.remove(statecode.state.unwrap().secret()); // Clearing the nolonger needed verifier from the memmory

                            match reqwest::Client::new()
                                .get(strategy.request_uri())
                                .header(
                                    reqwest::header::AUTHORIZATION,
                                    format!("Bearer {}", token.access_token().secret()),
                                )
                                .header(reqwest::header::USER_AGENT, Self::USER_AGENT)
                                .send()
                                .await
                            {
                                Ok(response) => {
                                    if response.status().is_success() {
                                        response
                                            .json::<serde_json::Value>()
                                            .await
                                            .map_err(|error| Error::Reqwest(error.to_string()))
                                            .map(|profile| {
                                                let mut refresh_token = None;

                                                let access_token = PAccessToken(
                                                    token.access_token().secret().into(),
                                                );

                                                if let Some(re) = token.refresh_token() {
                                                    refresh_token =
                                                        Some(PRefreshToken(re.secret().to_owned()));
                                                };

                                                return Ok(Oauth2ServerResponse {
                                                    access_token,
                                                    refresh_token,
                                                    profile,
                                                });
                                            })?
                                    } else {
                                        Err(Error::Reqwest(response.text().await.unwrap()))
                                    }
                                }
                                Err(e) => Err(Error::Reqwest(e.to_string())),
                            }
                        }
                        Err(err) => {
                            self.sessions.remove(statecode.state.unwrap().secret()); // Clearing the nolonger needed verifier from the memmory
                            Err(Error::Reqwest(err.to_string()))
                        }
                    }
                }
            }
            None => Err(Error::CSRFTokenMismatch),
        }
    }
}
