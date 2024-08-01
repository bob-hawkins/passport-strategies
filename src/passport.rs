use anyhow::{anyhow, bail};
use colored::Colorize;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::sync::Arc;

use crate::strategies::Strategy;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct StateCode {
    state: Option<CsrfToken>,
    code: Option<String>,
}

pub enum PassportResponse {
    FailureRedirect(Url),
    Profile(serde_json::Value),
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub enum Choice {
    Github,
    Google,
    Microsoft,
    Facebook,
    Discord,
    FortyTwo,
}

#[derive(Serialize, Deserialize)]
struct Verifier(PkceCodeVerifier);

#[derive(Clone)]
pub struct Passport {
    strategies: HashMap<Choice, Arc<dyn Strategy>>,
    /// This stores each [`BasicClient`] associated with each [`Strategy`] which will be used to communicate
    /// with the respected provider oauth2 server.
    clients: HashMap<Choice, BasicClient>,
    /// Strategy been operated on currently
    current: Option<Choice>,
    /// [`CsrfToken`] and [`PkceCodeVerifier`]. We need to keep a track of the two which will be used
    /// in getting the [`AccessToken`] from the provider. Thereafter, be deleted from the storage since will no longer be needed.
    sessions: HashMap<String, String>,
}

impl Default for Passport {
    fn default() -> Self {
        Self {
            strategies: HashMap::new(),
            clients: HashMap::new(),
            current: None,
            sessions: HashMap::new(),
        }
    }
}

unsafe impl Send for Passport {}
unsafe impl Sync for Passport {}

impl Passport {
    const USER_AGENT: &'static str = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1";

    pub fn authenticate(&mut self, state: Choice) -> anyhow::Result<()> {
        self.current = Some(state);

        Ok(())
    }

    /// The [`BasicClient`] for each [`Strategy`] is stored. It will be used later on to communicate with oauth2 server
    pub fn strategize<T: Strategy + Send + Clone + 'static>(
        &mut self,
        current: Choice,
        strategy: T,
    ) -> anyhow::Result<()> {
        let auth = match AuthUrl::new(strategy.auth_url().to_string()) {
            Ok(auth_uri) => auth_uri,
            Err(err) => bail!("{}{}", "Invalid Authentication URL: ".bold().red(), err),
        };

        let redirect_url = match RedirectUrl::new(strategy.redirect_url().to_string()) {
            Ok(uri) => uri,
            Err(err) => bail!("{}{}", "Invalid Redirect URL: ".bold().red(), err),
        };

        let client = BasicClient::new(
            ClientId::new(strategy.client_id().to_string()),
            Some(ClientSecret::new(strategy.client_secret().to_string())),
            auth,
            Some(strategy.token_url()?),
        )
        .set_redirect_uri(redirect_url);

        self.clients.insert(current.clone(), client);
        self.strategies.insert(current, Arc::new(strategy));

        Ok(())
    }

    pub fn generate_redirect_url(&mut self) -> anyhow::Result<String> {
        let (pkce_challenge, verifier) = PkceCodeChallenge::new_random_sha256();

        // self.current is the controlling factor for passport to know which strategy is currently being operated on.
        // so, it must be set first.
        if let None = self.current {
            bail!(
                "[`Passport::generate_redirect_url`] should be called after `self.current` is set"
            )
        }

        let current = self.current.as_ref().unwrap();
        let strategy = self.strategies.get(&current).unwrap();
        let scopes = strategy.scopes();
        let client = self.clients.get(&current).unwrap();
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(scopes)
            .url();

        // We need to keep track of the `PkceVerifier` since it will be needed later to verify the `Authorization Code` later sent from the provider server. Tricky, `PkceVerifier` neither implements `Copy` nor `Clone`
        // but only implements `Serialize` and `Deserialize`. So, serializing it to a String then storing it will enable us to work with its clone in
        // `Passport::profile` when setting a pkce verifier for the `Authorization Code`. This way, the compiler won't complain.
        let data = Verifier(verifier);
        let json_value = serde_json::to_string(&data).unwrap();

        self.sessions
            .insert(csrf_token.secret().to_string(), json_value);

        Ok(auth_url.to_string())
    }

    pub async fn profile(&mut self, statecode: StateCode) -> anyhow::Result<PassportResponse> {
        // self.current is the controlling factor for passport to know which strategy is currently being operated on.
        // so, it must be set first.
        if let None = self.current {
            bail!("[`Passport::profile`] should be called after `self.current` is set")
        }

        let current = self.current.as_ref().unwrap();

        // Adding check for StateCode for handling errors incase the authorization is cancelled by the user or csrf and code challenge mismatch.
        // This mean that unlike the previous versions, passport response enum is returned. It can either be a failure_redirect or json profile.
        if statecode.state.is_none() || statecode.code.is_none() {
            return Ok(PassportResponse::FailureRedirect(
                self.strategies.get(&current).unwrap().failure_redirect()?,
            ));
        }

        match self
            .sessions
            .get(statecode.state.as_ref().unwrap().secret())
        {
            Some(verifier) => {
                let json_pkce: Verifier = serde_json::from_str(&verifier).unwrap();
                let clients = self.clients.get(&current).unwrap();
                match clients
                    .clone()
                    .exchange_code(AuthorizationCode::new(statecode.code.unwrap().clone()))
                    .set_pkce_verifier(json_pkce.0)
                    .request_async(async_http_client)
                    .await
                {
                    Ok(access_token) => {
                        self.sessions.remove(statecode.state.unwrap().secret());

                        match reqwest::Client::new()
                            .get(self.strategies.get(&current).unwrap().request_uri())
                            .header(
                                reqwest::header::AUTHORIZATION,
                                format!("Bearer {}", access_token.access_token().secret()),
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
                                        .map_err(|error| anyhow!(error))
                                        .map(|mut profile| {
                                            profile["access_token"] =
                                                serde_json::json!(access_token
                                                    .access_token()
                                                    .secret());
                                            profile["refresh_token"] =
                                                match access_token.refresh_token() {
                                                    Some(token) => {
                                                        serde_json::json!(Some::<String>(
                                                            token.secret().into()
                                                        ))
                                                    }
                                                    None => serde_json::json!(None::<String>),
                                                };
                                            PassportResponse::Profile(profile)
                                        })
                                } else {
                                    anyhow::bail!(response.text().await.unwrap())
                                }
                            }
                            Err(e) => bail!(e),
                        }
                    }
                    Err(err) => {
                        self.sessions.remove(statecode.state.unwrap().secret());
                        anyhow::bail!(err.to_string())
                    }
                }
            }
            // Of Course, incase of csrf token mismatch, a redirect to specified redirect_url would be a nice take.
            None => Ok(PassportResponse::FailureRedirect(
                self.strategies.get(&current).unwrap().failure_redirect()?,
            )),
        }
    }
}
