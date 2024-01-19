use anyhow::anyhow;
use colored::Colorize;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use serde::de::Visitor;

use std::collections::HashMap;
use std::sync::Arc;

use crate::strategies::Strategy;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct StateCode {
    state: CsrfToken,
    code: String,
}

pub struct Verifier(PkceCodeVerifier);

impl serde::Serialize for Verifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_newtype_struct("verifier", &self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Verifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VerifierVisitor;

        impl<'de> Visitor<'de> for VerifierVisitor {
            type Value = Verifier;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("expecting a PkceCodeVerifier")
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                Ok(Verifier(serde::Deserialize::deserialize(deserializer)?))
            }
        }
        deserializer.deserialize_newtype_struct("verifier", VerifierVisitor)
    }
}

#[derive(Clone)]
pub struct PassPortBasicClient {
    types: HashMap<String, Arc<dyn Strategy>>,
    clients: HashMap<String, BasicClient>,
    current: String,
    sessions: HashMap<String, String>,
}

impl Default for PassPortBasicClient {
    fn default() -> Self {
        Self {
            types: HashMap::new(),
            clients: HashMap::new(),
            current: String::new(),
            sessions: HashMap::new(),
        }
    }
}

unsafe impl Send for PassPortBasicClient {}
unsafe impl Sync for PassPortBasicClient {}

impl PassPortBasicClient {
    const USER_AGENT: &'static str = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1";
    pub fn authenticate(&mut self, state: &str) {
        self.current.clear();
        self.current.push_str(state);
    }

    pub fn using<T: Strategy + Send + Clone + 'static>(&mut self, kind: &str, typ: T) {
        let auth = match AuthUrl::new(typ.auth_url().to_string()) {
            Ok(auth_uri) => auth_uri,
            Err(err) => panic!("{}{}", "Invalid Authentication URL: ".bold().red(), err),
        };
        let redirect_url = match RedirectUrl::new(typ.redirect_url().to_string()) {
            Ok(uri) => uri,
            Err(err) => panic!("{}{}", "Invalid Redirect URL: ".bold().red(), err),
        };
        let client = BasicClient::new(
            ClientId::new(typ.client_id().to_string()),
            Some(ClientSecret::new(typ.client_secret().to_string())),
            auth,
            typ.token_url(),
        )
        .set_redirect_uri(redirect_url);
        self.clients.insert(kind.to_string(), client);
        self.types.insert(kind.to_string(), Arc::new(typ));
    }

    pub fn generate_redirect_url(&mut self) -> String {
        let (pkce_challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let typ = self.types.get(&self.current);
        let scopes = typ.unwrap().scopes();

        let client = self.clients.get(&self.current).unwrap();
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            .add_scopes(scopes)
            .url();

        let data = Verifier(verifier);
        let json_value = serde_json::to_string(&data).unwrap();

        self.sessions
            .insert(csrf_token.secret().to_string(), json_value);

        auth_url.to_string()
    }

    pub async fn get_profile(
        &mut self,
        auth_state: StateCode,
    ) -> anyhow::Result<serde_json::Value> {
        match self.sessions.get(auth_state.state.secret()) {
            Some(verifier) => {
                let json_pkce: Verifier = serde_json::from_str(&verifier).unwrap();
                let clients = self.clients.get(&self.current).unwrap();
                match clients
                    .clone()
                    .exchange_code(AuthorizationCode::new(auth_state.code.clone()))
                    .set_pkce_verifier(json_pkce.0)
                    .request_async(async_http_client)
                    .await
                {
                    Ok(access_token) => {
                        self.sessions.remove(auth_state.state.secret());
                        let response = reqwest::Client::new()
                            .get(self.types.get(&self.current).unwrap().request_uri())
                            .header(
                                reqwest::header::AUTHORIZATION,
                                format!("Bearer {}", access_token.access_token().secret()),
                            )
                            .header(reqwest::header::USER_AGENT, Self::USER_AGENT)
                            .send()
                            .await
                            .unwrap();
                        if response.status().is_success() {
                            response
                                .json::<serde_json::Value>()
                                .await
                                .map_err(|error| anyhow!(error))
                                .map(|mut profile| {
                                    profile["access_token"] =
                                        serde_json::json!(access_token.access_token().secret());
                                    profile["refresh_token"] = match access_token.refresh_token() {
                                        Some(token) => {
                                            serde_json::json!(Some::<String>(token.secret().into()))
                                        }
                                        None => serde_json::json!(None::<String>),
                                    };
                                    profile
                                })
                        } else {
                            anyhow::bail!(response.text().await.unwrap())
                        }
                    }
                    Err(err) => anyhow::bail!(err.to_string()),
                }
            }
            None => anyhow::bail!("CSRF TOKEN mismatch"),
        }
    }
}
