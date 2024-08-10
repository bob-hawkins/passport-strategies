use std::fmt::{Debug, Display};

use super::{
    DISCORD_AUTH_URL, DISCORD_REQUEST_URL, DISCORD_TOKEN_URL, FACEBOOK_AUTH_URL,
    FACEBOOK_REQUEST_URL, FACEBOOK_TOKEN_URL, FORTYTWO_AUTH_URL, FORTYTWO_REQUEST_URL,
    FORTYTWO_TOKEN_URL, GITHUB_AUTH_URL, GITHUB_REQUEST_URL, GITHUB_TOKEN_URL, GOOGLE_AUTH_URL,
    GOOGLE_REQUEST_URL, GOOGLE_TOKEN_URL, MICROSOFT_AUTH_URL, MICROSOFT_REQUEST_URL,
    MICROSOFT_TOKEN_URL, REDDIT_AUTH_URL, REDDIT_REQUEST_URL, REDDIT_TOKEN_URL,
};
use oauth2::{Scope, TokenUrl};

#[derive(Clone)]
pub struct PAccessToken(pub String);

impl Display for PAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "PAccessToken([Redacted])")
    }
}

impl Debug for PAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "PAccessToken([Redacted])")
    }
}

#[derive(Clone)]
pub struct PRefreshToken(pub String);

impl Display for PRefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "PRefreshToken([Redacted])")
    }
}

impl Debug for PRefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", "PRefreshToken([Redacted])")
    }
}

impl Default for RedditStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(REDDIT_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(REDDIT_TOKEN_URL),
            request_uri: String::from(REDDIT_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

impl Default for FacebookStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(FACEBOOK_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(FACEBOOK_TOKEN_URL),
            request_uri: String::from(FACEBOOK_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

impl Default for GoogleStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(GOOGLE_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(GOOGLE_TOKEN_URL),
            request_uri: String::from(GOOGLE_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

impl Default for GithubStrategy {
    fn default() -> Self {
        GithubStrategy {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(GITHUB_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(GITHUB_TOKEN_URL),
            request_uri: String::from(GITHUB_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

impl Default for DiscordStrategy {
    fn default() -> Self {
        DiscordStrategy {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(DISCORD_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(DISCORD_TOKEN_URL),
            request_uri: String::from(DISCORD_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

impl Default for MicrosoftStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(MICROSOFT_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(MICROSOFT_TOKEN_URL),
            request_uri: String::from(MICROSOFT_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

impl Default for FortyTwoStrategy {
    fn default() -> Self {
        FortyTwoStrategy {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from(FORTYTWO_AUTH_URL),
            scopes: Vec::new(),
            token_uri: String::from(FORTYTWO_TOKEN_URL),
            request_uri: String::from(FORTYTWO_REQUEST_URL),
            redirect_uri: String::new(),
        }
    }
}

pub trait Strategy: Send + Sync {
    fn redirect_url(&self) -> String;
    fn request_uri(&self) -> String;
    fn scopes(&self) -> Vec<Scope>;
    fn client_id(&self) -> String;
    fn client_secret(&self) -> String;
    fn auth_url(&self) -> String;
    fn token_url(&self) -> Result<TokenUrl, Error>;
}

macro_rules! create_struct {
    ($($name:ident),*) => {
        use crate::error::Error;
        $(
            #[derive(Clone)]
            pub struct $name {
                pub(crate) client_id: String,
                pub(crate) client_secret: String,
                pub(crate) auth_uri: String,
                pub(crate) scopes: Vec<Scope>,
                pub(crate) request_uri: String,
                pub(crate) token_uri: String,
                pub(crate) redirect_uri: String,
            }

            impl $name {
                pub fn new(
                    client_id: &str,
                    client_secret: &str,
                    scopes: &[&str],
                    redirect_uri: &str,
                ) -> Self {
                    let mut strategy = Self::default();
                    strategy.client_id.push_str(client_id);
                    strategy.client_secret.push_str(client_secret);
                    strategy.redirect_uri.push_str(redirect_uri);

                    strategy
                        .scopes
                        .extend(scopes.iter().map(ToString::to_string).map(Scope::new));
                    strategy
                }
            }

            impl Strategy for $name {
                fn request_uri(&self) -> String {
                    self.request_uri.clone()
                }
                fn scopes(&self) -> Vec<Scope> {
                    self.scopes.clone()
                }
                fn client_id(&self) -> String {
                    self.client_id.clone()
                }

                fn client_secret(&self) -> String {
                    self.client_secret.clone()
                }

                fn auth_url(&self) -> String {
                    self.auth_uri.clone()
                }

                fn redirect_url(&self) -> String {
                    self.redirect_uri.clone()
                }

                fn token_url(&self) -> Result<TokenUrl, Error> {
                    match TokenUrl::new(self.token_uri.clone()) {
                        Ok(token) => Ok(token),
                        Err(err) => Err(Error::ParseError(err)),
                    }
                }
            }

        )*

    };
}

create_struct!(
    GithubStrategy,
    GoogleStrategy,
    MicrosoftStrategy,
    FacebookStrategy,
    DiscordStrategy,
    FortyTwoStrategy,
    RedditStrategy
);
