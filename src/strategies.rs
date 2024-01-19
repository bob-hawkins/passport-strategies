use std::fmt::Debug;

use colored::Colorize;
use oauth2::{Scope, TokenUrl};

#[derive(Debug, Clone)]
pub struct FacebookStrategy {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) auth_uri: String,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) request_uri: String,
    pub(crate) token_uri: String,
    pub(crate) redirect_uri: String,
}

impl Default for FacebookStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from("https://www.facebook.com/v18.0/dialog/oauth"),
            scopes: Vec::new(),
            token_uri: String::from("https://graph.facebook.com/v18.0/oauth/access_token"),
            request_uri: String::from("https://graph.facebook.com/me"),
            redirect_uri: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GoogleStrategy {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) auth_uri: String,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) request_uri: String,
    pub(crate) token_uri: String,
    pub(crate) redirect_uri: String,
}

impl Default for GoogleStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from("https://accounts.google.com/o/oauth2/auth"),
            scopes: Vec::new(),
            token_uri: String::from("https://oauth2.googleapis.com/token"),
            request_uri: String::from("https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses,phoneNumbers,metadata,nicknames,photos,userDefined,skills,clientData,addresses,birthdays,calendarUrls,events,ageRanges,interests,coverPhotos,biographies,genders,imClients,memberships,locations,miscKeywords,relations,organizations,urls,userDefined,sipAddresses,occupations,locales"),
            redirect_uri: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GithubStrategy {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) auth_uri: String,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) request_uri: String,
    pub(crate) token_uri: String,
    pub(crate) redirect_uri: String,
}

impl Default for GithubStrategy {
    fn default() -> Self {
        GithubStrategy {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from("https://github.com/login/oauth/authorize"),
            scopes: Vec::new(),
            token_uri: String::from("https://github.com/login/oauth/access_token"),
            request_uri: String::from("https://api.github.com/user"),
            redirect_uri: String::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MicrosoftStrategy {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) auth_uri: String,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) request_uri: String,
    pub(crate) token_uri: String,
    pub(crate) redirect_uri: String,
}

impl Default for MicrosoftStrategy {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            auth_uri: String::from("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=select_account"),
            scopes: Vec::new(),
            token_uri: String::from("https://login.microsoftonline.com/common/oauth2/v2.0/token"),
            request_uri: String::from("https://graph.microsoft.com/v1.0/me"),
            redirect_uri: String::new(),
        }
    }
}

pub trait Strategy: Debug {
    fn redirect_url(&self) -> String;
    fn request_uri(&self) -> String;
    fn scopes(&self) -> Vec<Scope>;
    fn client_id(&self) -> String;
    fn client_secret(&self) -> String;
    fn auth_url(&self) -> String;
    fn token_url(&self) -> Option<TokenUrl>;
}

macro_rules! new_strategy {
    ($($name:ty),*) => {
        $(
            impl $name {
                pub fn new(
                    client_id: &str,
                    client_secret: &str,
                    scopes: Vec<&str>,
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
        )*
    };
}

macro_rules! strategy {
    ($($name:ty),*) => {
        $(
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

                fn token_url(&self) -> Option<TokenUrl> {
                    match TokenUrl::new(self.token_uri.clone()) {
                        Ok(token) => Some(token),
                        Err(err) => panic!("{}{}", "Invalid Token URL: ".bold().red(), err),
                    }
                }
            }
        )*
    };
}

strategy!(
    GithubStrategy,
    GoogleStrategy,
    MicrosoftStrategy,
    FacebookStrategy
);

new_strategy!(
    GithubStrategy,
    GoogleStrategy,
    MicrosoftStrategy,
    FacebookStrategy
);

// impl<C> Message for Strategies<C>
// where
//     C: std::marker::Unpin + ToString + Clone + Send + 'static,
//     Self: Strategy<C> + std::marker::Unpin + Send + 'static,
// {
//     type Result = Option<PassPortBasicClient<Self, C>>;
// }
