use oauth2::url::ParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CsrfToken supplied does not match")]
    CSRFTokenMismatch,
    #[error("Request Error: `{0}`")]
    Reqwest(String),
    #[error("CsrfToken is missing")]
    MissingCsrfToken,
    /// This happens when user cancels authorization
    #[error("Authorization Code is missing")]
    MissingAuthorizationCode,
    #[error("Authorization Code and CsrfToken are missing")]
    MissingAuthorizationCodeAndCsrfToken,
    #[error("Parse Error: {0}")]
    ParseError(#[from] ParseError),
}
