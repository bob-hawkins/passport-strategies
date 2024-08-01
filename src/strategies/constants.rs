#![allow(unused)]

// Google
pub(crate) const GOOGLE_AUTH_URL: &'static str = "https://accounts.google.com/o/oauth2/auth";
pub(crate) const GOOGLE_TOKEN_URL: &'static str = "https://oauth2.googleapis.com/token";
pub(crate) const GOOGLE_REQUEST_URL: &'static str = "https://people.googleapis.com/v1/people/me?personFields=names,emailAddresses,phoneNumbers,metadata,nicknames,photos,userDefined,skills,clientData,addresses,birthdays,calendarUrls,events,ageRanges,interests,coverPhotos,biographies,genders,imClients,memberships,locations,miscKeywords,relations,organizations,urls,userDefined,sipAddresses,occupations,locales";

// Microsoft
pub(crate) const MICROSOFT_AUTH_URL: &'static str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=select_account";

pub(crate) const MICROSOFT_TOKEN_URL: &'static str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/token";
pub(crate) const MICROSOFT_REQUEST_URL: &'static str = "https://graph.microsoft.com/v1.0/me";

// Github
pub(crate) const GITHUB_AUTH_URL: &'static str = "https://github.com/login/oauth/authorize";
pub(crate) const GITHUB_TOKEN_URL: &'static str = "https://github.com/login/oauth/access_token";
pub(crate) const GITHUB_REQUEST_URL: &'static str = "https://api.github.com/user";

// Discord
pub(crate) const DISCORD_AUTH_URL: &'static str = "https://discord.com/oauth2/authorize";
pub(crate) const DISCORD_TOKEN_URL: &'static str = "https://discord.com/api/oauth2/token";
pub(crate) const DISCORD_REQUEST_URL: &'static str = "https://discord.com/api/users/@me";

// 42
pub(crate) const FORTYTWO_AUTH_URL: &'static str = "https://api.intra.42.fr/oauth/authorize";
pub(crate) const FORTYTWO_TOKEN_URL: &'static str = "https://api.intra.42.fr/oauth/token";
pub(crate) const FORTYTWO_REQUEST_URL: &'static str = "https://api.intra.42.fr/v2/me";

// Facebook
pub(crate) const FACEBOOK_AUTH_URL: &'static str = "https://www.facebook.com/v18.0/dialog/oauth";
pub(crate) const FACEBOOK_TOKEN_URL: &'static str =
    "https://graph.facebook.com/v18.0/oauth/access_token";
pub(crate) const FACEBOOK_REQUEST_URL: &'static str = "https://graph.facebook.com/me";
