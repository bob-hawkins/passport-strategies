# Passport strategies

Passport strategies for authenticating with Discord, Facebook, Google, Microsoft and Github using the OAuth 2.0 API. This library is a thin wrapper of [`oauth2`](https://crates.io/crates/oauth2) that simplifies the auth flow.
This module lets you authenticate with the above mentioned providers in your applications. By plugging into passport-strategies, (Discord, Microsoft, Google, Github and Facebook) authentication can be easily and unobtrusively integrated into any rust application or rust framework.

# Adding `passport-strategies`

```toml
passport-strategies = { version = "0.1.4" }
```

# Usage

Create an Application
Before using passport-strategies, you must register an application with the respective provider. If you have not already done so, a new application can be created at [`Facebook`](https://developers.facebook.com), [`Google`](https://console.cloud.google.com), [`Github`](https://github.com/settings/developers), [`Microsoft`](), [`Discord`]("https://discord.com/developers/"). Your application will be issued an app ID and app secret, which need to be provided to the strategy. You will also need to configure a redirect URI which matches the route in your application.

# Configure Strategy

The `passport-strategy` authenticates users using the desired provider account and OAuth 2.0 tokens. The `app ID(or in some cases client id)`, `redirect url` and `client secret` obtained when creating an application are supplied as requirements when creating the strategy. You do not need to provide the authorization url and token url.Unlike [`passportjs`](https://www.passportjs.org/), the strategy does not require a verify callback, which receives the access token and optional refresh token, as well as profile which contains the authenticated user's provider profile. Instead, the profile containing the access token and optional refresh token is returned to complete authentication.

# Example (Microsoft)

```rust,no_run
 use passport_strategies::strategies::MicrosoftStrategy;
 use passport_strategies::basic_client::PassPortBasicClient;

 let mut passport = PassPortBasicClient::default();
  passport.using(
           "microsoft", // Whether it's all caps or not or just an abbreviation or any other word, it's still acceptable provided that you should use it in the passport.authenticate() function.
           MicrosoftStrategy::new(
               "<client_id>",
               "<client_secret>",
               vec!["<scope>"],
               "<redirect_url>",
               "<failure_redirect>"
           ),
       );
```

# What's new

1. Improved error handling when user cancels authorization or incase of csrf and code challenge mismatch.
2. Discord Strategy integration.
3. I noticed that I accidentally debugged the access token in v0.1.4, so i had to remove it.
