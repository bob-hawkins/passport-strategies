# Passport strategies

Passport strategies for authenticating with Discord, 42, Facebook, Reddit, Google, Microsoft and Github using the OAuth 2.0 API. This library is a thin wrapper of [`oauth2`](https://crates.io/crates/oauth2) that simplifies authentication.
This module lets you authenticate with the above mentioned providers in your applications. By plugging into passport-strategies, (Discord, Microsoft, Google, 42, Reddit, Github and Facebook) authentication can be easily and unobtrusively integrated into any rust application or rust framework.

# Adding `passport-strategies`

```toml
passport-strategies = { version = "0.1.8" }
```

# Usage
## Create an Application
Before using passport-strategies, you must register an application with the respective provider. If you have not already done so, a new application can be created at [`Facebook`](https://developers.facebook.com), [`Google`](https://console.cloud.google.com), [`Github`](https://github.com/settings/developers), [`Microsoft`](https://portal.azure.com), [`Reddit`](https://www.reddit.com/prefs/apps), [`Discord`](https://discord.com/developers/) and [`42`](https://profile.intra.42.fr/oauth/applications/new). Your application will be issued an app ID and app secret, which need to be provided to the strategy. You will also need to configure a redirect URI which matches the route in your application.

# Configure Strategy

The `passport-strategy` authenticates users using the desired provider account and OAuth 2.0 tokens. The `app ID(or in some cases client id)`, `redirect url` and `client secret` obtained when creating an application are supplied as requirements when creating the strategy. You do not need to provide the authorization url and token url.Unlike [`passportjs`](https://www.passportjs.org/), the strategy does not require a verify callback, which receives the access token and optional refresh token, as well as profile which contains the authenticated user's provider profile. Instead, the profile, the access token and optional refresh token is returned to complete authentication.

# Example (Microsoft)

```rust,no_run
 use passport_strategies::strategies::MicrosoftStrategy;
 use passport_strategies::passport::Passport;

 let passport = Passport::default()
        .redirect_urls(passport_strategies::passport::Redirect::new(
            "http://localhost:<redirect_url_port>/signup",
            "http://localhost:<redirect_url_port>/success",
        )?)
        .strategize(
            Choice::Microsoft,
            MicrosoftStrategy::new(
                "<client_id>",
                "<client_secret>",
                &["user.read"],
                "<redirect_url>",
            ),
        )?;
```

# What's new

1. Support for the axum web framework.
2. Reddit Strategy integration.
3. Remove of the logic error in previous versions when multiple users try to authenticate at the same time.
