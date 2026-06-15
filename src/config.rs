use serde::Deserialize;
use std::fmt::{Display, Formatter};

/// Application configuration loaded from environment variables.
///
/// Uses `dotenvy` to load a `.env` file and `envy` to deserialize
/// into this struct. All fields are required unless a `default` is given.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Full `PostgreSQL` connection string.
    pub database_url: String,

    /// Secret used to sign JWT access tokens. Must be at least 32 bytes.
    pub jwt_secret: String,

    /// Redis connection URL used for the OAuth PKCE state store.
    ///
    /// Example: `redis://127.0.0.1:6379`
    /// Required when any OAuth provider is configured; the application will
    /// panic at startup if OAuth is enabled but this is absent.
    pub redis_url: String,

    /// Access token lifetime in seconds (default: 15 minutes).
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry_secs: u64,

    /// Refresh token lifetime in seconds (default: 7 days).
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry_secs: u64,

    /// TCP address the server binds to (default: 0.0.0.0:8080).
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// OAuth 2.0 provider configurations.
    ///
    /// Each provider is optional; the application only enables the providers
    /// whose credentials are present in the environment.
    #[serde(default)]
    pub oauth: OAuthConfig,
}

impl Config {
    /// Load configuration from the environment, optionally reading a `.env` file first.
    ///
    /// # Errors
    ///
    /// Returns an [`envy::Error`] if any required environment variables are missing or
    /// cannot be deserialized into the expected types.
    pub fn from_env() -> Result<Self, envy::Error> {
        let _ = dotenvy::dotenv();
        let mut config: Config = envy::from_env()?;
        config.oauth = OAuthConfig::from_env();
        Ok(config)
    }
}

/// Top-level OAuth configuration grouping all supported providers.
///
/// Fields are `None` when the corresponding environment variables are absent,
/// which causes the provider's routes to return `404 Not Found` at startup.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthConfig {
    /// Google OAuth 2.0 credentials.
    ///
    /// Required env vars: `OAUTH_GOOGLE_CLIENT_ID`, `OAUTH_GOOGLE_CLIENT_SECRET`,
    /// `OAUTH_GOOGLE_REDIRECT_URI`.
    #[serde(default)]
    pub google: Option<OAuthProviderConfig>,

    /// GitHub OAuth 2.0 credentials.
    ///
    /// Required env vars: `OAUTH_GITHUB_CLIENT_ID`, `OAUTH_GITHUB_CLIENT_SECRET`,
    /// `OAUTH_GITHUB_REDIRECT_URI`.
    #[serde(default)]
    pub github: Option<OAuthProviderConfig>,
}

impl OAuthConfig {
    /// Return the [`OAuthProviderConfig`] for a given [`OAuthProvider`], if configured.
    ///
    /// Used by `services/oauth.rs` to look up credentials without a match arm at every
    /// call site.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::config::{OAuthConfig, OAuthProvider};
    /// let cfg = OAuthConfig::default();
    /// assert!(cfg.provider(OAuthProvider::Google).is_none());
    /// ```
    #[must_use]
    pub fn provider(&self, provider: OAuthProvider) -> Option<&OAuthProviderConfig> {
        match provider {
            OAuthProvider::Google => self.google.as_ref(),
            OAuthProvider::GitHub => self.github.as_ref(),
        }
    }

    fn from_env() -> Self {
        let google = match (
            std::env::var("OAUTH_GOOGLE_CLIENT_ID").ok(),
            std::env::var("OAUTH_GOOGLE_CLIENT_SECRET").ok(),
            std::env::var("OAUTH_GOOGLE_REDIRECT_URI").ok(),
        ) {
            (Some(client_id), Some(client_secret), Some(redirect_uri)) => {
                Some(OAuthProviderConfig {
                    client_id,
                    client_secret,
                    redirect_uri,
                })
            }
            _ => None,
        };

        let github = match (
            std::env::var("OAUTH_GITHUB_CLIENT_ID").ok(),
            std::env::var("OAUTH_GITHUB_CLIENT_SECRET").ok(),
            std::env::var("OAUTH_GITHUB_REDIRECT_URI").ok(),
        ) {
            (Some(client_id), Some(client_secret), Some(redirect_uri)) => {
                Some(OAuthProviderConfig {
                    client_id,
                    client_secret,
                    redirect_uri,
                })
            }
            _ => None,
        };

        Self { google, github }
    }
}

/// Per-provider OAuth 2.0 credentials and endpoint configuration.
///
/// Deserialized from environment variables prefixed by the provider name, e.g.
/// `OAUTH_GOOGLE_CLIENT_ID`. The prefix is applied by the [`OAuthConfig`] parent
/// via `envy`'s flattened prefix mechanism.
#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProviderConfig {
    /// OAuth application client ID issued by the provider.
    pub client_id: String,

    /// OAuth application client secret issued by the provider.
    ///
    /// Treat this value as a password: never log it or expose it in error messages.
    pub client_secret: String,

    /// Absolute URI the provider redirects to after user consent.
    ///
    /// Must be registered in the provider's developer console and match exactly —
    /// including scheme, host, port, and path.
    pub redirect_uri: String,
}

/// Supported OAuth 2.0 identity providers.
///
/// Extend this enum and the corresponding [`OAuthConfig`] field when adding a new
/// provider. The `Display` impl is used to build environment-variable names and
/// URL path segments (e.g. `/auth/github`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OAuthProvider {
    Google,
    GitHub,
}

impl OAuthProvider {
    /// Parse a provider from a URL path segment.
    ///
    /// # Errors
    ///
    /// Returns `None` for unrecognised strings so callers can return `404 Not Found`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::config::OAuthProvider;
    /// assert_eq!(OAuthProvider::from_slug("github"), Some(OAuthProvider::GitHub));
    /// assert_eq!(OAuthProvider::from_slug("unknown"), None);
    /// ```
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "google" => Some(Self::Google),
            "github" => Some(Self::GitHub),
            _ => None,
        }
    }

    /// Return the lowercase URL path segment for this provider.
    ///
    /// Used when constructing `/auth/{provider}` and `/auth/{provider}/callback` routes.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
        }
    }
}

impl Display for OAuthProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

fn default_access_token_expiry() -> u64 {
    900 // 15 minutes
}

fn default_refresh_token_expiry() -> u64 {
    604_800 // 7 days
}

fn default_bind_addr() -> String {
    "0.0.0.0:8080".to_owned()
}
