use std::sync::Arc;

use deadpool_redis::{Config as RedisConfig, Pool as RedisPool, Runtime};
use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse, basic::BasicClient,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::{OAuthProvider, OAuthProviderConfig};
use crate::errors::OAuthError;

/// Serialised form of a pending authorization, stored as a JSON string in Redis.
///
/// Only the fields that need to survive the round-trip are included.
/// `PkceCodeVerifier` is a newtype over `String` so we store its secret directly.
#[derive(Serialize, Deserialize)]
struct StoredPendingAuth {
    /// The raw PKCE verifier secret.
    verifier_secret: String,
    /// Which provider initiated this flow.
    provider: String,
}

/// Redis-backed store for short-lived PKCE/CSRF state tokens.
///
/// Each entry is keyed by the opaque `state` string that travels to the
/// provider and back. Keys are set with a TTL of [`STATE_TTL_SECS`] and are
/// consumed atomically on retrieval, preventing replay attacks.
///
/// # Multi-instance behaviour
///
/// Because state is stored in Redis rather than process memory, any number of
/// application replicas can handle the callback for an authorization that was
/// initiated on a different instance.
pub struct StateStore {
    pool: RedisPool,
}

/// Lifetime of a pending authorization entry in Redis (seconds).
const STATE_TTL_SECS: u64 = 600; // 10 minutes

/// Namespace prefix for all OAuth state keys.
const KEY_PREFIX: &str = "oauth_state:";

impl StateStore {
    /// Construct a [`StateStore`] from a Redis connection URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid or the pool cannot be created.
    pub fn new(redis_url: &str) -> Result<Self, deadpool_redis::CreatePoolError> {
        let cfg = RedisConfig::from_url(redis_url);
        let pool = cfg.create_pool(Some(Runtime::Tokio1))?;
        Ok(Self { pool })
    }

    /// Wrap in an [`Arc`] for sharing across Axum handler clones.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Persist a pending auth entry with a TTL.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] if the Redis connection or write fails.
    pub async fn insert(
        &self,
        state: &str,
        provider: OAuthProvider,
        verifier: PkceCodeVerifier,
    ) -> Result<(), OAuthError> {
        let payload = serde_json::to_string(&StoredPendingAuth {
            verifier_secret: verifier.secret().clone(),
            provider: provider.to_string(),
        })
        // StoredPendingAuth only contains String fields; serialisation cannot fail.
        .expect("StoredPendingAuth serialisation is infallible");

        let key = format!("{KEY_PREFIX}{state}");
        let mut conn = self.pool.get().await.map_err(OAuthError::StateStore)?;
        conn.set_ex::<_, _, ()>(&key, payload, STATE_TTL_SECS)
            .await
            .map_err(OAuthError::StateStoreRedis)?;

        Ok(())
    }

    /// Atomically retrieve and delete the entry for `state`.
    ///
    /// Returns `None` when the key is absent (never existed, already consumed,
    /// or expired). The atomic GETDEL ensures a valid callback URL cannot be
    /// replayed even if observed in browser history or server logs.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] if the Redis connection fails or the stored
    /// value cannot be deserialised.
    pub async fn take(
        &self,
        state: &str,
        expected_provider: OAuthProvider,
    ) -> Result<PkceCodeVerifier, OAuthError> {
        let key = format!("{KEY_PREFIX}{state}");
        let mut conn = self.pool.get().await.map_err(OAuthError::StateStore)?;

        // GETDEL atomically returns the value and removes the key in one round-trip.
        // Available since Redis 6.2; for older Redis use a MULTI/EXEC pipeline.
        let raw: Option<String> = conn
            .get_del(&key)
            .await
            .map_err(OAuthError::StateStoreRedis)?;
        let raw = raw.ok_or(OAuthError::InvalidState)?;
        let stored: StoredPendingAuth =
            serde_json::from_str(&raw).map_err(|_| OAuthError::InvalidState)?;
        let actual = OAuthProvider::from_slug(&stored.provider).ok_or(OAuthError::InvalidState)?;
        if actual != expected_provider {
            return Err(OAuthError::ProviderMismatch {
                expected: expected_provider,
                actual,
            });
        }

        Ok(PkceCodeVerifier::new(stored.verifier_secret))
    }
}

/// Provider-agnostic user identity returned after a successful OAuth flow.
///
/// `services/user.rs` uses this to find-or-create a local account and link
/// the `OAuthAccount` relation (see `models.rs`).
#[derive(Debug, Clone)]
pub struct OAuthProfile {
    /// Which provider authenticated this user.
    pub provider: OAuthProvider,
    /// The user's stable, unique identifier within that provider.
    pub provider_user_id: String,
    /// Primary email address as reported by the provider.
    ///
    /// Treat with care: not all providers verify email addresses.
    /// Google and GitHub both do, so this field is trusted for account merging
    /// only for those two providers.
    pub email: String,
    /// Human-readable display name, if the provider exposes one.
    pub display_name: Option<String>,
    /// Public avatar URL, if available.
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserInfo {
    id: u64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
    login: String,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// Outcome of [`build_authorization_url`].
pub struct AuthorizationRequest {
    /// The URL to redirect the user's browser to.
    pub url: Url,
    /// The opaque `state` token that must be round-tripped through the provider
    /// and passed to [`exchange_code`].  Store it in [`StateStore`] immediately.
    pub state_key: String,
}

/// Build the provider consent-screen URL and register the PKCE state.
///
/// The caller **must** redirect the user to [`AuthorizationRequest::url`] and
/// record `state_key` in the [`StateStore`] — both happen atomically in the
/// route handler so there is no window where the state exists but the redirect
/// has not yet been issued.
///
/// # Errors
///
/// Returns [`OAuthError::ProviderNotConfigured`] if `provider_cfg` is `None`,
/// or [`OAuthError::InvalidRedirectUri`] if the stored redirect URI is malformed.
pub async fn build_authorization_url(
    provider: OAuthProvider,
    provider_cfg: &OAuthProviderConfig,
    store: &StateStore,
) -> Result<AuthorizationRequest, OAuthError> {
    let (auth_url, token_url) = provider_endpoints(provider);
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (url, csrf_token) = BasicClient::new(ClientId::new(provider_cfg.client_id.clone()))
        .set_client_secret(ClientSecret::new(provider_cfg.client_secret.clone()))
        .set_auth_uri(
            oauth2::AuthUrl::new(auth_url.to_owned()).map_err(OAuthError::InvalidRedirectUri)?,
        )
        .set_token_uri(
            oauth2::TokenUrl::new(token_url.to_owned()).map_err(OAuthError::InvalidRedirectUri)?,
        )
        .set_redirect_uri(
            RedirectUrl::new(provider_cfg.redirect_uri.clone())
                .map_err(OAuthError::InvalidRedirectUri)?,
        )
        .authorize_url(CsrfToken::new_random)
        .add_scopes(provider_scopes(provider))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let state_key = csrf_token.secret().clone();
    store.insert(&state_key, provider, pkce_verifier).await?;

    Ok(AuthorizationRequest {
        url,
        state_key: state_key.to_owned(),
    })
}

/// Exchange an authorization code for an access token.
///
/// Validates the `state` against the [`StateStore`] (CSRF + PKCE) and
/// returns the raw access token on success.  The state entry is consumed so
/// it cannot be replayed.
///
/// # Errors
///
/// - [`OAuthError::InvalidState`]: unknown, expired, or already-used state
/// - [`OAuthError::ProviderMismatch`]: state belongs to a different provider
/// - [`OAuthError::TokenExchange`]: provider rejected the code
/// - [`OAuthError::InvalidRedirectUri`]: config error
pub async fn exchange_code(
    provider: OAuthProvider,
    provider_cfg: &OAuthProviderConfig,
    code: &str,
    state: &str,
    store: &StateStore,
) -> Result<String, OAuthError> {
    let (_, token_url) = provider_endpoints(provider);
    let verifier = store.take(state, provider).await?;
    let http_client = oauth2::reqwest::Client::new();

    let token_result = BasicClient::new(ClientId::new(provider_cfg.client_id.clone()))
        .set_client_secret(ClientSecret::new(provider_cfg.client_secret.clone()))
        .set_auth_uri(
            oauth2::AuthUrl::new("https://placeholder.invalid".to_owned())
                .expect("placeholder auth URL is valid"),
        )
        .set_token_uri(
            oauth2::TokenUrl::new(token_url.to_owned()).map_err(OAuthError::InvalidRedirectUri)?,
        )
        .set_redirect_uri(
            RedirectUrl::new(provider_cfg.redirect_uri.clone())
                .map_err(OAuthError::InvalidRedirectUri)?,
        )
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .set_pkce_verifier(verifier)
        .request_async(&http_client)
        .await
        .map_err(|e| OAuthError::TokenExchange(e.to_string()))?;

    Ok(token_result.access_token().secret().clone())
}

/// Fetch and normalise the authenticated user's profile from the provider.
///
/// Each provider exposes a different user-info API; this function maps them all
/// to [`OAuthProfile`] so the rest of the application stays provider-agnostic.
///
/// # Errors
///
/// - [`OAuthError::ProviderUnreachable`]: HTTP request failed
/// - [`OAuthError::IncompleteProfile`]: required field absent in response
pub async fn fetch_user_profile(
    provider: OAuthProvider,
    access_token: &str,
) -> Result<OAuthProfile, OAuthError> {
    match provider {
        OAuthProvider::Google => fetch_google_profile(access_token).await,
        OAuthProvider::GitHub => fetch_github_profile(access_token).await,
    }
}

/// Static provider endpoints. Extending to a third provider means adding one
/// arm here and in `provider_scopes`.
fn provider_endpoints(provider: OAuthProvider) -> (&'static str, &'static str) {
    match provider {
        OAuthProvider::Google => (
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
        ),
        OAuthProvider::GitHub => (
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
        ),
    }
}

/// Scopes to request from each provider.
fn provider_scopes(provider: OAuthProvider) -> Vec<Scope> {
    match provider {
        OAuthProvider::Google => vec![
            Scope::new("openid".to_owned()),
            Scope::new("email".to_owned()),
            Scope::new("profile".to_owned()),
        ],
        OAuthProvider::GitHub => vec![
            Scope::new("read:user".to_owned()),
            Scope::new("user:email".to_owned()),
        ],
    }
}

async fn fetch_google_profile(access_token: &str) -> Result<OAuthProfile, OAuthError> {
    let info: GoogleUserInfo = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?
        .error_for_status()
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?;

    Ok(OAuthProfile {
        provider: OAuthProvider::Google,
        provider_user_id: info.sub,
        email: info.email,
        display_name: info.name,
        avatar_url: info.picture,
    })
}

async fn fetch_github_profile(access_token: &str) -> Result<OAuthProfile, OAuthError> {
    let client = reqwest::Client::new();

    let info: GitHubUserInfo = client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header(reqwest::header::USER_AGENT, "your-app-name")
        .send()
        .await
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?
        .error_for_status()
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?;

    let email = match info.email {
        Some(e) => e,
        None => fetch_github_primary_email(&client, access_token).await?,
    };

    Ok(OAuthProfile {
        provider: OAuthProvider::GitHub,
        provider_user_id: info.id.to_string(),
        email,
        display_name: info.name.or(Some(info.login)),
        avatar_url: info.avatar_url,
    })
}

/// Fetch the primary verified email from GitHub's `/user/emails` endpoint.
///
/// This is a separate request; it is only made when the public profile omits
/// the email (common for users who mark it private).
async fn fetch_github_primary_email(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<String, OAuthError> {
    let emails: Vec<GitHubEmail> = client
        .get("https://api.github.com/user/emails")
        .bearer_auth(access_token)
        .header(reqwest::header::USER_AGENT, "your-app-name")
        .send()
        .await
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?
        .error_for_status()
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| OAuthError::ProviderUnreachable(e.to_string()))?;

    emails
        .into_iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email)
        .ok_or(OAuthError::IncompleteProfile("email"))
}
