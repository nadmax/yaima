use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

use crate::config::OAuthProvider;

/// Top-level application error type.
///
/// Every variant maps to an HTTP status code and a stable `code` string
/// that clients can match on without parsing human-readable messages.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("token has expired")]
    TokenExpired,

    #[error("token is invalid")]
    TokenInvalid,

    #[error("missing authorization header")]
    MissingAuthHeader,

    #[error("refresh token not found or revoked")]
    RefreshTokenInvalid,

    #[error("email is already taken")]
    EmailTaken,

    #[error("username is already taken")]
    UsernameTaken,

    #[error("user not found")]
    UserNotFound,

    #[error("account is disabled")]
    AccountDisabled,

    #[error("insufficient permissions")]
    Forbidden,

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("password hashing error")]
    Hashing,

    #[error("internal server error")]
    Internal(#[from] anyhow::Error),

    /// Wraps the full OAuth error hierarchy so any `OAuthError` can be
    /// propagated with `?` inside handlers that return `AppResult`.
    #[error(transparent)]
    OAuth(#[from] OAuthError),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidCredentials
            | Self::TokenExpired
            | Self::TokenInvalid
            | Self::MissingAuthHeader
            | Self::RefreshTokenInvalid => StatusCode::UNAUTHORIZED,
            Self::EmailTaken | Self::UsernameTaken => StatusCode::CONFLICT,
            Self::UserNotFound => StatusCode::NOT_FOUND,
            Self::AccountDisabled | Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Database(_) | Self::Hashing | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::OAuth(e) => e.status_code(),
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenInvalid => "TOKEN_INVALID",
            Self::MissingAuthHeader => "MISSING_AUTH_HEADER",
            Self::RefreshTokenInvalid => "REFRESH_TOKEN_INVALID",
            Self::EmailTaken => "EMAIL_TAKEN",
            Self::UsernameTaken => "USERNAME_TAKEN",
            Self::UserNotFound => "USER_NOT_FOUND",
            Self::AccountDisabled => "ACCOUNT_DISABLED",
            Self::Forbidden => "FORBIDDEN",
            Self::Database(_) => "DATABASE_ERROR",
            Self::Hashing => "HASHING_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
            Self::OAuth(e) => e.error_code(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = json!({
            "error": {
                "code":    self.error_code(),
                "message": self.to_string(),
            }
        });

        tracing::warn!(
            status = status.as_u16(),
            code   = self.error_code(),
            error  = %self,
            "request error"
        );

        (status, Json(body)).into_response()
    }
}

/// Application result type using `AppError` as the error variant.
pub type AppResult<T> = Result<T, AppError>;

/// Errors that can occur during any stage of the OAuth 2.0 flow.
///
/// Kept as a separate type from [`AppError`] because a single `OAuthError`
/// maps to multiple HTTP status codes. The [`From`] impl on `AppError` wraps
/// it in [`AppError::OAuth`], and `status_code`/`error_code` delegate here,
/// so the full response shape stays consistent with every other error variant.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// The requested provider is not enabled in the server configuration.
    #[error("OAuth provider '{0}' is not configured")]
    ProviderNotConfigured(OAuthProvider),

    /// The `state` parameter returned by the provider did not match any
    /// pending authorization. Either it expired, was already consumed, or
    /// is forged.
    #[error("invalid or expired OAuth state token")]
    InvalidState,

    /// The `state` in the callback belongs to a different provider than the
    /// route that received it — likely a misconfigured redirect URI.
    #[error("OAuth state provider mismatch: expected {expected}, got {actual}")]
    ProviderMismatch {
        expected: OAuthProvider,
        actual: OAuthProvider,
    },

    /// The authorization code could not be exchanged for tokens.
    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    /// A network request to the provider's API failed.
    #[error("provider unreachable: {0}")]
    ProviderUnreachable(String),

    /// The provider's user-info response was missing a required field.
    #[error("incomplete provider profile: missing field '{0}'")]
    IncompleteProfile(&'static str),

    /// The provider returned a redirect URI that could not be parsed.
    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(#[from] oauth2::url::ParseError),

    /// The Redis connection pool returned an error.
    #[error("OAuth state store unavailable: {0}")]
    StateStore(#[from] deadpool_redis::PoolError),

    /// A Redis command failed.
    #[error("OAuth state store error: {0}")]
    StateStoreRedis(#[from] redis::RedisError),

    /// The provider email is already linked to a different local account and
    /// the conflict cannot be resolved automatically.
    ///
    /// Raised by `services/auth.rs` when two users have separately
    /// authenticated with different providers that report the same email,
    /// and automatic merging is disabled.
    #[error("account conflict: email '{email}' is already linked to a different account")]
    AccountConflict { email: String },

    /// The provider returned an error response on the callback (e.g. `access_denied`).
    ///
    /// This means the user declined consent or the provider rejected the request —
    /// not a server-side fault.
    #[error("provider denied authorization: {error} — {detail}")]
    ProviderDenied { error: String, detail: String },

    /// The provider slug in the URL path did not match any known provider.
    #[error("unknown OAuth provider: '{0}'")]
    UnknownProvider(String),
}

impl OAuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::ProviderNotConfigured(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidState | Self::ProviderMismatch { .. } => StatusCode::UNAUTHORIZED,
            Self::TokenExchange(_) => StatusCode::BAD_GATEWAY,
            Self::ProviderUnreachable(_) => StatusCode::BAD_GATEWAY,
            Self::IncompleteProfile(_) => StatusCode::BAD_GATEWAY,
            Self::InvalidRedirectUri(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::StateStore(_) | Self::StateStoreRedis(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::AccountConflict { .. } => StatusCode::CONFLICT,
            Self::ProviderDenied { .. } => StatusCode::BAD_REQUEST,
            Self::UnknownProvider(_) => StatusCode::NOT_FOUND,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::ProviderNotConfigured(_) => "OAUTH_PROVIDER_NOT_CONFIGURED",
            Self::InvalidState => "OAUTH_INVALID_STATE",
            Self::ProviderMismatch { .. } => "OAUTH_PROVIDER_MISMATCH",
            Self::TokenExchange(_) => "OAUTH_TOKEN_EXCHANGE_FAILED",
            Self::ProviderUnreachable(_) => "OAUTH_PROVIDER_UNREACHABLE",
            Self::IncompleteProfile(_) => "OAUTH_INCOMPLETE_PROFILE",
            Self::InvalidRedirectUri(_) => "OAUTH_INVALID_REDIRECT_URI",
            Self::StateStore(_) => "OAUTH_STATE_STORE_UNAVAILABLE",
            Self::StateStoreRedis(_) => "OAUTH_STATE_STORE_ERROR",
            Self::AccountConflict { .. } => "OAUTH_ACCOUNT_CONFLICT",
            Self::ProviderDenied { .. } => "OAUTH_PROVIDER_DENIED",
            Self::UnknownProvider(_) => "OAUTH_UNKNOWN_PROVIDER",
        }
    }
}
