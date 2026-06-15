use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

/// Access tier assigned to every user.
///
/// Stored as the Postgres `user_role` enum; serialised as a lowercase string
/// in JWTs and API responses so clients never have to handle integer codes.
///
/// | Role    | Intended for                                          |
/// |---------|-------------------------------------------------------|
/// | `guest` | Provisional accounts or pre-verification users        |
/// | `user`  | Fully registered members (default on registration)   |
/// | `admin` | Operators with elevated privileges                    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Guest,
    User,
    Admin,
}

/// How the session was established.
///
/// Encoded into the JWT so handlers can enforce an authentication method
/// without an extra database round-trip.
///
/// | Variant    | Issued by                                      |
/// |------------|------------------------------------------------|
/// | `password` | `POST /auth/login` (email + password)          |
/// | `oauth`    | `GET /auth/{provider}/callback` (OAuth 2.0)    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    OAuth,
}

/// Claims embedded in every access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (the user's UUID).
    pub sub: Uuid,

    /// Issued-at (Unix timestamp seconds).
    pub iat: u64,

    /// Expiration (Unix timestamp seconds).
    pub exp: u64,

    pub email: String,
    pub display_name: String,

    /// Role at the time the token was issued.
    ///
    /// If a user's role changes, they must obtain a new access token before
    /// the new role takes effect (i.e. after the current token expires or on
    /// the next refresh cycle).
    pub role: Role,

    /// Authentication method used to issue this token.
    ///
    /// Defaults to [`AuthMethod::Password`] so tokens minted before this
    /// field was introduced continue to deserialise without error — existing
    /// sessions are not invalidated on deploy.
    #[serde(default = "default_auth_method")]
    pub auth_method: AuthMethod,
}

fn default_auth_method() -> AuthMethod {
    AuthMethod::Password
}

impl Role {
    /// Returns `true` if this role is at least as privileged as `required`.
    ///
    /// Hierarchy (ascending): `Guest < User < Admin`.
    #[must_use]
    pub fn is_at_least(self, required: Role) -> bool {
        self.level() >= required.level()
    }

    fn level(self) -> u8 {
        match self {
            Role::Guest => 0,
            Role::User => 1,
            Role::Admin => 2,
        }
    }
}

/// OAuth provider identifier.
///
/// Stored as the Postgres `oauth_provider` enum.  Adding a new provider
/// requires a migration (`ALTER TYPE oauth_provider ADD VALUE '...'`) **and**
/// a new variant here; the compiler will then surface every unhandled match
/// arm so nothing is missed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "oauth_provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Google,
    GitHub,
}

impl From<crate::config::OAuthProvider> for Provider {
    fn from(p: crate::config::OAuthProvider) -> Self {
        match p {
            crate::config::OAuthProvider::Google => Provider::Google,
            crate::config::OAuthProvider::GitHub => Provider::GitHub,
        }
    }
}

/// Canonical user row — pure identity, no credential data.
///
/// A `User` row is created once and never holds authentication secrets.
/// Secrets live in [`LocalCredential`] (password) or [`OAuthCredential`]
/// (OAuth tokens).  A user may have zero or more of each; the only invariant
/// enforced at the application level is that at least one credential exists.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,

    /// Primary contact address; unique across the table.
    pub email: String,

    /// Human-readable display name shown in the UI.
    ///
    /// For locally-registered users this is collected at sign-up.
    /// For OAuth-only users it is populated from the provider's profile
    /// (e.g. GitHub `login`, Google `name`) and may be updated later.
    pub display_name: String,

    pub role: Role,
    pub is_active: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Password credential for a locally-registered account.
///
/// Rows in this table are optional: an OAuth-only user has a `users` row but
/// **no** `local_credentials` row.  Services that need a password must query
/// for `Option<LocalCredential>` and handle the absent case explicitly — see
/// `services/auth.rs`.
///
/// # Database table
/// ```sql
/// CREATE TABLE local_credentials (
///     user_id       UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
///     username      TEXT NOT NULL UNIQUE,
///     password_hash TEXT NOT NULL,
///     created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
///     updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
/// );
/// ```
#[derive(Debug, Clone, FromRow)]
pub struct LocalCredential {
    pub user_id: Uuid,

    /// Login handle chosen at registration; unique across the table.
    ///
    /// Kept here (not on `User`) because OAuth-only accounts have no username
    /// concept until one is explicitly set.
    pub username: String,

    /// Argon2id hash of the user's password.  Never serialised or logged.
    pub password_hash: String,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// OAuth 2.0 token set for a linked external provider.
///
/// Multiple rows per user are allowed (one per `(user_id, provider)` pair),
/// so a single account can be linked to both Google and GitHub.
///
/// # Token encryption
/// `access_token_enc` and `refresh_token_enc` store AES-GCM–encrypted blobs;
/// the plaintext tokens are never written to the database.  The encryption key
/// is sourced from `AppConfig::oauth_token_key` at runtime.
///
/// # Database table
/// ```sql
/// CREATE TABLE oauth_credentials (
///     id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
///     user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
///     provider           oauth_provider NOT NULL,
///     provider_user_id   TEXT NOT NULL,
///     access_token_enc   TEXT,
///     refresh_token_enc  TEXT,
///     expires_at         TIMESTAMPTZ,
///     created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
///     updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
///     UNIQUE (provider, provider_user_id)
/// );
/// ```
#[derive(Debug, Clone, FromRow)]
pub struct OAuthCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: Provider,

    /// Stable identifier issued by the provider (e.g. Google `sub`, GitHub `id`).
    pub provider_user_id: String,

    /// AES-GCM–encrypted access token, base64-encoded.
    /// `None` if the provider did not supply one on the most recent exchange.
    pub access_token_enc: Option<String>,

    /// AES-GCM–encrypted refresh token, base64-encoded.
    /// `None` for providers that do not issue refresh tokens.
    pub refresh_token_enc: Option<String>,

    /// UTC instant at which `access_token_enc` expires.
    /// `None` for providers that do not advertise token lifetime.
    pub expires_at: Option<OffsetDateTime>,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Payload for `POST /auth/register`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    /// Valid e-mail address; must be unique.
    #[schema(example = "alice@example.com")]
    pub email: String,

    /// Display name; must be unique (3–32 chars).
    #[schema(example = "alice")]
    pub username: String,

    /// Plain-text password (min 8 chars). Stored only as an Argon2 hash.
    #[schema(example = "hunter2secret")]
    pub password: String,
}

/// Payload for `POST /auth/login`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    /// Registered e-mail address.
    #[schema(example = "alice@example.com")]
    pub email: String,

    /// Plain-text password.
    #[schema(example = "hunter2secret")]
    pub password: String,
}

/// Payload for `POST /auth/refresh`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// Opaque refresh token previously issued by `/auth/login`.
    pub refresh_token: String,
}

/// Payload for `POST /auth/change-password`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    /// Current password for confirmation.
    pub current_password: String,

    /// New password (min 8 chars).
    pub new_password: String,
}

/// Payload for `PUT /admin/users/:id/role`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub role: Role,
}

/// Returned by `/auth/register` and `/auth/login`.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    /// Short-lived JWT Bearer token.
    pub access_token: String,

    /// Opaque token used to obtain a new access token.
    pub refresh_token: String,

    /// Seconds until the access token expires.
    pub expires_in: u64,

    /// Public user information.
    pub user: UserResponse,
}

/// Returned by `GET /users/me` and admin user endpoints.
///
/// `has_local_credential` lets the admin UI decide whether a "reset password"
/// action is applicable — it is `false` for OAuth-only accounts.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,

    /// `Some(username)` for locally-registered accounts; `None` for
    /// OAuth-only accounts that have never set a username.
    pub username: Option<String>,

    pub role: Role,

    /// Whether a local (password-based) credential exists for this user.
    pub has_local_credential: bool,

    pub created_at: String,
    pub updated_at: String,
}

/// View model combining a [`User`] with its optional [`LocalCredential`].
///
/// Constructed in the service layer after both rows have been fetched; passed
/// to `UserResponse::from` to produce the API response.
///
/// ```rust
/// let view = UserView {
///     user,
///     local_credential: Some(lc),
/// };
/// let response = UserResponse::from(view);
/// ```
pub struct UserView {
    pub user: User,
    /// `None` for OAuth-only accounts.
    pub local_credential: Option<LocalCredential>,
}

impl From<UserView> for UserResponse {
    fn from(v: UserView) -> Self {
        let UserView {
            user,
            local_credential,
        } = v;
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            username: local_credential.as_ref().map(|lc| lc.username.clone()),
            role: user.role,
            has_local_credential: local_credential.is_some(),
            created_at: user
                .created_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            updated_at: user
                .updated_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }
}

/// Generic success acknowledgement.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
