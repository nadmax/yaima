use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::{
    errors::{AppError, AppResult},
    models::{AuthMethod, Claims, Role},
    state::AppState,
};

/// Extract a raw Bearer token from the `Authorization` header, if present.
pub fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Validates the JWT and injects the decoded [`Claims`] into a handler.
///
/// Returns `401 Unauthorized` on any failure. For role-gated handlers,
/// prefer the typed extractors below ([`RequireUser`], [`RequireAdmin`]).
pub struct AuthUser(pub Claims);

impl<S> FromRequestParts<S> for AuthUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let token = extract_bearer(&parts.headers).ok_or(AppError::MissingAuthHeader)?;
        let claims = app_state.token.validate_access_token(token)?;
        Ok(AuthUser(claims))
    }
}

/// Requires the caller to hold at least the `User` role.
///
/// Returns `401` if the token is absent/invalid, `403` if the role is too low.
pub struct RequireUser(pub Claims);

impl<S> FromRequestParts<S> for RequireUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        require_role(&claims, Role::User)?;
        Ok(RequireUser(claims))
    }
}

/// Requires the caller to hold the `Admin` role.
///
/// Returns `401` if the token is absent/invalid, `403` if the role is too low.
pub struct RequireAdmin(pub Claims);

impl<S> FromRequestParts<S> for RequireAdmin
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        require_role(&claims, Role::Admin)?;
        Ok(RequireAdmin(claims))
    }
}

/// Requires the token to have been issued via an OAuth 2.0 provider.
///
/// Use on endpoints that are only meaningful for OAuth sessions — for example,
/// listing or unlinking a connected provider identity (`GET /auth/connections`,
/// `DELETE /auth/connections/{provider}`).
///
/// Returns `401` if the token is absent or invalid, `403` if it was issued
/// via password login.
pub struct RequireOAuthSession(pub Claims);

impl<S> FromRequestParts<S> for RequireOAuthSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthUser(claims) = AuthUser::from_request_parts(parts, state).await?;
        require_auth_method(&claims, AuthMethod::OAuth)?;
        Ok(RequireOAuthSession(claims))
    }
}

/// Return `Err(AppError::Forbidden)` if the claims do not meet the minimum role.
fn require_role(claims: &Claims, minimum: Role) -> AppResult<()> {
    if claims.role.is_at_least(minimum) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Return `Err(AppError::Forbidden)` if the token was not issued via the
/// expected authentication method.
fn require_auth_method(claims: &Claims, expected: AuthMethod) -> AppResult<()> {
    if claims.auth_method == expected {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}
