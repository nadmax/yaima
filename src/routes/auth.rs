use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
};
use serde::Deserialize;

use crate::{
    config::OAuthProvider,
    errors::{AppError, AppResult, OAuthError},
    middleware::AuthUser,
    models::{AuthResponse, LoginRequest, MessageResponse, RefreshRequest, RegisterRequest},
    services::oauth,
    state::AppState,
};

/// Mount all `/auth/*` routes onto a new [`Router`].
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/{provider}", get(authorize))
        .route("/auth/{provider}/callback", get(callback))
}

/// Register a new user account.
///
/// # Errors
///
/// Returns an [`AppError`] if the email or username is already taken, or if
/// the underlying service or database call fails.
#[utoipa::path(
    post,
    path = "/auth/register",
    tag  = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created",      body = AuthResponse),
        (status = 409, description = "Email/username taken", body = serde_json::Value),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> AppResult<(StatusCode, Json<AuthResponse>)> {
    let response = state
        .auth
        .register(&req.email, &req.username, &req.password)
        .await?;

    tracing::info!(email = %req.email, "new user registered");
    Ok((StatusCode::CREATED, Json(response)))
}

/// Authenticate with email and password.
///
/// # Errors
///
/// Returns an [`AppError`] if the credentials are invalid, or if the
/// underlying service or database call fails.
#[utoipa::path(
    post,
    path = "/auth/login",
    tag  = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated",        body = AuthResponse),
        (status = 401, description = "Invalid credentials",  body = serde_json::Value),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<AuthResponse>> {
    let response = state.auth.login(&req.email, &req.password).await?;

    tracing::info!(email = %req.email, "user logged in");
    Ok(Json(response))
}

/// Exchange a refresh token for a new token pair.
///
/// # Errors
///
/// Returns an [`AppError`] if the refresh token is invalid or expired, or if
/// the underlying service or database call fails.
#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag  = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Token refreshed",       body = AuthResponse),
        (status = 401, description = "Refresh token invalid", body = serde_json::Value),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> AppResult<Json<AuthResponse>> {
    let response = state.auth.refresh(&req.refresh_token).await?;
    Ok(Json(response))
}

/// Revoke all refresh tokens for the currently authenticated user.
///
/// # Errors
///
/// Returns an [`AppError`] if the underlying service or database call fails.
#[utoipa::path(
    post,
    path = "/auth/logout",
    tag  = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Logged out",        body = MessageResponse),
        (status = 401, description = "Not authenticated", body = serde_json::Value),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
) -> AppResult<Json<MessageResponse>> {
    state.auth.logout(claims.sub).await?;

    tracing::info!(user_id = %claims.sub, "user logged out");
    Ok(Json(MessageResponse::new("Logged out successfully")))
}

/// Redirect the user to the provider's consent screen.
///
/// Resolves the provider slug, builds the PKCE authorization URL, and issues a
/// `302 Found` to the provider. The PKCE verifier and CSRF state are stored
/// server-side in [`AppState::oauth_store`] until the callback arrives.
///
/// # Errors
///
/// Returns `404 Not Found` for unrecognised provider slugs and
/// `503 Service Unavailable` when the provider is recognised but its
/// credentials are not present in the server configuration.
#[utoipa::path(
    get,
    path = "/auth/{provider}",
    tag  = "auth",
    params(("provider" = String, Path, description = "OAuth provider slug (e.g. `google`, `github`)")),
    responses(
        (status = 302, description = "Redirect to provider consent screen"),
        (status = 404, description = "Unknown provider",         body = serde_json::Value),
        (status = 503, description = "Provider not configured",  body = serde_json::Value),
    )
)]
pub async fn authorize(
    Path(slug): Path<String>,
    State(state): State<AppState>,
) -> AppResult<Redirect> {
    let provider = resolve_provider(&slug)?;

    let provider_cfg = state
        .config
        .oauth
        .provider(provider)
        .ok_or(OAuthError::ProviderNotConfigured(provider))?;

    let auth_request =
        oauth::build_authorization_url(provider, provider_cfg, &state.oauth_store).await?;

    tracing::debug!(%provider, "redirecting to OAuth consent screen");
    Ok(Redirect::to(auth_request.url.as_str()))
}

/// Query parameters echoed back by the provider on the callback redirect.
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    /// The authorization code to exchange for tokens.
    code: Option<String>,
    /// The opaque CSRF state token that was round-tripped through the provider.
    state: Option<String>,
    /// Set by the provider when the user denied consent or an error occurred.
    error: Option<String>,
    /// Human-readable description accompanying `error`, when present.
    error_description: Option<String>,
}

/// Handle the provider callback, issue an application JWT on success.
///
/// Steps:
/// 1. Surface any provider-reported error (e.g. `access_denied`) immediately.
/// 2. Validate the CSRF `state` and consume the stored PKCE verifier.
/// 3. Exchange the authorization code for a provider access token.
/// 4. Fetch and normalise the user profile.
/// 5. Find or create a local account and link the `OAuthAccount` relation.
/// 6. Issue an application JWT using the existing `services/token` logic.
///
/// # Errors
///
/// Returns `400 Bad Request` for missing parameters or provider-reported
/// errors, `401 Unauthorized` for CSRF/PKCE failures, and `502 Bad Gateway`
/// when the provider is unreachable.
#[utoipa::path(
    get,
    path = "/auth/{provider}/callback",
    tag  = "auth",
    params(
        ("provider"          = String, Path,  description = "OAuth provider slug"),
        ("code"              = String, Query, description = "Authorization code from the provider"),
        ("state"             = String, Query, description = "CSRF state token"),
        ("error"             = Option<String>, Query, description = "Provider error code, if any"),
        ("error_description" = Option<String>, Query, description = "Provider error detail, if any"),
    ),
    responses(
        (status = 302, description = "Login successful — redirect to application"),
        (status = 400, description = "Provider denied access or missing params", body = serde_json::Value),
        (status = 401, description = "CSRF / PKCE validation failed",            body = serde_json::Value),
        (status = 404, description = "Unknown provider",                         body = serde_json::Value),
        (status = 502, description = "Provider unreachable",                     body = serde_json::Value),
    )
)]
pub async fn callback(
    Path(slug): Path<String>,
    Query(params): Query<CallbackParams>,
    State(state): State<AppState>,
) -> AppResult<Redirect> {
    if let Some(error) = params.error {
        let detail = params
            .error_description
            .unwrap_or_else(|| "no detail provided".to_owned());
        tracing::warn!(%error, %detail, "OAuth provider returned an error");
        return Err(OAuthError::ProviderDenied { error, detail }.into());
    }

    let code = params.code.ok_or(OAuthError::InvalidState)?;
    let csrf_state = params.state.ok_or(OAuthError::InvalidState)?;

    let provider = resolve_provider(&slug)?;

    let provider_cfg = state
        .config
        .oauth
        .provider(provider)
        .ok_or(OAuthError::ProviderNotConfigured(provider))?;

    let access_token = oauth::exchange_code(
        provider,
        provider_cfg,
        &code,
        &csrf_state,
        &state.oauth_store,
    )
    .await?;

    let profile = oauth::fetch_user_profile(provider, &access_token).await?;
    let response = state.auth.login_or_register_oauth(&profile).await?;

    tracing::info!(
        user_id = %response.user.id,
        %provider,
        "user authenticated via OAuth",
    );

    let redirect_url = format!("/auth/success?token={}", response.access_token);
    Ok(Redirect::to(&redirect_url))
}

/// Resolve a URL path segment to an [`OAuthProvider`], or return `404`.
fn resolve_provider(slug: &str) -> AppResult<OAuthProvider> {
    OAuthProvider::from_slug(slug)
        .ok_or_else(|| AppError::OAuth(OAuthError::UnknownProvider(slug.to_owned())))
}
