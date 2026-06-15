use axum::{
    Json, Router,
    extract::State,
    routing::{delete, get, put},
};

use crate::{
    errors::AppResult,
    middleware::RequireUser,
    models::{ChangePasswordRequest, MessageResponse, UserResponse, UserView},
    state::AppState,
};

/// Mount all `/users/*` routes onto a new [`Router`].
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users/me", get(get_me))
        .route("/users/me/password", put(change_password))
        .route("/users/me", delete(deactivate_account))
}

/// Return the profile of the currently authenticated user.
///
/// # Errors
///
/// Returns an [`AppError`] if the user no longer exists, or if the
/// underlying service or database call fails.
#[utoipa::path(
    get,
    path = "/users/me",
    tag  = "users",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user profile", body = UserResponse),
        (status = 401, description = "Not authenticated",    body = serde_json::Value),
    )
)]
pub async fn get_me(
    State(state): State<AppState>,
    RequireUser(claims): RequireUser,
) -> AppResult<Json<UserResponse>> {
    let user = state.user.find_by_id(claims.sub).await?;
    let credential = state.user.find_local_credential(user.id).await?;

    Ok(Json(UserResponse::from(UserView {
        user,
        local_credential: credential,
    })))
}

/// Change the authenticated user's password.
///
/// # Errors
///
/// Returns an [`AppError`] if the current password is incorrect, or if
/// revoking existing tokens or the underlying service or database call fails.
#[utoipa::path(
    put,
    path = "/users/me/password",
    tag  = "users",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password updated",  body = MessageResponse),
        (status = 401, description = "Wrong password",    body = serde_json::Value),
    )
)]
pub async fn change_password(
    State(state): State<AppState>,
    RequireUser(claims): RequireUser,
    Json(req): Json<ChangePasswordRequest>,
) -> AppResult<Json<MessageResponse>> {
    state
        .user
        .change_password(claims.sub, &req.current_password, &req.new_password)
        .await?;

    state.token.revoke_all_user_tokens(claims.sub).await?;

    tracing::info!(user_id = %claims.sub, "password changed");
    Ok(Json(MessageResponse::new("Password updated successfully")))
}

/// Deactivate (soft-delete) the authenticated user's account.
///
/// # Errors
///
/// Returns an [`AppError`] if deactivating the account or revoking existing
/// tokens fails due to a service or database error.
#[utoipa::path(
    delete,
    path = "/users/me",
    tag  = "users",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Account deactivated", body = MessageResponse),
        (status = 401, description = "Not authenticated",   body = serde_json::Value),
    )
)]
pub async fn deactivate_account(
    State(state): State<AppState>,
    RequireUser(claims): RequireUser,
) -> AppResult<Json<MessageResponse>> {
    state.user.deactivate(claims.sub).await?;
    state.token.revoke_all_user_tokens(claims.sub).await?;

    tracing::info!(user_id = %claims.sub, "account deactivated");
    Ok(Json(MessageResponse::new("Account deactivated")))
}
