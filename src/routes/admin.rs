use axum::{
    Json, Router,
    extract::{Path, State},
    routing::put,
};
use uuid::Uuid;

use crate::{
    errors::AppResult,
    middleware::RequireAdmin,
    models::{UpdateRoleRequest, UserResponse, UserView},
    services::admin::AdminService,
    state::AppState,
};

/// Mount all `/admin/*` routes onto a new [`Router`].
pub fn router() -> Router<AppState> {
    Router::new().route("/admin/users/{id}/role", put(update_user_role))
}

/// Assign a new role to any user.
///
/// Only reachable by callers whose JWT carries the `admin` role.
///
/// # Errors
///
/// Returns an [`AppError`] if the target user does not exist, or if the
/// underlying service or database call fails.
#[utoipa::path(
    put,
    path = "/admin/users/{id}/role",
    tag  = "admin",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Target user ID")),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated",      body = UserResponse),
        (status = 401, description = "Not authenticated", body = serde_json::Value),
        (status = 403, description = "Not an admin",      body = serde_json::Value),
        (status = 404, description = "User not found",    body = serde_json::Value),
    )
)]
pub async fn update_user_role(
    State(state): State<AppState>,
    RequireAdmin(claims): RequireAdmin,
    Path(target_id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> AppResult<Json<UserResponse>> {
    let svc = AdminService::new(&state.user);
    let user = svc
        .update_user_role(claims.sub, target_id, req.role)
        .await?;

    let credential = state.user.find_local_credential(user.id).await?;

    Ok(Json(UserResponse::from(UserView {
        user,
        local_credential: credential,
    })))
}
