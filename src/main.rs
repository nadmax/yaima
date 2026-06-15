mod config;
mod errors;
mod middleware;
mod models;
mod routes;
mod services;
mod state;

use axum::{Json, Router, http::StatusCode, routing::get};
use sqlx::postgres::PgPoolOptions;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::services::oauth::StateStore;
use config::Config;
use services::{auth::AuthService, token::TokenService, user::UserService};
use state::AppState;

#[derive(OpenApi)]
#[openapi(
    info(
        title       = "YAIMA",
        version     = "0.1.0",
        description = "Yet Another Identity Management API",
    ),
    paths(
        routes::auth::register,
        routes::auth::login,
        routes::auth::refresh,
        routes::auth::logout,
        routes::auth::authorize,
        routes::auth::callback,
        routes::users::get_me,
        routes::users::change_password,
        routes::users::deactivate_account,
        routes::admin::update_user_role,
        health,
    ),
    components(
        schemas(
            models::RegisterRequest,
            models::LoginRequest,
            models::RefreshRequest,
            models::ChangePasswordRequest,
            models::UpdateRoleRequest,
            models::Role,
            models::AuthResponse,
            models::UserResponse,
            models::MessageResponse,
        ),
    ),
    modifiers(&BearerSecurityAddon),
    tags(
        (name = "auth",  description = "Authentication operations"),
        (name = "users", description = "Authenticated user operations"),
        (name = "admin", description = "Admin-only operations (requires admin role)"),
        (name = "system", description = "Liveness and infrastructure endpoints"),
    )
)]
struct ApiDoc;

/// Injects the `bearer_auth` HTTP security scheme into the generated `OpenAPI`
/// document. utoipa v5 does not support `security_schemes` inside the
/// `components()` macro attribute — schemes must be added via `Modify`.
struct BearerSecurityAddon;

impl Modify for BearerSecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                Http::builder()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("{}=debug,tower_http=info", env!("CARGO_PKG_NAME")).into()
            }),
        )
        .init();

    let config = Config::from_env().expect("failed to load configuration from environment");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("database migrations complete");

    let user = UserService::new(pool.clone());
    let token = TokenService::new(pool.clone(), config.clone());
    let auth = AuthService::new(user.clone(), token.clone(), config.clone());
    let oauth_store = StateStore::new(&config.redis_url)
        .expect("failed to create OAuth state store")
        .shared();
    let state = AppState::new(auth, user, token, config.clone(), oauth_store);
    let app = Router::new()
        .route("/health", get(health))
        .merge(routes::auth::router())
        .merge(routes::users::router())
        .merge(routes::admin::router())
        .merge(SwaggerUi::new("/apidocs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "server listening");
    axum::serve(listener, app).await?;

    Ok(())
}

/// Liveness probe (Returns `200 OK` with a JSON body).
#[utoipa::path(
    get,
    path = "/health",
    tag  = "system",
    responses(
        (status = 200, description = "Service is healthy", body = serde_json::Value,
         example = json!({"status": "ok"})),
    )
)]
async fn health() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}
