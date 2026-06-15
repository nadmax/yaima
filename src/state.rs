use std::sync::Arc;

use crate::{
    config::Config,
    services::{auth::AuthService, oauth::StateStore, token::TokenService, user::UserService},
};

/// Shared application state cloned into every request handler.
///
/// All contained services are cheap to clone (they hold an `Arc` internally
/// via `PgPool` / `Config`).
#[derive(Clone)]
pub struct AppState {
    pub auth: AuthService,
    pub user: UserService,
    pub token: TokenService,
    /// Application configuration, used by OAuth routes to look up provider
    /// credentials without a separate service layer.
    pub config: Config,
    /// Short-lived PKCE/CSRF state store for the OAuth 2.0 flow.
    pub oauth_store: Arc<StateStore>,
}

impl AppState {
    #[must_use]
    pub fn new(
        auth: AuthService,
        user: UserService,
        token: TokenService,
        config: Config,
        oauth_store: Arc<StateStore>,
    ) -> Self {
        Self {
            auth,
            user,
            token,
            config,
            oauth_store,
        }
    }
}
