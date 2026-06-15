use uuid::Uuid;

use crate::{
    config::Config,
    errors::{AppError, AppResult},
    models::{AuthMethod, AuthResponse, LocalCredential, Role, UserResponse, UserView},
    services::{
        oauth::OAuthProfile,
        token::{TokenService, verify_password},
        user::UserService,
    },
};

#[derive(Clone)]
pub struct AuthService {
    user: UserService,
    token: TokenService,
    config: Config,
}

impl AuthService {
    #[must_use]
    pub fn new(user: UserService, token: TokenService, config: Config) -> Self {
        Self {
            user,
            token,
            config,
        }
    }

    /// Register a new account with a local credential and immediately issue tokens.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if validation, hashing, or any database call fails,
    /// or if the email or username is already taken.
    pub async fn register(
        &self,
        email: &str,
        username: &str,
        password: &str,
    ) -> AppResult<AuthResponse> {
        validate_password(password)?;
        validate_username(username)?;

        // Use email prefix as display_name on registration; users can update it later.
        let display_name = email.split('@').next().unwrap_or(username);
        let (user, credential) = self
            .user
            .create(email, display_name, username, password)
            .await?;

        self.issue_tokens(
            user.id,
            &user.email.clone(),
            &user.display_name.clone(),
            user.role,
            AuthMethod::Password,
            UserView {
                user,
                local_credential: Some(credential),
            },
        )
        .await
    }

    /// Validate credentials and issue tokens.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidCredentials`] if the email is not found, the
    /// account has no local credential (OAuth-only), or the password is wrong.
    /// Returns [`AppError::AccountDisabled`] if the account is inactive.
    pub async fn login(&self, email: &str, password: &str) -> AppResult<AuthResponse> {
        let user = self
            .user
            .find_by_email(email)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !user.is_active {
            return Err(AppError::AccountDisabled);
        }

        // OAuth-only accounts have no local credential row; treat identically
        // to a wrong password to avoid leaking account existence.
        let credential: LocalCredential = self
            .user
            .find_local_credential(user.id)
            .await?
            .ok_or(AppError::InvalidCredentials)?;

        if !verify_password(password, &credential.password_hash)? {
            return Err(AppError::InvalidCredentials);
        }

        self.issue_tokens(
            user.id,
            &user.email.clone(),
            &user.display_name.clone(),
            user.role,
            AuthMethod::Password,
            UserView {
                user,
                local_credential: Some(credential),
            },
        )
        .await
    }

    /// Exchange a valid refresh token for a fresh token pair.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the token is invalid/expired, the account is
    /// inactive, or any database or token generation call fails.
    pub async fn refresh(&self, raw_refresh_token: &str) -> AppResult<AuthResponse> {
        let (new_refresh_token, user_id) =
            self.token.rotate_refresh_token(raw_refresh_token).await?;

        let user = self.user.find_by_id(user_id).await?;

        if !user.is_active {
            return Err(AppError::AccountDisabled);
        }

        let credential = self.user.find_local_credential(user.id).await?;

        // A missing local credential means this is an OAuth-only account.
        let auth_method = if credential.is_some() {
            AuthMethod::Password
        } else {
            AuthMethod::OAuth
        };

        let access_token = self.token.generate_access_token(
            user.id,
            &user.email,
            &user.display_name,
            user.role,
            auth_method,
        )?;

        Ok(AuthResponse {
            access_token,
            refresh_token: new_refresh_token,
            expires_in: self.config.access_token_expiry_secs,
            user: UserResponse::from(UserView {
                user,
                local_credential: credential,
            }),
        })
    }

    /// Revoke all refresh tokens for the authenticated user.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the underlying database call fails.
    pub async fn logout(&self, user_id: Uuid) -> AppResult<()> {
        self.token.revoke_all_user_tokens(user_id).await
    }

    /// Find or create a local user from a verified OAuth profile, then issue tokens.
    ///
    /// See module-level docs for the account-merging resolution order.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if any database call or token generation fails,
    /// or if the resolved account has been deactivated.
    pub async fn login_or_register_oauth(&self, profile: &OAuthProfile) -> AppResult<AuthResponse> {
        let user = if let Some(u) = self
            .user
            .find_by_oauth_identity(profile.provider, &profile.provider_user_id)
            .await?
        {
            u
        } else {
            let u = match self.user.find_by_email(&profile.email).await? {
                Some(existing) => existing,
                None => {
                    self.user
                        .create_from_oauth(&profile.email, profile.display_name.as_deref())
                        .await?
                }
            };
            self.user.link_oauth_account(u.id, profile).await?;
            u
        };

        if !user.is_active {
            return Err(AppError::AccountDisabled);
        }

        // A merged account (OAuth + password) still has a local credential;
        // include it so `has_local_credential` is accurate in the response.
        let credential = self.user.find_local_credential(user.id).await?;

        self.issue_tokens(
            user.id,
            &user.email.clone(),
            &user.display_name.clone(),
            user.role,
            AuthMethod::OAuth,
            UserView {
                user,
                local_credential: credential,
            },
        )
        .await
    }

    async fn issue_tokens(
        &self,
        user_id: Uuid,
        email: &str,
        display_name: &str,
        role: Role,
        auth_method: AuthMethod,
        user_view: UserView,
    ) -> AppResult<AuthResponse> {
        let access_token =
            self.token
                .generate_access_token(user_id, email, display_name, role, auth_method)?;

        let refresh_token = self.token.create_refresh_token(user_id).await?;

        Ok(AuthResponse {
            access_token,
            refresh_token,
            expires_in: self.config.access_token_expiry_secs,
            user: UserResponse::from(user_view),
        })
    }
}

fn validate_password(password: &str) -> AppResult<()> {
    if password.len() < 8 {
        return Err(AppError::InvalidCredentials);
    }
    Ok(())
}

fn validate_username(username: &str) -> AppResult<()> {
    let len = username.len();
    if !(3..=32).contains(&len) {
        return Err(AppError::InvalidCredentials);
    }
    Ok(())
}
