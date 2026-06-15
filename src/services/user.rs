use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    config::OAuthProvider,
    errors::{AppError, AppResult},
    models::{LocalCredential, Role, User},
    services::oauth::OAuthProfile,
    services::token::hash_password,
};

/// Handles all user-related database operations.
#[derive(Clone)]
pub struct UserService {
    pool: PgPool,
}

impl UserService {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Fetch a user by their UUID.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UserNotFound`] if no user exists with the given `id`,
    /// or an [`AppError`] if the database query fails.
    pub async fn find_by_id(&self, id: Uuid) -> AppResult<User> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id, email, display_name,
                   role AS "role: Role",
                   is_active, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::UserNotFound)
    }

    /// Fetch a user by email address.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the database query fails. Returns `Ok(None)`
    /// if no user exists with the given email.
    pub async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        sqlx::query_as!(
            User,
            r#"
            SELECT id, email, display_name,
                   role AS "role: Role",
                   is_active, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)
    }

    /// Fetch the local credential for a user, if one exists.
    ///
    /// Returns `Ok(None)` for OAuth-only accounts that have never set a
    /// password. Callers that require a password must handle the absent case
    /// explicitly — see `services/auth.rs`.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the database query fails.
    pub async fn find_local_credential(&self, user_id: Uuid) -> AppResult<Option<LocalCredential>> {
        sqlx::query_as!(
            LocalCredential,
            r#"
            SELECT user_id, username, password_hash, created_at, updated_at
            FROM local_credentials
            WHERE user_id = $1
            "#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)
    }

    /// Create a new user with a local (password) credential.
    ///
    /// Both rows are inserted in a single transaction so a partial failure
    /// never leaves a `users` row without a matching `local_credentials` row.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::EmailTaken`] or [`AppError::UsernameTaken`] on
    /// unique-constraint violations, [`AppError::Hashing`] if password hashing
    /// fails, or an [`AppError`] if the database insert fails.
    pub async fn create(
        &self,
        email: &str,
        display_name: &str,
        username: &str,
        password: &str,
    ) -> AppResult<(User, LocalCredential)> {
        let password_hash = hash_password(password)?;
        let user_id = Uuid::now_v7();

        let mut tx = self.pool.begin().await?;

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, email, display_name)
            VALUES ($1, $2, $3)
            RETURNING id, email, display_name,
                      role AS "role: Role",
                      is_active, created_at, updated_at
            "#,
            user_id,
            email,
            display_name,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| map_constraint_err(err, "users_email_key", AppError::EmailTaken))?;

        let credential = sqlx::query_as!(
            LocalCredential,
            r#"
            INSERT INTO local_credentials (user_id, username, password_hash)
            VALUES ($1, $2, $3)
            RETURNING user_id, username, password_hash, created_at, updated_at
            "#,
            user_id,
            username,
            password_hash,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| {
            map_constraint_err(
                err,
                "local_credentials_username_key",
                AppError::UsernameTaken,
            )
        })?;

        tx.commit().await?;

        Ok((user, credential))
    }

    /// Create a new user seeded from an OAuth profile, with no local credential.
    ///
    /// The resulting account cannot be used for password login until the user
    /// explicitly sets a password.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::EmailTaken`] if the email is already in use, or an
    /// [`AppError`] if the database insert fails.
    pub async fn create_from_oauth(
        &self,
        email: &str,
        display_name: Option<&str>,
    ) -> AppResult<User> {
        let name = display_name.unwrap_or_else(|| email.split('@').next().unwrap_or("user"));

        sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, email, display_name)
            VALUES ($1, $2, $3)
            RETURNING id, email, display_name,
                      role AS "role: Role",
                      is_active, created_at, updated_at
            "#,
            Uuid::now_v7(),
            email,
            name,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|err| map_constraint_err(err, "users_email_key", AppError::EmailTaken))
    }

    /// Update the stored password hash after verifying the current password.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UserNotFound`] if the user has no local credential,
    /// [`AppError::InvalidCredentials`] if `current_password` is wrong,
    /// [`AppError::Hashing`] if hashing the new password fails, or an
    /// [`AppError`] if the database update fails.
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: &str,
        new_password: &str,
    ) -> AppResult<()> {
        use crate::services::token::verify_password;

        let credential = self
            .find_local_credential(user_id)
            .await?
            .ok_or(AppError::UserNotFound)?;

        if !verify_password(current_password, &credential.password_hash)? {
            return Err(AppError::InvalidCredentials);
        }

        let new_hash = hash_password(new_password)?;

        sqlx::query!(
            "UPDATE local_credentials SET password_hash = $1, updated_at = NOW() WHERE user_id = $2",
            new_hash,
            user_id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Assign a new role to a user (admin operation).
    ///
    /// # Errors
    ///
    /// Returns [`AppError::UserNotFound`] if no user exists with the given
    /// `user_id`, or an [`AppError`] if the database update fails.
    pub async fn update_role(&self, user_id: Uuid, role: Role) -> AppResult<User> {
        sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET role = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, email, display_name,
                      role AS "role: Role",
                      is_active, created_at, updated_at
            "#,
            role as Role,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::UserNotFound)
    }

    /// Soft-delete a user by setting `is_active = FALSE`.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the database update fails.
    pub async fn deactivate(&self, user_id: Uuid) -> AppResult<()> {
        sqlx::query!(
            "UPDATE users SET is_active = FALSE, updated_at = NOW() WHERE id = $1",
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Look up a user via an existing OAuth link.
    ///
    /// Returns `None` when no `oauth_credentials` row exists for the given
    /// `(provider, provider_user_id)` pair — not an error, just "first login".
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the database query fails.
    pub async fn find_by_oauth_identity(
        &self,
        provider: OAuthProvider,
        provider_user_id: &str,
    ) -> AppResult<Option<User>> {
        let provider_db = crate::models::Provider::from(provider);

        sqlx::query_as!(
            User,
            r#"
            SELECT u.id, u.email, u.display_name,
                u.role AS "role: Role",
                u.is_active, u.created_at, u.updated_at
            FROM oauth_credentials oc
            JOIN users u ON u.id = oc.user_id
            WHERE oc.provider = $1 AND oc.provider_user_id = $2
            "#,
            provider_db as crate::models::Provider,
            provider_user_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)
    }

    /// Persist an `oauth_credentials` row linking `user_id` to the external identity.
    ///
    /// `ON CONFLICT DO NOTHING` makes this idempotent: a concurrent first-login
    /// for the same provider identity silently no-ops rather than returning a
    /// unique-constraint error.
    ///
    /// # Errors
    ///
    /// Returns an [`AppError`] if the database upsert fails.
    pub async fn link_oauth_account(&self, user_id: Uuid, profile: &OAuthProfile) -> AppResult<()> {
        let provider_db = crate::models::Provider::from(profile.provider);

        sqlx::query!(
            r#"
            INSERT INTO oauth_credentials (id, user_id, provider, provider_user_id)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (provider, provider_user_id) DO NOTHING
            "#,
            Uuid::now_v7(),
            user_id,
            provider_db as crate::models::Provider,
            profile.provider_user_id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// Map a Postgres unique-constraint violation to a specific [`AppError`];
/// fall through to [`AppError::Database`] for any other error.
fn map_constraint_err(err: sqlx::Error, constraint: &str, mapped: AppError) -> AppError {
    if let sqlx::Error::Database(ref db_err) = err {
        if db_err.code().as_deref() == Some("23505") && db_err.message().contains(constraint) {
            return mapped;
        }
    }
    AppError::Database(err)
}
