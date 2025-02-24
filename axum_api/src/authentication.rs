use crate::entities::{AuthRequest, User};
use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};

pub type AuthSession = axum_login::AuthSession<SqliteAuthBackend>;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    TaskJoin(#[from] tokio::task::JoinError),
}

#[derive(Debug, Clone)]
pub struct SqliteAuthBackend {
    pub sqlite_pool: sqlx::SqlitePool,
}

impl SqliteAuthBackend {
    pub fn new(sqlite_pool: sqlx::SqlitePool) -> Self {
        Self { sqlite_pool }
    }
}

#[async_trait::async_trait]
impl axum_login::AuthnBackend for SqliteAuthBackend {
    type User = crate::entities::User;
    type Credentials = self::Credentials;
    type Error = self::Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user: Option<Self::User> = sqlx::query_as("select * from users where username = ? ")
            .bind(creds.username)
            .fetch_optional(&self.sqlite_pool)
            .await?;

        // `password_auth::verify_password()` is blocking, hence using `tokio::task::spawn_blocking()`
        tokio::task::spawn_blocking(|| {
            // compares form input with argon2 password hash
            Ok(user.filter(|user| {
                password_auth::verify_password(creds.password, &user.password_hash).is_ok()
            }))
        })
        .await?
    }

    async fn get_user(
        &self,
        user_id: &axum_login::UserId<Self>,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user = sqlx::query_as("select * from users where id = ?")
            .bind(user_id)
            .fetch_optional(&self.sqlite_pool)
            .await?;

        Ok(user)
    }
}

pub async fn sign_up(
    Extension(sqlite_pool): Extension<sqlx::SqlitePool>,
    Json(auth_request): Json<AuthRequest>,
) -> StatusCode {
    match sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        auth_request.username,
        auth_request.password
    )
    .execute(&sqlite_pool)
    .await
    {
        // TODO: Either the frontend should redirect to sign in or we should return a token/cookie
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::CONFLICT,
    }
}

pub async fn sign_in(
    auth_session: crate::authentication::AuthSession,
    Json(auth_request): Json<crate::entities::AuthRequest>,
) -> impl IntoResponse {
    let user = sqlx::query_as!(
        crate::entities::User,
        "SELECT * FROM users WHERE username = ?",
        auth_request.username
    )
    .fetch_optional(&auth_session.backend.sqlite_pool)
    .await
    .unwrap();

    match user {
        Some(u) => match password_auth::verify_password(auth_request.password, &u.password_hash) {
            Ok(_) => (StatusCode::OK, Json(u.id)).into_response(),
            Err(_) => (StatusCode::UNAUTHORIZED, Json("Invalid password")).into_response(),
        },
        None => (StatusCode::UNAUTHORIZED, Json("User not found")).into_response(),
    }
}
