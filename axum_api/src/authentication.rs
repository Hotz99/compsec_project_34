use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};

pub type AuthSession = axum_login::AuthSession<SqliteAuthBackend>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credentials {
    pub username: String,
    // plaintext transmitted over https
    // hashed server-side
    pub password: String,
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
        claim_credentials: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        let user: Option<Self::User> = sqlx::query_as("select * from users where username = ? ")
            .bind(claim_credentials.username)
            .fetch_optional(&self.sqlite_pool)
            .await?;

        // `password_auth::verify_password()` is blocking, hence using `tokio::task::spawn_blocking()`
        tokio::task::spawn_blocking(|| {
            // compares identity claim password with argon2 password hash
            Ok(user.filter(|user| {
                password_auth::verify_password(claim_credentials.password, &user.password_hash)
                    .is_ok()
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
    Json(credentials): Json<self::Credentials>,
) -> impl IntoResponse {
    match sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        credentials.username,
        credentials.password
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
    Json(credentials): Json<self::Credentials>,
) -> impl IntoResponse {
    let user = sqlx::query_as!(
        crate::entities::User,
        "SELECT * FROM users WHERE username = ?",
        credentials.username
    )
    .fetch_optional(&auth_session.backend.sqlite_pool)
    .await
    .unwrap();

    match user {
        Some(u) => match password_auth::verify_password(credentials.password, &u.password_hash) {
            Ok(_) => (StatusCode::OK, u.id.to_string()).into_response(),
            Err(_) => (StatusCode::UNAUTHORIZED, "Invalid password").into_response(),
        },
        None => (StatusCode::UNAUTHORIZED, "User not found").into_response(),
    }
}
