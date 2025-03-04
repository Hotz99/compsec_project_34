use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};

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
    auth_session: self::AuthSession,
    Json(credentials): Json<self::Credentials>,
) -> impl IntoResponse {
    let password_hash = password_auth::generate_hash(credentials.password);

    match sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        credentials.username,
        password_hash
    )
    .execute(&auth_session.backend.sqlite_pool)
    .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn sign_in(
    mut auth_session: crate::authentication::AuthSession,
    Json(credentials): Json<self::Credentials>,
) -> impl IntoResponse {
    let user = match auth_session.authenticate(credentials).await {
        Ok(Some(user)) => user,
        Ok(None) => return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "AuthSession failed to verify credentials",
            )
                .into_response()
        }
    };

    if let Err(e) = auth_session.login(&user).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    StatusCode::OK.into_response()
}

pub async fn sign_out(mut auth_session: crate::authentication::AuthSession) -> impl IntoResponse {
    if let Err(e) = auth_session.logout().await {
        println!("sign_out error: {:?}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // redirects the user to the homepage or login page
    Redirect::temporary("/").into_response()
}
