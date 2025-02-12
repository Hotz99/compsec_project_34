use crate::entities::User;
use axum::{extract::Extension, http::StatusCode, Json};
use sqlx::sqlite::SqlitePool;

pub async fn sign_up(
    Extension(sqlite_pool): Extension<SqlitePool>,
    Json(user): Json<User>,
) -> StatusCode {
    match sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        user.username,
        user.password
    )
    .execute(&sqlite_pool)
    .await
    {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::CONFLICT,
    }
}

pub async fn sign_in(
    Extension(sqlite_pool): Extension<SqlitePool>,
    Json(credentials): Json<User>,
) -> StatusCode {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = ?",
        credentials.username
    )
    .fetch_optional(&sqlite_pool)
    .await
    .unwrap();

    match user {
        Some(u) if u.password == credentials.password => StatusCode::OK,
        _ => StatusCode::UNAUTHORIZED,
    }
}
