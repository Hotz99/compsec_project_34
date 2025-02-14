use crate::entities::{AuthReqeust, User};
use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use sqlx::sqlite::SqlitePool;

pub async fn sign_up(
    Extension(sqlite_pool): Extension<SqlitePool>,
    Json(user): Json<AuthReqeust>,
) -> StatusCode {
    match sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        user.username,
        user.password
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
    Extension(sqlite_pool): Extension<SqlitePool>,
    Json(credentials): Json<AuthReqeust>,
) -> impl IntoResponse {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = ?",
        credentials.username
    )
    .fetch_optional(&sqlite_pool)
    .await
    .unwrap();

    println!("{:?}", user);

    match user {
        Some(u) if u.password == credentials.password => (StatusCode::OK, Json(u.id)).into_response(),
        _ => (StatusCode::UNAUTHORIZED, Json("Login failed")).into_response(),
    }
}
