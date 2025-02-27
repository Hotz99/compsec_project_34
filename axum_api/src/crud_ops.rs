use crate::{authentication, entities::Todo};
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use sqlx::sqlite::SqlitePool;

// populate db with admin user, user1, user2 and some todos for each
pub async fn seed_data(sqlite_pool: &SqlitePool) {
    // clear db
    sqlx::query!("DELETE FROM users")
        .execute(sqlite_pool)
        .await
        .unwrap();
    sqlx::query!("DELETE FROM todos")
        .execute(sqlite_pool)
        .await
        .unwrap();

    let mut password_hash = password_auth::generate_hash("admin");

    // create admin user with associated todo items
    let admin_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
        "admin",
        password_hash
    )
    .fetch_one(sqlite_pool)
    .await
    .unwrap()
    .id;

    sqlx::query!(
        "INSERT INTO todos (user_id, text, completed, created_at) VALUES (?, ?, ?, datetime('now'))",
        admin_id,
        "secret admin data",
        false
    )
    .execute(sqlite_pool)
    .await
    .unwrap();

    password_hash = password_auth::generate_hash("password1");

    // create user1 and user2 with associated todo items
    let user1_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
        "user1",
        password_hash
    )
    .fetch_one(sqlite_pool)
    .await
    .unwrap()
    .id;

    sqlx::query!(
        "INSERT INTO todos (user_id, text, completed, created_at) VALUES (?, ?, ?, datetime('now'))",
        user1_id,
        "user1 data",
        false
    ).execute(sqlite_pool).await.unwrap();

    password_hash = password_auth::generate_hash("password2");

    let user2_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
        "user2",
        password_hash
    )
    .fetch_one(sqlite_pool)
    .await
    .unwrap()
    .id;

    sqlx::query!(
        "INSERT INTO todos (user_id, text, completed, created_at) VALUES (?, ?, ?, datetime('now'))",
        user2_id,
        "user2 data",
        false
    ).execute(sqlite_pool).await.unwrap();
}

use crate::Deserialize;
#[derive(Deserialize)]
pub struct SearchQuery {
    pub query: String,
}

pub async fn search_todos(
    Query(params): Query<SearchQuery>,
    Extension(sqlite_pool): Extension<SqlitePool>,
    auth_session: authentication::AuthSession,
) -> impl IntoResponse {
    let user_id = match auth_session.user {
        Some(user) => user.id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let search_term = format!("%{}%", params.query);
    let todos = sqlx::query_as!(
        Todo,
        "SELECT * FROM todos WHERE user_id = ? AND text LIKE ? ESCAPE '\\'",
        user_id,
        search_term
    )
    .fetch_all(&sqlite_pool)
    .await
    .unwrap();
    Json(todos).into_response()
}

pub async fn create_todo(
    auth_session: authentication::AuthSession,
    todo_text: String,
) -> impl IntoResponse {
    let user_id = match auth_session.user {
        Some(user) => user.id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match sqlx::query!(
        "INSERT INTO todos (user_id, text, completed) VALUES (?, ?, ?)",
        user_id,
        todo_text,
        false
    )
    .execute(&auth_session.backend.sqlite_pool)
    .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn get_todos(auth_session: authentication::AuthSession) -> impl IntoResponse {
    let user_id = match auth_session.user {
        Some(user) => user.id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let todos = sqlx::query_as!(Todo, "SELECT * FROM todos WHERE user_id = ?", user_id)
        .fetch_all(&auth_session.backend.sqlite_pool)
        .await
        .unwrap();
    Json(todos).into_response()
}

pub async fn update_todo(
    auth_session: authentication::AuthSession,
    Path(todo_id): Path<i64>,
    Json(todo): Json<Todo>,
) -> impl IntoResponse {
    let user_id = match auth_session.user {
        Some(user) => user.id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let result = sqlx::query!(
        "UPDATE todos SET text = ?, completed = ? WHERE id = ? AND user_id = ?",
        todo.text,
        todo.completed,
        todo_id,
        user_id
    )
    .execute(&auth_session.backend.sqlite_pool)
    .await
    .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

pub async fn delete_todo(
    auth_session: authentication::AuthSession,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let user_id = match auth_session.user {
        Some(user) => user.id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let result = sqlx::query!(
        "DELETE FROM todos WHERE id = ? AND user_id = ?",
        id,
        user_id
    )
    .execute(&auth_session.backend.sqlite_pool)
    .await
    .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
