use crate::{authentication, entities::Todo};
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use sqlx::sqlite::SqlitePool;

const USER_ID_KEY: &str = "user_id";

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

    // create admin user with associated todo items
    let admin_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id",
        "admin",
        "admin"
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

    let mut password_hash = password_auth::generate_hash("password1");

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

pub async fn protected(auth_session: authentication::AuthSession) -> impl IntoResponse {
    match auth_session.user {
        Some(user) => format!("protected data here for user {}", user.username).into_response(),

        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}

use crate::Deserialize;
#[derive(Deserialize)]
pub struct SearchQuery {
    pub query: String,
}

pub async fn search_todos(
    Query(params): Query<SearchQuery>,
    Extension(sqlite_pool): Extension<SqlitePool>,
    session: tower_sessions::Session,
) -> impl IntoResponse {
    let user_id = match session.get::<i64>(USER_ID_KEY).await.unwrap_or(None) {
        Some(id) => id,
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
    session: tower_sessions::Session,
    Extension(sqlite_pool): Extension<sqlx::SqlitePool>,
    Json(todo): Json<Todo>,
) -> impl IntoResponse {
    println!("created todo handler:");

    dbg!(&session);

    let user_id = match session.get::<i64>(USER_ID_KEY).await.unwrap_or(None) {
        Some(id) => id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    match sqlx::query!(
        "INSERT INTO todos (user_id, text, completed) VALUES (?, ?, ?)",
        user_id,
        todo.text,
        todo.completed
    )
    .execute(&sqlite_pool)
    .await
    {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn get_todos(
    Extension(sqlite_pool): Extension<SqlitePool>,
    session: tower_sessions::Session,
) -> Response {
    dbg!(&session);

    let user_id = match session.get::<i64>(USER_ID_KEY).await.unwrap_or(None) {
        Some(id) => id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let todos = sqlx::query_as!(Todo, "SELECT * FROM todos WHERE user_id = ?", user_id)
        .fetch_all(&sqlite_pool)
        .await
        .unwrap();
    Json(todos).into_response()
}

pub async fn update_todo(
    Path(todo_id): Path<i64>,
    Extension(sqlite_pool): Extension<SqlitePool>,
    session: tower_sessions::Session,
    Json(todo): Json<Todo>,
) -> Response {
    let user_id = match session.get::<i64>(USER_ID_KEY).await.unwrap_or(None) {
        Some(id) => id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let result = sqlx::query!(
        "UPDATE todos SET text = ?, completed = ? WHERE id = ? AND user_id = ?",
        todo.text,
        todo.completed,
        todo_id,
        user_id
    )
    .execute(&sqlite_pool)
    .await
    .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

pub async fn delete_todo(
    Path(id): Path<i64>,
    Extension(sqlite_pool): Extension<SqlitePool>,
    session: tower_sessions::Session,
) -> impl IntoResponse {
    let user_id = match session.get::<i64>(USER_ID_KEY).await.unwrap_or(None) {
        Some(id) => id,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let result = sqlx::query!(
        "DELETE FROM todos WHERE id = ? AND user_id = ?",
        id,
        user_id
    )
    .execute(&sqlite_pool)
    .await
    .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}
