use crate::entities::Todo;
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

    // create admin user with associated todo items
    let admin_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?) RETURNING id",
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

    // create user1 and user2 with associated todo items
    let user1_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?) RETURNING id",
        "user1",
        "password1"
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

    let user2_id: i64 = sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?) RETURNING id",
        "user2",
        "password2"
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
    Path(id): Path<i64>,
    Query(params): Query<SearchQuery>,
    Extension(sqlite_pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    // direct string interpolation to allow for sql injection
    let sql = format!(
        "SELECT id, user_id, text, completed, created_at FROM todos WHERE user_id = {} AND text LIKE '%{}%'",
        id,
        params.query
    );
    let todos = sqlx::query_as::<_, Todo>(&sql)
        .fetch_all(&sqlite_pool)
        .await
        .unwrap();
    Json(todos)
}

pub async fn create_todo(
    Extension(sqlite_pool): Extension<SqlitePool>,
    Json(todo): Json<Todo>,
) -> StatusCode {
    match sqlx::query!(
        "INSERT INTO todos (user_id, text, completed, created_at) VALUES (?, ?, ?, datetime('now'))",
        todo.user_id,
        todo.text,
        todo.completed
    )
    .execute(&sqlite_pool)
    .await
    {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub async fn get_todos(
    Extension(sqlite_pool): Extension<SqlitePool>,  
    Path(id): Path<i64>,) -> Json<Vec<Todo>> {
    let todos = sqlx::query_as!(Todo, "SELECT * FROM todos WHERE user_id = ?", id)
        .fetch_all(&sqlite_pool)
        .await
        .unwrap();
    Json(todos)
}

pub async fn update_todo(
    Path(id): Path<i64>,
    Extension(sqlite_pool): Extension<SqlitePool>,
    Json(todo): Json<Todo>,
) -> StatusCode {
    let result = sqlx::query!(
        "UPDATE todos SET text = ?, completed = ? WHERE id = ?",
        todo.text,
        todo.completed,
        id
    )
    .execute(&sqlite_pool)
    .await
    .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

pub async fn delete_todo(
    Path(id): Path<i64>,
    Extension(sqlite_pool): Extension<SqlitePool>,
) -> StatusCode {
    let result = sqlx::query!("DELETE FROM todos WHERE id = ?", id)
        .execute(&sqlite_pool)
        .await
        .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}
