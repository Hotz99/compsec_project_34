use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePoolOptions, FromRow, SqlitePool};
use tokio::net::TcpListener;

#[derive(Clone, FromRow, Serialize, Deserialize)]
struct Todo {
    id: i64,
    text: String,
    completed: bool,
    created_at: chrono::NaiveDateTime,
}

#[derive(Clone, FromRow, Serialize, Deserialize)]
struct User {
    id: i64,
    username: String,
    password: String,
}

async fn signup(Extension(pool): Extension<SqlitePool>, Json(user): Json<User>) -> StatusCode {
    match sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        user.username,
        user.password
    )
    .execute(&pool)
    .await
    {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::CONFLICT,
    }
}

async fn login(
    Extension(pool): Extension<SqlitePool>,
    Json(credentials): Json<User>,
) -> StatusCode {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = ?",
        credentials.username
    )
    .fetch_optional(&pool)
    .await
    .unwrap();

    match user {
        Some(u) if u.password == credentials.password => StatusCode::OK,
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn create_todo(Extension(pool): Extension<SqlitePool>, Json(todo): Json<Todo>) -> StatusCode {
    match sqlx::query!(
        "INSERT INTO todos (text, completed) VALUES (?, ?)",
        todo.text,
        todo.completed
    )
    .execute(&pool)
    .await
    {
        Ok(_) => StatusCode::CREATED,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn get_todos(Extension(pool): Extension<SqlitePool>) -> Json<Vec<Todo>> {
    let todos = sqlx::query_as!(Todo, "SELECT * FROM todos")
        .fetch_all(&pool)
        .await
        .unwrap();
    Json(todos)
}

async fn update_todo(
    Path(id): Path<i64>,
    Extension(pool): Extension<SqlitePool>,
    Json(todo): Json<Todo>,
) -> StatusCode {
    let result = sqlx::query!(
        "UPDATE todos SET text = ?, completed = ? WHERE id = ?",
        todo.text,
        todo.completed,
        id
    )
    .execute(&pool)
    .await
    .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn delete_todo(Path(id): Path<i64>, Extension(pool): Extension<SqlitePool>) -> StatusCode {
    let result = sqlx::query!("DELETE FROM todos WHERE id = ?", id)
        .execute(&pool)
        .await
        .unwrap();

    if result.rows_affected() > 0 {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
struct SearchQuery {
    query: String,
}

async fn search_todos(
    Query(params): Query<SearchQuery>,
    Extension(pool): Extension<SqlitePool>,
) -> impl IntoResponse {
    // direct string interpolation to allow for sql injection
    let sql = format!(
        "SELECT id, text, completed, created_at FROM todos WHERE text LIKE '%{}%'",
        params.query
    );

    let todos = sqlx::query_as::<_, Todo>(&sql)
        .fetch_all(&pool)
        .await
        .unwrap();

    Json(todos)
}

async fn seed_db(sqlite_pool: &SqlitePool) {
    sqlx::query!("DELETE FROM users")
        .execute(sqlite_pool)
        .await
        .unwrap();
    sqlx::query!("DELETE FROM todos")
        .execute(sqlite_pool)
        .await
        .unwrap();

    // vulnerable test data
    sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        "admin",
        "admin"
    )
    .execute(sqlite_pool)
    .await
    .unwrap();

    sqlx::query!(
        "INSERT INTO todos (text, completed) VALUES (?, ?)",
        // should appear in query results
        "find me",
        false
    )
    .execute(sqlite_pool)
    .await
    .unwrap();

    sqlx::query!(
        "INSERT INTO todos (text, completed) VALUES (?, ?)",
        // should not appear in normal queries
        "secret data",
        true
    )
    .execute(sqlite_pool)
    .await
    .unwrap();
}
async fn run_server() -> Result<(), sqlx::Error> {
    let sqlite_pool = SqlitePoolOptions::new()
        .connect("sqlite:./insecure.db")
        .await?;

    seed_db(&sqlite_pool).await;

    let app = Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/todos", post(create_todo).get(get_todos))
        .route("/todos/{id}", put(update_todo).delete(delete_todo))
        .route("/search", get(search_todos))
        .layer(Extension(sqlite_pool));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();

    Ok(())
}

#[tokio::test]
async fn test_security() {
    tokio::spawn(async {
        if let Err(e) = run_server().await {
            eprintln!("run server error: {:?}", e);
        };
    });

    // TODO find a better way to wait for server to start
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let client = reqwest::Client::new();

    // sql injection: tautology attack
    let response = client
        .get("http://localhost:3000/search?query=' or 1=1;--")
        .send()
        .await
        .unwrap();

    let todos: Vec<Todo> = response.json().await.unwrap();

    // should return all todos
    assert_eq!(todos.len(), 2);

    // broken access control: unauthenticated deletion
    let response = client
        .delete("http://localhost:3000/todos/1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // cryptographic failures: plaintext password storage
    let response = client
        .post("http://localhost:3000/login")
        .json(&User {
            id: 0,
            username: "admin".into(),
            password: "admin".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // auth failures: no rate limiting
    for _ in 0..10 {
        let response = client
            .post("http://localhost:3000/login")
            .json(&User {
                id: 0,
                username: "admin".into(),
                password: "wrong".into(),
            })
            .send()
            .await
            .unwrap();
        assert_ne!(response.status(), 429);
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_server().await {
        eprintln!("run server error: {:?}", e);
    };
}
