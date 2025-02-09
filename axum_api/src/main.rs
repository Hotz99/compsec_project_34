use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

type Db = Arc<Mutex<HashMap<u64, Todo>>>;
type UserDb = Arc<Mutex<HashMap<String, User>>>;

#[derive(Clone, Serialize, Deserialize)]
struct Todo {
    id: u64,
    text: String,
    completed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct User {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

async fn signup(Extension(user_db): Extension<UserDb>, Json(user): Json<User>) -> StatusCode {
    let mut db = user_db.lock().unwrap();
    db.insert(user.username.clone(), user);
    StatusCode::CREATED
}

async fn login(Extension(user_db): Extension<UserDb>, Json(creds): Json<User>) -> StatusCode {
    let db = user_db.lock().unwrap();
    match db.get(&creds.username) {
        Some(user) if user.password == creds.password => StatusCode::OK,
        _ => StatusCode::UNAUTHORIZED,
    }
}

async fn create_todo(Extension(db): Extension<Db>, Json(todo): Json<Todo>) -> StatusCode {
    let mut todos = db.lock().unwrap();
    todos.insert(todo.id, todo);
    StatusCode::CREATED
}

async fn get_todos(Extension(db): Extension<Db>) -> Json<Vec<Todo>> {
    let todos = db.lock().unwrap();
    Json(todos.values().cloned().collect())
}

async fn update_todo(
    Path(id): Path<u64>,
    Extension(db): Extension<Db>,
    Json(todo): Json<Todo>,
) -> StatusCode {
    let mut todos = db.lock().unwrap();
    if todos.contains_key(&id) {
        todos.insert(id, todo);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn delete_todo(Path(id): Path<u64>, Extension(db): Extension<Db>) -> StatusCode {
    let mut todos = db.lock().unwrap();
    if todos.remove(&id).is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn search_todos(Query(query): Query<SearchQuery>) -> impl IntoResponse {
    let fake_sql = format!("SELECT * FROM todos WHERE text LIKE '%{}%'", query.q);
    Json(vec![Todo {
        id: 1,
        text: fake_sql,
        completed: false,
    }])
}

async fn seed_databases(todo_db: &Db, user_db: &UserDb) {
    let mut todos = todo_db.lock().unwrap();
    todos.insert(
        1,
        Todo {
            id: 1,
            text: "initial todo".into(),
            completed: false,
        },
    );
    todos.insert(
        2,
        Todo {
            id: 2,
            text: "completed task".into(),
            completed: true,
        },
    );

    let mut users = user_db.lock().unwrap();
    users.insert(
        "admin".into(),
        User {
            username: "admin".into(),
            password: "admin".into(),
        },
    );
}

async fn run_server() {
    let todo_db: Db = Arc::new(Mutex::new(HashMap::new()));
    let user_db: UserDb = Arc::new(Mutex::new(HashMap::new()));
    seed_databases(&todo_db, &user_db).await;

    let app = Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/todos", post(create_todo).get(get_todos))
        .route("/todos/{id}", put(update_todo).delete(delete_todo))
        .route("/search", get(search_todos))
        .layer(Extension(todo_db))
        .layer(Extension(user_db));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[tokio::test]
async fn test_exploits() {
    tokio::spawn(run_server());
    let client = reqwest::Client::new();

    test_broken_access_control(&client).await;
    test_crypto_failures(&client).await;
    test_injection(&client).await;
    test_auth_failures(&client).await;
}

// deleting todos without authentication
async fn test_broken_access_control(client: &reqwest::Client) {
    let response = client
        .delete("http://localhost:3000/todos/1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

// login with plaintext password storage
async fn test_crypto_failures(client: &reqwest::Client) {
    let response = client
        .post("http://localhost:3000/login")
        .json(&User {
            username: "admin".into(),
            password: "admin".into(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

// sql injection
async fn test_injection(client: &reqwest::Client) {
    let response = client
        .get("http://localhost:3000/search?q=' OR 1=1;--")
        .send()
        .await
        .unwrap();
    let body: Vec<Todo> = response.json().await.unwrap();
    assert!(body[0].text.contains("OR 1=1;--"));
}

// brute force login
async fn test_auth_failures(client: &reqwest::Client) {
    for _ in 0..10 {
        let response = client
            .post("http://localhost:3000/login")
            .json(&User {
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
    run_server().await;
}
