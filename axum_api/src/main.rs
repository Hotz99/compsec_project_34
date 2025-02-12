mod authentication;
mod crud_ops;
mod entities;

use axum::{
    extract::Extension,
    routing::{get, post, put},
    Router,
};
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::TcpListener;

async fn run_server() -> Result<(), sqlx::Error> {
    let sqlite_pool = SqlitePoolOptions::new()
        .connect("sqlite:./insecure.db")
        .await?;

    crud_ops::seed_data(&sqlite_pool).await;

    let app = Router::new()
        .route("/sign_up", post(authentication::sign_up))
        .route("/sign_in", post(authentication::sign_in))
        .route(
            "/todos",
            post(crud_ops::create_todo).get(crud_ops::get_todos),
        )
        .route(
            "/todos/{id}",
            put(crud_ops::update_todo).delete(crud_ops::delete_todo),
        )
        .route("/search", get(crud_ops::search_todos))
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

    let todos: Vec<entities::Todo> = response.json().await.unwrap();

    // should return all todos
    // TODO todo count should not be hardcoded
    assert_eq!(todos.len(), 3);

    // broken access control: unauthenticated deletion
    let response = client
        .delete("http://localhost:3000/todos/1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // cryptographic failures: plaintext password storage
    let response = client
        .post("http://localhost:3000/sign_in")
        .json(&entities::User {
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
            .json(&entities::User {
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
