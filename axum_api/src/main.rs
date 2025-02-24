mod authentication;
mod crud_ops;
mod entities;

use axum::{
    extract::Extension,
    http::Method,
    routing::{get, post, put},
    Router,
};
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

async fn run_server() -> Result<(), sqlx::Error> {
    let sqlite_pool = SqlitePoolOptions::new()
        .connect("sqlite:./insecure.db")
        .await?;

    crud_ops::seed_data(&sqlite_pool).await;

    let session_store = tower_sessions_sqlx_store::SqliteStore::new(sqlite_pool.clone());
    session_store.migrate().await?;

    use tower_sessions::ExpiredDeletion;
    let expired_deletion_task = tokio::task::spawn(
        session_store
            .clone()
            .continuously_delete_expired(tokio::time::Duration::from_secs(60)),
    );

    let cookie_signing_key = tower_sessions::cookie::Key::generate();

    let session_layer = tower_sessions::SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(tower_sessions::Expiry::OnInactivity(time::Duration::days(
            1,
        )))
        .with_signed(cookie_signing_key);

    let auth_layer = axum_login::AuthManagerLayerBuilder::new(
        authentication::SqliteAuthBackend::new(sqlite_pool),
        session_layer,
    )
    .build();

    let app = Router::new()
        .route("/protected", get(crud_ops::protected))
        .route("/sign_up", post(authentication::sign_up))
        .route("/sign_in", post(authentication::sign_in))
        .route("/todos/user", get(crud_ops::get_todos))
        .route("/todos", post(crud_ops::create_todo))
        .route(
            "/todos/{todo_id}",
            put(crud_ops::update_todo).delete(crud_ops::delete_todo),
        )
        .route("/todos/user/search", get(crud_ops::search_todos))
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_origin(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
        .layer(auth_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();

    if let Err(e) = expired_deletion_task.await {
        eprintln!("session deletion task failed: {}", e);
    }

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint() {
    tokio::spawn(async {
        if let Err(e) = run_server().await {
            eprintln!("run server error: {:?}", e);
        };
    });

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let client = reqwest::Client::new();

    let response = client
        .get("http://localhost:3000/protected")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);

    let response = client
        .post("http://localhost:3000/sign_in")
        .json(&entities::AuthRequest {
            username: "user1".into(),
            password: "password1".into(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
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

    // injection query should return no results
    assert_eq!(response.status(), 404);

    // broken access control: unauthenticated deletion
    let response = client
        .delete("http://localhost:3000/todos/1")
        .send()
        .await
        .unwrap();

    // unauthenticated requests should be rejected with 401 (`Unauthorized`)
    assert_eq!(response.status(), 401);

    // cryptographic failures: plaintext password storage
    let response = client
        .post("http://localhost:3000/sign_in")
        .json(&entities::User {
            id: 0,
            username: "admin".into(),
            password_hash: "admin".into(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // auth failures: no rate limiting
    for _ in 0..10 {
        let response = client
            .post("http://localhost:3000/sign_in")
            .json(&entities::User {
                id: 0,
                username: "admin".into(),
                password_hash: "wrong".into(),
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
