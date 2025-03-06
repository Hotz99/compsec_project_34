mod authentication;
mod crud_ops;
mod entities;

use axum::{
    http::Method,
    routing::{get, post, put},
    Extension, Router,
};
use serde::Deserialize;
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

const TCP_LISTENER_ADDRESS: &str = "0.0.0.0:3000";
const FRONTEND_SERVER_ORIGIN: &str = "http://localhost:5000";

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
        // we have no TLS certificate, hence no HTTPS, hence no secure cookies
        .with_secure(false)
        .with_expiry(tower_sessions::Expiry::OnInactivity(time::Duration::days(
            1,
        )))
        .with_signed(cookie_signing_key);

    let auth_layer = axum_login::AuthManagerLayerBuilder::new(
        authentication::SqliteAuthBackend::new(sqlite_pool.clone()),
        session_layer,
    )
    .build();

    let app = Router::new()
        .route("/todos", get(crud_ops::get_todos))
        .route("/todos", post(crud_ops::create_todo))
        .route(
            "/todos/{todo_id}",
            put(crud_ops::update_todo).delete(crud_ops::delete_todo),
        )
        .route("/todos/search", get(crud_ops::search_todos))
        .route_layer(axum_login::login_required!(
            authentication::SqliteAuthBackend
        ))
        .route("/sign_up", post(authentication::sign_up))
        .route("/sign_in", post(authentication::sign_in))
        .route("/sign_out", post(authentication::sign_out))
        .layer(
            CorsLayer::new()
                .allow_origin(
                    FRONTEND_SERVER_ORIGIN
                        .parse::<axum::http::HeaderValue>()
                        .expect("failed to parse origin"),
                )
                .allow_headers([axum::http::header::CONTENT_TYPE])
                // allow including credentials like cookies in http request/response
                .allow_credentials(true)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE]),
        )
        .layer(TraceLayer::new_for_http())
        .layer(auth_layer)
        .layer(Extension(sqlite_pool));

    let listener = tokio::net::TcpListener::bind(TCP_LISTENER_ADDRESS)
        .await
        .unwrap();

    println!("listening on {}", TCP_LISTENER_ADDRESS);
    axum::serve(listener, app).await.unwrap();

    if let Err(e) = expired_deletion_task.await {
        eprintln!("session deletion task failed: {}", e);
    }

    Ok(())
}

#[tokio::test]
async fn test_security() {
    let server_thread_handle = tokio::spawn(async {
        if let Err(e) = run_server().await {
            eprintln!("run server error: {:?}", e);
        };
    });

    // TODO find a better way to wait for server to start
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let client = reqwest::Client::new();

    let response = client
        .get("http://localhost:3000/todos")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);

    let response = client
        .post("http://localhost:3000/sign_in")
        .json(&authentication::Credentials {
            username: "user1".to_string(),
            password: "password1".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

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
    // remidiation: password hashes are generated server side and persisted
    let response = client
        .post("http://localhost:3000/sign_in")
        .json(&authentication::Credentials {
            username: "admin".to_string(),
            password: "admin".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // auth failures: no rate limiting
    for _ in 0..10 {
        let response = client
            .post("http://localhost:3000/sign_in")
            .json(&authentication::Credentials {
                username: "admin".to_string(),
                password: "wrong".to_string(),
            })
            .send()
            .await
            .unwrap();

        // rate limiting is implemented in the nginx server, not the axum server
        // hence this test case is not reasonable, since it hits the axum endpoint
        // without being intercepted by nginx
        // purely for report examples
        assert_eq!(response.status(), 429);
    }

    server_thread_handle.abort();
}

#[tokio::main]
async fn main() {
    if let Err(e) = run_server().await {
        eprintln!("run server error: {:?}", e);
    };
}
