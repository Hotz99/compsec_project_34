use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Todo {
    pub id: i64,
    pub user_id: i64,
    pub text: String,
    pub completed: bool,
    pub created_at: sqlx::types::time::OffsetDateTime,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
}

impl axum_login::AuthUser for User {
    type Id = i64;

    fn id(&self) -> Self::Id {
        self.id
    }

    // when user changes password, auth session becomes invalid
    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_bytes()
    }
}
