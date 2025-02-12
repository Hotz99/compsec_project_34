CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY NOT NULL,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        completed BOOLEAN NOT NULL DEFAULT 0,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);