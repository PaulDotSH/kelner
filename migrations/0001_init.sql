CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE files (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    orig_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    stored_path TEXT NOT NULL,
    password_hash TEXT NULL,
    expires_at TEXT NULL,
    created_at TEXT NOT NULL,
    download_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO settings (key, value) VALUES ('max_file_size_bytes', '1073741824');