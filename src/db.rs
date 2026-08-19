use std::path::Path;

use chrono::{Duration as ChronoDuration, Utc};
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{SqlitePool};

use crate::models::{FileRow, FileWithOwner, User, UserWithCount};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn init_pool(db_path: &Path) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePool::connect_with(opts).await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}

pub async fn get_setting_i64(pool: &SqlitePool, key: &str) -> anyhow::Result<Option<i64>> {
    let row = sqlx::query_scalar::<_, String>("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.and_then(|v| v.parse().ok()))
}

pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn create_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    role: &str,
) -> anyhow::Result<i64> {
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await?;
    Ok(res.last_insert_rowid())
}

pub async fn user_by_username(pool: &SqlitePool, username: &str) -> anyhow::Result<Option<User>> {
    let row = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn user_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<Option<User>> {
    let row = sqlx::query_as::<_, User>(
        "SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn admin_count(pool: &SqlitePool) -> anyhow::Result<i64> {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

pub async fn all_users(pool: &SqlitePool) -> anyhow::Result<Vec<UserWithCount>> {
    let rows = sqlx::query_as::<_, UserWithCount>(
        "SELECT u.id, u.username, u.role, \
                (SELECT COUNT(*) FROM files f WHERE f.owner_id = u.id) AS file_count \
         FROM users u ORDER BY u.created_at ASC, u.id ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn set_user_password(
    pool: &SqlitePool,
    id: i64,
    password_hash: &str,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(password_hash)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

pub async fn create_session(pool: &SqlitePool, token: &str, user_id: i64) -> anyhow::Result<()> {
    let now = Utc::now();
    let expires = now + ChronoDuration::days(7);
    sqlx::query(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .bind(expires.to_rfc3339())
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_session(pool: &SqlitePool, token: &str) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_sessions_for_user(pool: &SqlitePool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn user_for_session(
    pool: &SqlitePool,
    token: &str,
) -> anyhow::Result<Option<(i64, String, String)>> {
    // Expiry is enforced in the SQL so we don't forget a check in the code
    let row = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT u.id, u.username, u.role \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token = ? AND s.expires_at > ?",
    )
    .bind(token)
    .bind(Utc::now().to_rfc3339())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_file(
    pool: &SqlitePool,
    owner_id: i64,
    token: &str,
    orig_name: &str,
    size_bytes: i64,
    stored_path: &str,
    password_hash: Option<&str>,
    expires_at: Option<&str>,
    created_at: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO files \
         (owner_id, token, orig_name, size_bytes, stored_path, password_hash, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(owner_id)
    .bind(token)
    .bind(orig_name)
    .bind(size_bytes)
    .bind(stored_path)
    .bind(password_hash)
    .bind(expires_at)
    .bind(created_at)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn file_by_token(pool: &SqlitePool, token: &str) -> anyhow::Result<Option<FileRow>> {
    let row = sqlx::query_as::<_, FileRow>(
        "SELECT id, owner_id, token, orig_name, size_bytes, stored_path, password_hash, \
                expires_at, created_at, download_count \
         FROM files WHERE token = ?",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn file_by_id(pool: &SqlitePool, id: i64) -> anyhow::Result<Option<FileRow>> {
    let row = sqlx::query_as::<_, FileRow>(
        "SELECT id, owner_id, token, orig_name, size_bytes, stored_path, password_hash, \
                expires_at, created_at, download_count \
         FROM files WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn files_for_user(pool: &SqlitePool, user_id: i64) -> anyhow::Result<Vec<FileRow>> {
    let rows = sqlx::query_as::<_, FileRow>(
        "SELECT id, owner_id, token, orig_name, size_bytes, stored_path, password_hash, \
                expires_at, created_at, download_count \
         FROM files WHERE owner_id = ? ORDER BY created_at DESC, id DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn all_files(pool: &SqlitePool) -> anyhow::Result<Vec<FileWithOwner>> {
    let rows = sqlx::query_as::<_, FileWithOwner>(
        "SELECT f.id, f.owner_id, f.token, f.orig_name, f.size_bytes, f.stored_path, \
                f.password_hash, f.expires_at, f.created_at, f.download_count, u.username AS owner_name \
         FROM files f JOIN users u ON u.id = f.owner_id \
         ORDER BY f.created_at DESC, f.id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn delete_file_row(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM files WHERE id = ?").bind(id).execute(pool).await?;
    Ok(())
}

pub async fn delete_files_for_user(pool: &SqlitePool, user_id: i64) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM files WHERE owner_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn bump_download_count(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE files SET download_count = download_count + 1 WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}