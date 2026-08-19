use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub created_at: String,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct Session {
    pub token: String,
    pub user_id: i64,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct FileRow {
    pub id: i64,
    pub owner_id: i64,
    pub token: String,
    pub orig_name: String,
    pub size_bytes: i64,
    pub stored_path: String,
    pub password_hash: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub download_count: i64,
}

#[derive(Debug, Clone, FromRow)]
#[allow(dead_code)]
pub struct FileWithOwner {
    pub id: i64,
    pub owner_id: i64,
    pub token: String,
    pub orig_name: String,
    pub size_bytes: i64,
    pub stored_path: String,
    pub password_hash: Option<String>,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub download_count: i64,
    pub owner_name: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct UserWithCount {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub file_count: i64,
}