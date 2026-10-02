use std::collections::HashMap;

use axum::extract::{Extension, Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use chrono::Utc;
use serde::Deserialize;

use crate::auth::{hash_password_async, CurrentUser};
use crate::db;
use crate::fmt;
use crate::routes::{flash_redirect, html_response, AppError};
use crate::templates::{self, FileView, UserView};
use crate::AppState;

#[derive(Deserialize)]
pub struct CreateUserForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    password: String,
}

#[derive(Deserialize)]
pub struct SettingsForm {
    max_file_size_mb: i64,
}

pub async fn admin_page(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let users = db::all_users(&st.pool).await?;
    let files = db::all_files(&st.pool).await?;
    let max = db::get_setting_i64(&st.pool, "max_file_size_bytes")
        .await?
        .unwrap_or(1 << 30);
    let max_mb = max / (1024 * 1024);
    let base = fmt::base_url(&headers);
    let now = Utc::now();

    let user_views: Vec<UserView> = users.iter().map(|u| UserView::from_row(u, me.id)).collect();
    let file_views: Vec<FileView> = files
        .iter()
        .map(|f| FileView::from_owner_row(f, now, &base))
        .collect();

    let nav = templates::UserNav {
        name: me.username.clone(),
        role: me.role.clone(),
    };
    let err = q.get("err").and_then(|k| fmt::flash_message(k));
    let ok = q.get("ok").and_then(|k| fmt::flash_message(k));
    let html = templates::admin_page(Some(&nav), user_views, file_views, max_mb, err, ok)?;
    Ok(html_response(html))
}

#[inline]
fn redirect_err(key: &str) -> Response {
    flash_redirect("/admin", "err", key)
}

pub async fn create_user(
    State(st): State<AppState>,
    Form(form): Form<CreateUserForm>,
) -> Result<Response, AppError> {
    let username = form.username.trim().to_string();
    if username.is_empty() {
        return Ok(redirect_err("username_required"));
    }
    if form.password.len() < 6 {
        return Ok(redirect_err("password_too_short"));
    }
    if db::user_by_username(&st.pool, &username).await?.is_some() {
        return Ok(redirect_err("username_taken"));
    }
    let hash = hash_password_async(form.password).await?;
    db::create_user(&st.pool, &username, &hash, "user").await?;
    Ok(flash_redirect("/admin", "ok", "user_created"))
}

pub async fn delete_user(
    State(st): State<AppState>,
    Extension(me): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    if id == me.id {
        // An admin shouldn't be able to delete their own account through the
        // UI (they'd lock themselves out); the last admin is protected below.
        return Err(AppError::Forbidden("You cannot delete your own account".into()));
    }
    let target = db::user_by_id(&st.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;
    if target.role == "admin" && db::admin_count(&st.pool).await? <= 1 {
        // Never allow removing the final admin — there must always be a way
        // back into the admin panel.
        return Err(AppError::Forbidden("Cannot delete the last admin".into()));
    }
    // Delete the user's files (DB rows + on-disk files) before the user row,
    // so nothing orphaned is left behind if a later step fails.
    let files = db::files_for_user(&st.pool, id).await?;
    db::delete_files_for_user(&st.pool, id).await?;
    for f in &files {
        let _ = tokio::fs::remove_file(&f.stored_path).await;
    }
    db::delete_sessions_for_user(&st.pool, id).await?;
    db::delete_user(&st.pool, id).await?;
    Ok(flash_redirect("/admin", "ok", "user_deleted"))
}

pub async fn set_password(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<PasswordForm>,
) -> Result<Response, AppError> {
    if form.password.len() < 6 {
        return Ok(redirect_err("password_too_short"));
    }
    let hash = hash_password_async(form.password).await?;
    db::set_user_password(&st.pool, id, &hash).await?;
    // kill all existing sessions for that user
    db::delete_sessions_for_user(&st.pool, id).await?;
    Ok(flash_redirect("/admin", "ok", "password_updated"))
}

pub async fn delete_file(
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let row = db::file_by_id(&st.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".into()))?;
    db::delete_file_row(&st.pool, id).await?;
    let _ = tokio::fs::remove_file(&row.stored_path).await;
    Ok(flash_redirect("/admin", "ok", "file_deleted"))
}

pub async fn settings(
    State(st): State<AppState>,
    Form(form): Form<SettingsForm>,
) -> Result<Response, AppError> {
    let mb = form.max_file_size_mb;
    if mb < 1 {
        return Ok(redirect_err("max_size_too_small"));
    }
    if mb > 1024 * 1024 {
        return Ok(redirect_err("max_size_too_large"));
    }
    let bytes = mb * 1024 * 1024;
    db::set_setting(&st.pool, "max_file_size_bytes", &bytes.to_string()).await?;
    Ok(flash_redirect("/admin", "ok", "settings_saved"))
}