use std::collections::HashMap;
use std::path::PathBuf;

use axum::extract::multipart::Field;
use axum::extract::{Extension, Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use tokio::io::AsyncWriteExt;

use crate::auth::{gen_token, hash_password_async, CurrentUser};
use crate::db;
use crate::fmt;
use crate::routes::{flash_redirect, html_response, AppError};
use crate::templates::{self, FileView};
use crate::AppState;

// The upload route has no body limit (the file is streamed to disk), so the
// small text fields next to it are read with an explicit cap instead.
const MAX_EXP_FIELD: usize = 16;
const MAX_PASSWORD_FIELD: usize = 1024;

pub async fn dashboard() -> Response {
    Redirect::to(&fmt::join("/files")).into_response()
}

pub async fn files_page(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let rows = db::files_for_user(&st.pool, user.id).await?;
    let base = fmt::base_url(&headers);
    let now = Utc::now();
    let files: Vec<FileView> = rows
        .iter()
        .map(|r| FileView::from_row(r, now, &base))
        .collect();
    let nav = templates::UserNav {
        name: user.username.clone(),
        role: user.role.clone(),
    };
    let max = db::get_setting_i64(&st.pool, "max_file_size_bytes")
        .await?
        .unwrap_or(1 << 30);
    let max_mb = max / (1024 * 1024);
    let err = q.get("err").and_then(|k| fmt::flash_message(k));
    let ok = q.get("ok").and_then(|k| fmt::flash_message(k));
    let html = templates::files_page(Some(&nav), files, err, ok, max_mb)?;
    Ok(html_response(html))
}

/// A file written to disk but not yet recorded in the DB. Dropping it deletes
/// the file unless `keep` was set, so every failure path (size limit, client
/// disconnect, bad field, DB error, cancelled request) cleans up after itself.
struct PendingUpload {
    path: PathBuf,
    token: String,
    orig_name: String,
    size: i64,
    keep: bool,
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn small_text(mut field: Field<'_>, max: usize) -> Result<String, AppError> {
    let mut buf = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| AppError::BadRequest(e.body_text()))?
    {
        if buf.len() + chunk.len() > max {
            return Err(AppError::BadRequest("Form field is too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| AppError::BadRequest("Form field is not valid UTF-8".into()))
}

pub async fn upload(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let max_size = db::get_setting_i64(&st.pool, "max_file_size_bytes")
        .await?
        .unwrap_or(1 << 30);

    let mut upload: Option<PendingUpload> = None;
    let mut exp = "30d".to_string();
    let mut password: Option<String> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(e.body_text()))?
    {
        match field.name().unwrap_or("") {
            "file" => {
                let fname = match field.file_name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                if fname.is_empty() {
                    continue;
                }
                // Only one file is ever recorded; a second would be written
                // to disk with no DB row pointing at it.
                if upload.is_some() {
                    return Err(AppError::BadRequest("Only one file per upload".into()));
                }
                // Prevent guessing
                let token = gen_token(32);
                // Absolute path. The sweeper and download route read this back
                // so it must be consistent no matter the CWD.
                let path = st.data_dir.join(format!("uploads/{token}"));
                let mut out = tokio::fs::File::create(&path).await?;
                let pending = upload.insert(PendingUpload {
                    path,
                    token,
                    orig_name: fname,
                    size: 0,
                    keep: false,
                });

                // Stream chunks to disk instead of in memory buffer
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|e| AppError::BadRequest(e.body_text()))?
                {
                    pending.size += chunk.len() as i64;
                    if pending.size > max_size {
                        // `out` is closed before `upload` drops and deletes the file.
                        return Err(AppError::TooLarge);
                    }
                    out.write_all(&chunk).await?;
                }
                out.flush().await?;
            }
            "exp" => exp = small_text(field, MAX_EXP_FIELD).await?,
            "password" => {
                let t = small_text(field, MAX_PASSWORD_FIELD).await?;
                if !t.is_empty() {
                    password = Some(t);
                }
            }
            _ => {}
        }
    }

    let Some(mut upload) = upload else {
        return Err(AppError::BadRequest("No file selected".into()));
    };

    let now = Utc::now();
    // Map the UI's preset selector ("10m", "1h", ...) to a duration; Fallback to 30d
    let expires_at = now + fmt::expiry_preset_duration(&exp);
    let pass_hash = match password {
        Some(p) => Some(hash_password_async(p).await?),
        None => None,
    };
    let created = now.to_rfc3339();
    let expires_s = expires_at.to_rfc3339();
    let stored_path = upload.path.to_string_lossy().to_string();

    db::insert_file(
        &st.pool,
        user.id,
        &upload.token,
        &upload.orig_name,
        upload.size,
        &stored_path,
        pass_hash.as_deref(),
        Some(&expires_s),
        &created,
    )
    .await?;
    upload.keep = true;

    Ok(flash_redirect("/files", "ok", "file_uploaded"))
}

pub async fn delete_file(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let row = db::file_by_id(&st.pool, id)
        .await?
        .ok_or_else(|| AppError::NotFound("File not found".into()))?;
    if row.owner_id != user.id && user.role != "admin" {
        return Err(AppError::Forbidden(
            "You can only delete your own files".into(),
        ));
    }
    db::delete_file_row(&st.pool, id).await?;
    let _ = tokio::fs::remove_file(&row.stored_path).await;
    Ok(flash_redirect("/files", "ok", "file_deleted"))
}
