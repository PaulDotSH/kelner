use std::collections::HashMap;

use axum::extract::{Extension, Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::auth::{gen_token, hash_password_async, CurrentUser};
use crate::db;
use crate::fmt;
use crate::routes::{html_response, AppError};
use crate::templates::{self, FileView};
use crate::AppState;

pub async fn dashboard() -> Response {
    Redirect::to("/files").into_response()
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
    let err = q.get("err").map(String::as_str);
    let ok = q.get("ok").map(String::as_str);
    let html = templates::files_page(Some(&nav), files, err, ok, max_mb)?;
    Ok(html_response(html))
}

pub async fn upload(
    State(st): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    let max_size = db::get_setting_i64(&st.pool, "max_file_size_bytes")
        .await?
        .unwrap_or(1 << 30);

    let mut file_meta: Option<(String, String, i64)> = None; // (token, orig_name, size)
    let mut exp = "30d".to_string();
    let mut password: Option<String> = None;

    while let Some(field) = multipart
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
                let token = gen_token(32);
                // Prevent guessing
                let rel = format!("uploads/{token}");
                let path = st.data_dir.join(&rel);
                let mut out = tokio::fs::File::create(&path).await?;

                let mut stream = field;
                let mut size: i64 = 0;
                let mut exceeded = false;
                // Stream chunks to disk instead of in memory buffer
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|e| AppError::BadRequest(e.to_string()))?;
                    size += chunk.len() as i64;
                    if size > max_size {
                        exceeded = true;
                        break;
                    }
                    out.write_all(&chunk).await?;
                }
                out.flush().await?;
                drop(out);

                if exceeded {
                    // Delete the partial file and return 413.
                    let _ = tokio::fs::remove_file(&path).await;
                    return Err(AppError::TooLarge);
                }
                file_meta = Some((token, fname, size));
            }
            "exp" => {
                if let Ok(t) = field.text().await {
                    exp = t;
                }
            }
            "password" => {
                if let Ok(t) = field.text().await {
                    if !t.is_empty() {
                        password = Some(t);
                    }
                }
            }
            _ => {}
        }
    }

    let Some((token, orig_name, size)) = file_meta else {
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
    let rel = format!("uploads/{token}");
    // Absolute path. The sweeper and download route read this back
    // so it must be consistent no matter the CWD.
    let stored_path = st.data_dir.join(&rel).to_string_lossy().to_string();

    db::insert_file(
        &st.pool,
        user.id,
        &token,
        &orig_name,
        size,
        &stored_path,
        pass_hash.as_deref(),
        Some(&expires_s),
        &created,
    )
    .await?;

    Ok(Redirect::to(&format!("/files?ok={}", fmt::qenc("File uploaded"))).into_response())
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
    Ok(Redirect::to(&format!("/files?ok={}", fmt::qenc("File deleted"))).into_response())
}