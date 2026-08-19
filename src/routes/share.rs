use axum::extract::{Form, Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use serde::Deserialize;
use tokio_util::io::ReaderStream;

use crate::auth::{grant_cookie_valid, set_grant_cookie_header, sign_grant, verify_password_async};
use crate::db;
use crate::fmt;
use crate::models::FileRow;
use crate::routes::{html_response, AppError};
use crate::templates::{self, FileShareView};
use crate::AppState;

#[derive(Deserialize)]
pub struct PasswordForm {
    password: String,
}

async fn load_file(st: &AppState, token: &str) -> Result<FileRow, AppError> {
    let row = db::file_by_token(&st.pool, token)
        .await?
        .ok_or_else(|| AppError::NotFound("This link does not exist.".into()))?;
    if fmt::is_expired(&row, Utc::now()) {
        // Expired links are removed on access and on sweep
        // so a dead link is cleaned up the moment anyone
        // tries to use it.
        purge_file(st, &row).await;
        return Err(AppError::Gone);
    }
    Ok(row)
}

async fn purge_file(st: &AppState, row: &FileRow) {
    // DB row first, then the file on disk. Failure to remove shouldn't happen and is ignored
    let _ = db::delete_file_row(&st.pool, row.id).await;
    let _ = tokio::fs::remove_file(&row.stored_path).await;
}

pub async fn share_page(
    State(st): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let row = load_file(&st, &token).await?;
    let granted = grant_cookie_valid(&headers, &st.cookie_secret, &token);
    // `granted` (access) tells the template whether to show the password form or the
    // download UI.
    let view = FileShareView::from_row(&row, Utc::now(), granted);
    let html = templates::share_page(view, None, granted)?;
    Ok(html_response(html))
}

pub async fn share_password(
    State(st): State<AppState>,
    Path(token): Path<String>,
    Form(form): Form<PasswordForm>,
) -> Result<Response, AppError> {
    let row = load_file(&st, &token).await?;
    let Some(hash) = &row.password_hash else {
        return Ok(Redirect::to(&format!("/f/{token}/dl")).into_response());
    };
    if verify_password_async(form.password, hash.clone()).await? {
        // Correct password returns a signed path-scoped cookie so the
        // browser is authorized to download for the next hour without asking
        // again. We sign it (HMAC) to avoid storing state
        let signed = sign_grant(&st.cookie_secret, &token);
        let mut resp = Redirect::to(&format!("/f/{token}/dl")).into_response();
        resp.headers_mut()
            .insert(SET_COOKIE, set_grant_cookie_header(&token, &signed));
        Ok(resp)
    } else {
        let granted = false;
        let view = FileShareView::from_row(&row, Utc::now(), granted);
        let html = templates::share_page(view, Some("Incorrect password. Try again."), granted)?;
        Ok(html_response(html))
    }
}

pub async fn share_download(
    State(st): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let row = load_file(&st, &token).await?;

    if row.password_hash.is_some() && !grant_cookie_valid(&headers, &st.cookie_secret, &token) {
        return Ok(Redirect::to(&format!("/f/{token}")).into_response());
    }

    let file = tokio::fs::File::open(std::path::Path::new(&row.stored_path))
        .await
        .map_err(|_| AppError::NotFound("File is missing from disk".into()))?;
    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let inline = fmt::is_previewable(&row.orig_name);
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::OK;
    // CONTENT_TYPE: the browser uses this to pick a renderer, taken from file extension
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(fmt::content_type(&row.orig_name)).expect("valid content type"),
    );
    // CONTENT_LENGTH: lets the browser show an accurate download progress bar
    // and lets the client detect a truncated transfer early. We use the size
    // we recorded at upload time
    resp.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&row.size_bytes.to_string()).expect("valid content length"),
    );
    // Content-Disposition controls whether the browser renders or forces a download
    resp.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&fmt::content_disposition(&row.orig_name, inline))
            .expect("valid disposition"),
    );
    // X-Content-Type-Options: without this a file we label
    // image/png but which actually contains HTML could be executed as HTML in
    // the origin's context (stored XSS).
    resp.headers_mut()
        .insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    // no-store: never cache share downloads.
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));

    db::bump_download_count(&st.pool, row.id).await?;
    Ok(resp)
}