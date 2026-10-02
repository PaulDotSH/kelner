use std::io::SeekFrom;

use axum::extract::{Form, Path, State};
use axum::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, RANGE, REFERRER_POLICY, SET_COOKIE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::auth::{
    grant_cookie_valid, set_grant_cookie_header, sign_grant, verify_password_async, GRANT_TTL_SECS,
};
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
        return Ok(Redirect::to(&fmt::join(&format!("/f/{token}/dl"))).into_response());
    };
    if verify_password_async(form.password, hash.clone()).await? {
        // Correct password returns a signed path-scoped cookie so the
        // browser is authorized to download for the next hour without asking
        // again. We sign it (HMAC) to avoid storing state
        let signed = sign_grant(&st.cookie_secret, &token, Utc::now().timestamp() + GRANT_TTL_SECS);
        let mut resp = Redirect::to(&fmt::join(&format!("/f/{token}/dl"))).into_response();
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

/// A single satisfiable byte range (`start` and `end` are inclusive).
struct ByteRange {
    start: u64,
    end: u64,
}

/// Result of parsing the `Range` header for a file of `size` bytes.
enum RangeResult {
    /// No usable range (absent header, malformed, or multipart) -> serve full 200.
    None,
    /// A single satisfiable range -> serve 206.
    Satisfiable(ByteRange),
    /// Range starts past the end of the file (or empty file) -> serve 416.
    Unsatisfiable,
}

fn parse_range(headers: &HeaderMap, size: u64) -> RangeResult {
    let Some(value) = headers.get(RANGE).and_then(|v| v.to_str().ok()) else {
        return RangeResult::None;
    };
    let Some(rest) = value.trim().strip_prefix("bytes=") else {
        return RangeResult::None;
    };
    // Multipart ranges are not supported; ignoring the header and serving the
    // full file is always a valid response per RFC 7233.
    if rest.contains(',') {
        return RangeResult::None;
    }
    let Some((s, e)) = rest.split_once('-') else {
        return RangeResult::None;
    };
    let s = s.trim();
    let e = e.trim();
    if s.is_empty() {
        // Suffix form `bytes=-N`: the last N bytes.
        if size == 0 {
            return RangeResult::Unsatisfiable;
        }
        let n: u64 = match e.parse() {
            Ok(n) if n > 0 => n,
            _ => return RangeResult::Unsatisfiable,
        };
        let start = size.saturating_sub(n);
        return RangeResult::Satisfiable(ByteRange { start, end: size - 1 });
    }
    let start: u64 = match s.parse() {
        Ok(v) => v,
        Err(_) => return RangeResult::None,
    };
    if start >= size {
        return RangeResult::Unsatisfiable;
    }
    let end = if e.is_empty() {
        size - 1
    } else {
        match e.parse::<u64>() {
            Ok(v) => v.min(size - 1),
            Err(_) => return RangeResult::None,
        }
    };
    if end < start {
        return RangeResult::Unsatisfiable;
    }
    RangeResult::Satisfiable(ByteRange { start, end })
}

pub async fn share_download(
    State(st): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let row = load_file(&st, &token).await?;

    if row.password_hash.is_some() && !grant_cookie_valid(&headers, &st.cookie_secret, &token) {
        return Ok(Redirect::to(&fmt::join(&format!("/f/{token}"))).into_response());
    }

    let total = row.size_bytes.max(0) as u64;
    let range = parse_range(&headers, total);

    // Unsatisfiable range: 416 with the full size advertised so the client can
    // retry with a valid offset.
    if let RangeResult::Unsatisfiable = range {
        let mut resp = Response::new(axum::body::Body::empty());
        *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
        resp.headers_mut().insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes */{total}")).expect("valid content-range"),
        );
        resp.headers_mut()
            .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        return Ok(resp);
    }

    let file = tokio::fs::File::open(std::path::Path::new(&row.stored_path))
        .await
        .map_err(|_| AppError::NotFound("File is missing from disk".into()))?;

    // Build the body, length, and status according to whether a range applies.
    // ReaderStream::with_capacity uses a 64KB buffer (vs the 8KB default) so
    // large files are copied in 8x fewer syscalls.
    let (body, content_length, status, content_range) =
        if let RangeResult::Satisfiable(r) = range {
            let mut f = file;
            f.seek(SeekFrom::Start(r.start))
                .await
                .map_err(|_| AppError::NotFound("File is missing from disk".into()))?;
            let limited = f.take(r.end - r.start + 1);
            let body = axum::body::Body::from_stream(ReaderStream::with_capacity(limited, 64 * 1024));
            (
                body,
                r.end - r.start + 1,
                StatusCode::PARTIAL_CONTENT,
                Some(format!("bytes {}-{}/{}", r.start, r.end, total)),
            )
        } else {
            let body = axum::body::Body::from_stream(ReaderStream::with_capacity(file, 64 * 1024));
            (body, total, StatusCode::OK, None)
        };

    let inline = fmt::is_previewable(&row.orig_name);
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    // ACCEPT_RANGES advertises that byte ranges are supported, which browsers
    // and download managers use for resume and seeking.
    resp.headers_mut()
        .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    // CONTENT_TYPE: the browser uses this to pick a renderer, taken from file extension
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_str(fmt::content_type(&row.orig_name)).expect("valid content type"),
    );
    // CONTENT_LENGTH: lets the browser show an accurate download progress bar
    // and lets the client detect a truncated transfer early. For partial
    // responses it is the length of the range, not the whole file.
    resp.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).expect("valid content length"),
    );
    if let Some(cr) = content_range {
        resp.headers_mut().insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&cr).expect("valid content-range"),
        );
    }
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
    // The URL is the capability: a link clicked inside a previewed PDF must not
    // leak it to a third-party site via Referer.
    resp.headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    // CSP: only our own share page may frame the file (PDF preview iframe).
    // Everything except PDFs is also sandboxed (no scripts, opaque origin), so
    // even if something ever got rendered as a document it can't act as us.
    // PDFs can't be sandboxed: Chrome refuses to load its viewer in a sandbox.
    let csp = if fmt::preview_kind(&row.orig_name) == "pdf" {
        "frame-ancestors 'self'"
    } else {
        "default-src 'none'; sandbox; frame-ancestors 'self'"
    };
    resp.headers_mut()
        .insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(csp));

    db::bump_download_count(&st.pool, row.id).await?;
    Ok(resp)
}