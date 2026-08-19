mod admin;
mod auth;
mod files;
mod share;

use axum::extract::DefaultBodyLimit;
use axum::http::header::{HeaderValue, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::auth::{require_admin, require_auth};
use crate::fmt;
use crate::templates;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/login", get(auth::login_page).post(auth::login))
        .route("/f/{token}", get(share::share_page).post(share::share_password))
        .route("/f/{token}/dl", get(share::share_download))
        .route("/static/style.css", get(static_css));

    // DefaultBodyLimit::disable() because we stream the upload and enforce the size
    // limit in code (files.rs::upload) so we can abort cleanly on overflow.
    let private = Router::new()
        .route("/", get(files::dashboard))
        .route("/logout", post(auth::logout))
        .route("/files", get(files::files_page))
        .route("/upload", post(files::upload))
        .route("/files/{id}/delete", post(files::delete_file))
        .layer(DefaultBodyLimit::disable())
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let admin = Router::new()
        .route("/", get(admin::admin_page))
        .route("/files/{id}/delete", post(admin::delete_file))
        .route("/users", post(admin::create_user))
        .route("/users/{id}/delete", post(admin::delete_user))
        .route("/users/{id}/password", post(admin::set_password))
        .route("/settings", post(admin::settings))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin));

    // Router<AppState>, state NOT applied yet — it must be applied once, at the
    // end, so the whole tree (including the outer base-path nest) shares it.
    let app = public
        .merge(private)
        .nest("/admin", admin);

    // Mount everything under the base path (e.g. /s/kelner) when configured.
    // When empty, serve at the domain root.
    if fmt::base_path().is_empty() {
        app.with_state(state)
    } else {
        Router::new().nest(fmt::base_path(), app).with_state(state)
    }
}

async fn static_css() -> impl IntoResponse {
    // CSS is compiled into the binary (include_str!) so there's no extra file
    // to deploy. CACHE_CONTROL instead of refetch on every load
    let css = include_str!("../../static/style.css");
    (
        [
            (CONTENT_TYPE, "text/css; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        css,
    )
}

// Wrap a rendered HTML page in a text/html response.
#[inline]
pub fn html_response(html: String) -> Response {
    let mut resp = Response::new(html.into());
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    resp
}

#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    Gone,
    BadRequest(String),
    Forbidden(String),
    TooLarge,
    Internal(anyhow::Error),
}

// Crazy use of emojis
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, icon, title, message) = match &self {
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, "🕳️", "Not found", m.as_str()),
            AppError::Gone => (
                StatusCode::GONE,
                "⏳",
                "Link expired",
                "This link has expired and is gone.",
            ),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "⚠️", "Bad request", m.as_str()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, "🔒", "Forbidden", m.as_str()),
            AppError::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "🛑",
                "Too large",
                "The upload exceeds the maximum allowed size.",
            ),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "💥",
                    "Server error",
                    "Something went wrong. Please try again.",
                )
            }
        };
        let body = templates::render_msg_page(icon, title, message).unwrap_or_else(|_| title.to_string());
        html_response(body).with_status(status)
    }
}

trait WithStatus {
    fn with_status(self, status: StatusCode) -> Response;
}

impl WithStatus for Response {
    #[inline]
    fn with_status(mut self, status: StatusCode) -> Response {
        *self.status_mut() = status;
        self
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.into())
    }
}