use axum::extract::{Form, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::auth::{gen_token, session_token_from_headers, verify_password_async};
use crate::db;
use crate::routes::{html_response, AppError};
use crate::templates;
use crate::AppState;

// Argon2id hash of a random string, used by `login` to burn the same CPU when a username
// doesn't exist, so timing can't reveal whether an account is registered.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$qVxv2ZLgkBO01+zUceAPfA$6eZYYhK+ymqdyauqNi9ogMqEeXn2PHDcIrP1d2rcvZo";

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

async fn logged_in(st: &AppState, headers: &HeaderMap) -> bool {
    match session_token_from_headers(headers) {
        Some(tok) => db::user_for_session(&st.pool, &tok)
            .await
            .map(|o| o.is_some())
            .unwrap_or(false),
        None => false,
    }
}

pub async fn login_page(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if logged_in(&st, &headers).await {
        return Ok(Redirect::to("/").into_response());
    }
    let html = templates::login_page(None)?;
    Ok(html_response(html))
}

pub async fn login(
    State(st): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let user = db::user_by_username(&st.pool, &form.username).await?;
    // Prevent username-enumeration by timing: when the username doesn't exist
    // we still run an Argon2 verify against a fixed dummy hash, so the response
    // time is the same whether or not the account exists.
    let valid = match &user {
        Some(u) => verify_password_async(form.password.clone(), u.password_hash.clone()).await?,
        None => verify_password_async(form.password.clone(), DUMMY_HASH.to_string()).await?,
    };
    if !valid {
        let html = templates::login_page(Some("Invalid username or password"))?;
        return Ok(html_response(html));
    }
    let user = user.expect("user is Some when valid");
    let token = gen_token(64);
    db::create_session(&st.pool, &token, user.id).await?;
    Ok(crate::auth::redirect_with_session_cookie("/", &token))
}

pub async fn logout(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Clear cookie from DB and client
    if let Some(tok) = session_token_from_headers(&headers) {
        db::delete_session(&st.pool, &tok).await?;
    }
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut()
        .insert(axum::http::header::SET_COOKIE, crate::auth::clear_session_cookie_header());
    Ok(resp)
}