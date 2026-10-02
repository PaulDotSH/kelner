use std::path::Path;
use std::sync::OnceLock;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::extract::{Request, State};
use axum::http::header::{HeaderMap, SET_COOKIE};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use hmac::{Hmac, KeyInit, Mac};
use rand::distr::{Alphanumeric, Distribution};
use rand::Rng;
use sha2::Sha256;
use tokio::sync::Semaphore;

use crate::db;
use crate::fmt;
use crate::AppState;

pub const SESSION_COOKIE: &str = "kelner_session";
pub const GRANT_COOKIE: &str = "kelner_grant";
pub const GRANT_TTL_SECS: i64 = 3600;

/// Whether cookies carry the `Secure` attribute. Set once at startup from the
/// `COOKIE_SECURE` env var; on unless explicitly disabled.
static COOKIE_SECURE: OnceLock<bool> = OnceLock::new();

/// Anything but `0`/`false`/`no`/`off` (or unset) keeps `Secure` on. Only turn it off
/// when serving plain HTTP on a non-localhost address, or browsers will drop the cookie.
pub fn init_cookie_secure(env_value: Option<&str>) {
    let off = env_value.is_some_and(|v| {
        matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off")
    });
    let _ = COOKIE_SECURE.set(!off);
}

#[inline]
fn secure_attr() -> &'static str {
    if *COOKIE_SECURE.get().unwrap_or(&true) { "; Secure" } else { "" }
}

/// Scope the session cookie to the app's own prefix, so other apps on the same
/// host (when served under BASE_PATH) never receive it.
#[inline]
fn session_cookie_path() -> &'static str {
    match fmt::base_path() {
        "" => "/",
        base => base,
    }
}

#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: i64,
    pub username: String,
    pub role: String,
}

#[inline]
pub fn gen_token(len: usize) -> String {
    // Alphanumeric (A-Za-z0-9) keeps tokens URL-safe
    let mut rng = rand::rng();
    Alphanumeric
        .sample_iter(&mut rng)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn hash_password(password: &str) -> Result<String, anyhow::Error> {
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("failed to encode argon2 salt: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::PasswordHash;
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

// Each Argon2 run allocates ~19 MiB. Login and share-unlock are public, so without a cap a
// burst of requests would fan out across the whole blocking pool (512 threads, ~10 GB).
// Extra requests just queue for a permit.
static HASH_PERMITS: Semaphore = Semaphore::const_new(4);

// Argon2 is CPU-heavy; run it on the blocking pool so the runtime never stalls on hashing.
// The permit moves into the blocking task so it's held until hashing actually finishes,
// even if the client disconnects and the request future is dropped.
pub async fn hash_password_async(password: String) -> Result<String, anyhow::Error> {
    let permit = HASH_PERMITS.acquire().await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await?
}

pub async fn verify_password_async(password: String, hash: String) -> Result<bool, anyhow::Error> {
    let permit = HASH_PERMITS.acquire().await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        Ok(verify_password(&password, &hash))
    })
    .await?
}

pub fn load_or_create_secret(path: &Path) -> anyhow::Result<[u8; 32]> {
    // The cookie secret is generated once and persisted to disk so that
    // sessions and signed grant cookies survive restarts
    if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&bytes);
            return Ok(secret);
        }
        anyhow::bail!("secret key file is corrupt (expected 32 bytes): {}", path.display());
    }
    let mut secret = [0u8; 32];
    rand::rng().fill(&mut secret);
    std::fs::write(path, secret)?;
    Ok(secret)
}

#[inline]
pub fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == SESSION_COOKIE {
                let v = v.trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}

#[inline]
pub fn set_session_cookie_header(value: &str) -> HeaderValue {
    // HttpOnly: JS can't read the cookie, so a stored XSS can't steal the session.
    // SameSite=Lax: the cookie is not sent on cross-site requests, mitigating CSRF.
    // Max-Age=604800 (7d): matches the server-side session lifetime.
    // Secure: never sent over plain HTTP (see COOKIE_SECURE).
    let cookie = format!(
        "{}={}; Path={}; HttpOnly; SameSite=Lax; Max-Age=604800{}",
        SESSION_COOKIE,
        value,
        session_cookie_path(),
        secure_attr()
    );
    HeaderValue::from_str(&cookie).expect("session cookie is valid")
}

#[inline]
pub fn clear_session_cookie_header() -> HeaderValue {
    // For logout
    let cookie = format!(
        "{}=; Path={}; HttpOnly; SameSite=Lax; Max-Age=0{}",
        SESSION_COOKIE,
        session_cookie_path(),
        secure_attr()
    );
    HeaderValue::from_str(&cookie).expect("clear cookie is valid")
}

#[inline]
pub fn set_grant_cookie_header(token: &str, signed: &str) -> HeaderValue {
    // The password-grant cookie is scoped to the file's path (Path=/f/{token},
    // prefixed by the base path when served under one) so it only ever
    // accompanies requests for that file. Short-lived (1h), HttpOnly,
    // SameSite=Lax for the same reasons as the session cookie.
    let cookie = format!(
        "{}={}; Path={}/f/{}; HttpOnly; SameSite=Lax; Max-Age={}{}",
        GRANT_COOKIE,
        signed,
        fmt::base_path(),
        token,
        GRANT_TTL_SECS,
        secure_attr()
    );
    HeaderValue::from_str(&cookie).expect("grant cookie is valid")
}

type HmacSha256 = Hmac<Sha256>;

#[inline]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[inline]
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

// Constant-time byte comparison.
// This prevents short circuit when finding a different byte, so we prevent timing attacks
#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[inline]
fn grant_mac(secret: &[u8], payload: &str) -> impl AsRef<[u8]> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes()
}

// The grant is `{token}.{expires_unix}.{hmac}`, an HMAC-SHA256 over `{token}.{expires_unix}`
// keyed with the server's COOKIE_SECRET. The expiry is signed so the grant dies server-side
// too; the cookie's Max-Age alone wouldn't stop a copied value from being replayed forever.
pub fn sign_grant(secret: &[u8], token: &str, expires_unix: i64) -> String {
    let payload = format!("{token}.{expires_unix}");
    let sig = hex_encode(grant_mac(secret, &payload).as_ref());
    format!("{payload}.{sig}")
}

// The token embedded in the value must match the requested file and the
// expiry must be in the future, otherwise the cookie is rejected
pub fn verify_grant(secret: &[u8], cookie_value: &str, token: &str, now_unix: i64) -> bool {
    let Some((payload, sig)) = cookie_value.rsplit_once('.') else {
        return false;
    };
    let Some((t, exp)) = payload.split_once('.') else {
        return false;
    };
    if t != token {
        return false;
    }
    let Ok(exp) = exp.parse::<i64>() else {
        return false;
    };
    if exp <= now_unix {
        return false;
    }
    let Some(sig_bytes) = hex_decode(sig) else {
        return false;
    };
    ct_eq(grant_mac(secret, payload).as_ref(), &sig_bytes)
}

#[inline]
pub fn grant_cookie_valid(headers: &HeaderMap, secret: &[u8], token: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    let Some(cookie) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|c| c.to_str().ok())
    else {
        return false;
    };
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == GRANT_COOKIE && verify_grant(secret, v.trim(), token, now) {
                return true;
            }
        }
    }
    false
}

async fn resolve_session(st: &AppState, headers: &HeaderMap) -> Option<CurrentUser> {
    let token = session_token_from_headers(headers)?;
    let (id, username, role) = db::user_for_session(&st.pool, &token).await.ok()??;
    Some(CurrentUser { id, username, role })
}

// Gate private routes
pub async fn require_auth(
    State(st): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    match resolve_session(&st, req.headers()).await {
        Some(user) => {
            // Store the resolved user in the request extensions to avoid another DB hit
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => Redirect::to(&fmt::join("/login")).into_response(),
    }
}

pub async fn require_admin(
    State(st): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    match resolve_session(&st, req.headers()).await {
        Some(user) if user.role == "admin" => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Some(_) => (StatusCode::FORBIDDEN, "Admins only").into_response(),
        None => Redirect::to(&fmt::join("/login")).into_response(),
    }
}

#[inline]
pub fn redirect_with_session_cookie(location: &str, token: &str) -> Response {
    let mut resp = Redirect::to(location).into_response();
    resp.headers_mut().insert(SET_COOKIE, set_session_cookie_header(token));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn grant_valid_until_expiry() {
        let g = sign_grant(SECRET, "abc", 1000);
        assert!(verify_grant(SECRET, &g, "abc", 999));
        assert!(!verify_grant(SECRET, &g, "abc", 1000));
    }

    #[test]
    fn grant_rejects_other_token_or_secret() {
        let g = sign_grant(SECRET, "abc", 1000);
        assert!(!verify_grant(SECRET, &g, "abd", 0));
        assert!(!verify_grant(b"another secret", &g, "abc", 0));
    }

    #[test]
    fn grant_rejects_tampered_expiry() {
        let g = sign_grant(SECRET, "abc", 1000);
        let forged = g.replacen(".1000.", ".9999.", 1);
        assert!(!verify_grant(SECRET, &forged, "abc", 0));
    }

    #[test]
    fn grant_rejects_legacy_format() {
        // Pre-expiry grants were `{token}.{hmac(token)}`
        let legacy = format!("abc.{}", hex_encode(grant_mac(SECRET, "abc").as_ref()));
        assert!(!verify_grant(SECRET, &legacy, "abc", 0));
    }
}