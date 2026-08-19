use std::fmt::Write as _;

use axum::http::HeaderMap;
use chrono::{DateTime, Duration as ChronoDuration, Utc};

use crate::models::FileRow;

#[inline]
pub fn human_size(bytes: i64) -> String {
    let b = bytes.max(0) as f64;
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = b;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", bytes.max(0))
    } else {
        format!("{:.1} {}", value, units[unit])
    }
}

#[inline]
pub fn window_label(created: &str, expires: &str) -> String {
    let Ok(c) = DateTime::parse_from_rfc3339(created) else { return "30d".into() };
    let Ok(e) = DateTime::parse_from_rfc3339(expires) else { return "30d".into() };
    let d = e - c; // chrono::TimeDelta
    // midpoints between consecutive presets: 10m/1h/1d/7d/30d
    if d <= ChronoDuration::minutes(35) {
        "10m".into()
    } else if d <= ChronoDuration::hours(12) + ChronoDuration::minutes(30) {
        "1h".into()
    } else if d <= ChronoDuration::days(4) {
        "1d".into()
    } else if d <= ChronoDuration::days(18) + ChronoDuration::hours(12) {
        "7d".into()
    } else {
        "30d".into()
    }
}

#[inline]
pub fn remaining_label(now: DateTime<Utc>, expires: &str) -> String {
    let Ok(e) = DateTime::parse_from_rfc3339(expires) else { return "—".into() };
    let e = e.with_timezone(&Utc);
    let left = (e - now).max(ChronoDuration::zero());
    if left < ChronoDuration::minutes(1) {
        format!("{}s left", left.num_seconds())
    } else if left < ChronoDuration::hours(1) {
        format!("{}m left", left.num_minutes())
    } else if left < ChronoDuration::days(1) {
        format!("{}h left", left.num_hours())
    } else {
        format!("{}d left", left.num_days())
    }
}

#[inline]
pub fn expires_line(expires: &str) -> String {
    match DateTime::parse_from_rfc3339(expires) {
        Ok(e) => format!("Expires {}", e.with_timezone(&Utc).format("%b %d")),
        Err(_) => "Expires unknown".into(),
    }
}

#[inline]
pub fn is_expired(row: &FileRow, now: DateTime<Utc>) -> bool {
    is_expired_ts(now, row.expires_at.as_deref())
}

#[inline]
pub fn is_expired_ts(now: DateTime<Utc>, expires_at: Option<&str>) -> bool {
    expires_at
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc) <= now)
        .unwrap_or(false)
}

/// Urgent when less than a fifth of the window remains.
#[inline]
pub fn is_urgent(now: DateTime<Utc>, created: &str, expires: &str) -> bool {
    let Ok(c) = DateTime::parse_from_rfc3339(created) else { return false };
    let Ok(e) = DateTime::parse_from_rfc3339(expires) else { return false };
    let c = c.with_timezone(&Utc);
    let e = e.with_timezone(&Utc);
    let total = (e - c).num_seconds().max(1);
    let left = (e - now).num_seconds().max(0);
    left < total / 5
}

#[inline]
fn ext_of(name: &str) -> &str {
    name.rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or("")
}

#[inline]
pub fn is_previewable(name: &str) -> bool {
    match ext_of(name).to_ascii_lowercase().as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "pdf" => true,
        _ => false,
    }
}

#[inline]
pub fn preview_kind(name: &str) -> &'static str {
    if ext_of(name).eq_ignore_ascii_case("pdf") {
        "pdf"
    } else {
        "img"
    }
}

// This is what AI was made for thank god
#[inline]
pub fn content_type(name: &str) -> &'static str {
    match ext_of(name).to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "json" => "application/json",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "7z" => "application/x-7z-compressed",
        _ => "application/octet-stream",
    }
}

/// RFC 5987 percent-encoding for the `filename*` parameter.
#[inline]
fn rfc5987_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => out.push(b as char),
            b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[inline]
pub fn content_disposition(name: &str, inline: bool) -> String {
    let disposition = if inline { "inline" } else { "attachment" };
    let safe = name
        .chars()
        .filter(|c| !matches!(c, '"' | '\\' | '\n' | '\r'))
        .collect::<String>();
    let ascii = safe.chars().all(|c| c.is_ascii());
    if ascii {
        format!("{disposition}; filename=\"{safe}\"")
    } else {
        format!(
            "{disposition}; filename=\"{safe}\"; filename*=UTF-8''{}",
            rfc5987_encode(name)
        )
    }
}

#[inline]
pub fn base_url(headers: &HeaderMap) -> String {
    // Reconstruct the external URL for share links. x-forwarded-proto is set
    // by the reverse proxy in front of kelner; we trust the first value since
    // the app is expected to run behind one. HOST is the domain the client
    // actually used, so links work regardless of which hostname is configured.
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("http").trim().to_string())
        .unwrap_or_else(|| "http".to_string());
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();
    format!("{scheme}://{host}")
}

/// Percent-encode a value for safe use in a query string.
///
/// Delegates to `form_urlencoded` (already in the dependency tree via axum's
/// Query/Form parsing) so our encode side is guaranteed to match the decode
/// side: spaces become '+', everything non-unreserved is %XX-escaped.
#[inline]
pub fn qenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[inline]
pub fn expiry_preset_duration(preset: &str) -> ChronoDuration {
    match preset {
        "10m" => ChronoDuration::minutes(10),
        "1h" => ChronoDuration::hours(1),
        "1d" => ChronoDuration::days(1),
        "7d" => ChronoDuration::days(7),
        _ => ChronoDuration::days(30),
    }
}