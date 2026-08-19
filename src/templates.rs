use chrono::Utc;
use sailfish::TemplateSimple as _;
use sailfish_minify::TemplateSimple;

use crate::fmt;
use crate::models::{FileRow, FileWithOwner, UserWithCount};

pub struct UserNav {
    pub name: String,
    pub role: String,
}

pub struct FileView {
    pub id: i64,
    pub name: String,
    pub size: String,
    pub window: String,
    pub remaining: String,
    pub expiry_class: String,
    pub expired: bool,
    pub downloads: i64,
    pub url: String,
    pub owner: String,
}

impl FileView {
    pub fn from_row(row: &FileRow, now: chrono::DateTime<Utc>, base: &str) -> Self {
        let expired = fmt::is_expired(row, now);
        let remaining = if expired {
            String::new()
        } else {
            fmt::remaining_label(now, row.expires_at.as_deref().unwrap_or(""))
        };
        let window = row
            .expires_at
            .as_deref()
            .map(|e| fmt::window_label(&row.created_at, e))
            .unwrap_or_else(|| "30d".into());
        let urgent = !expired
            && row
                .expires_at
                .as_deref()
                .map(|e| fmt::is_urgent(now, &row.created_at, e))
                .unwrap_or(false);
        let expiry_class = if urgent { "expiry urgent".into() } else { "expiry".into() };
        Self {
            id: row.id,
            name: row.orig_name.clone(),
            size: fmt::human_size(row.size_bytes),
            window,
            remaining,
            expiry_class,
            expired,
            downloads: row.download_count,
            url: format!("{base}/f/{}", row.token),
            owner: String::new(),
        }
    }

    pub fn from_owner_row(row: &FileWithOwner, now: chrono::DateTime<Utc>, base: &str) -> Self {
        let expired = fmt::is_expired_ts(now, row.expires_at.as_deref());
        let remaining = if expired {
            String::new()
        } else {
            fmt::remaining_label(now, row.expires_at.as_deref().unwrap_or(""))
        };
        let window = row
            .expires_at
            .as_deref()
            .map(|e| fmt::window_label(&row.created_at, e))
            .unwrap_or_else(|| "30d".into());
        let urgent = !expired
            && row
                .expires_at
                .as_deref()
                .map(|e| fmt::is_urgent(now, &row.created_at, e))
                .unwrap_or(false);
        let expiry_class = if urgent { "expiry urgent".into() } else { "expiry".into() };
        Self {
            id: row.id,
            name: row.orig_name.clone(),
            size: fmt::human_size(row.size_bytes),
            window,
            remaining,
            expiry_class,
            expired,
            downloads: row.download_count,
            url: format!("{base}/f/{}", row.token),
            owner: row.owner_name.clone(),
        }
    }
}

pub struct FileShareView {
    pub token: String,
    pub name: String,
    pub size: String,
    pub window: String,
    pub remaining: String,
    pub expires_line: String,
    pub icon: &'static str,
    pub is_preview: bool,
    pub preview_kind: &'static str,
    pub show_preview: bool,
    pub password_protected: bool,
    pub expired: bool,
}

impl FileShareView {
    pub fn from_row(row: &FileRow, now: chrono::DateTime<Utc>, granted: bool) -> Self {
        let expired = fmt::is_expired(row, now);
        let is_preview = fmt::is_previewable(&row.orig_name);
        let password_protected = row.password_hash.is_some();
        let remaining = if expired {
            String::new()
        } else {
            fmt::remaining_label(now, row.expires_at.as_deref().unwrap_or(""))
        };
        let window = row
            .expires_at
            .as_deref()
            .map(|e| fmt::window_label(&row.created_at, e))
            .unwrap_or_else(|| "30d".into());
        let icon = match fmt::preview_kind(&row.orig_name) {
            "pdf" => "📄",
            "img" => "🖼️",
            _ => "📄",
        };
        Self {
            token: row.token.clone(),
            name: row.orig_name.clone(),
            size: fmt::human_size(row.size_bytes),
            window,
            remaining,
            expires_line: row
                .expires_at
                .as_deref()
                .map(fmt::expires_line)
                .unwrap_or_else(|| "Never expires".into()),
            icon,
            is_preview,
            preview_kind: fmt::preview_kind(&row.orig_name),
            show_preview: is_preview && (!password_protected || granted),
            password_protected,
            expired,
        }
    }
}

pub struct UserView {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub badge_class: String,
    pub file_count: i64,
    pub is_self: bool,
}

impl UserView {
    pub fn from_row(row: &UserWithCount, self_id: i64) -> Self {
        let is_admin = row.role == "admin";
        Self {
            id: row.id,
            name: row.username.clone(),
            role: row.role.clone(),
            badge_class: if is_admin { "badge-admin" } else { "badge-user" }.into(),
            file_count: row.file_count,
            is_self: row.id == self_id,
        }
    }
}

#[derive(TemplateSimple)]
#[template(path = "layout.stpl")]
pub struct Layout<'a> {
    pub title: &'a str,
    pub user: Option<&'a UserNav>,
    pub content: &'a str,
}

#[derive(TemplateSimple)]
#[template(path = "login.stpl")]
pub struct LoginPage<'a> {
    pub error: Option<&'a str>,
}

#[derive(TemplateSimple)]
#[template(path = "files.stpl")]
pub struct FilesPage<'a> {
    pub files: Vec<FileView>,
    pub err: Option<&'a str>,
    pub ok: Option<&'a str>,
    pub max_size_mb: i64,
}

#[derive(TemplateSimple)]
#[template(path = "share.stpl")]
pub struct SharePage<'a> {
    pub file: FileShareView,
    pub error: Option<&'a str>,
    pub granted: bool,
}

#[derive(TemplateSimple)]
#[template(path = "admin.stpl")]
pub struct AdminPage<'a> {
    pub users: Vec<UserView>,
    pub files: Vec<FileView>,
    pub max_size_mb: i64,
    pub err: Option<&'a str>,
    pub ok: Option<&'a str>,
}

#[derive(TemplateSimple)]
#[template(path = "msg.stpl")]
pub struct MsgPage<'a> {
    pub icon: &'a str,
    pub title: &'a str,
    pub message: &'a str,
}

pub fn render_page(title: &str, user: Option<&UserNav>, content: String) -> Result<String, anyhow::Error> {
    let layout = Layout { title, user, content: &content };
    Ok(layout.render_once().map_err(|e| anyhow::anyhow!("template error: {e}"))?)
}

pub fn render_msg_page(icon: &str, title: &str, message: &str) -> Result<String, anyhow::Error> {
    let msg = MsgPage { icon, title, message };
    let content = msg
        .render_once()
        .map_err(|e| anyhow::anyhow!("template error: {e}"))?;
    render_page(title, None, content)
}

fn tpl_anyhow<T>(r: Result<T, sailfish::runtime::RenderError>) -> anyhow::Result<T> {
    r.map_err(|e| anyhow::anyhow!("template error: {e}"))
}

pub fn login_page(error: Option<&str>) -> anyhow::Result<String> {
    let p = LoginPage { error };
    let content = tpl_anyhow(p.render_once())?;
    render_page("Sign in", None, content)
}

pub fn files_page(
    user: Option<&UserNav>,
    files: Vec<FileView>,
    err: Option<&str>,
    ok: Option<&str>,
    max_size_mb: i64,
) -> anyhow::Result<String> {
    let p = FilesPage { files, err, ok, max_size_mb };
    let content = tpl_anyhow(p.render_once())?;
    render_page("My files", user, content)
}

pub fn share_page(file: FileShareView, error: Option<&str>, granted: bool) -> anyhow::Result<String> {
    let p = SharePage { file, error, granted };
    let content = tpl_anyhow(p.render_once())?;
    render_page("kelner", None, content)
}

pub fn admin_page(
    user: Option<&UserNav>,
    users: Vec<UserView>,
    files: Vec<FileView>,
    max_size_mb: i64,
    err: Option<&str>,
    ok: Option<&str>,
) -> anyhow::Result<String> {
    let p = AdminPage { users, files, max_size_mb, err, ok };
    let content = tpl_anyhow(p.render_once())?;
    render_page("Admin", user, content)
}