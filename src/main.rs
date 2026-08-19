mod auth;
mod db;
mod fmt;
mod models;
mod routes;
mod templates;

use std::path::PathBuf;
use std::time::Duration;

use sqlx::SqlitePool;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub data_dir: PathBuf,
    pub cookie_secret: [u8; 32],
}

/// On a fresh install (zero users), create the default admin account so the
/// platform is usable immediately. Username/password come from the optional
/// ADMIN_USERNAME / ADMIN_PASSWORD env vars, defaulting to `admin` / `admin`.
/// The admin can change their password from the admin panel after logging in.
async fn seed_default_admin(pool: &SqlitePool) -> anyhow::Result<()> {
    if db::admin_count(pool).await? > 0 {
        return Ok(());
    }
    let username = std::env::var("ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
    let password = std::env::var("ADMIN_PASSWORD").unwrap_or_else(|_| "admin".into());
    if username.is_empty() || password.is_empty() {
        return Ok(());
    }
    let hash = auth::hash_password_async(password).await?;
    db::create_user(pool, &username, &hash, "admin").await?;
    tracing::info!("created default admin user '{username}'");
    Ok(())
}

// Two worker threads: enough to overlap two streaming transfers in parallel
// without the background footprint of a full multi-core runtime. Argon2 hashing
// is already offloaded to the blocking pool, so 2 workers is plenty here.
#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let data_dir = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".into()));
    std::fs::create_dir_all(data_dir.join("uploads"))?;

    let pool = db::init_pool(&data_dir.join("kelner.db")).await?;
    let cookie_secret = auth::load_or_create_secret(&data_dir.join("secret.key"))?;

    seed_default_admin(&pool).await?;

    let state = AppState {
        pool,
        data_dir,
        cookie_secret,
    };

    spawn_sweeper(state.clone());

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:9111".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("kelner listening on http://{bind} (data dir: {})", state.data_dir.display());

    let app = routes::router(state);
    axum::serve(listener, app).await?;
    Ok(())
}

// every 60s delete expired file rows + their files.
fn spawn_sweeper(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = chrono::Utc::now().to_rfc3339();
            let paths = match sqlx::query_scalar::<_, String>(
                "DELETE FROM files WHERE expires_at IS NOT NULL AND expires_at <= ? RETURNING stored_path",
            )
            .bind(&now)
            .fetch_all(&state.pool)
            .await
            {
                Ok(paths) => paths,
                Err(e) => {
                    tracing::warn!("sweeper error: {e}");
                    continue;
                }
            };
            if !paths.is_empty() {
                tracing::info!("sweeper purged {} expired file(s)", paths.len());
                for p in paths {
                    let _ = tokio::fs::remove_file(&p).await;
                }
            }

            // Expired sessions are only deleted on logout/password reset, so
            // this sweep keeps the table bounded.
            match sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
                .bind(&now)
                .execute(&state.pool)
                .await
            {
                Ok(res) if res.rows_affected() > 0 => {
                    tracing::info!("sweeper purged {} expired session(s)", res.rows_affected());
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("sweeper session purge error: {e}"),
            }
        }
    });
}