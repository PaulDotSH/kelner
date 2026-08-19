# kelner

A self-hosted, lightweight file-sharing service with expiring links and optional
password protection. Upload a file, get a link, and the file disappears
when the link expires

Built with Rust, axum, SQLite (via sqlx), and sailfish templates. Everything is
packaged into a single binary plus a data directory.
This is meant to be used behind nginx or something similar so you could gate the login if needed (rate limiting etc)

## AI Usage
This README and some of the code was AI generated, with all the AI generated parts being reviewed by me
This isn't meant as a project that should "get big", this is what I will use on my personal server

## Features

- Upload files with a pickable expiry window: **10m, 1h, 1d, 7d, 30d**.
- Optional per-file password protection.
- Public share links (`/f/{token}`) that don't require a login to download.
- Inline preview for images and PDFs when the file is unprotected or unlocked.
- Accounts with role-based access (`user` / `admin`).
- Admin panel: manage users, reset passwords, delete any file, configure the
  max upload size.
- Expired files are purged automatically by a background sweeper (and lazily on
  access), so dead links clean themselves up.
- Download counter per file.

## Quick start

Requires a Rust toolchain (edition 2024).

```sh
cargo build --release
DATA_DIR=./data BIND_ADDR=127.0.0.1:9111 ./target/release/kelner
```

On a fresh install (zero admins in the DB) a default admin account is seeded
automatically:

| Env var           | Default  | Purpose                                        |
|-------------------|----------|------------------------------------------------|
| `ADMIN_USERNAME`  | `admin`  | Username of the bootstrap admin account.       |
| `ADMIN_PASSWORD`  | `admin`  | Password of the bootstrap admin account.       |
| `DATA_DIR`        | `./data` | Where the SQLite DB, secret key, and uploads live. |
| `BIND_ADDR`       | `127.0.0.1:9111` | Socket address to listen on.           |

> The default credentials are `admin` / `admin`. **Change the password from the
> admin panel after first login.** The bootstrap admin is only created when
> there are no admins yet, so existing installs are never affected.

Log in at `http://127.0.0.1:9111/login`, upload a file, and copy its share link.

## Configuration

All runtime configuration is via environment variables (see table above). The
max upload size is stored in the `settings` table and editable from the admin
panel (`/admin`); it defaults to 1 GiB and is clamped to `[1 MB, 1 TiB]`.

## Architecture

### Request routing

Routes are layered into three groups in `src/routes/mod.rs`:

1. **`public`** - no session required: `/login`, the share page `/f/{token}`,
   the download route `/f/{token}/dl`, and the compiled-in stylesheet.
2. **`private`** - mounted under `/` behind `require_auth`: `/files`, `/upload`,
   file deletion. The upload route **disables `DefaultBodyLimit`** because the
   size cap is enforced in code during streaming (`src/routes/files.rs`), which
   lets us abort cleanly with a 413 and delete the partial file.
3. **`admin`** - nested under `/admin` behind `require_admin` (session required
   *and* role must be `admin`).

Middleware resolves the session once and stashes the `CurrentUser` in the
request extensions; handlers read it back with `Extension<CurrentUser>` instead
of re-querying the DB.

### Authentication & sessions

- Passwords are hashed with **Argon2id** (`src/auth.rs`). Hashing runs on the
  blocking pool (`spawn_blocking`) so the single-threaded runtime never stalls.
- Login issues a random 32-char alphanumeric token, stores it in the `sessions`
  table (7-day expiry), and sets the `kelner_session` cookie. Every request
  re-validates the token against the DB; expired sessions are rejected in SQL
  (`expires_at > now`) so no code path can forget the check.
- The cookie is `HttpOnly` (JS can't steal it, mitigating stored XSS),
  `SameSite=Lax` (not sent cross-site, mitigating CSRF), and `Max-Age=604800`
  to match the server-side lifetime. Logout deletes the DB row *and* clears the
  cookie, so the token is dead server-side even if the browser still sends it.
- The cookie HMAC secret is generated once, persisted to `data/secret.key`
  (32 bytes / 256 bits), and reused across restarts so sessions survive.

### Password-protected files (signed grant cookies)

Instead of storing "who unlocked which file" server-side, kelner mints a
**stateless grant**: an HMAC-SHA256 signature over the file token, keyed with
the cookie secret (`sign_grant` in `src/auth.rs`).

- Set as the `kelner_grant` cookie, scoped to `Path=/f/{token}` so it only ever
  travels with requests for that one file.
- Short-lived (1h) and `HttpOnly` / `SameSite=Lax` for the same reasons as the
  session cookie.
- The embedded token must match the requested file (`verify_grant`), so a grant
  for one file can't be replayed on another.
- Signatures are compared with a **constant-time** comparison (`ct_eq`): a
  naive `==` leaks, via timing, how many leading bytes match, which would let an
  attacker recover the expected HMAC byte-by-byte.
- If the cookie secret ever leaks, the 1h lifetime bounds the exposure.

### File lifecycle & expiry

- Uploaded files are streamed to `{data_dir}/uploads/{token}` where the token
  is a random 24-char alphanumeric string - the on-disk name can never collide
  or be attacker-chosen (no path traversal, no overwriting). The original name
  is kept only in the DB row.
- The **absolute** path is stored in the `files.stored_path` column so the
  sweeper and download route work regardless of the process CWD.
- Expiry is enforced in three places:
  1. **Access time**: `load_file` rejects expired files with a 410 Gone and
     purges them lazily on the spot.
  2. **Background sweeper** (`spawn_sweeper` in `src/main.rs`): every 60s,
     `DELETE ... RETURNING stored_path` removes expired rows and their files,
     so expired data disappears even if nobody ever hits the link.
  3. **Admin/user delete**: DB row removed first, then the on-disk file
     (best-effort).

### Downloads & response headers

`/f/{token}/dl` streams the file with headers chosen deliberately
(`src/routes/share.rs`):

| Header                   | Why                                                                  |
|--------------------------|----------------------------------------------------------------------|
| `Content-Type`           | The browser picks a renderer (image viewer, PDF plugin, text) from it; derived from the file extension. |
| `Content-Length`         | Accurate progress bar + early detection of truncated transfers; uses the size recorded at upload. |
| `Content-Disposition`    | `inline` for previewable files (images/PDFs), `attachment` otherwise - controls whether the browser renders or downloads. |
| `X-Content-Type-Options: nosniff` | Stops MIME sniffing. Without it, a file we label `image/png` but which actually contains HTML could be executed as HTML in the origin's context (stored XSS). Share URLs are public and attacker-controlled, so this matters. |
| `Cache-Control: no-store` | Share links are meant to expire and be revocable - neither the browser nor any intermediary cache should keep a copy that outlives the link. |

### Security

- Argon2id password hashing; timing-safe login (an unknown username still runs
  the verify against a dummy so response times don't leak whether the account
  exists).
- Constant-time HMAC comparison for grant cookies.
- `HttpOnly` + `SameSite=Lax` cookies everywhere.
- `nosniff` + `no-store` on downloads.
- Admins cannot delete their own account, and the **last admin** can never be
  removed - there is always a way back into the panel.
- Resetting a user's password kills all of that user's existing sessions.

## Data model

```
users(id, username UNIQUE, password_hash, role, created_at)
sessions(token UNIQUE, user_id, created_at, expires_at)
files(id, owner_id, token UNIQUE, orig_name, size_bytes, stored_path,
      password_hash NULL, expires_at NULL, created_at, download_count)
settings(key PK, value)
```

Defined in `migrations/0001_init.sql`, applied automatically at startup via
sqlx's `Migrator`.

## Project layout

```
src/
  main.rs          # startup, config, admin seeding, background sweeper
  auth.rs          # hashing, session/grant cookies, middleware, HMAC signing
  db.rs            # all SQLite access
  fmt.rs           # display helpers (sizes, expiry labels, content types, base_url, qenc)
  models.rs        # row types
  templates.rs     # sailfish template structs + render helpers
  routes/
    mod.rs         # router composition, AppError -> HTTP responses
    auth.rs        # login / logout
    files.rs       # dashboard, upload, delete own file
    share.rs       # public share page, unlock, download
    admin.rs       # user/file/settings admin endpoints
templates/         # .stpl templates (layout, login, files, share, admin, msg)
static/style.css   # compiled into the binary
migrations/        # SQL migrations
```