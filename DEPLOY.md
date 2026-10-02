# Deploying kelner behind Caddy

kelner listens on plain HTTP on localhost and expects a reverse proxy in front
of it for TLS and rate limiting. This guide uses [Caddy](https://caddyserver.com),
which handles TLS certificates automatically.

## 1. Run kelner

Build it with `cargo build --release`, then run it as a service. Example systemd unit
(`/etc/systemd/system/kelner.service`):

```ini
[Unit]
Description=kelner file sharing
After=network.target

[Service]
User=kelner
WorkingDirectory=/var/lib/kelner
ExecStart=/usr/local/bin/kelner
Environment=DATA_DIR=/var/lib/kelner/data
Environment=BIND_ADDR=127.0.0.1:9111
# Only when serving under a path prefix (see "Subdomain vs. path prefix")
# Environment=BASE_PATH=/s/kelner
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Keep `BIND_ADDR` on `127.0.0.1` so the only way in is through Caddy.

Cookies are sent with the `Secure` flag by default, so the site must be reached
over HTTPS. Caddy gives you HTTPS automatically. Set `COOKIE_SECURE=false` only
when testing over plain HTTP on an address other than localhost.

## 2. Build Caddy with the rate-limit plugin

kelner has two public endpoints that check passwords, and both need rate
limiting:

| Endpoint          | What an attacker gets by brute-forcing it |
|-------------------|-------------------------------------------|
| `POST /login`     | An account, possibly the admin account.   |
| `POST /f/{token}` | A password-protected file. File passwords have no minimum length, so short ones fall quickly. |

kelner already limits how many password hashes run at once, so a flood of
requests can't exhaust memory. That cap doesn't stop a slow, steady
password-guessing attack, though. Per-IP rate limiting is the proxy's job.

Stock Caddy has no rate limiter. Build Caddy with
[`caddy-ratelimit`](https://github.com/mholt/caddy-ratelimit) using `xcaddy`:

```sh
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/mholt/caddy-ratelimit
sudo mv caddy /usr/bin/caddy
```

## 3. Caddyfile

### On its own subdomain (recommended)

```caddyfile
{
	# rate_limit is a plugin directive, so Caddy needs to be told where it
	# runs relative to the built-in ones.
	order rate_limit before basic_auth
}

files.example.com {
	rate_limit {
		# Password checks: login and unlocking a protected share link.
		# 10 attempts per minute per client IP; over that gets 429 + Retry-After.
		zone passwords {
			match {
				method POST
				path /login /f/*
			}
			key {client_ip}
			events 10
			window 1m
		}
	}

	# Optional: cap request size at the proxy too (kelner enforces its own
	# admin-configured limit while streaming).
	# request_body {
	# 	max_size 2GB
	# }

	reverse_proxy 127.0.0.1:9111
}
```

### Under a path prefix

Set `BASE_PATH=/s/kelner` on kelner and proxy the prefix **without stripping
it**, since kelner's routes already include it:

```caddyfile
{
	order rate_limit before basic_auth
}

example.com {
	rate_limit {
		zone kelner_passwords {
			match {
				method POST
				path /s/kelner/login /s/kelner/f/*
			}
			key {client_ip}
			events 10
			window 1m
		}
	}

	handle /s/kelner* {
		reverse_proxy 127.0.0.1:9111
	}

	# ... other sites/apps on example.com
}
```

## Subdomain vs. path prefix

Use a subdomain if you can. Under a path prefix, kelner shares an **origin**
with everything else on that host. kelner scopes its cookies to its own prefix,
so other apps never receive them. But the browser's same-origin policy doesn't
look at paths: an XSS bug in *any* other app on `example.com` can make
authenticated requests to `/s/kelner/admin` and read the responses. A separate
subdomain puts kelner in its own origin and removes that exposure.

## Notes

- **Share links:** kelner builds share URLs from the `Host` and
  `X-Forwarded-Proto` headers. Caddy forwards the original `Host` and sets
  `X-Forwarded-Proto` by default, so no extra config is needed.
- **Behind a CDN or another proxy** (e.g. Cloudflare in front of Caddy): set
  [`trusted_proxies`](https://caddyserver.com/docs/caddyfile/options#trusted-proxies)
  in Caddy's global options. Otherwise `{client_ip}` is the CDN's address, and
  everyone shares one rate-limit bucket.
- **Large uploads:** Caddy streams request bodies to kelner and has no body
  size limit or read/write timeouts by default, so large uploads work as-is.
  If you add `timeouts` under the `servers` global option, leave `read_body`
  long enough for your biggest upload.
- **Data directory:** `DATA_DIR` holds `secret.key`, which signs cookies, and
  the SQLite database. Make it readable only by the `kelner` user
  (`chmod 700`).
