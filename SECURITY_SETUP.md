# Security V1 Setup

## 1) Set admin password hash (recommended)
Generate a hash:

```bash
python3 - <<'PY'
from werkzeug.security import generate_password_hash
print(generate_password_hash("PUT_STRONG_PASSWORD_HERE"))
PY
```

Put it in environment:

```bash
SGEST_ADMIN_PASSWORD_HASH=pbkdf2:sha256:...
```

## 2) Set strong app secret

```bash
python3 - <<'PY'
import secrets
print(secrets.token_hex(64))
PY
```

Use output as `SGEST_SECRET_KEY`.

## 3) Enable HTTPS mode
- Set reverse proxy/TLS.
- Then set:

```bash
SGEST_COOKIE_SECURE=1
```

## 4) Protect webhooks
Set token:

```bash
SGEST_REQUIRE_WEBHOOK_TOKEN=1
SGEST_WEBHOOK_TOKEN=YOUR_RANDOM_TOKEN
```

Send token from Etsy/Vinted webhook as:
- `X-Webhook-Token: YOUR_RANDOM_TOKEN`
or
- `Authorization: Bearer YOUR_RANDOM_TOKEN`

## 5) Optional host allowlist

```bash
SGEST_ALLOWED_HOSTS=stock.example.com
```

## 6) Default credentials warning
If no admin password env is set, app fallback is:
- user: `admin`
- pass: `change-me-now`

Change it immediately before public exposure.
