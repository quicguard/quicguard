# konfig — Configuration & Request Validation

Runtime configuration loaded from Redis with per-organization policies, JWT authentication via cookies, and domain-based routing.

## How It Works

```
Client Request
      │
      ▼
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│ Extract Host │────▶│ Lookup Org   │────▶│ Check for     │
│   header     │     │   by domain  │     │ ?token= param │
└─────────────┘     └──────────────┘     └───────┬───────┘
                                                  │
                                          ┌───────┴───────┐
                                          │               │
                                     Has token      No token
                                     in query       in query
                                          │               │
                                          ▼               ▼
                                  ┌──────────────┐ ┌──────────────┐
                                  │ Set-Cookie   │ │ Extract from │
                                  │ & redirect   │ │ Cookie       │
                                  └──────┬───────┘ └──────┬───────┘
                                         │                │
                                         ▼                ▼
                                    302 clean URL   ┌───────────────┐
                                                    │ Validate JWT  │
                                                    │ (iss, aud,    │
                                                    │  exp)         │
                                                    └───────┬───────┘
                                                            │
                                                    ┌───────┴───────┐
                                                    │               │
                                                 Valid          Invalid/
                                                    │           Expired
                                                    ▼               │
                                           ┌───────────────┐       │
                                           │ Evaluate      │       │
                                           │ Policies      │       │
                                           └───────┬───────┘       │
                                                   │               │
                                           ┌───────┴───────┐       │
                                           │               │     302 to
                                         ALLOW           DENY    IDP URL
                                           │               │
                                           ▼               ▼
                                      Proxy to         403 Forbidden
                                      upstream
```

## Redis Data Model

Organizations are stored in a Redis hash. Each field is an org ID mapping to a JSON document:

```
HSET quicguard:organizations "org-demo" '{ "id": "org-demo", ... }'
```

Live updates are pushed via Redis pubsub on the configured channel.

## Organization Config Schema

```json
{
    "id": "org-demo",
    "name": "Demo Corp",
    "domains": ["demo.localhost"],
    "policies": [
        {
            "id": "allow-read",
            "name": "Allow reading",
            "rules": [
                {
                    "resource": {"Prefix": "/api/"},
                    "methods": ["GET", "HEAD"],
                    "conditions": []
                }
            ],
            "effect": "Allow"
        }
    ],
    "domain_policies": {
        "app.demo.localhost": [
            {
                "id": "app-deny-delete",
                "name": "Deny DELETE on app subdomain",
                "rules": [
                    {
                        "resource": {"Prefix": "/"},
                        "methods": ["DELETE"],
                        "conditions": []
                    }
                ],
                "effect": "Deny"
            }
        ]
    },
    "upstream": {
        "base_url": "http://127.0.0.1:1025",
        "timeout_ms": 5000,
        "max_retries": 3
    },
    "auth": {
        "jwt_issuer": "https://auth.quicguard.dev",
        "jwt_audience": "quicguard-proxy",
        "jwt_public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----",
        "cookie_name": "session_token",
        "redirect_url": "https://auth.quicguard.dev/login",
        "idp_url": "https://auth.quicguard.dev/idp"
    },
    "tls": {
        "demo.localhost": {
            "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
        }
    }
}
```

### Key Fields

| Field | Description |
|---|---|
| `domains` | List of domain names this org handles. Host header is matched against these. |
| `policies` | Global policies applied when no domain-specific policy matches. |
| `domain_policies` | Per-domain policies that override the global ones. |
| `auth.cookie_name` | Name of the HTTP cookie containing the JWT token. |
| `auth.jwt_issuer` | Expected `iss` claim in the JWT. |
| `auth.jwt_audience` | Expected `aud` claim in the JWT. |
| `auth.jwt_public_key` | PEM-encoded Ed25519 public key for JWT signature verification (EdDSA). |
| `auth.idp_url` | Identity Provider URL. Users are redirected here when no token, or token is invalid/expired. Falls back to `redirect_url` if empty. |
| `tls` | Per-domain TLS certificates. Map of domain → `{cert_pem, key_pem}`. Used for QUIC server TLS. If empty, falls back to `--cert`/`--key` CLI args. |
| `upstream.base_url` | Backend URL requests are proxied to. |

### Policy Rules

- **Resource patterns**: `Exact("/api/v1")`, `Prefix("/api/")`, `Glob("/api/*/users/*")`
- **Methods**: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`
- **Conditions** (optional): Match on JWT claims — `Equals`, `NotEquals`, `In`, `NotIn`, `Contains`, `StartsWith`
- **Effect**: `Allow` or `Deny`. Deny takes precedence.

## Quick Start

### 1. Seed Redis

```bash
cd konfig
./scripts/seed-redis.sh
```

This creates a sample org with:
- **Domain**: `demo.localhost`
- **Upstream**: `http://127.0.0.1:1025`
- **Policies**: Allow GET/HEAD on `/api/*`, deny writes on `/api/admin/*`

### 2. Start a backend on port 1025

```bash
python3 -m http.server 1025
```

### 3. Start the quicguard server

```bash
cargo run --bin server -- \
  --redis-url redis://127.0.0.1:6379 \
  --listen 0.0.0.0:4433
```

### 4. Test with curl

The seed script generates a sample JWT. Use it like this:

```bash
# ── Generate a test JWT ──────────────────────────────────────────────────
# Using the jwt-gen binary (Ed25519, iss='https://auth.quicguard.dev', aud='quicguard-proxy'):
TOKEN=$(cargo run -p konfig --bin jwt-gen -- private.pem "https://auth.quicguard.dev" "quicguard-proxy")

# Or generate directly with openssl + the binary:
openssl genpkey -algorithm Ed25519 -out private.pem
cargo run -p konfig --bin jwt-gen -- private.pem "https://auth.quicguard.dev" "quicguard-proxy"

# ── Allowed: GET /api/users with valid token ─────────────────────────────
curl -v \
  --resolve "demo.localhost:4433:127.0.0.1" \
  --cookie "session_token=$TOKEN" \
  "https://demo.localhost:4433/api/users"
# Expected: 200 OK (proxied to 127.0.0.1:1025)

# ── Denied: missing token (expect 302 redirect to IDP) ─────────────────────
curl -v \
  --resolve "demo.localhost:4433:127.0.0.1" \
  "https://demo.localhost:4433/api/users"
# Expected: 302 Found, Location: https://auth.quicguard.dev/idp?redirect_uri=...

# ── Denied: DELETE on /api/admin/* (expect 403) ─────────────────────────
curl -v \
  --resolve "demo.localhost:4433:127.0.0.1" \
  --cookie "session_token=$TOKEN" \
  -X DELETE \
  "https://demo.localhost:4433/api/admin/users"
# Expected: 403 Forbidden

# ── Denied: POST on /api/admin/* (expect 403) ──────────────────────────
curl -v \
  --resolve "demo.localhost:4433:127.0.0.1" \
  --cookie "session_token=$TOKEN" \
  -X POST \
  -d '{"name":"test"}' \
  "https://demo.localhost:4433/api/admin/config"
# Expected: 403 Forbidden

# ── Denied: unknown domain (expect 404) ─────────────────────────────────
curl -v \
  --resolve "unknown.localhost:4433:127.0.0.1" \
  --cookie "session_token=$TOKEN" \
  "https://unknown.localhost:4433/api/users"
# Expected: 404 Not Found
```

## Running Tests

```bash
# All konfig tests (unit + integration)
cargo test -p konfig

# Just integration tests
cargo test -p konfig --test integration_tests
```

The integration tests verify:
- Cookie parsing (single, multiple, whitespace, empty, custom names)
- Domain lookup (found, not found, reload, remove, multiple orgs)
- JWT validation (valid, wrong key, wrong issuer, malformed, empty)
- Policy evaluation (allow/deny by method and path)
- Full flow: cookie → domain → JWT → policy decision

## Server CLI Options

```
--redis-url           Redis URL (default: redis://127.0.0.1:6379)
--redis-org-key       Redis hash key for org configs (default: quicguard:organizations)
--redis-pubsub-channel  Redis pubsub channel (default: quicguard:updates)
--redirect-url        Redirect URL for unauthenticated requests
--idp-url             Identity Provider URL for auth redirects (per-customer)
```

> **Note:** JWT auth settings and per-domain TLS certificates are configured per-organization
> in Redis, not via CLI arguments. See the Organization Config Schema above.
