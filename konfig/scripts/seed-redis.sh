#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# seed-redis.sh — Populate Redis with a sample QuicGuard organization config
#
# Usage:
#   ./scripts/seed-redis.sh                  # seed with defaults
#   ./scripts/seed-redis.sh --flush          # flush and re-seed
#   REDIS_URL=redis://:pass@host:6379 ./scripts/seed-redis.sh
# ──────────────────────────────────────────────────────────────────────────────

REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"
ORG_KEY="${ORG_KEY:-quicguard:organizations}"
PUBSUB_CHANNEL="${PUBSUB_CHANNEL:-quicguard:updates}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Check Redis ──────────────────────────────────────────────────────────────
command -v redis-cli &>/dev/null || fail "redis-cli not found. Install Redis tools."
redis-cli -u "$REDIS_URL" ping &>/dev/null || fail "Cannot connect to Redis at $REDIS_URL"
info "Connected to Redis at $REDIS_URL"

# ── Optional flush ───────────────────────────────────────────────────────────
if [[ "${1:-}" == "--flush" ]]; then
    redis-cli -u "$REDIS_URL" DEL "$ORG_KEY" &>/dev/null
    info "Flushed key $ORG_KEY"
fi

# ── Sample organization config ───────────────────────────────────────────────
# Domain: demo.localhost
# Upstream: 127.0.0.1:1025 (local dev server)
# Cookie name: session_token
# Policies:
#   - Allow GET/HEAD on /api/*
#   - Deny DELETE on /api/admin/*
#   - Deny POST/PUT/PATCH on /api/admin/*

# Generate Ed25519 keypair for JWT signing
JWT_KEY_DIR=$(mktemp -d)
trap "rm -rf $JWT_KEY_DIR" EXIT
openssl genpkey -algorithm Ed25519 -out "$JWT_KEY_DIR/private.pem" 2>/dev/null
openssl pkey -in "$JWT_KEY_DIR/private.pem" -pubout -out "$JWT_KEY_DIR/public.pem" 2>/dev/null
JWT_PRIVATE_KEY=$(cat "$JWT_KEY_DIR/private.pem")
JWT_PUBLIC_KEY=$(cat "$JWT_KEY_DIR/public.pem")

ORG_JSON=$(cat <<EOF
{
    "id": "org-demo",
    "name": "Demo Corp",
    "domains": ["demo.localhost", "app.demo.localhost"],
    "policies": [
        {
            "id": "allow-read",
            "name": "Allow reading API resources",
            "rules": [
                {
                    "resource": {"Prefix": "/api/"},
                    "methods": ["GET", "HEAD"],
                    "conditions": []
                }
            ],
            "effect": "Allow"
        },
        {
            "id": "deny-admin-write",
            "name": "Deny write operations on admin endpoints",
            "rules": [
                {
                    "resource": {"Prefix": "/api/admin/"},
                    "methods": ["POST", "PUT", "PATCH", "DELETE"],
                    "conditions": []
                }
            ],
            "effect": "Deny"
        }
    ],
    "domain_policies": {
        "app.demo.localhost": [
            {
                "id": "app-deny-delete",
                "name": "Deny all DELETE on app subdomain",
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
        "jwt_public_key": "$(echo "$JWT_PUBLIC_KEY" | sed ':a;N;$!ba;s/\n/\\n/g')",
        "cookie_name": "session_token",
        "redirect_url": "https://auth.quicguard.dev/login",
        "idp_url": "https://auth.quicguard.dev/idp"
    }
}
EOF
)

redis-cli -u "$REDIS_URL" HSET "$ORG_KEY" "org-demo" "$ORG_JSON" &>/dev/null
ok "Seeded organization org-demo (demo.localhost -> 127.0.0.1:1025)"

# ── Generate a sample JWT for testing ────────────────────────────────────────
JWT_PAYLOAD=$(cargo run -p konfig --bin jwt-gen -- "$JWT_KEY_DIR/private.pem" "https://auth.quicguard.dev" "quicguard-proxy" "user-001" "org-demo" 2>/dev/null || echo "")

if [[ -n "$JWT_PAYLOAD" ]]; then
    ok "Generated sample Ed25519-signed JWT (expires in 1h)"
else
    info "Failed to generate JWT via jwt-gen binary"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GREEN}Redis seeded successfully${NC}"
echo ""
echo "  Domain:     demo.localhost"
echo "  Upstream:   http://127.0.0.1:1025"
echo "  JWT algo:   EdDSA (Ed25519, asymmetric)"
echo "  JWT issuer: https://auth.quicguard.dev"
echo "  JWT aud:    quicguard-proxy"
echo "  Cookie:     session_token"
echo "  IDP URL:    https://auth.quicguard.dev/idp"
echo ""
echo "  Policies:"
echo "    GET/HEAD  /api/*              -> ALLOW"
echo "    POST/PUT/PATCH/DELETE /api/admin/* -> DENY"
echo "    DELETE / (app.demo.localhost)  -> DENY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ -n "$JWT_PAYLOAD" ]]; then
echo "  Quick test with curl:"
echo ""
echo "  # Start a backend on 127.0.0.1:1025 (e.g. python3 -m http.server 1025)"
echo "  # Start quicguard server:"
echo "  cargo run --bin server -- \\"
echo "    --redis-url $REDIS_URL \\"
echo "    --jwt-issuer https://auth.quicguard.dev \\"
echo "    --jwt-audience quicguard-proxy \\"
echo "    --jwt-public-key /path/to/public.pem \\"
echo "    --cookie-name session_token \\"
echo "    --idp-url https://auth.quicguard.dev/idp"
echo ""
echo "  # Then test with:"
echo "TOKEN=$JWT_PAYLOAD"
echo 'curl -v --http3-only -k --resolve "demo.localhost:4433:127.0.0.1" \'
echo '    --cookie "session_token=$TOKEN" \'
echo '    "https://demo.localhost:4433/api/users"'
echo ""
echo "  # Without token (expect 302 redirect to IDP):"
echo 'curl -v --http3-only -k --resolve "demo.localhost:4433:127.0.0.1" \'
echo '    "https://demo.localhost:4433/api/users"'
echo ""
echo "  # DELETE on admin (expect 403):"
echo 'curl -v --http3-only -k --resolve "demo.localhost:4433:127.0.0.1" \'
echo '    --cookie "session_token=$TOKEN" \'
echo '    -X DELETE "https://demo.localhost:4433/api/admin/users"'
fi
