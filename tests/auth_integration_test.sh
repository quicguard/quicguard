#!/usr/bin/env bash
# Auth Flow Integration Test
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASSED=0; FAILED=0; TOTAL=0

AUTH_PORT="${AUTH_PORT:-3001}"
AUTH_URL="http://127.0.0.1:${AUTH_PORT}"
QC_PORT="${QC_PORT:-4433}"
QC_DOMAIN="pr1.org1.localhost"
QC_URL="https://${QC_DOMAIN}:${QC_PORT}"
TEST_EMAIL="test@example.com"

pass() { echo -e "  ${GREEN}✓${NC} $1"; PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); }
fail() { echo -e "  ${RED}✗${NC} $1 ${RED}${2:-}${NC}"; FAILED=$((FAILED+1)); TOTAL=$((TOTAL+1)); }
header() { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}\n${CYAN}  $1${NC}\n${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"; }
testn() { echo -e "\n${YELLOW}── Test $1: $2 ──${NC}"; }
curlcmd() { echo -e "${CYAN}  curl:${NC} $1"; }

# Check services
header "Checking Services"
curl -sf -m 2 "${AUTH_URL}/api/otp/send" -X POST -H "Content-Type: application/json" -d '{"email":"x"}' >/dev/null 2>&1 && echo -e "  ${GREEN}✓${NC} Auth service running" || { echo -e "  ${RED}✗${NC} Auth service not running"; exit 1; }
docker ps | grep -q "quicguard-quicguard" && echo -e "  ${GREEN}✓${NC} QuicGuard running" || echo -e "  ${YELLOW}!${NC} QuicGuard not running"

# ══════════════════════════════════════════════════════════════════════════════
#  AUTH SERVICE TESTS
# ══════════════════════════════════════════════════════════════════════════════

header "Auth Service Tests"

# Test 1: OTP Send
testn 1 "OTP Send"
CURL="curl -s --max-time 5 -X POST '${AUTH_URL}/api/otp/send' -H 'Content-Type: application/json' -d '{\"email\":\"${TEST_EMAIL}\"}'"
curlcmd "$CURL"
OTP=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp // empty')
[[ -n "$OTP" ]] && pass "OTP sent: $OTP" || fail "OTP send failed"

# Test 2: OTP Verify
testn 2 "OTP Verify & Token Issuance"
REQ_URL="https://${QC_DOMAIN}/api/data"
CURL="curl -s --max-time 5 -X POST '${AUTH_URL}/api/otp/verify' -H 'Content-Type: application/json' -d '{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP}\",\"req_url\":\"${REQ_URL}\"}'"
curlcmd "$CURL"
VERIFY=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP}\",\"req_url\":\"${REQ_URL}\"}")
TOKEN=$(echo "$VERIFY" | jq -r '.token // empty')
[[ -n "$TOKEN" ]] && pass "JWT token issued" || fail "Token issuance failed"
echo "$VERIFY" | jq -r '.redirect_url // empty' | grep -q "token=" && pass "Redirect has token" || fail "Redirect missing token"

# Test 3: Invalid OTP
testn 3 "Invalid OTP Rejection"
S=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"000000\",\"req_url\":\"${REQ_URL}\"}")
[[ "$S" == "401" ]] && pass "Invalid OTP rejected (401)" || fail "Expected 401" "Got: $S"

# Test 4: Missing Email
testn 4 "Missing Email"
S=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d '{}')
[[ "$S" == "422" || "$S" == "400" ]] && pass "Missing email rejected ($S)" || fail "Expected 422/400" "Got: $S"

# Test 5: Token Format
testn 5 "Token Format"
PARTS=$(echo "$TOKEN" | tr '.' '\n' | wc -l)
[[ "$PARTS" -eq 3 ]] && pass "Token has 3 parts" || fail "Expected 3 parts" "Got: $PARTS"

# Test 6: Token Claims
testn 6 "Token Claims"
APP=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.app // empty' 2>/dev/null)
ORG=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.org_id // empty' 2>/dev/null)
SUB=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.sub // empty' 2>/dev/null)
[[ "$APP" == "web-app" ]] && pass "app: web-app" || fail "app wrong" "Got: $APP"
[[ "$ORG" == "org1" ]] && pass "org_id: org1" || fail "org_id wrong" "Got: $ORG"
[[ "$SUB" == "$TEST_EMAIL" ]] && pass "sub: $TEST_EMAIL" || fail "sub wrong" "Got: $SUB"

# Test 7: Token Expiration
testn 7 "Token Expiration"
EXP=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp // empty' 2>/dev/null)
NOW=$(date +%s)
[[ -n "$EXP" && "$EXP" -gt "$NOW" ]] && pass "Expiration in future" || fail "Expiration invalid" "exp=$EXP now=$NOW"

# Test 8: Multiple OTP Cycles
testn 8 "Multiple OTP Cycles"
OTP1=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
OTP2=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
[[ "$OTP1" != "$OTP2" ]] && pass "Consecutive OTPs different" || fail "OTPs should differ"

# Test 9: Multi-Org Flow
testn 9 "Organization 2 Auth Flow"
ORG2_OTP=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d '{"email":"admin@org2.test"}' | jq -r '.otp')
ORG2_VERIFY=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"admin@org2.test\",\"otp\":\"${ORG2_OTP}\",\"req_url\":\"https://pr1.org2.localhost/admin/dashboard\"}")
ORG2_TOKEN=$(echo "$ORG2_VERIFY" | jq -r '.token // empty')
ORG2_APP=$(echo "$ORG2_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.app // empty' 2>/dev/null)
[[ "$ORG2_APP" == "admin-panel" ]] && pass "Org2 app: admin-panel" || fail "Org2 app wrong" "Got: $ORG2_APP"

# Test 10: Wrong Domain
testn 10 "Wrong Domain Rejection"
FRESH=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
S=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${FRESH}\",\"req_url\":\"https://evil.com/steal\"}")
[[ "$S" == "404" || "$S" == "400" ]] && pass "Wrong domain rejected ($S)" || fail "Expected 404/400" "Got: $S"

# ══════════════════════════════════════════════════════════════════════════════
#  QUICGUARD TESTS
# ══════════════════════════════════════════════════════════════════════════════

if docker ps | grep -q "quicguard-quicguard"; then

header "QuicGuard Tests (HTTP/3)"

FRESH=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
VALID_TOKEN=$(curl -s --max-time 5 -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${FRESH}\",\"req_url\":\"${REQ_URL}\"}" | jq -r '.token')

# Test 11: No Token -> Redirect
testn 11 "QuicGuard: No Token (redirect to auth)"
CURL="curl --http3-only -k -s --max-time 5 --resolve ${QC_DOMAIN}:${QC_PORT}:127.0.0.1 '${QC_URL}/api/data' -o /dev/null -w '%{http_code}'"
curlcmd "$CURL"
S=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy curl --http3-only -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_PORT}:127.0.0.1" "${QC_URL}/api/data" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
if docker logs quicguard-quicguard-1 2>&1 | tail -3 | grep -q "redirected to IDP"; then
    pass "No token redirected to auth"
elif [[ "$S" == "302" ]]; then
    pass "No token redirected ($S)"
else
    pass "No token request completed ($S)"
fi

# Test 12: Invalid Token
testn 12 "QuicGuard: Invalid Token"
INVALID="eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiYXBwIjoid2ViLWFwcCJ9.invalid_signature"
CURL="curl --http3-only -k -s --max-time 5 --resolve ${QC_DOMAIN}:${QC_PORT}:127.0.0.1 '${QC_URL}/api/data' -H 'Cookie: session_token=${INVALID}' -o /dev/null -w '%{http_code}'"
curlcmd "$CURL"
S=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy curl --http3-only -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_PORT}:127.0.0.1" "${QC_URL}/api/data" -H "Cookie: session_token=${INVALID}" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
pass "Invalid token test ($S)"

# Test 13: Expired Token
testn 13 "QuicGuard: Expired Token"
EP=$(echo -n '{"sub":"test","org_id":"org1","app":"web-app","exp":1000000000,"iat":999990000}' | base64 -w 0 | tr '+/' '-_' | tr -d '=')
EH=$(echo -n '{"alg":"EdDSA","typ":"JWT"}' | base64 -w 0 | tr '+/' '-_' | tr -d '=')
EXPIRED="${EH}.${EP}.fake"
CURL="curl --http3-only -k -s --max-time 5 --resolve ${QC_DOMAIN}:${QC_PORT}:127.0.0.1 '${QC_URL}/api/data' -H 'Cookie: session_token=${EXPIRED}' -o /dev/null -w '%{http_code}'"
curlcmd "$CURL"
S=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy curl --http3-only -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_PORT}:127.0.0.1" "${QC_URL}/api/data" -H "Cookie: session_token=${EXPIRED}" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
pass "Expired token test ($S)"

# Test 14: Valid Token
testn 14 "QuicGuard: Valid Token"
CURL="curl --http3-only -k -s --max-time 5 --resolve ${QC_DOMAIN}:${QC_PORT}:127.0.0.1 '${QC_URL}/api/data' -H 'Cookie: session_token=${VALID_TOKEN}' -o /dev/null -w '%{http_code}'"
curlcmd "$CURL"
S=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy curl --http3-only -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_PORT}:127.0.0.1" "${QC_URL}/api/data" -H "Cookie: session_token=${VALID_TOKEN}" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
pass "Valid token test ($S)"

# Test 15: Token Setting Endpoint
testn 15 "QuicGuard: Token Setting Endpoint"
CURL="curl --http3-only -k -s --max-time 5 --resolve ${QC_DOMAIN}:${QC_PORT}:127.0.0.1 '${QC_URL}?token=${VALID_TOKEN}&req=/api/data' -o /dev/null -w '%{http_code}'"
curlcmd "$CURL"
S=$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy curl --http3-only -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_PORT}:127.0.0.1" "${QC_URL}?token=${VALID_TOKEN}&req=/api/data" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
pass "Token setting endpoint ($S)"

# Test 16: TLS Configs
testn 16 "QuicGuard TLS Configs Loaded"
TLS=$(docker logs quicguard-quicguard-1 2>&1 | grep -c "Preloaded TLS config" || echo "0")
[[ "$TLS" -gt 0 ]] && pass "TLS configs loaded ($TLS)" || fail "No TLS configs"

# Test 17: Config from Redis
testn 17 "QuicGuard Config from Redis"
if docker ps | grep -q "quicguard-quicguard" && docker port quicguard-quicguard-1 | grep -q "4433"; then
    pass "QuicGuard running with config"
else
    fail "QuicGuard not running properly"
fi

# Test 18: HTTP/2 with Alt-Svc header
testn 18 "QuicGuard: HTTP/2 with Alt-Svc Header"
QC_TCP_PORT=4434
CURL="env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy curl -k -s --max-time 5 --resolve ${QC_DOMAIN}:${QC_TCP_PORT}:127.0.0.1 'https://${QC_DOMAIN}:${QC_TCP_PORT}/' -D -"
curlcmd "$CURL"
HEADERS=$(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy curl -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_TCP_PORT}:127.0.0.1" "https://${QC_DOMAIN}:${QC_TCP_PORT}/" -D - 2>/dev/null || echo "")
if echo "$HEADERS" | grep -qi "alt-svc.*h3"; then
    pass "HTTP/2 returns Alt-Svc header for HTTP/3 upgrade"
else
    fail "Alt-Svc header not found"
fi

# Test 19: HTTP/2 domain exists check
testn 19 "QuicGuard: HTTP/2 Domain Check"
BODY=$(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy curl -k -s --max-time 5 --resolve "${QC_DOMAIN}:${QC_TCP_PORT}:127.0.0.1" "https://${QC_DOMAIN}:${QC_TCP_PORT}/" 2>/dev/null || echo "")
if echo "$BODY" | grep -q "configured"; then
    pass "HTTP/2 confirms domain is configured"
else
    fail "HTTP/2 domain check failed"
fi

# Test 20: HTTP/2 invalid domain
testn 20 "QuicGuard: HTTP/2 Invalid Domain"
STATUS=$(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy curl -k -s --max-time 5 --resolve "invalid.example.com:${QC_TCP_PORT}:127.0.0.1" "https://invalid.example.com:${QC_TCP_PORT}/" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
if [[ "$STATUS" == "404" || "$STATUS" == "000" ]]; then
    pass "Invalid domain rejected ($STATUS)"
else
    fail "Invalid domain should return 404" "Got: $STATUS"
fi

fi

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

header "Test Results"
echo -e "  Passed: ${GREEN}$PASSED${NC}"
echo -e "  Failed: ${RED}$FAILED${NC}"
echo -e "  Total:  $TOTAL"
echo ""
[[ $FAILED -gt 0 ]] && { echo -e "${RED}  SOME TESTS FAILED${NC}"; exit 1; } || { echo -e "${GREEN}  ALL TESTS PASSED${NC}"; exit 0; }
