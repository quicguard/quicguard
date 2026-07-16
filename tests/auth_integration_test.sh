#!/usr/bin/env bash
#
# QuicGuard Auth Flow Integration Test
#
# Tests the complete authentication flow for QuicGuard.
# Run with: ./tests/auth_integration_test.sh
#
# Options:
#   -h, --help     Show help
#   -v, --verbose  Show verbose output
#

set -euo pipefail

AUTH_PORT="${AUTH_PORT:-3001}"
AUTH_URL="http://127.0.0.1:${AUTH_PORT}"
TEST_EMAIL="test@example.com"
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) head -10 "$0"; exit 0 ;;
        -v|--verbose) VERBOSE=true; shift ;;
        *) shift ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASSED=0; FAILED=0; TOTAL=0

print_header() { echo ""; echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"; }
print_test() { echo ""; echo -e "${YELLOW}── Test $1: $2 ──${NC}"; }
print_curl() { echo -e "${CYAN}  curl command:${NC}"; echo -e "    $1"; echo ""; }
pass() { echo -e "  ${GREEN}✓${NC} $1"; PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; [[ -n "${2:-}" ]] && echo -e "    ${RED}$2${NC}"; FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); }

# ── Check auth service ───────────────────────────────────────────────────

print_header "Checking Services"
if curl -sf -m 2 "$AUTH_URL/api/otp/send" -X POST -H "Content-Type: application/json" -d '{"email":"check"}' >/dev/null 2>&1 || \
   curl -sf -m 2 -o /dev/null -w "%{http_code}" "$AUTH_URL/api/otp/send" -X POST -H "Content-Type: application/json" -d '{"email":"check"}' 2>/dev/null | grep -qE '^[2-4]'; then
    echo -e "${GREEN}✓${NC} Auth service is running"
else
    echo -e "${RED}✗${NC} Auth service not running on port $AUTH_PORT"
    exit 1
fi

# ── Tests ────────────────────────────────────────────────────────────────

print_header "Auth Flow Integration Tests"

# Test 1: OTP Send
print_test 1 "OTP Send"
CURL_CMD="curl -s -X POST '${AUTH_URL}/api/otp/send' -H 'Content-Type: application/json' -d '{\"email\":\"${TEST_EMAIL}\"}'"
print_curl "$CURL_CMD"
OTP_RESPONSE=$(curl -s -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}")
OTP_CODE=$(echo "$OTP_RESPONSE" | jq -r '.otp // empty')
[[ -n "$OTP_CODE" ]] && pass "OTP sent successfully (code: $OTP_CODE)" || fail "OTP send failed" "Response: $OTP_RESPONSE"

# Test 2: OTP Verify
print_test 2 "OTP Verify and Token Issuance"
REQ_URL="https://pr1.org1.localhost/api/data"
CURL_CMD="curl -s -X POST '${AUTH_URL}/api/otp/verify' -H 'Content-Type: application/json' -d '{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP_CODE}\",\"req_url\":\"${REQ_URL}\"}'"
print_curl "$CURL_CMD"
VERIFY_RESPONSE=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP_CODE}\",\"req_url\":\"${REQ_URL}\"}")
TOKEN=$(echo "$VERIFY_RESPONSE" | jq -r '.token // empty')
REDIRECT_URL=$(echo "$VERIFY_RESPONSE" | jq -r '.redirect_url // empty')
[[ -n "$TOKEN" ]] && pass "JWT token issued" || fail "Token issuance failed" "Response: $VERIFY_RESPONSE"
[[ "$REDIRECT_URL" == *"token="* ]] && pass "Redirect URL contains token" || fail "Redirect URL missing token"

# Test 3: Invalid OTP
print_test 3 "Invalid OTP Rejection"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"000000\",\"req_url\":\"${REQ_URL}\"}")
[[ "$STATUS" == "401" ]] && pass "Invalid OTP rejected (401)" || fail "Should return 401" "Got: $STATUS"

# Test 4: Missing Email
print_test 4 "Missing Email Validation"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d '{}')
[[ "$STATUS" == "422" || "$STATUS" == "400" ]] && pass "Missing email rejected ($STATUS)" || fail "Should return 422/400" "Got: $STATUS"

# Test 5: Token Format
print_test 5 "Token Format (JWT Structure)"
PARTS=$(echo "$TOKEN" | tr '.' '\n' | wc -l)
[[ "$PARTS" -eq 3 ]] && pass "Token has 3 parts" || fail "Token should have 3 parts" "Got: $PARTS"

# Test 6: Multiple OTP Cycles
print_test 6 "Multiple OTP Cycles"
OTP1=$(curl -s -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
OTP2=$(curl -s -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
[[ "$OTP1" != "$OTP2" ]] && pass "Consecutive OTPs are different" || fail "OTPs should be different"
TOKEN2=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP2}\",\"req_url\":\"${REQ_URL}\"}" | jq -r '.token // empty')
[[ -n "$TOKEN2" ]] && pass "Second OTP cycle succeeded" || fail "Second OTP cycle failed"

# Test 7: Redirect URL
print_test 7 "Redirect URL Parameter Validation"
[[ "$REDIRECT_URL" == *"pr1.org1.localhost"* ]] && pass "Redirect contains domain" || fail "Redirect missing domain"
[[ "$REDIRECT_URL" == *"token="* ]] && pass "Redirect contains token param" || fail "Redirect missing token param"

# Test 8: Multi-Org
print_test 8 "Organization 2 Auth Flow"
ORG2_OTP=$(curl -s -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d '{"email":"admin@org2.test"}' | jq -r '.otp')
ORG2_VERIFY=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"admin@org2.test\",\"otp\":\"${ORG2_OTP}\",\"req_url\":\"https://pr1.org2.localhost/admin/dashboard\"}")
ORG2_TOKEN=$(echo "$ORG2_VERIFY" | jq -r '.token // empty')
ORG2_REDIRECT=$(echo "$ORG2_VERIFY" | jq -r '.redirect_url // empty')
[[ -n "$ORG2_TOKEN" ]] && pass "Org2 JWT issued" || fail "Org2 token failed"
[[ "$ORG2_REDIRECT" == *"pr1.org2.localhost"* ]] && pass "Org2 redirect correct" || fail "Org2 redirect wrong"

# Test 9: Wrong Domain
print_test 9 "Wrong Domain Rejection"
FRESH_OTP=$(curl -s -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${FRESH_OTP}\",\"req_url\":\"https://evil.com/steal\"}")
[[ "$STATUS" == "404" || "$STATUS" == "400" ]] && pass "Wrong domain rejected ($STATUS)" || fail "Should reject wrong domain" "Got: $STATUS"

# Test 10: Concurrent
print_test 10 "Concurrent Request Handling"
(for i in 1 2 3; do curl -s -m 3 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d '{"email":"concurrent@test.com"}' -o /dev/null & done; wait) >/dev/null 2>&1
FINAL_OTP=$(curl -s -m 3 -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d '{"email":"concurrent@test.com"}' | jq -r '.otp')
[[ -n "$FINAL_OTP" && "$FINAL_OTP" != "null" ]] && pass "Server handled concurrent requests" || fail "Server not responsive"

# ── QuicGuard Auth Flow Tests ───────────────────────────────────────────

print_header "QuicGuard Auth Flow Tests"

# Test 11: Token has app claim
print_test 11 "Token contains app claim for QuicGuard"
FRESH_OTP=$(curl -s -X POST "${AUTH_URL}/api/otp/send" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')
QC_TOKEN=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" -H "Content-Type: application/json" -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${FRESH_OTP}\",\"req_url\":\"https://pr1.org1.localhost/api/data\"}" | jq -r '.token')
APP_CLAIM=$(echo "$QC_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.app // empty' 2>/dev/null)
[[ -n "$APP_CLAIM" ]] && pass "Token has app claim: $APP_CLAIM" || fail "Token missing app claim"

# Test 12: Token has correct org_id
print_test 12 "Token contains correct org_id"
ORG_CLAIM=$(echo "$QC_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.org_id // empty' 2>/dev/null)
[[ "$ORG_CLAIM" == "org1" ]] && pass "Token has correct org_id: org1" || fail "Token has wrong org_id" "Got: $ORG_CLAIM"

# Test 13: Token has valid expiration
print_test 13 "Token has valid expiration"
EXP=$(echo "$QC_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.exp // empty' 2>/dev/null)
NOW=$(date +%s)
[[ -n "$EXP" && "$EXP" -gt "$NOW" ]] && pass "Token expiration is in the future" || fail "Token expiration invalid" "exp: $EXP, now: $NOW"

# Test 14: QuicGuard container running
print_test 14 "QuicGuard container is running"
docker ps | grep -q "quicguard-quicguard" && pass "QuicGuard container running" || fail "QuicGuard container not running"

# Test 15: QuicGuard loaded TLS configs
print_test 15 "QuicGuard loaded TLS configs"
QC_LOGS=$(docker logs quicguard-quicguard-1 2>&1)
TLS_COUNT=$(echo "$QC_LOGS" | grep -c "Preloaded TLS config" || echo "0")
[[ "$TLS_COUNT" -gt 0 ]] && pass "QuicGuard preloaded $TLS_COUNT TLS configs" || fail "No TLS configs preloaded"

# Test 16: QuicGuard connected to Redis
print_test 16 "QuicGuard loaded config from Redis"
echo "$QC_LOGS" | grep -q "Loaded configuration from Redis" && pass "QuicGuard loaded config from Redis" || fail "QuicGuard did not load config"

# ── Summary ──────────────────────────────────────────────────────────────

print_header "Test Results"
echo -e "  Passed: ${GREEN}$PASSED${NC}"
echo -e "  Failed: ${RED}$FAILED${NC}"
echo -e "  Total:  $TOTAL"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}  SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}  ALL TESTS PASSED${NC}"
    exit 0
fi
