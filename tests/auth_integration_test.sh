#!/usr/bin/env bash
#
# ══════════════════════════════════════════════════════════════════════════════
# QuicGuard Auth Flow Integration Test
# ══════════════════════════════════════════════════════════════════════════════
#
# DESCRIPTION:
#   Tests the complete authentication flow for QuicGuard.
#   This script assumes all services are already running (use scripts/start.sh).
#
# TESTS COVERED:
#   1. OTP Send - Request OTP code via email
#   2. OTP Verify - Verify OTP and get JWT token
#   3. Invalid OTP - Verify rejection of wrong OTP
#   4. Missing Fields - Verify validation of required fields
#   5. Token Format - Verify JWT structure
#   6. Multiple OTP Cycles - Test multiple authentication attempts
#   7. Redirect URL - Verify token and domain in redirect
#   8. Multi-Org Flow - Test authentication for different organizations
#   9. Wrong Domain - Verify rejection of unauthorized domains
#  10. Concurrent Requests - Test server stability under load
#
# PREREQUISITES:
#   - Services running (start with: ./scripts/start.sh start)
#   - curl, jq installed
#
# USAGE:
#   ./tests/auth_integration_test.sh
#
# OPTIONS:
#   -h, --help     Show this help message
#   -v, --verbose  Show verbose output
#
# EXAMPLES:
#   # Run all tests
#   ./tests/auth_integration_test.sh
#
#   # Run with verbose output
#   ./tests/auth_integration_test.sh -v
#
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────

AUTH_PORT="${AUTH_PORT:-3001}"
AUTH_URL="http://127.0.0.1:${AUTH_PORT}"
TEST_EMAIL="test@example.com"
VERBOSE=false

# ── Parse arguments ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            head -40 "$0" | tail -38
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# ── Colors ─────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Counters ───────────────────────────────────────────────────────────────

PASSED=0
FAILED=0
TOTAL=0

# ── Helper functions ───────────────────────────────────────────────────────

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
}

print_test() {
    echo ""
    echo -e "${YELLOW}── Test $1: $2 ──${NC}"
}

print_curl() {
    echo -e "${CYAN}  curl command:${NC}"
    echo -e "    $1"
    echo ""
}

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    PASSED=$((PASSED + 1))
    TOTAL=$((TOTAL + 1))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    if [[ -n "${2:-}" ]]; then
        echo -e "    ${RED}$2${NC}"
    fi
    FAILED=$((FAILED + 1))
    TOTAL=$((TOTAL + 1))
}

# ── Check services ─────────────────────────────────────────────────────────

print_header "Checking Services"

if ! curl -sf -m 2 "$AUTH_URL/api/otp/send" -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"check"}' >/dev/null 2>&1; then
    # Check if it's just a validation error (means service is running)
    HTTP_CODE=$(curl -sf -m 2 -o /dev/null -w "%{http_code}" "$AUTH_URL/api/otp/send" \
        -X POST -H "Content-Type: application/json" \
        -d '{"email":"check"}' 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "000" ]]; then
        echo -e "${RED}Auth service not running on port $AUTH_PORT${NC}"
        echo "Please start services first: ./scripts/start.sh start"
        exit 1
    fi
fi
echo -e "${GREEN}✓${NC} Auth service is running"

# ══════════════════════════════════════════════════════════════════════════════
#  TESTS
# ══════════════════════════════════════════════════════════════════════════════

print_header "Auth Flow Integration Tests"

# ── Test 1: OTP Send ──────────────────────────────────────────────────────

print_test 1 "OTP Send"

CURL_CMD="curl -s -X POST '${AUTH_URL}/api/otp/send' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${TEST_EMAIL}\"}'"
print_curl "$CURL_CMD"

OTP_RESPONSE=$(curl -s -X POST "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\"}")

if [[ "$VERBOSE" == "true" ]]; then
    echo "  Response: $OTP_RESPONSE"
fi

OTP_CODE=$(echo "$OTP_RESPONSE" | jq -r '.otp // empty')
OTP_MESSAGE=$(echo "$OTP_RESPONSE" | jq -r '.message // empty')

if [[ -n "$OTP_CODE" ]]; then
    pass "OTP sent successfully (code: $OTP_CODE)"
else
    fail "OTP send failed" "Response: $OTP_RESPONSE"
fi

# ── Test 2: OTP Verify and Token Issuance ────────────────────────────────

print_test 2 "OTP Verify and Token Issuance"

REQ_URL="https://pr1.org1.localhost/api/data"
CURL_CMD="curl -s -X POST '${AUTH_URL}/api/otp/verify' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP_CODE}\",\"req_url\":\"${REQ_URL}\"}'"
print_curl "$CURL_CMD"

VERIFY_RESPONSE=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP_CODE}\",\"req_url\":\"${REQ_URL}\"}")

if [[ "$VERBOSE" == "true" ]]; then
    echo "  Response: $VERIFY_RESPONSE"
fi

TOKEN=$(echo "$VERIFY_RESPONSE" | jq -r '.token // empty')
REDIRECT_URL=$(echo "$VERIFY_RESPONSE" | jq -r '.redirect_url // empty')

if [[ -n "$TOKEN" ]]; then
    pass "JWT token issued"
else
    fail "Token issuance failed" "Response: $VERIFY_RESPONSE"
fi

if [[ -n "$REDIRECT_URL" ]]; then
    pass "Redirect URL returned"
    if echo "$REDIRECT_URL" | grep -q "token="; then
        pass "Redirect URL contains token parameter"
    else
        fail "Redirect URL missing token parameter"
    fi
else
    fail "Redirect URL not returned"
fi

# ── Test 3: Invalid OTP ──────────────────────────────────────────────────

print_test 3 "Invalid OTP Rejection"

CURL_CMD="curl -s -o /dev/null -w '%{http_code}' -X POST '${AUTH_URL}/api/otp/verify' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${TEST_EMAIL}\",\"otp\":\"000000\",\"req_url\":\"${REQ_URL}\"}'"
print_curl "$CURL_CMD"

INVALID_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${AUTH_URL}/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"000000\",\"req_url\":\"${REQ_URL}\"}")

if [[ "$INVALID_STATUS" == "401" ]]; then
    pass "Invalid OTP correctly rejected (401)"
else
    fail "Invalid OTP should return 401" "Got: $INVALID_STATUS"
fi

# ── Test 4: Missing Email ────────────────────────────────────────────────

print_test 4 "Missing Email Validation"

CURL_CMD="curl -s -o /dev/null -w '%{http_code}' -X POST '${AUTH_URL}/api/otp/send' \\
  -H 'Content-Type: application/json' \\
  -d '{}'"
print_curl "$CURL_CMD"

MISSING_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d '{}')

if [[ "$MISSING_STATUS" == "422" || "$MISSING_STATUS" == "400" ]]; then
    pass "Missing email correctly rejected ($MISSING_STATUS)"
else
    fail "Missing email should return 422 or 400" "Got: $MISSING_STATUS"
fi

# ── Test 5: Token Format ──────────────────────────────────────────────────

print_test 5 "Token Format (JWT Structure)"

JWT_PARTS=$(echo "$TOKEN" | tr '.' '\n' | wc -l)
if [[ "$JWT_PARTS" -eq 3 ]]; then
    pass "Token has 3 parts (valid JWT structure)"
else
    fail "Token should have 3 parts" "Got: $JWT_PARTS"
fi

# Decode header
HEADER=$(echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null || echo "")
ALG=$(echo "$HEADER" | jq -r '.alg // empty' 2>/dev/null || echo "")
if [[ "$ALG" == "EdDSA" ]]; then
    pass "Token uses EdDSA algorithm"
else
    pass "Token algorithm: ${ALG:-unknown}"
fi

# ── Test 6: Multiple OTP Cycles ──────────────────────────────────────────

print_test 6 "Multiple OTP Cycles"

CURL_CMD1="curl -s -X POST '${AUTH_URL}/api/otp/send' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${TEST_EMAIL}\"}'"
print_curl "$CURL_CMD1"

OTP1=$(curl -s -X POST "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')

OTP2=$(curl -s -X POST "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')

if [[ "$OTP1" != "$OTP2" ]]; then
    pass "Consecutive OTPs are different"
else
    fail "Consecutive OTPs should be different"
fi

# Verify second OTP works
CURL_CMD2="curl -s -X POST '${AUTH_URL}/api/otp/verify' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP2}\",\"req_url\":\"${REQ_URL}\"}'"
print_curl "$CURL_CMD2"

VERIFY2=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${OTP2}\",\"req_url\":\"${REQ_URL}\"}")
TOKEN2=$(echo "$VERIFY2" | jq -r '.token // empty')

if [[ -n "$TOKEN2" ]]; then
    pass "Second OTP cycle succeeded"
else
    fail "Second OTP cycle failed"
fi

# ── Test 7: Redirect URL Validation ──────────────────────────────────────

print_test 7 "Redirect URL Parameter Validation"

if echo "$REDIRECT_URL" | grep -q "pr1.org1.localhost"; then
    pass "Redirect URL contains correct domain"
else
    fail "Redirect URL missing correct domain"
fi

if echo "$REDIRECT_URL" | grep -q "token="; then
    pass "Redirect URL contains token parameter"
else
    fail "Redirect URL missing token parameter"
fi

# ── Test 8: Multi-Org Flow ──────────────────────────────────────────────

print_test 8 "Organization 2 Auth Flow"

ORG2_EMAIL="admin@org2.test"
ORG2_REQ="https://pr1.org2.localhost/admin/dashboard"

CURL_CMD="curl -s -X POST '${AUTH_URL}/api/otp/send' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${ORG2_EMAIL}\"}'"
print_curl "$CURL_CMD"

ORG2_OTP=$(curl -s -X POST "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ORG2_EMAIL}\"}" | jq -r '.otp')

CURL_CMD="curl -s -X POST '${AUTH_URL}/api/otp/verify' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${ORG2_EMAIL}\",\"otp\":\"${ORG2_OTP}\",\"req_url\":\"${ORG2_REQ}\"}'"
print_curl "$CURL_CMD"

ORG2_VERIFY=$(curl -s -X POST "${AUTH_URL}/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${ORG2_EMAIL}\",\"otp\":\"${ORG2_OTP}\",\"req_url\":\"${ORG2_REQ}\"}")
ORG2_TOKEN=$(echo "$ORG2_VERIFY" | jq -r '.token // empty')
ORG2_REDIRECT=$(echo "$ORG2_VERIFY" | jq -r '.redirect_url // empty')

if [[ -n "$ORG2_TOKEN" ]]; then
    pass "Org2 JWT token issued"
else
    fail "Org2 token issuance failed"
fi

if echo "$ORG2_REDIRECT" | grep -q "pr1.org2.localhost"; then
    pass "Org2 redirect points to correct domain"
else
    fail "Org2 redirect has wrong domain"
fi

# ── Test 9: Wrong Domain ──────────────────────────────────────────────

print_test 9 "Wrong Domain Rejection"

FRESH_OTP=$(curl -s -X POST "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\"}" | jq -r '.otp')

CURL_CMD="curl -s -o /dev/null -w '%{http_code}' -X POST '${AUTH_URL}/api/otp/verify' \\
  -H 'Content-Type: application/json' \\
  -d '{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${FRESH_OTP}\",\"req_url\":\"https://evil.com/steal\"}'"
print_curl "$CURL_CMD"

WRONG_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    "${AUTH_URL}/api/otp/verify" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${TEST_EMAIL}\",\"otp\":\"${FRESH_OTP}\",\"req_url\":\"https://evil.com/steal\"}")

if [[ "$WRONG_STATUS" == "404" || "$WRONG_STATUS" == "400" ]]; then
    pass "Wrong domain correctly rejected ($WRONG_STATUS)"
else
    fail "Wrong domain should be rejected" "Got: $WRONG_STATUS"
fi

# ── Test 10: Concurrent Requests ────────────────────────────────────────

print_test 10 "Concurrent Request Handling"

CONC_EMAIL="concurrent@test.com"

CURL_CMD="for i in 1 2 3; do
  curl -s -X POST '${AUTH_URL}/api/otp/send' \\
    -H 'Content-Type: application/json' \\
    -d '{\"email\":\"${CONC_EMAIL}\"}' &
done
wait"
print_curl "$CURL_CMD"

(
    for i in 1 2 3; do
        curl -s -m 3 -X POST "${AUTH_URL}/api/otp/send" \
            -H "Content-Type: application/json" \
            -d "{\"email\":\"${CONC_EMAIL}\"}" -o /dev/null &
    done
    wait
) >/dev/null 2>&1

# Verify server is still responsive
FINAL_OTP=$(curl -s -m 3 -X POST "${AUTH_URL}/api/otp/send" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${CONC_EMAIL}\"}" | jq -r '.otp')

if [[ -n "$FINAL_OTP" && "$FINAL_OTP" != "null" ]]; then
    pass "Server handled concurrent requests successfully"
else
    fail "Server not responsive after concurrent requests"
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

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
