#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$DASHBOARD_DIR")"

DB_NAME="dashboard_test_runner"
DB_USER="quicguard"
DB_PASS="quicguard"
DB_PORT="5432"
REDIS_PORT="6379"

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --unit          Run only unit tests (no external deps needed)"
    echo "  --integration   Run only integration tests (needs Postgres)"
    echo "  --all           Run all tests (default)"
    echo "  --cleanup       Stop test containers after tests"
    echo "  --docker        Use Docker for Postgres/Redis (requires docker)"
    echo "  --help          Show this help"
    exit 0
}

RUN_UNIT=true
RUN_INTEGRATION=true
CLEANUP=false
USE_DOCKER=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit) RUN_INTEGRATION=false; shift ;;
        --integration) RUN_UNIT=false; shift ;;
        --all) shift ;;
        --cleanup) CLEANUP=true; shift ;;
        --docker) USE_DOCKER=true; shift ;;
        --help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

echo "=== QuicGuard Dashboard Test Runner ==="

# --- Unit Tests ---
if [ "$RUN_UNIT" = true ]; then
    echo ""
    echo "--- Running Unit Tests (no dependencies) ---"
    cd "$DASHBOARD_DIR"
    cargo test --lib 2>&1
    echo "Unit tests: PASSED"
fi

# --- Integration Tests ---
if [ "$RUN_INTEGRATION" = true ]; then
    echo ""
    echo "--- Checking Integration Test Dependencies ---"

    # Check for Postgres
    PG_READY=false
    if pg_isready -h localhost -p "$DB_PORT" -q 2>/dev/null; then
        PG_READY=true
        echo "Postgres already running on port $DB_PORT"
    elif [ "$USE_DOCKER" = true ]; then
        echo "Starting Postgres via Docker..."
        docker run -d --name dashboard-test-postgres \
            -e POSTGRES_DB="$DB_NAME" \
            -e POSTGRES_USER="$DB_USER" \
            -e POSTGRES_PASSWORD="$DB_PASS" \
            -p "$DB_PORT:5432" \
            postgres:16-alpine 2>/dev/null || true
        echo "Waiting for Postgres to be ready..."
        for i in $(seq 1 30); do
            if pg_isready -h localhost -p "$DB_PORT" -q 2>/dev/null; then
                PG_READY=true
                break
            fi
            sleep 1
        done
    fi

    if [ "$PG_READY" = false ]; then
        echo ""
        echo "ERROR: Postgres is not available on port $DB_PORT"
        echo ""
        echo "Options:"
        echo "  1. Start Postgres manually and ensure it's accessible"
        echo "  2. Run with --docker flag (requires Docker): $0 --docker"
        echo "  3. Run unit tests only: $0 --unit"
        echo ""
        echo "If Postgres is running on a different host/port, set DATABASE_URL:"
        echo "  DATABASE_URL=postgres://user:pass@host:port/dbname $0"
        exit 1
    fi

    # Create test database
    echo "Setting up test database..."
    PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -p "$DB_PORT" -d postgres -c \
        "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || true
    PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -p "$DB_PORT" -d postgres -c \
        "CREATE DATABASE $DB_NAME;" 2>/dev/null

    # Run migrations
    echo "Running migrations..."
    DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@localhost:${DB_PORT}/${DB_NAME}" \
        cargo run -- run-migrations 2>&1

    # Run integration tests
    echo ""
    echo "--- Running Integration Tests ---"
    DATABASE_URL="postgres://${DB_USER}:${DB_PASS}@localhost:${DB_PORT}/${DB_NAME}" \
        cargo test --test api_tests 2>&1
    echo "Integration tests: PASSED"

    # Cleanup test database
    echo "Cleaning up test database..."
    PGPASSWORD="$DB_PASS" psql -h localhost -U "$DB_USER" -p "$DB_PORT" -d postgres -c \
        "DROP DATABASE IF EXISTS $DB_NAME;" 2>/dev/null || true

    # Stop Docker container if we started it
    if [ "$USE_DOCKER" = true ] && [ "$CLEANUP" = true ]; then
        echo "Stopping test Docker containers..."
        docker stop dashboard-test-postgres 2>/dev/null || true
        docker rm dashboard-test-postgres 2>/dev/null || true
    fi
fi

echo ""
echo "=== All tests passed ==="
