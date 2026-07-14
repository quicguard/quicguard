#!/usr/bin/env bash
#
# ══════════════════════════════════════════════════════════════════════════════
# QuicGuard System Startup Script
# ══════════════════════════════════════════════════════════════════════════════
#
# DESCRIPTION:
#   Starts all QuicGuard services and loads sample data for testing.
#
# SERVICES:
#   - Redis (port 6379)
#   - Dashboard Backend (port 3000)
#   - Auth Service (port 3001)
#   - QuicGuard Proxy (port 4433)
#
# PREREQUISITES:
#   - redis-server installed
#   - cargo (Rust toolchain)
#   - jq
#   - curl
#
# USAGE:
#   ./scripts/start.sh [command]
#
# COMMANDS:
#   start      Start all services (default)
#   stop       Stop all services
#   restart    Restart all services
#   status     Show service status
#   logs       Tail all service logs
#   load-data  Load sample data into Redis
#   help       Show this help message
#
# EXAMPLES:
#   # Start all services with sample data
#   ./scripts/start.sh start
#
#   # Just load sample data (services must be running)
#   ./scripts/start.sh load-data
#
#   # Check what's running
#   ./scripts/start.sh status
#
#   # View all logs
#   ./scripts/start.sh logs
#
#   # Stop everything
#   ./scripts/start.sh stop
#
# SAMPLE DATA:
#   The script loads test organizations from tests/test_data.json:
#   - org1: Organization 1 (pr1.org1.localhost, pr2.org1.localhost, sec1.org1.localhost)
#     - Apps: web-app, mobile-app
#   - org2: Organization 2 (pr1.org2.localhost, pr2.org2.localhost, sec1.org2.localhost)
#     - Apps: admin-panel, public-site
#
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$PROJECT_ROOT/logs"
PID_DIR="$PROJECT_ROOT/.pids"
TEST_DATA="$PROJECT_ROOT/tests/test_data.json"

REDIS_PORT="${REDIS_PORT:-6379}"
DASHBOARD_PORT="${DASHBOARD_PORT:-3000}"
AUTH_PORT="${AUTH_PORT:-3001}"
QC_PORT="${QC_PORT:-4433}"

REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
REDIS_ORG_KEY="${REDIS_ORG_KEY:-quicguard:organizations}"

# ── Colors ─────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Helper functions ───────────────────────────────────────────────────────

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════════════${NC}"
}

print_status() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "  ${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

check_port() {
    lsof -i:"$1" >/dev/null 2>&1 || \
    ss -tlnp 2>/dev/null | grep -q ":$1 " || \
    netstat -tlnp 2>/dev/null | grep -q ":$1 "
}

wait_for_port() {
    local port=$1
    local service=$2
    local max_wait=${3:-30}
    local count=0

    while ! check_port "$port"; do
        sleep 1
        count=$((count + 1))
        if [ $count -ge $max_wait ]; then
            print_error "Timeout waiting for $service on port $port"
            return 1
        fi
    done
    print_status "$service is running on port $port"
}

stop_pid() {
    local pid_file=$1
    local service=$2

    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            sleep 1
            print_status "Stopped $service"
        fi
        rm -f "$pid_file"
    fi
}

cleanup() {
    echo ""
    print_warning "Shutting down services..."
    stop_pid "$PID_DIR/quicguard.pid" "QuicGuard"
    stop_pid "$PID_DIR/auth.pid" "Auth Service"
    stop_pid "$PID_DIR/dashboard.pid" "Dashboard"
    print_status "All services stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ── Help ───────────────────────────────────────────────────────────────────

show_help() {
    head -55 "$0" | tail -50
}

# ── Load sample data ──────────────────────────────────────────────────────

load_sample_data() {
    print_header "Loading Sample Data"

    if [[ ! -f "$TEST_DATA" ]]; then
        print_error "Test data file not found: $TEST_DATA"
        return 1
    fi

    # Check Redis is running
    if ! redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
        print_error "Redis not running on port $REDIS_PORT"
        return 1
    fi

    # Clear existing data
    redis-cli -p "$REDIS_PORT" DEL "$REDIS_ORG_KEY" >/dev/null 2>&1 || true
    print_status "Cleared existing org data"

    # Load each organization
    local org_ids
    org_ids=$(jq -r 'keys[]' "$TEST_DATA")

    for org_id in $org_ids; do
        local org_json
        org_json=$(jq -c --arg id "$org_id" '.[$id]' "$TEST_DATA")
        if redis-cli -p "$REDIS_PORT" HSET "$REDIS_ORG_KEY" "$org_id" "$org_json" | grep -qE '^[0-9]+$'; then
            print_status "Loaded org '$org_id'"
        else
            print_error "Failed to load org '$org_id'"
            return 1
        fi
    done

    echo ""
    echo -e "${GREEN}Sample data loaded successfully!${NC}"
    echo ""
    echo "Organizations:"
    echo "  - org1: pr1.org1.localhost, pr2.org1.localhost, sec1.org1.localhost"
    echo "  - org2: pr1.org2.localhost, pr2.org2.localhost, sec1.org2.localhost"
}

# ── Main commands ──────────────────────────────────────────────────────────

ACTION=${1:-help}

case $ACTION in
    start)
        print_header "QuicGuard System Startup"

        # Create directories
        mkdir -p "$LOG_DIR" "$PID_DIR"

        # 1. Start Redis
        print_warning "Starting Redis..."
        if check_port "$REDIS_PORT"; then
            print_warning "Redis already running on port $REDIS_PORT"
        else
            redis-server --port "$REDIS_PORT" --daemonize yes \
                --logfile "$LOG_DIR/redis.log" \
                --save "" 2>/dev/null
            sleep 1
            if check_port "$REDIS_PORT"; then
                print_status "Redis started on port $REDIS_PORT"
            else
                print_error "Failed to start Redis"
                exit 1
            fi
        fi

        # Load sample data
        load_sample_data

        # 2. Build and start Dashboard
        print_warning "Building Dashboard..."
        cd "$PROJECT_ROOT/dashboard"
        cargo build --release 2>&1 | tail -1
        print_status "Dashboard built"

        print_warning "Starting Dashboard..."
        if check_port "$DASHBOARD_PORT"; then
            print_warning "Dashboard already running on port $DASHBOARD_PORT"
        else
            DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost/quicguard}" \
            REDIS_URL="$REDIS_URL" \
            JWT_SECRET="${JWT_SECRET:-secret}" \
            RUST_LOG=info \
            ./target/release/dashboard > "$LOG_DIR/dashboard.log" 2>&1 &
            echo $! > "$PID_DIR/dashboard.pid"
            wait_for_port "$DASHBOARD_PORT" "Dashboard"
        fi

        # 3. Build and start Auth Service
        print_warning "Building Auth Service..."
        cd "$PROJECT_ROOT/auth"
        cargo build --release 2>&1 | tail -1
        print_status "Auth Service built"

        print_warning "Starting Auth Service..."
        if check_port "$AUTH_PORT"; then
            print_warning "Auth Service already running on port $AUTH_PORT"
        else
            REDIS_URL="$REDIS_URL" \
            REDIS_ORG_KEY="$REDIS_ORG_KEY" \
            AUTH_SERVER_PORT="$AUTH_PORT" \
            RUST_LOG=info \
            ./target/release/auth-service > "$LOG_DIR/auth.log" 2>&1 &
            echo $! > "$PID_DIR/auth.pid"
            wait_for_port "$AUTH_PORT" "Auth Service"
        fi

        # 4. Build and start QuicGuard
        print_warning "Building QuicGuard..."
        cd "$PROJECT_ROOT"
        cargo build --release -p quicguard 2>&1 | tail -1
        print_status "QuicGuard built"

        print_warning "Starting QuicGuard..."
        if check_port "$QC_PORT"; then
            print_warning "QuicGuard already running on port $QC_PORT"
        else
            RUST_LOG=info \
            ./target/release/quicguard > "$LOG_DIR/quicguard.log" 2>&1 &
            echo $! > "$PID_DIR/quicguard.pid"
            wait_for_port "$QC_PORT" "QuicGuard"
        fi

        echo ""
        print_header "All Services Started"
        echo ""
        echo "Services:"
        echo -e "  ${GREEN}✓${NC} Redis:        http://localhost:$REDIS_PORT"
        echo -e "  ${GREEN}✓${NC} Dashboard:    http://localhost:$DASHBOARD_PORT"
        echo -e "  ${GREEN}✓${NC} Auth Service: http://localhost:$AUTH_PORT"
        echo -e "  ${GREEN}✓${NC} QuicGuard:    http://localhost:$QC_PORT"
        echo ""
        echo "Sample Data:"
        echo "  - org1: pr1.org1.localhost, pr2.org1.localhost, sec1.org1.localhost"
        echo "  - org2: pr1.org2.localhost, pr2.org2.localhost, sec1.org2.localhost"
        echo ""
        echo "Quick Links:"
        echo "  - Dashboard:    http://localhost:$DASHBOARD_PORT"
        echo "  - Auth Login:   http://localhost:$AUTH_PORT"
        echo ""
        echo "Commands:"
        echo "  - Stop:         ./scripts/start.sh stop"
        echo "  - Status:       ./scripts/start.sh status"
        echo "  - Logs:         ./scripts/start.sh logs"
        echo "  - Run Tests:    ./tests/auth_integration_test.sh"
        ;;

    stop)
        echo "Stopping services..."
        stop_pid "$PID_DIR/quicguard.pid" "QuicGuard"
        stop_pid "$PID_DIR/auth.pid" "Auth Service"
        stop_pid "$PID_DIR/dashboard.pid" "Dashboard"
        print_warning "Redis was not stopped (might be used by other projects)"
        echo ""
        print_status "All services stopped"
        ;;

    restart)
        $0 stop
        sleep 2
        $0 start
        ;;

    status)
        print_header "Service Status"
        echo ""

        if check_port "$REDIS_PORT"; then
            echo -e "  ${GREEN}✓${NC} Redis:        Running (port $REDIS_PORT)"
        else
            echo -e "  ${RED}✗${NC} Redis:        Not running"
        fi

        if check_port "$DASHBOARD_PORT"; then
            echo -e "  ${GREEN}✓${NC} Dashboard:    Running (port $DASHBOARD_PORT)"
        else
            echo -e "  ${RED}✗${NC} Dashboard:    Not running"
        fi

        if check_port "$AUTH_PORT"; then
            echo -e "  ${GREEN}✓${NC} Auth Service: Running (port $AUTH_PORT)"
        else
            echo -e "  ${RED}✗${NC} Auth Service: Not running"
        fi

        if check_port "$QC_PORT"; then
            echo -e "  ${GREEN}✓${NC} QuicGuard:    Running (port $QC_PORT)"
        else
            echo -e "  ${RED}✗${NC} QuicGuard:    Not running"
        fi

        echo ""
        echo "Sample Data in Redis:"
        if redis-cli -p "$REDIS_PORT" HLEN "$REDIS_ORG_KEY" >/dev/null 2>&1; then
            local count
            count=$(redis-cli -p "$REDIS_PORT" HLEN "$REDIS_ORG_KEY" 2>/dev/null || echo "0")
            echo -e "  ${GREEN}✓${NC} $count organizations loaded"
        else
            echo -e "  ${RED}✗${NC} No data found"
        fi
        ;;

    logs)
        print_header "Service Logs"
        echo "Tailing logs (Ctrl+C to stop)..."
        echo ""
        tail -f "$LOG_DIR"/*.log 2>/dev/null || echo "No log files found"
        ;;

    load-data)
        load_sample_data
        ;;

    help|--help|-h)
        show_help
        ;;

    *)
        echo "Unknown command: $ACTION"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac
