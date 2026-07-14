#!/bin/bash

# QuicGuard System Startup Script
# Starts all services: Redis, Dashboard, Auth Service, QuicGuard

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Log directory
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"

# PID file directory
PID_DIR="$PROJECT_ROOT/.pids"
mkdir -p "$PID_DIR"

# Function to print status
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to check if a port is in use
check_port() {
    lsof -i:$1 >/dev/null 2>&1
}

# Function to wait for a service
wait_for_service() {
    local port=$1
    local service=$2
    local max_wait=${3:-30}
    local count=0

    while ! check_port $port; do
        sleep 1
        count=$((count + 1))
        if [ $count -ge $max_wait ]; then
            print_error "Timeout waiting for $service on port $port"
            return 1
        fi
    done
    print_status "$service is running on port $port"
}

# Function to stop a service
stop_service() {
    local pid_file=$1
    local service=$2

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            print_status "Stopped $service (PID: $pid)"
        fi
        rm -f "$pid_file"
    fi
}

# Cleanup function
cleanup() {
    echo ""
    print_warning "Shutting down all services..."
    stop_service "$PID_DIR/redis.pid" "Redis"
    stop_service "$PID_DIR/dashboard.pid" "Dashboard"
    stop_service "$PID_DIR/auth.pid" "Auth Service"
    stop_service "$PID_DIR/quicguard.pid" "QuicGuard"
    print_status "All services stopped"
    exit 0
}

# Trap cleanup on exit
trap cleanup SIGINT SIGTERM

# Parse command line arguments
ACTION=${1:-start}

case $ACTION in
    start)
        echo "=========================================="
        echo "  QuicGuard System Startup"
        echo "=========================================="
        echo ""

        # 1. Start Redis
        print_warning "Starting Redis..."
        if check_port 6379; then
            print_warning "Redis is already running on port 6379"
        else
            redis-server --daemonize yes --logfile "$LOG_DIR/redis.log" --port 6379
            sleep 1
            if check_port 6379; then
                print_status "Redis started on port 6379"
            else
                print_error "Failed to start Redis"
                exit 1
            fi
        fi

        # 2. Build and start Dashboard
        print_warning "Building Dashboard..."
        cd "$PROJECT_ROOT/dashboard"
        cargo build --release 2>&1 | tail -1
        print_status "Dashboard built"

        print_warning "Starting Dashboard..."
        if check_port 3000; then
            print_warning "Dashboard is already running on port 3000"
        else
            DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost/quicguard}" \
            REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}" \
            JWT_SECRET="${JWT_SECRET:-secret}" \
            RUST_LOG=info \
            ./target/release/dashboard > "$LOG_DIR/dashboard.log" 2>&1 &
            echo $! > "$PID_DIR/dashboard.pid"
            wait_for_service 3000 "Dashboard"
        fi

        # 3. Build and start Auth Service
        print_warning "Building Auth Service..."
        cd "$PROJECT_ROOT/auth"
        cargo build --release 2>&1 | tail -1
        print_status "Auth Service built"

        print_warning "Starting Auth Service..."
        if check_port 3001; then
            print_warning "Auth Service is already running on port 3001"
        else
            REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}" \
            REDIS_ORG_KEY="${REDIS_ORG_KEY:-quicguard:organizations}" \
            AUTH_SERVER_PORT=3001 \
            RUST_LOG=info \
            ./target/release/auth-service > "$LOG_DIR/auth.log" 2>&1 &
            echo $! > "$PID_DIR/auth.pid"
            wait_for_service 3001 "Auth Service"
        fi

        # 4. Build and start QuicGuard
        print_warning "Building QuicGuard..."
        cd "$PROJECT_ROOT"
        cargo build --release -p quicguard 2>&1 | tail -1
        print_status "QuicGuard built"

        print_warning "Starting QuicGuard..."
        if check_port 4433; then
            print_warning "QuicGuard is already running on port 4433"
        else
            RUST_LOG=info \
            ./target/release/quicguard > "$LOG_DIR/quicguard.log" 2>&1 &
            echo $! > "$PID_DIR/quicguard.pid"
            wait_for_service 4433 "QuicGuard"
        fi

        echo ""
        echo "=========================================="
        echo "  All services started successfully!"
        echo "=========================================="
        echo ""
        echo "Services:"
        echo "  - Redis:        http://localhost:6379"
        echo "  - Dashboard:    http://localhost:3000"
        echo "  - Auth Service: http://localhost:3001"
        echo "  - QuicGuard:    http://localhost:4433"
        echo ""
        echo "Logs: $LOG_DIR/"
        echo "PIDs: $PID_DIR/"
        echo ""
        echo "To stop all services: $0 stop"
        echo "To view logs: $0 logs"
        ;;

    stop)
        echo "Stopping all services..."
        stop_service "$PID_DIR/quicguard.pid" "QuicGuard"
        stop_service "$PID_DIR/auth.pid" "Auth Service"
        stop_service "$PID_DIR/dashboard.pid" "Dashboard"
        # Don't stop Redis as it might be used by other projects
        print_warning "Note: Redis was not stopped (might be used by other projects)"
        print_status "All services stopped"
        ;;

    restart)
        $0 stop
        sleep 2
        $0 start
        ;;

    status)
        echo "Service Status:"
        echo "---------------"
        if check_port 6379; then
            print_status "Redis: Running"
        else
            print_error "Redis: Not running"
        fi
        if check_port 3000; then
            print_status "Dashboard: Running"
        else
            print_error "Dashboard: Not running"
        fi
        if check_port 3001; then
            print_status "Auth Service: Running"
        else
            print_error "Auth Service: Not running"
        fi
        if check_port 4433; then
            print_status "QuicGuard: Running"
        else
            print_error "QuicGuard: Not running"
        fi
        ;;

    logs)
        echo "Tailing logs (Ctrl+C to stop)..."
        tail -f "$LOG_DIR"/*.log
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
