#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$DASHBOARD_DIR")"

echo "=== QuicGuard Dashboard Setup ==="

# Check prerequisites
command -v cargo >/dev/null 2>&1 || { echo "Error: cargo not found. Install Rust."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Error: docker not found."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm not found. Install Node.js."; exit 1; }

# Start services
echo "Starting Postgres and Redis..."
cd "$ROOT_DIR/services"
docker compose up -d
echo "Waiting for Postgres..."
sleep 3

# Copy .env if not exists
if [ ! -f "$DASHBOARD_DIR/.env" ]; then
    echo "Creating .env from .env.example..."
    cp "$DASHBOARD_DIR/.env.example" "$DASHBOARD_DIR/.env"
    echo "Please edit $DASHBOARD_DIR/.env with your settings."
fi

# Build and run migrations
echo "Building dashboard..."
cd "$DASHBOARD_DIR"
cargo build --release

echo "Running database migrations..."
DATABASE_URL=$(grep DATABASE_URL .env | cut -d= -f2-)
export DATABASE_URL
./target/release/dashboard run-migrations

# Create initial admin
echo "Creating initial admin user..."
ADMIN_EMAIL="${1:-admin@quicguard.local}"
ADMIN_PASS="${2:-admin123}"
./target/release/dashboard create-admin "$ADMIN_EMAIL" "$ADMIN_PASS" || true

# Build frontend
echo "Building frontend..."
cd "$DASHBOARD_DIR/frontend"
npm install
npm run build

echo ""
echo "=== Setup Complete ==="
echo "Start the dashboard: cd $DASHBOARD_DIR && cargo run --release"
echo "Dashboard will be at: http://localhost:3000"
echo "Admin login: $ADMIN_EMAIL / $ADMIN_PASS"
