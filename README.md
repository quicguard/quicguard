# QuicGuard - WireGuard-like VPN using HTTP/3 QUIC

A high-performance VPN implementation inspired by WireGuard, built using HTTP/3 QUIC protocol with the s2n-quic library. This project tunnels IP packets over QUIC streams, providing encrypted communication.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Building](#building)
- [Deployment](#deployment)
- [Usage](#usage)
- [Dashboard](#dashboard)

## Overview

QuicGuard creates a secure tunnel between a client and server using the QUIC protocol (RFC 9000). Unlike traditional VPNs that use custom protocols on easily-blocked ports, QuicGuard operates over UDP port 4433, making it indistinguishable from regular HTTPS/HTTP3 traffic to network observers.

## Requirements

### System Requirements

- **Operating System**: Linux (Linux 5.1+ for io-uring support)
- **Privileges**: Root access (for TUN device creation)
- **Architecture**: x86_64, aarch64

### Build Requirements

- Rust 1.70 or later
- CMake (for aws-lc-sys)
- C compiler (gcc/clang)
- pkg-config

### Runtime Dependencies

- `iproute2` (for `ip` command)
- `iptables` (for NAT, server only)

## Building

### From Source

```bash
# Clone the repository
git clone https://github.com/quicguard/quicguard.git
cd quicguard

# Build in release mode
cargo build --release

# Binaries will be in target/release/
ls -la target/release/{client,server,quicguard}
```

### Build Options

```bash
# Debug build (faster compilation, slower runtime)
cargo build

# Release build with debug symbols
cargo build --release --features debug


# Static binary (requires musl)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Deployment

### Server Deployment

#### 1. Prepare the Server

```bash
# Create deployment directory
sudo mkdir -p /opt/quicguard
sudo mkdir -p /opt/quicguard/certs
sudo mkdir -p /var/log/quicguard

# Copy binary
sudo cp target/release/server /opt/quicguard/

# Set permissions
sudo chmod 755 /opt/quicguard/server
```

#### 2. Seed Redis with Configuration

TLS certificates are loaded from Redis per-organization, not from disk files.
Run the seed script to populate Redis with a sample org including TLS certs:

```bash
cd konfig
./scripts/seed-redis.sh
```

#### 3. Configure Firewall

```bash
# Allow QUIC traffic (UDP 4433)
sudo ufw allow 4433/udp

# Or with iptables
sudo iptables -A INPUT -p udp --dport 4433 -j ACCEPT
```

#### 4. Enable IP Forwarding

```bash
# Temporary (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 5. Create Systemd Service

```bash
sudo tee /etc/systemd/system/quicguard.service << 'EOF'
[Unit]
Description=QuicGuard Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/quicguard/server \
    --listen 0.0.0.0:4433 \
    --server-ip 10.0.0.1 \
    --enable-nat \
    --external-interface eth0
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable quicguard
sudo systemctl start quicguard

# Check status
sudo systemctl status quicguard
sudo journalctl -u quicguard -f
```

### Client Deployment

#### 1. Install Client

```bash
# Create directory
mkdir -p ~/quicguard/certs

# Copy binary and certificate
cp target/release/client ~/quicguard/
cp certs/ca.pem ~/quicguard/certs/
```

#### 2. Create Connection Script

```bash
cat > ~/quicguard/connect.sh << 'EOF'
#!/bin/bash
sudo ~/quicguard/client \
    --server YOUR_SERVER_IP:4433 \
    --server-name localhost \
    --ca-cert ~/quicguard/certs/ca.pem \
    --verbose
EOF

chmod +x ~/quicguard/connect.sh
```

## Usage

### Quick Start

#### Terminal 1 - Server (requires root)

```bash
# Seed Redis first (includes TLS certs)
cd konfig && ./scripts/seed-redis.sh

# Start server
sudo ./target/release/server \
    --enable-nat \
    --external-interface eth0 \
    --verbose
```

#### Terminal 2 - Client (requires root)

```bash
# Connect to server
sudo ./target/release/client \
    --server 192.168.1.100:4433 \
    --ca-cert certs/ca.pem \
    --verbose
```

#### Terminal 3 - Test Connection

```bash
# Ping through tunnel
ping 10.0.0.1

# Check your external IP (should be server's IP)
curl ifconfig.me
```

### Server Options

```
QuicGuard Server

Usage: server [OPTIONS]

Options:
  -l, --listen <LISTEN>
          Listen address (IP:port)
          [default: 0.0.0.0:4433]

  -t, --tun-name <TUN_NAME>
          TUN device name
          [default: masque0]

      --server-ip <SERVER_IP>
          Server tunnel IP address
          [default: 10.0.0.1]

      --subnet-mask <SUBNET_MASK>
          Tunnel subnet mask
          [default: 255.255.255.0]

      --ip-pool-start <IP_POOL_START>
          Starting IP for client allocation
          [default: 10.0.0.2]

      --external-interface <EXTERNAL_INTERFACE>
          External interface for NAT (e.g., eth0, ens3)
          [default: eth0]

      --enable-nat
          Enable NAT for outbound traffic

      --mtu <MTU>
          MTU for the tunnel
          [default: 1400]

      --redis-url <REDIS_URL>
          Redis URL for configuration
          [default: redis://127.0.0.1:6379]

      --redis-org-key <REDIS_ORG_KEY>
          Redis hash key for organization configs
          [default: quicguard:organizations]

      --redis-pubsub-channel <REDIS_PUBSUB_CHANNEL>
          Redis pubsub channel for live config updates
          [default: quicguard:updates]

      --redirect-url <REDIRECT_URL>
          Redirect URL for unauthenticated requests

      --idp-url <IDP_URL>
          Identity Provider URL. Users are redirected here when
          no token, or token is invalid/expired (per-customer).

  -v, --verbose
          Enable verbose logging
```

> **Note:** JWT auth settings (`jwt_issuer`, `jwt_audience`, `jwt_public_key`, `cookie_name`)
> and per-domain TLS certificates are configured per-organization in Redis, not via CLI arguments.
> See [konfig/README.md](konfig/README.md) for the full configuration schema.

### Client Options

```
QuicGuard Client

Usage: client [OPTIONS]

Options:
  -s, --server <SERVER>
          Server address (IP:port)
          [default: 127.0.0.1:4433]

      --server-name <SERVER_NAME>
          Server hostname for TLS verification
          [default: localhost]

      --ca-cert <CA_CERT>
          Path to CA certificate for server verification
          [default: certs/ca.pem]

  -t, --tun-name <TUN_NAME>
          TUN device name
          [default: masque0]

  -i, --ip <IP>
          Request specific tunnel IP

      --default-route
          Set as default route (route all traffic through tunnel)

      --mtu <MTU>
          MTU for the tunnel
          [default: 1400]

  -v, --verbose
          Enable verbose logging

      --insecure
          Skip TLS certificate verification (testing only)
```

## Dashboard

A web-based management dashboard for configuring organizations, users, and policies. The dashboard syncs configurations to Redis in real-time so the running QUIC server picks up changes instantly.

### Quick Start

```bash
# 1. Start Postgres and Redis
cd services && docker compose -f services.yaml up -d
cd ..

# 2. Run the setup script
cd dashboard && bash scripts/setup.sh

# 3. Start the dashboard
cargo run --release
# Dashboard at http://localhost:3000
```

### Features

- **User Management**: Admin can create/approve/delete customer accounts
- **Organization Config**: Structured forms for domains, upstream, auth, TLS, and policies
- **Auto-generation**: JWT key pairs and TLS certificates can be auto-generated
- **Policy Management**: Add/remove org-level and domain-specific access policies
- **Real-time Sync**: Config changes publish to Redis via `quicguard:updates` pubsub channel

### Architecture

```
Svelte SPA ──▶ Axum Backend ──▶ Postgres (users, orgs)
                    │
                    └──────────▶ Redis (pubsub + org configs)
```

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/signup` | None | Register (pending approval) |
| POST | `/api/auth/login` | None | Login, get JWT |
| GET | `/api/auth/me` | Any | Current user info |
| GET | `/api/admin/users` | Admin | List all users |
| PUT | `/api/admin/users/:id/approve` | Admin | Approve user |
| DELETE | `/api/admin/users/:id` | Admin | Delete user |
| GET | `/api/admin/organizations` | Admin | List all orgs |
| GET | `/api/organizations` | Customer | List own orgs |
| POST | `/api/organizations` | Customer | Create org |
| PUT | `/api/organizations/:id` | Customer | Update org |
| DELETE | `/api/organizations/:id` | Customer | Delete org |
| POST | `/api/organizations/:id/policies` | Customer | Add policy |
| DELETE | `/api/organizations/:id/policies/:pid` | Customer | Remove policy |
| POST | `/api/organizations/:id/domain-policies` | Customer | Add domain policy |
| DELETE | `/api/organizations/:id/domain-policies/:domain/:pid` | Customer | Remove domain policy |

### Configuration

Copy `.env.example` to `.env` and configure:

```env
DATABASE_URL=postgres://quicguard:quicguard@localhost:5432/quicguard
REDIS_URL=redis://127.0.0.1:6379
JWT_SECRET=your-secret-key
SERVER_PORT=3000
```

### Testing

```bash
# Unit tests (no dependencies)
cargo test -p dashboard --lib

# Integration tests (requires Postgres)
bash scripts/run-tests.sh

# With Docker for Postgres
bash scripts/run-tests.sh --docker
```

### Frontend Development

```bash
cd frontend
npm install
npm run dev    # Dev server on :5173 with API proxy to :3000
npm run build  # Build to ../static/
```

## IDP Integration

QuicGuard supports Identity Provider (IDP) integration for the HTTP/3 proxy mode. Each customer can configure their own IDP URL.

### How It Works

```
1. User visits proxy → no token cookie
2. Proxy returns 302 → {idp_url}?redirect_uri={original_url}
3. User authenticates at IDP
4. IDP redirects back → {original_url}?token={jwt}
5. Proxy sees ?token= → sets Set-Cookie header → 302 to clean URL
6. Subsequent requests use the cookie
```

### Configuration

Set the `auth` and `tls` fields per organization in Redis:

```json
{
    "auth": {
        "jwt_issuer": "https://auth.example.com",
        "jwt_audience": "quicguard-proxy",
        "jwt_public_key": "...",
        "cookie_name": "session_token",
        "redirect_url": "https://auth.example.com/login",
        "idp_url": "https://auth.example.com/idp"
    },
    "tls": {
        "app.example.com": {
            "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
            "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
        }
    }
}
```

### Behavior

- **Missing token**: 302 redirect to `{idp_url}?redirect_uri={encoded_url}`
- **Invalid/expired token**: Same 302 redirect to IDP
- **Token in query param** (`?token=jwt`): Sets `Set-Cookie` with `HttpOnly; Secure; SameSite=Lax`, then 302 redirects to clean URL
- **Valid token in cookie**: Normal proxy flow
- If `idp_url` is empty, falls back to `redirect_url`. If both are empty, returns 401.
