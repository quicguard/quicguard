# QuicGuard - WireGuard-like VPN using HTTP/3 QUIC

A high-performance VPN implementation inspired by WireGuard, built using HTTP/3 QUIC protocol with the s2n-quic library. This project tunnels IP packets over QUIC streams, providing encrypted communication.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Building](#building)
- [Deployment](#deployment)
- [Usage](#usage)

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

#### 2. Generate Certificates

```bash
# Generate self-signed certificates
cd /opt/quicguard
sudo ./server --generate-certs

# Or use your own certificates
sudo cp /path/to/your/server.pem certs/
sudo cp /path/to/your/server.key certs/

# For clients, copy the CA certificate
sudo cp certs/server.pem certs/ca.pem
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
    --cert /opt/quicguard/certs/server.pem \
    --key /opt/quicguard/certs/server.key \
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
# Generate certificates and start server
sudo ./target/release/server \
    --generate-certs \
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

      --cert <CERT>
          Path to server certificate
          [default: certs/server.pem]

      --key <KEY>
          Path to server private key
          [default: certs/server.key]

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

      --generate-certs
          Generate self-signed certificates if not present

  -v, --verbose
          Enable verbose logging
```

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
