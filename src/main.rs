// QuicGuard using HTTP/3 QUIC
// This file provides a unified entry point for both client and server modes

mod protocol;
mod tun_device;

use clap::{Parser, Subcommand};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "QuicGuard")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as QuicGuard server
    Server {
        /// Listen address (IP:port)
        #[arg(short, long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,

        /// TUN device name
        #[arg(short, long, default_value = "quicguard0")]
        tun_name: String,

        /// Server tunnel IP address
        #[arg(long, default_value = "10.0.0.1")]
        server_ip: Ipv4Addr,

        /// Tunnel subnet mask
        #[arg(long, default_value = "255.255.255.0")]
        subnet_mask: Ipv4Addr,

        /// Starting IP for client allocation
        #[arg(long, default_value = "10.0.0.2")]
        ip_pool_start: Ipv4Addr,

        /// External interface for NAT
        #[arg(long, default_value = "eth0")]
        external_interface: String,

        /// Enable NAT for outbound traffic
        #[arg(long)]
        enable_nat: bool,

        /// MTU for the tunnel
        #[arg(long, default_value = "1400")]
        mtu: u16,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run as QuicGuard client
    Client {
        /// Server address (IP:port)
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        server: SocketAddr,

        /// Server hostname for TLS verification
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Path to CA certificate
        #[arg(long, default_value = "certs/ca.pem")]
        ca_cert: PathBuf,

        /// TUN device name
        #[arg(short, long, default_value = "quicguard0")]
        tun_name: String,

        /// Request specific tunnel IP
        #[arg(short, long)]
        ip: Option<Ipv4Addr>,

        /// Set as default route
        #[arg(long)]
        default_route: bool,

        /// MTU for the tunnel
        #[arg(long, default_value = "1400")]
        mtu: u16,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,

        /// Skip TLS verification (insecure)
        #[arg(long)]
        insecure: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { .. } => {
            eprintln!("Please run the server binary directly: cargo run --bin server");
            eprintln!("Or use: cargo run --bin server -- --help");
        }
        Commands::Client { .. } => {
            eprintln!("Please run the client binary directly: cargo run --bin client");
            eprintln!("Or use: cargo run --bin client -- --help");
        }
    }
}
