// QuicGuard using HTTP/3 QUIC
// This file provides a unified entry point for both client and server modes

mod protocol;
mod tun_device;
mod certs;

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

        /// Path to server certificate
        #[arg(long, default_value = "certs/server.pem")]
        cert: PathBuf,

        /// Path to server private key
        #[arg(long, default_value = "certs/server.key")]
        key: PathBuf,

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

        /// Generate self-signed certificates
        #[arg(long)]
        generate_certs: bool,

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

    /// Generate certificates for testing
    GenerateCerts {
        /// Output directory
        #[arg(short, long, default_value = "certs")]
        output: PathBuf,

        /// Server hostname
        #[arg(long, default_value = "localhost")]
        hostname: String,
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
        Commands::GenerateCerts { output, hostname } => {
            if let Err(e) = generate_certs(&output, &hostname) {
                eprintln!("Error generating certificates: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn generate_certs(output: &PathBuf, hostname: &str) -> anyhow::Result<()> {
    let cert_path = output.join("server.pem");
    let key_path = output.join("server.key");

    // Remove existing files to force regeneration
    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);

    certs::generate_certificates(&cert_path, &key_path, hostname)?;

    // Copy cert as CA for clients
    let ca_path = output.join("ca.pem");
    std::fs::copy(&cert_path, &ca_path)?;

    println!("Generated certificates in {:?}", output);
    println!("  Server cert: {:?}", cert_path);
    println!("  Server key:  {:?}", key_path);
    println!("  CA cert:     {:?}", ca_path);
    
    Ok(())
}

