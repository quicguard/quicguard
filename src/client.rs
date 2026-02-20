// QuicGuard Uses s2n-quic for HTTP/3 QUIC transport

mod protocol;
mod tun_device;
mod certs;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use protocol::{Message, MessageType, MAX_PACKET_SIZE};
use s2n_quic::provider::limits::Limits;
use s2n_quic::{client::Connect, Client};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tun_device::TunDevice;

#[derive(Parser, Debug)]
#[command(author, version, about = "QuicGuard Client")]
struct Args {
    /// Server address (IP:port)
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    server: SocketAddr,

    /// Server hostname for TLS verification
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Path to CA certificate for server verification
    #[arg(long, default_value = "certs/ca.pem")]
    ca_cert: PathBuf,

    /// TUN device name
    #[arg(short, long, default_value = "quicguard0")]
    tun_name: String,

    /// Request specific tunnel IP
    #[arg(short, long)]
    ip: Option<Ipv4Addr>,

    /// Set as default route (route all traffic through tunnel)
    #[arg(long)]
    default_route: bool,

    /// MTU for the tunnel
    #[arg(long, default_value = "1400")]
    mtu: u16,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Skip TLS certificate verification (insecure, for testing only)
    #[arg(long)]
    insecure: bool,
}


fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    info!("Starting QuicGuard Client");
    info!("Connecting to server: {}", args.server);

    // Run the client
    tokio_uring::start(async {
        run_client(args).await
    })
}

async fn run_client(args: Args) -> Result<()> {
    // Build QUIC client
    let client = build_client(&args).await?;

    // Connect to server
    info!("Establishing QUIC connection to {}", args.server);
    let connect = Connect::new(args.server)
        .with_server_name(args.server_name.as_str());
    
    let mut connection = client
        .connect(connect)
        .await
        .context("Failed to connect to server")?;

    info!("QUIC connection established");

    // Keep connection alive
    connection.keep_alive(true)?;

    // Open bidirectional stream for control messages
    let stream = connection
        .open_bidirectional_stream()
        .await
        .context("Failed to open bidirectional stream")?;

    let (mut recv_stream, mut send_stream) = stream.split();

    // Generate client ID
    let client_id: [u8; 16] = rand::random();

    // Send client hello
    let hello_msg = Message::client_hello(client_id, args.ip);
    let encoded = hello_msg.encode();
    send_stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .await?;
    send_stream.write_all(&encoded).await?;
    info!("Sent ClientHello");

    // Wait for server hello
    let mut len_buf = [0u8; 4];
    recv_stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv_stream.read_exact(&mut msg_buf).await?;

    let response = Message::decode(Bytes::from(msg_buf))
        .map_err(|e| anyhow::anyhow!("Failed to decode server response: {}", e))?;

    if response.msg_type != MessageType::ServerHello {
        anyhow::bail!("Expected ServerHello, got {:?}", response.msg_type);
    }

    let server_hello = response
        .parse_server_hello()
        .map_err(|e| anyhow::anyhow!("Failed to parse ServerHello: {}", e))?;

    info!("Received ServerHello:");
    info!("  Assigned IP: {}", server_hello.assigned_ip);
    info!("  Server IP: {}", server_hello.server_ip);
    info!("  Subnet: {}", server_hello.subnet_mask);

    // Create and configure TUN device
    let tun = TunDevice::new(&args.tun_name).await?;
    let tun_name = tun.name().to_string();
    TunDevice::configure(&tun_name, server_hello.assigned_ip, server_hello.subnet_mask, args.mtu)?;

    if args.default_route {
        // Add route to server first (so we don't lose connectivity)
        info!("Setting up routing for full tunnel mode");
        // TODO: Add route to server via original gateway
        tun.set_default_route(server_hello.server_ip)?;
    }

    info!("TUN device {} configured and ready", args.tun_name);

    // Create channels for communication between tasks
    let (tun_to_quic_tx, mut tun_to_quic_rx) = mpsc::channel::<Vec<u8>>(1000);
    let (quic_to_tun_tx, mut quic_to_tun_rx) = mpsc::channel::<Vec<u8>>(1000);

    // Split TUN into read and write halves to avoid lock contention
    let (mut tun_read_half, mut tun_write_half) = tun.split();

    // Task: Read from TUN, send to channel
    let tun_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            match tun_read_half.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if tun_to_quic_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(_) => continue,
                Err(e) => {
                    error!("Error reading from TUN: {}", e);
                    break;
                }
            }
        }
    });

    // Task: Receive from channel, write to TUN
    let tun_writer = tokio::spawn(async move {
        while let Some(data) = quic_to_tun_rx.recv().await {
            if let Err(e) = tun_write_half.write(&data).await {
                error!("Error writing to TUN: {}", e);
                break;
            }
        }
    });

    // Task: Read from channel, send to QUIC stream
    let quic_sender = tokio::spawn(async move {
        while let Some(data) = tun_to_quic_rx.recv().await {
            let msg = Message::ip_packet(data);
            let encoded = msg.encode();
            
            if let Err(e) = send_stream.write_all(&(encoded.len() as u32).to_be_bytes()).await {
                error!("Error writing length to QUIC: {}", e);
                break;
            }
            if let Err(e) = send_stream.write_all(&encoded).await {
                error!("Error writing to QUIC: {}", e);
                break;
            }
            debug!("Sent {} bytes to server", encoded.len());
        }
    });

    // Task: Read from QUIC stream, send to channel
    let quic_receiver = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            match recv_stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Error reading from QUIC: {}", e);
                    break;
                }
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;
            if msg_len > MAX_PACKET_SIZE + 100 {
                error!("Message too large: {} bytes", msg_len);
                continue;
            }

            let mut msg_buf = vec![0u8; msg_len];
            match recv_stream.read_exact(&mut msg_buf).await {
                Ok(_) => {}
                Err(e) => {
                    error!("Error reading message from QUIC: {}", e);
                    break;
                }
            }

            match Message::decode(Bytes::from(msg_buf)) {
                Ok(msg) => match msg.msg_type {
                    MessageType::IpPacket => {
                        debug!("Received {} bytes from server", msg.payload.len());
                        if quic_to_tun_tx.send(msg.payload.to_vec()).await.is_err() {
                            break;
                        }
                    }
                    MessageType::Keepalive => {
                        debug!("Received keepalive");
                    }
                    MessageType::Disconnect => {
                        info!("Server requested disconnect");
                        break;
                    }
                    _ => {
                        warn!("Unexpected message type: {:?}", msg.msg_type);
                    }
                },
                Err(e) => {
                    error!("Failed to decode message: {}", e);
                }
            }
        }
    });

    // Wait for any task to complete (which indicates a problem)
    tokio::select! {
        _ = tun_reader => info!("TUN reader stopped"),
        _ = tun_writer => info!("TUN writer stopped"),
        _ = quic_sender => info!("QUIC sender stopped"),
        _ = quic_receiver => info!("QUIC receiver stopped"),
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down");
        }
    }

    info!("Client shutting down");
    Ok(())
}

async fn build_client(args: &Args) -> Result<Client> {
    if args.insecure {
        warn!("TLS verification disabled - this is insecure!");
    }

    // Load CA certificate for server verification
    if !args.ca_cert.exists() {
        anyhow::bail!(
            "CA certificate not found at {:?}. Generate certificates first or use --insecure",
            args.ca_cert
        );
    }

    // Configure connection limits for better performance
    let limits = Limits::new()
        .with_max_idle_timeout(Duration::from_secs(30))?
        .with_data_window(2 * 1024 * 1024)?  // 2MB receive window
        .with_max_send_buffer_size(2 * 1024 * 1024)?;  // 2MB send buffer

    let client = Client::builder()
        .with_tls(args.ca_cert.as_path())?
        .with_io("0.0.0.0:0")?
        .with_limits(limits)?
        .start()
        .map_err(|e| anyhow::anyhow!("Failed to start client: {}", e))?;

    Ok(client)
}

// Simple random generation for client ID
mod rand {
    pub fn random<T: Default + AsMut<[u8]>>() -> T {
        let mut result = T::default();
        let bytes = result.as_mut();
        
        // Use /dev/urandom for random bytes
        if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = file.read_exact(bytes);
        } else {
            // Fallback to time-based seed
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            let seed = now.as_nanos() as u64;
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = ((seed >> (i % 8 * 8)) & 0xFF) as u8;
            }
        }
        
        result
    }
}
