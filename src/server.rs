// QuicGuard Uses s2n-quic for HTTP/3 QUIC transport

mod protocol;
mod tun_device;
mod certs;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use protocol::{Message, MessageType, MAX_PACKET_SIZE};
use s2n_quic::provider::limits::Limits;
use s2n_quic::Server;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use tun_device::{enable_ip_forwarding, setup_nat, TunDevice, TunWriter};

#[derive(Parser, Debug)]
#[command(author, version, about = "QuicGuard")]
struct Args {
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

    /// External interface for NAT (e.g., eth0)
    #[arg(long, default_value = "eth0")]
    external_interface: String,

    /// Enable NAT for outbound traffic
    #[arg(long)]
    enable_nat: bool,

    /// MTU for the tunnel
    #[arg(long, default_value = "1400")]
    mtu: u16,

    /// Generate self-signed certificates if not present
    #[arg(long)]
    generate_certs: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

}

/// Client session information
struct ClientSession {
    client_id: [u8; 16],
    assigned_ip: Ipv4Addr,
    tx: mpsc::Sender<Vec<u8>>,
}

/// IP address pool manager
struct IpPool {
    next_ip: Ipv4Addr,
    allocated: HashMap<Ipv4Addr, [u8; 16]>, // IP -> client_id
}

impl IpPool {
    fn new(start: Ipv4Addr) -> Self {
        Self {
            next_ip: start,
            allocated: HashMap::new(),
        }
    }

    fn allocate(&mut self, client_id: [u8; 16], requested: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        // If client requested specific IP and it's available, use it
        if let Some(ip) = requested {
            if !self.allocated.contains_key(&ip) {
                self.allocated.insert(ip, client_id);
                return Some(ip);
            }
        }

        // Allocate next available IP
        let ip = self.next_ip;
        self.allocated.insert(ip, client_id);
        
        // Increment for next allocation
        let octets = self.next_ip.octets();
        self.next_ip = Ipv4Addr::new(
            octets[0],
            octets[1],
            octets[2],
            octets[3].wrapping_add(1),
        );
        
        Some(ip)
    }

    fn release(&mut self, ip: Ipv4Addr) {
        self.allocated.remove(&ip);
    }

    fn get_client_by_ip(&self, ip: Ipv4Addr) -> Option<[u8; 16]> {
        self.allocated.get(&ip).copied()
    }
}

type ClientMap = Arc<RwLock<HashMap<[u8; 16], ClientSession>>>;
type IpToClientMap = Arc<RwLock<HashMap<Ipv4Addr, [u8; 16]>>>;


fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    info!("Starting QuicGuard");
    info!("Listen address: {}", args.listen);

    // Run the server
    tokio_uring::start(async {
    run_server(args).await
    })
}

async fn run_server(args: Args) -> Result<()> {
    // Generate certificates if requested and not present
    if args.generate_certs {
        certs::generate_certificates(&args.cert, &args.key, "localhost")?;
        
        // Also generate CA cert for client
        let ca_path = args.cert.parent().unwrap_or(std::path::Path::new(".")).join("ca.pem");
        std::fs::copy(&args.cert, &ca_path)?;
        info!("Copied certificate to {:?} for client use", ca_path);
    }

    // Enable IP forwarding
    if let Err(e) = enable_ip_forwarding() {
        warn!("Failed to enable IP forwarding: {}. You may need root privileges.", e);
    }

    // Setup NAT if requested
    if args.enable_nat {
        let network = format!("{}/{}", args.server_ip, netmask_to_cidr(args.subnet_mask));
        if let Err(e) = setup_nat(&network, &args.external_interface) {
            warn!("Failed to setup NAT: {}. You may need root privileges.", e);
        }
    }

    let tun = TunDevice::new(&args.tun_name).await?;

    let tun_name = tun.name().to_string();

    TunDevice::configure(&tun_name, args.server_ip, args.subnet_mask, args.mtu)?;
    info!("TUN device {} configured", tun_name);

    // Split TUN into read and write halves to avoid lock contention
    let (tun_reader, tun_writer) = tun.split();

    // Configure connection limits for better performance
    let limits = Limits::new()
        .with_max_idle_timeout(Duration::from_secs(30))?
        .with_data_window(2 * 1024 * 1024)?  // 2MB receive window
        .with_max_send_buffer_size(2 * 1024 * 1024)?;  // 2MB send buffer

    // Build QUIC server with tuned limits
    let server = Server::builder()
        .with_tls((args.cert.as_path(), args.key.as_path()))?
        .with_io(args.listen)?
        .with_limits(limits)?
        .start()
        .map_err(|e| anyhow::anyhow!("Failed to start server: {}", e))?;

    info!("QUIC server listening on {}", args.listen);

    // Shared state
    let clients: ClientMap = Arc::new(RwLock::new(HashMap::new()));
    let ip_to_client: IpToClientMap = Arc::new(RwLock::new(HashMap::new()));
    let ip_pool = Arc::new(Mutex::new(IpPool::new(args.ip_pool_start)));

    // Channel for sending packets from TUN to clients (not used in current impl but reserved)
    let (_tun_broadcast_tx, _) = tokio::sync::broadcast::channel::<(Ipv4Addr, Vec<u8>)>(1000);
    
    // Wrap TUN reader in Arc<Mutex> for the reader task (only one reader)
    let tun_reader = Arc::new(Mutex::new(tun_reader));
    // Wrap TUN writer in Arc<Mutex> for sharing among client handlers
    let tun_writer = Arc::new(Mutex::new(tun_writer));

    // Clone for TUN reader task
    let tun_reader_handle = Arc::clone(&tun_reader);
    let clients_for_tun = Arc::clone(&clients);
    let ip_to_client_for_tun = Arc::clone(&ip_to_client);

    // Task: Read from TUN and route to appropriate client
    let tun_read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            let n = {
                let mut tun = tun_reader_handle.lock().await;
                match tun.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    Ok(_) => continue,
                    Err(e) => {
                        error!("Error reading from TUN: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        continue;
                    }
                }
            };

            // Extract destination IP from packet
            if let Some(dest_ip) = protocol::extract_dest_ip(&buf[..n]) {
                if let std::net::IpAddr::V4(dest_ipv4) = dest_ip {
                    // Find client with this IP
                    let client_id = {
                        let ip_map = ip_to_client_for_tun.read().await;
                        ip_map.get(&dest_ipv4).copied()
                    };

                    if let Some(client_id) = client_id {
                        let clients = clients_for_tun.read().await;
                        if let Some(session) = clients.get(&client_id) {
                            if let Err(e) = session.tx.send(buf[..n].to_vec()).await {
                                debug!("Failed to send to client: {}", e);
                            }
                        }
                    } else {
                        debug!("No client found for destination IP: {}", dest_ipv4);
                    }
                }
            }
        }
    });

    // Accept connections
    let mut server = server;
    let server_ip = args.server_ip;
    let subnet_mask = args.subnet_mask;

    while let Some(connection) = server.accept().await {
        let clients = Arc::clone(&clients);
        let ip_to_client = Arc::clone(&ip_to_client);
        let ip_pool = Arc::clone(&ip_pool);
        let tun_writer = Arc::clone(&tun_writer);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                connection,
                clients,
                ip_to_client,
                ip_pool,
                tun_writer,
                server_ip,
                subnet_mask,
            )
            .await
            {
                error!("Connection error: {}", e);
            }
        });
    }

    tun_read_task.abort();
    Ok(())
}

async fn handle_connection(
    mut connection: s2n_quic::Connection,
    clients: ClientMap,
    ip_to_client: IpToClientMap,
    ip_pool: Arc<Mutex<IpPool>>,
    tun_writer: Arc<Mutex<TunWriter>>,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
) -> Result<()> {
    let remote_addr = connection.remote_addr()?;
    info!("New connection from {}", remote_addr);

    // Keep connection alive
    connection.keep_alive(true)?;

    // Accept bidirectional stream
    let stream = connection
        .accept_bidirectional_stream()
        .await
        .context("Failed to accept stream")?
        .ok_or_else(|| anyhow::anyhow!("No stream available"))?;

    let (mut recv_stream, mut send_stream) = stream.split();

    // Read client hello
    let mut len_buf = [0u8; 4];
    recv_stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv_stream.read_exact(&mut msg_buf).await?;

    let msg = Message::decode(Bytes::from(msg_buf))
        .map_err(|e| anyhow::anyhow!("Failed to decode message: {}", e))?;

    if msg.msg_type != MessageType::ClientHello {
        anyhow::bail!("Expected ClientHello, got {:?}", msg.msg_type);
    }

    let client_hello = msg
        .parse_client_hello()
        .map_err(|e| anyhow::anyhow!("Failed to parse ClientHello: {}", e))?;

    info!("ClientHello from {:?}", client_hello.client_id);

    // Allocate IP for client
    let assigned_ip = {
        let mut pool = ip_pool.lock().await;
        pool.allocate(client_hello.client_id, client_hello.requested_ip)
            .ok_or_else(|| anyhow::anyhow!("Failed to allocate IP"))?
    };

    info!("Assigned IP {} to client", assigned_ip);

    // Send server hello
    let server_hello = Message::server_hello(
        assigned_ip,
        server_ip,
        subnet_mask,
        vec![Ipv4Addr::new(8, 8, 8, 8)], // DNS
    );
    let encoded = server_hello.encode();
    send_stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .await?;
    send_stream.write_all(&encoded).await?;

    // Create channel for sending packets to this client
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);

    // Register client session
    let session = ClientSession {
        client_id: client_hello.client_id,
        assigned_ip,
        tx,
    };

    {
        let mut clients = clients.write().await;
        clients.insert(client_hello.client_id, session);
    }

    {
        let mut ip_map = ip_to_client.write().await;
        ip_map.insert(assigned_ip, client_hello.client_id);
    }

    let client_id = client_hello.client_id;
    let clients_cleanup = Arc::clone(&clients);
    let ip_to_client_cleanup = Arc::clone(&ip_to_client);
    let ip_pool_cleanup = Arc::clone(&ip_pool);

    // Cleanup function
    let cleanup = || async move {
        info!("Cleaning up client session for IP {}", assigned_ip);
        {
            let mut clients = clients_cleanup.write().await;
            clients.remove(&client_id);
        }
        {
            let mut ip_map = ip_to_client_cleanup.write().await;
            ip_map.remove(&assigned_ip);
        }
        {
            let mut pool = ip_pool_cleanup.lock().await;
            pool.release(assigned_ip);
        }
    };

    // Task: Send packets from channel to QUIC stream
    let quic_sender = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            let msg = Message::ip_packet(data);
            let encoded = msg.encode();

            if let Err(e) = send_stream
                .write_all(&(encoded.len() as u32).to_be_bytes())
                .await
            {
                error!("Error writing to QUIC: {}", e);
                break;
            }
            if let Err(e) = send_stream.write_all(&encoded).await {
                error!("Error writing to QUIC: {}", e);
                break;
            }
        }
    });

    // Task: Receive packets from QUIC stream and write to TUN
    let tun_writer_for_recv = Arc::clone(&tun_writer);
    let quic_receiver = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            match recv_stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) => {
                    info!("Client disconnected: {}", e);
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
                    info!("Client disconnected: {}", e);
                    break;
                }
            }

            match Message::decode(Bytes::from(msg_buf)) {
                Ok(msg) => match msg.msg_type {
                    MessageType::IpPacket => {
                        debug!("Received {} bytes from client", msg.payload.len());
                        let mut tun = tun_writer_for_recv.lock().await;
                        if let Err(e) = tun.write(&msg.payload).await {
                            error!("Error writing to TUN: {}", e);
                        }
                    }
                    MessageType::Keepalive => {
                        debug!("Received keepalive from client");
                    }
                    MessageType::Disconnect => {
                        info!("Client requested disconnect");
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

    // Wait for either task to complete
    tokio::select! {
        _ = quic_sender => {},
        _ = quic_receiver => {},
    }

    // Cleanup
    cleanup().await;

    Ok(())
}

fn netmask_to_cidr(netmask: Ipv4Addr) -> u8 {
    let octets = netmask.octets();
    let mut cidr = 0u8;
    for octet in octets {
        cidr += octet.count_ones() as u8;
    }
    cidr
}
