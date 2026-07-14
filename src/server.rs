// QuicGuard Uses s2n-quic for HTTP/3 QUIC transport

mod html;
mod http3;
mod protocol;
mod s2n_h3;
mod tun_device;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use konfig::{AuthConfig, ProxyState, RedisConfig};
use protocol::{Message, MessageType, MAX_PACKET_SIZE};
use s2n_quic::provider::limits::Limits;
use s2n_quic::Server;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use tun_device::{enable_ip_forwarding, setup_nat, TunDevice, TunWriter};

type TlsConfigCache = Arc<Mutex<HashMap<String, s2n_quic::provider::tls::s2n_tls::config::Config>>>;

/// Per-domain TLS certificate loader with background preloading.
///
/// A shared cache holds pre-built `config::Config` per domain. Configs are built
/// at startup via `preload_tls_configs` and refreshed directly when a Redis
/// pubsub update is received. The `load` method performs only a fast cache
/// lookup — no on-demand TLS building.
struct DomainCertLoader {
    state: Arc<ProxyState>,
    cache: TlsConfigCache,
}

impl DomainCertLoader {
    fn new(state: Arc<ProxyState>, cache: TlsConfigCache) -> Self {
        Self {
            state,
            cache,
        }
    }

    async fn build_config_for_domain(
        state: &ProxyState,
        domain: &str,
    ) -> Result<s2n_quic::provider::tls::s2n_tls::config::Config> {
        use s2n_quic::provider::tls::s2n_tls::security::DEFAULT_TLS13;

        let (cert_pem, key_pem) = {
            let org_index = state.org_index.read().await;
            let org_id = org_index.get(domain).ok_or_else(|| {
                anyhow::anyhow!("No organization configured for domain '{domain}'")
            })?;
            let orgs = state.config.read().await;
            let org = orgs.organizations.get(org_id).ok_or_else(|| {
                anyhow::anyhow!("Organization '{org_id}' not found for domain '{domain}'")
            })?;
            let domain_config = org.domains.get(domain).ok_or_else(|| {
                anyhow::anyhow!(
                    "No configuration for domain '{domain}' in org '{org_id}'"
                )
            })?;
            let tls = &domain_config.tls;
            if tls.cert_pem.is_empty() || tls.key_pem.is_empty() {
                anyhow::bail!(
                    "Empty TLS certificate or key for domain '{domain}' in org '{org_id}'"
                );
            }
            (tls.cert_pem.clone(), tls.key_pem.clone())
        };

        let mut builder = s2n_quic::provider::tls::s2n_tls::config::Builder::new();
        builder
            .set_security_policy(&DEFAULT_TLS13)
            .context("Failed to set TLS security policy")?;
        builder
            .enable_quic()
            .context("Failed to enable QUIC in TLS config")?;
        builder
            .set_application_protocol_preference([b"h3".as_slice(), b"quicguard/0.1".as_slice()])
            .context("Failed to set ALPN")?;
        builder
            .load_pem(cert_pem.as_bytes(), key_pem.as_bytes())
            .with_context(|| format!("Failed to load TLS cert for domain '{domain}'"))?;

        builder.build().context("Failed to build TLS config")
    }
}

impl s2n_quic::provider::tls::s2n_tls::ConfigLoader for DomainCertLoader {
    fn load(
        &mut self,
        cx: s2n_quic::provider::tls::s2n_tls::ConnectionContext,
    ) -> s2n_quic::provider::tls::s2n_tls::config::Config {
        let domain = cx
            .server_name
            .map(|s| s.to_string())
            .unwrap_or_default();

        let configs = self.cache.blocking_lock();
        match configs.get(&domain) {
            Some(config) => config.clone(),
            None => {
                error!("TLS config not preloaded for domain '{domain}' — connection will fail");
                s2n_quic::provider::tls::s2n_tls::config::Builder::new()
                    .build()
                    .expect("failed to build empty TLS config")
            }
        }
    }
}

/// Preload TLS configs for all domains in ProxyState into the shared cache.
/// Called once at startup.
async fn preload_tls_configs(state: &ProxyState, cache: &TlsConfigCache) {
    let domains: Vec<String> = {
        let org_index = state.org_index.read().await;
        org_index.keys().cloned().collect()
    };

    let mut new_configs = HashMap::new();
    for domain in &domains {
        // Skip if already cached
        {
            let configs = cache.lock().await;
            if configs.contains_key(domain) {
                continue;
            }
        }

        match DomainCertLoader::build_config_for_domain(state, domain).await {
            Ok(config) => {
                new_configs.insert(domain.clone(), config);
                info!("Preloaded TLS config for domain: {domain}");
            }
            Err(e) => {
                warn!("Failed to preload TLS config for domain '{domain}': {e}");
            }
        }
    }

    if !new_configs.is_empty() {
        let mut configs = cache.lock().await;
        for (domain, config) in new_configs {
            configs.insert(domain, config);
        }
    }
}

fn build_tls_server(
    proxy_state: Arc<ProxyState>,
    cache: TlsConfigCache,
) -> Result<s2n_quic::provider::tls::s2n_tls::Server<DomainCertLoader>> {
    let loader = DomainCertLoader::new(proxy_state, cache);
    Ok(s2n_quic::provider::tls::s2n_tls::Server::from_loader(loader))
}

#[derive(Parser, Debug)]
#[command(author, version, about = "QuicGuard")]
struct Args {
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

    /// External interface for NAT (e.g., eth0)
    #[arg(long, default_value = "eth0")]
    external_interface: String,

    /// Enable NAT for outbound traffic
    #[arg(long)]
    enable_nat: bool,

    /// MTU for the tunnel
    #[arg(long, default_value = "1400")]
    mtu: u16,

    /// Redis URL for configuration
    #[arg(long, default_value = "redis://127.0.0.1:6379")]
    redis_url: String,

    /// Redis hash key for organization configs
    #[arg(long, default_value = "quicguard:organizations")]
    redis_org_key: String,

    /// Redis pubsub channel for live config updates
    #[arg(long, default_value = "quicguard:updates")]
    redis_pubsub_channel: String,

    /// Redirect URL for unauthenticated requests
    #[arg(long, default_value = "")]
    redirect_url: String,

    /// IDP (Identity Provider) URL for authentication redirects
    #[arg(long, default_value = "")]
    idp_url: String,

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
        self.next_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3].wrapping_add(1));

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
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    info!("Starting QuicGuard");
    info!("Listen address: {}", args.listen);

    // Run the server
    tokio_uring::start(async { run_server(args).await })
}

async fn run_server(args: Args) -> Result<()> {
    // Initialize konfig ProxyState from Redis
    let redis_config = RedisConfig {
        url: args.redis_url.clone(),
        org_key: args.redis_org_key.clone(),
        pubsub_channel: args.redis_pubsub_channel.clone(),
    };

    let auth_config = AuthConfig {
        jwt_issuer: String::new(),
        jwt_audience: String::new(),
        jwks_url: String::new(),
        jwt_public_key: String::new(),
        jwt_private_key: String::new(),
        cookie_name: "session_token".to_string(),
        redirect_url: args.redirect_url.clone(),
        idp_url: args.idp_url.clone(),
        req_param_name: "req".to_string(),
        token_param_name: "token".to_string(),
    };

    let proxy_state = match ProxyState::from_redis(redis_config.clone(), auth_config).await {
        Ok(state) => {
            info!("Loaded configuration from Redis");
            Arc::new(state)
        }
        Err(e) => {
            warn!(
                "Failed to load config from Redis: {}. Starting with empty config.",
                e
            );
            Arc::new(ProxyState::empty(redis_config))
        }
    };

    // Create shared TLS config cache and preload all domains at startup
    let tls_cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));
    preload_tls_configs(&proxy_state, &tls_cache).await;

    // Start Redis subscriber for live config updates
    let (update_tx, mut update_rx) = tokio::sync::mpsc::channel::<konfig::OrgUpdate>(64);
    let subscriber_state = Arc::clone(&proxy_state);
    tokio::spawn(async move {
        if let Err(e) = konfig::redis_subscriber(subscriber_state, update_tx).await {
            error!("Redis subscriber error: {}", e);
        }
    });

    // Task: handle config updates from Redis pubsub — update state + TLS cache
    {
        let state = Arc::clone(&proxy_state);
        let cache = Arc::clone(&tls_cache);
        tokio::spawn(async move {
            while let Some(update) = update_rx.recv().await {
                match update.action.as_str() {
                    "delete" => {
                        // Capture domains before removal for TLS cache cleanup
                        let domains: Vec<String> = {
                            let config = state.config.read().await;
                            config
                                .organizations
                                .get(&update.org_id)
                                .map(|o| o.domains.keys().cloned().collect())
                                .unwrap_or_default()
                        };
                        state.remove_org(&update.org_id).await;
                        let mut configs = cache.lock().await;
                        for domain in &domains {
                            configs.remove(domain);
                            info!("Removed TLS cache for domain: {domain}");
                        }
                    }
                    _ => {
                        if let Some(org) = update.organization {
                            let domains: Vec<String> = org.domains.keys().cloned().collect();
                            state.reload_org(&update.org_id, org).await;
                            // Build TLS configs for each domain in the updated org
                            for domain in &domains {
                                match DomainCertLoader::build_config_for_domain(&state, domain)
                                    .await
                                {
                                    Ok(config) => {
                                        cache.lock().await.insert(domain.clone(), config);
                                        info!("Updated TLS config for domain: {domain}");
                                    }
                                    Err(e) => {
                                        warn!("Failed to build TLS config for domain '{domain}': {e}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // Enable IP forwarding
    if let Err(e) = enable_ip_forwarding() {
        warn!(
            "Failed to enable IP forwarding: {}. You may need root privileges.",
            e
        );
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
        .with_data_window(2 * 1024 * 1024)? // 2MB receive window
        .with_max_send_buffer_size(2 * 1024 * 1024)?; // 2MB send buffer

    let tls = build_tls_server(Arc::clone(&proxy_state), Arc::clone(&tls_cache))?;

    // Build QUIC server with tuned limits
    let server = Server::builder()
        .with_tls(tls)?
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
    //temp commented
    // let tun_read_task = tokio::spawn(async move {
    //     let mut buf = vec![0u8; MAX_PACKET_SIZE];
    //     loop {
    //         let n = {
    //             let mut tun = tun_reader_handle.lock().await;
    //             match tun.read(&mut buf).await {
    //                 Ok(n) if n > 0 => n,
    //                 Ok(_) => continue,
    //                 Err(e) => {
    //                     error!("Error reading from TUN: {}", e);
    //                     tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    //                     continue;
    //                 }
    //             }
    //         };

    //         // Extract destination IP from packet
    //         if let Some(dest_ip) = protocol::extract_dest_ip(&buf[..n]) {
    //             if let std::net::IpAddr::V4(dest_ipv4) = dest_ip {
    //                 // Find client with this IP
    //                 let client_id = {
    //                     let ip_map = ip_to_client_for_tun.read().await;
    //                     ip_map.get(&dest_ipv4).copied()
    //                 };

    //                 if let Some(client_id) = client_id {
    //                     let clients = clients_for_tun.read().await;
    //                     if let Some(session) = clients.get(&client_id) {
    //                         if let Err(e) = session.tx.send(buf[..n].to_vec()).await {
    //                             debug!("Failed to send to client: {}", e);
    //                         }
    //                     }
    //                 } else {
    //                     debug!("No client found for destination IP: {}", dest_ipv4);
    //                 }
    //             }
    //         }
    //     }
    // });

    // Accept connections
    let mut server = server;
    let server_ip = args.server_ip;
    let subnet_mask = args.subnet_mask;

    while let Some(connection) = server.accept().await {
        let clients = Arc::clone(&clients);
        let ip_to_client = Arc::clone(&ip_to_client);
        let ip_pool = Arc::clone(&ip_pool);
        let tun_writer = Arc::clone(&tun_writer);
        let proxy_state = Arc::clone(&proxy_state);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                connection,
                clients,
                ip_to_client,
                ip_pool,
                tun_writer,
                server_ip,
                subnet_mask,
                proxy_state,
            )
            .await
            {
                error!("Connection error: {}", e);
            }
        });
    }

    //tun_read_task.abort();
    Ok(())
}

async fn read_message(recv_stream: &mut s2n_quic::stream::ReceiveStream) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    recv_stream.read_exact(&mut len_buf).await?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    let mut msg_buf = vec![0u8; msg_len];
    recv_stream.read_exact(&mut msg_buf).await?;
    let msg = Message::decode(Bytes::from(msg_buf))
        .map_err(|e| anyhow::anyhow!("Failed to decode message: {}", e))?;
    return Ok(msg);
}
async fn handle_connection(
    mut connection: s2n_quic::Connection,
    clients: ClientMap,
    ip_to_client: IpToClientMap,
    ip_pool: Arc<Mutex<IpPool>>,
    tun_writer: Arc<Mutex<TunWriter>>,
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    proxy_state: Arc<ProxyState>,
) -> Result<()> {
    let remote_addr = connection.remote_addr()?;
    info!("New connection from {}", remote_addr);
    let alpn_byte = connection
        .application_protocol()
        .context("Faild to read ALPN")?;
    let alpn = std::str::from_utf8(&alpn_byte)?;
    info!("ALPN: {}", alpn);
    if alpn == "h3" {
        // Wrap the raw s2n-quic connection in the h3 adapter
        let h3_conn = s2n_h3::H3Connection::new(connection);
        info!("h3_conn created");

        // Build the h3 server connection
        let mut h3_server_conn = h3::server::Connection::<_, Bytes>::new(h3_conn)
            .await
            .context("Failed to build h3 server connection")?;
        info!("h3_server_conn created");

        // Build the hyper client once
        use hyper_util::client::legacy::connect::HttpConnector;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;
        type HttpClient =
            Client<HttpConnector, http_body_util::combinators::BoxBody<Bytes, std::io::Error>>;
        let client: HttpClient = Client::builder(TokioExecutor::new()).build(HttpConnector::new());

        // Accept requests in a loop (handles keep-alive / multiple requests per connection)
        loop {
            match h3_server_conn.accept().await {
                Ok(Some(resolver)) => {
                    info!("resolver created");
                    let client = client.clone();

                    // Drive the connection AND the request together.
                    // h3_server_conn.accept() keeps polling the QUIC state machine,
                    // which is what actually flushes the send buffer after finish().
                    // Without this, dropping h3_server_conn tears down the connection
                    // before QUIC has delivered the last bytes to the peer.
                    let result = tokio::join!(
                        // Left: keep the connection driver alive
                        async {
                            // After the request task finishes we'll break out of the
                            // loop, but until then we must keep polling accept() so
                            // the QUIC layer can flush outstanding data.
                            h3_server_conn.accept().await
                        },
                        // Right: handle the request
                        async {
                            http3::process_h3_request(resolver, client, "", proxy_state.clone()).await
                        }
                    );

                    match result {
                        (_, Ok(url)) => {
                            info!("HTTP/3 request URL: {}", url);
                        }
                        (_, Err(e)) => {
                            tracing::error!("request failed: {e}");
                        }
                    }
                }
                Ok(None) => {
                    info!("h3 connection closed");
                    break;
                }
                Err(e) => {
                    tracing::error!("h3 accept error: {e}");
                    break;
                }
            }
        }
    } else {
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
        let msg = read_message(&mut recv_stream).await;

        //It's vpn request
        info!("Connection type: VPN");
        let msg = msg.unwrap();
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
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use konfig::{AuthConfig, DomainConfig, Organization, RedisConfig, TlsConfig, UpstreamConfig};
    use s2n_quic::provider::tls::s2n_tls::ConfigLoader as _;

    const CERT_A: &str = "-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIULG5l5gELKiyq/u4XeqiEL7U/XMEwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPYXBwLmV4YW1wbGUuY29tMB4XDTI2MDYzMDEzNTU0M1oXDTM2
MDYyNzEzNTU0M1owGjEYMBYGA1UEAwwPYXBwLmV4YW1wbGUuY29tMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEFV7aJg5M1DT/Mfy63DcQlwt0Tt9h7rjtInR2GPJz
pXgEmTXDlcSRlEQnxL/5NYTfr7CxOwmn3whupbCdbGDopaNvMG0wHQYDVR0OBBYE
FCqVnRJunA4kC2Ut2Ekrh/lf/RvDMB8GA1UdIwQYMBaAFCqVnRJunA4kC2Ut2Ekr
h/lf/RvDMA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIPYXBwLmV4YW1wbGUu
Y29tMAoGCCqGSM49BAMCA0gAMEUCIQDHQncFsh5NIvrev5W3ybRErc7B8K1nuX33
cgj60qlkPQIgHMjqPPWzzmz7fv740Lt452KA7cLhFcIBoTxtJ+Kslyo=
-----END CERTIFICATE-----";

    const KEY_A: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgU3BXdn1LdVQ+BWxN
U+IsO1Qz3hmArsfI7ZwV88t9wgmhRANCAAQVXtomDkzUNP8x/LrcNxCXC3RO32Hu
uO0idHYY8nOleASZNcOVxJGURCfEv/k1hN+vsLE7CaffCG6lsJ1sYOil
-----END PRIVATE KEY-----";

    const CERT_B: &str = "-----BEGIN CERTIFICATE-----
MIIBqzCCAVGgAwIBAgIUKGuCatpSJUetWLqfI+dD/pWD8sswCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRb3RoZXIuZXhhbXBsZS5jb20wHhcNMjYwNjMwMTM1NTQzWhcN
MzYwNjI3MTM1NTQzWjAcMRowGAYDVQQDDBFvdGhlci5leGFtcGxlLmNvbTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABMTySiLCw3Eo/3NNtWFxneW4nHG4J+jh/eUn
nxsnCWM0DZvRo5fbc5aTEbTWyKraUp2QIMugF+tBWVgiqWCtGnajcTBvMB0GA1Ud
DgQWBBTDfLWKFCc+qbQui2WrXA08k3GKpTAfBgNVHSMEGDAWgBTDfLWKFCc+qbQu
i2WrXA08k3GKpTAPBgNVHRMBAf8EBTADAQH/MBwGA1UdEQQVMBOCEW90aGVyLmV4
YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIQCg8r0pLpH80mvfCjsEhHmiIdu9
FMmdoqD9qvQaoAWgygIgHecxP+m40Ys171QNwJjjfsYGJsFCh22mPdGXLonAiHE=
-----END CERTIFICATE-----";

    const KEY_B: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgb2kYomMfQ7iO1hWg
q+6k53HLaEgUGqHB/8sLTHSYsrShRANCAATE8koiwsNxKP9zTbVhcZ3luJxxuCfo
4f3lJ58bJwljNA2b0aOX23OWkxG01siq2lKdkCDLoBfrQVlYIqlgrRp2
-----END PRIVATE KEY-----";

    fn make_redis() -> RedisConfig {
        RedisConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            org_key: "test:orgs".to_string(),
            pubsub_channel: "test:updates".to_string(),
        }
    }

    fn make_auth() -> AuthConfig {
        AuthConfig {
            jwt_issuer: String::new(),
            jwt_audience: String::new(),
            jwks_url: String::new(),
            jwt_public_key: String::new(),
            jwt_private_key: String::new(),
            cookie_name: "session_token".to_string(),
            redirect_url: String::new(),
            idp_url: String::new(),
            req_param_name: "req".to_string(),
            token_param_name: "token".to_string(),
        }
    }

    fn make_upstream() -> UpstreamConfig {
        UpstreamConfig {
            base_url: "http://127.0.0.1:8080".to_string(),
            timeout_ms: 5000,
            max_retries: 3,
        }
    }

    fn make_org(org_id: &str, domains: Vec<&str>, certs: Vec<(&str, &str, &str)>) -> Organization {
        let cert_map: HashMap<String, (String, String)> = certs
            .into_iter()
            .map(|(domain, cert, key)| {
                (domain.to_string(), (cert.to_string(), key.to_string()))
            })
            .collect();
        let domain_configs: HashMap<String, DomainConfig> = domains
            .into_iter()
            .map(|d| {
                let (cert_pem, key_pem) = cert_map.get(d)
                    .map(|(c, k)| (c.clone(), k.clone()))
                    .unwrap_or_default();
                (
                    d.to_string(),
                    DomainConfig {
                        upstream: make_upstream(),
                        tls: TlsConfig { cert_pem, key_pem },
                    },
                )
            })
            .collect();
        Organization {
            id: org_id.to_string(),
            name: format!("Org {org_id}"),
            domains: domain_configs,
            apps: HashMap::new(),
            user_groups: HashMap::new(),
            app_user_groups: HashMap::new(),
            auth: make_auth(),
        }
    }

    async fn make_state(orgs: Vec<Organization>) -> Arc<ProxyState> {
        let state = Arc::new(ProxyState::empty(make_redis()));
        for org in orgs {
            let id = org.id.clone();
            state.reload_org(&id, org).await;
        }
        state
    }

    // ── build_config_for_domain ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_build_config_for_known_domain() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;

        let result = DomainCertLoader::build_config_for_domain(&state, "app.example.com").await;
        assert!(result.is_ok(), "build_config_for_domain failed: {:?}", result.err());
    }

    #[tokio::test]
    async fn test_build_config_for_unknown_domain() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;

        let result = DomainCertLoader::build_config_for_domain(&state, "unknown.example.com").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No organization"));
    }

    #[tokio::test]
    async fn test_build_config_for_domain_without_tls() {
        let org = Organization {
            id: "org-notls".to_string(),
            name: "No TLS Org".to_string(),
            domains: HashMap::from([(
                "notls.example.com".to_string(),
                DomainConfig {
                    upstream: make_upstream(),
                    tls: TlsConfig::default(),
                },
            )]),
            apps: HashMap::new(),
            user_groups: HashMap::new(),
            app_user_groups: HashMap::new(),
            auth: make_auth(),
        };
        let state = make_state(vec![org]).await;

        let result = DomainCertLoader::build_config_for_domain(&state, "notls.example.com").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty TLS certificate"));
    }

    #[tokio::test]
    async fn test_build_config_different_domains_different_certs() {
        let org = make_org(
            "org-multi",
            vec!["app.example.com", "api.example.com"],
            vec![
                ("app.example.com", CERT_A, KEY_A),
                ("api.example.com", CERT_B, KEY_B),
            ],
        );
        let state = make_state(vec![org]).await;

        let config_a = DomainCertLoader::build_config_for_domain(&state, "app.example.com").await;
        let config_b = DomainCertLoader::build_config_for_domain(&state, "api.example.com").await;

        assert!(config_a.is_ok());
        assert!(config_b.is_ok());
    }

    // ── preload_tls_configs ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_preload_populates_cache() {
        let org = make_org(
            "org-a",
            vec!["app.example.com", "api.example.com"],
            vec![
                ("app.example.com", CERT_A, KEY_A),
                ("api.example.com", CERT_B, KEY_B),
            ],
        );
        let state = make_state(vec![org]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        preload_tls_configs(&state, &cache).await;

        let configs = cache.lock().await;
        assert_eq!(configs.len(), 2);
        assert!(configs.contains_key("app.example.com"));
        assert!(configs.contains_key("api.example.com"));
    }

    #[tokio::test]
    async fn test_preload_skips_already_cached() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        preload_tls_configs(&state, &cache).await;
        preload_tls_configs(&state, &cache).await;

        let configs = cache.lock().await;
        assert_eq!(configs.len(), 1);
    }

    #[tokio::test]
    async fn test_preload_after_reload_picks_up_new_domain() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        preload_tls_configs(&state, &cache).await;
        assert_eq!(cache.lock().await.len(), 1);

        // Add a new domain via reload
        let updated = make_org(
            "org-a",
            vec!["app.example.com", "api.example.com"],
            vec![
                ("app.example.com", CERT_A, KEY_A),
                ("api.example.com", CERT_B, KEY_B),
            ],
        );
        state.reload_org("org-a", updated).await;

        // Simulate watcher: remove stale, then preload picks up new domain
        let current_domains: std::collections::HashSet<String> = {
            let org_index = state.org_index.read().await;
            org_index.keys().cloned().collect()
        };
        cache.lock().await.retain(|domain, _| current_domains.contains(domain));
        preload_tls_configs(&state, &cache).await;

        let configs = cache.lock().await;
        assert_eq!(configs.len(), 2);
        assert!(configs.contains_key("app.example.com"));
        assert!(configs.contains_key("api.example.com"));
    }

    #[tokio::test]
    async fn test_preload_clears_stale_entries() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        preload_tls_configs(&state, &cache).await;
        assert_eq!(cache.lock().await.len(), 1);

        state.remove_org("org-a").await;

        // Simulate watcher: remove stale entries, then preload (nothing new to add)
        let current_domains: std::collections::HashSet<String> = {
            let org_index = state.org_index.read().await;
            org_index.keys().cloned().collect()
        };
        cache.lock().await.retain(|domain, _| current_domains.contains(domain));
        preload_tls_configs(&state, &cache).await;

        assert_eq!(cache.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_preload_empty_state() {
        let state = make_state(vec![]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        preload_tls_configs(&state, &cache).await;

        assert_eq!(cache.lock().await.len(), 0);
    }

    #[tokio::test]
    async fn test_preload_multiple_orgs() {
        let org_a = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let org_b = make_org("org-b", vec!["other.example.com"], vec![("other.example.com", CERT_B, KEY_B)]);
        let state = make_state(vec![org_a, org_b]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        preload_tls_configs(&state, &cache).await;

        let configs = cache.lock().await;
        assert_eq!(configs.len(), 2);
        assert!(configs.contains_key("app.example.com"));
        assert!(configs.contains_key("other.example.com"));
    }

    // ── DomainCertLoader cache integration ───────────────────────────────────

    #[tokio::test]
    async fn test_loader_returns_cached_config_on_hit() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        // Preload
        preload_tls_configs(&state, &cache).await;

        // Verify the cache has the config
        let configs = cache.lock().await;
        assert!(configs.contains_key("app.example.com"));
    }

    #[tokio::test]
    async fn test_loader_cache_miss_triggers_build() {
        let org = make_org("org-a", vec!["app.example.com"], vec![("app.example.com", CERT_A, KEY_A)]);
        let state = make_state(vec![org]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        // Empty cache
        assert!(!cache.lock().await.contains_key("app.example.com"));

        // Build on demand (simulates what load() does on cache miss)
        let config = DomainCertLoader::build_config_for_domain(&state, "app.example.com").await;
        assert!(config.is_ok());

        // Insert into cache (simulates load() caching the result)
        cache.lock().await.insert("app.example.com".to_string(), config.unwrap());
        assert!(cache.lock().await.contains_key("app.example.com"));
    }

    #[tokio::test]
    async fn test_loader_unknown_domain_does_not_cache() {
        let state = make_state(vec![]).await;
        let cache: TlsConfigCache = Arc::new(Mutex::new(HashMap::new()));

        let result = DomainCertLoader::build_config_for_domain(&state, "unknown.example.com").await;
        assert!(result.is_err());

        // Should NOT be in cache
        assert!(!cache.lock().await.contains_key("unknown.example.com"));
    }
}
