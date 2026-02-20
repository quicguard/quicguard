// Comprehensive Server Benchmark
// Tests throughput, latency, and concurrent connections

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::Barrier;

// Include protocol module
#[path = "../src/protocol.rs"]
mod protocol;

#[path = "../src/certs.rs"]
mod certs;

use protocol::{Message, MessageType};

const SERVER_ADDR: &str = "127.0.0.1:4433";
const CERT_PATH: &str = "certs/server.pem";
const KEY_PATH: &str = "certs/server.key";
const CA_PATH: &str = "certs/ca.pem";

/// Benchmark configuration
struct BenchConfig {
    server_addr: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_path: PathBuf,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            server_addr: SERVER_ADDR.parse().unwrap(),
            cert_path: PathBuf::from(CERT_PATH),
            key_path: PathBuf::from(KEY_PATH),
            ca_path: PathBuf::from(CA_PATH),
        }
    }
}

/// Statistics collector for detailed metrics
#[derive(Debug, Default)]
struct BenchStats {
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    latencies_ns: std::sync::Mutex<Vec<u64>>,
}

impl BenchStats {
    fn new() -> Self {
        Self::default()
    }

    fn record_send(&self, bytes: u64) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_receive(&self, bytes: u64) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_latency(&self, latency_ns: u64) {
        if let Ok(mut latencies) = self.latencies_ns.lock() {
            latencies.push(latency_ns);
        }
    }

    fn summary(&self) -> String {
        let sent = self.packets_sent.load(Ordering::Relaxed);
        let recv = self.packets_received.load(Ordering::Relaxed);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_recv = self.bytes_received.load(Ordering::Relaxed);

        let latencies = self.latencies_ns.lock().unwrap();
        let (avg_lat, p50, p95, p99) = if !latencies.is_empty() {
            let mut sorted = latencies.clone();
            sorted.sort();
            let avg = sorted.iter().sum::<u64>() / sorted.len() as u64;
            let p50 = sorted[sorted.len() / 2];
            let p95 = sorted[(sorted.len() as f64 * 0.95) as usize];
            let p99 = sorted[(sorted.len() as f64 * 0.99) as usize];
            (avg, p50, p95, p99)
        } else {
            (0, 0, 0, 0)
        };

        format!(
            "Packets: sent={}, recv={}, Bytes: sent={}, recv={}\n\
             Latency (ns): avg={}, p50={}, p95={}, p99={}",
            sent, recv, bytes_sent, bytes_recv, avg_lat, p50, p95, p99
        )
    }
}

/// Create a mock QUIC client for benchmarking with timeout
async fn create_bench_client(
    config: &BenchConfig,
) -> anyhow::Result<s2n_quic::Connection> {
    use s2n_quic::client::Connect;
    use s2n_quic::provider::limits::Limits;
    use s2n_quic::Client;

    let limits = Limits::new()
        .with_max_idle_timeout(Duration::from_secs(2))?
        .with_data_window(2 * 1024 * 1024)?
        .with_max_send_buffer_size(2 * 1024 * 1024)?;

    let client = Client::builder()
        .with_tls(config.ca_path.as_path())?
        .with_io("0.0.0.0:0")?
        .with_limits(limits)?
        .start()
        .map_err(|e| anyhow::anyhow!("Failed to start client: {}", e))?;

    let connect = Connect::new(config.server_addr).with_server_name("localhost");

    // Add timeout for connection attempt
    let connection = tokio::time::timeout(
        Duration::from_secs(1),
        client.connect(connect)
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout - is the server running?"))?
    .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;
    
    Ok(connection)
}

/// Perform handshake and return the stream (with timeout)
async fn perform_handshake(
    connection: &mut s2n_quic::Connection,
) -> anyhow::Result<(
    s2n_quic::stream::ReceiveStream,
    s2n_quic::stream::SendStream,
)> {
    // Wrap entire handshake in timeout
    tokio::time::timeout(Duration::from_secs(1), async {
        connection.keep_alive(true)?;

        let stream = connection.open_bidirectional_stream().await?;
        let (mut recv_stream, mut send_stream) = stream.split();

        // Generate client ID
        let client_id: [u8; 16] = rand::random();

        // Send client hello
        let hello_msg = Message::client_hello(client_id, None);
        let encoded = hello_msg.encode();
        send_stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await?;
        send_stream.write_all(&encoded).await?;

        // Wait for server hello
        let mut len_buf = [0u8; 4];
        recv_stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; msg_len];
        recv_stream.read_exact(&mut msg_buf).await?;

        let response = Message::decode(Bytes::from(msg_buf))
            .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;
        if response.msg_type != MessageType::ServerHello {
            anyhow::bail!("Expected ServerHello");
        }

        Ok((recv_stream, send_stream))
    })
    .await
    .map_err(|_| anyhow::anyhow!("Handshake timeout"))?
}

/// Generate a random IP packet payload
fn generate_packet(size: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    // Create a minimal IPv4 header + payload
    let mut packet = vec![0u8; size.max(20)];
    
    // IPv4 header
    packet[0] = 0x45; // Version 4, IHL 5
    packet[1] = 0x00; // DSCP/ECN
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 17; // Protocol: UDP
    // Source IP: 10.0.0.2
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    // Dest IP: 8.8.8.8
    packet[16..20].copy_from_slice(&[8, 8, 8, 8]);
    
    // Random payload
    rng.fill(&mut packet[20..]);
    
    packet
}

// ============================================================================
// BENCHMARK: Single Connection Throughput
// ============================================================================

fn bench_single_connection_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = BenchConfig::default();

    // Check if server is running
    let server_available = rt.block_on(async {
        match create_bench_client(&config).await {
            Ok(_) => true,
            Err(e) => {
                eprintln!("Server not available: {}. Skipping benchmark.", e);
                false
            }
        }
    });

    if !server_available {
        eprintln!("⚠️  Start the server with: cargo run --release --bin server");
        return;
    }

    let mut group = c.benchmark_group("single_connection_throughput");
    
    for packet_size in [64, 256, 512, 1024, 1400].iter() {
        group.throughput(Throughput::Bytes(*packet_size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("packet_size", packet_size),
            packet_size,
            |b, &size| {
                b.to_async(&rt).iter(|| async {
                    let config = BenchConfig::default();
                    let mut connection = create_bench_client(&config).await.unwrap();
                    let (mut recv_stream, mut send_stream) = 
                        perform_handshake(&mut connection).await.unwrap();

                    let packet = generate_packet(size);
                    let msg = Message::ip_packet(packet);
                    let encoded = msg.encode();

                    // Send packet
                    send_stream
                        .write_all(&(encoded.len() as u32).to_be_bytes())
                        .await
                        .unwrap();
                    send_stream.write_all(&encoded).await.unwrap();

                    black_box(encoded.len())
                });
            },
        );
    }
    
    group.finish();
}

// ============================================================================
// BENCHMARK: Sustained Throughput (Multiple Packets)
// ============================================================================

fn bench_sustained_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = BenchConfig::default();

    let server_available = rt.block_on(async {
        create_bench_client(&config).await.is_ok()
    });

    if !server_available {
        eprintln!("⚠️  Server not available for sustained throughput test");
        return;
    }

    let mut group = c.benchmark_group("sustained_throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    for num_packets in [100, 500, 1000].iter() {
        let total_bytes = *num_packets as u64 * 1400;
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("packets", num_packets),
            num_packets,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    let config = BenchConfig::default();
                    let mut connection = create_bench_client(&config).await.unwrap();
                    let (_recv_stream, mut send_stream) =
                        perform_handshake(&mut connection).await.unwrap();

                    let packet = generate_packet(1400);
                    let msg = Message::ip_packet(packet);
                    let encoded = msg.encode();

                    for _ in 0..count {
                        send_stream
                            .write_all(&(encoded.len() as u32).to_be_bytes())
                            .await
                            .unwrap();
                        send_stream.write_all(&encoded).await.unwrap();
                    }

                    black_box(count)
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: Connection Establishment Latency
// ============================================================================

fn bench_connection_latency(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = BenchConfig::default();

    let server_available = rt.block_on(async {
        create_bench_client(&config).await.is_ok()
    });

    if !server_available {
        eprintln!("⚠️  Server not available for connection latency test");
        return;
    }

    let mut group = c.benchmark_group("connection_latency");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(30);

    group.bench_function("full_handshake", |b| {
        b.to_async(&rt).iter(|| async {
            let config = BenchConfig::default();
            let start = Instant::now();
            
            let mut connection = create_bench_client(&config).await.unwrap();
            let _streams = perform_handshake(&mut connection).await.unwrap();
            
            black_box(start.elapsed())
        });
    });

    group.finish();
}

// ============================================================================
// BENCHMARK: Concurrent Connections
// ============================================================================

fn bench_concurrent_connections(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = BenchConfig::default();

    let server_available = rt.block_on(async {
        create_bench_client(&config).await.is_ok()
    });

    if !server_available {
        eprintln!("⚠️  Server not available for concurrent connections test");
        return;
    }

    let mut group = c.benchmark_group("concurrent_connections");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(20);

    for num_clients in [2, 5, 10].iter() {
        group.bench_with_input(
            BenchmarkId::new("clients", num_clients),
            num_clients,
            |b, &count| {
                b.to_async(&rt).iter(|| async {
                    let barrier = Arc::new(Barrier::new(count));
                    let stats = Arc::new(BenchStats::new());
                    
                    let mut handles = Vec::new();

                    for _ in 0..count {
                        let barrier = Arc::clone(&barrier);
                        let stats = Arc::clone(&stats);
                        let config = BenchConfig::default();

                        let handle = tokio::spawn(async move {
                            // Wait for all clients to be ready
                            barrier.wait().await;

                            let mut connection = match create_bench_client(&config).await {
                                Ok(c) => c,
                                Err(_) => return,
                            };
                            
                            let (_recv, mut send) = match perform_handshake(&mut connection).await {
                                Ok(s) => s,
                                Err(_) => return,
                            };

                            // Send 10 packets per client
                            let packet = generate_packet(1400);
                            let msg = Message::ip_packet(packet);
                            let encoded = msg.encode();

                            for _ in 0..10 {
                                let start = Instant::now();
                                
                                if send
                                    .write_all(&(encoded.len() as u32).to_be_bytes())
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                if send.write_all(&encoded).await.is_err() {
                                    break;
                                }
                                
                                stats.record_send(encoded.len() as u64);
                                stats.record_latency(start.elapsed().as_nanos() as u64);
                            }
                        });

                        handles.push(handle);
                    }

                    for handle in handles {
                        let _ = handle.await;
                    }

                    black_box(stats.packets_sent.load(Ordering::Relaxed))
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: Message Encoding/Decoding (CPU bound)
// ============================================================================

fn bench_message_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_encoding");

    for size in [64, 256, 1024, 1400].iter() {
        let packet = generate_packet(*size);
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("encode", size),
            &packet,
            |b, packet| {
                b.iter(|| {
                    let msg = Message::ip_packet(black_box(packet.clone()));
                    black_box(msg.encode())
                });
            },
        );
    }

    for size in [64, 256, 1024, 1400].iter() {
        let packet = generate_packet(*size);
        let msg = Message::ip_packet(packet);
        let encoded = msg.encode();

        group.bench_with_input(
            BenchmarkId::new("decode", size),
            &encoded,
            |b, encoded| {
                b.iter(|| {
                    black_box(Message::decode(black_box(encoded.clone())))
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// BENCHMARK: Packet Generation (for baseline)
// ============================================================================

fn bench_packet_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_generation");

    for size in [64, 256, 1024, 1400, 9000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("generate", size),
            size,
            |b, &size| {
                b.iter(|| {
                    black_box(generate_packet(size))
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Custom benchmark runner for detailed statistics
// ============================================================================

fn run_detailed_benchmark() {
    println!("\n========================================");
    println!("DETAILED SERVER BENCHMARK");
    println!("========================================\n");

    let rt = Runtime::new().unwrap();
    let config = BenchConfig::default();

    // Check server availability
    let server_available = rt.block_on(async {
        match create_bench_client(&config).await {
            Ok(_) => {
                println!("✓ Server is available at {}", config.server_addr);
                true
            }
            Err(e) => {
                println!("✗ Server not available: {}", e);
                println!("\nPlease start the server with:");
                println!("  cargo run --release --bin server\n");
                false
            }
        }
    });

    if !server_available {
        return;
    }

    // Run throughput test
    println!("\n--- Throughput Test (1000 packets x 1400 bytes) ---");
    let stats = Arc::new(BenchStats::new());
    let stats_clone = Arc::clone(&stats);

    let duration = rt.block_on(async {
        let start = Instant::now();
        let config = BenchConfig::default();

        let mut connection = create_bench_client(&config).await.unwrap();
        let (_recv, mut send) = perform_handshake(&mut connection).await.unwrap();

        let packet = generate_packet(1400);
        let msg = Message::ip_packet(packet);
        let encoded = msg.encode();

        for _ in 0..1000 {
            let pkt_start = Instant::now();
            
            send.write_all(&(encoded.len() as u32).to_be_bytes())
                .await
                .unwrap();
            send.write_all(&encoded).await.unwrap();
            
            stats_clone.record_send(encoded.len() as u64);
            stats_clone.record_latency(pkt_start.elapsed().as_nanos() as u64);
        }

        start.elapsed()
    });

    let bytes_sent = stats.bytes_sent.load(Ordering::Relaxed);
    let throughput_mbps = (bytes_sent as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0);
    let packets_per_sec = stats.packets_sent.load(Ordering::Relaxed) as f64 / duration.as_secs_f64();

    println!("Duration: {:?}", duration);
    println!("Throughput: {:.2} Mbps", throughput_mbps);
    println!("Packets/sec: {:.0}", packets_per_sec);
    println!("{}", stats.summary());

    // Connection establishment test
    println!("\n--- Connection Establishment Test (10 connections) ---");
    let latencies: Vec<Duration> = rt.block_on(async {
        let mut lats = Vec::new();
        for _ in 0..10 {
            let start = Instant::now();
            let config = BenchConfig::default();
            let mut connection = create_bench_client(&config).await.unwrap();
            let _ = perform_handshake(&mut connection).await.unwrap();
            lats.push(start.elapsed());
        }
        lats
    });

    let avg_lat: Duration = latencies.iter().sum::<Duration>() / latencies.len() as u32;
    let min_lat = latencies.iter().min().unwrap();
    let max_lat = latencies.iter().max().unwrap();

    println!("Avg connection time: {:?}", avg_lat);
    println!("Min connection time: {:?}", min_lat);
    println!("Max connection time: {:?}", max_lat);

    println!("\n========================================");
    println!("BENCHMARK COMPLETE");
    println!("========================================\n");
}

// ============================================================================
// Criterion groups
// ============================================================================

criterion_group!(
    benches,
    bench_message_encoding,
    bench_packet_generation,
    bench_single_connection_throughput,
    bench_sustained_throughput,
    bench_connection_latency,
    bench_concurrent_connections,
);

criterion_main!(benches);

// Run with: cargo bench --bench server_benchmark
// Or for detailed stats: cargo bench --bench server_benchmark -- --verbose
