use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioExecutor;
use konfig::ProxyState;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use tracing::info;

/// Extract the domain (host without port) from a request
fn extract_domain_from_request(req: &Request<hyper::body::Incoming>) -> String {
    req.uri()
        .host()
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Build HTTP/2 TLS configuration for a domain
fn build_http2_tls_config(
    org: &konfig::Organization,
    domain: &str,
) -> Result<ServerConfig> {
    let domain_config = org.domains.get(domain)
        .ok_or_else(|| anyhow::anyhow!("No domain config for {domain}"))?;
    
    let tls = &domain_config.tls;
    if tls.cert_pem.is_empty() || tls.key_pem.is_empty() {
        anyhow::bail!("No TLS certificate for domain {domain}");
    }
    
    let cert_chain: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut tls.cert_pem.as_bytes())
        .context("Failed to parse certificate")?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    
    // Try PKCS8 first, then RSA
    let private_key = if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut tls.key_pem.as_bytes())
        .context("Failed to parse PKCS8 private key")?
        .into_iter()
        .next() {
        rustls::PrivateKey(key)
    } else {
        let keys = rustls_pemfile::rsa_private_keys(&mut tls.key_pem.as_bytes())
            .context("Failed to parse RSA private key")?;
        if let Some(key) = keys.into_iter().next() {
            rustls::PrivateKey(key)
        } else {
            anyhow::bail!("No private key found");
        }
    };
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to set TLS config")?;
    
    Ok(config)
}

/// Handle a single HTTP/1.1 or HTTP/2 connection
async fn handle_connection(
    stream: TlsStream<tokio::net::TcpStream>,
    domain: String,
    proxy_state: Arc<ProxyState>,
    alt_svc: String,
) -> Result<()> {
    let io = hyper_util::rt::TokioIo::new(stream);
    
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let domain = domain.clone();
        let proxy_state = proxy_state.clone();
        let alt_svc = alt_svc.clone();
        
        async move {
            handle_request(req, &domain, &proxy_state, &alt_svc).await
        }
    });
    
    // Use http1::Builder which also handles HTTP/2 via ALPN
    hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .await
        .context("HTTP connection error")?;
    
    Ok(())
}

/// Handle a single HTTP/2 request
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    domain: &str,
    proxy_state: &ProxyState,
    alt_svc: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri_path = req.uri().path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    
    tracing::debug!("h2 request: {} {} on domain {}", method, uri_path, domain);
    
    // Extract domain from request (fallback to connection domain)
    let request_domain = extract_domain_from_request(&req);
    let effective_domain = if request_domain.is_empty() { domain } else { &request_domain };
    
    // Look up organization - just check if domain exists
    let _org = match proxy_state.lookup_org(effective_domain).await {
        Some(org) => org,
        None => {
            tracing::debug!("No org found for domain: {}", effective_domain);
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap());
        }
    };
    
    // Domain exists - return response with Alt-Svc header to upgrade to HTTP/3
    // No policy evaluation - just tell the client to use HTTP/3
    let response_body = format!(
        "Domain {} is configured. Use HTTP/3 for full access.",
        effective_domain
    );
    
    let alt_svc_header = hyper::header::HeaderValue::from_str(alt_svc)
        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("h3=\":4433\"; ma=86400"));
    
    Ok(Response::builder()
        .status(200)
        .header("alt-svc", alt_svc_header)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

/// Start the HTTP/2 TCP server
pub async fn start_http2_server(
    listen_addr: std::net::SocketAddr,
    proxy_state: Arc<ProxyState>,
) -> Result<()> {
    let alt_svc = format!("h3=\":{}\"; ma=86400", listen_addr.port());
    
    let listener = TcpListener::bind(listen_addr)
        .await
        .context(format!("Failed to bind TCP listener on {}", listen_addr))?;
    
    info!("HTTP/2 server listening on {}", listen_addr);
    
    loop {
        let (stream, addr) = listener.accept().await?;
        tracing::debug!("New TCP connection from {}", addr);
        
        let proxy_state = proxy_state.clone();
        let alt_svc = alt_svc.clone();
        
        tokio::spawn(async move {
            // Get the first available domain for TLS config
            let org_index = proxy_state.org_index.read().await;
            let first_domain = org_index.keys().next().cloned().unwrap_or_default();
            drop(org_index);
            
            if first_domain.is_empty() {
                tracing::error!("No domains configured");
                return;
            }
            
            tracing::debug!("Building TLS config for domain: {}", first_domain);
            
            // Build TLS config using the first available domain
            match build_http2_tls_config_for_domain(&proxy_state, &first_domain).await {
                Ok(tls_config) => {
                    tracing::debug!("TLS config built successfully");
                    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            tracing::debug!("TLS handshake completed for {}", addr);
                            if let Err(e) = handle_connection(tls_stream, first_domain, proxy_state, alt_svc).await {
                                tracing::error!("HTTP/2 connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::error!("TLS handshake error from {}: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to build TLS config: {}", e);
                }
            }
        });
    }
}

/// Build TLS config for a specific domain
async fn build_http2_tls_config_for_domain(
    proxy_state: &ProxyState,
    domain: &str,
) -> Result<ServerConfig> {
    let org_index = proxy_state.org_index.read().await;
    let org_id = org_index.get(domain)
        .ok_or_else(|| anyhow::anyhow!("No organization for domain {}", domain))?;
    
    let config = proxy_state.config.read().await;
    let org = config.organizations.get(org_id)
        .ok_or_else(|| anyhow::anyhow!("Organization {} not found", org_id))?;
    
    build_http2_tls_config(org, domain)
}
