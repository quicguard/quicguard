// TLS certificate generation for QUIC connections

use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use std::fs;
use std::path::Path;
use tracing::info;

/// Generate self-signed certificates for server and client
pub fn generate_certificates(
    cert_path: &Path,
    key_path: &Path,
    hostname: &str,
) -> Result<()> {
    // Check if certificates already exist
    if cert_path.exists() && key_path.exists() {
        info!("Certificates already exist, skipping generation");
        return Ok(());
    }

    // Create parent directories if they don't exist
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Generate self-signed certificate
    let subject_alt_names = vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    let cert = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

    // Write the certificate
    let cert_pem = cert.serialize_pem()
        .map_err(|e| anyhow::anyhow!("Failed to serialize certificate: {}", e))?;
    fs::write(cert_path, &cert_pem)
        .context("Failed to write certificate")?;

    // Write the private key
    let key_pem = cert.serialize_private_key_pem();
    fs::write(key_path, &key_pem)
        .context("Failed to write private key")?;

    info!(
        "Generated self-signed certificate for {} at {:?}",
        hostname, cert_path
    );

    Ok(())
}

/// Load certificate chain from PEM file
pub fn load_certificate(path: &Path) -> Result<Vec<rustls::Certificate>> {
    let cert_pem = fs::read(path)
        .context("Failed to read certificate file")?;
    
    let mut reader = std::io::BufReader::new(&cert_pem[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in file");
    }

    Ok(certs)
}

/// Load private key from PEM file
pub fn load_private_key(path: &Path) -> Result<rustls::PrivateKey> {
    let key_pem = fs::read(path)
        .context("Failed to read private key file")?;
    
    let mut reader = std::io::BufReader::new(&key_pem[..]);
    
    // Try to read EC key first, then RSA
    if let Some(key) = rustls_pemfile::ec_private_keys(&mut reader)?.into_iter().next() {
        return Ok(rustls::PrivateKey(key));
    }
    
    let mut reader = std::io::BufReader::new(&key_pem[..]);
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader)?.into_iter().next() {
        return Ok(rustls::PrivateKey(key));
    }

    let mut reader = std::io::BufReader::new(&key_pem[..]);
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader)?.into_iter().next() {
        return Ok(rustls::PrivateKey(key));
    }

    anyhow::bail!("No private key found in file")
}
