use rcgen::{CertificateParams, KeyPair};

pub struct GeneratedJwtKeys {
    pub public_key: String,
    pub private_key: String,
}

pub struct GeneratedTlsCert {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate an Ed25519 key pair for JWT signing.
pub fn generate_jwt_keys() -> anyhow::Result<GeneratedJwtKeys> {
    tracing::debug!("Generating Ed25519 key pair for JWT signing");

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    tracing::debug!("Ed25519 key pair generated");

    let certified = CertificateParams::new(vec!["quicguard.local".to_string()])?
        .self_signed(&key_pair)?;

    let public_key = certified.pem();
    let private_key = key_pair.serialize_pem();

    tracing::debug!("JWT key pair PEM encoded (public: {} bytes, private: {} bytes)",
        public_key.len(), private_key.len());

    Ok(GeneratedJwtKeys {
        public_key,
        private_key,
    })
}

/// Generate a self-signed TLS certificate for a domain.
pub fn generate_tls_cert(domain: &str) -> anyhow::Result<GeneratedTlsCert> {
    tracing::debug!(domain = domain, "Generating self-signed TLS certificate");

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    tracing::debug!(domain = domain, "TLS key pair generated");

    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.is_ca = rcgen::IsCa::NoCa;

    let certified = params.self_signed(&key_pair)?;
    tracing::debug!(domain = domain, "TLS certificate signed (cert: {} bytes, key: {} bytes)",
        certified.pem().len(), key_pair.serialize_pem().len());

    Ok(GeneratedTlsCert {
        cert_pem: certified.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_jwt_keys_returns_valid_pem() {
        let keys = generate_jwt_keys().unwrap();
        assert!(!keys.public_key.is_empty());
        assert!(!keys.private_key.is_empty());
        assert!(keys.public_key.contains("BEGIN CERTIFICATE"));
        assert!(keys.private_key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_jwt_keys_unique_each_time() {
        let keys1 = generate_jwt_keys().unwrap();
        let keys2 = generate_jwt_keys().unwrap();
        assert_ne!(keys1.private_key, keys2.private_key);
    }

    #[test]
    fn test_generate_tls_cert_returns_valid_pem() {
        let cert = generate_tls_cert("example.com").unwrap();
        assert!(!cert.cert_pem.is_empty());
        assert!(!cert.key_pem.is_empty());
        assert!(cert.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_generate_tls_cert_different_domains_produce_different_certs() {
        let cert_a = generate_tls_cert("a.example.com").unwrap();
        let cert_b = generate_tls_cert("b.example.com").unwrap();
        // Different domains produce different certificates
        assert_ne!(cert_a.cert_pem, cert_b.cert_pem);
    }

    #[test]
    fn test_generate_tls_cert_unique_each_time() {
        let cert1 = generate_tls_cert("test.com").unwrap();
        let cert2 = generate_tls_cert("test.com").unwrap();
        assert_ne!(cert1.key_pem, cert2.key_pem);
    }

}
