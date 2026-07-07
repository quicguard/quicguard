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
