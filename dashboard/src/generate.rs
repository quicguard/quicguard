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
/// Returns PEM-encoded certificate (with embedded public key) and private key.
pub fn generate_jwt_keys() -> anyhow::Result<GeneratedJwtKeys> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let certified = CertificateParams::new(vec!["quicguard.local".to_string()])?
        .self_signed(&key_pair)?;

    let public_key = certified.pem();
    let private_key = key_pair.serialize_pem();

    Ok(GeneratedJwtKeys {
        public_key,
        private_key,
    })
}

/// Generate a self-signed TLS certificate for a domain.
/// Returns PEM-encoded certificate and private key.
pub fn generate_tls_cert(domain: &str) -> anyhow::Result<GeneratedTlsCert> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.is_ca = rcgen::IsCa::NoCa;

    let certified = params.self_signed(&key_pair)?;

    Ok(GeneratedTlsCert {
        cert_pem: certified.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}
