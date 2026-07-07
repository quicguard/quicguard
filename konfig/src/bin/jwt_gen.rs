use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

#[derive(serde::Serialize)]
struct Claims {
    sub: String,
    org_id: String,
    iss: String,
    aud: String,
    roles: Vec<String>,
    permissions: Vec<String>,
    exp: u64,
    iat: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: jwt-gen <private_key.pem> <issuer> <audience> [subject] [org_id]");
        std::process::exit(1);
    }

    let key_path = &args[1];
    let issuer = &args[2];
    let audience = &args[3];
    let subject = args.get(4).map(|s| s.as_str()).unwrap_or("user-001");
    let org_id = args.get(5).map(|s| s.as_str()).unwrap_or("org-demo");

    let key_bytes = fs::read(key_path).expect("failed to read private key file");
    let key = EncodingKey::from_ed_pem(&key_bytes).expect("failed to parse Ed25519 private key");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = Claims {
        sub: subject.to_string(),
        org_id: org_id.to_string(),
        iss: issuer.to_string(),
        aud: audience.to_string(),
        roles: vec!["user".to_string()],
        permissions: vec!["read".to_string()],
        exp: now + 3600,
        iat: now,
    };

    let header = Header::new(Algorithm::EdDSA);
    let token = encode(&header, &claims, &key).expect("failed to encode JWT");
    println!("{token}");
}
