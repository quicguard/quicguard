use std::collections::HashMap;
use std::sync::Arc;

use konfig::*;

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

fn make_auth_config() -> AuthConfig {
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

fn make_redis() -> RedisConfig {
    RedisConfig {
        url: "redis://127.0.0.1:6379".to_string(),
        org_key: "test:orgs".to_string(),
        pubsub_channel: "test:updates".to_string(),
    }
}

fn make_org_with_tls(org_id: &str, domain_tls: HashMap<String, TlsConfig>) -> Organization {
    Organization {
        id: org_id.to_string(),
        name: format!("Org {org_id}"),
        domains: domain_tls
            .into_iter()
            .map(|(d, tls)| {
                (
                    d,
                    DomainConfig {
                        upstream: make_upstream(),
                        tls,
                    },
                )
            })
            .collect(),
        apps: HashMap::new(),
        user_groups: HashMap::new(),
        app_user_groups: HashMap::new(),
        auth: make_auth_config(),
    }
}

async fn make_state_with_tls(orgs: Vec<Organization>) -> Arc<ProxyState> {
    let state = Arc::new(ProxyState::empty(make_redis()));
    for org in orgs {
        let id = org.id.clone();
        state.reload_org(&id, org).await;
    }
    state
}

// ── TLS config per domain ──────────────────────────────────────────────────

#[tokio::test]
async fn test_two_orgs_different_tls_certs() {
    let org_a = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    let org_b = make_org_with_tls(
        "org-b",
        HashMap::from([(
            "other.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_B.to_string(),
                key_pem: KEY_B.to_string(),
            },
        )]),
    );

    let state = make_state_with_tls(vec![org_a, org_b]).await;

    let orgs = state.config.read().await;
    let org_a = &orgs.organizations["org-a"];
    let org_b = &orgs.organizations["org-b"];

    let tls_a = &org_a.domains["app.example.com"].tls;
    let tls_b = &org_b.domains["other.example.com"].tls;
    assert!(!tls_a.cert_pem.is_empty());
    assert!(!tls_b.cert_pem.is_empty());
    assert_ne!(tls_a.cert_pem, tls_b.cert_pem);
}

#[tokio::test]
async fn test_org_with_multiple_domain_certs() {
    let org = Organization {
        id: "org-multi".to_string(),
        name: "Multi-Domain Org".to_string(),
        domains: HashMap::from([
            (
                "app.example.com".to_string(),
                DomainConfig {
                    upstream: make_upstream(),
                    tls: TlsConfig {
                        cert_pem: CERT_A.to_string(),
                        key_pem: KEY_A.to_string(),
                    },
                },
            ),
            (
                "api.example.com".to_string(),
                DomainConfig {
                    upstream: make_upstream(),
                    tls: TlsConfig {
                        cert_pem: CERT_B.to_string(),
                        key_pem: KEY_B.to_string(),
                    },
                },
            ),
        ]),
        apps: HashMap::new(),
        user_groups: HashMap::new(),
        app_user_groups: HashMap::new(),
        auth: make_auth_config(),
    };

    let state = make_state_with_tls(vec![org]).await;

    let orgs = state.config.read().await;
    let org = &orgs.organizations["org-multi"];
    assert_eq!(org.domains.len(), 2);
    let tls_app = &org.domains["app.example.com"].tls;
    let tls_api = &org.domains["api.example.com"].tls;
    assert!(!tls_app.cert_pem.is_empty());
    assert!(!tls_api.cert_pem.is_empty());
    assert_ne!(tls_app.cert_pem, tls_api.cert_pem);
}

#[tokio::test]
async fn test_collect_all_tls_certs_from_state() {
    let org_a = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    let org_b = make_org_with_tls(
        "org-b",
        HashMap::from([(
            "other.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_B.to_string(),
                key_pem: KEY_B.to_string(),
            },
        )]),
    );

    let state = make_state_with_tls(vec![org_a, org_b]).await;

    // Simulate what build_tls_config does: collect all certs from all orgs
    let mut collected_certs: Vec<(String, String, String)> = Vec::new();
    let orgs = state.config.read().await;
    for org in orgs.organizations.values() {
        for (domain, domain_cfg) in &org.domains {
            if !domain_cfg.tls.cert_pem.is_empty() && !domain_cfg.tls.key_pem.is_empty() {
                collected_certs.push((
                    domain.clone(),
                    domain_cfg.tls.cert_pem.clone(),
                    domain_cfg.tls.key_pem.clone(),
                ));
            }
        }
    }

    assert_eq!(collected_certs.len(), 2);

    let domains: Vec<&str> = collected_certs.iter().map(|(d, _, _)| d.as_str()).collect();
    assert!(domains.contains(&"app.example.com"));
    assert!(domains.contains(&"other.example.com"));

    let cert_a = &collected_certs
        .iter()
        .find(|(d, _, _)| d == "app.example.com")
        .unwrap()
        .1;
    let cert_b = &collected_certs
        .iter()
        .find(|(d, _, _)| d == "other.example.com")
        .unwrap()
        .1;
    assert_ne!(cert_a, cert_b);
}

#[test]
fn test_tls_config_serialization_roundtrip() {
    let org = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    let json = serde_json::to_string_pretty(&org).unwrap();
    let deserialized: Organization = serde_json::from_str(&json).unwrap();

    let tls = &deserialized.domains["app.example.com"].tls;
    assert_eq!(tls.cert_pem, CERT_A);
    assert_eq!(tls.key_pem, KEY_A);
}

#[test]
fn test_tls_config_deserialization_without_tls_field() {
    let json = r#"{
        "id": "org-old",
        "name": "Old Org",
        "domains": {
            "old.example.com": {
                "upstream": {
                    "base_url": "http://127.0.0.1:8080",
                    "timeout_ms": 5000,
                    "max_retries": 3
                }
            }
        },
        "auth": {
            "jwt_issuer": "",
            "jwt_audience": "",
            "jwt_public_key": "",
            "cookie_name": "session_token",
            "redirect_url": ""
        }
    }"#;

    let org: Organization = serde_json::from_str(json).unwrap();
    let tls = &org.domains["old.example.com"].tls;
    assert!(tls.cert_pem.is_empty());
    assert!(tls.key_pem.is_empty());
    assert!(org.apps.is_empty());
}

#[tokio::test]
async fn test_config_version_increments_on_reload() {
    let state = make_state_with_tls(vec![]).await;

    let v0 = state.config_version.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(v0, 0);

    let org = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    state.reload_org("org-a", org).await;

    let v1 = state.config_version.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(v1, 1);

    // Reload same org again — version should increment
    let org = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    state.reload_org("org-a", org).await;

    let v2 = state.config_version.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(v2, 2);
}

#[tokio::test]
async fn test_config_version_increments_on_remove() {
    let org = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    let state = make_state_with_tls(vec![org]).await;

    let v0 = state.config_version.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(v0, 1); // make_state_with_tls called reload_org once

    state.remove_org("org-a").await;

    let v1 = state.config_version.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(v1, 2);
}

#[tokio::test]
async fn test_new_domain_appears_after_reload() {
    let org = make_org_with_tls(
        "org-a",
        HashMap::from([(
            "app.example.com".to_string(),
            TlsConfig {
                cert_pem: CERT_A.to_string(),
                key_pem: KEY_A.to_string(),
            },
        )]),
    );
    let state = make_state_with_tls(vec![org]).await;

    // Initially only app.example.com exists
    let orgs = state.config.read().await;
    assert!(orgs.organizations["org-a"].domains.contains_key("app.example.com"));
    assert!(!orgs.organizations["org-a"].domains.contains_key("api.example.com"));
    drop(orgs);

    // Add api.example.com via reload
    let updated = Organization {
        id: "org-a".to_string(),
        name: "Org A".to_string(),
        domains: HashMap::from([
            (
                "app.example.com".to_string(),
                DomainConfig {
                    upstream: make_upstream(),
                    tls: TlsConfig {
                        cert_pem: CERT_A.to_string(),
                        key_pem: KEY_A.to_string(),
                    },
                },
            ),
            (
                "api.example.com".to_string(),
                DomainConfig {
                    upstream: make_upstream(),
                    tls: TlsConfig {
                        cert_pem: CERT_B.to_string(),
                        key_pem: KEY_B.to_string(),
                    },
                },
            ),
        ]),
        apps: HashMap::new(),
        user_groups: HashMap::new(),
        app_user_groups: HashMap::new(),
        auth: make_auth_config(),
    };
    state.reload_org("org-a", updated).await;

    // Now api.example.com should be present
    let orgs = state.config.read().await;
    assert!(orgs.organizations["org-a"].domains.contains_key("app.example.com"));
    assert!(orgs.organizations["org-a"].domains.contains_key("api.example.com"));
    assert_eq!(orgs.organizations["org-a"].domains.len(), 2);
}
