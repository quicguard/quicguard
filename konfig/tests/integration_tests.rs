use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use konfig::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

const JWT_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINULhlYMwjtUBOB4D9/tvMvN7tKINe85iozOEXrd4ryQ\n-----END PRIVATE KEY-----";

const JWT_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----";

fn make_auth_config(cookie_name: &str) -> AuthConfig {
    AuthConfig {
        jwt_issuer: "https://auth.quicguard.dev".to_string(),
        jwt_audience: "quicguard-proxy".to_string(),
        jwks_url: "https://auth.quicguard.dev/.well-known/jwks.json".to_string(),
        jwt_public_key: JWT_PUBLIC_KEY.to_string(),
        cookie_name: cookie_name.to_string(),
        redirect_url: "https://auth.quicguard.dev/login".to_string(),
        idp_url: "https://auth.quicguard.dev/idp".to_string(),
    }
}

fn make_sample_org(org_id: &str, domain: &str, cookie_name: &str) -> Organization {
    Organization {
        id: org_id.to_string(),
        name: format!("Org {org_id}"),
        domains: vec![domain.to_string()],
        policies: vec![
            Policy {
                id: "allow-read".to_string(),
                name: "Allow reading".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/api/".to_string()),
                    methods: HashSet::from([HttpMethod::Get, HttpMethod::Head]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Allow,
            },
            Policy {
                id: "deny-delete".to_string(),
                name: "Deny delete on admin".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/api/admin/".to_string()),
                    methods: HashSet::from([HttpMethod::Delete]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Deny,
            },
        ],
        domain_policies: HashMap::new(),
        upstream: UpstreamConfig {
            base_url: "http://127.0.0.1:1025".to_string(),
            timeout_ms: 5000,
            max_retries: 3,
        },
        auth: make_auth_config(cookie_name),
    }
}

fn encode_jwt(claims: &TokenClaims) -> String {
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let key = jsonwebtoken::EncodingKey::from_ed_pem(JWT_PRIVATE_KEY.as_bytes())
        .expect("failed to load Ed25519 private key");
    jsonwebtoken::encode(&header, &claims, &key).expect("failed to encode JWT")
}

fn make_claims(sub: &str, org_id: &str) -> TokenClaims {
    TokenClaims {
        sub: sub.to_string(),
        org_id: org_id.to_string(),
        roles: vec!["user".to_string()],
        permissions: vec!["read".to_string()],
        iss: Some("https://auth.quicguard.dev".to_string()),
        aud: Some("quicguard-proxy".to_string()),
        exp: None,
        iat: None,
    }
}

async fn make_state(orgs: Vec<Organization>) -> Arc<ProxyState> {
    let state = ProxyState::empty(RedisConfig {
        url: "redis://127.0.0.1:6379".to_string(),
        org_key: "test:orgs".to_string(),
        pubsub_channel: "test:updates".to_string(),
    });

    for org in orgs {
        let id = org.id.clone();
        state.reload_org(&id, org).await;
    }

    Arc::new(state)
}

// ── Cookie parsing tests ─────────────────────────────────────────────────────

#[test]
fn test_parse_cookie_single() {
    let result = parse_cookie("session_token=abc123", "session_token");
    assert_eq!(result.as_deref(), Some("abc123"));
}

#[test]
fn test_parse_cookie_multiple() {
    let result = parse_cookie("theme=dark; session_token=jwt.jwt.jwt; lang=en", "session_token");
    assert_eq!(result.as_deref(), Some("jwt.jwt.jwt"));
}

#[test]
fn test_parse_cookie_not_found() {
    let result = parse_cookie("theme=dark; lang=en", "session_token");
    assert!(result.is_none());
}

#[test]
fn test_parse_cookie_empty_value() {
    let result = parse_cookie("session_token=", "session_token");
    assert_eq!(result.as_deref(), Some(""));
}

#[test]
fn test_parse_cookie_whitespace() {
    let result = parse_cookie("  session_token = jwt.jwt.jwt  ; theme=dark", "session_token");
    assert_eq!(result.as_deref(), Some("jwt.jwt.jwt"));
}

#[test]
fn test_parse_cookie_empty_header() {
    let result = parse_cookie("", "session_token");
    assert!(result.is_none());
}

#[test]
fn test_parse_cookie_custom_name() {
    let result = parse_cookie("my_custom_cookie=xyz", "my_custom_cookie");
    assert_eq!(result.as_deref(), Some("xyz"));
}

// ── Domain lookup tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_domain_lookup_found() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let found = state.lookup_org("demo.localhost").await;
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, "org1");
}

#[tokio::test]
async fn test_domain_lookup_not_found() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let found = state.lookup_org("unknown.localhost").await;
    assert!(found.is_none());
}

#[tokio::test]
async fn test_domain_lookup_multiple_orgs() {
    let org1 = make_sample_org("org1", "app1.localhost", "session_token");
    let org2 = make_sample_org("org2", "app2.localhost", "session_token");
    let state = make_state(vec![org1, org2]).await;

    assert_eq!(state.lookup_org("app1.localhost").await.unwrap().id, "org1");
    assert_eq!(state.lookup_org("app2.localhost").await.unwrap().id, "org2");
}

#[tokio::test]
async fn test_domain_lookup_after_remove() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    state.remove_org("org1").await;
    assert!(state.lookup_org("demo.localhost").await.is_none());
}

#[tokio::test]
async fn test_domain_lookup_after_reload() {
    let org = make_sample_org("org1", "old.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let mut updated = make_sample_org("org1", "new.localhost", "session_token");
    updated.name = "Updated Org".to_string();
    state.reload_org("org1", updated).await;

    assert!(state.lookup_org("old.localhost").await.is_none());
    assert_eq!(
        state.lookup_org("new.localhost").await.unwrap().name,
        "Updated Org"
    );
}

// ── JWT validation tests ─────────────────────────────────────────────────────

#[test]
fn test_jwt_valid_token() {
    let auth = make_auth_config("session_token");
    let claims = make_claims("user1", "org1");
    let token = encode_jwt(&claims);

    let key = jsonwebtoken::DecodingKey::from_ed_pem(auth.jwt_public_key.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&[auth.jwt_issuer.as_str()]);
    validation.set_audience(&[auth.jwt_audience.as_str()]);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let result = jsonwebtoken::decode::<TokenClaims>(&token, &key, &validation);
    assert!(result.is_ok(), "JWT decode failed: {:?}", result.err());
    assert_eq!(result.unwrap().claims.sub, "user1");
}

#[test]
fn test_jwt_wrong_key() {
    let claims = make_claims("user1", "org1");
    let token = encode_jwt(&claims);

    let wrong_key = jsonwebtoken::DecodingKey::from_ed_pem(
        b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA3l8JbM8MrkZa25tjV/mBobdfxMFPNia0woHA9J98ku8=\n-----END PUBLIC KEY-----",
    )
    .unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://auth.quicguard.dev"]);
    validation.set_audience(&["quicguard-proxy"]);

    let result = jsonwebtoken::decode::<TokenClaims>(&token, &wrong_key, &validation);
    assert!(result.is_err());
}

#[test]
fn test_jwt_wrong_issuer() {
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    let key = jsonwebtoken::EncodingKey::from_ed_pem(JWT_PRIVATE_KEY.as_bytes()).unwrap();

    let token = jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "sub": "user1",
            "org_id": "org1",
            "iss": "https://wrong.issuer.com",
            "aud": "quicguard-proxy"
        }),
        &key,
    )
    .unwrap();

    let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(JWT_PUBLIC_KEY.as_bytes()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&["https://auth.quicguard.dev"]);
    validation.set_audience(&["quicguard-proxy"]);

    let result = jsonwebtoken::decode::<TokenClaims>(&token, &dec_key, &validation);
    assert!(result.is_err());
}

#[test]
fn test_jwt_malformed_token() {
    let result = validate_jwt("not.a.valid.jwt", &make_auth_config("session_token"));
    assert!(matches!(result, Err(ProxyError::InvalidToken)));
}

#[test]
fn test_jwt_empty_token() {
    let result = validate_jwt("", &make_auth_config("session_token"));
    assert!(matches!(result, Err(ProxyError::InvalidToken)));
}

// ── Policy evaluation with claims tests ──────────────────────────────────────

#[test]
fn test_policy_evaluate_allow_read() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let claims = make_claims("user1", "org1");

    assert!(evaluate_policies(&org, "demo.localhost", &HttpMethod::Get, "/api/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "demo.localhost", &HttpMethod::Head, "/api/users", &claims).is_ok());
}

#[test]
fn test_policy_evaluate_deny_post() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let claims = make_claims("user1", "org1");

    assert!(evaluate_policies(&org, "demo.localhost", &HttpMethod::Post, "/api/users", &claims).is_err());
}

#[test]
fn test_policy_evaluate_deny_delete_admin() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let claims = make_claims("user1", "org1");

    assert!(evaluate_policies(&org, "demo.localhost", &HttpMethod::Delete, "/api/admin/users", &claims).is_err());
}

#[test]
fn test_policy_evaluate_delete_non_admin_ok() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let claims = make_claims("user1", "org1");

    // DELETE on /api/users is not covered by deny-delete (which targets /api/admin/)
    // and not covered by allow-read (which is GET/HEAD only), so no policy matches → denied
    assert!(evaluate_policies(&org, "demo.localhost", &HttpMethod::Delete, "/api/users", &claims).is_err());
}

// ── Full integration: cookie → domain → JWT → policy ─────────────────────────

#[tokio::test]
async fn test_full_flow_valid_cookie_allow() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    // 1. Look up org by domain
    let org = state.lookup_org("demo.localhost").await.unwrap();

    // 2. Generate a valid JWT and put it in a cookie
    let claims = make_claims("user1", "org1");
    let token = encode_jwt(&claims);
    let cookie_header = format!("theme=dark; session_token={token}; lang=en");

    let parsed_token = parse_cookie(&cookie_header, &org.auth.cookie_name).unwrap();

    // 3. Validate JWT
    let parsed_claims = validate_jwt(&parsed_token, &org.auth).unwrap();
    assert_eq!(parsed_claims.sub, "user1");

    // 4. Evaluate policies
    assert!(evaluate_policies(&org, "demo.localhost", &HttpMethod::Get, "/api/users", &parsed_claims).is_ok());
}

#[tokio::test]
async fn test_full_flow_missing_cookie() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let org = state.lookup_org("demo.localhost").await.unwrap();
    let token = parse_cookie("theme=dark", &org.auth.cookie_name);

    assert!(token.is_none());
}

#[tokio::test]
async fn test_full_flow_invalid_jwt() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let org = state.lookup_org("demo.localhost").await.unwrap();
    let token = parse_cookie("session_token=bad.token.value", &org.auth.cookie_name).unwrap();

    let result = validate_jwt(&token, &org.auth);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_full_flow_valid_jwt_policy_denied() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let org = state.lookup_org("demo.localhost").await.unwrap();

    // Generate a valid JWT
    let claims = make_claims("user1", "org1");
    let token = encode_jwt(&claims);

    let parsed_claims = validate_jwt(&token, &org.auth).unwrap();

    // DELETE on /api/admin/ is denied
    let result = evaluate_policies(&org, "demo.localhost", &HttpMethod::Delete, "/api/admin/users", &parsed_claims);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_full_flow_domain_not_found() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    let org = state.lookup_org("unknown.localhost").await;
    assert!(org.is_none());
}

#[tokio::test]
async fn test_full_flow_custom_cookie_name() {
    let org = make_sample_org("org1", "demo.localhost", "my_app_session");
    let state = make_state(vec![org]).await;

    let org = state.lookup_org("demo.localhost").await.unwrap();
    assert_eq!(org.auth.cookie_name, "my_app_session");

    // Correct cookie name
    let token = parse_cookie("my_app_session=valid.jwt.token", &org.auth.cookie_name);
    assert!(token.is_some());

    // Wrong cookie name
    let token = parse_cookie("session_token=valid.jwt.token", &org.auth.cookie_name);
    assert!(token.is_none());
}

#[tokio::test]
async fn test_full_flow_org_reload_preserves_lookup() {
    let org = make_sample_org("org1", "demo.localhost", "session_token");
    let state = make_state(vec![org]).await;

    // Verify initial lookup works
    assert!(state.lookup_org("demo.localhost").await.is_some());

    // Reload with different domain
    let updated = make_sample_org("org1", "new.localhost", "session_token");
    state.reload_org("org1", updated).await;

    // Old domain gone, new domain works
    assert!(state.lookup_org("demo.localhost").await.is_none());
    assert!(state.lookup_org("new.localhost").await.is_some());
}

// ── Config from JSON (simulates Redis load) ──────────────────────────────────

#[test]
fn test_config_from_json_roundtrip() {
    let json = r#"{
        "id": "org1",
        "name": "Demo Corp",
        "domains": ["demo.localhost"],
        "policies": [
            {
                "id": "allow-read",
                "name": "Allow reading",
                "rules": [
                    {
                        "resource": {"Prefix": "/api/"},
                        "methods": ["GET", "HEAD"],
                        "conditions": []
                    }
                ],
                "effect": "Allow"
            },
            {
                "id": "deny-delete-admin",
                "name": "Deny delete on admin",
                "rules": [
                    {
                        "resource": {"Prefix": "/api/admin/"},
                        "methods": ["DELETE"],
                        "conditions": []
                    }
                ],
                "effect": "Deny"
            }
        ],
        "domain_policies": {},
        "upstream": {
            "base_url": "http://127.0.0.1:1025",
            "timeout_ms": 5000,
            "max_retries": 3
        },
        "auth": {
            "jwt_issuer": "https://auth.quicguard.dev",
            "jwt_audience": "quicguard-proxy",
            "jwt_public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----",
            "cookie_name": "session_token",
            "redirect_url": "https://auth.quicguard.dev/login",
            "idp_url": "https://auth.quicguard.dev/idp"
        }
    }"#;

    let org: Organization = serde_json::from_str(json).unwrap();
    assert_eq!(org.id, "org1");
    assert_eq!(org.domains, vec!["demo.localhost"]);
    assert_eq!(org.upstream.base_url, "http://127.0.0.1:1025");
    assert_eq!(org.auth.cookie_name, "session_token");
    assert_eq!(org.policies.len(), 2);

    // Verify it serializes back cleanly
    let serialized = serde_json::to_string(&org).unwrap();
    let deserialized: Organization = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.id, "org1");
    assert_eq!(deserialized.auth.cookie_name, "session_token");
}
