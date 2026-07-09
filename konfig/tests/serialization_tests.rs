use std::collections::{HashMap, HashSet};

use konfig::*;

#[test]
fn test_config_serialization_roundtrip() {
    let config = ProxyConfig {
        organizations: HashMap::from([(
            "org1".to_string(),
            Organization {
                id: "org1".to_string(),
                name: "Test Org".to_string(),
                domains: HashMap::from([(
                    "app.example.com".to_string(),
                    DomainConfig {
                        upstream: UpstreamConfig {
                            base_url: "https://api.example.com".to_string(),
                            timeout_ms: 5000,
                            max_retries: 3,
                        },
                        tls: TlsConfig::default(),
                        policies: vec![
                            Policy {
                                id: "p1".to_string(),
                                name: "Allow GET".to_string(),
                                rules: vec![PolicyRule {
                                    resource: ResourcePattern::Prefix("/api/".to_string()),
                                    methods: HashSet::from([HttpMethod::Get]),
                                    conditions: vec![Condition {
                                        claim: "org_id".to_string(),
                                        operator: ConditionOperator::Equals,
                                        value: "org1".to_string(),
                                    }],
                                }],
                                effect: PolicyEffect::Allow,
                            },
                            Policy {
                                id: "dp1".to_string(),
                                name: "Domain policy".to_string(),
                                rules: vec![PolicyRule {
                                    resource: ResourcePattern::Exact("/api/special".to_string()),
                                    methods: HashSet::from([HttpMethod::Post]),
                                    conditions: vec![],
                                }],
                                effect: PolicyEffect::Deny,
                            },
                        ],
                    },
                )]),
                auth: AuthConfig {
                    jwt_issuer: "https://auth.example.com".to_string(),
                    jwt_audience: "proxy".to_string(),
                    jwks_url: "https://auth.example.com/.well-known/jwks.json".to_string(),
                    jwt_public_key: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----".to_string(),
                    cookie_name: "session_token".to_string(),
                    redirect_url: "https://auth.example.com/login".to_string(),
                    idp_url: String::new(),
                },
            },
        )]),
    };

    let json = serde_json::to_string_pretty(&config).unwrap();
    let deserialized: ProxyConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.organizations.len(), 1);
    let org = deserialized.organizations.get("org1").unwrap();
    assert_eq!(org.name, "Test Org");
    assert_eq!(org.domains.len(), 1);
    let domain_cfg = org.domains.get("app.example.com").unwrap();
    assert_eq!(domain_cfg.policies.len(), 2);
    assert_eq!(domain_cfg.policies[0].id, "p1");
    assert_eq!(domain_cfg.policies[1].id, "dp1");
}

#[test]
fn test_organization_serialization_with_defaults() {
    let json = r#"{
        "id": "org1",
        "name": "Test Org",
        "domains": {
            "app.example.com": {
                "upstream": {
                    "base_url": "https://api.example.com",
                    "timeout_ms": 5000
                }
            }
        },
        "auth": {
            "jwt_issuer": "https://auth.example.com",
            "jwt_audience": "proxy",
            "jwt_public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----",
            "redirect_url": "https://auth.example.com/login"
        }
    }"#;

    let org: Organization = serde_json::from_str(json).unwrap();
    assert_eq!(org.id, "org1");
    assert_eq!(org.domains.len(), 1);
    let domain_cfg = org.domains.get("app.example.com").unwrap();
    assert!(domain_cfg.policies.is_empty());
    assert!(domain_cfg.tls.cert_pem.is_empty());
    assert!(domain_cfg.upstream.max_retries == 3);
    assert_eq!(org.auth.cookie_name, "session_token");
}

#[test]
fn test_policy_serialization_roundtrip() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Test Policy".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Glob("/api/*/users/*".to_string()),
            methods: HashSet::from([HttpMethod::Get, HttpMethod::Post]),
            conditions: vec![
                Condition {
                    claim: "org_id".to_string(),
                    operator: ConditionOperator::Equals,
                    value: "org1".to_string(),
                },
                Condition {
                    claim: "sub".to_string(),
                    operator: ConditionOperator::In,
                    value: "admin,superadmin".to_string(),
                },
            ],
        }],
        effect: PolicyEffect::Allow,
    };

    let json = serde_json::to_string_pretty(&policy).unwrap();
    let deserialized: Policy = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, "p1");
    assert_eq!(deserialized.rules.len(), 1);
    assert_eq!(deserialized.rules[0].conditions.len(), 2);
    assert!(matches!(deserialized.effect, PolicyEffect::Allow));
}

#[test]
fn test_http_method_serialization() {
    let methods = vec![
        (HttpMethod::Get, "\"GET\""),
        (HttpMethod::Post, "\"POST\""),
        (HttpMethod::Put, "\"PUT\""),
        (HttpMethod::Delete, "\"DELETE\""),
        (HttpMethod::Patch, "\"PATCH\""),
        (HttpMethod::Head, "\"HEAD\""),
        (HttpMethod::Options, "\"OPTIONS\""),
    ];

    for (method, expected_json) in methods {
        let json = serde_json::to_string(&method).unwrap();
        assert_eq!(json, expected_json);

        let deserialized: HttpMethod = serde_json::from_str(&json).unwrap();
        assert!(std::mem::discriminant(&deserialized) == std::mem::discriminant(&method));
    }
}

#[test]
fn test_policy_effect_default() {
    let json = r#"{
        "id": "p1",
        "name": "Test",
        "rules": []
    }"#;

    let policy: Policy = serde_json::from_str(json).unwrap();
    assert!(matches!(policy.effect, PolicyEffect::Allow));
}

#[test]
fn test_policy_effect_deny_serialization() {
    let policy = Policy {
        id: "p1".to_string(),
        name: "Deny Policy".to_string(),
        rules: vec![],
        effect: PolicyEffect::Deny,
    };

    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("Deny"));

    let deserialized: Policy = serde_json::from_str(&json).unwrap();
    assert!(matches!(deserialized.effect, PolicyEffect::Deny));
}

#[test]
fn test_resource_pattern_serialization() {
    let patterns = vec![
        ResourcePattern::Exact("/api/v1/users".to_string()),
        ResourcePattern::Prefix("/api/v1/".to_string()),
        ResourcePattern::Glob("/api/*/users/*".to_string()),
    ];

    for pattern in patterns {
        let json = serde_json::to_string(&pattern).unwrap();
        let deserialized: ResourcePattern = serde_json::from_str(&json).unwrap();

        let (original, deserialized) = match (&pattern, &deserialized) {
            (ResourcePattern::Exact(a), ResourcePattern::Exact(b)) => (a, b),
            (ResourcePattern::Prefix(a), ResourcePattern::Prefix(b)) => (a, b),
            (ResourcePattern::Glob(a), ResourcePattern::Glob(b)) => (a, b),
            _ => panic!("Pattern type mismatch"),
        };
        assert_eq!(original, deserialized);
    }
}

#[test]
fn test_condition_operator_serialization() {
    let operators = vec![
        (ConditionOperator::Equals, "\"Equals\""),
        (ConditionOperator::NotEquals, "\"NotEquals\""),
        (ConditionOperator::In, "\"In\""),
        (ConditionOperator::NotIn, "\"NotIn\""),
        (ConditionOperator::Contains, "\"Contains\""),
        (ConditionOperator::StartsWith, "\"StartsWith\""),
    ];

    for (op, expected_json) in operators {
        let json = serde_json::to_string(&op).unwrap();
        assert_eq!(json, expected_json);

        let deserialized: ConditionOperator = serde_json::from_str(&json).unwrap();
        assert!(std::mem::discriminant(&deserialized) == std::mem::discriminant(&op));
    }
}

#[test]
fn test_token_claims_serialization() {
    let claims = TokenClaims {
        sub: "user1".to_string(),
        org_id: "org1".to_string(),
        roles: vec!["admin".to_string()],
        permissions: vec!["read".to_string(), "write".to_string()],
        iss: Some("https://auth.example.com".to_string()),
        aud: Some("proxy".to_string()),
        exp: Some(1234567890),
        iat: Some(1234567800),
    };

    let json = serde_json::to_string_pretty(&claims).unwrap();
    let deserialized: TokenClaims = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.sub, "user1");
    assert_eq!(deserialized.org_id, "org1");
    assert_eq!(deserialized.roles, vec!["admin"]);
    assert_eq!(deserialized.permissions, vec!["read", "write"]);
    assert_eq!(deserialized.exp, Some(1234567890));
}

#[test]
fn test_token_claims_with_defaults() {
    let json = r#"{
        "sub": "user1",
        "org_id": "org1"
    }"#;

    let claims: TokenClaims = serde_json::from_str(json).unwrap();
    assert!(claims.roles.is_empty());
    assert!(claims.permissions.is_empty());
    assert!(claims.exp.is_none());
    assert!(claims.iat.is_none());
}

#[test]
fn test_complex_organization_json() {
    let json = r#"{
        "id": "org123",
        "name": "Acme Corp",
        "domains": {
            "app.acme.com": {
                "upstream": {
                    "base_url": "https://backend.acme.com",
                    "timeout_ms": 10000,
                    "max_retries": 5
                },
                "tls": {
                    "cert_pem": "CERT_APP",
                    "key_pem": "KEY_APP"
                },
                "policies": [
                    {
                        "id": "general-read",
                        "name": "Allow reading",
                        "rules": [
                            {
                                "resource": {"Prefix": "/api/"},
                                "methods": ["GET"],
                                "conditions": []
                            }
                        ],
                        "effect": "Allow"
                    }
                ]
            },
            "api.acme.com": {
                "upstream": {
                    "base_url": "https://backend.acme.com",
                    "timeout_ms": 10000,
                    "max_retries": 5
                },
                "tls": {
                    "cert_pem": "CERT_API",
                    "key_pem": "KEY_API"
                },
                "policies": [
                    {
                        "id": "api-deny-delete",
                        "name": "Deny delete on API",
                        "rules": [
                            {
                                "resource": {"Prefix": "/api/"},
                                "methods": ["DELETE"],
                                "conditions": []
                            }
                        ],
                        "effect": "Deny"
                    }
                ]
            }
        },
        "auth": {
            "jwt_issuer": "https://auth.acme.com",
            "jwt_audience": "acme-proxy",
            "jwt_public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----",
            "cookie_name": "acme_session",
            "redirect_url": "https://auth.acme.com/sso"
        }
    }"#;

    let org: Organization = serde_json::from_str(json).unwrap();

    assert_eq!(org.id, "org123");
    assert_eq!(org.domains.len(), 2);
    assert_eq!(org.domains["app.acme.com"].policies.len(), 1);
    assert_eq!(org.domains["api.acme.com"].policies.len(), 1);
    assert_eq!(org.domains["app.acme.com"].upstream.max_retries, 5);
    assert_eq!(org.auth.cookie_name, "acme_session");
}
