use std::collections::{HashMap, HashSet};

use konfig::*;

fn test_claims(sub: &str, org_id: &str, app: &str) -> TokenClaims {
    TokenClaims {
        sub: sub.to_string(),
        org_id: org_id.to_string(),
        app: app.to_string(),
        roles: vec![],
        permissions: vec![],
        iss: None,
        aud: None,
        exp: None,
        iat: None,
    }
}

fn test_org_with_app() -> Organization {
    let mut apps = HashMap::new();
    apps.insert(
        "main".to_string(),
        AppConfig {
            domains: vec!["app.example.com".to_string()],
            policies: vec![Policy {
                id: "p1".to_string(),
                name: "Allow GET".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/api/v1/".to_string()),
                    methods: HashSet::from([HttpMethod::Get]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Allow,
            }],
        },
    );

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
            },
        )]),
        apps,
        user_groups: HashMap::new(),
        app_user_groups: HashMap::new(),
        auth: AuthConfig {
            jwt_issuer: "https://auth.example.com".to_string(),
            jwt_audience: "proxy".to_string(),
            jwks_url: "https://auth.example.com/.well-known/jwks.json".to_string(),
            jwt_public_key: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----".to_string(),
            jwt_private_key: String::new(),
            cookie_name: "session_token".to_string(),
            redirect_url: "https://auth.example.com/login".to_string(),
            idp_url: String::new(),
            req_param_name: "req".to_string(),
            token_param_name: "token".to_string(),
        },
    }
}

#[test]
fn test_evaluate_empty_app_returns_error() {
    let org = test_org_with_app();
    let claims = test_claims("user1", "org1", "");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_err());
}

#[test]
fn test_evaluate_general_allow_policy() {
    let org = test_org_with_app();
    let claims = test_claims("user1", "org1", "main");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/v1/users", &claims).is_err());
}

#[test]
fn test_evaluate_general_deny_blocks_matching() {
    let mut org = test_org_with_app();
    org.apps.insert("main".to_string(), AppConfig {
        domains: vec!["app.example.com".to_string()],
        policies: vec![Policy {
            id: "p1".to_string(),
            name: "Deny DELETE".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/api/v1/".to_string()),
                methods: HashSet::from([HttpMethod::Delete]),
                conditions: vec![],
            }],
            effect: PolicyEffect::Deny,
        }],
    });

    let claims = test_claims("user1", "org1", "main");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Delete, "/api/v1/users", &claims).is_err());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_specific_allow() {
    let mut org = test_org_with_app();
    org.apps.insert("main".to_string(), AppConfig {
        domains: vec!["app.example.com".to_string()],
        policies: vec![Policy {
            id: "p1".to_string(),
            name: "Allow GET on app domain".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/api/".to_string()),
                methods: HashSet::from([HttpMethod::Get]),
                conditions: vec![],
            }],
            effect: PolicyEffect::Allow,
        }],
    });

    let claims = test_claims("user1", "org1", "main");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_deny_blocks_even_if_allow_also_present() {
    let mut org = test_org_with_app();
    org.apps.insert("main".to_string(), AppConfig {
        domains: vec!["app.example.com".to_string()],
        policies: vec![
            Policy {
                id: "p1".to_string(),
                name: "Allow all".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/".to_string()),
                    methods: HashSet::from([HttpMethod::Get, HttpMethod::Delete]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Allow,
            },
            Policy {
                id: "p2".to_string(),
                name: "Deny DELETE".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/".to_string()),
                    methods: HashSet::from([HttpMethod::Delete]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Deny,
            },
        ],
    });

    let claims = test_claims("user1", "org1", "main");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Delete, "/api/users", &claims).is_err());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());
}

#[test]
fn test_evaluate_domain_not_found_returns_error() {
    let org = test_org_with_app();
    let claims = test_claims("user1", "org1", "main");

    assert!(evaluate_policies(&org, "unknown.example.com", &HttpMethod::Get, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_policy_with_condition() {
    let mut org = test_org_with_app();
    org.apps.insert("main".to_string(), AppConfig {
        domains: vec!["app.example.com".to_string()],
        policies: vec![Policy {
            id: "p1".to_string(),
            name: "Allow specific sub on domain".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/".to_string()),
                methods: HashSet::from([HttpMethod::Get]),
                conditions: vec![Condition {
                    claim: "sub".to_string(),
                    operator: ConditionOperator::StartsWith,
                    value: "admin-".to_string(),
                }],
            }],
            effect: PolicyEffect::Allow,
        }],
    });

    let claims = test_claims("admin-user", "org1", "main");
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());

    let claims = test_claims("regular-user", "org1", "main");
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_no_policies_allows_all() {
    let mut org = test_org_with_app();
    org.apps.insert("main".to_string(), AppConfig {
        domains: vec!["app.example.com".to_string()],
        policies: vec![],
    });

    let claims = test_claims("user1", "org1", "main");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/v1/users", &claims).is_ok());
}

#[test]
fn test_evaluate_complex_real_world_scenario() {
    let mut org = test_org_with_app();
    org.domains.insert(
        "internal.example.com".to_string(),
        DomainConfig {
            upstream: UpstreamConfig {
                base_url: "https://api.example.com".to_string(),
                timeout_ms: 5000,
                max_retries: 3,
            },
            tls: TlsConfig::default(),
        },
    );

    org.apps.insert("main".to_string(), AppConfig {
        domains: vec!["app.example.com".to_string()],
        policies: vec![
            Policy {
                id: "general-allow-read".to_string(),
                name: "Allow reading public resources".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/api/public/".to_string()),
                    methods: HashSet::from([HttpMethod::Get]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Allow,
            },
            Policy {
                id: "general-deny-admin".to_string(),
                name: "Deny admin endpoints".to_string(),
                rules: vec![PolicyRule {
                    resource: ResourcePattern::Prefix("/api/admin/".to_string()),
                    methods: HashSet::from([HttpMethod::Get, HttpMethod::Post, HttpMethod::Delete]),
                    conditions: vec![],
                }],
                effect: PolicyEffect::Deny,
            },
        ],
    });

    org.apps.insert("internal".to_string(), AppConfig {
        domains: vec!["internal.example.com".to_string()],
        policies: vec![Policy {
            id: "internal-allow-admin".to_string(),
            name: "Allow admin on internal domain".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/api/admin/".to_string()),
                methods: HashSet::from([HttpMethod::Get, HttpMethod::Post]),
                conditions: vec![Condition {
                    claim: "org_id".to_string(),
                    operator: ConditionOperator::Equals,
                    value: "org1".to_string(),
                }],
            }],
            effect: PolicyEffect::Allow,
        }],
    });

    let main_claims = test_claims("user1", "org1", "main");
    let internal_claims = test_claims("user1", "org1", "internal");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/public/data", &main_claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/admin/users", &main_claims).is_err());
    assert!(evaluate_policies(&org, "internal.example.com", &HttpMethod::Get, "/api/admin/users", &internal_claims).is_ok());
    assert!(evaluate_policies(&org, "internal.example.com", &HttpMethod::Delete, "/api/admin/users", &internal_claims).is_err());
}
