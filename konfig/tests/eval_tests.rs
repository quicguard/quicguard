use std::collections::{HashMap, HashSet};

use konfig::*;

fn test_claims(sub: &str, org_id: &str) -> TokenClaims {
    TokenClaims {
        sub: sub.to_string(),
        org_id: org_id.to_string(),
        roles: vec![],
        permissions: vec![],
        exp: None,
        iat: None,
    }
}

fn test_org() -> Organization {
    Organization {
        id: "org1".to_string(),
        name: "Test Org".to_string(),
        domains: vec!["app.example.com".to_string()],
        policies: vec![],
        domain_policies: HashMap::new(),
        upstream: UpstreamConfig {
            base_url: "https://api.example.com".to_string(),
            timeout_ms: 5000,
            max_retries: 3,
        },
        auth: AuthConfig {
            jwt_issuer: "https://auth.example.com".to_string(),
            jwt_audience: "proxy".to_string(),
            jwks_url: "https://auth.example.com/.well-known/jwks.json".to_string(),
            token_header: "Authorization".to_string(),
            token_prefix: "Bearer".to_string(),
            redirect_url: "https://auth.example.com/login".to_string(),
        },
    }
}

#[test]
fn test_evaluate_no_policies_allows_all() {
    let org = test_org();
    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/v1/users", &claims).is_ok());
}

#[test]
fn test_evaluate_general_allow_policy() {
    let mut org = test_org();
    org.policies = vec![Policy {
        id: "p1".to_string(),
        name: "Allow GET".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Prefix("/api/v1/".to_string()),
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Allow,
    }];

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/v1/users", &claims).is_err());
}

#[test]
fn test_evaluate_general_deny_blocks_matching() {
    let mut org = test_org();
    org.policies = vec![Policy {
        id: "p1".to_string(),
        name: "Deny DELETE".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Prefix("/api/v1/".to_string()),
            methods: HashSet::from([HttpMethod::Delete]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Deny,
    }];

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Delete, "/api/v1/users", &claims).is_err());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/v1/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_specific_allow() {
    let mut org = test_org();
    org.domain_policies.insert(
        "app.example.com".to_string(),
        vec![Policy {
            id: "p1".to_string(),
            name: "Allow GET on app domain".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/api/".to_string()),
                methods: HashSet::from([HttpMethod::Get]),
                conditions: vec![],
            }],
            effect: PolicyEffect::Allow,
        }],
    );

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_deny_blocks_even_if_general_allows() {
    let mut org = test_org();

    org.domain_policies.insert(
        "app.example.com".to_string(),
        vec![Policy {
            id: "p1".to_string(),
            name: "Deny DELETE".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/".to_string()),
                methods: HashSet::from([HttpMethod::Delete]),
                conditions: vec![],
            }],
            effect: PolicyEffect::Deny,
        }],
    );

    org.policies = vec![Policy {
        id: "p2".to_string(),
        name: "Allow all".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Prefix("/".to_string()),
            methods: HashSet::from([HttpMethod::Get, HttpMethod::Delete]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Allow,
    }];

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Delete, "/api/users", &claims).is_err());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_not_found_falls_to_general() {
    let mut org = test_org();

    org.domain_policies.insert(
        "other.example.com".to_string(),
        vec![Policy {
            id: "p1".to_string(),
            name: "Deny GET".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/".to_string()),
                methods: HashSet::from([HttpMethod::Get]),
                conditions: vec![],
            }],
            effect: PolicyEffect::Deny,
        }],
    );

    org.policies = vec![Policy {
        id: "p2".to_string(),
        name: "Allow GET".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Prefix("/".to_string()),
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Allow,
    }];

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());
}

#[test]
fn test_evaluate_domain_allow_no_general_allows() {
    let mut org = test_org();

    org.domain_policies.insert(
        "app.example.com".to_string(),
        vec![Policy {
            id: "p1".to_string(),
            name: "Allow GET".to_string(),
            rules: vec![PolicyRule {
                resource: ResourcePattern::Prefix("/".to_string()),
                methods: HashSet::from([HttpMethod::Get]),
                conditions: vec![],
            }],
            effect: PolicyEffect::Allow,
        }],
    );

    org.policies = vec![Policy {
        id: "p2".to_string(),
        name: "Deny POST".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Prefix("/".to_string()),
            methods: HashSet::from([HttpMethod::Post]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Deny,
    }];

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Post, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_domain_policy_with_condition() {
    let mut org = test_org();

    org.domain_policies.insert(
        "app.example.com".to_string(),
        vec![Policy {
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
    );

    let claims = test_claims("admin-user", "org1");
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());

    let claims = test_claims("regular-user", "org1");
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_err());
}

#[test]
fn test_evaluate_empty_domain_policies_no_effect() {
    let mut org = test_org();
    org.domain_policies.insert("app.example.com".to_string(), vec![]);

    org.policies = vec![Policy {
        id: "p1".to_string(),
        name: "Allow GET".to_string(),
        rules: vec![PolicyRule {
            resource: ResourcePattern::Prefix("/".to_string()),
            methods: HashSet::from([HttpMethod::Get]),
            conditions: vec![],
        }],
        effect: PolicyEffect::Allow,
    }];

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/users", &claims).is_ok());
}

#[test]
fn test_evaluate_complex_real_world_scenario() {
    let mut org = test_org();

    org.policies = vec![
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
    ];

    org.domain_policies.insert(
        "internal.example.com".to_string(),
        vec![Policy {
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
    );

    let claims = test_claims("user1", "org1");

    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/public/data", &claims).is_ok());
    assert!(evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/api/admin/users", &claims).is_err());
    assert!(evaluate_policies(&org, "internal.example.com", &HttpMethod::Get, "/api/admin/users", &claims).is_ok());
    assert!(evaluate_policies(&org, "internal.example.com", &HttpMethod::Delete, "/api/admin/users", &claims).is_err());
}
