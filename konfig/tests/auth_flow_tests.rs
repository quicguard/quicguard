use std::collections::{HashMap, HashSet};

use konfig::*;

fn make_auth() -> AuthConfig {
    AuthConfig {
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
    }
}

fn make_test_org() -> Organization {
    let mut app_domains = HashMap::new();
    app_domains.insert(
        "pr1.example.com".to_string(),
        AppDomainConfig {
            paths: vec!["/api".to_string(), "/web".to_string()],
            r#type: "primary".to_string(),
        },
    );

    let mut apps = HashMap::new();
    apps.insert(
        "web-app".to_string(),
        AppConfig {
            domains: app_domains,
            policies: vec![Policy {
                id: "pol-1".to_string(),
                name: "Allow all".to_string(),
                effect: PolicyEffect::Allow,
                rules: vec![PolicyRule {
                    methods: HashSet::from([HttpMethod::Get]),
                    conditions: vec![],
                }],
            }],
        },
    );

    Organization {
        id: "org-1".to_string(),
        name: "Test Org".to_string(),
        domains: HashMap::new(),
        apps,
        user_groups: HashMap::new(),
        app_user_groups: HashMap::new(),
        auth: make_auth(),
    }
}

// ── find_matching_app tests ──────────────────────────────────────────────

#[test]
fn test_find_matching_app_exact_path() {
    let org = make_test_org();
    let result = find_matching_app(&org, "pr1.example.com", "/api/users");
    assert_eq!(result, Some("web-app".to_string()));
}

#[test]
fn test_find_matching_app_root_path() {
    let org = make_test_org();
    let result = find_matching_app(&org, "pr1.example.com", "/web/dashboard");
    assert_eq!(result, Some("web-app".to_string()));
}

#[test]
fn test_find_matching_app_no_domain() {
    let org = make_test_org();
    let result = find_matching_app(&org, "unknown.example.com", "/api/users");
    assert!(result.is_none());
}

#[test]
fn test_find_matching_app_multiple_apps() {
    let mut org = make_test_org();

    let mut admin_domains = HashMap::new();
    admin_domains.insert(
        "pr1.example.com".to_string(),
        AppDomainConfig {
            paths: vec!["/admin".to_string()],
            r#type: "primary".to_string(),
        },
    );
    org.apps.insert(
        "admin-app".to_string(),
        AppConfig {
            domains: admin_domains,
            policies: vec![],
        },
    );

    // /api/users matches web-app (longest prefix /api)
    assert_eq!(
        find_matching_app(&org, "pr1.example.com", "/api/users"),
        Some("web-app".to_string())
    );

    // /admin/settings matches admin-app (longest prefix /admin)
    assert_eq!(
        find_matching_app(&org, "pr1.example.com", "/admin/settings"),
        Some("admin-app".to_string())
    );

    // /unknown matches nothing
    assert!(find_matching_app(&org, "pr1.example.com", "/unknown").is_none());
}

#[test]
fn test_find_matching_app_longest_prefix_wins() {
    let mut org = make_test_org();

    // Add a more specific path to web-app
    if let Some(web_app) = org.apps.get_mut("web-app") {
        if let Some(domain_config) = web_app.domains.get_mut("pr1.example.com") {
            domain_config.paths.push("/api/v2/admin".to_string());
        }
    }

    // /api/v2/admin/users matches /api/v2/admin (longer) over /api
    assert_eq!(
        find_matching_app(&org, "pr1.example.com", "/api/v2/admin/users"),
        Some("web-app".to_string())
    );
}

// ── evaluate_policies tests ──────────────────────────────────────────────

#[test]
fn test_evaluate_policies_without_resource() {
    let org = make_test_org();
    let claims = TokenClaims {
        sub: "user-1".to_string(),
        org_id: "org-1".to_string(),
        app: "web-app".to_string(),
        roles: vec![],
        permissions: vec![],
        iss: None,
        aud: None,
        exp: None,
        iat: None,
    };

    let result = evaluate_policies(&org, "pr1.example.com", &HttpMethod::Get, &claims);
    assert!(result.is_ok());
}

#[test]
fn test_evaluate_policies_deny_blocks() {
    let mut org = make_test_org();
    org.apps.insert(
        "restricted-app".to_string(),
        AppConfig {
            domains: HashMap::from([(
                "pr1.example.com".to_string(),
                AppDomainConfig {
                    paths: vec!["/api".to_string()],
                    r#type: "primary".to_string(),
                },
            )]),
            policies: vec![Policy {
                id: "pol-deny".to_string(),
                name: "Deny POST".to_string(),
                effect: PolicyEffect::Deny,
                rules: vec![PolicyRule {
                    methods: HashSet::from([HttpMethod::Post]),
                    conditions: vec![],
                }],
            }],
        },
    );

    let claims = TokenClaims {
        sub: "user-1".to_string(),
        org_id: "org-1".to_string(),
        app: "restricted-app".to_string(),
        roles: vec![],
        permissions: vec![],
        iss: None,
        aud: None,
        exp: None,
        iat: None,
    };

    assert!(evaluate_policies(&org, "pr1.example.com", &HttpMethod::Post, &claims).is_err());
    assert!(evaluate_policies(&org, "pr1.example.com", &HttpMethod::Get, &claims).is_err());
}

#[test]
fn test_evaluate_policies_empty_app_denied() {
    let org = make_test_org();
    let claims = TokenClaims {
        sub: "user-1".to_string(),
        org_id: "org-1".to_string(),
        app: String::new(),
        roles: vec![],
        permissions: vec![],
        iss: None,
        aud: None,
        exp: None,
        iat: None,
    };

    assert!(evaluate_policies(&org, "pr1.example.com", &HttpMethod::Get, &claims).is_err());
}

// ── app domain hashmap access ────────────────────────────────────────────

#[test]
fn test_app_domain_hashmap_access() {
    let org = make_test_org();
    let web_app = org.apps.get("web-app").unwrap();

    assert!(web_app.domains.contains_key("pr1.example.com"));
    assert!(!web_app.domains.contains_key("other.example.com"));

    let domain_config = web_app.domains.get("pr1.example.com").unwrap();
    assert_eq!(domain_config.paths, vec!["/api".to_string(), "/web".to_string()]);
    assert_eq!(domain_config.r#type, "primary");
}

// ── primary vs dependency ────────────────────────────────────────────────

#[test]
fn test_primary_vs_dependency() {
    let mut org = make_test_org();

    org.apps.insert(
        "dep-app".to_string(),
        AppConfig {
            domains: HashMap::from([(
                "pr1.example.com".to_string(),
                AppDomainConfig {
                    paths: vec!["/dep".to_string()],
                    r#type: "dependency".to_string(),
                },
            )]),
            policies: vec![Policy {
                id: "pol-dep".to_string(),
                name: "Allow GET".to_string(),
                effect: PolicyEffect::Allow,
                rules: vec![PolicyRule {
                    methods: HashSet::from([HttpMethod::Get]),
                    conditions: vec![],
                }],
            }],
        },
    );

    // Primary type
    let primary_config = org
        .apps
        .get("web-app")
        .unwrap()
        .domains
        .get("pr1.example.com")
        .unwrap();
    assert_eq!(primary_config.r#type, "primary");

    // Dependency type
    let dep_config = org
        .apps
        .get("dep-app")
        .unwrap()
        .domains
        .get("pr1.example.com")
        .unwrap();
    assert_eq!(dep_config.r#type, "dependency");

    // Both match via find_matching_app
    assert_eq!(
        find_matching_app(&org, "pr1.example.com", "/api"),
        Some("web-app".to_string())
    );
    assert_eq!(
        find_matching_app(&org, "pr1.example.com", "/dep"),
        Some("dep-app".to_string())
    );
}
