use std::collections::HashMap;

use konfig::*;

fn default_auth() -> AuthConfig {
    AuthConfig {
        jwt_issuer: "https://auth.example.com".to_string(),
        jwt_audience: "proxy".to_string(),
        jwks_url: "https://auth.example.com/.well-known/jwks.json".to_string(),
        jwt_public_key: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAB8WW87geWYlziXa6h0b17GTogvEcdkCk+XWhrX/hS+Y=\n-----END PUBLIC KEY-----".to_string(),
        cookie_name: "session_token".to_string(),
        redirect_url: "https://auth.example.com/login".to_string(),
        idp_url: String::new(),
    }
}

fn default_upstream() -> UpstreamConfig {
    UpstreamConfig {
        base_url: "https://api.example.com".to_string(),
        timeout_ms: 5000,
        max_retries: 3,
    }
}

fn default_redis() -> RedisConfig {
    RedisConfig {
        url: "redis://127.0.0.1:6379".to_string(),
        org_key: "proxy:organizations".to_string(),
        pubsub_channel: "proxy:config_updates".to_string(),
    }
}

fn test_org(id: &str, domains: Vec<&str>) -> Organization {
    Organization {
        id: id.to_string(),
        name: format!("Org {}", id),
        domains: domains.into_iter().map(String::from).collect(),
        policies: vec![],
        domain_policies: HashMap::new(),
        upstream: default_upstream(),
        auth: default_auth(),
    }
}

#[tokio::test]
async fn test_proxy_state_lookup_existing_org() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::from([(
                "org1".to_string(),
                test_org("org1", vec!["app.example.com"]),
            )]),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::from([(
            "app.example.com".to_string(),
            "org1".to_string(),
        )])),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    let org = state.lookup_org("app.example.com").await;
    assert!(org.is_some());
    assert_eq!(org.unwrap().id, "org1");
}

#[tokio::test]
async fn test_proxy_state_lookup_nonexistent_domain() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::new(),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::new()),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    let org = state.lookup_org("unknown.example.com").await;
    assert!(org.is_none());
}

#[tokio::test]
async fn test_proxy_state_reload_org() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::new(),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::new()),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    let org = test_org("org1", vec!["app.example.com"]);
    state.reload_org("org1", org).await;

    let found = state.lookup_org("app.example.com").await;
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, "org1");
}

#[tokio::test]
async fn test_proxy_state_reload_updates_existing() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::from([(
                "org1".to_string(),
                test_org("org1", vec!["old.example.com"]),
            )]),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::from([(
            "old.example.com".to_string(),
            "org1".to_string(),
        )])),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    let updated_org = Organization {
        id: "org1".to_string(),
        name: "Updated Org".to_string(),
        domains: vec!["new.example.com".to_string()],
        policies: vec![],
        domain_policies: HashMap::new(),
        upstream: default_upstream(),
        auth: default_auth(),
    };
    state.reload_org("org1", updated_org).await;

    assert!(state.lookup_org("old.example.com").await.is_none());
    assert!(state.lookup_org("new.example.com").await.is_some());
}

#[tokio::test]
async fn test_proxy_state_remove_org() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::from([(
                "org1".to_string(),
                test_org("org1", vec!["app.example.com"]),
            )]),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::from([(
            "app.example.com".to_string(),
            "org1".to_string(),
        )])),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    state.remove_org("org1").await;

    assert!(state.lookup_org("app.example.com").await.is_none());
    let config = state.config.read().await;
    assert!(!config.organizations.contains_key("org1"));
}

#[tokio::test]
async fn test_proxy_state_remove_nonexistent_org() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::new(),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::new()),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    state.remove_org("nonexistent").await;

    let config = state.config.read().await;
    assert!(config.organizations.is_empty());
}

#[tokio::test]
async fn test_proxy_state_multiple_domains_per_org() {
    let state = ProxyState {
        config: tokio::sync::RwLock::new(ProxyConfig {
            organizations: HashMap::from([(
                "org1".to_string(),
                test_org("org1", vec!["app1.example.com", "app2.example.com"]),
            )]),
        }),
        org_index: tokio::sync::RwLock::new(HashMap::from([
            ("app1.example.com".to_string(), "org1".to_string()),
            ("app2.example.com".to_string(), "org1".to_string()),
        ])),
        redis_config: default_redis(),
        auth_config: default_auth(),
    };

    assert!(state.lookup_org("app1.example.com").await.is_some());
    assert!(state.lookup_org("app2.example.com").await.is_some());

    state.remove_org("org1").await;

    assert!(state.lookup_org("app1.example.com").await.is_none());
    assert!(state.lookup_org("app2.example.com").await.is_none());
}
