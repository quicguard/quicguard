use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use futures_util::StreamExt;
use jsonwebtoken::Validation;

pub mod config;
pub mod policy;

pub use config::*;
pub use policy::*;

#[derive(Debug)]
pub enum ProxyError {
    OrganizationNotFound,
    MissingToken,
    InvalidToken,
    ExpiredToken,
    InvalidMethod,
    AccessDenied,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::OrganizationNotFound => write!(f, "Organization not found"),
            ProxyError::MissingToken => write!(f, "Missing authentication token"),
            ProxyError::InvalidToken => write!(f, "Invalid authentication token"),
            ProxyError::ExpiredToken => write!(f, "Authentication token has expired"),
            ProxyError::InvalidMethod => write!(f, "Invalid HTTP method"),
            ProxyError::AccessDenied => write!(f, "Access denied"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// Parse a raw `Cookie` header value and return the value for `cookie_name`.
///
/// Format: `"name1=value1; name2=value2"`
pub fn parse_cookie(cookie_header: &str, cookie_name: &str) -> Option<String> {
    cookie_header.split(';').find_map(|pair| {
        let pair = pair.trim();
        let mut parts = pair.splitn(2, '=');
        let name = parts.next()?.trim();
        let value = parts.next()?.trim();
        if name == cookie_name {
            Some(value.to_string())
        } else {
            None
        }
    })
}

pub struct ProxyState {
    pub config: tokio::sync::RwLock<ProxyConfig>,
    pub org_index: tokio::sync::RwLock<HashMap<String, String>>,
    pub redis_config: RedisConfig,
    pub auth_config: AuthConfig,
    pub config_version: AtomicU64,
}

impl ProxyState {
    pub fn empty(redis_cfg: RedisConfig) -> Self {
        Self {
            config: tokio::sync::RwLock::new(ProxyConfig {
                organizations: HashMap::new(),
            }),
            org_index: tokio::sync::RwLock::new(HashMap::new()),
            redis_config: redis_cfg,
            auth_config: AuthConfig {
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
            },
            config_version: AtomicU64::new(0),
        }
    }

    pub async fn from_redis(
        redis_cfg: RedisConfig,
        auth_cfg: AuthConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let client = redis::Client::open(redis_cfg.url.as_str())?;
        let mut conn = client.get_multiplexed_async_connection().await?;

        let raw: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(&redis_cfg.org_key)
            .query_async(&mut conn)
            .await?;

        let mut orgs = HashMap::new();
        for (id, json) in &raw {
            if let Ok(org) = serde_json::from_str::<Organization>(json) {
                orgs.insert(id.clone(), org);
            }
        }

        let org_index: HashMap<String, String> = orgs
            .iter()
            .flat_map(|(id, org)| org.domains.keys().map(move |d| (d.clone(), id.clone())))
            .collect();

        Ok(Self {
            config: tokio::sync::RwLock::new(ProxyConfig {
                organizations: orgs,
            }),
            org_index: tokio::sync::RwLock::new(org_index),
            redis_config: redis_cfg,
            auth_config: auth_cfg,
            config_version: AtomicU64::new(0),
        })
    }

    pub async fn lookup_org(&self, domain: &str) -> Option<Organization> {
        let org_index = self.org_index.read().await;
        let org_id = org_index.get(domain)?;
        let config = self.config.read().await;
        config.organizations.get(org_id).cloned()
    }

    pub async fn reload_org(&self, org_id: &str, org: Organization) {
        let old_domains: Vec<String> = {
            let config = self.config.read().await;
            config.organizations.get(org_id).map(|o| o.domains.keys().cloned().collect()).unwrap_or_default()
        };

        {
            let mut org_index = self.org_index.write().await;
            for domain in &old_domains {
                org_index.remove(domain);
            }
            for domain in org.domains.keys() {
                org_index.insert(domain.clone(), org_id.to_string());
            }
        }

        let mut config = self.config.write().await;
        config.organizations.insert(org_id.to_string(), org);
        self.config_version.fetch_add(1, Ordering::SeqCst);
    }

    pub async fn remove_org(&self, org_id: &str) {
        let mut config = self.config.write().await;
        if let Some(org) = config.organizations.remove(org_id) {
            let mut org_index = self.org_index.write().await;
            for domain in org.domains.keys() {
                org_index.remove(domain);
            }
        }
        self.config_version.fetch_add(1, Ordering::SeqCst);
    }
}

pub async fn redis_subscriber(
    state: std::sync::Arc<ProxyState>,
    updates: tokio::sync::mpsc::Sender<OrgUpdate>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = redis::Client::open(state.redis_config.url.as_str())?;
    let mut pubsub = client.get_async_pubsub().await?;

    pubsub
        .subscribe(&state.redis_config.pubsub_channel)
        .await?;

    let mut msg_stream = pubsub.on_message();

    while let Some(msg) = msg_stream.next().await {
        let payload: String = msg.get_payload()?;

        if let Ok(update) = serde_json::from_str::<OrgUpdate>(&payload) {
            let _ = updates.send(update).await;
        }
    }

    Ok(())
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OrgUpdate {
    pub org_id: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub organization: Option<Organization>,
}

pub fn validate_jwt(
    token: &str,
    auth_config: &AuthConfig,
) -> Result<TokenClaims, ProxyError> {
    let key = jsonwebtoken::DecodingKey::from_ed_pem(auth_config.jwt_public_key.as_bytes())
        .map_err(|_| ProxyError::InvalidToken)?;

    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&[auth_config.jwt_issuer.as_str()]);
    validation.set_audience(&[&auth_config.jwt_audience]);
    validation.validate_exp = true;
    validation.required_spec_claims.clear();

    let token_data = jsonwebtoken::decode::<TokenClaims>(token, &key, &validation).map_err(
        |e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => ProxyError::ExpiredToken,
            _ => ProxyError::InvalidToken,
        },
    )?;

    Ok(token_data.claims)
}

pub fn evaluate_policies(
    org: &Organization,
    domain: &str,
    method: &HttpMethod,
    path: &str,
    claims: &TokenClaims,
) -> Result<(), ProxyError> {
    let app_id = if claims.app.is_empty() {
        return Err(ProxyError::AccessDenied);
    } else {
        claims.app.clone()
    };

    let app = org.apps.get(&app_id).ok_or(ProxyError::AccessDenied)?;

    if !app.domains.iter().any(|d| d == domain) {
        return Err(ProxyError::AccessDenied);
    }

    let mut any_deny = false;
    let mut any_allow = false;

    for policy in &app.policies {
        if policy.matches_request(method, path, claims) {
            match policy.effect {
                PolicyEffect::Deny => any_deny = true,
                PolicyEffect::Allow => any_allow = true,
            }
        }
    }

    if any_deny {
        return Err(ProxyError::AccessDenied);
    }
    if any_allow || app.policies.is_empty() {
        Ok(())
    } else {
        Err(ProxyError::AccessDenied)
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use std::collections::HashMap;
    use std::collections::HashSet;

    fn make_app_org() -> Organization {
        let mut apps = HashMap::new();
        apps.insert(
            "web-app".to_string(),
            AppConfig {
                domains: vec!["app.example.com".to_string()],
                policies: vec![Policy {
                    id: "pol-1".to_string(),
                    name: "Allow GET".to_string(),
                    effect: PolicyEffect::Allow,
                    rules: vec![PolicyRule {
                        resource: ResourcePattern::Prefix("/".to_string()),
                        methods: HashSet::from([HttpMethod::Get]),
                        conditions: vec![],
                    }],
                }],
            },
        );

        Organization {
            id: "org-test".to_string(),
            name: "Test Org".to_string(),
            domains: HashMap::new(),
            apps,
            user_groups: HashMap::new(),
            app_user_groups: HashMap::new(),
            auth: AuthConfig {
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
            },
        }
    }

    #[test]
    fn test_evaluate_policies_with_valid_app() {
        let org = make_app_org();
        let claims = TokenClaims {
            sub: "user-1".to_string(),
            org_id: "org-test".to_string(),
            app: "web-app".to_string(),
            roles: vec![],
            permissions: vec![],
            iss: None,
            aud: None,
            exp: None,
            iat: None,
        };

        let result =
            evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/", &claims);
        assert!(result.is_ok());
    }

    #[test]
    fn test_evaluate_policies_with_invalid_app() {
        let org = make_app_org();
        let claims = TokenClaims {
            sub: "user-1".to_string(),
            org_id: "org-test".to_string(),
            app: "nonexistent".to_string(),
            roles: vec![],
            permissions: vec![],
            iss: None,
            aud: None,
            exp: None,
            iat: None,
        };

        let result =
            evaluate_policies(&org, "app.example.com", &HttpMethod::Get, "/", &claims);
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_policies_with_wrong_domain() {
        let org = make_app_org();
        let claims = TokenClaims {
            sub: "user-1".to_string(),
            org_id: "org-test".to_string(),
            app: "web-app".to_string(),
            roles: vec![],
            permissions: vec![],
            iss: None,
            aud: None,
            exp: None,
            iat: None,
        };

        let result =
            evaluate_policies(&org, "other.example.com", &HttpMethod::Get, "/", &claims);
        assert!(result.is_err());
    }
}
