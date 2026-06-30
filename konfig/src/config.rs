use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub organizations: HashMap<String, Organization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    #[serde(default)]
    pub domain_policies: HashMap<String, Vec<Policy>>,
    pub upstream: UpstreamConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub timeout_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

fn default_max_retries() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_issuer: String,
    pub jwt_audience: String,
    #[serde(default)]
    pub jwks_url: String,
    pub jwt_public_key: String,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    pub redirect_url: String,
    #[serde(default)]
    pub idp_url: String,
}

fn default_cookie_name() -> String {
    "session_token".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub org_key: String,
    pub pubsub_channel: String,
}
