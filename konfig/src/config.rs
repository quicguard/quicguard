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
    pub jwks_url: String,
    pub token_header: String,
    #[serde(default = "default_token_prefix")]
    pub token_prefix: String,
    pub redirect_url: String,
}

fn default_token_prefix() -> String {
    "Bearer".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub org_key: String,
    pub pubsub_channel: String,
}
