use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::policy::Policy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub organizations: HashMap<String, Organization>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub cert_pem: String,
    #[serde(default)]
    pub key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub domains: HashMap<String, DomainConfig>,
    #[serde(default)]
    pub apps: HashMap<String, AppConfig>,
    #[serde(default)]
    pub user_groups: HashMap<String, UserGroup>,
    #[serde(default)]
    pub app_user_groups: HashMap<String, Vec<String>>,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDomainConfig {
    pub paths: Vec<String>,
    #[serde(default = "default_primary")]
    pub r#type: String,
}

fn default_primary() -> String {
    "primary".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub domains: HashMap<String, AppDomainConfig>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum UserGroup {
    #[serde(rename = "email_otp")]
    EmailOtp {
        #[serde(default)]
        emails: Vec<String>,
        #[serde(default)]
        email_patterns: Vec<String>,
    },
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
    #[serde(default)]
    pub jwt_private_key: String,
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    pub redirect_url: String,
    #[serde(default)]
    pub idp_url: String,
    #[serde(default = "default_req_param_name")]
    pub req_param_name: String,
    #[serde(default = "default_token_param_name")]
    pub token_param_name: String,
}

fn default_cookie_name() -> String {
    "session_token".to_string()
}

fn default_req_param_name() -> String {
    "req".to_string()
}

fn default_token_param_name() -> String {
    "token".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub org_key: String,
    pub pubsub_channel: String,
}
