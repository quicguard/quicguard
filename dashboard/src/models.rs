use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub approved: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organization {
    pub id: String,
    pub owner_id: Uuid,
    pub name: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

// --- Structured org creation ---

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationStructured {
    pub id: String,
    pub name: String,
    pub domains: Vec<String>,
    // Upstream
    pub upstream_base_url: String,
    pub upstream_timeout_ms: u64,
    pub upstream_max_retries: Option<u32>,
    // Auth
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_public_key: Option<String>,
    pub auto_generate_jwt_keys: bool,
    pub cookie_name: Option<String>,
    pub redirect_url: Option<String>,
    pub idp_url: Option<String>,
    // TLS
    pub tls_configs: Vec<TlsInput>,
}

#[derive(Debug, Deserialize)]
pub struct TlsInput {
    pub domain: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub auto_generate: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganizationStructured {
    pub name: Option<String>,
    pub domains: Option<Vec<String>>,
    pub upstream_base_url: Option<String>,
    pub upstream_timeout_ms: Option<u64>,
    pub upstream_max_retries: Option<u32>,
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub jwt_public_key: Option<String>,
    pub auto_generate_jwt_keys: Option<bool>,
    pub cookie_name: Option<String>,
    pub redirect_url: Option<String>,
    pub idp_url: Option<String>,
    pub tls_configs: Option<Vec<TlsInput>>,
}

// --- Policy management ---

#[derive(Debug, Deserialize)]
pub struct AddPolicy {
    pub policy_id: String,
    pub name: String,
    pub effect: Option<String>,
    pub rules: Vec<PolicyRuleInput>,
}

#[derive(Debug, Deserialize)]
pub struct PolicyRuleInput {
    pub resource_type: String,
    pub resource_value: String,
    pub methods: Vec<String>,
    pub conditions: Option<Vec<ConditionInput>>,
}

#[derive(Debug, Deserialize)]
pub struct ConditionInput {
    pub claim: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct AddDomainPolicy {
    pub domain: String,
    pub policy_id: String,
    pub name: String,
    pub effect: Option<String>,
    pub rules: Vec<PolicyRuleInput>,
}
