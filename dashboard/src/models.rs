use std::collections::HashMap;

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

// --- Per-domain input ---

#[derive(Debug, Deserialize)]
pub struct DomainInput {
    pub upstream_base_url: String,
    pub upstream_timeout_ms: u64,
    pub upstream_max_retries: Option<u32>,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub auto_generate_tls: bool,
}

#[derive(Debug, Deserialize)]
pub struct AppInput {
    pub domains: Vec<String>,
    #[serde(default)]
    pub policies: Vec<AddPolicy>,
}

#[derive(Debug, Deserialize)]
pub struct UserGroupInput {
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub email_patterns: Vec<String>,
}

// --- Structured org creation ---

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub id: String,
    pub name: String,
    pub domains: HashMap<String, DomainInput>,
    #[serde(default)]
    pub apps: HashMap<String, AppInput>,
    #[serde(default)]
    pub user_groups: HashMap<String, UserGroupInput>,
    #[serde(default)]
    pub app_user_groups: HashMap<String, Vec<String>>,
    // Auth (shared across all domains)
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_public_key: Option<String>,
    pub auto_generate_jwt_keys: bool,
    pub cookie_name: Option<String>,
    pub redirect_url: Option<String>,
    pub idp_url: Option<String>,
    pub req_param_name: Option<String>,
    pub token_param_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    pub domains: Option<HashMap<String, DomainInput>>,
    #[serde(default)]
    pub apps: Option<HashMap<String, AppInput>>,
    #[serde(default)]
    pub user_groups: Option<HashMap<String, UserGroupInput>>,
    #[serde(default)]
    pub app_user_groups: Option<HashMap<String, Vec<String>>>,
    // Auth fields
    pub jwt_issuer: Option<String>,
    pub jwt_audience: Option<String>,
    pub jwt_public_key: Option<String>,
    pub auto_generate_jwt_keys: Option<bool>,
    pub cookie_name: Option<String>,
    pub redirect_url: Option<String>,
    pub idp_url: Option<String>,
    pub req_param_name: Option<String>,
    pub token_param_name: Option<String>,
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
