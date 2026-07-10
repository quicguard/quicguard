use serde::{Deserialize, Serialize};

use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum PolicyEffect {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub resource: ResourcePattern,
    pub methods: HashSet<HttpMethod>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourcePattern {
    /// Exact match: "/api/v1/users"
    Exact(String),
    /// Prefix match: "/api/v1/"
    Prefix(String),
    /// Glob match: "/api/v1/users/*"
    Glob(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub claim: String,
    pub operator: ConditionOperator,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    In,
    NotIn,
    Contains,
    StartsWith,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub org_id: String,
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(default)]
    pub iat: Option<u64>,
}

impl Policy {
    pub fn matches_request(&self, method: &HttpMethod, path: &str, claims: &TokenClaims) -> bool {
        self.rules.iter().any(|rule| {
            rule.methods.contains(method)
                && rule.resource.matches(path)
                && rule.conditions.iter().all(|c| c.evaluate(claims))
        })
    }
}

impl ResourcePattern {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            ResourcePattern::Exact(exact) => path == exact,
            ResourcePattern::Prefix(prefix) => path.starts_with(prefix),
            ResourcePattern::Glob(glob) => glob_match(glob, path),
        }
    }
}

impl Condition {
    pub fn evaluate(&self, claims: &TokenClaims) -> bool {
        let claim_value = match self.claim.as_str() {
            "sub" => Some(&claims.sub),
            "org_id" => Some(&claims.org_id),
            "app" => Some(&claims.app),
            _ => None,
        };

        match claim_value {
            Some(val) => match self.operator {
                ConditionOperator::Equals => val == &self.value,
                ConditionOperator::NotEquals => val != &self.value,
                ConditionOperator::Contains => val.contains(&self.value),
                ConditionOperator::StartsWith => val.starts_with(&self.value),
                ConditionOperator::In => self.value.split(',').any(|v| v == val.as_str()),
                ConditionOperator::NotIn => !self.value.split(',').any(|v| v == val.as_str()),
            },
            None => false,
        }
    }
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    glob_match_inner(&pattern, &text)
}

fn glob_match_inner(pattern: &[char], text: &[char]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }

    if pattern[0] == '*' {
        for i in 0..=text.len() {
            if glob_match_inner(&pattern[1..], &text[i..]) {
                return true;
            }
        }
        return false;
    }

    if !text.is_empty() && (pattern[0] == '?' || pattern[0] == text[0]) {
        return glob_match_inner(&pattern[1..], &text[1..]);
    }

    false
}
