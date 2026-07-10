# Org Config Restructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure the per-org config to separate domains, apps, user groups, and add configurable auth parameter names, with app-based policy evaluation in QuicGuard.

**Architecture:** The config shape changes from flat domain+policy to a layered model: domains (upstream+tls only) → apps (domains+policies) → user_groups (email OTP) → app_user_groups (N-to-N). QuicGuard reads the `app` claim from JWT and evaluates policies at the app level. Auth parameter names become configurable per-org.

**Tech Stack:** Rust (konfig, quicguard, dashboard backend), Svelte (dashboard frontend), Redis (config storage), PostgreSQL (dashboard DB)

## Global Constraints

- JWT keys use Ed25519 (PKCS_ED25519) — same as current
- Config JSON must be backward-compatible for Redis sync (konfig::Organization deserialization)
- All existing tests must continue to pass after each task
- Frontend uses Svelte 4 with svelte-spa-router
- No new external dependencies unless absolutely required

---

## File Structure

### Konfig Library (`konfig/src/`)

| File | Responsibility |
|------|---------------|
| `config.rs` | Config structs: `Organization`, `DomainConfig`, `AppConfig`, `UserGroup`, `AuthConfig` |
| `policy.rs` | `TokenClaims` with `app` field, `Policy`, `PolicyRule`, `Condition` |
| `lib.rs` | `evaluate_policies` (app-based), `validate_jwt`, `ProxyState`, `redis_subscriber` |

### QuicGuard Server (`src/`)

| File | Responsibility |
|------|---------------|
| `http3.rs` | Request handling with configurable `req_param_name` and `token_param_name` |

### Dashboard Backend (`dashboard/src/`)

| File | Responsibility |
|------|---------------|
| `models.rs` | Input structs: `CreateOrganization`, `UpdateOrganization`, `AppInput`, `UserGroupInput` |
| `routes/organizations.rs` | `build_org_config`, `build_update_config` with new shape |
| `auth.rs` | JWT creation with `app` claim |

### Dashboard Frontend (`dashboard/frontend/src/`)

| File | Responsibility |
|------|---------------|
| `routes/Dashboard.svelte` | UI for apps, user groups, app-user group assignments |
| `lib/api.js` | API calls (if new endpoints needed) |

---

## Task 1: Konfig — Config Structs

**Covers:** New config shape with apps, user_groups, app_user_groups; remove policies from DomainConfig; add jwt_private_key, req_param_name, token_param_name to AuthConfig

**Files:**
- Modify: `konfig/src/config.rs`
- Test: `konfig/tests/` (if integration tests exist)

**Interfaces:**
- Consumes: existing `Policy` type from `policy.rs`
- Produces: `Organization`, `AppConfig`, `UserGroup`, `UserGroupType` structs used by `lib.rs`

- [ ] **Step 1: Read current config.rs**

Read `konfig/src/config.rs` to understand current structs.

- [ ] **Step 2: Update AuthConfig**

Add `jwt_private_key`, `req_param_name`, `token_param_name` fields:

```rust
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

fn default_req_param_name() -> String {
    "req".to_string()
}

fn default_token_param_name() -> String {
    "token".to_string()
}
```

- [ ] **Step 3: Add AppConfig struct**

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub domains: Vec<String>,
    #[serde(default)]
    pub policies: Vec<Policy>,
}
```

- [ ] **Step 4: Add UserGroup structs**

```rust
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
```

- [ ] **Step 5: Remove policies from DomainConfig**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    // policies removed — now in AppConfig
}
```

- [ ] **Step 6: Update Organization struct**

```rust
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
```

- [ ] **Step 7: Update ProxyState and related code in lib.rs**

In `lib.rs`, the `ProxyState::empty()` and `ProxyState::from_redis()` methods reference `AuthConfig` fields. Update the defaults in `empty()`:

```rust
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
```

- [ ] **Step 8: Run existing konfig tests**

Run: `cargo test -p konfig`
Expected: All tests pass (existing tests don't use `policies` field in `DomainConfig` directly — they use helper functions)

- [ ] **Step 9: Update konfig test helpers**

In `konfig/src/lib.rs` tests, update `make_auth()` and `make_org()` to include new fields:

```rust
fn make_auth() -> AuthConfig {
    AuthConfig {
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
    }
}
```

Update `make_org()` to include `apps`, `user_groups`, `app_user_groups`:

```rust
Organization {
    id: org_id.to_string(),
    name: format!("Org {org_id}"),
    domains: domain_configs,
    apps: HashMap::new(),
    user_groups: HashMap::new(),
    app_user_groups: HashMap::new(),
    auth: make_auth(),
}
```

- [ ] **Step 10: Run konfig tests again**

Run: `cargo test -p konfig`
Expected: All tests pass

- [ ] **Step 11: Commit**

```bash
git add konfig/src/config.rs konfig/src/lib.rs
git commit -m "feat(konfig): restructure config with apps, user_groups, configurable auth params"
```

---

## Task 2: Konfig — TokenClaims with `app` field

**Covers:** Add `app` claim to JWT token claims

**Files:**
- Modify: `konfig/src/policy.rs:68-84`

**Interfaces:**
- Consumes: nothing (standalone change)
- Produces: `TokenClaims` used by `evaluate_policies` and quicguard

- [ ] **Step 1: Add `app` field to TokenClaims**

```rust
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
```

- [ ] **Step 2: Run konfig tests**

Run: `cargo test -p konfig`
Expected: All tests pass (existing tests don't assert on `app` field)

- [ ] **Step 3: Commit**

```bash
git add konfig/src/policy.rs
git commit -m "feat(konfig): add app claim to TokenClaims"
```

---

## Task 3: Konfig — App-based Policy Evaluation

**Covers:** QuicGuard checks policies based on app claim in token, verifies domain exists in app, evaluates app policies

**Files:**
- Modify: `konfig/src/lib.rs:215-244` (`evaluate_policies`)

**Interfaces:**
- Consumes: `Organization`, `TokenClaims` (with `app` field)
- Produces: `Result<(), ProxyError>` — same as before

- [ ] **Step 1: Rewrite evaluate_policies**

Replace the current `evaluate_policies` function:

```rust
pub fn evaluate_policies(
    org: &Organization,
    domain: &str,
    method: &HttpMethod,
    path: &str,
    claims: &TokenClaims,
) -> Result<(), ProxyError> {
    // 1. Find the app by claims.app
    let app_id = if claims.app.is_empty() {
        return Err(ProxyError::AccessDenied);
    };
    let app = org.apps.get(&app_id).ok_or(ProxyError::AccessDenied)?;

    // 2. Verify domain is in this app's domain list
    if !app.domains.contains(&domain.to_string()) {
        return Err(ProxyError::AccessDenied);
    }

    // 3. Evaluate app policies
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
```

- [ ] **Step 2: Add test for app-based policy evaluation**

Add to `konfig/src/lib.rs` tests:

```rust
#[cfg(test)]
mod policy_tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn make_app_org() -> Organization {
        let mut apps = HashMap::new();
        apps.insert("web-app".to_string(), AppConfig {
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
        });

        Organization {
            id: "org-test".to_string(),
            name: "Test Org".to_string(),
            domains: HashMap::new(),
            apps,
            user_groups: HashMap::new(),
            app_user_groups: HashMap::new(),
            auth: make_auth(),
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

        let result = evaluate_policies(
            &org, "app.example.com", &HttpMethod::Get, "/", &claims,
        );
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

        let result = evaluate_policies(
            &org, "app.example.com", &HttpMethod::Get, "/", &claims,
        );
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

        let result = evaluate_policies(
            &org, "other.example.com", &HttpMethod::Get, "/", &claims,
        );
        assert!(result.is_err());
    }
}
```

- [ ] **Step 3: Run konfig tests**

Run: `cargo test -p konfig`
Expected: All tests pass including new policy tests

- [ ] **Step 4: Commit**

```bash
git add konfig/src/lib.rs
git commit -m "feat(konfig): implement app-based policy evaluation"
```

---

## Task 4: QuicGuard — Configurable Auth Parameters

**Covers:** Use configurable req_param_name and token_param_name in redirect flow

**Files:**
- Modify: `src/http3.rs:108-172`

**Interfaces:**
- Consumes: `org.auth.req_param_name`, `org.auth.token_param_name`
- Produces: redirect URLs with correct parameter names

- [ ] **Step 1: Update IDP redirect to use configurable param name**

In `http3.rs`, replace the hardcoded `redirect_uri` with `req_param_name`:

```rust
// Line ~162-163: Change from:
let callback_url = format!("{idp_url}?redirect_uri={}", urlencoding::encode(&original_url));
// To:
let req_param = &org.auth.req_param_name;
let callback_url = format!("{idp_url}?{req_param}={}", urlencoding::encode(&original_url));
```

Do the same for the second redirect block (lines ~194-195).

- [ ] **Step 2: Update token callback to use configurable param name**

In `http3.rs`, replace the hardcoded `token` query param check with `token_param_name`:

```rust
// Line ~110-136: Change from:
if key == "token" && !val.is_empty() {
// To:
let token_param = &org.auth.token_param_name;
// ... in the loop:
if key == token_param && !val.is_empty() {
```

- [ ] **Step 3: Run quicguard tests**

Run: `cargo test -p quicguard` or `cargo test` from project root
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/http3.rs
git commit -m "feat(quicguard): use configurable auth parameter names"
```

---

## Task 5: Dashboard Backend — Models

**Covers:** New input structs for apps, user_groups, app_user_groups

**Files:**
- Modify: `dashboard/src/models.rs`

**Interfaces:**
- Consumes: existing `AddPolicy`, `PolicyRuleInput`
- Produces: `CreateOrganization`, `UpdateOrganization` used by routes

- [ ] **Step 1: Add AppInput struct**

```rust
#[derive(Debug, Deserialize)]
pub struct AppInput {
    pub domains: Vec<String>,
    #[serde(default)]
    pub policies: Vec<AddPolicy>,
}
```

- [ ] **Step 2: Add UserGroupInput struct**

```rust
#[derive(Debug, Deserialize)]
pub struct UserGroupInput {
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub email_patterns: Vec<String>,
}
```

- [ ] **Step 3: Update CreateOrganization**

```rust
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
    // Auth fields
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub jwt_public_key: Option<String>,
    pub auto_generate_jwt_keys: bool,
    pub cookie_name: Option<String>,
    pub redirect_url: Option<String>,
    pub idp_url: Option<String>,
    #[serde(default = "default_req_param_name")]
    pub req_param_name: Option<String>,
    #[serde(default = "default_token_param_name")]
    pub token_param_name: Option<String>,
}

fn default_req_param_name() -> Option<String> {
    Some("req".to_string())
}

fn default_token_param_name() -> Option<String> {
    Some("token".to_string())
}
```

- [ ] **Step 4: Update UpdateOrganization**

```rust
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
```

- [ ] **Step 5: Run dashboard tests**

Run: `cargo test -p dashboard` or `cargo test` from `dashboard/`
Expected: Compilation succeeds (tests may fail until routes are updated)

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/models.rs
git commit -m "feat(dashboard): add app, user_group, and auth param input models"
```

---

## Task 6: Dashboard Backend — Config Builder

**Covers:** Build new config shape with apps, user_groups, app_user_groups

**Files:**
- Modify: `dashboard/src/routes/organizations.rs:37-131` (`build_org_config`)
- Modify: `dashboard/src/routes/organizations.rs:133-242` (`build_update_config`)

**Interfaces:**
- Consumes: `CreateOrganization`, `UpdateOrganization` (from Task 5)
- Produces: `serde_json::Value` config for Redis

- [ ] **Step 1: Update build_org_config**

Replace the function to include apps, user_groups, app_user_groups, and remove policies from domains:

```rust
fn build_org_config(input: &CreateOrganization) -> Result<Value, String> {
    // JWT keys (same as before)
    let (jwt_public_key, jwt_private_key) = if input.auto_generate_jwt_keys {
        let keys = generate::generate_jwt_keys().map_err(|e| e.to_string())?;
        (keys.public_key, keys.private_key)
    } else {
        let pk = input.jwt_public_key.clone().unwrap_or_default();
        (pk, String::new())
    };

    let cookie_name = input.cookie_name.clone().unwrap_or_else(|| "session_token".to_string());
    let redirect_url = input.redirect_url.clone().unwrap_or_default();
    let idp_url = input.idp_url.clone().unwrap_or_default();
    let req_param_name = input.req_param_name.clone().unwrap_or_else(|| "req".to_string());
    let token_param_name = input.token_param_name.clone().unwrap_or_else(|| "token".to_string());

    // Build per-domain configs (no policies)
    let mut domains = HashMap::new();
    for (domain_name, domain_input) in &input.domains {
        let (cert, key) = if domain_input.auto_generate_tls {
            let cert = generate::generate_tls_cert(domain_name).map_err(|e| e.to_string())?;
            (cert.cert_pem, cert.key_pem)
        } else {
            (
                domain_input.cert_pem.clone().unwrap_or_default(),
                domain_input.key_pem.clone().unwrap_or_default(),
            )
        };

        let max_retries = domain_input.upstream_max_retries.unwrap_or(3);

        domains.insert(
            domain_name.clone(),
            json!({
                "upstream": {
                    "base_url": domain_input.upstream_base_url,
                    "timeout_ms": domain_input.upstream_timeout_ms,
                    "max_retries": max_retries
                },
                "tls": {
                    "cert_pem": cert,
                    "key_pem": key
                }
            }),
        );
    }

    // Build apps (with domains and policies)
    let mut apps = HashMap::new();
    for (app_id, app_input) in &input.apps {
        let policies: Vec<Value> = app_input.policies.iter().map(|p| build_policy_value(p)).collect();
        apps.insert(
            app_id.clone(),
            json!({
                "domains": app_input.domains,
                "policies": policies
            }),
        );
    }

    // Build user_groups
    let mut user_groups = HashMap::new();
    for (group_id, group_input) in &input.user_groups {
        user_groups.insert(
            group_id.clone(),
            json!({
                "type": "email_otp",
                "emails": group_input.emails,
                "email_patterns": group_input.email_patterns
            }),
        );
    }

    let config = json!({
        "id": input.id,
        "name": input.name,
        "auth": {
            "jwt_issuer": input.jwt_issuer,
            "jwt_audience": input.jwt_audience,
            "jwt_public_key": jwt_public_key,
            "jwt_private_key": jwt_private_key,
            "cookie_name": cookie_name,
            "redirect_url": redirect_url,
            "idp_url": idp_url,
            "req_param_name": req_param_name,
            "token_param_name": token_param_name
        },
        "domains": domains,
        "apps": apps,
        "user_groups": user_groups,
        "app_user_groups": input.app_user_groups
    });

    Ok(config)
}
```

- [ ] **Step 2: Update build_update_config**

Update to handle apps, user_groups, app_user_groups, and new auth fields:

```rust
fn build_update_config(
    input: &UpdateOrganization,
    existing_config: &Value,
) -> Result<Value, String> {
    let mut config = existing_config.clone();
    let config_obj = config.as_object_mut().ok_or("Config is not a JSON object")?;

    // Update domains (same as before but without policies)
    if let Some(domains) = &input.domains {
        let existing_domains = config_obj
            .entry("domains".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("domains is not a JSON object")?;

        for (domain_name, domain_input) in domains {
            let domain_config = existing_domains
                .entry(domain_name.clone())
                .or_insert_with(|| json!({}));

            // Update upstream
            if let Some(upstream) = domain_config.get_mut("upstream").and_then(|v| v.as_object_mut()) {
                upstream.insert("base_url".to_string(), json!(domain_input.upstream_base_url));
                upstream.insert("timeout_ms".to_string(), json!(domain_input.upstream_timeout_ms));
                if let Some(retries) = domain_input.upstream_max_retries {
                    upstream.insert("max_retries".to_string(), json!(retries));
                }
            } else {
                let max_retries = domain_input.upstream_max_retries.unwrap_or(3);
                domain_config["upstream"] = json!({
                    "base_url": domain_input.upstream_base_url,
                    "timeout_ms": domain_input.upstream_timeout_ms,
                    "max_retries": max_retries
                });
            }

            // Update TLS
            if domain_input.auto_generate_tls {
                let cert = generate::generate_tls_cert(domain_name).map_err(|e| e.to_string())?;
                domain_config["tls"] = json!({
                    "cert_pem": cert.cert_pem,
                    "key_pem": cert.key_pem
                });
            } else if let (Some(cert), Some(key)) = (&domain_input.cert_pem, &domain_input.key_pem) {
                domain_config["tls"] = json!({
                    "cert_pem": cert,
                    "key_pem": key
                });
            }
        }
    }

    // Update apps
    if let Some(apps) = &input.apps {
        let existing_apps = config_obj
            .entry("apps".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("apps is not a JSON object")?;

        for (app_id, app_input) in apps {
            let policies: Vec<Value> = app_input.policies.iter().map(|p| build_policy_value(p)).collect();
            existing_apps.insert(
                app_id.clone(),
                json!({
                    "domains": app_input.domains,
                    "policies": policies
                }),
            );
        }
    }

    // Update user_groups
    if let Some(user_groups) = &input.user_groups {
        let existing_groups = config_obj
            .entry("user_groups".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("user_groups is not a JSON object")?;

        for (group_id, group_input) in user_groups {
            existing_groups.insert(
                group_id.clone(),
                json!({
                    "type": "email_otp",
                    "emails": group_input.emails,
                    "email_patterns": group_input.email_patterns
                }),
            );
        }
    }

    // Update app_user_groups
    if let Some(app_user_groups) = &input.app_user_groups {
        config_obj.insert("app_user_groups".to_string(), json!(app_user_groups));
    }

    // Update auth fields
    if let Some(auth) = config_obj.get_mut("auth") {
        if let Some(issuer) = &input.jwt_issuer {
            auth["jwt_issuer"] = json!(issuer);
        }
        if let Some(audience) = &input.jwt_audience {
            auth["jwt_audience"] = json!(audience);
        }
        if let Some(cookie) = &input.cookie_name {
            auth["cookie_name"] = json!(cookie);
        }
        if let Some(redirect) = &input.redirect_url {
            auth["redirect_url"] = json!(redirect);
        }
        if let Some(idp) = &input.idp_url {
            auth["idp_url"] = json!(idp);
        }
        if let Some(req_param) = &input.req_param_name {
            auth["req_param_name"] = json!(req_param);
        }
        if let Some(token_param) = &input.token_param_name {
            auth["token_param_name"] = json!(token_param);
        }

        // JWT key handling
        match input.auto_generate_jwt_keys {
            Some(true) => {
                let keys = generate::generate_jwt_keys().map_err(|e| e.to_string())?;
                auth["jwt_public_key"] = json!(keys.public_key);
                auth["jwt_private_key"] = json!(keys.private_key);
            }
            Some(false) => {
                if let Some(pub_key) = &input.jwt_public_key {
                    auth["jwt_public_key"] = json!(pub_key);
                }
            }
            None => {
                if let Some(pub_key) = &input.jwt_public_key {
                    auth["jwt_public_key"] = json!(pub_key);
                }
            }
        }
    }

    Ok(config)
}
```

- [ ] **Step 3: Run dashboard tests**

Run: `cargo test` from `dashboard/`
Expected: Compilation succeeds

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/routes/organizations.rs
git commit -m "feat(dashboard): update config builder for new org shape"
```

---

## Task 7: Dashboard Backend — JWT with `app` claim

**Covers:** Auth app generates JWT with app_id claim

**Files:**
- Modify: `dashboard/src/auth.rs:7-13` (Claims struct), `dashboard/src/auth.rs:23-46` (create_token)

**Interfaces:**
- Consumes: `app_id` parameter
- Produces: JWT string with `app` claim

- [ ] **Step 1: Add `app` field to Claims**

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub app: String,
    pub exp: usize,
}
```

- [ ] **Step 2: Update create_token to accept app_id**

```rust
pub fn create_token(
    user_id: &str,
    email: &str,
    role: &str,
    app_id: &str,
    config: &Config,
) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        app: app_id.to_string(),
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
}
```

- [ ] **Step 3: Update callers of create_token**

In `dashboard/src/routes/auth.rs:116`, update the login handler:

```rust
// Change from:
let token = create_token(&user.id.to_string(), &user.email, &user.role, &config)
// To:
let token = create_token(&user.id.to_string(), &user.email, &user.role, "", &config)
```

(The empty string is a placeholder — the actual auth app flow will set the app_id based on user group matching.)

- [ ] **Step 4: Run dashboard tests**

Run: `cargo test` from `dashboard/`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/auth.rs dashboard/src/routes/auth.rs
git commit -m "feat(dashboard): add app claim to JWT token"
```

---

## Task 8: Dashboard Frontend — Apps Management UI

**Covers:** UI for creating/editing apps with domain selection and policies

**Files:**
- Modify: `dashboard/frontend/src/routes/Dashboard.svelte`

**Interfaces:**
- Consumes: org config with `apps` field
- Produces: API calls with `apps` data

- [ ] **Step 1: Add apps state variables**

Add after the existing domain variables:

```javascript
// --- Apps ---
let createApps = [makeAppEntry()];
let editApps = [makeAppEntry()];

function makeAppEntry() {
  return {
    id: '',
    domains: [],
    policies: [],
  };
}
```

- [ ] **Step 2: Add apps step to create wizard**

Update the steps array to include "Apps":

```javascript
// In openCreateWizard():
createApps = [makeAppEntry()];

// Update steps display:
{#each ['Basic Info', 'Domains', 'Apps', 'User Groups', 'Auth'] as step, i}
```

Add a new step 3 for Apps (shift Auth to step 5):

```svelte
{:else if createStep === 3}
  <div class="step-content">
    <p class="muted">Configure apps and their policies.</p>
    {#each createApps as _, i}
      <div class="domain-config-card">
        <div class="domain-config-header">
          <label class="domain-label">App ID
            <input bind:value={createApps[i].id} placeholder="web-app" />
          </label>
          {#if createApps.length > 1}
            <button class="btn-delete-sm" on:click={() => removeCreateApp(i)}>Remove</button>
          {/if}
        </div>
        <div class="domain-config-body">
          <div class="config-group">
            <h4>Domains</h4>
            <p class="muted">Select domains for this app:</p>
            {#each createDomains as _, di}
              {#if createDomains[di].name}
                <label class="check-label">
                  <input type="checkbox" checked={createApps[i].domains.includes(createDomains[di].name)}
                    on:change={() => toggleAppDomain(createApps[i], createDomains[di].name)} />
                  {createDomains[di].name}
                </label>
              {/if}
            {/each}
          </div>
          <div class="config-group">
            <h4>Policies</h4>
            {#each createApps[i].policies as pol, pi}
              <div class="policy-card">
                <div class="policy-header">
                  <span class="policy-name">{pol.name}</span>
                  <span class="badge" class:badge-allow={pol.effect === 'Allow'} class:badge-deny={pol.effect === 'Deny'}>{pol.effect}</span>
                  <button class="btn-delete-sm" on:click={() => removeCreateAppPolicy(i, pi)}>Remove</button>
                </div>
                {#each pol.rules as rule}
                  <div class="policy-rule">
                    <code>{rule.resource_type}: {rule.resource_value}</code>
                    <span>{rule.methods.join(', ')}</span>
                  </div>
                {/each}
              </div>
            {/each}
            <button class="btn-add-sm" on:click={() => { appPolicyTarget = i; showWizardPolicyForm = true; }}>+ Add Policy</button>
          </div>
        </div>
      </div>
    {/each}
    <button class="btn-add-sm" on:click={addCreateApp}>+ Add App</button>
  </div>
```

- [ ] **Step 3: Add helper functions for apps**

```javascript
function addCreateApp() {
  createApps = [...createApps, makeAppEntry()];
}

function removeCreateApp(i) {
  createApps = createApps.filter((_, idx) => idx !== i);
}

function toggleAppDomain(app, domain) {
  if (app.domains.includes(domain)) {
    app.domains = app.domains.filter(d => d !== domain);
  } else {
    app.domains = [...app.domains, domain];
  }
}

function removeCreateAppPolicy(appIdx, polIdx) {
  createApps[appIdx].policies = createApps[appIdx].policies.filter((_, i) => i !== polIdx);
  createApps = createApps;
}
```

- [ ] **Step 4: Update submitCreateOrg to include apps**

```javascript
const appsObj = {};
for (const a of createApps) {
  if (!a.id.trim()) continue;
  appsObj[a.id.trim()] = {
    domains: a.domains,
    policies: a.policies,
  };
}

await api.orgs.create({
  // ... existing fields ...
  apps: appsObj,
  // ... auth fields ...
});
```

- [ ] **Step 5: Add similar changes for edit wizard**

Apply the same pattern for editApps, editApps step in edit wizard, and submitEditOrg.

- [ ] **Step 6: Test in browser**

Run the dashboard frontend and verify:
- Create wizard shows Apps step
- Can add/remove apps
- Can select domains for each app
- Can add policies to apps
- Config is submitted correctly

- [ ] **Step 7: Commit**

```bash
git add dashboard/frontend/src/routes/Dashboard.svelte
git commit -m "feat(dashboard-ui): add apps management in create/edit wizards"
```

---

## Task 9: Dashboard Frontend — User Groups UI

**Covers:** UI for creating/editing user groups with email OTP configuration

**Files:**
- Modify: `dashboard/frontend/src/routes/Dashboard.svelte`

**Interfaces:**
- Consumes: org config with `user_groups` and `app_user_groups` fields
- Produces: API calls with `user_groups` and `app_user_groups` data

- [ ] **Step 1: Add user_groups state variables**

```javascript
// --- User Groups ---
let createUserGroups = [makeUserGroupEntry()];
let editUserGroups = [makeUserGroupEntry()];

function makeUserGroupEntry() {
  return {
    id: '',
    emails: [],
    emailPatterns: [],
  };
}
```

- [ ] **Step 2: Add user_groups step to create wizard**

Add step 4 for User Groups:

```svelte
{:else if createStep === 4}
  <div class="step-content">
    <p class="muted">Configure user groups for email OTP authentication.</p>
    {#each createUserGroups as _, i}
      <div class="domain-config-card">
        <div class="domain-config-header">
          <label class="domain-label">Group ID
            <input bind:value={createUserGroups[i].id} placeholder="admins" />
          </label>
          {#if createUserGroups.length > 1}
            <button class="btn-delete-sm" on:click={() => removeCreateUserGroup(i)}>Remove</button>
          {/if}
        </div>
        <div class="domain-config-body">
          <div class="config-group">
            <h4>Exact Emails</h4>
            {#each createUserGroups[i].emails as _, ei}
              <div class="condition-row">
                <input bind:value={createUserGroups[i].emails[ei]} placeholder="user@example.com" />
                <button class="btn-delete-sm" on:click={() => removeCreateEmail(i, ei)}>x</button>
              </div>
            {/each}
            <button class="btn-add-sm" on:click={() => addCreateEmail(i)}>+ Add Email</button>
          </div>
          <div class="config-group">
            <h4>Email Patterns</h4>
            {#each createUserGroups[i].emailPatterns as _, pi}
              <div class="condition-row">
                <input bind:value={createUserGroups[i].emailPatterns[pi]} placeholder="*@example.com" />
                <button class="btn-delete-sm" on:click={() => removeCreateEmailPattern(i, pi)}>x</button>
              </div>
            {/each}
            <button class="btn-add-sm" on:click={() => addCreateEmailPattern(i)}>+ Add Pattern</button>
          </div>
          <div class="config-group">
            <h4>Assign to Apps</h4>
            {#each createApps as _, ai}
              {#if createApps[ai].id}
                <label class="check-label">
                  <input type="checkbox" checked={isGroupAssignedToApp(createUserGroups[i].id, createApps[ai].id)}
                    on:change={() => toggleGroupAppAssignment(createUserGroups[i].id, createApps[ai].id)} />
                  {createApps[ai].id}
                </label>
              {/if}
            {/each}
          </div>
        </div>
      </div>
    {/each}
    <button class="btn-add-sm" on:click={addCreateUserGroup}>+ Add User Group</button>
  </div>
```

- [ ] **Step 3: Add helper functions for user groups**

```javascript
let createAppUserGroups = {};

function addCreateUserGroup() {
  createUserGroups = [...createUserGroups, makeUserGroupEntry()];
}

function removeCreateUserGroup(i) {
  const groupId = createUserGroups[i].id;
  delete createAppUserGroups[groupId];
  createUserGroups = createUserGroups.filter((_, idx) => idx !== i);
}

function addCreateEmail(groupIdx) {
  createUserGroups[groupIdx].emails = [...createUserGroups[groupIdx].emails, ''];
}

function removeCreateEmail(groupIdx, emailIdx) {
  createUserGroups[groupIdx].emails = createUserGroups[groupIdx].emails.filter((_, i) => i !== emailIdx);
  createUserGroups = createUserGroups;
}

function addCreateEmailPattern(groupIdx) {
  createUserGroups[groupIdx].emailPatterns = [...createUserGroups[groupIdx].emailPatterns, ''];
}

function removeCreateEmailPattern(groupIdx, patternIdx) {
  createUserGroups[groupIdx].emailPatterns = createUserGroups[groupIdx].emailPatterns.filter((_, i) => i !== patternIdx);
  createUserGroups = createUserGroups;
}

function isGroupAssignedToApp(groupId, appId) {
  return createAppUserGroups[appId]?.includes(groupId) || false;
}

function toggleGroupAppAssignment(groupId, appId) {
  if (!createAppUserGroups[appId]) {
    createAppUserGroups[appId] = [];
  }
  if (createAppUserGroups[appId].includes(groupId)) {
    createAppUserGroups[appId] = createAppUserGroups[appId].filter(g => g !== groupId);
  } else {
    createAppUserGroups[appId].push(groupId);
  }
}
```

- [ ] **Step 4: Update submitCreateOrg to include user_groups and app_user_groups**

```javascript
const userGroupsObj = {};
for (const g of createUserGroups) {
  if (!g.id.trim()) continue;
  userGroupsObj[g.id.trim()] = {
    emails: g.emails.filter(e => e.trim()),
    email_patterns: g.emailPatterns.filter(p => p.trim()),
  };
}

await api.orgs.create({
  // ... existing fields ...
  user_groups: userGroupsObj,
  app_user_groups: createAppUserGroups,
  // ... auth fields ...
});
```

- [ ] **Step 5: Add similar changes for edit wizard**

Apply the same pattern for editUserGroups, editAppUserGroups, and submitEditOrg.

- [ ] **Step 6: Test in browser**

Run the dashboard frontend and verify:
- Create wizard shows User Groups step
- Can add/remove user groups
- Can add emails and email patterns
- Can assign user groups to apps
- Config is submitted correctly

- [ ] **Step 7: Commit**

```bash
git add dashboard/frontend/src/routes/Dashboard.svelte
git commit -m "feat(dashboard-ui): add user groups and app assignment management"
```

---

## Task 10: Dashboard Frontend — Auth Config UI

**Covers:** UI for new auth fields (jwt_private_key, req_param_name, token_param_name)

**Files:**
- Modify: `dashboard/frontend/src/routes/Dashboard.svelte`

**Interfaces:**
- Consumes: org config with new auth fields
- Produces: API calls with new auth fields

- [ ] **Step 1: Add auth state variables**

```javascript
let reqParamName = 'req';
let tokenParamName = 'token';
let editReqParamName = '';
let editTokenParamName = '';
```

- [ ] **Step 2: Update create wizard auth step**

Update the auth step (now step 5) to include new fields:

```svelte
{:else if createStep === 5}
  <div class="step-content">
    <label>JWT Issuer <input bind:value={jwtIssuer} placeholder="https://auth.example.com" /></label>
    <label>JWT Audience <input bind:value={jwtAudience} placeholder="quicguard-proxy" /></label>
    <label class="check-label">
      <input type="checkbox" bind:checked={autoGenerateJwt} /> Auto-generate JWT key pair
    </label>
    {#if !autoGenerateJwt}
      <label>JWT Public Key (PEM) <textarea bind:value={jwtPublicKey} rows="4"></textarea></label>
    {/if}
    <label>Cookie Name <input bind:value={cookieName} placeholder="session_token" /></label>
    <label>Redirect URL <input bind:value={redirectUrl} placeholder="https://auth.example.com/login" /></label>
    <label>IDP URL <input bind:value={idpUrl} placeholder="https://auth.example.com/idp" /></label>
    <label>Request Parameter Name <input bind:value={reqParamName} placeholder="req" /></label>
    <label>Token Parameter Name <input bind:value={tokenParamName} placeholder="token" /></label>
  </div>
```

- [ ] **Step 3: Update submitCreateOrg to include new auth fields**

```javascript
await api.orgs.create({
  // ... existing fields ...
  req_param_name: reqParamName || null,
  token_param_name: tokenParamName || null,
});
```

- [ ] **Step 4: Update edit wizard to load and save new auth fields**

In `enterEditMode()`:
```javascript
editReqParamName = orgDetail.config.auth?.req_param_name || 'req';
editTokenParamName = orgDetail.config.auth?.token_param_name || 'token';
```

In `submitEditOrg()`:
```javascript
req_param_name: editReqParamName || undefined,
token_param_name: editTokenParamName || undefined,
```

- [ ] **Step 5: Update detail view to show new auth fields**

```svelte
<div class="detail-section">
  <h3>Auth</h3>
  <p>Issuer: <code>{orgDetail.config.auth?.jwt_issuer || '-'}</code></p>
  <p>Audience: <code>{orgDetail.config.auth?.jwt_audience || '-'}</code></p>
  <p>Cookie Name: <code>{orgDetail.config.auth?.cookie_name || '-'}</code></p>
  <p>Redirect URL: <code>{orgDetail.config.auth?.redirect_url || '-'}</code></p>
  <p>IDP URL: <code>{orgDetail.config.auth?.idp_url || '-'}</code></p>
  <p>Request Param: <code>{orgDetail.config.auth?.req_param_name || 'req'}</code></p>
  <p>Token Param: <code>{orgDetail.config.auth?.token_param_name || 'token'}</code></p>
</div>
```

- [ ] **Step 6: Test in browser**

Run the dashboard frontend and verify:
- Auth step shows new fields
- Values are saved and loaded correctly
- Detail view shows new auth fields

- [ ] **Step 7: Commit**

```bash
git add dashboard/frontend/src/routes/Dashboard.svelte
git commit -m "feat(dashboard-ui): add auth config fields for param names"
```

---

## Task 11: Integration Testing

**Covers:** End-to-end verification of all changes

**Files:**
- Test: manual testing across all components

**Interfaces:**
- Consumes: all previous tasks
- Produces: verified working system

- [ ] **Step 1: Run all unit tests**

```bash
# Konfig
cargo test -p konfig

# QuicGuard
cargo test -p quicguard

# Dashboard
cd dashboard && cargo test
```

Expected: All tests pass

- [ ] **Step 2: Build all components**

```bash
# Konfig
cargo build -p konfig

# QuicGuard
cargo build -p quicguard

# Dashboard backend
cd dashboard && cargo build

# Dashboard frontend
cd dashboard/frontend && npm run build
```

Expected: All builds succeed

- [ ] **Step 3: Manual integration test**

1. Start Redis and PostgreSQL
2. Run dashboard backend
3. Create an org via dashboard UI with:
   - 2 domains
   - 1 app with both domains
   - 1 user group with test emails
   - App assigned to user group
4. Verify config in Redis matches expected shape
5. Start quicguard
6. Test auth flow:
   - Request to domain without JWT → redirect to IDP with `req` param
   - After auth → JWT with `app` claim → redirect with `token` param
   - Subsequent request → JWT validated → app-based policy check

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: complete org config restructure with app-based policies"
```

---

## Summary

| Task | Component | Description |
|------|-----------|-------------|
| 1 | konfig | Config structs (AppConfig, UserGroup, AuthConfig updates) |
| 2 | konfig | TokenClaims with `app` field |
| 3 | konfig | App-based policy evaluation |
| 4 | quicguard | Configurable auth parameters |
| 5 | dashboard | Input models |
| 6 | dashboard | Config builder |
| 7 | dashboard | JWT with `app` claim |
| 8 | dashboard-ui | Apps management UI |
| 9 | dashboard-ui | User groups UI |
| 10 | dashboard-ui | Auth config UI |
| 11 | all | Integration testing |
