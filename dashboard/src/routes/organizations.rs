use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::{
    config::Config,
    db::DbPool,
    generate,
    middleware::AuthUser,
    models::{AddPolicy, CreateOrganization, Organization, UpdateOrganization},
    redis_sync,
};

pub fn org_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/", axum::routing::get(list_orgs))
        .route("/", axum::routing::post(create_org))
        .route("/{id}", axum::routing::get(get_org))
        .route("/{id}", axum::routing::put(update_org))
        .route("/{id}", axum::routing::delete(delete_org))
        .route(
            "/{id}/domains/{domain}/policies",
            axum::routing::post(add_domain_policy),
        )
        .route(
            "/{id}/domains/{domain}/policies/{policy_id}",
            axum::routing::delete(remove_domain_policy),
        )
}

// --- Build org config from structured input ---

fn build_org_config(input: &CreateOrganization) -> Result<Value, String> {
    tracing::debug!(org_id = %input.id, "Building org config from structured input");

    // JWT keys
    let (jwt_public_key, _jwt_private_key) = if input.auto_generate_jwt_keys {
        tracing::debug!(org_id = %input.id, "Auto-generating JWT key pair");
        let keys = generate::generate_jwt_keys().map_err(|e| {
            tracing::error!(org_id = %input.id, error = %e, "Failed to generate JWT keys");
            e.to_string()
        })?;
        tracing::debug!(org_id = %input.id, "JWT key pair generated successfully");
        (keys.public_key, keys.private_key)
    } else {
        tracing::debug!(org_id = %input.id, "Using provided JWT public key");
        let pk = input.jwt_public_key.clone().unwrap_or_default();
        (pk, String::new())
    };

    let cookie_name = input.cookie_name.clone().unwrap_or_else(|| "session_token".to_string());
    let redirect_url = input.redirect_url.clone().unwrap_or_default();
    let idp_url = input.idp_url.clone().unwrap_or_default();

    // Build per-domain configs
    let mut domains = HashMap::new();
    for (domain_name, domain_input) in &input.domains {
        tracing::debug!(org_id = %input.id, domain = %domain_name, "Processing domain config");

        // TLS
        let (cert, key) = if domain_input.auto_generate_tls {
            tracing::debug!(org_id = %input.id, domain = %domain_name,
                "Auto-generating TLS certificate");
            let cert = generate::generate_tls_cert(domain_name).map_err(|e| {
                tracing::error!(org_id = %input.id, domain = %domain_name, error = %e,
                    "Failed to generate TLS certificate");
                e.to_string()
            })?;
            tracing::debug!(org_id = %input.id, domain = %domain_name,
                "TLS certificate generated successfully");
            (cert.cert_pem, cert.key_pem)
        } else {
            tracing::debug!(org_id = %input.id, domain = %domain_name,
                "Using provided TLS certificate and key");
            (
                domain_input.cert_pem.clone().unwrap_or_default(),
                domain_input.key_pem.clone().unwrap_or_default(),
            )
        };

        // Policies
        let policies: Vec<Value> = domain_input
            .policies
            .iter()
            .map(|p| build_policy_value(p))
            .collect();

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
                },
                "policies": policies
            }),
        );
    }

    tracing::debug!(org_id = %input.id, domain_count = domains.len(),
        jwt_issuer = %input.jwt_issuer, "Building final org config JSON");

    let config = json!({
        "id": input.id,
        "name": input.name,
        "auth": {
            "jwt_issuer": input.jwt_issuer,
            "jwt_audience": input.jwt_audience,
            "jwt_public_key": jwt_public_key,
            "cookie_name": cookie_name,
            "redirect_url": redirect_url,
            "idp_url": idp_url
        },
        "domains": domains
    });

    tracing::debug!(org_id = %input.id, config_size = config.to_string().len(),
        "Org config built successfully");
    Ok(config)
}

fn build_update_config(
    input: &UpdateOrganization,
    existing_config: &Value,
) -> Result<Value, String> {
    let mut config = existing_config.clone();
    let config_obj = config.as_object_mut().ok_or("Config is not a JSON object")?;

    // Update domains (merge per-domain)
    if let Some(domains) = &input.domains {
        let existing_domains = config_obj
            .entry("domains".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("domains is not a JSON object")?;

        for (domain_name, domain_input) in domains {
            tracing::debug!(domain = %domain_name, "Merging domain update");

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
                let cert = generate::generate_tls_cert(domain_name).map_err(|e| {
                    tracing::error!(domain = %domain_name, error = %e,
                        "Failed to generate TLS certificate");
                    e.to_string()
                })?;
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

            // Update policies
            if !domain_input.policies.is_empty() {
                let policies: Vec<Value> = domain_input
                    .policies
                    .iter()
                    .map(|p| build_policy_value(p))
                    .collect();
                domain_config["policies"] = json!(policies);
            }
        }
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

        // JWT key handling
        match input.auto_generate_jwt_keys {
            Some(true) => {
                let keys = generate::generate_jwt_keys().map_err(|e| {
                    tracing::error!(error = %e, "Failed to generate JWT keys");
                    e.to_string()
                })?;
                auth["jwt_public_key"] = json!(keys.public_key);
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

pub fn build_policy_value(input: &AddPolicy) -> Value {
    tracing::debug!(policy_id = %input.policy_id, name = %input.name, effect = ?input.effect,
        rules_count = input.rules.len(), "Building policy value");

    let effect = input.effect.as_deref().unwrap_or("Allow");
    let rules: Vec<Value> = input
        .rules
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let resource = match r.resource_type.as_str() {
                "exact" => json!({"Exact": r.resource_value}),
                "prefix" => json!({"Prefix": r.resource_value}),
                "glob" => json!({"Glob": r.resource_value}),
                _ => json!({"Prefix": r.resource_value}),
            };
            let methods: Vec<String> = r.methods.iter().map(|m| m.to_uppercase()).collect();
            let conditions: Vec<Value> = r
                .conditions
                .as_ref()
                .unwrap_or(&vec![])
                .iter()
                .map(|c| {
                    json!({
                        "claim": c.claim,
                        "operator": c.operator,
                        "value": c.value
                    })
                })
                .collect();
            tracing::debug!(rule_idx = i, resource_type = %r.resource_type,
                resource_value = %r.resource_value, methods = ?methods, conditions_count = conditions.len(),
                "Policy rule built");
            json!({
                "resource": resource,
                "methods": methods,
                "conditions": conditions
            })
        })
        .collect();

    let policy = json!({
        "id": input.policy_id,
        "name": input.name,
        "effect": effect,
        "rules": rules
    });

    tracing::debug!(policy_id = %input.policy_id, "Policy value built");
    policy
}

async fn list_orgs(
    State((pool, _config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(user_id = %auth_user.id, "GET /api/organizations");

    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE owner_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth_user.id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %auth_user.id, error = %e, "DB error listing orgs");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(user_id = %auth_user.id, count = orgs.len(), "Organizations fetched");
    Ok(Json(json!({
        "organizations": orgs.into_iter().map(|o| json!({
            "id": o.id,
            "name": o.name,
            "config": o.config,
            "created_at": o.created_at
        })).collect::<Vec<_>>()
    })))
}

async fn get_org(
    State((pool, _config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, user_id = %auth_user.id, "GET /api/organizations/{}", org_id);

    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, user_id = %auth_user.id, error = %e,
            "DB error fetching org");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match org {
        Some(o) => {
            tracing::debug!(org_id = %org_id, "Organization found");
            Ok(Json(json!({
                "id": o.id,
                "name": o.name,
                "config": o.config,
                "created_at": o.created_at
            })))
        }
        None => {
            tracing::debug!(org_id = %org_id, user_id = %auth_user.id, "Organization not found");
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn create_org(
    State((pool, config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<CreateOrganization>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %input.id, name = %input.name, user_id = %auth_user.id,
        domain_count = input.domains.len(), "POST /api/organizations");

    tracing::debug!(org_id = %input.id, "Checking if org ID already exists");
    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)",
    )
    .bind(&input.id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %input.id, error = %e, "DB error checking org existence");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if existing {
        tracing::debug!(org_id = %input.id, "Create rejected: org ID already exists");
        return Err(StatusCode::CONFLICT);
    }

    tracing::debug!(org_id = %input.id, "Building org config");
    let org_config =
        build_org_config(&input).map_err(|e| {
            tracing::error!(org_id = %input.id, error = %e, "Failed to build org config");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::debug!(org_id = %input.id, "Inserting organization into DB");
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, owner_id, name, config) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(&input.id)
    .bind(auth_user.id)
    .bind(&input.name)
    .bind(&org_config)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %input.id, error = %e, "DB error inserting organization");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(org_id = %org.id, "Organization inserted into DB, syncing to Redis");
    if let Err(e) = redis_sync::sync_org_to_redis(&config, &org).await {
        tracing::error!(org_id = %org.id, error = %e, "Failed to sync org to Redis");
    } else {
        tracing::debug!(org_id = %org.id, "Organization synced to Redis successfully");
    }

    tracing::debug!(org_id = %org.id, "Organization created successfully");
    Ok(Json(json!({
        "id": org.id,
        "name": org.name,
        "config": org.config,
        "created_at": org.created_at
    })))
}

async fn update_org(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<UpdateOrganization>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, user_id = %auth_user.id, "PUT /api/organizations/{}", org_id);

    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error fetching org for update");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut org = match org {
        Some(o) => o,
        None => {
            tracing::debug!(org_id = %org_id, "Update failed: org not found");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    if let Some(name) = &input.name {
        tracing::debug!(org_id = %org_id, new_name = %name, "Updating org name");
        org.name = name.clone();
    }

    // Merge partial updates into existing config
    let org_config = build_update_config(&input, &org.config).map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "Failed to build update config");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    org.config = org_config;

    tracing::debug!(org_id = %org_id, "Saving updated org to DB");
    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET name = $1, config = $2, updated_at = NOW() WHERE id = $3 RETURNING *",
    )
    .bind(&org.name)
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error updating organization");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(org_id = %org_id, "Organization updated in DB, syncing to Redis");
    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!(org_id = %org_id, error = %e, "Failed to sync org to Redis");
    } else {
        tracing::debug!(org_id = %org_id, "Organization synced to Redis successfully");
    }

    tracing::debug!(org_id = %org_id, "Organization updated successfully");
    Ok(Json(json!({
        "id": updated.id,
        "name": updated.name,
        "config": updated.config,
        "created_at": updated.created_at
    })))
}

async fn delete_org(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<StatusCode, StatusCode> {
    tracing::debug!(org_id = %org_id, user_id = %auth_user.id, "DELETE /api/organizations/{}", org_id);

    tracing::debug!(org_id = %org_id, "Deleting organization from DB");
    let result = sqlx::query("DELETE FROM organizations WHERE id = $1 AND owner_id = $2")
        .bind(&org_id)
        .bind(auth_user.id)
        .execute(&pool)
        .await
        .map_err(|e| {
            tracing::error!(org_id = %org_id, error = %e, "DB error deleting organization");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if result.rows_affected() == 0 {
        tracing::debug!(org_id = %org_id, "Delete failed: org not found");
        return Err(StatusCode::NOT_FOUND);
    }

    tracing::debug!(org_id = %org_id, "Organization deleted from DB, removing from Redis");
    if let Err(e) = redis_sync::remove_org_from_redis(&config, &org_id).await {
        tracing::error!(org_id = %org_id, error = %e, "Failed to remove org from Redis");
    } else {
        tracing::debug!(org_id = %org_id, "Organization removed from Redis successfully");
    }

    tracing::debug!(org_id = %org_id, "Organization deleted successfully");
    Ok(StatusCode::NO_CONTENT)
}

async fn add_domain_policy(
    State((pool, config)): State<(DbPool, Config)>,
    Path((org_id, domain)): Path<(String, String)>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<AddPolicy>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %input.policy_id,
        user_id = %auth_user.id, "POST /api/organizations/{}/domains/{}/policies", org_id, domain);

    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error fetching org for domain policy add");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut org = match org {
        Some(o) => o,
        None => {
            tracing::debug!(org_id = %org_id, "Add domain policy failed: org not found");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let policy = build_policy_value(&input);
    let config_obj = org.config.as_object_mut().ok_or_else(|| {
        tracing::error!(org_id = %org_id, "Config is not a JSON object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let domain_config = config_obj
        .get_mut("domains")
        .and_then(|d| d.as_object_mut())
        .and_then(|d| d.get_mut(&domain))
        .ok_or_else(|| {
            tracing::debug!(org_id = %org_id, domain = %domain, "Domain not found in config");
            StatusCode::NOT_FOUND
        })?;

    let domain_obj = domain_config.as_object_mut().ok_or_else(|| {
        tracing::error!(org_id = %org_id, domain = %domain,
            "Domain config is not a JSON object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let policies = domain_obj
        .entry("policies".to_string())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            tracing::error!(org_id = %org_id, domain = %domain,
                "Policies field is not an array");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %input.policy_id,
        current_count = policies.len(),
        "Appending policy to domain config");
    policies.push(policy);

    tracing::debug!(org_id = %org_id, "Saving updated config to DB");
    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error saving domain policy");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(org_id = %org_id, "Syncing org to Redis after domain policy add");
    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!(org_id = %org_id, error = %e, "Failed to sync org to Redis");
    } else {
        tracing::debug!(org_id = %org_id, "Org synced to Redis after domain policy add");
    }

    tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %input.policy_id,
        "Domain policy added successfully");
    Ok(Json(json!({
        "id": updated.id,
        "config": updated.config
    })))
}

async fn remove_domain_policy(
    State((pool, config)): State<(DbPool, Config)>,
    Path((org_id, domain, policy_id)): Path<(String, String, String)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %policy_id,
        user_id = %auth_user.id,
        "DELETE /api/organizations/{}/domains/{}/policies/{}", org_id, domain, policy_id);

    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e,
            "DB error fetching org for domain policy remove");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut org = match org {
        Some(o) => o,
        None => {
            tracing::debug!(org_id = %org_id, "Remove domain policy failed: org not found");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let config_obj = org.config.as_object_mut().ok_or_else(|| {
        tracing::error!(org_id = %org_id, "Config is not a JSON object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let domain_policies = config_obj
        .get_mut("domains")
        .and_then(|d| d.as_object_mut())
        .and_then(|d| d.get_mut(&domain))
        .and_then(|d| d.get_mut("policies"))
        .and_then(|p| p.as_array_mut())
        .ok_or_else(|| {
            tracing::debug!(org_id = %org_id, domain = %domain,
                "No policies found for domain");
            StatusCode::NOT_FOUND
        })?;

    let before = domain_policies.len();
    domain_policies.retain(|p| {
        p.get("id").and_then(|v| v.as_str()) != Some(&policy_id)
    });
    tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %policy_id,
        before = before, after = domain_policies.len(),
        "Policy removed from domain config");

    tracing::debug!(org_id = %org_id, "Saving updated config to DB");
    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error saving domain policy removal");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(org_id = %org_id, "Syncing org to Redis after domain policy remove");
    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!(org_id = %org_id, error = %e, "Failed to sync org to Redis");
    } else {
        tracing::debug!(org_id = %org_id, "Org synced to Redis after domain policy remove");
    }

    tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %policy_id,
        "Domain policy removed successfully");
    Ok(Json(json!({
        "id": updated.id,
        "config": updated.config
    })))
}
