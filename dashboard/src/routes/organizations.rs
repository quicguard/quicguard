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
    models::{
        AddDomainPolicy, AddPolicy, CreateOrganizationStructured, Organization,
        UpdateOrganizationRaw,
    },
    redis_sync,
};

pub fn org_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/", axum::routing::get(list_orgs))
        .route("/", axum::routing::post(create_org))
        .route("/{id}", axum::routing::get(get_org))
        .route("/{id}", axum::routing::put(update_org))
        .route("/{id}", axum::routing::delete(delete_org))
        .route("/{id}/policies", axum::routing::post(add_policy))
        .route("/{id}/policies/{policy_id}", axum::routing::delete(remove_policy))
        .route("/{id}/domain-policies", axum::routing::post(add_domain_policy))
        .route("/{id}/domain-policies/{domain}/{policy_id}", axum::routing::delete(remove_domain_policy))
}

// --- Build org config from structured input ---

fn build_org_config(input: &CreateOrganizationStructured) -> Result<Value, String> {
    tracing::debug!(org_id = %input.id, "Building org config from structured input");

    let max_retries = input.upstream_max_retries.unwrap_or(3);
    let cookie_name = input.cookie_name.clone().unwrap_or_else(|| "session_token".to_string());
    let redirect_url = input.redirect_url.clone().unwrap_or_default();
    let idp_url = input.idp_url.clone().unwrap_or_default();

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

    // TLS configs
    tracing::debug!(org_id = %input.id, tls_count = input.tls_configs.len(), "Processing TLS configs");
    let mut tls = HashMap::new();
    for tls_input in &input.tls_configs {
        let (cert, key) = if tls_input.auto_generate {
            tracing::debug!(org_id = %input.id, domain = %tls_input.domain,
                "Auto-generating TLS certificate");
            let cert = generate::generate_tls_cert(&tls_input.domain).map_err(|e| {
                tracing::error!(org_id = %input.id, domain = %tls_input.domain, error = %e,
                    "Failed to generate TLS certificate");
                e.to_string()
            })?;
            tracing::debug!(org_id = %input.id, domain = %tls_input.domain,
                "TLS certificate generated successfully");
            (cert.cert_pem, cert.key_pem)
        } else {
            tracing::debug!(org_id = %input.id, domain = %tls_input.domain,
                "Using provided TLS certificate and key");
            let c = tls_input.cert_pem.clone().unwrap_or_default();
            let k = tls_input.key_pem.clone().unwrap_or_default();
            (c, k)
        };
        tls.insert(
            tls_input.domain.clone(),
            json!({
                "cert_pem": cert,
                "key_pem": key
            }),
        );
    }

    tracing::debug!(org_id = %input.id, domains = ?input.domains, upstream = %input.upstream_base_url,
        jwt_issuer = %input.jwt_issuer, "Building final org config JSON");

    let config = json!({
        "id": input.id,
        "name": input.name,
        "domains": input.domains,
        "policies": [],
        "domain_policies": {},
        "upstream": {
            "base_url": input.upstream_base_url,
            "timeout_ms": input.upstream_timeout_ms,
            "max_retries": max_retries
        },
        "auth": {
            "jwt_issuer": input.jwt_issuer,
            "jwt_audience": input.jwt_audience,
            "jwt_public_key": jwt_public_key,
            "cookie_name": cookie_name,
            "redirect_url": redirect_url,
            "idp_url": idp_url
        },
        "tls": tls
    });

    tracing::debug!(org_id = %input.id, config_size = config.to_string().len(),
        "Org config built successfully");
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
    Json(input): Json<CreateOrganizationStructured>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %input.id, name = %input.name, user_id = %auth_user.id,
        domains = ?input.domains, "POST /api/organizations");

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
    Json(input): Json<UpdateOrganizationRaw>,
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

    if let Some(name) = input.name {
        tracing::debug!(org_id = %org_id, new_name = %name, "Updating org name");
        org.name = name;
    }
    if let Some(config_val) = input.config {
        tracing::debug!(org_id = %org_id, "Updating org config (raw JSON)");
        org.config = config_val;
    }

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

async fn add_policy(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<AddPolicy>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, policy_id = %input.policy_id, policy_name = %input.name,
        user_id = %auth_user.id, "POST /api/organizations/{}/policies", org_id);

    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error fetching org for policy add");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut org = match org {
        Some(o) => o,
        None => {
            tracing::debug!(org_id = %org_id, "Add policy failed: org not found");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let policy = build_policy_value(&input);
    let config_obj = org.config.as_object_mut().ok_or_else(|| {
        tracing::error!(org_id = %org_id, "Config is not a JSON object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let policies = config_obj
        .entry("policies")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            tracing::error!(org_id = %org_id, "Policies field is not an array");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::debug!(org_id = %org_id, policy_id = %input.policy_id, current_count = policies.len(),
        "Appending policy to org config");
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
        tracing::error!(org_id = %org_id, error = %e, "DB error saving policy");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(org_id = %org_id, "Syncing org to Redis after policy add");
    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!(org_id = %org_id, error = %e, "Failed to sync org to Redis");
    } else {
        tracing::debug!(org_id = %org_id, "Org synced to Redis after policy add");
    }

    tracing::debug!(org_id = %org_id, policy_id = %input.policy_id, "Policy added successfully");
    Ok(Json(json!({
        "id": updated.id,
        "config": updated.config
    })))
}

async fn remove_policy(
    State((pool, config)): State<(DbPool, Config)>,
    Path((org_id, policy_id)): Path<(String, String)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, policy_id = %policy_id, user_id = %auth_user.id,
        "DELETE /api/organizations/{}/policies/{}", org_id, policy_id);

    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error fetching org for policy remove");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut org = match org {
        Some(o) => o,
        None => {
            tracing::debug!(org_id = %org_id, "Remove policy failed: org not found");
            return Err(StatusCode::NOT_FOUND);
        }
    };

    let config_obj = org.config.as_object_mut().ok_or_else(|| {
        tracing::error!(org_id = %org_id, "Config is not a JSON object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    if let Some(policies) = config_obj.get_mut("policies").and_then(|v| v.as_array_mut()) {
        let before = policies.len();
        policies.retain(|p| {
            p.get("id").and_then(|v| v.as_str()) != Some(&policy_id)
        });
        tracing::debug!(org_id = %org_id, policy_id = %policy_id,
            before = before, after = policies.len(),
            "Policy removed from config");
    } else {
        tracing::debug!(org_id = %org_id, "No policies array found in config");
    }

    tracing::debug!(org_id = %org_id, "Saving updated config to DB");
    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(org_id = %org_id, error = %e, "DB error saving policy removal");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(org_id = %org_id, "Syncing org to Redis after policy remove");
    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!(org_id = %org_id, error = %e, "Failed to sync org to Redis");
    } else {
        tracing::debug!(org_id = %org_id, "Org synced to Redis after policy remove");
    }

    tracing::debug!(org_id = %org_id, policy_id = %policy_id, "Policy removed successfully");
    Ok(Json(json!({
        "id": updated.id,
        "config": updated.config
    })))
}

async fn add_domain_policy(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<AddDomainPolicy>,
) -> Result<Json<Value>, StatusCode> {
    tracing::debug!(org_id = %org_id, domain = %input.domain, policy_id = %input.policy_id,
        user_id = %auth_user.id, "POST /api/organizations/{}/domain-policies", org_id);

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

    let domain_name = input.domain.clone();
    let policy_id = input.policy_id.clone();
    let policy_input = AddPolicy {
        policy_id: input.policy_id,
        name: input.name,
        effect: input.effect,
        rules: input.rules,
    };
    let policy = build_policy_value(&policy_input);

    let config_obj = org.config.as_object_mut().ok_or_else(|| {
        tracing::error!(org_id = %org_id, "Config is not a JSON object");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let domain_policies = config_obj
        .entry("domain_policies")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            tracing::error!(org_id = %org_id, "domain_policies is not a JSON object");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let domain_arr = domain_policies
        .entry(domain_name.clone())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            tracing::error!(org_id = %org_id, domain = %domain_name,
                "Domain policies entry is not an array");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::debug!(org_id = %org_id, domain = %domain_name, policy_id = %policy_id,
        current_count = domain_arr.len(),
        "Appending domain policy to config");
    domain_arr.push(policy);

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

    tracing::debug!(org_id = %org_id, domain = %domain_name, policy_id = %policy_id,
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
        "DELETE /api/organizations/{}/domain-policies/{}/{}", org_id, domain, policy_id);

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
    if let Some(domain_policies) = config_obj
        .get_mut("domain_policies")
        .and_then(|v| v.as_object_mut())
    {
        if let Some(policies) = domain_policies.get_mut(&domain).and_then(|v| v.as_array_mut()) {
            let before = policies.len();
            policies.retain(|p| {
                p.get("id").and_then(|v| v.as_str()) != Some(&policy_id)
            });
            tracing::debug!(org_id = %org_id, domain = %domain, policy_id = %policy_id,
                before = before, after = policies.len(),
                "Domain policy removed from config");
        } else {
            tracing::debug!(org_id = %org_id, domain = %domain,
                "No policies found for domain");
        }
    } else {
        tracing::debug!(org_id = %org_id, "No domain_policies found in config");
    }

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
