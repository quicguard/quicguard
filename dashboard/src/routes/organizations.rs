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
    let max_retries = input.upstream_max_retries.unwrap_or(3);
    let cookie_name = input.cookie_name.clone().unwrap_or_else(|| "session_token".to_string());
    let redirect_url = input.redirect_url.clone().unwrap_or_default();
    let idp_url = input.idp_url.clone().unwrap_or_default();

    // JWT keys
    let (jwt_public_key, _jwt_private_key) = if input.auto_generate_jwt_keys {
        let keys = generate::generate_jwt_keys().map_err(|e| e.to_string())?;
        (keys.public_key, keys.private_key)
    } else {
        let pk = input.jwt_public_key.clone().unwrap_or_default();
        (pk, String::new())
    };

    // TLS configs
    let mut tls = HashMap::new();
    for tls_input in &input.tls_configs {
        let (cert, key) = if tls_input.auto_generate {
            let cert = generate::generate_tls_cert(&tls_input.domain).map_err(|e| e.to_string())?;
            (cert.cert_pem, cert.key_pem)
        } else {
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

    Ok(config)
}

fn build_policy_value(input: &AddPolicy) -> Value {
    let effect = input.effect.as_deref().unwrap_or("Allow");
    let rules: Vec<Value> = input
        .rules
        .iter()
        .map(|r| {
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
            json!({
                "resource": resource,
                "methods": methods,
                "conditions": conditions
            })
        })
        .collect();

    json!({
        "id": input.policy_id,
        "name": input.name,
        "effect": effect,
        "rules": rules
    })
}

async fn list_orgs(
    State((pool, _config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE owner_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth_user.id)
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

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
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match org {
        Some(o) => Ok(Json(json!({
            "id": o.id,
            "name": o.name,
            "config": o.config,
            "created_at": o.created_at
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn create_org(
    State((pool, config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<CreateOrganizationStructured>,
) -> Result<Json<Value>, StatusCode> {
    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)",
    )
    .bind(&input.id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing {
        return Err(StatusCode::CONFLICT);
    }

    let org_config =
        build_org_config(&input).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, owner_id, name, config) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(&input.id)
    .bind(auth_user.id)
    .bind(&input.name)
    .bind(&org_config)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &org).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

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
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut org = match org {
        Some(o) => o,
        None => return Err(StatusCode::NOT_FOUND),
    };

    if let Some(name) = input.name {
        org.name = name;
    }
    if let Some(config_val) = input.config {
        org.config = config_val;
    }

    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET name = $1, config = $2, updated_at = NOW() WHERE id = $3 RETURNING *",
    )
    .bind(&org.name)
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

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
    let result = sqlx::query("DELETE FROM organizations WHERE id = $1 AND owner_id = $2")
        .bind(&org_id)
        .bind(auth_user.id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Err(e) = redis_sync::remove_org_from_redis(&config, &org_id).await {
        tracing::error!("Failed to remove org from Redis: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn add_policy(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<AddPolicy>,
) -> Result<Json<Value>, StatusCode> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut org = match org {
        Some(o) => o,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let policy = build_policy_value(&input);
    let config_obj = org.config.as_object_mut().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let policies = config_obj
        .entry("policies")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    policies.push(policy);

    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

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
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut org = match org {
        Some(o) => o,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let config_obj = org.config.as_object_mut().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(policies) = config_obj.get_mut("policies").and_then(|v| v.as_array_mut()) {
        policies.retain(|p| {
            p.get("id").and_then(|v| v.as_str()) != Some(&policy_id)
        });
    }

    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

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
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut org = match org {
        Some(o) => o,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let policy_input = AddPolicy {
        policy_id: input.policy_id,
        name: input.name,
        effect: input.effect,
        rules: input.rules,
    };
    let policy = build_policy_value(&policy_input);

    let config_obj = org.config.as_object_mut().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let domain_policies = config_obj
        .entry("domain_policies")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let domain_arr = domain_policies
        .entry(input.domain.clone())
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    domain_arr.push(policy);

    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

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
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut org = match org {
        Some(o) => o,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let config_obj = org.config.as_object_mut().ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(domain_policies) = config_obj
        .get_mut("domain_policies")
        .and_then(|v| v.as_object_mut())
    {
        if let Some(policies) = domain_policies.get_mut(&domain).and_then(|v| v.as_array_mut()) {
            policies.retain(|p| {
                p.get("id").and_then(|v| v.as_str()) != Some(&policy_id)
            });
        }
    }

    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET config = $1, updated_at = NOW() WHERE id = $2 RETURNING *",
    )
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

    Ok(Json(json!({
        "id": updated.id,
        "config": updated.config
    })))
}
