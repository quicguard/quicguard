use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};

use crate::{
    config::Config,
    db::DbPool,
    middleware::AuthUser,
    models::{CreateOrganization, Organization, UpdateOrganization},
    redis_sync,
};

pub fn org_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/", axum::routing::get(list_orgs))
        .route("/", axum::routing::post(create_org))
        .route("/{id}", axum::routing::put(update_org))
        .route("/{id}", axum::routing::delete(delete_org))
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

async fn create_org(
    State((pool, config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<CreateOrganization>,
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

    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, owner_id, name, config) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(&input.id)
    .bind(auth_user.id)
    .bind(&input.name)
    .bind(&input.config)
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
    Json(input): Json<UpdateOrganization>,
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
