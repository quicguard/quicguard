use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    config::Config,
    db::DbPool,
    middleware::AuthUser,
    models::{Organization, User},
};

pub fn admin_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/users", axum::routing::get(list_users))
        .route("/users/{id}/approve", axum::routing::put(approve_user))
        .route("/users/{id}", axum::routing::delete(delete_user))
        .route("/organizations", axum::routing::get(list_all_orgs))
}

async fn list_users(
    State((pool, _config)): State<(DbPool, Config)>,
    _auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "users": users.into_iter().map(|u| json!({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "approved": u.approved,
            "created_at": u.created_at
        })).collect::<Vec<_>>()
    })))
}

async fn approve_user(
    State((pool, _config)): State<(DbPool, Config)>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let result = sqlx::query("UPDATE users SET approved = true, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(json!({"message": "User approved"})))
}

async fn delete_user(
    State((pool, _config)): State<(DbPool, Config)>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn list_all_orgs(
    State((pool, _config)): State<(DbPool, Config)>,
) -> Result<Json<Value>, StatusCode> {
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations ORDER BY created_at DESC",
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "organizations": orgs.into_iter().map(|o| json!({
            "id": o.id,
            "owner_id": o.owner_id,
            "name": o.name,
            "config": o.config,
            "created_at": o.created_at
        })).collect::<Vec<_>>()
    })))
}
