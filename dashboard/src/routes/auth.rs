use axum::{
    extract::State,
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};

use crate::{
    auth::{create_token, hash_password, verify_password},
    config::Config,
    db::DbPool,
    middleware::AuthUser,
    models::{CreateUser, LoginUser, User},
};

pub fn auth_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/signup", axum::routing::post(signup))
        .route("/login", axum::routing::post(login))
        .route("/me", axum::routing::get(me))
}

async fn signup(
    State((pool, _config)): State<(DbPool, Config)>,
    Json(input): Json<CreateUser>,
) -> Result<Json<Value>, StatusCode> {
    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
    )
    .bind(&input.email)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing {
        return Err(StatusCode::CONFLICT);
    }

    let password_hash =
        hash_password(&input.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
    )
    .bind(&input.email)
    .bind(&password_hash)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "id": user.id,
        "email": user.email,
        "approved": user.approved,
        "message": "Account created. Waiting for admin approval."
    })))
}

async fn login(
    State((pool, config)): State<(DbPool, Config)>,
    Json(input): Json<LoginUser>,
) -> Result<Json<Value>, StatusCode> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = $1",
    )
    .bind(&input.email)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = match user {
        Some(u) => u,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    if !verify_password(&input.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !user.approved {
        return Err(StatusCode::FORBIDDEN);
    }

    let token = create_token(&user.id.to_string(), &user.email, &user.role, &config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role
        }
    })))
}

async fn me(
    State((pool, _config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1",
    )
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match user {
        Some(u) => Ok(Json(json!({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "approved": u.approved
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}
