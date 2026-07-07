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
    tracing::debug!(email = %input.email, "POST /api/auth/signup");

    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
    )
    .bind(&input.email)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(email = %input.email, error = %e, "DB error checking existing user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    if existing {
        tracing::debug!(email = %input.email, "Signup rejected: email already exists");
        return Err(StatusCode::CONFLICT);
    }

    tracing::debug!(email = %input.email, "Hashing password");
    let password_hash =
        hash_password(&input.password).map_err(|e| {
            tracing::error!(email = %input.email, error = %e, "Failed to hash password");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::debug!(email = %input.email, "Inserting user into DB");
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
    )
    .bind(&input.email)
    .bind(&password_hash)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        tracing::error!(email = %input.email, error = %e, "DB error inserting user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::debug!(user_id = %user.id, email = %user.email, "User created successfully");
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
    tracing::debug!(email = %input.email, "POST /api/auth/login");

    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE email = $1",
    )
    .bind(&input.email)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(email = %input.email, error = %e, "DB error fetching user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user = match user {
        Some(u) => u,
        None => {
            tracing::debug!(email = %input.email, "Login failed: user not found");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    tracing::debug!(user_id = %user.id, email = %input.email, "Verifying password");
    if !verify_password(&input.password, &user.password_hash)
        .map_err(|e| {
            tracing::error!(user_id = %user.id, error = %e, "Password verification error");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        tracing::debug!(user_id = %user.id, "Login failed: invalid password");
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !user.approved {
        tracing::debug!(user_id = %user.id, "Login failed: user not approved");
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::debug!(user_id = %user.id, role = %user.role, "Generating JWT token");
    let token = create_token(&user.id.to_string(), &user.email, &user.role, &config)
        .map_err(|e| {
            tracing::error!(user_id = %user.id, error = %e, "Failed to create JWT token");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::debug!(user_id = %user.id, email = %user.email, role = %user.role, "Login successful");
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
    tracing::debug!(user_id = %auth_user.id, "GET /api/auth/me");

    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE id = $1",
    )
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %auth_user.id, error = %e, "DB error fetching user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match user {
        Some(u) => {
            tracing::debug!(user_id = %u.id, "Returning user info");
            Ok(Json(json!({
                "id": u.id,
                "email": u.email,
                "role": u.role,
                "approved": u.approved
            })))
        }
        None => {
            tracing::debug!(user_id = %auth_user.id, "User not found");
            Err(StatusCode::NOT_FOUND)
        }
    }
}
