use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{auth::validate_token, config::Config, db::DbPool, models::User};

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: String,
}

pub async fn auth_middleware(
    State((pool, config)): State<(DbPool, Config)>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    tracing::debug!(path = %path, "auth_middleware: processing request");

    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => {
            tracing::debug!(path = %path, "auth_middleware: no Bearer token found");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    tracing::debug!(path = %path, "auth_middleware: validating JWT token");
    let claims = validate_token(token, &config).map_err(|e| {
        tracing::debug!(path = %path, error = %e, "auth_middleware: invalid token");
        StatusCode::UNAUTHORIZED
    })?;

    tracing::debug!(path = %path, user_id = %claims.sub, role = %claims.role,
        "auth_middleware: fetching user from DB");
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            tracing::error!(path = %path, user_id = %claims.sub, error = %e,
                "auth_middleware: DB error fetching user");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match user {
        Some(u) if u.approved => {
            tracing::debug!(path = %path, user_id = %u.id, email = %u.email, role = %u.role,
                "auth_middleware: access granted");
            request.extensions_mut().insert(AuthUser {
                id: u.id,
                email: u.email,
                role: u.role,
            });
            request.extensions_mut().insert(pool);
            request.extensions_mut().insert(config);
            Ok(next.run(request).await)
        }
        Some(_) => {
            tracing::debug!(path = %path, user_id = %claims.sub,
                "auth_middleware: access denied (user not approved)");
            Err(StatusCode::FORBIDDEN)
        }
        None => {
            tracing::debug!(path = %path, user_id = %claims.sub,
                "auth_middleware: access denied (user not found)");
            Err(StatusCode::FORBIDDEN)
        }
    }
}

pub async fn admin_only(
    State((pool, config)): State<(DbPool, Config)>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    tracing::debug!(path = %path, "admin_only: processing request");

    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => {
            tracing::debug!(path = %path, "admin_only: no Bearer token found");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    tracing::debug!(path = %path, "admin_only: validating JWT token");
    let claims = validate_token(token, &config).map_err(|e| {
        tracing::debug!(path = %path, error = %e, "admin_only: invalid token");
        StatusCode::UNAUTHORIZED
    })?;

    if claims.role != "admin" {
        tracing::debug!(path = %path, user_id = %claims.sub, role = %claims.role,
            "admin_only: access denied (not admin)");
        return Err(StatusCode::FORBIDDEN);
    }

    tracing::debug!(path = %path, user_id = %claims.sub,
        "admin_only: fetching user from DB");
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?)
        .fetch_optional(&pool)
        .await
        .map_err(|e| {
            tracing::error!(path = %path, user_id = %claims.sub, error = %e,
                "admin_only: DB error fetching user");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    match user {
        Some(u) if u.approved => {
            tracing::debug!(path = %path, user_id = %u.id, email = %u.email,
                "admin_only: admin access granted");
            request.extensions_mut().insert(AuthUser {
                id: u.id,
                email: u.email,
                role: u.role,
            });
            request.extensions_mut().insert(pool);
            request.extensions_mut().insert(config);
            Ok(next.run(request).await)
        }
        Some(_) => {
            tracing::debug!(path = %path, user_id = %claims.sub,
                "admin_only: access denied (user not approved)");
            Err(StatusCode::FORBIDDEN)
        }
        None => {
            tracing::debug!(path = %path, user_id = %claims.sub,
                "admin_only: access denied (user not found)");
            Err(StatusCode::FORBIDDEN)
        }
    }
}
