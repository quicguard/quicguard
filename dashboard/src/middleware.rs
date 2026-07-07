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
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = validate_token(token, &config).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?)
        .fetch_optional(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match user {
        Some(u) if u.approved => {
            request.extensions_mut().insert(AuthUser {
                id: u.id,
                email: u.email,
                role: u.role,
            });
            request.extensions_mut().insert(pool);
            request.extensions_mut().insert(config);
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::FORBIDDEN),
    }
}

pub async fn admin_only(
    State((pool, config)): State<(DbPool, Config)>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let token = match token {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = validate_token(token, &config).map_err(|_| StatusCode::UNAUTHORIZED)?;

    if claims.role != "admin" {
        return Err(StatusCode::FORBIDDEN);
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&claims.sub).map_err(|_| StatusCode::UNAUTHORIZED)?)
        .fetch_optional(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match user {
        Some(u) if u.approved => {
            request.extensions_mut().insert(AuthUser {
                id: u.id,
                email: u.email,
                role: u.role,
            });
            request.extensions_mut().insert(pool);
            request.extensions_mut().insert(config);
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::FORBIDDEN),
    }
}
