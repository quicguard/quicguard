use anyhow::Result;
use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post, Router},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use konfig::TokenClaims;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};
use url::Url;

mod config;
mod db;
pub mod otp;

use config::Config;
use db::Database;

#[derive(Clone)]
struct AppState {
    db: Database,
    config: Config,
}

#[derive(Deserialize)]
struct SendOtpRequest {
    email: String,
}

#[derive(Serialize)]
struct SendOtpResponse {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    otp: Option<String>, // Only in test mode
}

#[derive(Deserialize)]
struct VerifyOtpRequest {
    email: String,
    otp: String,
    req_url: String, // The original URL that initiated auth
}

#[derive(Serialize)]
struct VerifyOtpResponse {
    token: String,
    redirect_url: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn send_otp(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SendOtpRequest>,
) -> Result<(StatusCode, Json<SendOtpResponse>), (StatusCode, Json<ErrorResponse>)> {
    let otp = otp::generate_otp();
    
    info!("Generating OTP for email: {}", payload.email);
    
    // Store OTP in Redis
    state.db.store_otp(&payload.email, &otp, state.config.otp_expiry_seconds)
        .await
        .map_err(|e| {
            error!("Failed to store OTP: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Failed to generate OTP".to_string() }),
            )
        })?;

    // In production, send OTP via email API
    // For now, return OTP in response for testing
    let response = if state.config.email_api_url.is_some() {
        // TODO: Call email API to send OTP
        SendOtpResponse {
            message: "OTP sent to email".to_string(),
            otp: None,
        }
    } else {
        // Test mode: return OTP in response
        warn!("No email API configured, returning OTP in response (test mode)");
        SendOtpResponse {
            message: "OTP generated (test mode)".to_string(),
            otp: Some(otp),
        }
    };

    Ok((StatusCode::OK, Json(response)))
}

async fn verify_otp(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyOtpRequest>,
) -> Result<(StatusCode, Json<VerifyOtpResponse>), (StatusCode, Json<ErrorResponse>)> {
    info!("Verifying OTP for email: {}", payload.email);
    
    // Verify OTP
    let valid = state.db.verify_otp(&payload.email, &payload.otp)
        .await
        .map_err(|e| {
            error!("Failed to verify OTP: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Failed to verify OTP".to_string() }),
            )
        })?;

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse { error: "Invalid or expired OTP".to_string() }),
        ));
    }

    // Parse the request URL to get domain
    let req_url = Url::parse(&payload.req_url)
        .map_err(|e| {
            warn!("Invalid request URL: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Invalid request URL".to_string() }),
            )
        })?;

    let domain = req_url.host_str().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: "Invalid request URL: no host".to_string() }),
        )
    })?;

    // Look up organization by domain
    let org = state.db.lookup_org(domain)
        .await
        .map_err(|e| {
            error!("Failed to lookup org: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Failed to lookup organization".to_string() }),
            )
        })?
        .ok_or_else(|| {
            warn!("No organization found for domain: {}", domain);
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "Organization not found".to_string() }),
            )
        })?;

    // Find matching app
    let path = req_url.path();
    let app_id = konfig::find_matching_app(&org, domain, path)
        .ok_or_else(|| {
            warn!("No matching app for domain {} path {}", domain, path);
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse { error: "No matching application".to_string() }),
            )
        })?;

    // Generate JWT
    let now = Utc::now();
    let exp = now + Duration::hours(state.config.jwt_expiry_hours);

    let claims = TokenClaims {
        sub: payload.email.clone(),
        org_id: org.id.clone(),
        app: app_id.clone(),
        roles: vec![],
        permissions: vec![],
        iss: Some(org.auth.jwt_issuer.clone()),
        aud: Some(org.auth.jwt_audience.clone()),
        exp: Some(exp.timestamp() as u64),
        iat: Some(now.timestamp() as u64),
    };

    let encoding_key = EncodingKey::from_ed_pem(org.auth.jwt_private_key.as_bytes())
        .map_err(|e| {
            error!("Failed to create encoding key: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Failed to create JWT".to_string() }),
            )
        })?;

    let token = encode(&Header::new(jsonwebtoken::Algorithm::EdDSA), &claims, &encoding_key)
        .map_err(|e| {
            error!("Failed to encode JWT: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse { error: "Failed to create JWT".to_string() }),
            )
        })?;

    // Build redirect URL with token
    let mut redirect_url = req_url;
    redirect_url.query_pairs_mut().append_pair(&org.auth.token_param_name, &token);

    info!("Issued JWT for email: {}, org: {}, app: {}", payload.email, org.id, app_id);

    Ok((
        StatusCode::OK,
        Json(VerifyOtpResponse {
            token,
            redirect_url: redirect_url.to_string(),
        }),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load configuration
    let config = Config::from_env()?;
    info!("Starting auth service on port {}", config.server_port);

    // Initialize database
    let db = Database::new(&config.redis_url, &config.redis_org_key)?;
    info!("Connected to Redis");

    // Create shared state
    let state = Arc::new(AppState { db, config: config.clone() });

    // Build router
    let app = Router::new()
        .route("/api/otp/send", post(send_otp))
        .route("/api/otp/verify", post(verify_otp))
        .fallback_service(ServeDir::new("static"))
        .with_state(state);

    // Start server
    let addr = format!("0.0.0.0:{}", config.server_port);
    info!("Auth service listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_generate_otp() {
        let otp = otp::generate_otp();
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }
}
