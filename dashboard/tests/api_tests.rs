mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::TestContext;

// ============================================================================
// Auth Tests
// ============================================================================

#[tokio::test]
async fn test_signup_creates_user() {
    let ctx = TestContext::new().await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "email": "new@test.com",
                        "password": "password123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["email"], "new@test.com");
    assert_eq!(json["approved"], false);
    assert!(json["message"].as_str().unwrap().contains("Waiting for admin approval"));
}

#[tokio::test]
async fn test_signup_duplicate_email_returns_conflict() {
    let ctx = TestContext::new().await;
    ctx.create_user("dup@test.com", "pass123", false).await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "email": "dup@test.com",
                        "password": "password123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_login_unapproved_user_returns_forbidden() {
    let ctx = TestContext::new().await;
    ctx.create_user("unapproved@test.com", "pass123", false).await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "email": "unapproved@test.com",
                        "password": "pass123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_login_wrong_password_returns_unauthorized() {
    let ctx = TestContext::new().await;
    ctx.create_user("user@test.com", "correct", true).await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "email": "user@test.com",
                        "password": "wrong"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_nonexistent_user_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "email": "nobody@test.com",
                        "password": "pass"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_approved_user_returns_token() {
    let ctx = TestContext::new().await;
    ctx.create_user("approved@test.com", "pass123", true).await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "email": "approved@test.com",
                        "password": "pass123"
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["token"].as_str().unwrap().len() > 20);
    assert_eq!(json["user"]["email"], "approved@test.com");
    assert_eq!(json["user"]["role"], "customer");
}

#[tokio::test]
async fn test_me_returns_user_info() {
    let ctx = TestContext::new().await;
    let (id, email, _) = ctx.create_user("me@test.com", "pass123", true).await;
    let token = ctx.make_token(&id.to_string(), &email, "customer");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["email"], "me@test.com");
    assert_eq!(json["role"], "customer");
    assert_eq!(json["approved"], true);
}

#[tokio::test]
async fn test_me_no_token_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_invalid_token_returns_unauthorized() {
    let ctx = TestContext::new().await;
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/auth/me")
                .header("authorization", "Bearer invalid-token-here")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// Admin Tests
// ============================================================================

#[tokio::test]
async fn test_admin_list_users() {
    let ctx = TestContext::new().await;
    let (admin_id, admin_email, _) = ctx.create_admin("admin@test.com", "admin123").await;
    ctx.create_user("user1@test.com", "pass", true).await;
    ctx.create_user("user2@test.com", "pass", false).await;
    let token = ctx.make_token(&admin_id.to_string(), &admin_email, "admin");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/admin/users")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let users = json["users"].as_array().unwrap();
    // 3 users: admin + 2 customers
    assert_eq!(users.len(), 3);
}

#[tokio::test]
async fn test_admin_approve_user() {
    let ctx = TestContext::new().await;
    let (admin_id, admin_email, _) = ctx.create_admin("admin@test.com", "admin123").await;
    let (user_id, _, _) = ctx.create_user("pending@test.com", "pass", false).await;
    let token = ctx.make_token(&admin_id.to_string(), &admin_email, "admin");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/admin/users/{}/approve", user_id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify user is now approved
    let user = sqlx::query_as::<_, dashboard::models::User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert!(user.approved);
}

#[tokio::test]
async fn test_admin_approve_nonexistent_user_returns_not_found() {
    let ctx = TestContext::new().await;
    let (admin_id, admin_email, _) = ctx.create_admin("admin@test.com", "admin123").await;
    let token = ctx.make_token(&admin_id.to_string(), &admin_email, "admin");
    let app = ctx.app();

    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/admin/users/{}/approve", fake_id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_delete_user() {
    let ctx = TestContext::new().await;
    let (admin_id, admin_email, _) = ctx.create_admin("admin@test.com", "admin123").await;
    let (user_id, _, _) = ctx.create_user("todelete@test.com", "pass", true).await;
    let token = ctx.make_token(&admin_id.to_string(), &admin_email, "admin");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/admin/users/{}", user_id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify user is gone
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0);
}

#[tokio::test]
async fn test_non_admin_cannot_access_admin_routes() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("customer@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/admin/users")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ============================================================================
// Organization Tests
// ============================================================================

fn make_org_payload(id: &str, name: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "name": name,
        "domains": {
            "app.example.com": {
                "upstream_base_url": "http://localhost:8080",
                "upstream_timeout_ms": 5000,
                "auto_generate_tls": true
            }
        },
        "jwt_issuer": "https://auth.example.com",
        "jwt_audience": "quicguard",
        "auto_generate_jwt_keys": true
    })
}

#[tokio::test]
async fn test_create_org() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("orgowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("org-1", "Test Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "org-1");
    assert_eq!(json["name"], "Test Org");
    // Verify config has per-domain structure, auth, tls
    assert!(json["config"]["domains"]["app.example.com"].is_object());
    assert!(!json["config"]["auth"]["jwt_public_key"].as_str().unwrap().is_empty());
    assert!(!json["config"]["domains"]["app.example.com"]["tls"]["cert_pem"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_create_org_duplicate_id_returns_conflict() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("owner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create first org
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("dup-org", "First")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Try duplicate
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("dup-org", "Second")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_list_orgs() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("listowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create 2 orgs
    for i in 0..2 {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations")
                    .header("authorization", format!("Bearer {}", token))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&make_org_payload(
                        &format!("list-org-{}", i),
                        &format!("Org {}", i),
                    )).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["organizations"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_get_org() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("getowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("get-org", "Get Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/get-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], "get-org");
    assert_eq!(json["name"], "Get Org");
}

#[tokio::test]
async fn test_get_nonexistent_org_returns_not_found() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("noowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/nonexistent")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_org() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("delowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("del-org", "Del Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Delete
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/del-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify gone
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/del-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_user_cannot_access_other_users_org() {
    let ctx = TestContext::new().await;
    let (owner1_id, owner1_email, _) = ctx.create_user("owner1@test.com", "pass", true).await;
    let (owner2_id, owner2_email, _) = ctx.create_user("owner2@test.com", "pass", true).await;
    let token1 = ctx.make_token(&owner1_id.to_string(), &owner1_email, "customer");
    let token2 = ctx.make_token(&owner2_id.to_string(), &owner2_email, "customer");
    let app = ctx.app();

    // Owner1 creates org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token1))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("owner1-org", "Owner1 Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Owner2 tries to access it
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/owner1-org")
                .header("authorization", format!("Bearer {}", token2))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ============================================================================
// Policy Tests
// ============================================================================

#[tokio::test]
async fn test_add_policy_to_org() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("polowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("pol-org", "Pol Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add policy to domain
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations/pol-org/domains/app.example.com/policies")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": "allow-read",
                    "name": "Allow Read Access",
                    "effect": "Allow",
                    "rules": [{
                        "resource_type": "prefix",
                        "resource_value": "/api/v1/",
                        "methods": ["GET", "POST"],
                        "conditions": []
                    }]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let policies = json["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["id"], "allow-read");
    assert_eq!(policies[0]["name"], "Allow Read Access");
    assert_eq!(policies[0]["effect"], "Allow");
}

#[tokio::test]
async fn test_remove_policy_from_org() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("rmpolowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("rmpol-org", "RmPol Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add policy to domain
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations/rmpol-org/domains/app.example.com/policies")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": "temp-policy",
                    "name": "Temp Policy",
                    "rules": [{"resource_type": "prefix", "resource_value": "/", "methods": ["GET"]}]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Remove policy
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/rmpol-org/domains/app.example.com/policies/temp-policy")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_add_domain_policy() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("dpowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("dp-org", "DP Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add domain policy via new endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations/dp-org/domains/app.example.com/policies")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": "domain-deny",
                    "name": "Deny Admin on App Domain",
                    "effect": "Deny",
                    "rules": [{
                        "resource_type": "prefix",
                        "resource_value": "/admin",
                        "methods": ["GET", "POST"],
                        "conditions": []
                    }]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let dp = json["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp.len(), 1);
    assert_eq!(dp[0]["effect"], "Deny");
}

#[tokio::test]
async fn test_remove_domain_policy() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("rmdpowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("rmdp-org", "RmDP Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add domain policy via new endpoint
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations/rmdp-org/domains/app.example.com/policies")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": "rm-dpol",
                    "name": "To Remove",
                    "rules": [{"resource_type": "prefix", "resource_value": "/", "methods": ["GET"]}]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Remove
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/rmdp-org/domains/app.example.com/policies/rm-dpol")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let dp = json["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp.len(), 0);
}

#[tokio::test]
async fn test_multiple_policies_ordering() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("multiowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    // Create org
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("multi-org", "Multi Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Add 3 policies to domain
    for i in 0..3 {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations/multi-org/domains/app.example.com/policies")
                    .header("authorization", format!("Bearer {}", token))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&serde_json::json!({
                        "policy_id": format!("pol-{}", i),
                        "name": format!("Policy {}", i),
                        "rules": [{"resource_type": "prefix", "resource_value": "/", "methods": ["GET"]}]
                    })).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // Verify all 3 exist
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/multi-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let policies = json["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 3);
    assert_eq!(policies[0]["id"], "pol-0");
    assert_eq!(policies[1]["id"], "pol-1");
    assert_eq!(policies[2]["id"], "pol-2");
}

// ============================================================================
// Auto-generation Tests
// ============================================================================

#[tokio::test]
async fn test_create_org_auto_generates_jwt_keys() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("autogen@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&make_org_payload("autogen-org", "AutoGen Org")).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // JWT public key should be auto-generated
    let jwt_key = json["config"]["auth"]["jwt_public_key"].as_str().unwrap();
    assert!(jwt_key.contains("BEGIN CERTIFICATE"));
    assert!(!jwt_key.is_empty());

    // TLS cert should be auto-generated
    let tls_cert = json["config"]["domains"]["app.example.com"]["tls"]["cert_pem"].as_str().unwrap();
    assert!(tls_cert.contains("BEGIN CERTIFICATE"));

    let tls_key = json["config"]["domains"]["app.example.com"]["tls"]["key_pem"].as_str().unwrap();
    assert!(tls_key.contains("BEGIN PRIVATE KEY"));
}

#[tokio::test]
async fn test_create_org_with_manual_keys() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("manual@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");
    let app = ctx.app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "id": "manual-org",
                    "name": "Manual Org",
                    "domains": {
                        "manual.example.com": {
                            "upstream_base_url": "http://localhost:8080",
                            "upstream_timeout_ms": 5000,
                            "auto_generate_tls": false,
                            "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
                            "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----"
                        }
                    },
                    "jwt_issuer": "https://auth.example.com",
                    "jwt_audience": "quicguard",
                    "auto_generate_jwt_keys": false,
                    "jwt_public_key": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["config"]["auth"]["jwt_public_key"].as_str().unwrap().contains("MIIB..."));
    assert!(json["config"]["domains"]["manual.example.com"]["tls"]["cert_pem"].as_str().unwrap().contains("MIIB..."));
    assert!(json["config"]["domains"]["manual.example.com"]["tls"]["key_pem"].as_str().unwrap().contains("MIIB..."));
}

// ============================================================================
// Unit Tests: build_org_config, build_policy_value
// ============================================================================

#[test]
fn test_build_policy_value_minimal() {
    let input = dashboard::models::AddPolicy {
        policy_id: "test-pol".to_string(),
        name: "Test Policy".to_string(),
        effect: None,
        rules: vec![dashboard::models::PolicyRuleInput {
            resource_type: "prefix".to_string(),
            resource_value: "/api/".to_string(),
            methods: vec!["GET".to_string()],
            conditions: None,
        }],
    };

    let policy = dashboard::routes::organizations::build_policy_value(&input);
    assert_eq!(policy["id"], "test-pol");
    assert_eq!(policy["name"], "Test Policy");
    assert_eq!(policy["effect"], "Allow"); // default
    assert!(policy["rules"].as_array().unwrap().len() == 1);
}

#[test]
fn test_build_policy_value_with_conditions() {
    let input = dashboard::models::AddPolicy {
        policy_id: "cond-pol".to_string(),
        name: "Conditional".to_string(),
        effect: Some("Deny".to_string()),
        rules: vec![dashboard::models::PolicyRuleInput {
            resource_type: "exact".to_string(),
            resource_value: "/admin".to_string(),
            methods: vec!["GET".to_string(), "POST".to_string()],
            conditions: Some(vec![dashboard::models::ConditionInput {
                claim: "role".to_string(),
                operator: "Equals".to_string(),
                value: "admin".to_string(),
            }]),
        }],
    };

    let policy = dashboard::routes::organizations::build_policy_value(&input);
    assert_eq!(policy["effect"], "Deny");
    let conditions = policy["rules"][0]["conditions"].as_array().unwrap();
    assert_eq!(conditions.len(), 1);
    assert_eq!(conditions[0]["claim"], "role");
    assert_eq!(conditions[0]["operator"], "Equals");
}

#[test]
fn test_build_policy_value_resource_types() {
    for (res_type, expected_key) in [("exact", "Exact"), ("prefix", "Prefix"), ("glob", "Glob"), ("unknown", "Prefix")] {
        let input = dashboard::models::AddPolicy {
            policy_id: "res-test".to_string(),
            name: "Res Test".to_string(),
            effect: None,
            rules: vec![dashboard::models::PolicyRuleInput {
                resource_type: res_type.to_string(),
                resource_value: "/test".to_string(),
                methods: vec!["GET".to_string()],
                conditions: None,
            }],
        };

        let policy = dashboard::routes::organizations::build_policy_value(&input);
        let resource = &policy["rules"][0]["resource"];
        assert!(resource.as_object().unwrap().contains_key(expected_key),
            "Expected key '{}' for resource_type '{}'", expected_key, res_type);
    }
}
