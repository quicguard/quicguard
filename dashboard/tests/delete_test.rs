mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::TestContext;

/// Test the exact flow: create org -> verify exists -> delete -> verify gone.
/// This is the test that validates the user's reported 405 issue.
#[tokio::test]
async fn test_create_then_delete_org() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("deleter@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");

    // Step 1: Create org
    println!("Step 1: Creating org 'test-delete-org'");
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "id": "test-delete-org",
                    "name": "Test Delete Org",
                    "domains": ["app.example.com"],
                    "upstream_base_url": "http://localhost:8080",
                    "upstream_timeout_ms": 5000,
                    "jwt_issuer": "https://auth.example.com",
                    "jwt_audience": "quicguard",
                    "auto_generate_jwt_keys": true,
                    "tls_configs": [
                        {"domain": "app.example.com", "auto_generate": true}
                    ]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Create should return 200");
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let created: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(created["id"], "test-delete-org");
    println!("  Created: {}", created["id"]);

    // Step 2: Verify org exists via GET
    println!("Step 2: Verifying org exists via GET");
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/test-delete-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "GET should return 200");
    println!("  GET returned 200 OK");

    // Step 3: Verify org in list
    println!("Step 3: Verifying org appears in list");
    let response = ctx.app()
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let orgs = list["organizations"].as_array().unwrap();
    assert_eq!(orgs.len(), 1, "Should have 1 org");
    assert_eq!(orgs[0]["id"], "test-delete-org");
    println!("  List contains 1 org: {}", orgs[0]["id"]);

    // Step 4: DELETE the org
    println!("Step 4: Deleting org via DELETE");
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/test-delete-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "DELETE should return 204, got {}",
        response.status()
    );
    println!("  DELETE returned 204 No Content");

    // Step 5: Verify org is gone via GET
    println!("Step 5: Verifying org is gone via GET");
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/test-delete-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET after DELETE should return 404"
    );
    println!("  GET returned 404 Not Found (correct)");

    // Step 6: Verify org is gone from list
    println!("Step 6: Verifying org is gone from list");
    let response = ctx.app()
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let orgs = list["organizations"].as_array().unwrap();
    assert_eq!(orgs.len(), 0, "Should have 0 orgs after delete");
    println!("  List is empty (correct)");

    println!("All steps passed!");
}

/// Test delete with numeric ID (matching user's "1" ID).
#[tokio::test]
async fn test_create_then_delete_numeric_id() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("numid@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");

    // Create org with numeric-style ID
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "id": "1",
                    "name": "Org One",
                    "domains": ["one.example.com"],
                    "upstream_base_url": "http://localhost:8080",
                    "upstream_timeout_ms": 5000,
                    "jwt_issuer": "https://auth.example.com",
                    "jwt_audience": "quicguard",
                    "auto_generate_jwt_keys": true,
                    "tls_configs": [{"domain": "one.example.com", "auto_generate": true}]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    println!("Created org with id='1'");

    // Delete it
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/1")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "DELETE /api/organizations/1 should return 204, got {}",
        response.status()
    );
    println!("Deleted org id='1' — 204 No Content");

    // Verify gone
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/1")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    println!("Verified org id='1' is gone — 404 Not Found");
}
