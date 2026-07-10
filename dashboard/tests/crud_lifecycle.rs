mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use common::TestContext;

/// Helper: create org via API and return the response JSON.
async fn create_org(ctx: &TestContext, token: &str, id: &str, name: &str) -> serde_json::Value {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "id": id,
                    "name": name,
                    "domains": {
                        "app.example.com": {
                            "upstream_base_url": "http://localhost:8080",
                            "upstream_timeout_ms": 5000,
                            "auto_generate_tls": true
                        },
                        "api.example.com": {
                            "upstream_base_url": "http://localhost:8080",
                            "upstream_timeout_ms": 5000,
                            "auto_generate_tls": true
                        }
                    },
                    "jwt_issuer": "https://auth.example.com",
                    "jwt_audience": "quicguard",
                    "auto_generate_jwt_keys": true
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: get org via API.
async fn get_org(ctx: &TestContext, token: &str, id: &str) -> serde_json::Value {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/organizations/{}", id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: list orgs via API.
async fn list_orgs(ctx: &TestContext, token: &str) -> Vec<serde_json::Value> {
    let app = ctx.app();
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    json["organizations"].as_array().unwrap().clone()
}

/// Helper: delete org via API.
async fn delete_org(ctx: &TestContext, token: &str, id: &str) -> StatusCode {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/organizations/{}", id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

/// Helper: add policy to domain via API.
async fn add_policy(ctx: &TestContext, token: &str, org_id: &str, policy_id: &str, name: &str) -> serde_json::Value {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/organizations/{}/domains/app.example.com/policies", org_id))
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": policy_id,
                    "name": name,
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
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: remove policy from domain via API.
async fn remove_policy(ctx: &TestContext, token: &str, org_id: &str, policy_id: &str) -> serde_json::Value {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/organizations/{}/domains/app.example.com/policies/{}", org_id, policy_id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: add domain policy via API.
async fn add_domain_policy(ctx: &TestContext, token: &str, org_id: &str, domain: &str, policy_id: &str) -> serde_json::Value {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/organizations/{}/domains/{}/policies", org_id, domain))
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": policy_id,
                    "name": format!("Domain policy for {}", domain),
                    "effect": "Deny",
                    "rules": [{
                        "resource_type": "prefix",
                        "resource_value": "/admin",
                        "methods": ["GET"],
                        "conditions": []
                    }]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Helper: remove domain policy via API.
async fn remove_domain_policy(ctx: &TestContext, token: &str, org_id: &str, domain: &str, policy_id: &str) -> serde_json::Value {
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/organizations/{}/domains/{}/policies/{}", org_id, domain, policy_id))
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ============================================================================
// Full CRUD Lifecycle Tests
// ============================================================================

/// Complete lifecycle: create org -> verify -> add policies -> verify -> remove policies -> verify -> delete -> verify gone.
#[tokio::test]
async fn test_full_org_lifecycle() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("lifecycle@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");

    // 1. Create org
    println!("=== Step 1: Create org ===");
    let created = create_org(&ctx, &token, "lifecycle-org", "Lifecycle Org").await;
    assert_eq!(created["id"], "lifecycle-org");
    assert_eq!(created["name"], "Lifecycle Org");

    // Verify domains exist
    let domains = created["config"]["domains"].as_object().unwrap();
    assert!(domains.contains_key("app.example.com"));
    assert!(domains.contains_key("api.example.com"));

    // Verify auto-generated keys
    assert!(!created["config"]["auth"]["jwt_public_key"].as_str().unwrap().is_empty());
    assert!(!created["config"]["domains"]["app.example.com"]["tls"]["cert_pem"].as_str().unwrap().is_empty());
    assert!(!created["config"]["domains"]["api.example.com"]["tls"]["cert_pem"].as_str().unwrap().is_empty());

    // 2. Get org
    println!("=== Step 2: Get org ===");
    let fetched = get_org(&ctx, &token, "lifecycle-org").await;
    assert_eq!(fetched["id"], "lifecycle-org");
    assert_eq!(fetched["name"], "Lifecycle Org");

    // 3. List orgs
    println!("=== Step 3: List orgs ===");
    let orgs = list_orgs(&ctx, &token).await;
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["id"], "lifecycle-org");

    // 4. Add policies
    println!("=== Step 4: Add policies ===");
    let result = add_policy(&ctx, &token, "lifecycle-org", "pol-1", "Allow Read").await;
    let policies = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["id"], "pol-1");

    let result = add_policy(&ctx, &token, "lifecycle-org", "pol-2", "Allow Write").await;
    let policies = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2);

    // 5. Add domain policy
    println!("=== Step 5: Add domain policy ===");
    let result = add_domain_policy(&ctx, &token, "lifecycle-org", "app.example.com", "dpol-1").await;
    let dp = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp.len(), 3);
    assert_eq!(dp[2]["id"], "dpol-1");
    assert_eq!(dp[2]["effect"], "Deny");

    // 6. Verify full config via GET
    println!("=== Step 6: Verify full config ===");
    let org = get_org(&ctx, &token, "lifecycle-org").await;
    assert_eq!(org["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(), 3);
    assert_eq!(org["config"]["domains"]["api.example.com"]["policies"].as_array().unwrap().len(), 0);

    // 7. Remove one policy
    println!("=== Step 7: Remove policy ===");
    let result = remove_policy(&ctx, &token, "lifecycle-org", "pol-1").await;
    assert_eq!(result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(), 2);

    // 8. Remove domain policy
    println!("=== Step 8: Remove domain policy ===");
    let result = remove_domain_policy(&ctx, &token, "lifecycle-org", "app.example.com", "dpol-1").await;
    assert_eq!(
        result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(),
        1
    );

    // 9. Verify only 1 policy remains
    println!("=== Step 9: Verify remaining ===");
    let org = get_org(&ctx, &token, "lifecycle-org").await;
    assert_eq!(org["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(), 1);
    assert_eq!(org["config"]["domains"]["app.example.com"]["policies"][0]["id"], "pol-2");

    // 10. Delete org
    println!("=== Step 10: Delete org ===");
    let status = delete_org(&ctx, &token, "lifecycle-org").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // 11. Verify gone
    println!("=== Step 11: Verify gone ===");
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/lifecycle-org")
                .header("authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // 12. Verify list is empty
    println!("=== Step 12: Verify list empty ===");
    let orgs = list_orgs(&ctx, &token).await;
    assert_eq!(orgs.len(), 0);
}

/// Test multiple orgs CRUD independently.
#[tokio::test]
async fn test_multiple_orgs_independent() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("multi@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");

    // Create 3 orgs
    create_org(&ctx, &token, "org-a", "Org A").await;
    create_org(&ctx, &token, "org-b", "Org B").await;
    create_org(&ctx, &token, "org-c", "Org C").await;

    // List shows all 3
    let orgs = list_orgs(&ctx, &token).await;
    assert_eq!(orgs.len(), 3);

    // Add policies to each
    add_policy(&ctx, &token, "org-a", "a-pol", "Policy A").await;
    add_policy(&ctx, &token, "org-b", "b-pol", "Policy B").await;
    add_policy(&ctx, &token, "org-c", "c-pol", "Policy C").await;

    // Verify each has exactly 1 policy
    let org_a = get_org(&ctx, &token, "org-a").await;
    assert_eq!(org_a["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(), 1);
    let org_b = get_org(&ctx, &token, "org-b").await;
    assert_eq!(org_b["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap().len(), 1);

    // Delete org-b
    let status = delete_org(&ctx, &token, "org-b").await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify org-b is gone, others remain
    let orgs = list_orgs(&ctx, &token).await;
    assert_eq!(orgs.len(), 2);
    let ids: Vec<&str> = orgs.iter().map(|o| o["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"org-a"));
    assert!(ids.contains(&"org-c"));
    assert!(!ids.contains(&"org-b"));
}

/// Test policy CRUD in detail — multiple policies, conditions, resource types.
#[tokio::test]
async fn test_policy_crud_detailed() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("policyowner@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");

    create_org(&ctx, &token, "pol-org", "Policy Org").await;

    // Add policy with conditions
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/organizations/pol-org/domains/app.example.com/policies")
                .header("authorization", format!("Bearer {}", token))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&serde_json::json!({
                    "policy_id": "cond-pol",
                    "name": "Conditional Policy",
                    "effect": "Deny",
                    "rules": [{
                        "resource_type": "exact",
                        "resource_value": "/admin",
                        "methods": ["GET", "POST", "DELETE"],
                        "conditions": [
                            {"claim": "role", "operator": "Equals", "value": "user"},
                            {"claim": "org_id", "operator": "NotEquals", "value": "admin-org"}
                        ]
                    }]
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let policies = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["effect"], "Deny");
    let conditions = policies[0]["rules"][0]["conditions"].as_array().unwrap();
    assert_eq!(conditions.len(), 2);

    // Add glob policy
    let result = add_policy(&ctx, &token, "pol-org", "glob-pol", "Glob Policy").await;
    let policies = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 2);

    // Remove the conditional policy
    let result = remove_policy(&ctx, &token, "pol-org", "cond-pol").await;
    let policies = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["id"], "glob-pol");
}

/// Test domain policy CRUD across multiple domains.
#[tokio::test]
async fn test_domain_policy_multi_domain() {
    let ctx = TestContext::new().await;
    let (user_id, user_email, _) = ctx.create_user("dpmulti@test.com", "pass", true).await;
    let token = ctx.make_token(&user_id.to_string(), &user_email, "customer");

    create_org(&ctx, &token, "dp-multi", "DP Multi").await;

    // Add domain policy to domain A
    let result = add_domain_policy(&ctx, &token, "dp-multi", "app.example.com", "dp-a1").await;
    let dp = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp.len(), 1);

    // Add another domain policy to domain A
    let result = add_domain_policy(&ctx, &token, "dp-multi", "app.example.com", "dp-a2").await;
    let dp = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp.len(), 2);

    // Add domain policy to domain B
    let result = add_domain_policy(&ctx, &token, "dp-multi", "api.example.com", "dp-b1").await;
    let dp_b = result["config"]["domains"]["api.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp_b.len(), 1);
    // Domain A should still have 2
    let dp_a = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp_a.len(), 2);

    // Remove from domain A
    let result = remove_domain_policy(&ctx, &token, "dp-multi", "app.example.com", "dp-a1").await;
    let dp_a = result["config"]["domains"]["app.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp_a.len(), 1);
    assert_eq!(dp_a[0]["id"], "dp-a2");
    // Domain B unaffected
    let dp_b = result["config"]["domains"]["api.example.com"]["policies"].as_array().unwrap();
    assert_eq!(dp_b.len(), 1);
}

/// Test user isolation — user A cannot access user B's orgs.
#[tokio::test]
async fn test_user_isolation() {
    let ctx = TestContext::new().await;
    let (user_a, email_a, _) = ctx.create_user("usera@test.com", "pass", true).await;
    let (user_b, email_b, _) = ctx.create_user("userb@test.com", "pass", true).await;
    let token_a = ctx.make_token(&user_a.to_string(), &email_a, "customer");
    let token_b = ctx.make_token(&user_b.to_string(), &email_b, "customer");

    // User A creates org
    create_org(&ctx, &token_a, "usera-org", "User A Org").await;

    // User B cannot see it
    let orgs = list_orgs(&ctx, &token_b).await;
    assert_eq!(orgs.len(), 0);

    // User B cannot get it
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/organizations/usera-org")
                .header("authorization", format!("Bearer {}", token_b))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // User B cannot delete it
    let response = ctx.app()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/usera-org")
                .header("authorization", format!("Bearer {}", token_b))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // User A can still access it
    let orgs = list_orgs(&ctx, &token_a).await;
    assert_eq!(orgs.len(), 1);
}

/// Test admin can view all orgs.
#[tokio::test]
async fn test_admin_sees_all_orgs() {
    let ctx = TestContext::new().await;
    let (user_a, email_a, _) = ctx.create_user("ownera@test.com", "pass", true).await;
    let (admin_id, admin_email, _) = ctx.create_admin("admin@test.com", "admin123").await;
    let token_a = ctx.make_token(&user_a.to_string(), &email_a, "customer");
    let token_admin = ctx.make_token(&admin_id.to_string(), &admin_email, "admin");

    // User creates org
    create_org(&ctx, &token_a, "ownera-org", "Owner A Org").await;

    // Admin can see all orgs
    let app = ctx.app();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/admin/organizations")
                .header("authorization", format!("Bearer {}", token_admin))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let orgs = json["organizations"].as_array().unwrap();
    assert_eq!(orgs.len(), 1);
    assert_eq!(orgs[0]["id"], "ownera-org");
}
