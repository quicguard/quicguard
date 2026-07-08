use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use dashboard::config::Config;

fn test_config() -> Config {
    Config {
        database_url: "postgres://unused:unused@localhost:5432/unused".to_string(),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        jwt_secret: "test-secret".to_string(),
        server_port: 0,
        redis_org_key: "test:orgs".to_string(),
        redis_pubsub_channel: "test:updates".to_string(),
    }
}

/// Test routes WITHOUT middleware — baseline.
#[tokio::test]
async fn test_routes_without_middleware() {
    let app = axum::Router::new()
        .nest(
            "/api/organizations",
            dashboard::routes::organizations::org_router(),
        )
        .with_state((
            sqlx::PgPool::connect_lazy("postgres://x").unwrap(),
            test_config(),
        ));

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/test-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED,
        "DELETE route not registered (no middleware)");
    println!("No middleware: DELETE -> {}", response.status());
}

/// Test routes WITH middleware — mimics actual server setup.
#[tokio::test]
async fn test_routes_with_middleware() {
    let state = (
        sqlx::PgPool::connect_lazy("postgres://x").unwrap(),
        test_config(),
    );

    let org_routes = dashboard::routes::organizations::org_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            dashboard::middleware::auth_middleware,
        ));

    let app = axum::Router::new()
        .nest("/api/organizations", org_routes)
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/organizations/test-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED,
        "DELETE route not registered (with middleware)");
    println!("With middleware: DELETE -> {}", response.status());
}

/// Test all routes WITH middleware.
#[tokio::test]
async fn test_all_routes_with_middleware() {
    let state = (
        sqlx::PgPool::connect_lazy("postgres://x").unwrap(),
        test_config(),
    );

    let org_routes = dashboard::routes::organizations::org_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            dashboard::middleware::auth_middleware,
        ));

    let app = axum::Router::new()
        .nest("/api/organizations", org_routes)
        .with_state(state);

    let tests = vec![
        ("GET", "/api/organizations"),
        ("POST", "/api/organizations"),
        ("GET", "/api/organizations/test-id"),
        ("PUT", "/api/organizations/test-id"),
        ("DELETE", "/api/organizations/test-id"),
        ("POST", "/api/organizations/test-id/policies"),
        ("DELETE", "/api/organizations/test-id/policies/pol-1"),
        ("POST", "/api/organizations/test-id/domain-policies"),
        ("DELETE", "/api/organizations/test-id/domain-policies/app.example.com/pol-1"),
    ];

    for (method, path) in tests {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED,
            "{} {} returned 405 — route not registered!", method, path);
        println!("{} {} -> {}", method, path, status);
    }
}

/// Full server setup test — matches main.rs exactly.
#[tokio::test]
async fn test_full_server_routing() {
    let state = (
        sqlx::PgPool::connect_lazy("postgres://x").unwrap(),
        test_config(),
    );

    let admin_routes = dashboard::routes::admin::admin_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            dashboard::middleware::admin_only,
        ));
    let org_routes = dashboard::routes::organizations::org_router()
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            dashboard::middleware::auth_middleware,
        ));

    let api_routes = axum::Router::new()
        .nest("/auth", dashboard::routes::auth::auth_router())
        .nest("/admin", admin_routes)
        .nest("/organizations", org_routes);

    let app = axum::Router::new()
        .nest("/api", api_routes)
        .with_state(state);

    let tests = vec![
        ("POST", "/api/auth/signup"),
        ("POST", "/api/auth/login"),
        ("GET", "/api/auth/me"),
        ("GET", "/api/admin/users"),
        ("PUT", "/api/admin/users/00000000-0000-0000-0000-000000000000/approve"),
        ("DELETE", "/api/admin/users/00000000-0000-0000-0000-000000000000"),
        ("GET", "/api/admin/organizations"),
        ("GET", "/api/organizations"),
        ("POST", "/api/organizations"),
        ("GET", "/api/organizations/test-id"),
        ("PUT", "/api/organizations/test-id"),
        ("DELETE", "/api/organizations/test-id"),
        ("POST", "/api/organizations/test-id/policies"),
        ("DELETE", "/api/organizations/test-id/policies/pol-1"),
        ("POST", "/api/organizations/test-id/domain-policies"),
        ("DELETE", "/api/organizations/test-id/domain-policies/app.example.com/pol-1"),
    ];

    for (method, path) in tests {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED,
            "{} {} returned 405 — route not registered!", method, path);
        println!("{} {} -> {}", method, path, status);
    }
}
