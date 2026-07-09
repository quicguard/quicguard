use dashboard::config::Config;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::atomic::{AtomicU32, Ordering};

static DB_COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct TestContext {
    pub pool: PgPool,
    pub config: Config,
}

impl TestContext {
    /// Creates a fresh test database and returns a TestContext.
    /// Requires DATABASE_URL env var pointing to a running Postgres.
    pub async fn new() -> Self {
        let base_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://quicguard:quicguard@localhost:5432/quicguard".to_string());

        let counter = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let db_name = format!("dashboard_test_{}", counter);

        // Connect to default postgres DB to create/drop test DB
        let base_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base_url)
            .await
            .expect("Failed to connect to base database");

        // Create test database
        sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
            .execute(&base_pool)
            .await
            .expect("Failed to drop test database");
        sqlx::query(&format!("CREATE DATABASE {}", db_name))
            .execute(&base_pool)
            .await
            .expect("Failed to create test database");

        // Connect to test database
        let test_url = base_url
            .rsplit_once('/')
            .map(|(base, _)| format!("{}/{}", base, db_name))
            .unwrap_or_else(|| base_url.clone());

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&test_url)
            .await
            .expect("Failed to connect to test database");

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("Failed to run migrations");

        let config = Config {
            database_url: test_url.clone(),
            redis_url: "redis://127.0.0.1:6379".to_string(),
            jwt_secret: "test-secret-key-for-testing".to_string(),
            server_port: 0,
            redis_org_key: format!("test:orgs:{}", db_name),
            redis_pubsub_channel: format!("test:updates:{}", db_name),
        };

        TestContext {
            pool,
            config,
        }
    }

    /// Creates a test user and returns (id, email, password).
    pub async fn create_user(&self, email: &str, password: &str, approved: bool) -> (uuid::Uuid, String, String) {
        let hash = dashboard::auth::hash_password(password).unwrap();
        let user = sqlx::query_as::<_, dashboard::models::User>(
            "INSERT INTO users (email, password_hash, role, approved) VALUES ($1, $2, 'customer', $3) RETURNING *",
        )
        .bind(email)
        .bind(&hash)
        .bind(approved)
        .fetch_one(&self.pool)
        .await
        .expect("Failed to create test user");
        (user.id, email.to_string(), password.to_string())
    }

    /// Creates a test admin user.
    pub async fn create_admin(&self, email: &str, password: &str) -> (uuid::Uuid, String, String) {
        let hash = dashboard::auth::hash_password(password).unwrap();
        let user = sqlx::query_as::<_, dashboard::models::User>(
            "INSERT INTO users (email, password_hash, role, approved) VALUES ($1, $2, 'admin', true) RETURNING *",
        )
        .bind(email)
        .bind(&hash)
        .fetch_one(&self.pool)
        .await
        .expect("Failed to create test admin");
        (user.id, email.to_string(), password.to_string())
    }

    /// Generates a valid JWT token for a user.
    pub fn make_token(&self, user_id: &str, email: &str, role: &str) -> String {
        dashboard::auth::create_token(user_id, email, role, &self.config).unwrap()
    }

    /// Builds the full app router (without middleware — for unit tests that call handlers directly).
    pub fn app(&self) -> axum::Router {
        let state = (self.pool.clone(), self.config.clone());
        let org_routes = dashboard::routes::organizations::org_router()
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                dashboard::middleware::auth_middleware,
            ));
        axum::Router::new()
            .nest(
                "/api",
                axum::Router::new()
                    .nest("/auth", dashboard::routes::auth::auth_router())
                    .nest("/admin", dashboard::routes::admin::admin_router())
                    .nest("/organizations", org_routes),
            )
            .with_state(state)
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        // Best-effort cleanup — test DB will be recreated on next run anyway
    }
}
