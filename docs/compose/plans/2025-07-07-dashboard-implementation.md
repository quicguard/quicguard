# QuicGuard Dashboard Implementation Plan

> [!NOTE]
> This document may not reflect the current implementation.
> See the final report for up-to-date state:
> [Final Report](../reports/dashboard.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use compose:subagent (recommended) or compose:execute to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a management dashboard (Axum + Svelte) for QuicGuard org configs with user auth, RBAC, Postgres persistence, and real-time Redis sync.

**Architecture:** New `dashboard` crate in workspace. Axum serves both API and SPA static files. Postgres stores users and org configs (JSONB). Org mutations sync to Redis via HSET + PUBLISH to `quicguard:updates`.

**Tech Stack:** axum, sqlx (postgres), bcrypt, jsonwebtoken, redis, svelte, vite, dotenvy

## Global Constraints

- Rust edition 2021, workspace root at `/home/amir/code/quicguard`
- Postgres: sqlx with `DATABASE_URL` env var, migrations in `dashboard/migrations/`
- JWT: HS256, 24h expiry, secret from `JWT_SECRET` env var
- Password: bcrypt cost 12
- Redis: reuse existing `quicguard:organizations` hash key and `quicguard:updates` pubsub channel
- Frontend: Svelte SPA built to `dashboard/static/`, served by Axum with SPA fallback
- All `.env` values must have `.env.example` with placeholder values

---

### Task 1: Project Scaffolding

**Covers:** [S2, S11, S12]

**Files:**
- Create: `dashboard/Cargo.toml`
- Create: `dashboard/.env.example`
- Create: `dashboard/.gitignore`
- Create: `dashboard/migrations/001_initial.sql`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces: workspace member `dashboard`, runnable via `cargo run -p dashboard`

- [ ] **Step 1: Add dashboard to workspace**

Edit `Cargo.toml` (root):
```toml
[workspace]
members = [".", "konfig", "dashboard"]
```

- [ ] **Step 2: Create dashboard crate**

```bash
mkdir -p dashboard/migrations dashboard/scripts
```

Create `dashboard/Cargo.toml`:
```toml
[package]
name = "dashboard"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "dashboard"
path = "src/main.rs"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "fs"] }
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "uuid", "chrono"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
bcrypt = "0.15"
jsonwebtoken = "9"
redis = { version = "1", features = ["tokio-comp"] }
dotenvy = "0.15"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
anyhow = "1"
```

- [ ] **Step 3: Create .env.example**

Create `dashboard/.env.example`:
```env
DATABASE_URL=postgres://quicguard:quicguard@localhost:5432/quicguard
REDIS_URL=redis://127.0.0.1:6379
JWT_SECRET=change-me-to-a-random-secret
SERVER_PORT=3000
REDIS_ORG_KEY=quicguard:organizations
REDIS_PUBSUB_CHANNEL=quicguard:updates
```

- [ ] **Step 4: Create .gitignore**

Create `dashboard/.gitignore`:
```
target/
.env
static/
frontend/node_modules/
frontend/dist/
```

- [ ] **Step 5: Create SQL migration**

Create `dashboard/migrations/001_initial.sql`:
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'customer',
    approved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organizations (
    id VARCHAR(64) PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organizations_owner_id ON organizations(owner_id);
```

- [ ] **Step 6: Create placeholder main.rs**

Create `dashboard/src/main.rs`:
```rust
fn main() {
    println!("QuicGuard Dashboard");
}
```

- [ ] **Step 7: Verify build**

Run: `cargo build -p dashboard`
Expected: Compiles successfully

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml dashboard/
git commit -m "feat(dashboard): scaffold project with Cargo.toml, migrations, and env config"
```

---

### Task 2: Config and Database Layer

**Covers:** [S4, S9]

**Files:**
- Create: `dashboard/src/config.rs`
- Create: `dashboard/src/db.rs`
- Create: `dashboard/src/models.rs`

**Interfaces:**
- Consumes: Task 1 (Cargo.toml, migrations)
- Produces: `Config` struct, `DbPool` type alias, `User`/`Organization` models

- [ ] **Step 1: Create config module**

Create `dashboard/src/config.rs`:
```rust
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub server_port: u16,
    pub redis_org_key: String,
    pub redis_pubsub_channel: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .map_err(|_| anyhow::anyhow!("DATABASE_URL not set"))?,
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            jwt_secret: std::env::var("JWT_SECRET")
                .map_err(|_| anyhow::anyhow!("JWT_SECRET not set"))?,
            server_port: std::env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            redis_org_key: std::env::var("REDIS_ORG_KEY")
                .unwrap_or_else(|_| "quicguard:organizations".to_string()),
            redis_pubsub_channel: std::env::var("REDIS_PUBSUB_CHANNEL")
                .unwrap_or_else(|_| "quicguard:updates".to_string()),
        })
    }
}
```

- [ ] **Step 2: Create models module**

Create `dashboard/src/models.rs`:
```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub approved: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organization {
    pub id: String,
    pub owner_id: Uuid,
    pub name: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganization {
    pub id: String,
    pub name: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    pub config: Option<serde_json::Value>,
}
```

- [ ] **Step 3: Create database module**

Create `dashboard/src/db.rs`:
```rust
use anyhow::Result;
use sqlx::postgres::{PgPool, PgPoolOptions};

pub type DbPool = PgPool;

pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn run_migrations(pool: &DbPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}
```

- [ ] **Step 4: Update main.rs to use config and db**

Replace `dashboard/src/main.rs`:
```rust
mod config;
mod db;
mod models;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = config::Config::from_env()?;
    let pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;

    tracing::info!("Database migrations applied");
    tracing::info!("Starting server on port {}", config.server_port);

    Ok(())
}
```

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/
git commit -m "feat(dashboard): add config, db pool, and models layer"
```

---

### Task 3: Auth System (JWT + Password)

**Covers:** [S6]

**Files:**
- Create: `dashboard/src/auth.rs`
- Create: `dashboard/src/middleware.rs`

**Interfaces:**
- Consumes: Task 2 (Config, User model, DbPool)
- Produces: `create_token()`, `validate_token()`, `AuthUser` extractor, `RequireRole` extractor

- [ ] **Step 1: Create auth module**

Create `dashboard/src/auth.rs`:
```rust
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub exp: usize,
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

pub fn create_token(
    user_id: &str,
    email: &str,
    role: &str,
    config: &Config,
) -> Result<String, jsonwebtoken::errors::Error> {
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
}

pub fn validate_token(
    token: &str,
    config: &Config,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}
```

- [ ] **Step 2: Create middleware module**

Create `dashboard/src/middleware.rs`:
```rust
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
            // Re-insert state so downstream handlers can access it
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
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/auth.rs dashboard/src/middleware.rs
git commit -m "feat(dashboard): add JWT auth and RBAC middleware"
```

---

### Task 4: Auth Routes (Signup, Login, Me)

**Covers:** [S5, S6]

**Files:**
- Create: `dashboard/src/routes/mod.rs`
- Create: `dashboard/src/routes/auth.rs`

**Interfaces:**
- Consumes: Task 2 (DbPool, models), Task 3 (auth functions, AuthUser)
- Produces: `auth_router()` function

- [ ] **Step 1: Create routes module**

Create `dashboard/src/routes/mod.rs`:
```rust
pub mod auth;
pub mod admin;
pub mod organizations;
```

Create placeholder files:
```bash
touch dashboard/src/routes/admin.rs dashboard/src/routes/organizations.rs
```

Add to `dashboard/src/routes/admin.rs`:
```rust
use axum::Router;
use crate::db::DbPool;
use crate::config::Config;

pub fn admin_router() -> Router<(DbPool, Config)> {
    Router::new()
}
```

Add to `dashboard/src/routes/organizations.rs`:
```rust
use axum::Router;
use crate::db::DbPool;
use crate::config::Config;

pub fn org_router() -> Router<(DbPool, Config)> {
    Router::new()
}
```

- [ ] **Step 2: Create auth routes**

Create `dashboard/src/routes/auth.rs`:
```rust
use axum::{
    extract::State,
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
use uuid::Uuid;

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
```

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/routes/
git commit -m "feat(dashboard): add auth routes (signup, login, me)"
```

---

### Task 5: Admin and Organization Routes

**Covers:** [S5, S7]

**Files:**
- Modify: `dashboard/src/routes/admin.rs`
- Modify: `dashboard/src/routes/organizations.rs`
- Create: `dashboard/src/redis_sync.rs`

**Interfaces:**
- Consumes: Task 2-4 (all prior modules)
- Produces: `admin_router()`, `org_router()`, `sync_org_to_redis()`, `remove_org_from_redis()`

- [ ] **Step 1: Create Redis sync module**

Create `dashboard/src/redis_sync.rs`:
```rust
use anyhow::Result;
use redis::AsyncCommands;
use serde_json::Value;

use crate::{config::Config, models::Organization};

#[derive(Debug, serde::Serialize)]
pub struct OrgUpdate {
    pub org_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<Value>,
}

pub async fn sync_org_to_redis(
    config: &Config,
    org: &Organization,
) -> Result<()> {
    let client = redis::Client::open(config.redis_url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;

    let json = serde_json::to_string(&org.config)?;

    let _: () = conn.hset(&config.redis_org_key, &org.id, &json).await?;

    let update = OrgUpdate {
        org_id: org.id.clone(),
        action: "update".to_string(),
        organization: Some(org.config.clone()),
    };
    let update_json = serde_json::to_string(&update)?;
    let _: () = conn.publish(&config.redis_pubsub_channel, &update_json).await?;

    Ok(())
}

pub async fn remove_org_from_redis(
    config: &Config,
    org_id: &str,
) -> Result<()> {
    let client = redis::Client::open(config.redis_url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;

    let _: () = conn.hdel(&config.redis_org_key, org_id).await?;

    let update = OrgUpdate {
        org_id: org_id.to_string(),
        action: "delete".to_string(),
        organization: None,
    };
    let update_json = serde_json::to_string(&update)?;
    let _: () = conn.publish(&config.redis_pubsub_channel, &update_json).await?;

    Ok(())
}
```

- [ ] **Step 2: Implement admin routes**

Replace `dashboard/src/routes/admin.rs`:
```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    config::Config,
    db::DbPool,
    middleware::{admin_only, AuthUser},
    models::User,
};

pub fn admin_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/users", axum::routing::get(list_users))
        .route("/users/{id}/approve", axum::routing::put(approve_user))
        .route("/users/{id}", axum::routing::delete(delete_user))
        .route("/organizations", axum::routing::get(list_all_orgs))
        .layer(axum::middleware::from_fn(admin_only))
}

async fn list_users(
    State((pool, _config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "users": users.into_iter().map(|u| json!({
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "approved": u.approved,
            "created_at": u.created_at
        })).collect::<Vec<_>>()
    })))
}

async fn approve_user(
    State((pool, _config)): State<(DbPool, Config)>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let result = sqlx::query("UPDATE users SET approved = true, updated_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(json!({"message": "User approved"})))
}

async fn delete_user(
    State((pool, _config)): State<(DbPool, Config)>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn list_all_orgs(
    State((pool, _config)): State<(DbPool, Config)>,
) -> Result<Json<Value>, StatusCode> {
    let orgs = sqlx::query_as::<_, crate::models::Organization>(
        "SELECT * FROM organizations ORDER BY created_at DESC",
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "organizations": orgs.into_iter().map(|o| json!({
            "id": o.id,
            "owner_id": o.owner_id,
            "name": o.name,
            "config": o.config,
            "created_at": o.created_at
        })).collect::<Vec<_>>()
    })))
}
```

- [ ] **Step 3: Implement organization routes**

Replace `dashboard/src/routes/organizations.rs`:
```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json, Router,
};
use serde_json::{json, Value};

use crate::{
    config::Config,
    db::DbPool,
    middleware::{admin_only, auth_middleware, AuthUser},
    models::{CreateOrganization, Organization, UpdateOrganization},
    redis_sync,
};

pub fn org_router() -> Router<(DbPool, Config)> {
    Router::new()
        .route("/", axum::routing::get(list_orgs))
        .route("/", axum::routing::post(create_org))
        .route("/{id}", axum::routing::put(update_org))
        .route("/{id}", axum::routing::delete(delete_org))
        .layer(axum::middleware::from_fn(auth_middleware))
}

async fn list_orgs(
    State((pool, _config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<Json<Value>, StatusCode> {
    let orgs = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE owner_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth_user.id)
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({
        "organizations": orgs.into_iter().map(|o| json!({
            "id": o.id,
            "name": o.name,
            "config": o.config,
            "created_at": o.created_at
        })).collect::<Vec<_>>()
    })))
}

async fn create_org(
    State((pool, config)): State<(DbPool, Config)>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<CreateOrganization>,
) -> Result<Json<Value>, StatusCode> {
    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1)",
    )
    .bind(&input.id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing {
        return Err(StatusCode::CONFLICT);
    }

    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, owner_id, name, config) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(&input.id)
    .bind(auth_user.id)
    .bind(&input.name)
    .bind(&input.config)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &org).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

    Ok(Json(json!({
        "id": org.id,
        "name": org.name,
        "config": org.config,
        "created_at": org.created_at
    })))
}

async fn update_org(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
    Json(input): Json<UpdateOrganization>,
) -> Result<Json<Value>, StatusCode> {
    let org = sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND owner_id = $2",
    )
    .bind(&org_id)
    .bind(auth_user.id)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut org = match org {
        Some(o) => o,
        None => return Err(StatusCode::NOT_FOUND),
    };

    if let Some(name) = input.name {
        org.name = name;
    }
    if let Some(config_val) = input.config {
        org.config = config_val;
    }

    let updated = sqlx::query_as::<_, Organization>(
        "UPDATE organizations SET name = $1, config = $2, updated_at = NOW() WHERE id = $3 RETURNING *",
    )
    .bind(&org.name)
    .bind(&org.config)
    .bind(&org_id)
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(e) = redis_sync::sync_org_to_redis(&config, &updated).await {
        tracing::error!("Failed to sync org to Redis: {}", e);
    }

    Ok(Json(json!({
        "id": updated.id,
        "name": updated.name,
        "config": updated.config,
        "created_at": updated.created_at
    })))
}

async fn delete_org(
    State((pool, config)): State<(DbPool, Config)>,
    Path(org_id): Path<String>,
    auth_user: axum::extract::Extension<AuthUser>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("DELETE FROM organizations WHERE id = $1 AND owner_id = $2")
        .bind(&org_id)
        .bind(auth_user.id)
        .execute(&pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Err(e) = redis_sync::remove_org_from_redis(&config, &org_id).await {
        tracing::error!("Failed to remove org from Redis: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/routes/admin.rs dashboard/src/routes/organizations.rs dashboard/src/redis_sync.rs
git commit -m "feat(dashboard): add admin/org routes and Redis sync"
```

---

### Task 6: Wire Up Main Server

**Covers:** [S2, S9]

**Files:**
- Modify: `dashboard/src/main.rs`

**Interfaces:**
- Consumes: Tasks 1-5 (all modules)
- Produces: Running Axum server on configured port

- [ ] **Step 1: Update main.rs**

Replace `dashboard/src/main.rs`:
```rust
mod auth;
mod config;
mod db;
mod middleware;
mod models;
mod redis_sync;
mod routes;

use axum::{middleware as axum_middleware, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, db::DbPool};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = Config::from_env()?;
    let pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&pool).await?;

    let state = (pool, config.clone());

    let api_routes = Router::new()
        .nest("/auth", routes::auth::auth_router())
        .nest("/admin", routes::admin::admin_router())
        .nest("/organizations", routes::organizations::org_router());

    let app = Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
```

- [ ] **Step 2: Verify build**

Run: `cargo build -p dashboard`
Expected: Compiles successfully (may warn about unused vars in placeholder files)

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/main.rs
git commit -m "feat(dashboard): wire up Axum server with routes and SPA fallback"
```

---

### Task 7: Svelte Frontend

**Covers:** [S8]

**Files:**
- Create: `dashboard/frontend/` (entire Svelte project)
- Create: `dashboard/static/` (build output)

**Interfaces:**
- Consumes: Task 6 (running backend API)
- Produces: Svelte SPA with login, signup, admin dashboard, customer dashboard

- [ ] **Step 1: Initialize Svelte project**

```bash
cd dashboard && npm create vite@latest frontend -- --template svelte
cd frontend && npm install
npm install svelte-spa-router
```

- [ ] **Step 2: Create TypeScript types**

Create `dashboard/frontend/src/lib/types.ts`:
```typescript
export interface User {
  id: string;
  email: string;
  role: 'admin' | 'customer';
  approved: boolean;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  config: Record<string, any>;
  created_at: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}
```

- [ ] **Step 3: Create API client**

Create `dashboard/frontend/src/lib/api.ts`:
```typescript
import { get } from 'svelte/store';
import { authStore } from './auth';

const BASE = '/api';

async function request(path: string, options: RequestInit = {}) {
  const { token } = get(authStore);
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || err.message || 'Request failed');
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  signup: (email: string, password: string) =>
    request('/auth/signup', { method: 'POST', body: JSON.stringify({ email, password }) }),

  login: (email: string, password: string) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),

  me: () => request('/auth/me'),

  admin: {
    listUsers: () => request('/admin/users'),
    approveUser: (id: string) => request(`/admin/users/${id}/approve`, { method: 'PUT' }),
    deleteUser: (id: string) => request(`/admin/users/${id}`, { method: 'DELETE' }),
    listOrgs: () => request('/admin/organizations'),
  },

  orgs: {
    list: () => request('/organizations'),
    create: (id: string, name: string, config: any) =>
      request('/organizations', { method: 'POST', body: JSON.stringify({ id, name, config }) }),
    update: (id: string, data: { name?: string; config?: any }) =>
      request(`/organizations/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
    delete: (id: string) => request(`/organizations/${id}`, { method: 'DELETE' }),
  },
};
```

- [ ] **Step 4: Create auth store**

Create `dashboard/frontend/src/lib/auth.ts`:
```typescript
import { writable } from 'svelte/store';
import type { User } from './types';

interface AuthState {
  token: string | null;
  user: User | null;
}

function createAuthStore() {
  const stored = typeof localStorage !== 'undefined'
    ? localStorage.getItem('auth')
    : null;
  const initial: AuthState = stored ? JSON.parse(stored) : { token: null, user: null };

  const { subscribe, set, update } = writable<AuthState>(initial);

  return {
    subscribe,
    login: (token: string, user: User) => {
      const state = { token, user };
      localStorage.setItem('auth', JSON.stringify(state));
      set(state);
    },
    logout: () => {
      localStorage.removeItem('auth');
      set({ token: null, user: null });
    },
  };
}

export const authStore = createAuthStore();
```

- [ ] **Step 5: Create Login page**

Create `dashboard/frontend/src/routes/Login.svelte`:
```svelte
<script lang="ts">
  import { push } from 'svelte-spa-router';
  import { api } from '../lib/api';
  import { authStore } from '../lib/auth';

  let email = '';
  let password = '';
  let error = '';
  let loading = false;

  async function handleLogin() {
    loading = true;
    error = '';
    try {
      const res = await api.login(email, password);
      authStore.login(res.token, res.user);
      push('/dashboard');
    } catch (e: any) {
      if (e.message.includes('403')) {
        error = 'Account not approved yet. Please wait for admin approval.';
      } else {
        error = e.message || 'Login failed';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="auth-container">
  <h1>Login</h1>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  <form on:submit|preventDefault={handleLogin}>
    <input type="email" bind:value={email} placeholder="Email" required />
    <input type="password" bind:value={password} placeholder="Password" required />
    <button type="submit" disabled={loading}>
      {loading ? 'Logging in...' : 'Login'}
    </button>
  </form>
  <p>Don't have an account? <a href="/signup">Sign up</a></p>
</div>

<style>
  .auth-container { max-width: 400px; margin: 80px auto; padding: 2rem; }
  .error { color: #e74c3c; margin-bottom: 1rem; padding: 0.5rem; background: #fdecea; border-radius: 4px; }
  input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
  button { width: 100%; padding: 0.75rem; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
  button:disabled { opacity: 0.6; }
  a { color: #3498db; }
</style>
```

- [ ] **Step 6: Create Signup page**

Create `dashboard/frontend/src/routes/Signup.svelte`:
```svelte
<script lang="ts">
  import { push } from 'svelte-spa-router';
  import { api } from '../lib/api';

  let email = '';
  let password = '';
  let error = '';
  let success = '';
  let loading = false;

  async function handleSignup() {
    loading = true;
    error = '';
    success = '';
    try {
      await api.signup(email, password);
      success = 'Account created! Waiting for admin approval.';
      setTimeout(() => push('/login'), 2000);
    } catch (e: any) {
      if (e.message.includes('409')) {
        error = 'Email already registered';
      } else {
        error = e.message || 'Signup failed';
      }
    } finally {
      loading = false;
    }
  }
</script>

<div class="auth-container">
  <h1>Sign Up</h1>
  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if success}
    <div class="success">{success}</div>
  {/if}
  <form on:submit|preventDefault={handleSignup}>
    <input type="email" bind:value={email} placeholder="Email" required />
    <input type="password" bind:value={password} placeholder="Password" required minlength="8" />
    <button type="submit" disabled={loading}>
      {loading ? 'Creating account...' : 'Sign Up'}
    </button>
  </form>
  <p>Already have an account? <a href="/login">Login</a></p>
</div>

<style>
  .auth-container { max-width: 400px; margin: 80px auto; padding: 2rem; }
  .error { color: #e74c3c; margin-bottom: 1rem; padding: 0.5rem; background: #fdecea; border-radius: 4px; }
  .success { color: #27ae60; margin-bottom: 1rem; padding: 0.5rem; background: #eafaf1; border-radius: 4px; }
  input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; }
  button { width: 100%; padding: 0.75rem; background: #27ae60; color: white; border: none; border-radius: 4px; cursor: pointer; }
  button:disabled { opacity: 0.6; }
  a { color: #3498db; }
</style>
```

- [ ] **Step 7: Create Dashboard page**

Create `dashboard/frontend/src/routes/Dashboard.svelte`:
```svelte
<script lang="ts">
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { authStore } from '../lib/auth';
  import { api } from '../lib/api';
  import type { User, Organization } from '../lib/types';

  let user: User | null = null;
  let users: User[] = [];
  let orgs: Organization[] = [];
  let loading = true;
  let error = '';

  // New org form
  let newOrgId = '';
  let newOrgName = '';
  let newOrgConfig = '{}';

  // Edit form
  let editingOrg: Organization | null = null;
  let editName = '';
  let editConfig = '';

  onMount(async () => {
    const unsub = authStore.subscribe(v => user = v.user);
    if (!user) { push('/login'); return; }
    await loadData();
    return unsub;
  });

  async function loadData() {
    loading = true;
    try {
      if (user?.role === 'admin') {
        const [usersRes, orgsRes] = await Promise.all([
          api.admin.listUsers(),
          api.admin.listOrgs(),
        ]);
        users = usersRes.users;
        orgs = orgsRes.organizations;
      } else {
        const res = await api.orgs.list();
        orgs = res.organizations;
      }
    } catch (e: any) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function approveUser(id: string) {
    await api.admin.approveUser(id);
    await loadData();
  }

  async function deleteUser(id: string) {
    if (!confirm('Delete this user?')) return;
    await api.admin.deleteUser(id);
    await loadData();
  }

  async function createOrg() {
    try {
      await api.orgs.create(newOrgId, newOrgName, JSON.parse(newOrgConfig));
      newOrgId = ''; newOrgName = ''; newOrgConfig = '{}';
      await loadData();
    } catch (e: any) {
      alert(e.message);
    }
  }

  function startEdit(org: Organization) {
    editingOrg = org;
    editName = org.name;
    editConfig = JSON.stringify(org.config, null, 2);
  }

  async function saveEdit() {
    if (!editingOrg) return;
    try {
      await api.orgs.update(editingOrg.id, {
        name: editName,
        config: JSON.parse(editConfig),
      });
      editingOrg = null;
      await loadData();
    } catch (e: any) {
      alert(e.message);
    }
  }

  async function deleteOrg(id: string) {
    if (!confirm('Delete this organization?')) return;
    await api.orgs.delete(id);
    await loadData();
  }

  function logout() {
    authStore.logout();
    push('/login');
  }
</script>

<div class="dashboard">
  <header>
    <h1>QuicGuard Dashboard</h1>
    <div>
      <span>{user?.email} ({user?.role})</span>
      <button on:click={logout}>Logout</button>
    </div>
  </header>

  {#if loading}
    <p>Loading...</p>
  {:else if error}
    <p class="error">{error}</p>
  {:else}
    {#if user?.role === 'admin'}
      <section>
        <h2>Users</h2>
        <table>
          <thead><tr><th>Email</th><th>Role</th><th>Approved</th><th>Actions</th></tr></thead>
          <tbody>
            {#each users as u}
              <tr>
                <td>{u.email}</td>
                <td>{u.role}</td>
                <td>{u.approved ? 'Yes' : 'No'}</td>
                <td>
                  {#if !u.approved}
                    <button on:click={() => approveUser(u.id)}>Approve</button>
                  {/if}
                  <button on:click={() => deleteUser(u.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}

    <section>
      <h2>Organizations</h2>
      <form on:submit|preventDefault={createOrg} class="org-form">
        <input bind:value={newOrgId} placeholder="Org ID" required />
        <input bind:value={newOrgName} placeholder="Name" required />
        <textarea bind:value={newOrgConfig} placeholder="Config (JSON)"></textarea>
        <button type="submit">Add Organization</button>
      </form>

      {#if editingOrg}
        <div class="edit-modal">
          <h3>Edit: {editingOrg.id}</h3>
          <input bind:value={editName} placeholder="Name" />
          <textarea bind:value={editConfig} rows="10"></textarea>
          <button on:click={saveEdit}>Save</button>
          <button on:click={() => editingOrg = null}>Cancel</button>
        </div>
      {/if}

      <table>
        <thead><tr><th>ID</th><th>Name</th><th>Actions</th></tr></thead>
        <tbody>
          {#each orgs as org}
            <tr>
              <td>{org.id}</td>
              <td>{org.name}</td>
              <td>
                <button on:click={() => startEdit(org)}>Edit</button>
                <button on:click={() => deleteOrg(org.id)}>Delete</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>
  {/if}
</div>

<style>
  .dashboard { max-width: 1000px; margin: 0 auto; padding: 2rem; }
  header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
  header div { display: flex; gap: 1rem; align-items: center; }
  section { margin-bottom: 2rem; }
  .error { color: #e74c3c; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { padding: 0.75rem; border-bottom: 1px solid #ddd; text-align: left; }
  th { background: #f5f5f5; }
  button { padding: 0.4rem 0.8rem; border: none; border-radius: 4px; cursor: pointer; }
  button:first-child { background: #3498db; color: white; }
  .org-form { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }
  .org-form input, .org-form textarea { padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
  .edit-modal { background: #f9f9f9; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }
  .edit-modal textarea { width: 100%; }
</style>
```

- [ ] **Step 8: Create App.svelte**

Replace `dashboard/frontend/src/App.svelte`:
```svelte
<script lang="ts">
  import Router from 'svelte-spa-router';
  import Login from './routes/Login.svelte';
  import Signup from './routes/Signup.svelte';
  import Dashboard from './routes/Dashboard.svelte';

  const routes = {
    '/login': Login,
    '/signup': Signup,
    '/dashboard': Dashboard,
    '*': Login,
  };
</script>

<Router {routes} />
```

- [ ] **Step 9: Configure Vite for SPA**

Replace `dashboard/frontend/vite.config.ts`:
```typescript
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:3000',
    },
  },
});
```

- [ ] **Step 10: Build frontend**

```bash
cd dashboard/frontend && npm run build
```

Expected: Output in `dashboard/static/`

- [ ] **Step 11: Commit**

```bash
git add dashboard/frontend/ dashboard/static/
git commit -m "feat(dashboard): add Svelte frontend with auth, admin, and org management"
```

---

### Task 8: Docker Compose and Setup Script

**Covers:** [S9]

**Files:**
- Modify: `services/services.yaml`
- Create: `dashboard/scripts/setup.sh`

**Interfaces:**
- Consumes: Tasks 1-7 (complete backend + frontend)
- Produces: Updated Docker Compose with Postgres, setup script

- [ ] **Step 1: Update Docker Compose**

Replace `services/services.yaml`:
```yaml
version: "3.9"

services:
  redis:
    image: redis:7.2-alpine
    restart: unless-stopped
    command: redis-server --include /usr/local/etc/redis/redis.conf
    hostname: redis
    user: root
    environment:
      - REDIS_PASSWORD=123456
    ports:
      - "6379:6379"
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: "512M"
    volumes:
      - ./redis.conf:/usr/local/etc/redis/redis.conf
      - redis-data:/data

  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: quicguard
      POSTGRES_USER: quicguard
      POSTGRES_PASSWORD: quicguard
    ports:
      - "5432:5432"
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: "512M"
    volumes:
      - ./pgdata:/var/lib/postgresql/data

volumes:
  redis-data:
    driver: local
```

- [ ] **Step 2: Create setup script**

Create `dashboard/scripts/setup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$DASHBOARD_DIR")"

echo "=== QuicGuard Dashboard Setup ==="

# Check prerequisites
command -v cargo >/dev/null 2>&1 || { echo "Error: cargo not found. Install Rust."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Error: docker not found."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm not found. Install Node.js."; exit 1; }

# Start services
echo "Starting Postgres and Redis..."
cd "$ROOT_DIR/services"
docker compose up -d
echo "Waiting for Postgres..."
sleep 3

# Copy .env if not exists
if [ ! -f "$DASHBOARD_DIR/.env" ]; then
    echo "Creating .env from .env.example..."
    cp "$DASHBOARD_DIR/.env.example" "$DASHBOARD_DIR/.env"
    echo "Please edit $DASHBOARD_DIR/.env with your settings."
fi

# Run migrations
echo "Running database migrations..."
cd "$DASHBOARD_DIR"
source .env
export DATABASE_URL
cargo run -- run-migrations 2>/dev/null || true

# Create initial admin
echo "Creating initial admin user..."
cargo run -- create-admin admin@quicguard.local admin123 2>/dev/null || echo "(Admin user may already exist)"

# Build frontend
echo "Building frontend..."
cd "$DASHBOARD_DIR/frontend"
npm install
npm run build

echo ""
echo "=== Setup Complete ==="
echo "Start the dashboard: cd $DASHBOARD_DIR && cargo run"
echo "Dashboard will be at: http://localhost:${SERVER_PORT:-3000}"
```

```bash
chmod +x dashboard/scripts/setup.sh
```

- [ ] **Step 3: Add CLI commands to main.rs**

Update `dashboard/src/main.rs` to add run-migrations and create-admin subcommands:
```rust
mod auth;
mod config;
mod db;
mod middleware;
mod models;
mod redis_sync;
mod routes;

use axum::{Router, middleware as axum_middleware};
use clap::{Parser, Subcommand};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, db::DbPool};

#[derive(Parser)]
#[command(name = "dashboard", about = "QuicGuard Dashboard")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    RunMigrations,
    CreateAdmin {
        email: String,
        password: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = Config::from_env()?;
    let pool = db::create_pool(&config.database_url).await?;

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::RunMigrations) => {
            db::run_migrations(&pool).await?;
            println!("Migrations applied successfully");
            return Ok(());
        }
        Some(Commands::CreateAdmin { email, password }) => {
            let hash = auth::hash_password(&password)?;
            let existing = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)",
            )
            .bind(&email)
            .fetch_one(&pool)
            .await?;

            if existing {
                println!("User {} already exists", email);
                return Ok(());
            }

            sqlx::query("INSERT INTO users (email, password_hash, role, approved) VALUES ($1, $2, 'admin', true)")
                .bind(&email)
                .bind(&hash)
                .execute(&pool)
                .await?;
            println!("Admin user '{}' created", email);
            return Ok(());
        }
        None => {}
    }

    db::run_migrations(&pool).await?;

    let state = (pool, config.clone());

    let api_routes = Router::new()
        .nest("/auth", routes::auth::auth_router())
        .nest("/admin", routes::admin::admin_router())
        .nest("/organizations", routes::organizations::org_router());

    let app = Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("static").append_index_html_on_directories(true))
        .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
```

- [ ] **Step 4: Commit**

```bash
git add services/services.yaml dashboard/scripts/ dashboard/src/main.rs
git commit -m "feat(dashboard): add Postgres to Docker Compose and setup script"
```

---

### Task 9: Final Verification

**Covers:** [S1-S12]

**Files:**
- Verify: all created files

**Interfaces:**
- Consumes: Tasks 1-8

- [ ] **Step 1: Build the dashboard**

Run: `cargo build -p dashboard`
Expected: Compiles successfully

- [ ] **Step 2: Start services**

```bash
cd services && docker compose up -d
```

- [ ] **Step 3: Start dashboard**

```bash
cd dashboard && cargo run
```

Expected: Server starts on port 3000

- [ ] **Step 4: Test API endpoints**

```bash
# Signup
curl -X POST http://localhost:3000/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Login (should fail - not approved yet)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# Create admin via CLI
cargo run -- create-admin admin@test.com admin123

# Login as admin
ADMIN_TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"admin123"}' | jq -r '.token')

# Approve user
USER_ID=$(curl -s http://localhost:3000/api/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.users[0].id')
curl -X PUT "http://localhost:3000/api/admin/users/$USER_ID/approve" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

- [ ] **Step 5: Verify Redis sync**

```bash
docker compose exec redis redis-cli HGETALL quicguard:organizations
```

- [ ] **Step 6: Stop services**

```bash
cd services && docker compose down
```

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "feat(dashboard): complete management dashboard with auth, RBAC, and Redis sync"
```
