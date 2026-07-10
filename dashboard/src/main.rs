use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use dashboard::auth;
use dashboard::config;
use dashboard::db;
use dashboard::middleware;
use dashboard::routes;

#[derive(Parser)]
#[command(name = "dashboard", about = "QuicGuard Dashboard")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to static files directory (SPA frontend)
    #[arg(long, default_value = None)]
    static_dir: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    RunMigrations,
    CreateAdmin {
        email: String,
        password: String,
    },
}

/// Resolve the static directory path:
/// 1. --static-dir CLI flag
/// 2. STATIC_DIR env var
/// 3. ./static relative to CWD
/// 4. ../static relative to binary (for cargo run from project root)
fn resolve_static_dir(cli_path: Option<String>) -> PathBuf {
    // 1. CLI flag
    if let Some(p) = cli_path {
        return PathBuf::from(p);
    }

    // 2. Env var
    if let Ok(p) = std::env::var("STATIC_DIR") {
        return PathBuf::from(p);
    }

    // 3. Relative to CWD
    let cwd_static = PathBuf::from("static");
    if cwd_static.exists() {
        return cwd_static;
    }

    // 4. Relative to binary location (handles `cargo run -p dashboard` from project root)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Binary at target/debug/dashboard -> try ../dashboard/static
            let from_exe = exe_dir.join("..").join("dashboard").join("static");
            if from_exe.exists() {
                return from_exe;
            }
            // Binary at target/debug/dashboard -> try ../../dashboard/static
            let from_exe2 = exe_dir.join("..").join("..").join("dashboard").join("static");
            if from_exe2.exists() {
                return from_exe2;
            }
        }
    }

    // 5. Fallback — use CARGO_MANIFEST_DIR at compile time (only works when building from dashboard/)
    let manifest_static = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");
    if manifest_static.exists() {
        return manifest_static;
    }

    // 6. Last resort
    cwd_static
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,dashboard=debug")),
        )
        .init();

    let cli = Cli::parse();
    let config = config::Config::from_env()?;
    let pool = db::create_pool(&config.database_url).await?;

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

    let static_dir = resolve_static_dir(cli.static_dir);
    tracing::info!(path = %static_dir.display(), "Static files directory");

    if !static_dir.exists() {
        tracing::warn!(path = %static_dir.display(),
            "Static directory does not exist — SPA frontend will not be served");
    }

    let state = (pool.clone(), config.clone());

    let admin_routes = routes::admin::admin_router()
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::admin_only));
    let org_routes = routes::organizations::org_router()
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));
    let protected_auth = routes::auth::protected_auth_router()
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));

    let api_routes = axum::Router::new()
        .nest("/auth", routes::auth::auth_router())
        .nest("/auth", protected_auth)
        .nest("/admin", admin_routes)
        .nest("/organizations", org_routes);

    let app = axum::Router::new()
        .nest("/api", api_routes)
        .fallback_service(
            tower_http::services::ServeDir::new(&static_dir)
                .append_index_html_on_directories(true),
        )
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        )
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config.server_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Dashboard server listening on {}", addr);
    tracing::info!("Dashboard URL: http://localhost:{}", config.server_port);
    axum::serve(listener, app).await?;

    Ok(())
}
