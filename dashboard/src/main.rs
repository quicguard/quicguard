use clap::{Parser, Subcommand};
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

    let config = config::Config::from_env()?;
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

    let state = (pool.clone(), config.clone());

    let admin_routes = routes::admin::admin_router()
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::admin_only));
    let org_routes = routes::organizations::org_router()
        .layer(axum::middleware::from_fn_with_state(state.clone(), middleware::auth_middleware));

    let api_routes = axum::Router::new()
        .nest("/auth", routes::auth::auth_router())
        .nest("/admin", admin_routes)
        .nest("/organizations", org_routes);

    let app = axum::Router::new()
        .nest("/api", api_routes)
        .fallback_service(tower_http::services::ServeDir::new("static").append_index_html_on_directories(true))
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
    axum::serve(listener, app).await?;

    Ok(())
}
