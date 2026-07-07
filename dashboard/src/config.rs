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
