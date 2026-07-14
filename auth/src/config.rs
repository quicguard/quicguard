use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: Option<String>,
    pub redis_url: String,
    pub redis_org_key: String,
    pub server_port: u16,
    pub otp_expiry_seconds: u64,
    pub jwt_expiry_hours: i64,
    pub email_api_url: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        Ok(Self {
            database_url: std::env::var("DATABASE_URL").ok(),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            redis_org_key: std::env::var("REDIS_ORG_KEY")
                .unwrap_or_else(|_| "quicguard:organizations".to_string()),
            server_port: std::env::var("AUTH_SERVER_PORT")
                .unwrap_or_else(|_| "3001".to_string())
                .parse()?,
            otp_expiry_seconds: 300,
            jwt_expiry_hours: 24,
            email_api_url: std::env::var("EMAIL_API_URL").ok(),
        })
    }
}
