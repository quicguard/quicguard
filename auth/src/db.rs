use std::collections::HashMap;

use anyhow::{Context, Result};
use konfig::Organization;
use redis::AsyncCommands;
use tracing::debug;

#[derive(Clone)]
pub struct Database {
    redis_client: redis::Client,
    org_key: String,
}

impl Database {
    pub fn new(redis_url: &str, org_key: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .context("Failed to create Redis client")?;
        Ok(Self {
            redis_client: client,
            org_key: org_key.to_string(),
        })
    }

    /// Store OTP with expiry
    pub async fn store_otp(&self, email: &str, otp: &str, expiry_seconds: u64) -> Result<()> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await
            .context("Failed to get Redis connection")?;
        
        let key = format!("otp:{}", email);
        let _: () = conn.set_ex(&key, otp, expiry_seconds).await
            .context("Failed to store OTP")?;
        
        debug!("Stored OTP for email: {}", email);
        Ok(())
    }

    /// Verify and consume OTP (one-time use)
    pub async fn verify_otp(&self, email: &str, otp: &str) -> Result<bool> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await
            .context("Failed to get Redis connection")?;
        
        let key = format!("otp:{}", email);
        
        // Get the stored OTP
        let stored_otp: Option<String> = conn.get(&key).await
            .context("Failed to get OTP")?;
        
        match stored_otp {
            Some(stored) if stored == otp => {
                // Delete OTP after successful verification (one-time use)
                let _: () = conn.del(&key).await
                    .context("Failed to delete OTP")?;
                debug!("OTP verified for email: {}", email);
                Ok(true)
            }
            _ => {
                debug!("OTP verification failed for email: {}", email);
                Ok(false)
            }
        }
    }

    /// Look up organization by domain
    pub async fn lookup_org(&self, domain: &str) -> Result<Option<Organization>> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await
            .context("Failed to get Redis connection")?;
        
        let raw: HashMap<String, String> = conn.hgetall(&self.org_key).await
            .context("Failed to get organizations")?;
        
        for (id, json) in &raw {
            if let Ok(org) = serde_json::from_str::<Organization>(json) {
                if org.domains.contains_key(domain) {
                    debug!("Found org {} for domain {}", id, domain);
                    return Ok(Some(org));
                }
            }
        }
        
        debug!("No org found for domain: {}", domain);
        Ok(None)
    }

    /// Get organization by ID
    pub async fn get_org(&self, org_id: &str) -> Result<Option<Organization>> {
        let mut conn = self.redis_client.get_multiplexed_async_connection().await
            .context("Failed to get Redis connection")?;
        
        let raw: Option<String> = conn.hget(&self.org_key, org_id).await
            .context("Failed to get organization")?;
        
        match raw {
            Some(json) => {
                let org: Organization = serde_json::from_str(&json)
                    .context("Failed to parse organization")?;
                Ok(Some(org))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        // Test that Database can be created (won't connect without Redis)
        let result = Database::new("redis://127.0.0.1:6379", "test:orgs");
        assert!(result.is_ok());
    }
}
