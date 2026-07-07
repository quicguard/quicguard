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

pub async fn sync_org_to_redis(config: &Config, org: &Organization) -> Result<()> {
    tracing::debug!(org_id = %org.id, "Connecting to Redis for org sync");
    let client = redis::Client::open(config.redis_url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    tracing::debug!(org_id = %org.id, "Redis connection established");

    let json = serde_json::to_string(&org.config)?;
    tracing::debug!(org_id = %org.id, redis_key = %config.redis_org_key, json_len = json.len(),
        "HSET org config to Redis");
    let _: () = conn.hset(&config.redis_org_key, &org.id, &json).await?;
    tracing::debug!(org_id = %org.id, "HSET complete");

    let update = OrgUpdate {
        org_id: org.id.clone(),
        action: "update".to_string(),
        organization: Some(org.config.clone()),
    };
    let update_json = serde_json::to_string(&update)?;
    tracing::debug!(org_id = %org.id, channel = %config.redis_pubsub_channel,
        "PUBLISH org update to Redis pubsub");
    let _: () = conn.publish(&config.redis_pubsub_channel, &update_json).await?;
    tracing::debug!(org_id = %org.id, "PUBLISH complete");

    Ok(())
}

pub async fn remove_org_from_redis(config: &Config, org_id: &str) -> Result<()> {
    tracing::debug!(org_id = org_id, "Connecting to Redis for org removal");
    let client = redis::Client::open(config.redis_url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;
    tracing::debug!(org_id = org_id, "Redis connection established");

    tracing::debug!(org_id = org_id, redis_key = %config.redis_org_key,
        "HDEL org from Redis");
    let _: () = conn.hdel(&config.redis_org_key, org_id).await?;
    tracing::debug!(org_id = org_id, "HDEL complete");

    let update = OrgUpdate {
        org_id: org_id.to_string(),
        action: "delete".to_string(),
        organization: None,
    };
    let update_json = serde_json::to_string(&update)?;
    tracing::debug!(org_id = org_id, channel = %config.redis_pubsub_channel,
        "PUBLISH delete notification to Redis pubsub");
    let _: () = conn.publish(&config.redis_pubsub_channel, &update_json).await?;
    tracing::debug!(org_id = org_id, "PUBLISH complete");

    Ok(())
}
