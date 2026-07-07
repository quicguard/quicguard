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

pub async fn remove_org_from_redis(config: &Config, org_id: &str) -> Result<()> {
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
