// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

//! Bus reaper — the self-draining loop for the retry and delayed queues
//! (bus `DESIGN.md` §4.3, §10).
//!
//! Two sorted sets per env carry deferred work:
//! - `bus:retry:{env}` — nacked messages waiting for their `retry_at`
//!   score. The reaper re-XADDs due entries to their source stream and
//!   ZREMs them; entries whose `retry_count` has exhausted `MAX_RETRIES`
//!   land in `bus:dlq:{env}` instead (manual replay stays the recovery
//!   path — the reaper never replays from the DLQ).
//! - `bus:delayed:{env}` — scheduled messages waiting for `delivery_at`.
//!   Due entries are XADDed to their target stream with the stored
//!   event_type/payload and removed.
//!
//! Every mutation is bounded and idempotent: an XADD that succeeds before
//! a ZREM failure re-delivers at-least-once (consumers dedupe on the
//! message's `idempotency_key`, principles §6.7); the poll interval keeps
//! a wedged pass from starving the produce path.

use crate::handlers::AppState;
use std::sync::Arc;

/// Retry cap before a nacked message is routed to the DLQ.
pub const MAX_RETRIES: u32 = 5;

/// Poll cadence (seconds) — the safety poll alongside consumer-driven
/// wake-ups.
const POLL_INTERVAL_SECS: u64 = 10;

/// Spawn the reaper loop.
pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
            if let Err(e) = drain_retry(&state).await {
                tracing::warn!(error = %e, "bus reaper: retry drain pass failed");
            }
            if let Err(e) = drain_delayed(&state).await {
                tracing::warn!(error = %e, "bus reaper: delayed drain pass failed");
            }
        }
    });
}

/// Drain due retries: re-XADD to the source stream, or move exhausted
/// entries to the DLQ. Bounded per pass (`RETRY_BATCH`) so a huge backlog
/// drains steadily without monopolizing the connection.
async fn drain_retry(state: &AppState) -> Result<(), String> {
    const RETRY_BATCH: usize = 100;
    let now = chrono::Utc::now().timestamp();

    // Discover env keys via SCAN (KEYS would block Valkey under load).
    let mut envs = Vec::new();
    let mut cursor = String::from("0");
    loop {
        let (next, keys): (String, Vec<String>) = glide::cmd("SCAN")
            .arg(&cursor)
            .arg("MATCH")
            .arg("bus:retry:*")
            .arg("COUNT")
            .arg(100)
            .query_async(&state.valkey.clone())
            .await
            .map_err(|e| e.to_string())?;
        envs.extend(keys.iter().filter_map(|k| {
            k.rsplit(':')
                .next()
                .and_then(|e| uuid::Uuid::parse_str(e).ok())
        }));
        cursor = next;
        if cursor == "0" || envs.len() > 64 {
            break;
        }
    }

    for env_id in envs {
        let retry_key = format!("bus:retry:{env_id}");
        let dlq_key = format!("bus:dlq:{env_id}");
        let entries: Vec<String> = glide::cmd("ZRANGEBYSCORE")
            .arg(&retry_key)
            .arg(0)
            .arg(now)
            .arg("LIMIT")
            .arg(0)
            .arg(RETRY_BATCH)
            .query_async(&state.valkey.clone())
            .await
            .map_err(|e| e.to_string())?;
        for entry in entries {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&entry) else {
                let _: i64 = glide::cmd("ZREM")
                    .arg(&retry_key)
                    .arg(&entry)
                    .query_async(&state.valkey.clone())
                    .await
                    .unwrap_or(0);
                continue;
            };
            let message_id = v
                .get("message_id")
                .and_then(|m| m.as_str())
                .unwrap_or_default()
                .to_string();
            let stream = v
                .get("stream")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            let group = v
                .get("group")
                .and_then(|g| g.as_str())
                .unwrap_or_default()
                .to_string();
            let retry_count = v.get("retry_count").and_then(|c| c.as_u64()).unwrap_or(0) as u32;
            let max_retries = v
                .get("max_retries")
                .and_then(|c| c.as_u64())
                .map(|c| c as u32)
                .unwrap_or(MAX_RETRIES);

            if retry_count + 1 >= max_retries {
                // Exhausted → DLQ (manual replay, bus DESIGN §10).
                let mut dlq_entry = v.clone();
                dlq_entry["reason"] = serde_json::json!("max retries exhausted");
                let _: i64 = glide::cmd("ZADD")
                    .arg(&dlq_key)
                    .arg(now)
                    .arg(dlq_entry.to_string())
                    .query_async(&state.valkey.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                let _: i64 = glide::cmd("ZREM")
                    .arg(&retry_key)
                    .arg(&entry)
                    .query_async(&state.valkey.clone())
                    .await
                    .unwrap_or(0);
                tracing::warn!(message_id = %message_id, env_id = %env_id, "bus reaper: message moved to DLQ (max retries)");
                continue;
            }

            // Re-XADD to the source stream for the waiting consumer group.
            // The consumer redelivers via XAUTOCLAIM/XREADGROUP on `group`.
            let mut xadd = glide::cmd("XADD");
            xadd.arg(&stream).arg("*");
            xadd.arg("event_type").arg(
                v.get("event_type")
                    .and_then(|e| e.as_str())
                    .unwrap_or("bus.retry"),
            );
            xadd.arg("payload").arg(
                v.get("payload")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
                    .to_string(),
            );
            xadd.arg("env_id").arg(env_id.to_string());
            xadd.arg("created_at").arg(now);
            xadd.arg("retry_of").arg(&message_id);
            xadd.arg("retry_count").arg(retry_count + 1);
            xadd.arg("consumer_group").arg(&group);
            let _: Result<String, _> = xadd
                .query_async(&state.valkey.clone())
                .await
                .map_err(|e| e.to_string());
            let _: i64 = glide::cmd("ZREM")
                .arg(&retry_key)
                .arg(&entry)
                .query_async(&state.valkey.clone())
                .await
                .unwrap_or(0);
        }
    }
    Ok(())
}

/// Drain due delayed messages: XADD to the target stream with the stored
/// event_type/payload, then ZREM.
async fn drain_delayed(state: &AppState) -> Result<(), String> {
    const DELAYED_BATCH: usize = 100;
    let now = chrono::Utc::now().timestamp();

    let mut envs = Vec::new();
    let mut cursor = String::from("0");
    loop {
        let (next, keys): (String, Vec<String>) = glide::cmd("SCAN")
            .arg(&cursor)
            .arg("MATCH")
            .arg("bus:delayed:*")
            .arg("COUNT")
            .arg(100)
            .query_async(&state.valkey.clone())
            .await
            .map_err(|e| e.to_string())?;
        envs.extend(keys.iter().filter_map(|k| {
            k.rsplit(':')
                .next()
                .and_then(|e| uuid::Uuid::parse_str(e).ok())
        }));
        cursor = next;
        if cursor == "0" || envs.len() > 64 {
            break;
        }
    }

    for env_id in envs {
        let delayed_key = format!("bus:delayed:{env_id}");
        let entries: Vec<String> = glide::cmd("ZRANGEBYSCORE")
            .arg(&delayed_key)
            .arg(0)
            .arg(now)
            .arg("LIMIT")
            .arg(0)
            .arg(DELAYED_BATCH)
            .query_async(&state.valkey.clone())
            .await
            .map_err(|e| e.to_string())?;
        for entry in entries {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&entry) else {
                let _: i64 = glide::cmd("ZREM")
                    .arg(&delayed_key)
                    .arg(&entry)
                    .query_async(&state.valkey.clone())
                    .await
                    .unwrap_or(0);
                continue;
            };
            let family = v
                .get("stream_family")
                .and_then(|f| f.as_str())
                .unwrap_or_default()
                .to_string();
            if family.is_empty() {
                let _: i64 = glide::cmd("ZREM")
                    .arg(&delayed_key)
                    .arg(&entry)
                    .query_async(&state.valkey.clone())
                    .await
                    .unwrap_or(0);
                continue;
            }
            let stream = crate::handlers::stream_key(&env_id.to_string(), &family);
            let event_type = v
                .get("event_type")
                .and_then(|e| e.as_str())
                .unwrap_or("bus.scheduled")
                .to_string();
            let payload = v.get("payload").cloned().unwrap_or(serde_json::Value::Null);
            let _: String = glide::cmd("XADD")
                .arg(&stream)
                .arg("*")
                .arg("event_type")
                .arg(&event_type)
                .arg("payload")
                .arg(payload.to_string())
                .arg("env_id")
                .arg(env_id.to_string())
                .arg("created_at")
                .arg(v.get("created_at").and_then(|c| c.as_i64()).unwrap_or(now))
                .arg("scheduled_message_id")
                .arg(v.get("message_id").and_then(|m| m.as_str()).unwrap_or(""))
                .query_async(&state.valkey.clone())
                .await
                .map_err(|e| e.to_string())?;
            let _: i64 = glide::cmd("ZREM")
                .arg(&delayed_key)
                .arg(&entry)
                .query_async(&state.valkey.clone())
                .await
                .unwrap_or(0);
        }
    }
    Ok(())
}
