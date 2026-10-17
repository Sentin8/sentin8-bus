// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use sqlx::Row;
use tokio::time::{timeout, Instant};

/// Spawn it.
pub fn spawn(pool: sqlx::PgPool, valkey: glide::GlideClient, listener_dsn: String) {
    tokio::spawn(async move {
        run(pool, valkey, listener_dsn).await;
    });
}

async fn run(pool: sqlx::PgPool, valkey: glide::GlideClient, listener_dsn: String) {
    tracing::info!("bus inbox relay started (LISTEN/NOTIFY + safety poll)");

    let batch_size: i64 = 1000;
    let safety_poll = Duration::from_secs(2);

    // The LISTEN connection is a dedicated 1-connection pool built from
    // the same certificate-presenting options as the service pool
    // (DESIGN §2, BUSLISTEN-1): `PgListener::connect` on the raw DSN
    // would present no client certificate and be refused by the
    // TLS-only cert-auth plane, silently degrading the relay to
    // poll-only at every boot.
    let listener_pool = match sentin8::config::pg_pool::connect_options_for(&listener_dsn) {
        Ok(opts) => match sqlx::pool::PoolOptions::default()
            .max_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .connect_with(opts)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to connect the LISTEN pool — falling back to poll-only");
                run_poll_only(pool, valkey, safety_poll, batch_size).await;
                return;
            }
        },
        Err(e) => {
            tracing::error!(error = %e, "invalid listener DSN (certificate identity) — falling back to poll-only");
            run_poll_only(pool, valkey, safety_poll, batch_size).await;
            return;
        }
    };
    let conn_str = listener_dsn.clone();
    let mut listener = match sqlx::postgres::PgListener::connect_with(&listener_pool).await {
        Ok(l) => {
            tracing::info!("bus inbox relay LISTEN on bus_inbox_changed");
            l
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to start PgListener — falling back to poll-only");
            run_poll_only(pool, valkey, safety_poll, batch_size).await;
            return;
        }
    };

    if let Err(e) = listener.listen("bus_inbox_changed").await {
        tracing::error!(error = %e, "failed to LISTEN on bus_inbox_changed — falling back to poll-only");
        run_poll_only(pool, valkey, safety_poll, batch_size).await;
        return;
    }

    loop {
        match drain(&pool, &valkey, batch_size).await {
            Ok(n) if n > 0 => {
                tracing::info!(drained = n, "bus inbox relay startup drain");
            }
            Ok(_) => break,
            Err(e) => {
                tracing::error!(error = %e, "bus inbox relay startup drain error");
                break;
            }
        }
    }

    let mut next_poll = Instant::now() + safety_poll;

    loop {
        let remaining = next_poll.saturating_duration_since(Instant::now());

        let notified = match timeout(remaining, listener.recv()).await {
            Ok(Ok(notification)) => {
                tracing::debug!(payload = %notification.payload(), "bus inbox NOTIFY received");
                true
            }
            Ok(Err(e)) => {
                tracing::error!(error = %e, "PgListener error — will reconnect");
                tokio::time::sleep(Duration::from_secs(1)).await;
                let reconnected: Result<sqlx::postgres::PgListener, sqlx::Error> = async {
                    let opts = sentin8::config::pg_pool::connect_options_for(&conn_str)?;
                    let pool = sqlx::pool::PoolOptions::default()
                        .max_connections(1)
                        .max_lifetime(None)
                        .idle_timeout(None)
                        .connect_with(opts)
                        .await?;
                    sqlx::postgres::PgListener::connect_with(&pool).await
                }
                .await;
                match reconnected {
                    Ok(new_listener) => {
                        listener = new_listener;
                        let _ = listener.listen("bus_inbox_changed").await;
                    }
                    Err(e2) => {
                        tracing::error!(error = %e2, "PgListener reconnect failed — continuing with poll-only");
                    }
                }
                false
            }
            Err(_) => true, // timeout elapsed — time for the safety poll
        };

        loop {
            match drain(&pool, &valkey, batch_size).await {
                Ok(n) => {
                    if n > 0 {
                        tracing::debug!(drained = n, "bus inbox relay drained batch");
                    }
                    if n < batch_size as usize {
                        break; // No more rows to drain
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "bus inbox relay drain error");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    break;
                }
            }
        }

        next_poll = Instant::now() + safety_poll;
        let _ = notified; // suppress unused warning
    }
}

async fn run_poll_only(
    pool: sqlx::PgPool,
    valkey: glide::GlideClient,
    poll_interval: Duration,
    batch_size: i64,
) {
    tracing::warn!("bus inbox relay running in poll-only mode (no LISTEN/NOTIFY)");
    loop {
        match drain(&pool, &valkey, batch_size).await {
            Ok(n) => {
                if n == 0 {
                    tokio::time::sleep(poll_interval).await;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "bus inbox relay error");
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

async fn drain(
    pool: &sqlx::PgPool,
    valkey: &glide::GlideClient,
    batch_size: i64,
) -> Result<usize, sqlx::Error> {
    // Single-entry delivery (bus design §4.3b): rows whose inline XADD
    // succeeded carry a `stream_message_id` and are excluded by the SELECT
    // below; they only need a relayed-mark. Mark them here so the unrelayed
    // index does not grow unbounded.
    if let Err(e) = sqlx::query(
        r#"WITH stamped AS (
            UPDATE inbox SET relayed = true, relayed_at = now()
            WHERE relayed = false AND stream_message_id IS NOT NULL
            RETURNING 1
        ) SELECT count(*) FROM stamped"#,
    )
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "inbox relay: stamped-row mark failed");
    }

    let envs: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT env_id FROM public.sentin8_outbox_unrelayed_envs('bus')",
    )
    .fetch_all(pool)
    .await?;
    let mut rows: Vec<sqlx::postgres::PgRow> = Vec::new();
    for env_id in envs {
        let mut tx = pool.begin().await?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(env_id)
            .execute(&mut *tx)
            .await;
        let mut batch = sqlx::query(
            r#"SELECT id, env_id, event_type, stream_family, payload,
                      publisher_id_token, publisher_subject, publisher_vertical
               FROM inbox
               WHERE relayed = false
                 AND stream_message_id IS NULL
               ORDER BY created_at
               LIMIT $1"#,
        )
        .bind(batch_size)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.append(&mut batch);
        if rows.len() >= batch_size as usize {
            break;
        }
    }
    let count = rows.len();
    for row in rows {
        let id: uuid::Uuid = row.get("id");
        let env_id: uuid::Uuid = row.get("env_id");
        let event_type: String = row.get("event_type");
        let stream_family: String = row.get("stream_family");
        let payload: serde_json::Value = row.get("payload");
        let publisher_id_token: Option<String> = row.get("publisher_id_token");
        let publisher_subject: Option<String> = row.get("publisher_subject");
        let publisher_vertical: Option<String> = row.get("publisher_vertical");

        let stream = format!("bus:{env_id}:{stream_family}");

        let conn = valkey.clone();
        let mut xadd = glide::cmd("XADD");
        xadd.arg(&stream)
            .arg("*")
            .arg("event_type")
            .arg(&event_type)
            .arg("payload")
            .arg(payload.to_string())
            .arg("env_id")
            .arg(env_id.to_string())
            .arg("created_at")
            .arg(chrono::Utc::now().timestamp())
            .arg("inbox_id")
            .arg(id.to_string());
        if let Some(ref subj) = publisher_subject {
            xadd.arg("publisher_subject").arg(subj);
        }
        if let Some(ref token) = publisher_id_token {
            xadd.arg("publisher_id_token").arg(token);
        }
        // VDC-2: re-attach the recorded provenance on relay-delivered
        // messages so `require_publisher` sees the same field the inline
        // XADD writes.
        if let Some(ref vert) = publisher_vertical {
            xadd.arg("publisher_vertical").arg(vert);
        }
        let xadd_result: glide::ValkeyResult<String> = xadd.query_async(&conn).await;

        match xadd_result {
            Ok(_) => {
                if let Err(e) = async {
                    let mut tx = pool.begin().await?;
                    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
                        .bind(env_id)
                        .execute(&mut *tx)
                        .await;
                    sqlx::query(
                        "UPDATE inbox SET relayed = true, relayed_at = now() WHERE id = $1",
                    )
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await
                }
                .await
                {
                    tracing::warn!(error = %e, "failed to mark inbox relayed");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, stream = %stream, "XADD failed; will retry next drain");
            }
        }
    }
    Ok(count)
}
