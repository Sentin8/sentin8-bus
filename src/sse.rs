// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response, Sse},
};
use serde::Deserialize;

use crate::auth;
use crate::handlers::{
    stream_key, validate_stream_family, AppState, ConsumeMessage, StreamEntries,
};

#[derive(Debug, Deserialize)]
/// The ssequery type.
pub struct SseQuery {
    /// The stream family.
    pub stream_family: String,
    /// The consumer group.
    pub consumer_group: String,
    #[serde(default = "default_consumer_name")]
    /// The consumer name.
    pub consumer_name: String,

    #[serde(default)]
    /// The token.
    pub token: Option<String>,
}

fn default_consumer_name() -> String {
    "sse-consumer".to_string()
}

fn make_sse_event(msg: &ConsumeMessage) -> axum::response::sse::Event {
    let json = serde_json::to_string(msg).unwrap_or_else(|_| "{}".into());
    axum::response::sse::Event::default()
        .id(&msg.message_id)
        .data(json)
}

/// Handle SSE handler.
pub async fn sse_handler(
    Query(q): Query<SseQuery>,
    State(state): State<AppState>,
    req_headers: HeaderMap,
) -> Response {
    // auth DESIGN §4.3f: certificate-first — a platform
    // workload presents its Acme-issued client certificate at the TLS
    // handshake and needs NO bearer at all (the registry map authorizes
    // `sentin8:bus:consume`). The Bearer path remains for user/delegated
    // consumers (and the legacy `?token=` query param).
    let headers = if req_headers.contains_key(axum::http::header::AUTHORIZATION) {
        req_headers
    } else if let Some(ref token) = q.token {
        let mut h = HeaderMap::new();
        if let Ok(val) = axum::http::HeaderValue::from_str(&format!("Bearer {token}")) {
            h.insert(axum::http::header::AUTHORIZATION, val);
        }
        h
    } else if req_headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| !s.is_empty())
    {
        // Certificate identity present (TLS-injected after CA verify) —
        // no bearer needed; the combined verifier resolves the workload.
        req_headers
    } else {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            "missing Authorization header, token query param, or client certificate",
        )
            .into_response();
    };

    let a = match auth::verify(&state.workload_registry, &state.config, &headers).await {
        Ok(a) => a,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    if !a.has_any_scope(&["sentin8:bus:consume"]) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "missing bus:consume scope",
        )
            .into_response();
    }

    if let Err(e) = validate_stream_family(&q.stream_family) {
        return e.into_response();
    }

    let env_id = match a.env_id() {
        Ok(id) => id,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let stream = stream_key(&env_id.to_string(), &q.stream_family);
    let group = format!("{}.{}", a.claims.sub, q.consumer_group);
    let consumer_name = q.consumer_name;

    // GLIDE: a DEDICATED client per SSE connection. `GlideClient::clone()`
    // shares one underlying pipeline — concurrent SSE consumers' blocking
    // `XREADGROUP BLOCK 10000` calls serialize behind each other and every
    // queued one times out (the ~23/min TimeoutError storm). The same
    // one-client-per-blocking-consumer discipline the SDK's MemBus
    // stream-consumer uses (group DESIGN.md §3.1).
    let valkey =
        match sentin8::middleware::valkey_client(&state.config.valkey_url, "sentin8:bus").await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "bus: SSE consumer connection failed");
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "valkey unavailable",
                )
                    .into_response();
            }
        };

    tracing::info!(%stream, %group, %consumer_name, "bus: SSE consumer connected");

    {
        let conn = valkey.clone();
        let _: Result<(), _> = glide::cmd("XGROUP")
            .arg("CREATE")
            .arg(&stream)
            .arg(&group)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&conn)
            .await;
    }

    let event_stream = async_stream::stream! {
        let valkey = valkey;
        let mut last_autoclaim = std::time::Instant::now();





        const AUTOCLAIM_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);


        const MIN_IDLE_MS: u64 = 60_000;

        loop {

            if last_autoclaim.elapsed() >= AUTOCLAIM_INTERVAL {
                last_autoclaim = std::time::Instant::now();



                let claimed: glide::ValkeyResult<(String, StreamEntries, Vec<String>)> =
                    glide::cmd("XAUTOCLAIM")
                        .arg(&stream)
                        .arg(&group)
                        .arg(&consumer_name)
                        .arg(MIN_IDLE_MS)
                        .arg("0-0")
                        .arg("COUNT")
                        .arg(20u64)
                        .query_async(&mut valkey.clone())
                        .await;
                match claimed {
                    Ok((_, entries, _deleted)) => {
                        if !entries.is_empty() {
                            tracing::info!(
                                %stream, %group, claimed = entries.len(),
                                "bus: SSE re-delivering abandoned pending entries (XAUTOCLAIM)"
                            );
                        }
                        for (id, fields) in entries {
                                let fmap: std::collections::HashMap<String, String> =
                                    fields.into_iter().collect();
                                let payload = fmap
                                    .get("payload")
                                    .and_then(|v| serde_json::from_str(v).ok())
                                    .unwrap_or(serde_json::Value::Null);
                                let message = ConsumeMessage {
                                    message_id: id,
                                    stream_family: fmap.get("stream_family").cloned().unwrap_or_default(),
                                    env_id: fmap.get("env_id").cloned().unwrap_or_default(),
                                    event_type: fmap.get("event_type").cloned().unwrap_or_default(),
                                    schema_version: fmap.get("schema_version").cloned().unwrap_or_else(|| "1.0".to_string()),
                                    payload,
                                    correlation_id: fmap.get("correlation_id").cloned().unwrap_or_default(),
                                    produced_by: fmap.get("produced_by").cloned().unwrap_or_default(),
                                    produced_at: fmap.get("created_at").cloned().unwrap_or_default(),
                                    idempotency_key: fmap.get("idempotency_key").filter(|v| !v.is_empty()).cloned(),
                                    publisher_id_token: fmap.get("publisher_id_token").filter(|v| !v.is_empty()).cloned(),
                                    publisher_subject: fmap.get("publisher_subject").filter(|v| !v.is_empty()).cloned(),
                                    publisher_vertical: fmap.get("publisher_vertical").filter(|v| !v.is_empty()).cloned(),
                                };
                                yield Ok::<_, Infallible>(make_sse_event(&message));
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, %stream, "bus: XAUTOCLAIM sweep skipped");
                    }
                }
            }

            let result: glide::ValkeyResult<Vec<(String, StreamEntries)>> =
                glide::cmd("XREADGROUP")
                .arg("GROUP")
                .arg(&group)
                .arg(&consumer_name)
                .arg("COUNT")
                .arg(10u64)
                .arg("BLOCK")
                .arg(10000u64)
                .arg("STREAMS")
                .arg(&stream)
                .arg(">")
                .query_async(&mut valkey.clone())
                .await;

            let messages = match result {
                Ok(entries) => {
                    let mut msgs = Vec::new();
                    for (_stream_name, stream_entries) in entries {
                        for (id, fields) in stream_entries {
                            let fmap: std::collections::HashMap<String, String> =
                                fields.into_iter().collect();
                            let payload = fmap
                                .get("payload")
                                .and_then(|v| serde_json::from_str(v).ok())
                                .unwrap_or(serde_json::Value::Null);
                            let idempotency_key = fmap
                                .get("idempotency_key")
                                .filter(|v| !v.is_empty())
                                .cloned();
                            let publisher_id_token = fmap
                                .get("publisher_id_token")
                                .filter(|v| !v.is_empty())
                                .cloned();
                            let publisher_subject = fmap
                                .get("publisher_subject")
                                .filter(|v| !v.is_empty())
                                .cloned();
                            let publisher_vertical = fmap
                                .get("publisher_vertical")
                                .filter(|v| !v.is_empty())
                                .cloned();
                            msgs.push(ConsumeMessage {
                                message_id: id,
                                stream_family: fmap.get("stream_family").cloned().unwrap_or_default(),
                                env_id: fmap.get("env_id").cloned().unwrap_or_default(),
                                event_type: fmap.get("event_type").cloned().unwrap_or_default(),
                                schema_version: fmap.get("schema_version").cloned().unwrap_or_else(|| "1.0".to_string()),
                                payload,
                                correlation_id: fmap.get("correlation_id").cloned().unwrap_or_default(),
                                produced_by: fmap.get("produced_by").cloned().unwrap_or_default(),
                                produced_at: fmap.get("created_at").cloned().unwrap_or_default(),
                                idempotency_key,
                                publisher_id_token,
                                publisher_subject,
                                publisher_vertical,
                            });
                        }
                    }
                    msgs
                }
                Err(e) => {
                    tracing::warn!(error = %e, %stream, "bus: SSE XREADGROUP error");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    vec![]
                }
            };

            if messages.is_empty() {




                let pending_raw: Option<glide::ValkeyValue> = glide::cmd("XPENDING")
                    .arg(&stream)
                    .arg(&group)
                    .query_async(&mut valkey.clone())
                    .await
                    .ok();
                if let Some(glide::ValkeyValue::Array(arr)) = pending_raw {
                    if let Some(glide::ValkeyValue::Int(n)) = arr.first() {
                        if *n > 100 {
                            tracing::warn!(%stream, %group, pending = *n, "bus: consumer group pending backlog > 100");
                        }
                    }
                }

                yield Ok::<_, Infallible>(axum::response::sse::Event::default().comment("heartbeat"));
            } else {
                for msg in &messages {
                    yield Ok::<_, Infallible>(make_sse_event(msg));
                }
            }
        }
    };

    Sse::new(event_stream)
        .keep_alive(
            axum::response::sse::KeepAlive::new()
                .interval(std::time::Duration::from_secs(15))
                .text("heartbeat"),
        )
        .into_response()
}
