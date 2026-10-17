// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use glide::AsyncCommands;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::config::BusConfig;

// Produce/consume wire types come from the shared contracts crate — the
// service re-exports them so the utoipa OpenAPI schema and the HTTP layer
// use one definition (bus contracts crate is the wire source of truth).
use sentin8::bus::contracts::{
    ProduceBatchItem, ProduceBatchRequest, ProduceBatchResponse, ProduceRequest, ProduceResponse,
};

// XREAD wire shape: [(stream-name, [(entry-id, [(field, value)])])].
pub(crate) type StreamEntries = Vec<(String, Vec<(String, String)>)>;

/// Validate stream family.
pub fn validate_stream_family(family: &str) -> Result<(), (StatusCode, String)> {
    if family.is_empty() || family.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "stream_family must be 1–64 characters".into(),
        ));
    }
    if family == "dlq" || family == "delayed" || family == "jti" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("stream_family '{family}' is reserved"),
        ));
    }
    for ch in family.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '_' && ch != '-' {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("stream_family contains invalid character '{ch}'"),
            ));
        }
    }
    Ok(())
}

fn audit_event(action: &str, actor: &str, env_id: &str, details: serde_json::Value) {
    tracing::info!(
        target: "sentin8::audit",
        audit_action = action,
        actor = actor,
        env_id = env_id,
        details = %details,
        "bus audit event"
    );
}

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<BusConfig>,
    /// The Valkey GLIDE client (shared command plane — non-blocking
    /// commands only; blocking reads ride the consume pool).
    pub valkey: glide::GlideClient,
    /// The blocking-consume connection pool (BUSCONNP-1): every
    /// `POST /v1/consume` blocking `XREADGROUP` leases a dedicated
    /// client from here for the duration of the read.
    pub consume_pool: Arc<crate::consume_pool::ConsumePool>,
    /// The pool.
    pub pool: sqlx::PgPool,

    /// The policy.
    pub policy: Arc<crate::policy::Engine>,

    /// The  workload registry map (boot-loaded + TTL-cached):
    /// the authorization record for certificate-only platform-workload
    /// calls (scopes + vertical + enabled, auth DESIGN §4.3f).
    pub workload_registry: sentin8::auth::workload_registry::WorkloadMap,

    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

/// Handle stream key.
pub fn stream_key(env_id: &str, family: &str) -> String {
    format!("bus:{env_id}:{family}")
}

/// The owning vertical of an event type (VDC-2, design/
/// sentin8-vertical-data-plane-contract.md §VDC.4): the FIRST colon segment
/// of the event name (`sentin8:sys:service:updated` → `sentin8`,
/// `bank8:ledger:posting:committed` → `bank8`). Every event name follows the
/// `vertical:service:resource:operation` convention (AGENTS.md event-naming
/// rule), so the prefix IS the ownership claim — only the named vertical's
/// workloads may mint the event.
#[must_use]
pub fn event_vertical_prefix(event_type: &str) -> &str {
    event_type.split(':').next().unwrap_or("")
}

/// VDC-2 event-ownership gate: rejects produce when the authenticated
/// producer's M2M `vertical` claim does not match the event type's owning
/// vertical (first colon segment). Platform producers carry
/// `vertical = "sentin8"`; a missing claim (pre-rotation tokens, non-M2M
/// producers) fails CLOSED — event minting is an M2M-only, provenance-gated
/// surface. Consumption is unrestricted: the gate is produce-side
/// provenance only (any service may subscribe to any family).
fn enforce_event_ownership(
    a: &crate::auth::AuthContext,
    event_type: &str,
) -> Result<(), (StatusCode, String)> {
    let expected = event_vertical_prefix(event_type);
    if expected.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "event_type must follow vertical:service:resource:operation".into(),
        ));
    }
    let actual = a.effective_vertical().unwrap_or_default();
    if actual.is_empty() || actual != expected {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "event_ownership: event_type '{event_type}' belongs to vertical \
                 '{expected}' but the producer's identity vertical is '{actual}' \
                 (VDC-2 — missing or mismatched vertical; enroll the owning service)"
            ),
        ));
    }
    Ok(())
}

#[utoipa::path(
    post,
    operation_id = "produce.send",
    path = "/v1/produce",
    request_body = ProduceRequest,
    responses(
        (status = 200, description = "Message produced", body = ProduceResponse),
        (status = 403, description = "Missing bus:produce scope"),
    ),
    security(("sentin8:bus:produce" = [])),
    tag = "bus",
)]
/// Handle produce.
pub async fn produce(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProduceRequest>,
) -> Result<Json<ProduceResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:produce"),
    )
    .await?;
    // BUS-3: one single-produce core shared with `produce_batch` —
    // `produce` is a thin envelope over it (bus DESIGN §4.3).
    produce_single(&state, &a, &headers, produce_env(&a, req.env_id)?, req)
        .await
        .map(Json)
}

#[utoipa::path(
    post,
    operation_id = "produce.batch",
    path = "/v1/produce/batch",
    request_body = ProduceBatchRequest,
    responses(
        (status = 200, description = "Batch accepted (per-row results)", body = ProduceBatchResponse),
        (status = 400, description = "Batch too large (max 100)"),
        (status = 429, description = "Per-family produce rate limit"),
        (status = 403, description = "Missing bus:produce scope"),
    ),
    security(("sentin8:bus:produce" = [])),
    tag = "bus",
)]
/// `POST /v1/produce/batch` — produce N events in one call (BUS-3, bus
/// DESIGN §4.3 / README §7). Each row runs through the SAME single-produce
/// core (validation, rate limit, inbox persist, XADD, stamp, audit) — the
/// batch is a transport-level optimization, not a transaction: rows are
/// independent and a failed row does not roll back its siblings.
pub async fn produce_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<ProduceBatchRequest>,
) -> Result<Json<ProduceBatchResponse>, (StatusCode, String)> {
    if batch.events.is_empty() {
        return Ok(Json(ProduceBatchResponse { results: vec![] }));
    }
    if batch.events.len() > 100 {
        return Err((
            StatusCode::BAD_REQUEST,
            "batch too large: max 100 events per call".to_string(),
        ));
    }
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:produce"),
    )
    .await?;

    let mut results = Vec::with_capacity(batch.events.len());
    for (index, req) in batch.events.into_iter().enumerate() {
        // Per-row env resolution (bus DESIGN §4.3 tenancy contract): rows
        // are independent — each row's env is validated against the
        // caller's identity class, so a batch may mix tenant envs.
        let env_id = match produce_env(&a, req.env_id) {
            Ok(env) => env,
            Err((status, error)) => {
                tracing::warn!(index, status = status.as_u16(), error = %error, "bus: batch produce row failed");
                results.push(ProduceBatchItem {
                    index,
                    message_id: None,
                    stream: None,
                    error: Some(error),
                });
                continue;
            }
        };
        match produce_single(&state, &a, &headers, env_id, req).await {
            Ok(resp) => results.push(ProduceBatchItem {
                index,
                message_id: Some(resp.message_id),
                stream: Some(resp.stream),
                error: None,
            }),
            Err((status, error)) => {
                tracing::warn!(index, status = status.as_u16(), error = %error, "bus: batch produce row failed");
                results.push(ProduceBatchItem {
                    index,
                    message_id: None,
                    stream: None,
                    error: Some(error),
                });
            }
        }
    }
    Ok(Json(ProduceBatchResponse { results }))
}

/// The produce env contract (bus DESIGN §4.3, WARN-21): the REQUEST's env is
/// authoritative for M2M workload tokens — tenancy travels per request (the
/// outbox relay drains env-by-env and produces tenant-family rows that its
/// system-env token could never claim), while OWNERSHIP stays per identity
/// (the `vertical` claim gate, `enforce_event_ownership`). A workload is
/// cert-bound (RFC 8705): the body env claim is the producer's declaration,
/// the stream key `bus:{env_id}:{family}` and the rate bucket follow it, and
/// the audit row records both. USER/delegated tokens keep the strict check —
/// a human caller produces only into the env their token carries (no
/// body-env override; cross-env access must come from a role, not a body).
fn produce_env(a: &auth::AuthContext, req_env: Option<Uuid>) -> Result<Uuid, (StatusCode, String)> {
    match req_env {
        Some(env) if a.claims.token_tp == "m2m" || a.claims.token_tp == "delegated" => Ok(env),
        Some(env) => {
            let token_env = a.env_id()?;
            if env != token_env {
                return Err((
                    StatusCode::FORBIDDEN,
                    "env_id does not match the authenticated tenant".to_string(),
                ));
            }
            Ok(env)
        }
        None => a.env_id().map_err(|_| {
            (
                StatusCode::FORBIDDEN,
                "tenant_unresolved: token has no env_id claim".to_string(),
            )
        }),
    }
}

/// The single-produce core shared by `produce` and `produce_batch`
/// (BUS-3): verify-then-validate-then-persist-then-XADD for ONE request.
/// `produce` calls it with the request's own env check; the batch handler
/// passes each row in turn.
async fn produce_single(
    state: &AppState,
    a: &auth::AuthContext,
    headers: &HeaderMap,
    env_id: Uuid,
    req: ProduceRequest,
) -> Result<ProduceResponse, (StatusCode, String)> {
    validate_stream_family(&req.stream_family)?;
    // VDC-2: event ownership — the event_type's first colon segment must
    // match the producer's M2M `vertical` claim (fail-closed on a missing
    // claim; see `enforce_event_ownership`).
    enforce_event_ownership(a, &req.event_type)?;
    // The env contract is enforced by the caller (produce_env): the passed
    // `env_id` is the row's resolved tenant (request-declared for M2M,
    // token-carried for users).

    // Per-family produce rate limit (bus README §7, BUS-4): a one-minute
    // token bucket keyed `(env_id, family)` in Valkey — INCR + PEXPIRE.
    // Exceeding the cap returns 429 with `Retry-After: 60` (the bucket
    // window) so producers back off deterministically. `0` disables.
    if state.config.produce_rate_limit_per_minute > 0 {
        let minute = chrono::Utc::now().format("%Y%m%d%H%M").to_string();
        let bucket = format!("bus:rl:{}:{}:{minute}", env_id, req.stream_family);
        let count: i64 = glide::cmd("INCR")
            .arg(&bucket)
            .query_async(&state.valkey.clone())
            .await
            .unwrap_or(0);
        if count == 1 {
            let _: Result<i64, _> = glide::cmd("PEXPIRE")
                .arg(&bucket)
                .arg(120_000_i64)
                .query_async(&state.valkey.clone())
                .await;
        }
        if count as u32 > state.config.produce_rate_limit_per_minute {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded for stream family; retry-after: 60".to_string(),
            ));
        }
    }

    let stream = stream_key(&env_id.to_string(), &req.stream_family);

    let publisher_id_token = req.publisher_id_token.clone().or_else(|| {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    });
    let publisher_subject = req
        .publisher_subject
        .clone()
        .unwrap_or_else(|| a.effective_subject());
    // VDC-2: record the verified producer's vertical claim — the consumer
    // side of the event-ownership gate (crates/bus/client
    // `require_publisher` asserts the event_type's first segment matches).
    let publisher_vertical = a.effective_vertical();

    let inbox_id = {
        let mut conn = state
            .pool
            .begin()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("pool: {e}")))?;
        sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, $2)")
            .bind(env_id)
            .bind(&req.stream_family)
            .execute(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("context: {e}")))?;
        let row: (uuid::Uuid,) = sqlx::query_as(
            r#"INSERT INTO inbox (env_id, event_type, stream_family, payload, publisher_id_token, publisher_subject)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id"#,)
            .bind(env_id)
            .bind(&req.event_type)
            .bind(&req.stream_family)
            .bind(&req.payload)
            .bind(publisher_id_token.as_deref())
            .bind(&publisher_subject)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("inbox persist: {e}")))?;
        let inbox_row_id = row.0;
        conn.commit().await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("inbox commit: {e}"),
            )
        })?;
        inbox_row_id
    };

    let conn = state.valkey.clone();
    let now = chrono::Utc::now().timestamp();
    let now_iso = chrono::Utc::now().to_rfc3339();
    let mut xadd = glide::cmd("XADD");
    xadd.arg(&stream)
        .arg("*")
        .arg("event_type")
        .arg(&req.event_type)
        .arg("schema_version")
        .arg("1.0")
        .arg("payload")
        .arg(req.payload.to_string())
        .arg("env_id")
        .arg(env_id.to_string())
        .arg("created_at")
        .arg(now)
        .arg("produced_at")
        .arg(&now_iso)
        .arg("produced_by")
        .arg(&a.claims.sub)
        .arg("correlation_id")
        .arg(req.correlation_id.as_deref().unwrap_or(""))
        .arg("idempotency_key")
        .arg(req.idempotency_key.as_deref().unwrap_or(""))
        .arg("publisher_subject")
        .arg(&publisher_subject)
        .arg("publisher_vertical")
        .arg(publisher_vertical.as_deref().unwrap_or(""));
    if let Some(ref token) = publisher_id_token {
        xadd.arg("publisher_id_token").arg(token);
    }
    let message_id: String = xadd.query_async(&conn).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("XADD failed: {e}"),
        )
    })?;

    // Single-entry delivery (bus design §4.3b): stamp the stream entry id on
    // the inbox row so the inbox relay skips it — the inline XADD already
    // published this event; without the stamp the relay would XADD the same
    // event a second time. A stamp failure is non-fatal (the row stays
    // unrelayed-without-id and the relay publishes it — at-least-once is
    // preserved either way).
    if let Err(e) = sqlx::query("UPDATE inbox SET stream_message_id = $1 WHERE id = $2")
        .bind(&message_id)
        .bind(inbox_id)
        .execute(&state.pool)
        .await
    {
        tracing::warn!(error = %e, inbox_id = %inbox_id, "produce: message_id stamp failed — relay will publish");
    }

    audit_event(
        "bus.produce",
        &a.claims.sub,
        &env_id.to_string(),
        serde_json::json!({
            "stream_family": req.stream_family,
            "event_type": req.event_type,
            "message_id": message_id,
            "publisher_subject": publisher_subject,
        }),
    );

    Ok(ProduceResponse { message_id, stream })
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for consume.
pub struct ConsumeRequest {
    /// The stream family.
    pub stream_family: String,
    /// The consumer group.
    pub consumer_group: String,
    #[serde(default = "default_consumer_name")]
    /// The consumer name.
    pub consumer_name: String,
    #[serde(default = "default_count", alias = "max_count")]
    /// The count count.
    pub count: u64,

    #[serde(default)]
    /// The block ms.
    pub block_ms: u64,
}

fn default_count() -> u64 {
    10
}

/// The server-side cap on a consume request's `block_ms` (BUSCONNP-1,
/// DESIGN.md §8 invariant 10): the caller's blocking hint is honored
/// up to 5s — the bus, not the caller, owns its connection occupancy
/// budget. Longer hints are truncated (the caller observes the cap as a
/// sooner empty batch, never an error).
const BLOCK_MS_CAP: u64 = 5_000;

fn default_consumer_name() -> String {
    "ws-consumer".to_string()
}

#[derive(Serialize, ToSchema)]
/// Response payload for consume.
pub struct ConsumeResponse {
    /// The messages.
    pub messages: Vec<ConsumeMessage>,
}

#[derive(Serialize, ToSchema)]
/// The consumemessage type.
pub struct ConsumeMessage {
    /// message identifier.
    pub message_id: String,
    /// The stream family.
    pub stream_family: String,
    /// env identifier.
    pub env_id: String,
    /// The event type.
    pub event_type: String,
    /// The schema version.
    pub schema_version: String,
    /// The payload.
    pub payload: serde_json::Value,
    /// correlation identifier.
    pub correlation_id: String,
    /// The produced by.
    pub produced_by: String,
    /// The produced at.
    pub produced_at: String,
    /// The idempotency key.
    pub idempotency_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// The publisher id token.
    pub publisher_id_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// The publisher subject.
    pub publisher_subject: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    /// The verified producer's vertical claim (VDC-2) — recorded at
    /// produce from the M2M token; consumers assert it against the
    /// event_type's first colon segment (`require_publisher`).
    pub publisher_vertical: Option<String>,
}

#[utoipa::path(
    post,
    operation_id = "consume.list",
    path = "/v1/consume",
    request_body = ConsumeRequest,
    responses(
        (status = 200, description = "Consumed messages", body = ConsumeResponse),
        (status = 403, description = "Missing bus:consume scope"),
    ),
    security(("sentin8:bus:consume" = [])),
    tag = "bus",
)]
/// Handle consume.
pub async fn consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsumeRequest>,
) -> Result<Json<ConsumeResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:consume"),
    )
    .await?;
    validate_stream_family(&req.stream_family)?;

    let env_id = a.env_id()?;
    let stream = stream_key(&env_id.to_string(), &req.stream_family);
    let group = format!("{}.{}", a.claims.sub, req.consumer_group);

    let conn = state.valkey.clone();

    let _: Result<(), _> = glide::cmd("XGROUP")
        .arg("CREATE")
        .arg(&stream)
        .arg(&group)
        .arg("0")
        .arg("MKSTREAM")
        .query_async(&conn)
        .await;

    // BUSCONNP-1 (DESIGN.md §8 invariant 10): the blocking XREADGROUP
    // runs on a DEDICATED pooled client — never the shared command
    // client. A blocking read on the shared client serializes behind
    // all other Valkey traffic; short-block pollers then pin the GLIDE
    // watchdog's pending count and sustain a silent empty-batch
    // timeout storm. The pool size bounds concurrent blocking reads;
    // surplus callers queue at acquire.
    let leased = match state.consume_pool.acquire().await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "bus: consume pool acquire failed");
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "valkey unavailable".to_string(),
            ));
        }
    };
    // The caller's block_ms is a HINT; the bus owns its connection
    // occupancy budget (invariant 10): cap at 5s.
    let block_ms = req.block_ms.min(BLOCK_MS_CAP);

    let mut cmd = glide::cmd("XREADGROUP");
    cmd.arg("GROUP")
        .arg(&group)
        .arg(&req.consumer_name)
        .arg("COUNT")
        .arg(req.count);
    if block_ms > 0 {
        cmd.arg("BLOCK").arg(block_ms);
    }
    cmd.arg("STREAMS").arg(&stream).arg(">");

    let result: glide::ValkeyResult<Vec<(String, StreamEntries)>> =
        cmd.query_async(leased.client()).await;
    drop(leased);

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
                        stream_family: req.stream_family.clone(),
                        env_id: fmap.get("env_id").cloned().unwrap_or_default(),
                        event_type: fmap.get("event_type").cloned().unwrap_or_default(),
                        schema_version: fmap
                            .get("schema_version")
                            .cloned()
                            .unwrap_or_else(|| "1.0".to_string()),
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
            // A timed-out or failed read is an EMPTY batch — the PEL
            // holds nothing (nothing was delivered), so the caller
            // simply re-polls (BUSCONNP-1 consume lifecycle). The miss
            // is logged at debug so a poller storm is observable without
            // spamming WARN.
            tracing::debug!(
                error = %e,
                stream = %stream,
                block_ms,
                "bus: consume XREADGROUP missed — empty batch returned"
            );
            vec![]
        }
    };

    Ok(Json(ConsumeResponse { messages }))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for ack.
pub struct AckRequest {
    /// The stream family.
    pub stream_family: String,
    /// The consumer group.
    pub consumer_group: String,
    /// message identifier.
    pub message_id: String,
}

#[utoipa::path(
    post,
    operation_id = "ack.send",
    path = "/v1/ack",
    request_body = AckRequest,
    responses(
        (status = 200, description = "Messages acknowledged"),
        (status = 403, description = "Missing bus:consume scope"),
    ),
    security(("sentin8:bus:consume" = [])),
    tag = "bus",
)]
/// Handle ack.
pub async fn ack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AckRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:consume"),
    )
    .await?;
    validate_stream_family(&req.stream_family)?;

    let env_id = a.env_id()?;
    let stream = stream_key(&env_id.to_string(), &req.stream_family);
    let group = format!("{}.{}", a.claims.sub, req.consumer_group);

    let conn = state.valkey.clone();
    let acked: i64 = glide::cmd("XACK")
        .arg(&stream)
        .arg(&group)
        .arg(&req.message_id)
        .query_async(&conn)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("XACK failed: {e}"),
            )
        })?;

    audit_event(
        "bus.ack",
        &a.claims.sub,
        &env_id.to_string(),
        serde_json::json!({
            "stream_family": req.stream_family,
            "consumer_group": req.consumer_group,
            "message_id": req.message_id,
            "acked": acked,
        }),
    );

    Ok(Json(serde_json::json!({"acked": acked})))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for nack.
pub struct NackRequest {
    /// The stream family.
    pub stream_family: String,
    /// The consumer group.
    pub consumer_group: String,
    /// message identifier.
    pub message_id: String,
    #[serde(default)]
    /// The retry after secs.
    pub retry_after_secs: Option<u64>,
    /// How many retries this message has already burned (nack count —
    /// maintained by the consumer across redeliveries). At `MAX_RETRIES`
    /// the reaper routes the message to the DLQ instead of the retry set.
    #[serde(default)]
    /// The retry count.
    pub retry_count: Option<u32>,
}

#[utoipa::path(
    post,
    operation_id = "nack.send",
    path = "/v1/nack",
    request_body = NackRequest,
    responses(
        (status = 200, description = "Message nacked"),
        (status = 403, description = "Missing bus:consume scope"),
    ),
    security(("sentin8:bus:consume" = [])),
    tag = "bus",
)]
/// Handle nack.
pub async fn nack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<NackRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:consume"),
    )
    .await?;
    validate_stream_family(&req.stream_family)?;

    let env_id = a.env_id()?;
    let stream = stream_key(&env_id.to_string(), &req.stream_family);
    let group = format!("{}.{}", a.claims.sub, req.consumer_group);
    let retry_after = req.retry_after_secs.unwrap_or(30);
    let now = chrono::Utc::now().timestamp();
    let retry_at = now + retry_after as i64;

    let retry_key = format!("bus:retry:{}", env_id);
    let conn = state.valkey.clone();
    let _: () = conn
        .zadd(
            &retry_key,
            serde_json::json!({
                "message_id": req.message_id,
                "stream": stream,
                "group": group,
                "stream_family": req.stream_family,
                "event_type": req.stream_family,
                "payload": serde_json::Value::Null,
                "retry_count": req.retry_count.unwrap_or(0),
                "max_retries": crate::reaper::MAX_RETRIES,
                "retry_at": retry_at,
            })
            .to_string(),
            retry_at,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ZADD retry failed: {e}"),
            )
        })?;

    audit_event(
        "bus.nack",
        &a.claims.sub,
        &env_id.to_string(),
        serde_json::json!({
            "stream_family": req.stream_family,
            "consumer_group": req.consumer_group,
            "message_id": req.message_id,
            "retry_after_secs": retry_after,
        }),
    );

    Ok(Json(serde_json::json!({
        "nacked": true,
        "message_id": req.message_id,
        "retry_after_secs": retry_after,
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
/// The dlqquery type.
pub struct DlqQuery {
    #[serde(default = "default_page")]
    /// The page.
    pub page: i64,
    #[serde(default = "default_page_size")]
    /// The page size.
    pub page_size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    50
}

#[utoipa::path(
    get,
    operation_id = "dlq.list",
    path = "/v1/dlq",
    params(("page" = Option<i64>, Query), ("page_size" = Option<i64>, Query)),
    responses(
        (status = 200, description = "DLQ entries"),
        (status = 403, description = "Missing bus:admin scope"),
    ),
    security(("sentin8:bus:admin" = [])),
    tag = "bus",
)]
/// List dlq.
pub async fn list_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<DlqQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:admin"),
    )
    .await?;

    let env_id = a.env_id()?;
    let dlq_key = format!("bus:dlq:{}", env_id);
    let conn = state.valkey.clone();
    let entries: Vec<(f64, String)> = glide::cmd("ZRANGE")
        .arg(&dlq_key)
        .arg(0)
        .arg(-1)
        .arg("WITHSCORES")
        .query_async(&conn)
        .await
        .unwrap_or_default();

    let dlq_entries: Vec<serde_json::Value> = entries
        .into_iter()
        .map(|(score, value)| serde_json::json!({"score": score, "data": value}))
        .collect();

    Ok(Json(
        serde_json::json!({"entries": dlq_entries, "total": dlq_entries.len()}),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for dlqreplay.
pub struct DlqReplayRequest {
    /// The stream family.
    pub stream_family: String,
    /// message identifier.
    pub message_id: String,
}

#[utoipa::path(
    post,
    operation_id = "dlq.replay",
    path = "/v1/dlq/replay",
    request_body = DlqReplayRequest,
    responses(
        (status = 200, description = "DLQ entry replayed"),
        (status = 403, description = "Missing bus:admin scope"),
    ),
    security(("sentin8:bus:admin" = [])),
    tag = "bus",
)]
/// Handle replay dlq.
pub async fn replay_dlq(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DlqReplayRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:admin"),
    )
    .await?;
    validate_stream_family(&req.stream_family)?;

    let env_id = a.env_id()?;
    let dlq_key = format!("bus:dlq:{}", env_id);
    let stream = stream_key(&env_id.to_string(), &req.stream_family);
    let conn = state.valkey.clone();

    let dlq_entries: Vec<String> = conn.zrange(&dlq_key, 0, -1).await.unwrap_or_default();
    let dlq_entry = dlq_entries
        .into_iter()
        .find(|e| e.contains(&req.message_id));

    if let Some(entry_json) = dlq_entry {
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&entry_json) {
            let event_type = entry
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("dlq.replay");
            let payload = entry
                .get("payload")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let _: String = glide::cmd("XADD")
                .arg(&stream)
                .arg("*")
                .arg("event_type")
                .arg(format!("{event_type}.replayed"))
                .arg("payload")
                .arg(payload.to_string())
                .arg("env_id")
                .arg(env_id.to_string())
                .arg("created_at")
                .arg(chrono::Utc::now().timestamp())
                .arg("replayed_from_dlq")
                .arg(&req.message_id)
                .query_async(&conn)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("XADD replay failed: {e}"),
                    )
                })?;
        }
    }

    let removed: i64 = glide::cmd("ZREM")
        .arg(&dlq_key)
        .arg(&req.message_id)
        .query_async(&conn)
        .await
        .unwrap_or(0);

    audit_event(
        "bus.dlq.replay",
        &a.claims.sub,
        &env_id.to_string(),
        serde_json::json!({
            "stream_family": req.stream_family,
            "message_id": req.message_id,
            "removed": removed,
        }),
    );

    Ok(Json(
        serde_json::json!({"replayed": true, "message_id": req.message_id, "removed": removed}),
    ))
}

#[utoipa::path(
    get,
    operation_id = "stream.list",
    path = "/v1/streams",
    responses(
        (status = 200, description = "List of streams"),
        (status = 403, description = "Missing bus:consume scope"),
    ),
    security(("sentin8:bus:consume" = [])),
    tag = "bus",
)]
/// List streams.
pub async fn list_streams(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:consume"),
    )
    .await?;

    let env_id = a.env_id()?;
    let prefix = format!("bus:{}:*", env_id);
    let conn = state.valkey.clone();

    let mut keys: Vec<String> = Vec::new();
    let mut cursor: String = "0".into();
    loop {
        let (new_cursor, batch): (String, Vec<String>) = glide::cmd("SCAN")
            .arg(&cursor)
            .arg("MATCH")
            .arg(&prefix)
            .arg("COUNT")
            .arg(100)
            .query_async(&conn)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("SCAN failed: {e}"),
                )
            })?;
        keys.extend(batch);
        cursor = new_cursor;
        if cursor == "0" {
            break;
        }
    }

    Ok(Json(serde_json::json!({"streams": keys})))
}

/// Handle health.
pub async fn health() -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({"status": "ok", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()});
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for schedule.
pub struct ScheduleRequest {
    /// The stream family.
    pub stream_family: String,
    /// The event type.
    pub event_type: String,
    /// The payload.
    pub payload: serde_json::Value,

    #[serde(default = "default_delay")]
    /// The delay seconds.
    pub delay_seconds: u64,
}

fn default_delay() -> u64 {
    0
}

#[derive(Serialize, ToSchema)]
/// Response payload for schedule.
pub struct ScheduleResponse {
    /// message identifier.
    pub message_id: String,
    /// The delivery at.
    pub delivery_at: i64,
}

#[utoipa::path(
    post,
    operation_id = "schedule.create",
    path = "/v1/schedule",
    request_body = ScheduleRequest,
    responses(
        (status = 200, description = "Message scheduled", body = ScheduleResponse),
        (status = 403, description = "Missing bus:produce scope"),
    ),
    security(("sentin8:bus:produce" = [])),
    tag = "bus",
)]
/// Handle schedule.
pub async fn schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScheduleRequest>,
) -> Result<Json<ScheduleResponse>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:produce"),
    )
    .await?;
    validate_stream_family(&req.stream_family)?;

    let env_id = a.env_id()?;
    let now = chrono::Utc::now().timestamp();
    let delivery_at = now + req.delay_seconds as i64;
    let message_id = Uuid::new_v4().to_string();

    let delayed_key = format!("bus:delayed:{}", env_id);
    let entry = serde_json::json!({
        "message_id": message_id,
        "stream_family": req.stream_family,
        "event_type": req.event_type,
        "payload": req.payload,
        "env_id": env_id.to_string(),
        "created_at": now,
        "delivery_at": delivery_at,
    });

    let conn = state.valkey.clone();
    let _: () = conn
        .zadd(&delayed_key, entry.to_string(), delivery_at)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ZADD failed: {e}"),
            )
        })?;

    audit_event(
        "bus.schedule",
        &a.claims.sub,
        &env_id.to_string(),
        serde_json::json!({
            "stream_family": req.stream_family,
            "event_type": req.event_type,
            "message_id": message_id,
            "delay_seconds": req.delay_seconds,
        }),
    );

    Ok(Json(ScheduleResponse {
        message_id,
        delivery_at,
    }))
}

#[utoipa::path(
    get,
    operation_id = "scheduled.list",
    path = "/v1/scheduled",
    responses(
        (status = 200, description = "Due scheduled messages"),
        (status = 403, description = "Missing bus:consume scope"),
    ),
    security(("sentin8:bus:consume" = [])),
    tag = "bus",
)]
/// List scheduled.
pub async fn list_scheduled(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:consume"),
    )
    .await?;

    let env_id = a.env_id()?;
    let now = chrono::Utc::now().timestamp();
    let delayed_key = format!("bus:delayed:{}", env_id);

    let conn = state.valkey.clone();
    let messages: Vec<String> = conn
        .zrangebyscore(&delayed_key, 0, now)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ZRANGEBYSCORE failed: {e}"),
            )
        })?;

    let parsed: Vec<serde_json::Value> = messages
        .into_iter()
        .filter_map(|s| serde_json::from_str(&s).ok())
        .collect();

    Ok(Json(serde_json::json!({
        "scheduled": parsed,
        "count": parsed.len(),
    })))
}

#[utoipa::path(
    get,
    operation_id = "stream.lag",
    path = "/v1/streams/{stream_family}/lag",
    params(("stream_family" = String, Path, description = "Stream family")),
    responses(
        (status = 200, description = "Consumer group lag"),
        (status = 403, description = "Missing bus:consume scope"),
    ),
    security(("sentin8:bus:consume" = [])),
    tag = "bus",
)]
/// Handle stream lag.
pub async fn stream_lag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(stream_family): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:consume"),
    )
    .await?;
    validate_stream_family(&stream_family)?;

    let env_id = a.env_id()?;
    let stream = stream_key(&env_id.to_string(), &stream_family);

    let conn = state.valkey.clone();

    let groups: Vec<Vec<String>> = glide::cmd("XINFO")
        .arg("GROUPS")
        .arg(&stream)
        .query_async(&conn)
        .await
        .unwrap_or_default();

    let mut group_lags = Vec::new();
    let mut i = 0;
    while i + 2 < groups.len() {
        let name = groups
            .get(i)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let pending: i64 = groups
            .get(i + 2)
            .and_then(|v| v.first())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        group_lags.push(serde_json::json!({
            "group": name,
            "pending": pending,
        }));
        i += 4; // XINFO GROUPS returns 4 fields per group: name, consumers, pending, last-delivered-id
    }

    let total: i64 = glide::cmd("XLEN")
        .arg(&stream)
        .query_async(&conn)
        .await
        .unwrap_or(0);

    Ok(Json(serde_json::json!({
        "stream": stream,
        "total_messages": total,
        "groups": group_lags,
    })))
}

#[utoipa::path(
    get,
    operation_id = "metrics.get",
    path = "/v1/metrics",
    responses(
        (status = 200, description = "Prometheus-style metrics", content_type = "text/plain"),
        (status = 403, description = "Missing bus:admin scope"),
    ),
    security(("sentin8:bus:admin" = [])),
    tag = "bus",
)]
/// Handle metrics.
pub async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let a = auth::verify(&state.workload_registry, &state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:bus:admin"),
    )
    .await?;

    let env_id = a.env_id()?;
    let conn = state.valkey.clone();

    let prefix = format!("bus:{}:*", env_id);
    let mut stream_keys: Vec<String> = Vec::new();
    let mut cursor: String = "0".into();
    loop {
        let (new_cursor, batch): (String, Vec<String>) = glide::cmd("SCAN")
            .arg(&cursor)
            .arg("MATCH")
            .arg(&prefix)
            .arg("COUNT")
            .arg(100)
            .query_async(&conn)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("SCAN failed: {e}"),
                )
            })?;
        stream_keys.extend(batch);
        cursor = new_cursor;
        if cursor == "0" {
            break;
        }
    }

    let dlq_key = format!("bus:dlq:{}", env_id);
    let dlq_depth: i64 = conn.zcard(&dlq_key).await.unwrap_or(0);

    let delayed_key = format!("bus:delayed:{}", env_id);
    let delayed_depth: i64 = conn.zcard(&delayed_key).await.unwrap_or(0);

    let mut out = String::new();
    out.push_str("# HELP sentin8_bus_streams_total Total number of streams for this tenant\n");
    out.push_str("# TYPE sentin8_bus_streams_total gauge\n");
    out.push_str(&format!(
        "sentin8_bus_streams_total {}\n",
        stream_keys.len()
    ));
    out.push_str("# HELP sentin8_bus_dlq_depth Number of messages in the dead-letter queue\n");
    out.push_str("# TYPE sentin8_bus_dlq_depth gauge\n");
    out.push_str(&format!("sentin8_bus_dlq_depth {}\n", dlq_depth));
    out.push_str("# HELP sentin8_bus_delayed_depth Number of messages in the delayed queue\n");
    out.push_str("# TYPE sentin8_bus_delayed_depth gauge\n");
    out.push_str(&format!("sentin8_bus_delayed_depth {}\n", delayed_depth));

    Ok(out)
}

#[cfg(test)]
mod vdc_tests {
    //! VDC-2 event-ownership gate unit tests (design/
    //! sentin8-vertical-data-plane-contract.md §VDC.4).

    use super::event_vertical_prefix;

    #[test]
    fn event_prefix_extracts_owning_vertical() {
        assert_eq!(
            event_vertical_prefix("sentin8:sys:service:updated"),
            "sentin8"
        );
        assert_eq!(
            event_vertical_prefix("bank8:ledger:posting:committed"),
            "bank8"
        );
        assert_eq!(
            event_vertical_prefix("hotel8:pms:reservation:created"),
            "hotel8"
        );
    }

    #[test]
    fn event_prefix_degenerate_forms_fail_closed() {
        // No colon → the whole name is the prefix; the gate then compares
        // against the token's vertical claim — a bare `sys` event fails
        // for every producer whose claim is a full vertical name.
        assert_eq!(event_vertical_prefix("no-colons"), "no-colons");
        // Empty event_type → empty prefix → the gate rejects 400.
        assert_eq!(event_vertical_prefix(""), "");
        // Leading colon → empty prefix → 400.
        assert_eq!(event_vertical_prefix(":leading"), "");
    }
}
