// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use axum::routing::{get, post};

use crate::handlers::{self, AppState};

/// Build state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::BusConfig::from_env();
    let valkey = sentin8::middleware::valkey_client(&config.valkey_url, "sentin8:bus").await?;

    // the fixed dedicated-client pool for HTTP consume
    // blocking reads - connected at boot so the first read pays no
    // handshake; a partially-failed pool still serves (fail-open).
    let consume_pool = crate::consume_pool::ConsumePool::connect(&config.valkey_url, 8).await?;
    tracing::info!(
        size = consume_pool.size(),
        "bus: blocking-consume connection pool connected"
    );

    let pool = core.pool.clone();

    crate::inbox_relay::spawn(pool.clone(), valkey.clone(), config.database_url.clone());

    let policy_engine = core.admin.policy.clone();
    // BOOTDEAD-1: the client resolution moved INSIDE the hot-reload loop
    // (a fresh-boot supervisor deadlocked waiting for a certificate only
    // its own spawn loop could make mintable).
    crate::policy::spawn_hot_reload(
        pool.clone(),
        config.sentin8_auth_issuer.as_str(),
        "sentin8:bus",
        policy_engine.clone(),
    );

    // auth DESIGN §4.3f: boot-load the workload registry map
    // (the token-free authorization record). Fail-open-with-warning on an
    // unreachable Valkey at boot: the process serves the bearer path
    // (user/delegated) while certificate-workload calls fail-closed until
    // the map loads on the next boot (dev: restart; the map is normally
    // published by enroll BEFORE services start). The load presents THIS
    // service's certificate identity over the Valkey TLS plane (group
    // DESIGN.md §3.1).
    let workload_registry = match sentin8::auth::workload_registry::WorkloadMap::boot_load(
        "sentin8:bus",
    )
    .await
    {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(error = %e, "bus: workload registry map unavailable at boot - certificate-workload calls fail-closed until next boot");
            sentin8::auth::workload_registry::WorkloadMap::boot_load_empty("sentin8:bus")
        }
    };

    let state = AppState {
        config: Arc::new(config.clone()),
        valkey: valkey.clone(),
        consume_pool: Arc::new(consume_pool),
        pool: pool.clone(),
        policy: policy_engine.clone(),
        workload_registry,
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:bus".to_string(),
            pool: pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
    };

    // Reaper (bus DESIGN §4.3): the retry and delayed sorted sets drain
    // themselves - due retries re-XADD to their source stream (exhausted
    // retries land in the DLQ), due delayed messages XADD to their target.
    crate::reaper::spawn(Arc::new(state.clone()));

    Ok(state)
}

/// Handle routes.
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route("/v1/produce", post(handlers::produce))
        .route("/v1/produce/batch", post(handlers::produce_batch))
        .route("/v1/consume", post(handlers::consume))
        .route("/v1/ack", post(handlers::ack))
        .route("/v1/nack", post(handlers::nack))
        .route("/v1/dlq", get(handlers::list_dlq))
        .route("/v1/dlq/replay", post(handlers::replay_dlq))
        .route("/v1/streams", get(handlers::list_streams))
        .route("/v1/schedule", post(handlers::schedule))
        .route("/v1/scheduled", get(handlers::list_scheduled))
        .route("/v1/streams/{stream_family}/lag", get(handlers::stream_lag))
        .route("/v1/metrics", get(handlers::metrics))
        .route("/v1/consume/sse", get(crate::sse::sse_handler))
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
