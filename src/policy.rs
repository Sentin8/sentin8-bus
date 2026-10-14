// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    boot_full, check_policy, engine_for, policy_bus_client, request_ctx, spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Handle require policy.
pub async fn require_policy(
    engine: &Engine,
    a: &crate::auth::AuthContext,
    headers: &axum::http::HeaderMap,
    target: sentin8::shield::EvalTarget,
) -> Result<sentin8::shield::EvalOutcome, (axum::http::StatusCode, String)> {
    let env_id = a.env_id()?;
    sentin8::shield::runtime::evaluate_full(
        engine,
        a.claims.sub.as_str(),
        env_id,
        a.claims.token_tp.as_str(),
        a.claims.scope.as_str(),
        headers,
        &target.action,
    )
    .await
}
