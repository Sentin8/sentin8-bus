// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

//! Router ↔ OpenAPI drift guard (OAPEC design §3).
//!
//! Introspects the typed route table (`Router<AppState>` BEFORE
//! `with_state` - the guard dispatches no request, so no state is needed)
//! and asserts the compiled spec covers every served route + no stale spec
//! pairs. Add a route without an annotation and this fails in CI before
//! the site API pages can trail.

use sentin8::openapi::OpenApi;
use sentin8::shell::drift_guard::{assert_openapi_covers_router, served_routes, spec_pairs};
use sentin8_bus_server::openapi::BusOpenApi;
use sentin8_bus_server::server::routes;

#[tokio::test]
async fn openapi_spec_covers_every_served_route() {
    // Typed-but-unbound router: axum's routing table is state-independent.
    let router: axum::Router<sentin8_bus_server::handlers::AppState> = routes(axum::Router::new());
    let served = served_routes(&router);
    let pairs = spec_pairs(&BusOpenApi::openapi());
    assert_openapi_covers_router(&served, &pairs, &[]);
}
