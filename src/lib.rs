// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

//! Library surface for Sentin8:Bus - tests import service internals through
//! this crate name, mirroring the post/cron pattern.

#![deny(missing_docs)]

/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// Produce/consume authentication helpers.
pub mod auth;
/// Environment configuration.
pub mod config;
/// The blocking-consume connection pool .
pub mod consume_pool;
/// HTTP handlers - produce, consume, DLQ, metrics.
pub mod handlers;
/// Inbox relay - persists produced events (outbox durability).
pub mod inbox_relay;
/// OpenAPI spec assembly.
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
#[cfg_attr(test, allow(dead_code))]
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::BusOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
/// Reaper - self-draining loop for the retry and delayed queues.
pub mod reaper;
/// Service self-registration declarations.
pub mod registration;
/// Axum router and state builder.
pub mod server;
/// SSE consume endpoint (server-pushed stream reads).
pub mod sse;
