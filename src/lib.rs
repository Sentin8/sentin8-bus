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
/// The blocking-consume connection pool (BUSCONNP-1).
pub mod consume_pool;
/// HTTP handlers - produce, consume, DLQ, metrics.
pub mod handlers;
/// Inbox relay - persists produced events (outbox durability).
pub mod inbox_relay;
/// OpenAPI spec assembly.
pub mod openapi;
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
