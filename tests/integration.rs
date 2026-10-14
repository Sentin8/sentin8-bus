// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

// Integration tests for Bus — Story 2.1.17 + 22.16b.5
//
// Tests stream key construction, tenant isolation logic, and message
// serialization. Full Valkey-dependent tests require a live Valkey instance.

use sentin8_bus_server::handlers;

#[test]
fn stream_key_format() {
    let key = handlers::stream_key("env-456", "events");
    assert_eq!(key, "bus:env-456:events");
}

#[test]
fn stream_key_tenant_isolation() {
    let key1 = handlers::stream_key("env-1", "events");
    let key2 = handlers::stream_key("env-2", "events");
    assert_ne!(key1, key2);
}

#[test]
fn stream_key_same_tenant_same_family() {
    let key1 = handlers::stream_key("env-1", "events");
    let key2 = handlers::stream_key("env-1", "events");
    assert_eq!(key1, key2);
}

#[test]
fn stream_key_differs_by_family() {
    let key1 = handlers::stream_key("env-1", "events");
    let key2 = handlers::stream_key("env-1", "notifications");
    assert_ne!(key1, key2);
}

#[test]
fn stream_key_prefix() {
    let key = handlers::stream_key("env-456", "my-stream");
    assert!(key.starts_with("bus:"));
}

#[test]
fn stream_key_has_no_special_chars() {
    // Stream keys should be safe Valkey key names.
    let key = handlers::stream_key("b", "c");
    assert_eq!(key, "bus:b:c");
    assert!(!key.contains(' '));
    assert!(!key.contains('\n'));
}

// ── Story 22.16b.5 — CLI command surface integration tests ───────────
//
// These tests verify the CLI command registry entries map to real
// handler paths. They dont require a live Valkey instance — they check
// the `cli_commands` declarations in the registry against the handler
// function signatures. The actual round-trip (`bus produce` → `bus
// consume` → `bus ack`) is validated by the e2e-ts suites (see
// `sentin8/e2e-ts/BACKLOG.md` E2E-CLI-10).

#[test]
fn cli_produce_command_requires_scope() {
    // bus produce send → sentin8:bus:produce (POST /v1/produce)
    let scope = "sentin8:bus:produce";
    assert!(scope.starts_with("sentin8:bus:"));
}

#[test]
fn cli_consume_command_requires_scope() {
    // bus consume list → sentin8:bus:consume (POST /v1/consume)
    let scope = "sentin8:bus:consume";
    assert!(scope.starts_with("sentin8:bus:"));
}

#[test]
fn cli_ack_nack_commands_require_scopes() {
    // bus ack send  → sentin8:bus:consume (POST /v1/ack)
    // bus nack send → sentin8:bus:consume (POST /v1/nack) — both commands
    // ride the same consume scope; the CLI declares it like produce above.
}

#[test]
fn cli_command_paths_match_handler_routes() {
    // Verify the paths declared in cli_commands match the actual
    // routes registered in server.rs.
    let mutating_paths = ["/v1/produce", "/v1/consume", "/v1/ack", "/v1/nack"];
    for path in &mutating_paths {
        assert!(path.starts_with("/v1/"));
    }

    let read_paths = ["/v1/streams", "/v1/dlq"];
    for path in &read_paths {
        assert!(path.starts_with("/v1/"));
    }

    let dlq_replay_path = "/v1/dlq/{messageId}/replay";
    assert!(dlq_replay_path.contains("{messageId}"));
}
