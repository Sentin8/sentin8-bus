// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for bus.
pub struct BusConfig {
    /// The port.
    pub port: u16,
    /// The valkey URL.
    pub valkey_url: String,
    /// The database URL.
    pub database_url: String,
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,

    /// The auth client.
    pub auth_client: AuthClient,
    /// Per-family produce rate limit (bus README §7, BUS-4): messages per
    /// minute per `(env_id, stream_family)` bucket. `0` disables limiting.
    pub produce_rate_limit_per_minute: u32,
}

impl BusConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_BUS_PORT")
                .expect("SENTIN8_BUS_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_BUS_PORT must be a valid u16"),
            // VALKEYDERIVE-1 (group DESIGN.md §3.1): explicit env override,
            // else the plane-derived URL (the `/0` suffix is inert — the
            // streams live in DB 0 and ACLs scope the keys).
            valkey_url: env::var("SENTIN8_BUS_VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(sentin8::config::service_valkey_url),
            database_url: env::var("SENTIN8_BUS_DATABASE_URL").unwrap_or_else(|_| {
                sentin8::config::Sentin8Config::default_database_url().to_string()
            }),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            produce_rate_limit_per_minute: env::var("SENTIN8_BUS_PRODUCE_RATE_LIMIT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
        }
    }
}
