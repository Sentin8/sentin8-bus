// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use axum::http::{HeaderMap, StatusCode};
use sentin8::auth::client::VerifiedClaims;
use sentin8::middleware::context::TLSContext;

use crate::config::BusConfig;

/// The authcontext type.
pub struct AuthContext {
    /// The claims.
    pub claims: VerifiedClaims,

    /// The tls.
    pub tls: Option<TLSContext>,

    /// auth DESIGN §4.3f: the resolved certificate-only
    /// platform-workload identity, when the request presented an enrolled
    /// client certificate INSTEAD of a bearer token (the certificate is
    /// the identity; the registry map is the authorization record).
    /// `None` on the bearer path (user/delegated JWT flows).
    pub workload: Option<WorkloadIdentity>,
}

impl AuthContext {
    /// The caller's scopes for Shield/handler checks — the map-granted
    /// set on the certificate path, the JWT `scope` claim on the bearer
    /// path.
    pub fn effective_scopes(&self) -> Vec<String> {
        if let Some(w) = &self.workload {
            return w.scopes.clone();
        }
        self.claims
            .scope
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }

    /// Whether the caller holds the given scope (map-granted on the
    /// certificate path; JWT claim on the bearer path).
    pub fn has_scope(&self, scope: &str) -> bool {
        if let Some(w) = &self.workload {
            return w.has_scope(scope);
        }
        self.claims.has_scope(scope)
    }

    /// The caller's vertical for the VDC-2 event-ownership gate —
    /// the map-stamped vertical on the certificate path, the JWT claim on
    /// the bearer path.
    pub fn effective_vertical(&self) -> Option<String> {
        if let Some(w) = &self.workload {
            return w.vertical.clone();
        }
        self.claims.vertical.clone()
    }

    /// The caller's subject for audit/publisher stamps — the workload CN
    /// (`m2m-{workload}`) on the certificate path, the JWT `sub` on the
    /// bearer path.
    pub fn effective_subject(&self) -> String {
        if let Some(w) = &self.workload {
            return format!("m2m-{}", w.workload);
        }
        self.claims.sub.clone()
    }
}

impl AuthContext {
    /// Handle env id.
    pub fn env_id(&self) -> Result<uuid::Uuid, (StatusCode, String)> {
        self.claims
            .env_id
            .as_ref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or_else(|| {
                (
                    StatusCode::FORBIDDEN,
                    "tenant_unresolved: token has no env_id claim".into(),
                )
            })
    }

    /// Handle has any scope.
    pub fn has_any_scope(&self, scopes: &[&str]) -> bool {
        self.claims.has_any_scope(scopes)
    }

    /// Handle cross check tls.
    pub fn cross_check_tls(&self) -> Result<(), (StatusCode, String)> {
        let jwt_env = match self.env_id() {
            Ok(env) => env,

            Err(_) => return Ok(()),
        };
        if let Some(tls) = &self.tls {
            if let Some(sentin8_tls_env) = tls.env_id {
                if sentin8_tls_env != jwt_env {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "tenant_mismatch: JWT env_id does not match TLS X-Sentin8-Env-Id".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Verify cert binding.
    pub fn verify_cert_binding(&self) -> Result<(), (StatusCode, String)> {
        if self.claims.token_tp != "m2m" {
            return Ok(());
        }

        if let Some(tls) = &self.tls {
            if let Some(_thumbprint) = &tls.client_cert_thumbprint {
                return Ok(());
            }
        }

        Ok(())
    }
}

/// Verify token.
pub async fn verify_token(
    config: &BusConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing Authorization header".into(),
            )
        })?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "expected Bearer token".into()))?;

    let claims = config
        .auth_client
        .clone()
        .verify_token(token)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("token verification failed: {e}"),
            )
        })?;

    // No one-shot jti replay guard (DESIGN §5): `access`/`delegated`
    // tokens are REUSABLE credentials — the Delegation Gateway caches
    // each delegated JWT (TTL = expiry) and legitimately re-presents it
    // for every request in the session; a `SET NX` on the jti would 401
    // the first cached reuse. Revocation rides the actor-revocation
    // check + token expiry, never per-service consumption.

    match claims.token_tp.as_str() {
        "access" | "m2m" | "delegated" => {}
        other => {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("invalid token type '{other}': only access/m2m/delegated tokens accepted"),
            ));
        }
    }

    if claims.token_tp != "m2m" {
        let aud = &claims.aud;
        let auth_issuer = &config.sentin8_auth_issuer;

        let aud_valid = aud.is_empty()
            || aud.split_whitespace().any(|a| {
                a == "bus"
                    || a == "sentin8"
                    || a == auth_issuer
                    || a.starts_with("https://auth.")
                    || a.starts_with("https://bus.")
            });
        if !aud_valid {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("audience mismatch: token aud '{aud}' does not include 'bus'"),
            ));
        }
    }

    let tls = TLSContext::from_headers(headers);
    let tls = if tls.env_id.is_none() && tls.application_id.is_none() && tls.service.is_none() {
        None // Not routed through TLS (direct call).
    } else {
        Some(tls)
    };

    let ctx = AuthContext {
        claims,
        tls,
        workload: None,
    };

    if ctx.claims.token_tp != "delegated" {
        ctx.cross_check_tls()?;
    }

    ctx.verify_cert_binding()?;

    Ok(ctx)
}

// ── certificate-only platform-workload identity ───────────

/// A platform workload's identity resolved from the TLS handshake
/// (auth DESIGN §4.3f) — no token exists on this path: the
/// CA-verified certificate IS the authentication, and the enroll-published
/// `m2m:workloads` registry map IS the authorization record (scopes +
/// vertical + enabled, boot-loaded and TTL-cached by this process).
#[derive(Debug, Clone)]
pub struct WorkloadIdentity {
    /// The workload name (certificate CN minus the `m2m-` prefix —
    /// `service_name` in the registry map).
    pub workload: String,
    /// The scopes the registry map grants this workload (empty when
    /// missing/disabled — fail-closed: an unenrolled identity exercises
    /// nothing).
    pub scopes: Vec<String>,
    /// The workload's vertical (VDC-2 event-ownership gate input;
    /// `None` when missing/disabled — produce refuses it).
    pub vertical: Option<String>,
    /// The service_type the workload performs work FOR (VDC-4 — Sys's
    /// tenant-snapshot scoped discovery keys on this claim).
    pub service_type: Option<String>,
    /// The presented certificate thumbprint (base64url SHA-256 of DER —
    /// the audit identity).
    pub thumbprint: String,
}

impl WorkloadIdentity {
    /// Whether the map grants this workload the given scope.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Resolve a platform-workload identity from the TLS-injected certificate
/// headers against the boot-loaded registry map (request-path read —
/// in-memory snapshot, no I/O). Returns `Err` on missing/invalid identity
/// headers (the caller answers 401) and `Ok(None)` when the request carried
/// no client certificate (the caller falls through to the bearer path or
/// 401s — browser/user flows keep their JWTs).
///
/// # Errors
/// Returns the rejection (status + message) for an unenrolled or disabled
/// workload — the authorization record is the map row.
pub async fn resolve_workload_identity(
    registry: &sentin8::auth::workload_registry::WorkloadMap,
    headers: &HeaderMap,
) -> Result<Option<WorkloadIdentity>, (StatusCode, String)> {
    // The TLS layer injects these ONLY after CA-verifying the presented
    // certificate (client-supplied copies are stripped before injection).
    let Some(subject) = headers
        .get("x-sentin8-client-cert-subject")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    else {
        return Ok(None); // no client certificate presented
    };
    let Some(workload) = subject.strip_prefix("m2m-").filter(|w| !w.is_empty()) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("certificate CN '{subject}' is not a platform workload identity"),
        ));
    };
    let thumbprint = headers
        .get("x-sentin8-client-cert-thumbprint")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();

    match registry.get(workload).await {
        Some(rec) if rec.enabled => Ok(Some(WorkloadIdentity {
            workload: workload.to_string(),
            scopes: rec.scopes,
            vertical: Some(rec.vertical),
            service_type: Some(rec.service_type),
            thumbprint,
        })),
        Some(_) => Err((
            StatusCode::UNAUTHORIZED,
            format!("workload '{workload}' is disabled (revoked)"),
        )),
        None => Err((
            StatusCode::UNAUTHORIZED,
            format!("workload '{workload}' is not enrolled (run vertical enroll for the owning service)"),
        )),
    }
}

/// The combined verification entry (auth DESIGN §4.3f):
/// certificate-first. When the TLS handshake presented an enrolled
/// platform-workload certificate, the identity is resolved against the
/// boot-loaded registry map (no token involved — the map is the
/// authorization record). Otherwise the request falls through to the
/// bearer path (user/delegated JWT flows unchanged).
///
/// The certificate path constructs a SYNTHETIC `VerifiedClaims` carrying
/// the resolved identity (`sub = m2m-{workload}`, `token_tp = "m2m"`,
/// scope/vertical/service_type from the map row, system env): the
/// existing handler seams (`claims.vertical` ownership gate, `env_id()`
/// resolution, Shield's request_ctx) read the SAME fields they always
/// did, and `AuthContext.workload` marks the provenance for the
/// effective_* accessors.
///
/// # Errors
/// Returns the rejection (status + message) for an unenrolled/disabled
/// workload or a failed bearer verification.
pub async fn verify(
    registry: &sentin8::auth::workload_registry::WorkloadMap,
    config: &BusConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    // Bearer-first, certificate fallback (DESIGN §5): a delegated token
    // names the acting user in `act.sub` (RFC 8693) — resolving the
    // hop's workload certificate first would shadow it. The certificate
    // remains the sole path for pure-M2M calls (no bearer).
    let has_bearer = headers.contains_key(axum::http::header::AUTHORIZATION)
        || headers.contains_key("authorization");
    if !has_bearer {
        if let Some(workload) = resolve_workload_identity(registry, headers).await? {
            let tls = TLSContext::from_headers(headers);
            let tls =
                if tls.env_id.is_none() && tls.application_id.is_none() && tls.service.is_none() {
                    None
                } else {
                    Some(tls)
                };
            let now = chrono::Utc::now().timestamp();
            let claims = VerifiedClaims {
                sub: format!("m2m-{}", workload.workload),
                iss: config.sentin8_auth_issuer.clone(),
                aud: String::new(),
                jti: format!("cert:{}", workload.thumbprint),
                iat: now,
                // No expiry: the identity is the certificate (valid until
                // Acme-side expiry or revocation via the map's `enabled`
                // flag, observed within the TTL). The synthetic claims live
                // for the REQUEST only — nothing caches them.
                exp: i64::MAX,
                token_tp: "m2m".into(),
                scope: workload.scopes.join(" "),
                env_id: tls
                    .as_ref()
                    .and_then(|t| t.env_id)
                    .map(|e| e.to_string())
                    .or_else(|| Some(sentin8::config::SYSTEM_ENV_ID.to_string())),
                email: None,
                act: None,
                vertical: workload.vertical.clone(),
                service_type: workload.service_type.clone(),
            };
            return Ok(AuthContext {
                claims,
                tls,
                workload: Some(workload),
            });
        }
    }
    verify_token(config, headers).await
}
