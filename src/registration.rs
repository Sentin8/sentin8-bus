// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, PgRole, PolicySetDecl, Registration, RelationDecl,
    SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:bus:read,sentin8:bus:write",
    role: "sentin8_bus_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "streams",
        label: "Streams",
        ui_endpoint: "/v1/admin/ui/streams",
        data_endpoint: "/v1/admin/streams",
        icon: "0xe60f",
    },
    AdminUiPage {
        route: "consumers",
        label: "Consumers",
        ui_endpoint: "/v1/admin/ui/consumers",
        data_endpoint: "/v1/admin/consumers",
        icon: "0xe33a",
    },
    AdminUiPage {
        route: "metrics",
        label: "Metrics",
        ui_endpoint: "/v1/admin/ui/metrics",
        data_endpoint: "/v1/admin/metrics",
        icon: "0xe0cc",
    },
    AdminUiPage {
        route: "dlq",
        label: "DLQ",
        ui_endpoint: "/v1/admin/ui/dlq",
        data_endpoint: "/v1/admin/dlq",
        icon: "0xe238",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::BusOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:bus over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        policies: "permit(principal, action == Action::\"sentin8:bus:produce\", resource) when { principal.scopes.contains(\"sentin8:bus:produce\") };\npermit(principal, action == Action::\"sentin8:bus:produce\", resource) when { principal.scopes.contains(\"sentin8:bus:admin\") };\npermit(principal, action == Action::\"sentin8:bus:consume\", resource) when { principal.scopes.contains(\"sentin8:bus:consume\") };\npermit(principal, action == Action::\"sentin8:bus:consume\", resource) when { principal.scopes.contains(\"sentin8:bus:admin\") };\npermit(principal, action == Action::\"sentin8:bus:admin\", resource) when { principal.scopes.contains(\"sentin8:bus:admin\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

const RELATIONS: &[RelationDecl] = &[];

const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "bus-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:bus",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:bus:admin",
        ],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:bus-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "bus-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-bus-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Handle print.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:bus",
        subdomain: "bus",
        health_path: "/v1/health",
        admin_scopes: &[
            AdminScope::Tuple("sentin8:bus:admin", "sentin8:bus:admin"),
            AdminScope::Tuple("sentin8:bus:admin", "sentin8:bus:produce"),
            AdminScope::Tuple("sentin8:bus:admin", "sentin8:bus:consume"),
            AdminScope::Tuple("sentin8:bus:admin", "sentin8:bus:policy:read"),
            AdminScope::Tuple("sentin8:bus:admin", "sentin8:bus:policy:write"),
        ],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Bus",
            icon: "0xe60f",
            service_flag: "bus",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
