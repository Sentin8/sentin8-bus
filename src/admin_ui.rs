// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;
use sqlx::Row;

#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    target_env_id: Option<String>,
}

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = serde_json::Value),
        (status = 403, description = "Caller lacks a bus read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:bus:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(_q): Query<TargetEnvQuery>,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify(&state.workload_registry, &state.config, &headers).await?;
    if !a.has_any_scope(&[
        "sentin8:bus:read",
        "sentin8:bus:admin",
        "sentin8:bus:consume",
        "sentin8:bus:produce",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
        "sentin8:env:admin",
    ]) {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "missing admin scope".into(),
        ));
    }
    let def = match page.as_str() {
        "overview" => AdminPage::new("Bus Overview")
            .widget(card(
                "Summary",
                "Active streams, consumer groups, produce/consume rates.",
            ))
            .build(),
        "streams" => AdminPage::new("Streams")
            .widget(table(
                vec![
                    col("id", "Stream ID"),
                    cols("name", "Name"),
                    cols("stream_family", "Stream Family"),
                    cols("consumer_count", "Consumers"),
                ],
                "/streams",
            ))
            .build(),
        "consumers" => AdminPage::new("Consumers")
            .widget(table(
                vec![
                    col("stream_family", "Stream"),
                    cols("consumer_group", "Consumer Group"),
                    cols("consumer_name", "Consumer"),
                    cols("pending", "Pending"),
                ],
                "/consumers",
            ))
            .build(),
        "metrics" => AdminPage::new("Metrics")
            .widget(card(
                "Metrics",
                "Produce/consume count, latency, lag, DLQ depth.",
            ))
            .build(),
        "dlq" => AdminPage::new("Dead Letter Queue")
            .widget(table_with_actions(
                vec![col("score", "Score"), cols("data", "Entry")],
                "/dlq",
                vec![row_action_post("Replay", "dlq/{id}/replay")],
            ))
            .build(),

        p if sentin8::rfw::policy_page("sentin8:bus", p).is_some() => {
            sentin8::rfw::policy_page("sentin8:bus", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// Fetch admin data.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource (streams, dlq, ...)"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks a bus read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:bus:read" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::verify(&state.workload_registry, &state.config, &headers).await?;
    if !a.has_any_scope(&[
        "sentin8:bus:read",
        "sentin8:bus:admin",
        "sentin8:bus:consume",
        "sentin8:bus:produce",
        "sentin8:sys:admin",
        "sentin8:sys:org:admin",
        "sentin8:sys:env:admin",
        "sentin8:env:admin",
    ]) {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "missing admin scope".into(),
        ));
    }
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing target_env_id".into(),
            )
        })?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "streams" => sqlx::query("SELECT id::text, event_type, stream_family, relayed::text FROM inbox WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100")
            .bind(env_id)
            .fetch_all(&state.pool).await
            .map(|rows| rows.iter().map(|row| serde_json::json!({
                "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                "name": row.get::<Option<String>, &str>("event_type").unwrap_or_default(),
                "stream_family": row.get::<Option<String>, &str>("stream_family").unwrap_or_default(),
                "consumer_count": row.get::<Option<String>, &str>("relayed").unwrap_or_default(),
            })).collect()).unwrap_or_default(),
        "consumers" => {



            let pattern = format!("bus:{}:*", env_id);
            let mut rows_out: Vec<serde_json::Value> = Vec::new();
            let con = state.valkey.clone();

            let mut cursor: u64 = 0;
            loop {
                let (next_cursor, keys): (u64, Vec<String>) = glide::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&con)
                    .await
                    .unwrap_or((0, vec![]));
                for key in &keys {



                    let type_ok = glide::cmd("TYPE")
                        .arg(key)
                        .query_async::<String>(&con)
                        .await
                        .unwrap_or_default();
                    if type_ok != "stream" {
                        continue;
                    }

                    if let Ok(info) = glide::cmd("XINFO")
                        .arg("GROUPS")
                        .arg(key)
                        .query_async::<Vec<Vec<String>>>(&con)
                        .await
                    {
                        for group in info {
                            rows_out.push(serde_json::json!({
                                "stream_family": key.trim_start_matches(&format!("bus:{}:", env_id)),
                                "consumer_group": group.first().cloned().unwrap_or_default(),
                                "consumer_name": group.get(1).cloned().unwrap_or_default(),
                                "pending": group.get(2).cloned().unwrap_or_default(),
                            }));
                        }
                    }
                }
                if next_cursor == 0 {
                    break;
                }
                cursor = next_cursor;
            }
            rows_out
        }
        "dlq" => {
            let dlq_key = format!("bus:dlq:{}", env_id);
            let con = state.valkey.clone();
            let entries: Vec<(f64, String)> = glide::cmd("ZRANGE")
                .arg(&dlq_key)
                .arg(0)
                .arg(-1)
                .arg("WITHSCORES")
                .query_async(&con)
                .await
                .unwrap_or_default();
            entries.into_iter().map(|(score, data)| serde_json::json!({
                "score": score.to_string(),
                "data": data,
            })).collect()
        }
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
#[allow(dead_code)]
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}
