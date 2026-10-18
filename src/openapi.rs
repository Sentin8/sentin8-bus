// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

use utoipa::OpenApi;

use crate::handlers;

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::produce,
        handlers::produce_batch,
        handlers::consume,
        handlers::ack,
        handlers::nack,
        handlers::list_dlq,
        handlers::replay_dlq,
        handlers::list_streams,
        handlers::schedule,
        handlers::list_scheduled,
        handlers::stream_lag,
        handlers::metrics,
        handlers::health,
        crate::sse::sse_handler,
        crate::admin_ui::get_admin_ui,
        crate::admin_ui::get_admin_data,
        // Shield policy-admin surface — the shared annotated wrappers in
        // the shell (same wire contract the generic handlers above serve;
        // utoipa cannot path a generic handler — OAPEC design §2 rule 3).
        sentin8::shell::policy_list_sets,
        sentin8::shell::policy_get_set,
        sentin8::shell::policy_put_set,
        sentin8::shell::policy_delete_set,
        sentin8::shell::policy_test_set,
        sentin8::shell::policy_mode_enforce,
        sentin8::shell::policy_mode_shadow,
        sentin8::shell::policy_mode_disable,
        sentin8::shell::policy_list_relations,
        sentin8::shell::policy_put_relation,
        sentin8::shell::policy_delete_relation,
        sentin8::shell::policy_check_relation,
        sentin8::shell::policy_list_attributes,
        sentin8::shell::policy_put_attribute,
        sentin8::shell::policy_delete_attribute,
    ),
    components(schemas(
        sentin8::bus::contracts::ProduceRequest,
        sentin8::bus::contracts::ProduceResponse,
        sentin8::bus::contracts::ProduceBatchRequest,
        sentin8::bus::contracts::ProduceBatchResponse,
        sentin8::bus::contracts::ProduceBatchItem,
        handlers::ConsumeRequest,
        handlers::ConsumeResponse,
        handlers::ConsumeMessage,
        handlers::AckRequest,
        handlers::NackRequest,
        handlers::DlqQuery,
        handlers::DlqReplayRequest,
        handlers::ScheduleRequest,
        handlers::ScheduleResponse,
        crate::sse::SseQuery,
        crate::admin_ui::TargetEnvQuery,
        sentin8::shield::admin::PutPolicySetBody,
        sentin8::shield::admin::TestPolicySetBody,
        sentin8::shield::admin::PolicyModeBody,
        sentin8::shield::admin::PutRelationBody,
        sentin8::shield::admin::DeleteRelationQuery,
        sentin8::shield::admin::RelationCheckQuery,
        sentin8::shield::admin::PutAttributeBody,
        sentin8::shield::admin::ListAttributesQuery,
        sentin8::shield::admin::DeleteAttributeQuery,
    )),
    security(),
    tags(
        (name = "bus", description = "Sentin8:Bus admin API — produce, consume, ack, DLQ, streams, metrics"),
    ),
)]
/// The busopenapi type.
pub struct BusOpenApi;
