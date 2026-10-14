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
    )),
    security(),
    tags(
        (name = "bus", description = "Sentin8:Bus admin API — produce, consume, ack, DLQ, streams, metrics"),
    ),
)]
/// The busopenapi type.
pub struct BusOpenApi;
