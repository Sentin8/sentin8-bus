-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Bus — event bus service (DBX, architecture-principles §6.7).
--
-- `bus.inbox` is BUS-INTERNAL DURABILITY ONLY: it is written exclusively by
-- Bus's `POST /v1/produce` handler (persisting accepted produce requests
-- before the XADD) and drained by Bus's own relay under
-- `sentin8_bus_service` (NOBYPASSRLS). Producers hold NO grants on this
-- table — they write their own local `{service}.outbox` and push via the
-- produce API. The former BYPASSRLS `sentin8_bus_relay` role is RETIRED.
--
-- Every produce-persisted row carries the publisher identity token
-- (`publisher_id_token`) — the JWT that authenticated the request which
-- triggered the domain change (bus design §4.5) — enabling subscriber-side
-- delegation via RFC 8693 token exchange.

CREATE SCHEMA IF NOT EXISTS bus;
CREATE TABLE IF NOT EXISTS bus.inbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    -- Event type, e.g. "ledger.account.created".
    event_type      TEXT NOT NULL,
    -- Stream family for Redis stream routing, e.g. "ledger". DBX: derived
    -- by Bus from the verified M2M token identity (bus design §4.3a) — the
    -- PG-role-derived resolver (sentin8_bus_current_stream_family) is retired.
    stream_family   TEXT NOT NULL,
    -- JSON event payload.
    payload         JSONB NOT NULL,
    -- Publisher identity token — the JWT (compact serialization) that
    -- authenticated the request which triggered this event (bus design §4.5).
    publisher_id_token  TEXT,
    -- Extracted `sub` claim from the publisher token — for audit queries
    -- and correlation without parsing the full JWT.
    publisher_subject   TEXT,
    -- The verified producer's vertical claim (VDC-2, design/
    -- sentin8-vertical-data-plane-contract.md §VDC.4) — recorded at
    -- produce from the M2M token; re-attached on the relay XADD so
    -- relay-delivered messages carry the same provenance the inline
    -- write does (consumers assert it via `require_publisher`).
    publisher_vertical  TEXT,
    -- Relay state.
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    -- Stream entry id (`<ms>-<seq>`) stamped by the produce handler when its
    -- inline XADD succeeds — single-entry delivery (bus design §4.3b): the
    -- relay skips rows that already carry a message_id, so a produce-path
    -- XADD and the relay drain never publish the same event twice.
    stream_message_id   TEXT,
    -- Timestamps.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, event_type, publisher_subject, created_at)
);

-- Idempotency: the produce API rejects a duplicate idempotency_key per env
-- before INSERT (application-level check); the UNIQUE constraint above is a
-- structural backstop against exact-duplicate persistence.

-- Index for the relay's `WHERE relayed = false ORDER BY created_at` query.
CREATE INDEX IF NOT EXISTS idx_bus_inbox_unrelayed
    ON bus.inbox (created_at)
    WHERE relayed = false;

-- Index for per-family lag queries.
CREATE INDEX IF NOT EXISTS idx_bus_inbox_family
    ON bus.inbox (stream_family, relayed)
    WHERE relayed = false;

-- Index for publisher-subject audit queries.
CREATE INDEX IF NOT EXISTS idx_bus_inbox_publisher
    ON bus.inbox (publisher_subject, created_at)
    WHERE publisher_subject IS NOT NULL;

-- ── RLS (bus-internal table) ─────────────────────────────────────────────
-- Only Bus writes this table (the produce handler + relay, both running
-- under `sentin8_bus_service`). The SELECT policy admits bus's own role
-- with tenant context; every other role sees nothing.
ALTER TABLE bus.inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE bus.inbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS bus_inbox_select ON bus.inbox;
CREATE POLICY bus_inbox_select ON bus.inbox FOR SELECT
    USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS bus_inbox_insert ON bus.inbox;
CREATE POLICY bus_inbox_insert ON bus.inbox FOR INSERT
    WITH CHECK (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

-- UPDATE: only the in-bus relay marks rows relayed (same role, same tenant).
DROP POLICY IF EXISTS bus_inbox_update ON bus.inbox;
CREATE POLICY bus_inbox_update ON bus.inbox FOR UPDATE
    USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

-- ── LISTEN/NOTIFY: push-based relay wakeup ─────────────────────────────
-- Bus's own relay wakes on NOTIFY (millisecond latency); a 5s safety poll
-- in the relay catches missed notifications (NOTIFY is not durable).
CREATE OR REPLACE FUNCTION bus.bus_notify_inbox() RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('bus_inbox_changed', '');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS bus_inbox_notify_trigger ON bus.inbox;
CREATE TRIGGER bus_inbox_notify_trigger
    AFTER INSERT ON bus.inbox
    FOR EACH ROW
    EXECUTE FUNCTION bus.bus_notify_inbox();

-- ── Grants ─────────────────────────────────────────────────────────────
-- bus.inbox is written + read ONLY by `sentin8_bus_service` (the produce
-- handler and the in-bus relay). No producer grants exist (DBX §6.7).
GRANT USAGE ON SCHEMA bus TO sentin8_bus_service;
GRANT SELECT, INSERT, UPDATE ON bus.inbox TO sentin8_bus_service;

-- ── Sentin8:Policy boot loader (policy design §4.2b-r) ────────────────────
-- The bus process boot-loads its policy engine. Guarded copy of the sys
-- definition (sys owns the table — bus's init.sql may run first on a fresh
-- bootstrap; the missing-table case degrades and sys's init.sql recreates
-- the function).
DO $$
BEGIN
    CREATE OR REPLACE FUNCTION public.sentin8_boot_policy_load(p_service TEXT)
    RETURNS TABLE (
        id              UUID,
        env_id          UUID,
        service         TEXT,
        policy_set_name TEXT,
        description     TEXT,
        policies        TEXT,
        schema          TEXT,
        origin          TEXT,
        mode            TEXT,
        version         INT,
        enabled         BOOLEAN
    )
    LANGUAGE sql SECURITY DEFINER SET search_path = sys, public AS $func$
        SELECT id, env_id, service, policy_set_name, description,
               policies, schema, origin, mode, version, enabled
          FROM sys.policy_sets
         WHERE service = p_service AND enabled;
    $func$;
    GRANT EXECUTE ON FUNCTION public.sentin8_boot_policy_load(TEXT) TO sentin8_bus_service;
EXCEPTION WHEN undefined_table THEN NULL;
END $$;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: bus.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("bus").
CREATE TABLE IF NOT EXISTS bus.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bus_outbox_unrelayed
    ON bus.outbox (created_at) WHERE relayed = false;
ALTER TABLE bus.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE bus.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON bus.outbox;
CREATE POLICY outbox_select ON bus.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON bus.outbox;
CREATE POLICY outbox_insert ON bus.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON bus.outbox;
CREATE POLICY outbox_update ON bus.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION bus.bus_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('bus_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON bus.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON bus.outbox
    FOR EACH ROW
    EXECUTE FUNCTION bus.bus_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("bus").
CREATE TABLE IF NOT EXISTS bus.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bus_audit_journal_unpushed
    ON bus.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE bus.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE bus.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON bus.audit_journal;
CREATE POLICY audit_journal_dml ON bus.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Grants (after every table exists — GRANT on a not-yet-created table
-- aborts the whole init migration on a fresh bootstrap) ────────────────
GRANT SELECT, INSERT, UPDATE, DELETE ON bus.outbox TO sentin8_bus_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON bus.audit_journal TO sentin8_bus_service;
