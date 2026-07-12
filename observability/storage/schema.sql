-- observability.db — schema v1 (vedi docs/MASTER-IMPLEMENTATION-PLAN.md §1.3)
-- Migrazioni forward-only e idempotenti: ogni statement usa IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

-- 1. FLUSSI AGGREGATI (rollup al minuto via UPSERT — vedi 1.4)
CREATE TABLE IF NOT EXISTS flow_aggregates (
    window_start   INTEGER NOT NULL,          -- unix ts troncato a 60s
    tenant         TEXT NOT NULL,             -- gruppo/sede (scope multi-gruppo)
    src_ip         TEXT NOT NULL,
    dst_ip         TEXT NOT NULL,
    protocol       INTEGER,
    dst_port       INTEGER,
    total_bytes    INTEGER NOT NULL DEFAULT 0,
    total_packets  INTEGER NOT NULL DEFAULT 0,
    flow_count     INTEGER NOT NULL DEFAULT 0,
    exporter_ip    TEXT,
    UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
);
CREATE INDEX IF NOT EXISTS idx_flow_window_tenant
    ON flow_aggregates(window_start, tenant);
CREATE INDEX IF NOT EXISTS idx_flow_src_dst
    ON flow_aggregates(src_ip, dst_ip);

-- 2. EVENTI SYSLOG normalizzati
CREATE TABLE IF NOT EXISTS syslog_events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    tenant      TEXT NOT NULL,
    device_ip   TEXT,
    severity    INTEGER,
    action      TEXT,
    message     TEXT,
    exporter_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_syslog_ts_tenant ON syslog_events(ts, tenant);
CREATE INDEX IF NOT EXISTS idx_syslog_src ON syslog_events(device_ip);

-- 3. EVENTI CORRELATI (popolati dal correlatore, fase 4)
CREATE TABLE IF NOT EXISTS correlated_events (
    id            INTEGER PRIMARY KEY,
    created_ts    INTEGER NOT NULL,
    tenant        TEXT NOT NULL,
    kind          TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    switch_port   TEXT,
    severity      INTEGER,
    status        TEXT DEFAULT 'new' CHECK(status IN ('new','ack','resolved')),
    dedup_key     TEXT UNIQUE,
    evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_corr_tenant_status
    ON correlated_events(tenant, status);

-- 5. OSSERVAZIONI API (schema v2, §9.2): snapshot periodici via REST poller.
CREATE TABLE IF NOT EXISTS api_observations (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    tenant       TEXT NOT NULL,
    device_ip    TEXT NOT NULL,
    kind         TEXT NOT NULL,            -- system_status | interfaces | sessions | wifi_clients ...
    summary_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_apiobs_device_kind_ts
    ON api_observations(device_ip, kind, ts);

-- 4. EXPORTER SCONOSCIUTI in quarantena (ingest 3.5)
CREATE TABLE IF NOT EXISTS quarantined_exporters (
    exporter_ip  TEXT PRIMARY KEY,
    first_seen   INTEGER,
    last_seen    INTEGER,
    packet_count INTEGER NOT NULL DEFAULT 0
);
