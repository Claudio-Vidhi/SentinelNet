-- observability.db — schema v1 (vedi docs/MASTER-IMPLEMENTATION-PLAN.md §1.3)
-- Migrazioni forward-only e idempotenti: ogni statement usa IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

-- 1. (removed) flow_aggregates held NetFlow/IPFIX/sFlow buckets. The flow
-- listeners are gone; databases created before keep the table, untouched and
-- no longer read or written. New databases do not create it.

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

-- 3. (removed in v7) ``correlated_events`` and ``incident_events``. A database
-- older than v7 keeps them, untouched and no longer read.

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

-- 6. ALLERTE SIEM SOPPRESSE (Flow SIEM): riferimento a syslog_events.id.
-- Prima la soppressione era un no-op che rispondeva {"suppressed": true}
-- senza scrivere nulla: l'allerta ricompariva al refresh successivo.
CREATE TABLE IF NOT EXISTS siem_suppressions (
    event_id      INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    tenant        TEXT,
    reason        TEXT,
    suppressed_by TEXT
);

-- 7. TEMPLATE CHECKLIST AUDIT (v4: audit manutenzione firewall)
CREATE TABLE IF NOT EXISTS audit_templates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    version      INTEGER NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    status       TEXT NOT NULL CHECK(status IN ('draft', 'published', 'archived')),
    created_ts   INTEGER NOT NULL,
    created_by   TEXT NOT NULL DEFAULT 'system',
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS audit_template_items (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id       INTEGER NOT NULL,
    ref               TEXT NOT NULL,
    section_no        INTEGER NOT NULL,
    section_title     TEXT NOT NULL,
    title             TEXT NOT NULL,
    guidance_why      TEXT,
    guidance_good     TEXT,
    guidance_how      TEXT,
    thresholds_json   TEXT,
    check_kind        TEXT NOT NULL CHECK(check_kind IN ('manual', 'semi', 'auto')),
    severity_default  TEXT NOT NULL,
    is_prerequisite   INTEGER NOT NULL DEFAULT 0,
    requires_evidence INTEGER NOT NULL DEFAULT 0,
    sort_order        INTEGER NOT NULL,
    FOREIGN KEY (template_id) REFERENCES audit_templates(id) ON DELETE CASCADE,
    UNIQUE(template_id, ref)
);
CREATE INDEX IF NOT EXISTS idx_audit_tpl_items_tpl ON audit_template_items(template_id);

CREATE TABLE IF NOT EXISTS audit_engagements (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_name    TEXT NOT NULL,
    tenant           TEXT,
    location_id      TEXT,
    template_id      INTEGER NOT NULL,
    status           TEXT NOT NULL CHECK(status IN ('draft', 'in_progress', 'completed')),
    created_ts       INTEGER NOT NULL,
    updated_ts       INTEGER NOT NULL,
    created_by       TEXT NOT NULL DEFAULT 'system',
    assigned_to      TEXT,
    scope_notes      TEXT,
    onsite_or_remote TEXT DEFAULT 'remote',
    interviewee      TEXT,
    FOREIGN KEY (template_id) REFERENCES audit_templates(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_eng_status ON audit_engagements(status);

CREATE TABLE IF NOT EXISTS audit_engagement_items (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id       INTEGER NOT NULL,
    item_ref            TEXT NOT NULL,
    status              TEXT NOT NULL CHECK(status IN ('non_valutato', 'conforme', 'parziale', 'non_conforme', 'non_applicabile', 'da_verificare')),
    severity            TEXT CHECK(severity IN ('critica', 'alta', 'media', 'bassa', 'osservazione')),
    finding_text        TEXT,
    recommendation_text TEXT,
    assessed_by         TEXT,
    assessed_ts         INTEGER,
    ai_assisted         INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (engagement_id) REFERENCES audit_engagements(id) ON DELETE CASCADE,
    UNIQUE(engagement_id, item_ref)
);
CREATE INDEX IF NOT EXISTS idx_audit_eng_items_eng ON audit_engagement_items(engagement_id);

CREATE TABLE IF NOT EXISTS audit_evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    item_ref      TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK(kind IN ('file', 'config_ref', 'note', 'scan_finding')),
    payload_json  TEXT,
    filename      TEXT,
    path          TEXT,
    uploaded_ts   INTEGER NOT NULL,
    confidential  INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (engagement_id) REFERENCES audit_engagements(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_evidence_eng_ref ON audit_evidence(engagement_id, item_ref);

-- 10. MODELLO EVENTI UNIFICATO (v6): ogni sorgente viene proiettata qui da
-- observability/normalize.py. Its readers (Interfaces, interface errors,
-- diagnosis, SIEM notifications) read only this table: the raw tables stay
-- the provenance, not the contract.
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,       -- quando è successo
    ingested_ts  INTEGER NOT NULL,       -- quando è stato normalizzato
    tenant       TEXT NOT NULL,
    source       TEXT NOT NULL,          -- syslog|fortigate_api|snmp|linux|platform
    source_id    INTEGER,                -- id nella tabella d'origine (provenienza)
    event_type   TEXT NOT NULL,          -- log.security|log.event|device.state|device.change|platform.exporter_unknown
    entity_type  TEXT NOT NULL,          -- device|interface|exporter (flow: legacy rows only)
    entity_id    TEXT NOT NULL,          -- '10.1.0.5>8.8.8.8' | '10.1.0.254' | '10.1.0.254:port1'
    severity     INTEGER,                -- scala syslog 0-7
    device_ip    TEXT,
    interface    TEXT,
    src_ip       TEXT,
    dst_ip       TEXT,
    dst_port     INTEGER,
    protocol     TEXT,
    metrics_json TEXT,                   -- byte/pacchetti/valori misurati
    attrs_json   TEXT,                   -- resto normalizzato (azione, campo cambiato, ...)
    dedup_key    TEXT UNIQUE             -- rientri idempotenti
);
CREATE INDEX IF NOT EXISTS idx_events_ts_tenant  ON events(ts, tenant);
CREATE INDEX IF NOT EXISTS idx_events_type       ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_entity     ON events(tenant, entity_id, ts);
-- Covering index for "latest event per entity of a given type". Without it the
-- port-channel report's GROUP BY built a temp B-tree over every interface.state
-- row in the table (~3.1s on a 1M-row events table); with it the same lookup is
-- a covering index scan.
CREATE INDEX IF NOT EXISTS idx_events_type_entity ON events(event_type, tenant, entity_id, id);
-- Served the removed correlator's ingested_ts lookup. Kept: dropping it from
-- existing databases would need a migration.
CREATE INDEX IF NOT EXISTS idx_events_ingested   ON events(ingested_ts);

-- Posizione raggiunta da ogni adapter di normalizzazione: la tabella È il bus,
-- i consumatori avanzano leggendo per posizione.
CREATE TABLE IF NOT EXISTS normalize_cursors (
    source   TEXT PRIMARY KEY,
    last_id  INTEGER NOT NULL DEFAULT 0,
    last_ts  INTEGER NOT NULL DEFAULT 0
);

-- 8, 11, 12. (removed) incidents, evidence and incident_conclusions held the
-- incidents engine. It is gone; databases created before keep the tables,
-- no longer written, and retention empties them. New databases do not create
-- them.

CREATE TABLE IF NOT EXISTS audit_engagement_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    item_ref      TEXT,
    action        TEXT NOT NULL,
    details_json  TEXT,
    actor         TEXT NOT NULL DEFAULT 'system',
    ts            INTEGER NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES audit_engagements(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_audit_hist_eng ON audit_engagement_history(engagement_id);


-- 13. CONVERSAZIONI AI (v9): la chat dell'assistente perdeva tutto al cambio
-- tab. I messaggi stanno in un'unica colonna JSON perché la conversazione si
-- legge e si riscrive sempre intera (ogni turno rispedisce la storia completa
-- al provider): una tabella di messaggi non servirebbe a nessuna query.
-- ``username`` è il proprietario: ogni lettura e ogni scrittura filtrano su
-- di esso, una conversazione non è mai visibile a un altro utente.
CREATE TABLE IF NOT EXISTS ai_conversations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL,
    title         TEXT NOT NULL,
    messages_json TEXT NOT NULL,
    created_ts    INTEGER NOT NULL,
    updated_ts    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_conv_user
    ON ai_conversations(username, updated_ts DESC);


-- Saved NetSec Audit runs. Opt-in: the scan route writes here only when the
-- caller asked to keep the run. The whole result document is kept, because a
-- score without the findings behind it cannot be acted on later, and re-running
-- against a config that has since changed answers a different question.
CREATE TABLE IF NOT EXISTS netsec_audit_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    -- NULL for a pasted config: nothing to scope it by, so only unrestricted
    -- users see it.
    tenant          TEXT,
    device_name     TEXT,
    device_ip       TEXT,
    benchmark       TEXT NOT NULL,
    benchmark_title TEXT NOT NULL,
    vendor          TEXT NOT NULL,
    lang            TEXT NOT NULL,
    -- NULL when every rule came back UNKNOWN: score_rules() returns None
    -- rather than inventing a number, and 0 would read as "everything failed".
    score           INTEGER,
    summary_json    TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    actor           TEXT NOT NULL,
    run_name        TEXT
);

CREATE INDEX IF NOT EXISTS idx_netsec_audit_runs_tenant_ts
    ON netsec_audit_runs (tenant, ts DESC);


-- 14. NOTIFICHE EMAIL (v12)
CREATE TABLE IF NOT EXISTS notify_prefs (
    username               TEXT PRIMARY KEY,
    enabled                INTEGER NOT NULL DEFAULT 1,
    kinds_json             TEXT NOT NULL DEFAULT '["siem.alert","device.down","device.up","cve.new"]',
    min_severity           TEXT NOT NULL DEFAULT 'low',
    groups_json            TEXT NOT NULL DEFAULT '[]',
    mode                   TEXT NOT NULL DEFAULT 'immediate',
    digest_every_min       INTEGER NOT NULL DEFAULT 60,
    quiet_start            TEXT,
    quiet_end              TEXT,
    quiet_bypass_critical  INTEGER NOT NULL DEFAULT 1
);

-- Sidebar favorites, per user: the tab ids in the order they were added.
-- Additive table, no version bump: older code ignores it.
CREATE TABLE IF NOT EXISTS ui_favorites (
    username   TEXT PRIMARY KEY,
    tabs_json  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS notify_rules (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    name                   TEXT NOT NULL,
    enabled                INTEGER NOT NULL DEFAULT 1,
    recipients_json        TEXT NOT NULL,
    kinds_json             TEXT NOT NULL,
    min_severity           TEXT NOT NULL DEFAULT 'low',
    groups_json            TEXT NOT NULL DEFAULT '[]',
    mode                   TEXT NOT NULL DEFAULT 'immediate',
    digest_every_min       INTEGER NOT NULL DEFAULT 60,
    quiet_start            TEXT,
    quiet_end              TEXT,
    quiet_bypass_critical  INTEGER NOT NULL DEFAULT 1,
    created_by             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notify_outbox (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    device_ip   TEXT,
    grp         TEXT,
    title       TEXT NOT NULL,
    ctx_json    TEXT NOT NULL DEFAULT '{}',
    dedup_key   TEXT,
    created_ts  INTEGER NOT NULL,
    due_ts      INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_notify_outbox_due ON notify_outbox(due_ts, target);

CREATE TABLE IF NOT EXISTS notify_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    target      TEXT NOT NULL,
    recipient   TEXT NOT NULL,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL CHECK(status IN ('sent', 'failed', 'suppressed')),
    error       TEXT,
    item_count  INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_notify_log_ts ON notify_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_notify_log_target ON notify_log(target, ts DESC);

CREATE TABLE IF NOT EXISTS notify_cursors (
    source   TEXT PRIMARY KEY,
    last_id  INTEGER NOT NULL DEFAULT 0
);

-- 15. TRIAGE PROGRAMMATO (v13): pianificazione periodica automatica del triage
-- apparati per tenant e lista dispositivi in base ai permessi utente.
CREATE TABLE IF NOT EXISTS scheduled_triage (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    tenant           TEXT NOT NULL,
    devices_json     TEXT,
    interval_minutes INTEGER NOT NULL DEFAULT 360,
    created_by       TEXT NOT NULL,
    created_ts       REAL NOT NULL,
    last_run_ts      REAL,
    next_run_ts      REAL NOT NULL,
    last_status      TEXT,
    last_summary     TEXT
);
CREATE INDEX IF NOT EXISTS idx_scheduled_triage_due ON scheduled_triage(enabled, next_run_ts);

CREATE TABLE IF NOT EXISTS scheduled_triage_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    schedule_id   INTEGER NOT NULL,
    ts            REAL NOT NULL,
    tenant        TEXT NOT NULL,
    device_count  INTEGER NOT NULL,
    success_count INTEGER NOT NULL,
    error_count   INTEGER NOT NULL,
    status        TEXT NOT NULL,
    summary       TEXT,
    FOREIGN KEY(schedule_id) REFERENCES scheduled_triage(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_scheduled_triage_log_sched ON scheduled_triage_log(schedule_id, ts DESC);



-- 16. LETTURE ON DEMAND DEI CONTATORI DI ERRORE (v14): due letture a pochi
-- secondi di distanza (SNMP se l'apparato ha una community, altrimenti SSH).
-- Una riga per lettura, col risultato gia' calcolato per porta:
-- {"<interfaccia>": {"counters": {...}, "delta": {...}, "status": "..."}}.
-- Le letture periodiche restano negli eventi interface.state (metrics_json).
CREATE TABLE IF NOT EXISTS iface_counter_reads (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    tenant        TEXT NOT NULL,
    device_ip     TEXT NOT NULL,
    source        TEXT NOT NULL,            -- snmp | cli
    interval_s    INTEGER NOT NULL,
    requested_by  TEXT,
    result_json   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iface_counter_reads_dev
    ON iface_counter_reads(tenant, device_ip, ts);
