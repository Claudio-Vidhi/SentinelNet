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
    source         TEXT,                      -- listener di origine: ipfix|netflow|sflow (NULL = legacy)
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
    site_id          TEXT,
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

-- 8. INCIDENTI (v5): raggruppamento di correlated_events per entità condivisa
-- + gap temporale. Un incidente resta aperto (closed_ts NULL) finché arrivano
-- eventi; dopo un periodo di quiete viene chiuso.
CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY,
    tenant         TEXT NOT NULL,
    entity_key     TEXT NOT NULL,      -- 'ip:10.0.0.5' | 'port:sw01:Gi1/0/12'
    opened_ts      INTEGER NOT NULL,
    last_event_ts  INTEGER NOT NULL,
    closed_ts      INTEGER,            -- NULL = aperto, accetta nuovi eventi
    title          TEXT,
    severity       INTEGER,            -- la peggiore (min) fra gli eventi
    event_count    INTEGER NOT NULL DEFAULT 0,
    status         TEXT DEFAULT 'new' CHECK(status IN ('new','ack','resolved')),
    cause_kind     TEXT,               -- regola deterministica che ha concluso
    confidence     INTEGER,            -- 0-100, deterministico
    reasoning_json TEXT,               -- {cause, rules_fired[], sources_used[], evidence_refs[]}
    ai_narrative    TEXT,              -- prosa LLM: MAI la conclusione
    ai_narrative_ts INTEGER,
    ai_assisted     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incidents_open
    ON incidents(tenant, closed_ts, last_event_ts);
CREATE INDEX IF NOT EXISTS idx_incidents_entity
    ON incidents(tenant, entity_key, closed_ts);

-- Appartenenza evento→incidente. correlated_event_id NON ha FK: correlated_events
-- ha una retention propria (rollup.py) e un CASCADE da lì svuoterebbe in silenzio
-- gli incidenti.
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id         INTEGER NOT NULL,
    correlated_event_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, correlated_event_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incident_events_ce
    ON incident_events(correlated_event_id);

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

