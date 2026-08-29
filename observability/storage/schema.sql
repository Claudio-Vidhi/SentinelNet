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

-- 3. (rimossa in v7) ``correlated_events`` e ``incident_events`` sono state
-- sostituite da ``evidence``: il correlatore non produce più incidenti diretti
-- ma evidenze, e l'incidente è una vista derivata. Le righe preesistenti
-- vengono travasate da core/db.py::_migrate_v7_evidence.

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

-- 10. MODELLO EVENTI UNIFICATO (v6): ogni sorgente viene proiettata qui da
-- observability/normalize.py. Tutto ciò che viene dopo (correlazione,
-- ragionamento, baseline, knowledge base) legge SOLO questa tabella: le
-- tabelle grezze restano la provenienza, non il contratto.
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,       -- quando è successo
    ingested_ts  INTEGER NOT NULL,       -- quando è stato normalizzato
    tenant       TEXT NOT NULL,
    source       TEXT NOT NULL,          -- netflow|ipfix|sflow|syslog|fortigate_api|snmp|linux|platform
    source_id    INTEGER,                -- id nella tabella d'origine (provenienza)
    event_type   TEXT NOT NULL,          -- flow.aggregate|log.security|log.event|device.state|device.change|platform.exporter_unknown
    entity_type  TEXT NOT NULL,          -- flow|device|interface|exporter
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
-- Il correlatore seleziona per ts OPPURE per ingested_ts (vedi correlator.py):
-- senza questo indice il secondo ramo dell'OR sarebbe una scansione.
CREATE INDEX IF NOT EXISTS idx_events_ingested   ON events(ingested_ts);

-- Posizione raggiunta da ogni adapter di normalizzazione: la tabella È il bus,
-- i consumatori avanzano leggendo per posizione.
CREATE TABLE IF NOT EXISTS normalize_cursors (
    source   TEXT PRIMARY KEY,
    last_id  INTEGER NOT NULL DEFAULT 0,
    last_ts  INTEGER NOT NULL DEFAULT 0
);

-- 8. INCIDENTI (v5, ridefiniti in v7): raggruppamento delle EVIDENZE per
-- entità condivisa + gap temporale. Un incidente resta aperto (closed_ts NULL) finché arrivano
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
    resolved_ts    INTEGER,            -- istante della transizione a resolved:
                                       -- ancora la retention (v10). NULL finché aperto.
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

-- 11. EVIDENZE (v7): il Correlation Engine NON produce più incidenti, produce
-- evidenze. L'incidente è una vista derivata da esse.
--
--     events → regole di correlazione → evidence → incidents
--
-- Una riga di evidenza È l'associazione evento↔incidente: lo stesso evento può
-- essere evidenza per più incidenti (righe distinte), cosa che una colonna
-- correlation_id sull'evento non potrebbe esprimere.
--
-- ``role``: il ruolo causale è DICHIARATO DALLA REGOLA, mai dedotto. Sapere
-- che un aumento di traffico è conseguenza e non innesco richiede la direzione
-- causale, che la regola conosce per costruzione e un'euristica indovina.
--
-- ``rule_id``/``rule_version``/``params_json``: provenienza. La versione da
-- sola non basta, perché le soglie sono modificabili dall'admin a runtime:
-- stessa versione + soglia diversa = esito diverso. Le soglie EFFETTIVAMENTE
-- usate vengono quindi salvate qui accanto alla versione.
CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY,
    created_ts   INTEGER NOT NULL,          -- quando la regola ha concluso
    ts           INTEGER NOT NULL,          -- quando è successo il fatto
    tenant       TEXT NOT NULL,
    incident_id  INTEGER,                   -- NULL = non ancora assegnata
    event_id     INTEGER,                   -- events.id (NULL solo per il backfill legacy)
    entity_key   TEXT,                      -- 'ip:10.1.0.5' | 'port:sw01:Gi1/0/12'
    role         TEXT NOT NULL CHECK(role IN ('trigger','supporting','symptom','consequence')),
    rule_id      TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    params_json  TEXT,                      -- soglie effettive al momento dello scatto
    weight       INTEGER NOT NULL DEFAULT 1,
    severity     INTEGER,
    src_ip       TEXT,
    dst_ip       TEXT,
    switch_port  TEXT,
    summary      TEXT,                      -- una riga leggibile dall'ingegnere
    attrs_json   TEXT,
    dedup_key    TEXT UNIQUE,
    -- v8 — ciclo di vita, tenuto DELIBERATAMENTE minimo: active → retracted,
    -- nient'altro. Ogni altra sfumatura vive nel ragionamento, non qui.
    -- Un'evidenza ritrattata NON viene cancellata: il sistema deve poter dire
    -- "avevamo concluso X, poi un fatto nuovo l'ha invalidata".
    status                  TEXT NOT NULL DEFAULT 'active'
                            CHECK(status IN ('active', 'retracted')),
    retracted_by_evidence_id INTEGER,       -- QUALE evidenza l'ha invalidata
    retracted_by_rule_id     TEXT,          -- e quale regola l'ha decisa
    retracted_at             INTEGER,
    retracted_reason         TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_evidence_open     ON evidence(tenant, incident_id, ts);
CREATE INDEX IF NOT EXISTS idx_evidence_event    ON evidence(event_id);
CREATE INDEX IF NOT EXISTS idx_evidence_status   ON evidence(status, incident_id);

-- 12. STORICO DELLE CONCLUSIONI (v8): la conclusione di un incidente è
-- versionata come le regole. Quando un'evidenza viene ritrattata il
-- ragionamento si rifà, e quella precedente non sparisce: è ciò che permette
-- di dire "avevamo ipotizzato una congestione, ma una nuova evidenza l'ha
-- invalidata" invece di cambiare idea in silenzio.
CREATE TABLE IF NOT EXISTS incident_conclusions (
    id             INTEGER PRIMARY KEY,
    incident_id    INTEGER NOT NULL,
    concluded_ts   INTEGER NOT NULL,
    cause_kind     TEXT,
    confidence     INTEGER,
    reasoning_json TEXT,
    superseded_ts  INTEGER,               -- NULL = conclusione corrente
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_conclusions_incident
    ON incident_conclusions(incident_id, concluded_ts);

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

