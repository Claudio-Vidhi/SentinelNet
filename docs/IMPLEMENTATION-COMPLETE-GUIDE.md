You are absolutely right, and I apologize for the oversight. 

The final `FRONTEND-OBSERVABILITY-MODULE.md` I provided **only** covered the frontend JavaScript/HTML. It **excluded**:

1. The SQLite schema (from Part 1 of my earlier response).
2. The `routers/fortigate.py` and `wlc.py` boilerplate (from Part 2).
3. The detailed Refactoring Guide (migration table, DI pattern, step-by-step checklist).
4. The backend `routers/observability.py` (the actual API endpoints for `/top` and `/anomalies`).

To fix this, I am providing a **single, monolithic, comprehensive implementation guide** (`IMPLEMENTATION-COMPLETE-GUIDE.md`). 

---

# SentinelNet — Complete Observability & Refactoring Implementation Guide

**Version:** 1.0  
**Date:** 2026-07-12  
**Scope:** Backend (SQLite + Routers + UDP Listeners) + Frontend (Vis.js Integration) + Refactoring Strategy.  
**Prerequisites:** Python 3.11+, FastAPI, Uvicorn, Docker (optional).

---

## Table of Contents

1. [Database Schema (SQLite)](#1-database-schema-sqlite)
2. [Backend Routers: FortiGate & WLC (Refactoring Test Case)](#2-backend-routers-fortigate--wlc-refactoring-test-case)
3. [Backend Router: Observability (Top Talkers API)](#3-backend-router-observability-top-talkers-api)
4. [Async UDP Listeners (IPFIX/sFlow/Syslog)](#4-async-udp-listeners-ipfixsflowsyslog)
5. [Modular Refactoring Guide (Splitting `app_server.py`)](#5-modular-refactoring-guide-splitting-app_serverpy)
6. [Frontend UI Integration (Vis.js + Live Flows Tab)](#6-frontend-ui-integration-visjs--live-flows-tab)
7. [Docker & Deployment Updates](#7-docker--deployment-updates)
8. [Testing & Troubleshooting](#8-testing--troubleshooting)

---

## 1. Database Schema (SQLite)

**File:** `sentinelnet/observability/storage/schema.sql`

This creates the `observability.db` file alongside your existing `network_hosts.csv`. It is optimized for time-series aggregation and RBAC (tenant column).

```sql
-- observability.db
-- PRAGMA journal_mode=WAL;  -- Enable Write-Ahead Logging for concurrent writes

-- 1. AGGREGATED FLOWS (Minute-level rollups)
-- Ingests IPFIX/sFlow data, summarizes by minute to save disk space.
CREATE TABLE IF NOT EXISTS flow_aggregates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT NOT NULL,                     -- Matches user_group_scope
    window_start INTEGER NOT NULL,            -- Unix timestamp (minute precision)
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,                         -- 6 (TCP), 17 (UDP), 1 (ICMP)
    application_name TEXT,
    total_bytes INTEGER DEFAULT 0,
    total_packets INTEGER DEFAULT 0,
    flow_count INTEGER DEFAULT 1,             -- Number of flows summarized
    device_ip TEXT,                           -- Which router/firewall exported it
    ingress_interface TEXT,
    UNIQUE(window_start, src_ip, dst_ip, src_port, dst_port, protocol, tenant)
);

-- 2. SYSLOG EVENTS (Security Alerts)
-- Stores raw & normalized alerts from Palo Alto / FortiGate.
CREATE TABLE IF NOT EXISTS syslog_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT NOT NULL,
    received_at INTEGER NOT NULL,             -- Unix timestamp (system receive time)
    event_time INTEGER NOT NULL,              -- Unix timestamp (device-reported time)
    src_ip TEXT,
    dst_ip TEXT,
    threat_name TEXT,
    severity TEXT CHECK(severity IN ('Critical','High','Medium','Low','Info')),
    action TEXT CHECK(action IN ('blocked','allowed','reset','unknown')),
    raw_message TEXT,                         -- Full original syslog payload
    device_ip TEXT,                           -- Firewall that generated it
    session_id TEXT
);

-- 3. CORRELATED EVENTS (The "Stitching" Result)
-- Joins flows + syslog + topology data into actionable insights.
CREATE TABLE IF NOT EXISTS correlated_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT NOT NULL,
    detected_at INTEGER NOT NULL,             -- Unix timestamp
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    severity TEXT CHECK(severity IN ('Critical','High','Medium','Low','Info')),
    event_type TEXT CHECK(event_type IN ('malware_traffic','latency_spike','anomaly_flow','policy_deny')),
    description TEXT,
    flow_aggregate_id INTEGER,                -- FK to flow_aggregates (nullable)
    syslog_event_id INTEGER,                  -- FK to syslog_events (nullable)
    switch_port TEXT,                         -- Enriched via MAC history
    status TEXT DEFAULT 'new' CHECK(status IN ('new','acknowledged','resolved')),
    FOREIGN KEY(flow_aggregate_id) REFERENCES flow_aggregates(id) ON DELETE SET NULL,
    FOREIGN KEY(syslog_event_id) REFERENCES syslog_events(id) ON DELETE SET NULL
);

-- 4. PERFORMANCE INDEXES (Crucial for speed)
CREATE INDEX idx_flow_tenant_window ON flow_aggregates(tenant, window_start DESC);
CREATE INDEX idx_flow_src_dst ON flow_aggregates(src_ip, dst_ip);
CREATE INDEX idx_syslog_tenant_time ON syslog_events(tenant, event_time DESC);
CREATE INDEX idx_syslog_src ON syslog_events(src_ip);
CREATE INDEX idx_correlated_tenant_status ON correlated_events(tenant, status);
```

**Integration with your `data_config.py`:**

```python
# data_config.py
import sqlite3
from pathlib import Path

def get_observability_db_path() -> Path:
    data_dir = get_data_dir()  # your existing resolver
    return data_dir / "observability.db"

def get_observability_connection():
    db_path = get_observability_db_path()
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row  # Enable dict-like access
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn
```

---

## 2. Backend Routers: FortiGate & WLC (Refactoring Test Case)

This demonstrates how to extract **~10 endpoints** from `app_server.py` into modular routers using **Dependency Injection**.

### 2.1 FortiGate Router
**File:** `sentinelnet/routers/fortigate.py`

```python
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional
from sentinelnet.fortigate_service import (
    fgt_arp as _fgt_arp,
    fgt_device_inventory,
    fgt_full_config,
    fgt_diagnose_client,
    fgt_dhcp_leases
)
from sentinelnet.security_manager import require_operator, require_admin, get_current_user
from sentinelnet.user_manager import User, assert_group_allowed
from sentinelnet.inventory_manager import get_device_by_ip

router = APIRouter(prefix="/api", tags=["FortiGate"])

def get_fortigate_device(device_ip: str, user: User = Depends(get_current_user)):
    device = get_device_by_ip(device_ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not assert_group_allowed(user, device.get("group")):
        raise HTTPException(status_code=403, detail="Device not in your scope")
    return device

@router.get("/fgt/arp")
async def get_fortigate_arp(
    device_ip: str = Query(...),
    vdom: Optional[str] = Query(None),
    user: User = Depends(require_operator),
    device: dict = Depends(get_fortigate_device)
):
    result = _fgt_arp(device_ip, vdom=vdom, user=user)
    return {"status": "success", "data": result}

@router.get("/fgt/inventory")
async def get_fortigate_inventory(
    device_ip: str = Query(...),
    vdom: Optional[str] = Query(None),
    user: User = Depends(require_operator),
    device: dict = Depends(get_fortigate_device)
):
    result = fgt_device_inventory(device_ip, vdom=vdom)
    return {"status": "success", "data": result}

@router.get("/fgt/config")
async def get_fortigate_full_config(
    device_ip: str = Query(...),
    vdom: Optional[str] = Query(None),
    user: User = Depends(require_admin),
    device: dict = Depends(get_fortigate_device)
):
    config = fgt_full_config(device_ip, vdom=vdom)
    return {"status": "success", "config": config}

@router.get("/fgt/diagnose")
async def get_fortigate_diagnose(
    device_ip: str = Query(...),
    command: str = Query(...),
    vdom: Optional[str] = Query(None),
    user: User = Depends(require_operator),
    device: dict = Depends(get_fortigate_device)
):
    result = fgt_diagnose_client(device_ip, command, vdom=vdom)
    return {"status": "success", "data": result}

@router.get("/fgt/dhcp")
async def get_fortigate_dhcp_leases(
    device_ip: str = Query(...),
    interface: Optional[str] = Query(None),
    user: User = Depends(require_operator),
    device: dict = Depends(get_fortigate_device)
):
    leases = fgt_dhcp_leases(device_ip, interface=interface)
    return {"status": "success", "leases": leases}
```

### 2.2 WLC Router
**File:** `sentinelnet/routers/wlc.py`

```python
from fastapi import APIRouter, Depends, HTTPException, Query
from sentinelnet.security_manager import require_operator, require_admin, get_current_user
from sentinelnet.user_manager import User, assert_group_allowed
from sentinelnet.inventory_manager import get_device_by_ip
from sentinelnet.wlc_service import (
    wlc_ap_summary as _wlc_ap_summary,
    wlc_client_detail as _wlc_client_detail,
    wlc_client_summary as _wlc_client_summary,
    wlc_interfaces as _wlc_interfaces,
    wlc_diagnose_client as _wlc_diagnose_client
)

router = APIRouter(prefix="/api", tags=["Wireless"])

def get_wlc_device(controller_ip: str = Query(...), user: User = Depends(get_current_user)):
    device = get_device_by_ip(controller_ip)
    if not device:
        raise HTTPException(status_code=404, detail=f"WLC {controller_ip} not found")
    if not assert_group_allowed(user, device.get("group")):
        raise HTTPException(status_code=403, detail="Device not in your scope")
    return device

@router.get("/wlc/ap-summary")
async def get_wlc_ap_summary(user: User = Depends(require_operator), device: dict = Depends(get_wlc_device)):
    result = _wlc_ap_summary(device["ip"])
    return {"status": "success", "data": result}

@router.get("/wlc/client-summary")
async def get_wlc_client_summary(user: User = Depends(require_operator), device: dict = Depends(get_wlc_device)):
    result = _wlc_client_summary(device["ip"])
    return {"status": "success", "data": result}

@router.get("/wlc/client-detail")
async def get_wlc_client_detail(
    client_mac: str = Query(...),
    user: User = Depends(require_operator),
    device: dict = Depends(get_wlc_device)
):
    result = _wlc_client_detail(device["ip"], client_mac)
    return {"status": "success", "data": result}

@router.get("/wlc/interfaces")
async def get_wlc_interfaces(user: User = Depends(require_operator), device: dict = Depends(get_wlc_device)):
    result = _wlc_interfaces(device["ip"])
    return {"status": "success", "data": result}

@router.post("/wlc/diagnose")
async def get_wlc_diagnose(
    command: str = Query(...),
    user: User = Depends(require_admin),
    device: dict = Depends(get_wlc_device)
):
    result = _wlc_diagnose_client(device["ip"], command)
    return {"status": "success", "data": result}
```

---

## 3. Backend Router: Observability (Top Talkers API)

**File:** `sentinelnet/routers/observability.py`

This is the **new backend** that queries the SQLite schema to serve the frontend.

```python
from fastapi import APIRouter, Depends, HTTPException, Query
from sentinelnet.security_manager import require_operator
from sentinelnet.user_manager import User
from sentinelnet.observability.storage import get_observability_connection
import time

router = APIRouter(prefix="/api/v2/obs", tags=["Observability"])

@router.get("/top")
async def get_top_talkers(
    minutes: int = Query(5, ge=1, le=1440, description="Time window in minutes"),
    limit: int = Query(20, ge=1, le=100, description="Max number of flows to return"),
    user: User = Depends(require_operator)
):
    """
    Fetches the top bandwidth-consuming flows for the given time window.
    Tenant-scoped via the logged-in user's group.
    """
    conn = get_observability_connection()
    cursor = conn.cursor()
    
    # Calculate the cutoff timestamp (Unix epoch, minute precision)
    cutoff = int(time.time()) - (minutes * 60)
    
    # Parameterized query to prevent SQL injection
    cursor.execute("""
        SELECT 
            src_ip,
            dst_ip,
            protocol,
            SUM(total_bytes) as total_bytes,
            SUM(flow_count) as flow_count,
            -- Pick the most frequent application name in the window
            (SELECT application_name FROM flow_aggregates f2 
             WHERE f2.src_ip = f1.src_ip AND f2.dst_ip = f1.dst_ip 
               AND f2.tenant = f1.tenant AND f2.window_start >= ?
             GROUP BY application_name ORDER BY COUNT(*) DESC LIMIT 1) as application_name
        FROM flow_aggregates f1
        WHERE tenant = ? AND window_start >= ?
        GROUP BY src_ip, dst_ip, protocol
        ORDER BY total_bytes DESC
        LIMIT ?
    """, (cutoff, user.group, cutoff, limit))
    
    rows = cursor.fetchall()
    conn.close()
    
    # Convert rows to dicts (sqlite3.Row is already dict-like)
    return {"status": "success", "data": [dict(row) for row in rows]}

@router.get("/anomalies")
async def get_anomalies(
    status: str = Query("new", regex="^(new|acknowledged|resolved)$"),
    user: User = Depends(require_operator)
):
    """
    Fetches correlated security events (e.g., malware traffic blocked + flow matched).
    """
    conn = get_observability_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            detected_at,
            src_ip,
            dst_ip,
            severity,
            event_type,
            description,
            switch_port,
            status
        FROM correlated_events
        WHERE tenant = ? AND status = ?
        ORDER BY detected_at DESC
        LIMIT 50
    """, (user.group, status))
    
    rows = cursor.fetchall()
    conn.close()
    return {"status": "success", "data": [dict(row) for row in rows]}
```

---

## 4. Async UDP Listeners (IPFIX/sFlow/Syslog)

**File:** `sentinelnet/observability/ingesters/udp_server.py`

This reusable factory starts Async UDP servers inside the Uvicorn event loop.

```python
import asyncio
import logging
from typing import Callable, Optional

logger = logging.getLogger("uvicorn.observability")

class AsyncUDPServer:
    def __init__(self, host: str, port: int, handler: Callable, name: str = "UDP Listener"):
        self.host = host
        self.port = port
        self.handler = handler
        self.name = name
        self.transport: Optional[asyncio.DatagramTransport] = None

    async def start(self):
        loop = asyncio.get_running_loop()
        protocol_factory = lambda: UDPProtocol(self.handler, self.name)
        self.transport, _ = await loop.create_datagram_endpoint(
            protocol_factory,
            local_addr=(self.host, self.port)
        )
        logger.info(f"✅ {self.name} listening on {self.host}:{self.port}")

    async def stop(self):
        if self.transport:
            self.transport.close()
            logger.info(f"🛑 {self.name} stopped")

class UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: Callable, name: str):
        self.handler = handler
        self.name = name

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self.handler(data, addr))
```

**File:** `sentinelnet/observability/ingesters/handlers.py`

```python
import logging
from datetime import datetime
from sentinelnet.observability.storage import get_observability_connection

logger = logging.getLogger("uvicorn.observability")

async def handle_ipfix_flow(data: bytes, addr: tuple):
    # In production, decode binary IPFIX using 'ipfix' library.
    # Mock example: extract fields from a JSON payload for demo.
    try:
        # Mock parsing (replace with actual decoder)
        flow = {
            "src_ip": f"192.168.1.{data[0] % 254}",
            "dst_ip": f"10.0.0.{data[1] % 254}",
            "bytes": len(data),
            "packets": 10,
            "timestamp": int(datetime.utcnow().timestamp())
        }
        conn = get_observability_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO flow_aggregates 
            (tenant, window_start, src_ip, dst_ip, total_bytes, total_packets)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("default", flow["timestamp"], flow["src_ip"], flow["dst_ip"], flow["bytes"], flow["packets"]))
        conn.commit()
        conn.close()
        logger.info(f"📊 IPFIX flow stored: {flow['src_ip']} -> {flow['dst_ip']}")
    except Exception as e:
        logger.warning(f"Failed to parse IPFIX: {e}")

async def handle_sflow_sample(data: bytes, addr: tuple):
    logger.info(f"📈 sFlow sample received from {addr} ({len(data)} bytes)")

async def handle_syslog_message(data: bytes, addr: tuple):
    try:
        message = data.decode('utf-8', errors='ignore')
        conn = get_observability_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO syslog_events 
            (tenant, received_at, raw_message, src_ip)
            VALUES (?, ?, ?, ?)
        """, ("default", int(datetime.utcnow().timestamp()), message, "Unknown"))
        conn.commit()
        conn.close()
        logger.info(f"⚠️ Syslog event: {message[:50]}...")
    except Exception as e:
        logger.warning(f"Failed to parse Syslog: {e}")
```

---

## 5. Modular Refactoring Guide (Splitting `app_server.py`)

### 5.1 The Problem
Currently, `app_server.py` has **~51 endpoints** and a cohesion score of **0.04**. It is a "God Node."

### 5.2 The Solution (Migration Table)

| Old `@app` Route | New Router File | New Prefix |
| :--- | :--- | :--- |
| `/api/fgt/arp` | `routers/fortigate.py` | `/api` |
| `/api/wlc/ap-summary` | `routers/wlc.py` | `/api` |
| `/api/mac/search` | `routers/mac.py` | `/api` |
| `/api/ai/chat` | `routers/ai.py` | `/api` |
| `/api/sites` | `routers/sites.py` | `/api` |
| `/api/backup/run` | `routers/backup.py` | `/api` |
| `/api/v2/obs/top` | `routers/observability.py` | `/api/v2/obs` |

### 5.3 Dependency Injection (DI) Pattern

**Old (Bad):**
```python
@app.get("/api/fgt/arp")
async def fgt_arp(request: Request, device_ip: str):
    user = auth_middleware(request)  # Manual, repetitive
    if not user: raise HTTPException(401)
```

**New (Good):**
```python
@router.get("/fgt/arp")
async def fgt_arp(user: User = Depends(require_operator)):
    # Authentication & Authorization happen automatically BEFORE this line.
```

### 5.4 Step-by-Step Checklist

1. **Create** `sentinelnet/routers/__init__.py` (empty).
2. **Implement** `fortigate.py` and `wlc.py` (as provided above).
3. **Modify** `app_server.py`:
   - Import the routers: `from sentinelnet.routers import fortigate, wlc, observability`
   - (Optional) Use a lifespan manager to include them.
   - Delete the old `@app.get` definitions for FortiGate/WLC.
4. **Test** via Swagger UI (`/docs`) to ensure routes are still accessible.
5. **Repeat** for MAC, AI, Sites, and Backup routers over the next sprints.

### 5.5 Lifespan Manager Integration (in `app_server.py`)

Replace `@app.on_event("startup")` with a modern `lifespan` context manager:

```python
from contextlib import asynccontextmanager
from sentinelnet.routers import fortigate, wlc, observability
from sentinelnet.observability.ingesters.udp_server import AsyncUDPServer
from sentinelnet.observability.ingesters.handlers import handle_ipfix_flow, handle_sflow_sample, handle_syslog_message

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Include Routers
    app.include_router(fortigate.router)
    app.include_router(wlc.router)
    app.include_router(observability.router)
    
    # 2. Start UDP Listeners (if not running in test env)
    host = "0.0.0.0" if is_running_in_docker() else "127.0.0.1"
    ipfix = AsyncUDPServer(host, 4739, handle_ipfix_flow, "IPFIX")
    sflow = AsyncUDPServer(host, 6343, handle_sflow_sample, "sFlow")
    syslog = AsyncUDPServer(host, 514, handle_syslog_message, "Syslog")
    
    await asyncio.gather(ipfix.start(), sflow.start(), syslog.start())
    app.state.ipfix = ipfix
    
    yield  # App runs here
    
    # Shutdown
    await ipfix.stop()
    await sflow.stop()
    await syslog.stop()

app = FastAPI(lifespan=lifespan)
```

---

## 6. Frontend UI Integration (Vis.js + Live Flows Tab)

### 6.1 HTML (Add to `templates/dashboard.html`)

**Sidebar Button:**
```html
<button class="nav-btn" onclick="showTab('observability')" data-tab="observability">
  <i>📊</i> Live Flows
</button>
```

**Tab Content:**
```html
<div id="tab-observability" class="tab-content" style="display: none;">
  <div class="row">
    <div class="col-12">
      <h3>🌐 Live Network Flows (Top Talkers)</h3>
      <div style="display: flex; gap: 20px; align-items: center; margin-bottom: 15px;">
        <div>
          <label for="obs-minutes">Window:</label>
          <select id="obs-minutes" onchange="loadTopTalkers()">
            <option value="1">1 Minute</option>
            <option value="5" selected>5 Minutes</option>
            <option value="15">15 Minutes</option>
            <option value="60">1 Hour</option>
          </select>
        </div>
        <div><span id="obs-last-update" style="color: #666;">Last updated: --</span></div>
        <button onclick="loadTopTalkers()">🔄 Refresh</button>
        <button onclick="toggleAutoRefresh()" id="auto-refresh-btn" style="background-color: #28a745; color: white; border: none; border-radius: 4px; padding: 5px 15px;">Auto-Refresh: ON</button>
      </div>
      <div id="top-talkers-container" style="max-height: 600px; overflow-y: auto; border: 1px solid #ddd;">
        <table id="top-talkers-table" style="width: 100%; border-collapse: collapse;">
          <thead style="position: sticky; top: 0; background: #2c3e50; color: white;">
            <tr><th>#</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>App</th><th style="width:200px;">Traffic</th><th>Flows</th><th>Actions</th></tr>
          </thead>
          <tbody id="top-talkers-body"><tr><td colspan="8" style="text-align:center; padding:30px;">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</div>
```

### 6.2 JavaScript (Core Logic)

```javascript
let autoRefreshInterval = null;
let autoRefreshEnabled = true;

async function loadTopTalkers() {
    const minutes = document.getElementById('obs-minutes')?.value || 5;
    const tbody = document.getElementById('top-talkers-body');
    const updateSpan = document.getElementById('obs-last-update');

    try {
        const response = await fetch(`/api/v2/obs/top?minutes=${minutes}`, {
            headers: { 'Authorization': `Bearer ${sessionStorage.getItem('jwt_token')}` }
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const result = await response.json();
        const flows = result.data || [];
        updateSpan.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;

        if (flows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#888;">✅ No traffic in the last ${minutes} min.</td></tr>`;
            return;
        }

        const maxBytes = Math.max(...flows.map(f => f.total_bytes));
        let html = '';
        flows.forEach((flow, i) => {
            const barWidth = (flow.total_bytes / maxBytes * 100).toFixed(1);
            html += `
                <tr style="border-bottom:1px solid #eee;">
                    <td style="padding:8px; text-align:center;">${i+1}</td>
                    <td style="padding:8px; cursor:pointer; color:#007bff;" onclick="highlightInTopology('${flow.src_ip}')">${flow.src_ip}</td>
                    <td style="padding:8px; cursor:pointer; color:#007bff;" onclick="highlightInTopology('${flow.dst_ip}')">${flow.dst_ip}</td>
                    <td style="padding:8px;">${flow.protocol === 6 ? 'TCP' : 'UDP'}</td>
                    <td style="padding:8px;">${flow.application_name || 'Unknown'}</td>
                    <td style="padding:8px; width:200px;">
                        <div style="display:flex; align-items:center; gap:10px;">
                            <div style="flex-grow:1; height:8px; background:#e9ecef; border-radius:4px;">
                                <div style="height:100%; width:${barWidth}%; background:linear-gradient(90deg,#17a2b8,#007bff); border-radius:4px;"></div>
                            </div>
                            <span style="font-size:0.85em;">${formatBytes(flow.total_bytes)}</span>
                        </div>
                    </td>
                    <td style="padding:8px; text-align:center;">${flow.flow_count}</td>
                    <td style="padding:8px;"><button onclick="analyzeFlow('${flow.src_ip}','${flow.dst_ip}')" style="border:1px solid #ccc; border-radius:4px; cursor:pointer;">🧠 AI</button></td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" style="color:red;">❌ Error: ${e.message}</td></tr>`;
    }
}

function toggleAutoRefresh() {
    autoRefreshEnabled = !autoRefreshEnabled;
    const btn = document.getElementById('auto-refresh-btn');
    if (autoRefreshEnabled) { btn.textContent = 'Auto-Refresh: ON'; btn.style.backgroundColor = '#28a745'; startAutoRefresh(); } 
    else { btn.textContent = 'Auto-Refresh: OFF'; btn.style.backgroundColor = '#6c757d'; stopAutoRefresh(); }
}

function startAutoRefresh() {
    stopAutoRefresh();
    autoRefreshInterval = setInterval(() => {
        if (document.getElementById('tab-observability')?.style?.display !== 'none') loadTopTalkers();
    }, 10000);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) { clearInterval(autoRefreshInterval); autoRefreshInterval = null; }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function highlightInTopology(ip) {
    // Switch to topology tab
    document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
    document.getElementById('tab-topology').style.display = 'block';
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-tab="topology"]')?.classList.add('active');

    // Highlight in Vis.js (requires window.network to be set during Vis init)
    const network = window.network;
    if (!network) return alert('Topology not loaded yet.');
    const nodes = network.getBody().data.nodes;
    let found = null;
    nodes.forEach((node, id) => { if (node.label === ip || node.id === ip) found = id; });
    if (found) { network.selectNodes([found]); network.focus(found, { scale: 1.2, animation: true }); } 
    else { alert(`IP ${ip} not found in topology.`); }
}

function analyzeFlow(src, dst) {
    const input = document.getElementById('ai-input');
    if (input) { input.value = `Analyze traffic from ${src} to ${dst}. Any security alerts?`; document.getElementById('ai-send-btn')?.click(); }
    document.querySelector('[data-tab="ai"]')?.click();
}

// Initialize on tab switch
const originalShowTab = window.showTab;
window.showTab = function(tab) {
    originalShowTab(tab);
    if (tab === 'observability') { loadTopTalkers(); startAutoRefresh(); } 
    else { stopAutoRefresh(); }
};
// Expose globals
window.loadTopTalkers = loadTopTalkers;
window.toggleAutoRefresh = toggleAutoRefresh;
window.highlightInTopology = highlightInTopology;
window.analyzeFlow = analyzeFlow;
window.formatBytes = formatBytes;
```

---

## 7. Docker & Deployment Updates

**File:** `docker-compose.yml` (Add UDP ports)

```yaml
services:
  sentinelnet:
    image: claudiovidhi/sentinelnet:latest
    ports:
      - "8765:8765"
      - "4739:4739/udp"   # IPFIX
      - "6343:6343/udp"   # sFlow
      - "514:514/tcp"     # Syslog TCP
      - "514:514/udp"     # Syslog UDP
    environment:
      - SENTINELNET_DATA_DIR=/app/data
      - SENTINELNET_HOST=0.0.0.0
    volumes:
      - ./data:/app/data
```

---

## 8. Testing & Troubleshooting

### 8.1 Mock Data Injection (No hardware)
```bash
# Send a mock IPFIX packet to test ingestion
echo '{"src_ip":"192.168.1.100","dst_ip":"10.0.0.1","bytes":150000}' | nc -u -w1 localhost 4739
```

### 8.2 Verify SQLite Insertion
```bash
docker exec -it sentinelnet sqlite3 /app/data/observability.db "SELECT * FROM flow_aggregates;"
```

### 8.3 Common Pitfalls
- **UDP not binding:** Ensure ports are free (`sudo lsof -i :4739`). Bind to `0.0.0.0` inside Docker.
- **Table empty in UI:** Check if `SENTINELNET_DATA_DIR` matches the volume mount.
- **JWT 401 errors:** Ensure the frontend sends `Authorization: Bearer <token>` (use the same method as your other tables).

---

## Conclusion

This monolithic guide contains:
✅ SQLite Schema for flow storage.  
✅ Backend Routers for FortiGate, WLC, and Observability (Top Talkers).  
✅ Async UDP listeners for IPFIX/sFlow/Syslog.  
✅ A step-by-step refactoring guide to break up `app_server.py`.  
✅ Full frontend HTML/JavaScript to visualize data in your Vis.js dashboard.  
✅ Docker updates to expose UDP ports.

This is the **complete, actionable implementation package** for transforming SentinelNet into a **Day-2 Observability powerhouse**. Good luck with the deployment! 🚀