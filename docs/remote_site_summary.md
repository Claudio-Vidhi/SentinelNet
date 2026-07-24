# Remote Site Agent - Technical Architecture, Security & VM Testing Summary

This document provides a comprehensive technical summary of SentinelNet's Remote Site Agent (Mode B), covering architecture, local inventory mechanics, security threat modeling, VM environment testing, and future management roadmaps.

---

## 1. Architecture Overview (Mode B - Site Agent)

SentinelNet supports multi-site network management in two modes:
- **Central Poll (Mode A)**: Direct SSH from Central across VPN.
- **Site Agent (Mode B)**: Outbound HTTPS polling from lightweight agent process (`services/site_agent.py`) running inside the remote site network.

```
┌─────────────────────────────────────────┐               ┌───────────────────────────────────────────────┐
│         CENTRAL SENTINELNET             │               │            REMOTE SITE (VM / AGENT)          │
│                                         │  HTTPS (443)  │                                               │
│  - Web Dashboard & API                  │ ◄───────────  │  - site_agent.py                              │
│  - Site Registry & Token Hash           │  Outbound     │  - Local inventory (network_hosts.csv)        │
│  - Job Queue (SQLite)                   │  Polling      │  - Credentials stored locally                 │
│  - Consolidated Inventory & MAC Tracker │               │  - Direct local SSH to switches/firewalls     │
└─────────────────────────────────────────┘               └───────────────────────┬───────────────────────┘
                                                                                  │ Local SSH
                                                                                  ▼
                                                                  ┌───────────────────────────────┐
                                                                  │ Local Remote Switch/Firewall  │
                                                                  └───────────────────────────────┘
```

### Core Operation Principles:
1. **Outbound-Only Connection**: Agent initiates HTTPS connections to Central (`/api/agent/*`). No inbound ports need to be opened on remote site firewalls/NAT.
2. **Credential Isolation**: Local device SSH/Enable passwords reside **exclusively** on the remote agent VM (`network_hosts.csv`). Central receives metadata only (`IP`, `Vendor`, `Hostname`).
3. **Asynchronous Job Relay**: CLI commands requested from Central (`POST /api/send-command` or `POST /api/sites/{site_id}/command`) are queued in SQLite. Agent polls pending jobs (`GET /api/agent/jobs`), executes SSH locally via `core_engine`, and posts results (`POST /api/agent/jobs/{id}/result`).

---

## 2. Local Inventory Mechanism

On the remote agent VM, device records are stored in `--data-dir` (default: `./agent-data/network_hosts.csv`).

### Methods to Populate Local Inventory:
1. **Helper Script (Recommended)**:
   ```bash
   python scripts/vm_agent_test_helper.py add-device \
     --ip 192.168.56.10 --hostname sw-milano-01 --vendor cisco \
     --username admin --password secret --site-id milano-vm
   ```
2. **Direct CSV Edit**: Edit `agent-data/network_hosts.csv` directly with required headers.
3. **Export from Central**: Export CSV from Central UI -> Copy to agent `./agent-data/network_hosts.csv`.
4. **Python One-Liner**: Use `inventory_manager.add_device()` directly on agent VM.

### Data Uploaded to Central vs Kept Local:
- **Pushed to Central**: `IP`, `Vendor`, `Hostname`, `Site ID`.
- **Kept strictly Local**: `Username`, `Password`, `Secret`, `SNMP_Community`.

---

## 3. Security Threat Modeling & Risk Analysis

### Scenario A: What if Central Server is Compromised?
- **Remote Devices Remain Safe**: Central stores **zero passwords** for agent-managed remote sites (`Username`, `Password`, `Secret` are stored as empty strings `""`).
- Attacker on Central server cannot retrieve SSH credentials for remote site devices.

### Scenario B: What if Remote Site Agent VM is Compromised?
- **Central Protection**: Agent only holds a per-site token (`X-Site-Token`), **never** admin passwords, JWT secrets, or API keys of Central Server.
- **Scope Isolation**: Token is locked to its specific `site_id`. Compromised agent cannot read, alter, or command devices belonging to Central or other remote sites.
- **Instant Kill-Switch (Containment)**: Admin clicks **Rigenera token** or **Elimina sede** on Central UI. Central revokes token hash immediately; all subsequent requests from compromised VM get `HTTP 401 Unauthorized`.

---

## 4. VM Environment Testing Workflow

Use [scripts/vm_agent_test_helper.py](file:///c:/Users/vidhi/dev_ved/SentinelNet/scripts/vm_agent_test_helper.py) for testing on VirtualBox / VMware / KVM / Hyper-V:

1. **Create Site on Central**: Admin creates `milano-vm` (mode `agent`) on Central UI and copies token `agent_tok_...`.
2. **Setup Agent on VM**:
   ```bash
   python scripts/vm_agent_test_helper.py setup \
     --central-url http://<CENTRAL_IP>:8765 \
     --site-id milano-vm --token <TOKEN> --interval 15 --no-verify-tls
   ```
3. **Add Devices**:
   ```bash
   python scripts/vm_agent_test_helper.py add-device --ip 192.168.56.10 --hostname sw-01 --vendor cisco
   ```
4. **Run Diagnostics**:
   ```bash
   python scripts/vm_agent_test_helper.py check --config agent.json
   ```
5. **Start Agent**:
   ```bash
   python services/site_agent.py --config agent.json
   ```
6. **Verify End-to-End**:
   - Check Central Dashboard -> Sedi multi-sito -> *Ultimo contatto* updates.
   - Check Inventario -> Device appears tagged with `milano-vm`.
   - Send CLI command from Central -> Verify execution and response relay.

---

## 5. Future Architectural Roadmap & Advanced Management Ideas

| # | Concept | Mechanism | Benefits |
|---|---------|-----------|----------|
| 1 | **Central Managed Zero-Knowledge Encryption** | Client-side Age/RSA public-key encryption. Public key on Central, Private key in Agent VM TPM/Keyring. | Manage credentials centrally on UI without Central ever seeing plain text passwords. |
| 2 | **OS Native Keyring Storage** | Store credentials in `systemd-creds`, `keyctl` (Linux), or Windows Credential Manager. | Eliminates plaintext CSV files on disk; encrypted at rest by OS. |
| 3 | **Mutual TLS (mTLS) Authentication** | Replace static HTTP tokens with X.509 client certificates signed by internal CA. | Automatic certificate rotation, cryptographic identity, instant CRL revocation. |
| 4 | **Ephemeral JIT Credentials** | Ephemeral 60-second SSH certificates / RADIUS tokens requested per job. | Zero static passwords stored anywhere on remote switches or agents. |
| 5 | **WebSocket / gRPC Outbound Streaming** | Persistent `wss://central:8765/ws/agent` connection replacing 60s HTTP polling loop. | CLI execution latency drops from 60s to **< 50ms** (real-time stream). |
| 6 | **Containerized Edge Deployment** | Package agent as official Docker / K3s container. | Single-command deployment, isolated runtime, auto-healing. |
