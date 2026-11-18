# SentinelNet OT Demo (`ot-demo`)

Quick guide to run and test the SentinelNet OT features (§1–§5) locally on your PC using synthetic example data (RFC 5737 ranges, zero customer data).

## 1. Checkout & start locally

```sh
git fetch origin
git checkout ot-demo
uv sync
uv run python scripts/dev/run_ot_demo.py
```

Options:
- `--port 8931` — custom port (default `8931`)
- `--reset` — wipe `data/ot-demo/` and re-seed from scratch
- `--no-browser` — do not auto-open browser tab

Demo data is stored strictly inside `data/ot-demo/` (gitignored).

## 2. Demo credentials

- **Username:** `admin`
- **Password:** `Sentinel!Demo2026`

## 3. What is pre-seeded to test

- **Compliant OT tenant (`plant-demo`):**
  - Jump-host bastion probe (`ot-bastion`, `10.10.0.5`)
  - Purdue-tagged devices (`plc-01` `192.0.2.10` `L1`, `switch-01` `192.0.2.20` `L2`, `hmi-01` `192.0.2.30` `L2`, `fw-dmz-01` `192.0.2.40` `L3.5`)
  - Process criticality (`scheduled_shutdown`, `mission_critical`) and maintenance windows
  - OT Project Vault artifacts archived with SHA-256 hashes (`.zap18`, `.scd`, `.hmi`)
  - Healthy `interface.state` + segregated Modbus TCP cell flow + `Cell L1` / `IT/OT DMZ` segments
- **Contrast tenant with findings (`plant-legacy`):**
  - `switch-legacy-01` (`198.51.100.10`, Telnet + HTTP + SNMPv2c + unused `Fa0/4` `admin up` / `link down`)
  - `plc-legacy-01` (`198.51.100.20`, unsegregated `S7comm` flow from `203.0.113.50`, no OT vault artifact, direct `central` probe without DMZ)

## 4. Screens to check

1. **Inventory** (`tab-devices`): click the OT Project Vault button beside Download on `plc-01` to upload, verify SHA-256, download, or delete project files (`.zap*`, `.acd`, `.scd`, `.icd`, `.hmi`, `.s7p`, `.zip`).
2. **Network Blueprint** (`tab-blueprint`): inspect Purdue layers (`L1` / `L3.5`) and zone/conduit compliance.
3. **Vulnerabilities** (`tab-security` -> **CISA ICS & Air-Gap**): inspect air-gap toggle, CISA KEV/ICS advisory lookup, and Ed25519 offline bundle import/export.
4. **Security Audit / Status Report** (`/api/reports/network-status`): compare `plant-demo` vs `plant-legacy` across IEC 62443 controls (`SR 1.13`, `SR 3.1`, `SR 4.1`, `SR 5.1`, `SR 5.2`, `SR 7.3`, `SR 7.4`, `SR 7.7`) in JSON or `.docx`.
