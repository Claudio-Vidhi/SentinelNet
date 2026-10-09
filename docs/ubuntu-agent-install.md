# SentinelNet Probe Agent Installation on Ubuntu Server 24.04 LTS

Step-by-step guide for deploying a SentinelNet Probe Agent on Ubuntu Server 24.04 LTS to manage local devices and relay telemetry outbound to Central.

---

> **Linux only.** The probe agent is supported on Linux, and a Windows agent is
> not on the roadmap: the dashboard reads its log with `journalctl` and
> restarts it through systemd, neither of which exists elsewhere. Central
> itself may run on Windows — that is a separate choice. See
> [probes.md](probes.md) under *Supported platforms*.

## 1. Register Probe on Central Server

On Central Web UI (`http://<CENTRAL_IP>:8000/`):
1. Navigate to **Probes** tab -> click **New probe**.
2. Enter **Name** (e.g. `test_ub_agent`).
3. Select **Mode**: `Agent probe`.
4. Click **Create / Salva**.
5. **Copy the generated Token (`agent_tok_...`) immediately** (shown only once).

> **Probe ID Slug Rule:** Central converts spaces and underscores (`_`) into hyphens (`-`).
> Example: Probe name `test_ub_agent` produces `probe_id` `test-ub-agent`.

---

## 2. Install Packages on Ubuntu 24.04

Run on Ubuntu Server VM:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip curl
```

---

## 3. Clone Repository & Setup Virtual Environment

```bash
sudo mkdir -p /opt/SentinelNet
sudo chown -R $USER:$USER /opt/SentinelNet
cd /opt/SentinelNet

git clone https://github.com/Claudio-Vidhi/SentinelNet.git .
mkdir -p agent-data

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

---

## 4. Configure Agent (`/opt/SentinelNet/agent.json`)

Create the configuration file (replace `<CENTRAL_IP>`, `<PROBE_ID>`, and `<TOKEN>`):

```bash
tee /opt/SentinelNet/agent.json << 'EOF'
{
  "central_url": "http://192.0.2.10:8000",
  "probe_id": "test-ub-agent",
  "token": "YOUR_GENERATED_TOKEN_HERE",
  "interval": 15,
  "verify_tls": false,
  "data_dir": "/opt/SentinelNet/agent-data"
}
EOF

chmod 600 /opt/SentinelNet/agent.json
```

---

## 5. Verify Heartbeat with Central

Test authentication from Ubuntu VM:

```bash
curl -i -X POST http://192.0.2.10:8000/api/agent/heartbeat \
  -H "X-Probe-Id: test-ub-agent" \
  -H "X-Probe-Token: YOUR_GENERATED_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Must return `HTTP/1.1 200 OK` and `{"ok":true,"probe_id":"test-ub-agent",...}`.

---

## 6. Configure Systemd Service

Create `/etc/systemd/system/sentinelnet-agent.service`:

```bash
sudo tee /etc/systemd/system/sentinelnet-agent.service << EOF
[Unit]
Description=SentinelNet Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/SentinelNet
ExecStart=/opt/SentinelNet/.venv/bin/python services/probe_agent.py --config /opt/SentinelNet/agent.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

Start and enable service on boot:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet-agent
sudo systemctl status sentinelnet-agent
```

---

## 7. Local Device Inventory (Optional)

Create local device inventory file for the agent to manage:

```bash
cat << 'EOF' > /opt/SentinelNet/agent-data/network_hosts.csv
IP,Vendor,Profile,Username,Password,Enable Secret,Group,Hostname,Probe,SSH Port,Transports,SNMP Community,SNMP Disabled
EOF

chmod 600 /opt/SentinelNet/agent-data/network_hosts.csv
```

---

## Troubleshooting (Ubuntu)

| Symptom | Cause | Solution |
|---|---|---|
| `401 Unauthorized` on heartbeat | `probe_id` contains `_` or token mismatch. | Use slugified `probe_id` with hyphens (`test-ub-agent`) and verify token. |
| `Unit sentinelnet-agent.service not found` | Service unit not written to `/etc/systemd/system/`. | Create `/etc/systemd/system/sentinelnet-agent.service` and run `daemon-reload`. |
| `Permission denied` on `/opt/SentinelNet` | Directory owned by `root`. | Run `sudo chown -R $USER:$USER /opt/SentinelNet`. |
| Outbound connection timeout | Central firewall blocking port or routing issue. | Verify reachability: `curl -i http://<CENTRAL_IP>:8000/api/version`. |
