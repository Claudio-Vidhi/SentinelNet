# SentinelNet Central Installation on Fedora Server

Step-by-step guide for deploying the central SentinelNet management server on Fedora Server (or RHEL-compatible distributions) using `systemd`, `uv`, and `firewalld`.

---

## 1. Install System Packages

```bash
sudo dnf update -y
sudo dnf install -y git python3 python3-pip iputils firewalld
```

Install `uv` for virtualenv and package management:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

---

## 2. Clone Repository & Setup Virtual Environment

Assuming deployment in `/home/admin/DEV/SentinelNet` (or `/opt/sentinelnet/app`):

```bash
cd /home/admin/DEV
git clone https://github.com/Claudio-Vidhi/SentinelNet.git
cd SentinelNet

# Create data directory with restricted permissions
mkdir -p data
chmod 700 data

# Create Python virtual environment and install dependencies
uv venv .venv
uv pip install -r requirements.txt
```

---

## 3. Configure SELinux & Directory Permissions

If running out of `/home/`, SELinux blocks `systemd` from executing user-space binaries and reading home files. Apply required file labels and directory permissions:

```bash
# Allow systemd to execute the virtualenv Python binary
sudo chcon -R -t bin_t /home/admin/DEV/SentinelNet/.venv/bin
chmod -R 755 /home/admin/DEV/SentinelNet/.venv/bin

# Ensure parent directory traversal
chmod 755 /home/admin /home/admin/DEV
```

---

## 4. Create System Environment File

Store environment variables in `/etc/sentinelnet.env` (`init_t` readable):

```bash
sudo tee /etc/sentinelnet.env << 'EOF'
SENTINELNET_HOST=0.0.0.0
SENTINELNET_PORT=8000
SENTINELNET_NO_BROWSER=true
SENTINELNET_DATA_DIR=/home/admin/DEV/SentinelNet/data

# Optional: Observability listeners
# SENTINELNET_OBS_ENABLE=1
# SENTINELNET_OBS_BIND=0.0.0.0
# SENTINELNET_OBS_SYSLOG_ENABLE=1
# SENTINELNET_OBS_SYSLOG_PORT=5514
# SENTINELNET_OBS_NETFLOW_ENABLE=1
# SENTINELNET_OBS_NETFLOW_PORT=2055
EOF

sudo chmod 644 /etc/sentinelnet.env
```

---

## 5. Create Systemd Service Unit

Create `/etc/systemd/system/sentinelnet.service`:

```bash
sudo tee /etc/systemd/system/sentinelnet.service << 'EOF'
[Unit]
Description=SentinelNet Network Management Service
After=network.target

[Service]
Type=simple
User=admin
Group=admin
WorkingDirectory=/home/admin/DEV/SentinelNet
EnvironmentFile=/etc/sentinelnet.env
ExecStart=/home/admin/DEV/SentinelNet/.venv/bin/python app_server.py
Restart=always
RestartSec=5

# Hardening
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/home/admin/DEV/SentinelNet/data

[Install]
WantedBy=multi-user.target
EOF
```

---

## 6. Configure Firewall (`firewalld`)

Open the web console port and reload firewall:

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp

# If observability listeners enabled:
# sudo firewall-cmd --permanent --add-port=5514/udp
# sudo firewall-cmd --permanent --add-port=2055/udp
# sudo firewall-cmd --permanent --add-port=4739/udp
# sudo firewall-cmd --permanent --add-port=6343/udp

sudo firewall-cmd --reload
```

---

## 7. Start and Enable Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinelnet
sudo systemctl status sentinelnet
```

---

## 8. Initial Setup

1. Open `http://<SERVER_IP>:8000/` in a browser.
2. Complete first-run wizard to create local administrator account.

---

## Troubleshooting (Fedora)

| Symptom | Cause | Solution |
|---|---|---|
| `Failed to load environment files: Permission denied` | `EnvironmentFile` placed in `/home/*` where SELinux blocks systemd PID 1. | Place file at `/etc/sentinelnet.env` with `chmod 644`. |
| `status=203/EXEC` on startup | SELinux prevents `init_t` executing files labeled `user_home_t`. | Run `sudo chcon -R -t bin_t <path>/.venv/bin`. |
| `Connection refused` from other hosts | Port 8000 blocked by `firewalld`. | Run `sudo firewall-cmd --permanent --add-port=8000/tcp && sudo firewall-cmd --reload`. |
| Browser tries to open locally on headless server | `SENTINELNET_NO_BROWSER` not set. | Set `SENTINELNET_NO_BROWSER=true` in `/etc/sentinelnet.env`. |
