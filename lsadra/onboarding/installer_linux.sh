#!/usr/bin/env bash
# ============================================================================
# LSADRA Agent Installer for Linux
#
# Usage:
#   curl -s https://your-sentinel-server/install-agent.sh | sudo bash -s -- --token ABC123
#
# What this script does:
#   1. Creates /opt/lsadra-agent/
#   2. Downloads the agent script from the server
#   3. Registers with the server using the provided token
#   4. Writes config to /etc/lsadra-agent/config.yml
#   5. Installs and enables a systemd service
#
# Does NOT modify rsyslog or any other system service.
# ============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────
LSADRA_SERVER="${LSADRA_SERVER:-https://your-sentinel-server.example.com}"
INSTALL_DIR="/opt/lsadra-agent"
CONFIG_DIR="/etc/lsadra-agent"
CONFIG_FILE="${CONFIG_DIR}/config.yml"
SERVICE_NAME="lsadra-agent"
AGENT_USER="sentinel-agent"
TOKEN=""

# ── Parse arguments ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)  TOKEN="$2"; shift 2 ;;
        --server) LSADRA_SERVER="$2"; shift 2 ;;
        *)        echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$TOKEN" ]]; then
    echo "Error: --token is required."
    echo "Usage: sudo bash install-agent.sh --token <REGISTRATION_TOKEN>"
    exit 1
fi

echo "==> LSADRA Agent Installer"
echo "    Server: ${LSADRA_SERVER}"

# ── 1. Create install directory ───────────────────────────────────────────
echo "==> Creating ${INSTALL_DIR} ..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"

# ── 2. Download agent script ─────────────────────────────────────────────
echo "==> Downloading agent ..."
# In production this would pull a release artifact.  For the lab, we copy
# the Python script directly from the server or the local repo.
AGENT_URL="${LSADRA_SERVER}/agent/linux_agent.py"
curl -fsSL "${AGENT_URL}" -o "${INSTALL_DIR}/linux_agent.py" || {
    echo "Warning: Could not download agent from ${AGENT_URL}."
    echo "         Copy lsadra/endpoint_agent/linux_agent.py manually."
}

# ── 3. Register with server ──────────────────────────────────────────────
echo "==> Registering device with token ..."
HOSTNAME_VAL=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "linux-device")
OS_TYPE="linux"

RESPONSE=$(curl -sfS -X POST "${LSADRA_SERVER}/api/devices/register" \
    -H "Content-Type: application/json" \
    -d "{\"token\": \"${TOKEN}\", \"hostname\": \"${HOSTNAME_VAL}\", \"os_type\": \"${OS_TYPE}\"}" \
) || {
    echo "Error: Registration failed. Check token and server URL."
    exit 1
}

DEVICE_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['device_id'])")
API_KEY=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['api_key'])")
COLLECTOR_URL=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['collector_url'])")
LOG_PATHS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(','.join(json.load(sys.stdin)['log_paths']))")

echo "    Device ID:  ${DEVICE_ID}"
echo "    Collector:  ${COLLECTOR_URL}"

# ── 4. Write config ──────────────────────────────────────────────────────
echo "==> Writing config to ${CONFIG_FILE} ..."
cat > "${CONFIG_FILE}" <<EOF
# LSADRA Agent Configuration (auto-generated)
server_url: "${LSADRA_SERVER}"
collector_endpoint: "${COLLECTOR_URL}"
device_id: "${DEVICE_ID}"
api_key: "${API_KEY}"
log_paths:
$(echo "${LOG_PATHS}" | tr ',' '\n' | sed 's/^/  - /')
batch_size: 50
flush_interval_seconds: 10
EOF

chmod 600 "${CONFIG_FILE}"

# ── 5. Create systemd service ────────────────────────────────────────────
echo "==> Installing systemd service ..."

# Optional: create a dedicated low-priv user
if ! id -u "${AGENT_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${AGENT_USER}" || true
fi

# Fix permissions so the agent user can read the config
chown "${AGENT_USER}:${AGENT_USER}" "${CONFIG_FILE}"
chmod 600 "${CONFIG_FILE}"

# Grant read access to auth.log (many distros restrict it to root/adm)
usermod -aG adm "${AGENT_USER}" 2>/dev/null || true

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=LSADRA Endpoint Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/linux_agent.py --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

echo "==> Installation complete.  Status:"
systemctl status "${SERVICE_NAME}" --no-pager || true
echo ""
echo "Done!  The agent is tailing ${LOG_PATHS} and sending events to ${LSADRA_SERVER}."
