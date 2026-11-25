#!/usr/bin/env bash
# ============================================================================
# LSADRA Agent Installer for Linux
#
# Usage (the dashboard's Connect Device page generates this command with the
# real hashes filled in):
#   curl -fsSLo lsadra-install.sh https://your-server/static/installer_linux.sh \
#     && echo "<installer-sha256>  lsadra-install.sh" | sha256sum -c - \
#     && sudo bash lsadra-install.sh --token ABC123 --server https://your-server \
#          --agent-sha256 <agent-sha256>
#
# The installer is never piped straight into a shell: it is saved, checked
# against the hash the dashboard shows, and only then run. It in turn refuses
# an agent (or --file name=sha256 extra file) whose SHA-256 differs, and refuses plain-HTTP
# servers unless --allow-insecure-http is given (local labs only).
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
LSADRA_SERVER="${LSADRA_SERVER:-https://your-lsadra-server.example.com}"
INSTALL_DIR="/opt/lsadra-agent"
CONFIG_DIR="/etc/lsadra-agent"
CONFIG_FILE="${CONFIG_DIR}/config.yml"
SERVICE_NAME="lsadra-agent"
AGENT_USER="lsadra-agent"
TOKEN=""
AGENT_SHA256=""
EXTRA_FILES=()   # name=sha256 pairs for optional agent files (e.g. posture checks)
ALLOW_INSECURE_HTTP=0

# ── Parse arguments ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --token)  TOKEN="$2"; shift 2 ;;
        --server) LSADRA_SERVER="$2"; shift 2 ;;
        --agent-sha256) AGENT_SHA256="$2"; shift 2 ;;
        --file) EXTRA_FILES+=("$2"); shift 2 ;;
        --allow-insecure-http) ALLOW_INSECURE_HTTP=1; shift ;;
        *)        echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$TOKEN" ]]; then
    echo "Error: --token is required."
    echo "Usage: sudo bash install-agent.sh --token <REGISTRATION_TOKEN>"
    exit 1
fi

if [[ ! "$AGENT_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Error: --agent-sha256 <64 hex chars> is required."
    echo "       Copy the full install command from the dashboard's Connect Device page."
    exit 1
fi

case "$LSADRA_SERVER" in
    https://*) ;;
    http://*)
        if [[ "$ALLOW_INSECURE_HTTP" -ne 1 ]]; then
            echo "Error: ${LSADRA_SERVER} is plain HTTP. The device API key would travel unencrypted."
            echo "       Serve LSADRA over HTTPS, or pass --allow-insecure-http for a local lab."
            exit 1
        fi
        echo "WARNING: plain HTTP server. Use this only on a trusted local network."
        ;;
    *) echo "Error: --server must start with https:// (or http:// with --allow-insecure-http)."; exit 1 ;;
esac

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
AGENT_TMP="$(mktemp)"
trap 'rm -f "${AGENT_TMP}"' EXIT
curl -fsSL "${AGENT_URL}" -o "${AGENT_TMP}" || {
    echo "Error: could not download the agent from ${AGENT_URL}."
    exit 1
}
if ! echo "${AGENT_SHA256}  ${AGENT_TMP}" | sha256sum -c - >/dev/null 2>&1; then
    echo "Error: the downloaded agent does not match the expected SHA-256."
    echo "       Nothing was installed. Regenerate the command from the dashboard and retry."
    exit 1
fi
install -m 0755 "${AGENT_TMP}" "${INSTALL_DIR}/linux_agent.py"

# Optional agent files, each verified like the agent. Names are restricted to
# a plain file name so a crafted --file cannot write outside INSTALL_DIR.
for spec in ${EXTRA_FILES[@]+"${EXTRA_FILES[@]}"}; do
    name="${spec%%=*}"
    sha="${spec#*=}"
    if [[ ! "$name" =~ ^[A-Za-z0-9_.-]+$ || "$name" == .* || ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
        echo "Error: bad --file value '${spec}' (expected name=<64 hex chars>)."
        exit 1
    fi
    curl -fsSL "${LSADRA_SERVER}/agent/${name}" -o "${AGENT_TMP}" || {
        echo "Error: could not download ${name}."
        exit 1
    }
    if ! echo "${sha}  ${AGENT_TMP}" | sha256sum -c - >/dev/null 2>&1; then
        echo "Error: ${name} does not match the expected SHA-256. Nothing more was installed."
        exit 1
    fi
    install -m 0644 "${AGENT_TMP}" "${INSTALL_DIR}/${name}"
done

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
