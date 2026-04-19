#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${TARGET_DIR:-/opt/sni-spoofing}"
SERVICE_NAME="${SERVICE_NAME:-sni-spoofing}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3)}"

if [[ "${TARGET_DIR}" == "/" || "${TARGET_DIR}" == "/opt" || "${TARGET_DIR}" == "" ]]; then
  echo "Unsafe TARGET_DIR=${TARGET_DIR}"
  exit 1
fi

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "python3 not found"
  exit 1
fi

echo "[1/6] Installing app files to ${TARGET_DIR}"
rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"
cp -a "${SOURCE_DIR}/." "${TARGET_DIR}/"
find "${TARGET_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +

echo "[2/6] Installing Python dependencies"
if ! "${PYTHON_BIN}" -m pip install -r "${TARGET_DIR}/requirements.txt"; then
  echo "Default pip install failed, retrying with --break-system-packages"
  "${PYTHON_BIN}" -m pip install --break-system-packages -r "${TARGET_DIR}/requirements.txt"
fi

echo "[2.1/6] Verifying Python modules (netfilterqueue, scapy)"
"${PYTHON_BIN}" - <<'PY'
import importlib
import sys

checks = ("netfilterqueue", "scapy.all")
for mod in checks:
    try:
        importlib.import_module(mod)
    except Exception as exc:
        print(f"missing {mod}: {exc!r}")
        sys.exit(1)
print("python-modules-ok")
PY

echo "[3/6] Preparing runtime logs"
mkdir -p /var/log/sni-spoofing
chown root:root /var/log/sni-spoofing
chmod 0755 /var/log/sni-spoofing

if ! grep -q '"LOG_FILE"' "${TARGET_DIR}/config.json"; then
  echo "Warning: LOG_FILE not found in config.json"
fi

echo "[4/6] Installing systemd unit ${SERVICE_NAME}.service"
SERVICE_TEMPLATE="${TARGET_DIR}/deploy/sni-spoofing.service.template"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
sed \
  -e "s|__WORKDIR__|${TARGET_DIR}|g" \
  -e "s|__PYTHON__|${PYTHON_BIN}|g" \
  "${SERVICE_TEMPLATE}" > "${SERVICE_DEST}"

echo "[5/6] Installing logrotate config"
cp "${TARGET_DIR}/deploy/logrotate-sni-spoofing.conf" "/etc/logrotate.d/${SERVICE_NAME}"

echo "[6/6] Enabling and restarting service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo
echo "Service status:"
systemctl --no-pager --full status "${SERVICE_NAME}" || true
echo
echo "Healthcheck example:"
echo "  ${PYTHON_BIN} ${TARGET_DIR}/deploy/healthcheck.py --config ${TARGET_DIR}/config.json --systemd-unit ${SERVICE_NAME}.service"
