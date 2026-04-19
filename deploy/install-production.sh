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

find_bundle_file() {
  local candidate=""
  for candidate in \
    "${SOURCE_DIR}"/sni-spoofing-offline-bundle-*.tar.gz \
    "${TARGET_DIR}"/sni-spoofing-offline-bundle-*.tar.gz
  do
    if [[ -f "${candidate}" ]]; then
      printf "%s" "${candidate}"
      return 0
    fi
  done
  return 1
}

install_from_wheel_dir() {
  local wheel_dir="$1"
  if [[ ! -d "${wheel_dir}" ]] || ! compgen -G "${wheel_dir}/*.whl" >/dev/null 2>&1; then
    return 1
  fi
  echo "Using wheelhouse: ${wheel_dir}"
  if "${PYTHON_BIN}" -m pip install --no-index --find-links "${wheel_dir}" -r "${TARGET_DIR}/requirements.txt"; then
    return 0
  fi
  echo "Wheelhouse install failed, retrying with --break-system-packages"
  "${PYTHON_BIN}" -m pip install --break-system-packages --no-index --find-links "${wheel_dir}" -r "${TARGET_DIR}/requirements.txt"
}

install_from_bundle() {
  local bundle="$1"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  local wheel_dir=""
  echo "Trying offline bundle fallback: ${bundle}"
  if ! tar -xzf "${bundle}" -C "${tmp_dir}"; then
    rm -rf "${tmp_dir}"
    return 1
  fi
  wheel_dir="$(find "${tmp_dir}" -type d -path "*/deploy/offline-wheels" | head -n 1 || true)"
  if [[ -z "${wheel_dir}" ]]; then
    rm -rf "${tmp_dir}"
    return 1
  fi
  if install_from_wheel_dir "${wheel_dir}"; then
    rm -rf "${tmp_dir}"
    return 0
  fi
  rm -rf "${tmp_dir}"
  return 1
}

echo "[1/7] Installing system dependencies"
apt-get update -y
apt-get install -y \
  python3 python3-pip python3-dev \
  build-essential libpcap-dev libnetfilter-queue-dev \
  iptables logrotate ca-certificates iputils-ping

echo "[2/7] Installing app files to ${TARGET_DIR}"
rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"
cp -a "${SOURCE_DIR}/." "${TARGET_DIR}/"
find "${TARGET_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +

echo "[3/7] Installing Python dependencies"
if ! install_from_wheel_dir "${TARGET_DIR}/deploy/offline-wheels"; then
  if ! "${PYTHON_BIN}" -m pip install -r "${TARGET_DIR}/requirements.txt"; then
    echo "Default pip install failed, retrying with --break-system-packages"
    if ! "${PYTHON_BIN}" -m pip install --break-system-packages -r "${TARGET_DIR}/requirements.txt"; then
      BUNDLE_FILE="$(find_bundle_file || true)"
      if [[ -n "${BUNDLE_FILE}" ]]; then
        install_from_bundle "${BUNDLE_FILE}"
      else
        echo "No offline bundle found (sni-spoofing-offline-bundle-*.tar.gz)"
        exit 1
      fi
    fi
  fi
fi

echo "[3.1/7] Verifying Python modules (netfilterqueue, scapy)"
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

echo "[4/7] Preparing runtime logs"
mkdir -p /var/log/sni-spoofing
chown root:root /var/log/sni-spoofing
chmod 0755 /var/log/sni-spoofing

if ! grep -q '"LOG_FILE"' "${TARGET_DIR}/config.json"; then
  echo "Warning: LOG_FILE not found in config.json"
fi

echo "[5/7] Installing systemd unit ${SERVICE_NAME}.service"
SERVICE_TEMPLATE="${TARGET_DIR}/deploy/sni-spoofing.service.template"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}.service"
sed \
  -e "s|__WORKDIR__|${TARGET_DIR}|g" \
  -e "s|__PYTHON__|${PYTHON_BIN}|g" \
  "${SERVICE_TEMPLATE}" > "${SERVICE_DEST}"

echo "[6/7] Installing logrotate config"
cp "${TARGET_DIR}/deploy/logrotate-sni-spoofing.conf" "/etc/logrotate.d/${SERVICE_NAME}"

echo "[7/7] Enabling and restarting service"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

echo
echo "Service status:"
systemctl --no-pager --full status "${SERVICE_NAME}" || true
echo
echo "Healthcheck example:"
echo "  ${PYTHON_BIN} ${TARGET_DIR}/deploy/healthcheck.py --config ${TARGET_DIR}/config.json --systemd-unit ${SERVICE_NAME}.service"
