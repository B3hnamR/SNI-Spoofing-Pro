#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"
WHEEL_DIR="${WHEEL_DIR:-${SOURCE_DIR}/deploy/offline-wheels}"
OUTPUT_BUNDLE="${OUTPUT_BUNDLE:-$(dirname "${SOURCE_DIR}")/sni-spoofing-offline-bundle-$(date +%Y%m%d-%H%M%S).tar.gz}"

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "python3 not found"
  exit 1
fi

if [[ ! -f "${SOURCE_DIR}/requirements.txt" ]]; then
  echo "requirements.txt not found in ${SOURCE_DIR}"
  exit 1
fi

mkdir -p "${WHEEL_DIR}"
rm -f "${WHEEL_DIR}"/*.whl "${WHEEL_DIR}/MANIFEST.txt"

echo "[1/4] Building wheelhouse at ${WHEEL_DIR}"
if ! "${PYTHON_BIN}" -m pip wheel -r "${SOURCE_DIR}/requirements.txt" -w "${WHEEL_DIR}"; then
  echo "Default pip wheel failed, retrying with --break-system-packages"
  "${PYTHON_BIN}" -m pip wheel --break-system-packages -r "${SOURCE_DIR}/requirements.txt" -w "${WHEEL_DIR}"
fi

echo "[2/4] Writing wheelhouse manifest"
{
  echo "generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "python=$("${PYTHON_BIN}" -c 'import sys; print(sys.version.replace("\n"," "))')"
  echo "platform=$("${PYTHON_BIN}" -c 'import platform; print(platform.platform())')"
  echo "machine=$("${PYTHON_BIN}" -c 'import platform; print(platform.machine())')"
  echo "wheel_count=$(find "${WHEEL_DIR}" -maxdepth 1 -name '*.whl' | wc -l)"
  echo "requirements_sha256=$(sha256sum "${SOURCE_DIR}/requirements.txt" | awk '{print $1}')"
} > "${WHEEL_DIR}/MANIFEST.txt"

echo "[3/4] Creating offline bundle ${OUTPUT_BUNDLE}"
mkdir -p "$(dirname "${OUTPUT_BUNDLE}")"
tar \
  --exclude=".git" \
  --exclude="__pycache__" \
  --exclude="*.pyc" \
  --exclude=".qodo" \
  -czf "${OUTPUT_BUNDLE}" \
  -C "${SOURCE_DIR}" .

echo "[4/4] Done"
echo "Bundle: ${OUTPUT_BUNDLE}"
echo "Wheelhouse: ${WHEEL_DIR}"
echo
echo "Next on offline server:"
echo "  1) extract bundle"
echo "  2) run: sudo ./deploy/install-production.sh"
