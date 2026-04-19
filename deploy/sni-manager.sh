#!/usr/bin/env bash
set -u -o pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_DIR="${TARGET_DIR:-/opt/sni-spoofing}"
SERVICE_NAME="${SERVICE_NAME:-sni-spoofing}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOGROTATE_FILE="/etc/logrotate.d/${SERVICE_NAME}"
PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"
MANAGER_LINK="/usr/local/bin/sni-manager"

APP_CONFIG="${TARGET_DIR}/config.json"
APP_HEALTHCHECK="${TARGET_DIR}/deploy/healthcheck.py"
APP_REQUIREMENTS="${TARGET_DIR}/requirements.txt"
APP_SERVICE_TEMPLATE="${TARGET_DIR}/deploy/sni-spoofing.service.template"
APP_LOG_DIR="/var/log/sni-spoofing"
BACKUP_DIR="/var/backups/sni-spoofing"
SEPARATOR="------------------------------------------------------------"

if [[ -t 1 ]]; then
  C_RESET="\033[0m"
  C_BOLD="\033[1m"
  C_DIM="\033[2m"
  C_BLUE="\033[38;5;75m"
  C_GREEN="\033[38;5;77m"
  C_YELLOW="\033[38;5;220m"
  C_RED="\033[38;5;196m"
  C_CYAN="\033[38;5;81m"
else
  C_RESET=""
  C_BOLD=""
  C_DIM=""
  C_BLUE=""
  C_GREEN=""
  C_YELLOW=""
  C_RED=""
  C_CYAN=""
fi

print_banner() {
  clear
  echo -e "${C_BOLD}${C_BLUE}============================================================${C_RESET}"
  echo -e "${C_BOLD}${C_BLUE} SNI Spoofing Manager${C_RESET} ${C_DIM}(Ubuntu NFQUEUE Control Plane)${C_RESET}"
  echo -e "${C_BOLD}${C_BLUE}============================================================${C_RESET}"
  echo -e "${C_DIM}$(date '+%Y-%m-%d %H:%M:%S %Z')${C_RESET}"
  echo
}

info() { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
ok() { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
err() { echo -e "${C_RED}[ERR]${C_RESET} $*"; }

pause() {
  echo
  read -r -p "Press Enter to continue..."
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Run as root: sudo $0"
    exit 1
  fi
}

assert_safe_target() {
  if [[ "${TARGET_DIR}" == "/" || "${TARGET_DIR}" == "/opt" || -z "${TARGET_DIR}" ]]; then
    err "Unsafe TARGET_DIR=${TARGET_DIR}"
    exit 1
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    err "Missing command: ${cmd}"
    return 1
  fi
  return 0
}

is_installed() {
  [[ -f "${TARGET_DIR}/main.py" && -f "${APP_CONFIG}" && -f "${SERVICE_FILE}" ]]
}

service_active() {
  systemctl is-active --quiet "${SERVICE_NAME}.service"
}

service_enabled() {
  systemctl is-enabled --quiet "${SERVICE_NAME}.service"
}

nfqueue_rule_tag() {
  local qnum="1"
  if [[ -f "${APP_CONFIG}" ]]; then
    qnum="$(config_get NFQUEUE_NUM "1")"
  fi
  printf "sni-spoof-nfq-%s" "${qnum}"
}

configured_log_file() {
  if [[ -f "${APP_CONFIG}" ]]; then
    config_get LOG_FILE ""
  else
    printf ""
  fi
}

config_get() {
  local key="$1"
  local default="${2:-}"
  "${PYTHON_BIN}" - "${APP_CONFIG}" "${key}" "${default}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
default = sys.argv[3] if len(sys.argv) > 3 else ""
if not path.exists():
    print(default)
    sys.exit(0)
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print(default)
    sys.exit(0)
value = data.get(key, default)
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

config_set() {
  local key="$1"
  local value="$2"
  "${PYTHON_BIN}" - "${APP_CONFIG}" "${key}" "${value}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
key = sys.argv[2]
raw = sys.argv[3]

if not path.exists():
    raise SystemExit(f"missing config: {path}")

data = json.loads(path.read_text(encoding="utf-8"))
current = data.get(key, "")

if isinstance(current, bool):
    v = raw.strip().lower()
    if v in {"1", "true", "yes", "y", "on"}:
        new_value = True
    elif v in {"0", "false", "no", "n", "off"}:
        new_value = False
    else:
        raise SystemExit(f"invalid bool for {key}: {raw}")
elif isinstance(current, int):
    new_value = int(raw)
elif isinstance(current, float):
    new_value = float(raw)
else:
    new_value = raw

data[key] = new_value
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

merge_config_from_backup() {
  local backup_path="$1"
  "${PYTHON_BIN}" - "${APP_CONFIG}" "${backup_path}" <<'PY'
import json
import sys
from pathlib import Path

base_path = Path(sys.argv[1])
backup_path = Path(sys.argv[2])
if not base_path.exists() or not backup_path.exists():
    sys.exit(0)

base = json.loads(base_path.read_text(encoding="utf-8"))
old = json.loads(backup_path.read_text(encoding="utf-8"))
base.update(old)
base_path.write_text(json.dumps(base, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

install_system_packages() {
  info "Installing system dependencies (idempotent)"
  apt-get update -y
  apt-get install -y \
    python3 python3-pip python3-dev \
    build-essential libpcap-dev libnetfilter-queue-dev \
    iptables logrotate ca-certificates iputils-ping
}

sync_source_to_target() {
  if [[ "${SOURCE_DIR}" == "${TARGET_DIR}" ]]; then
    warn "Source and target are the same; skipping file sync."
    return 0
  fi

  info "Syncing source to ${TARGET_DIR}"
  rm -rf "${TARGET_DIR}"
  mkdir -p "${TARGET_DIR}"
  cp -a "${SOURCE_DIR}/." "${TARGET_DIR}/"
  find "${TARGET_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
}

install_python_deps() {
  info "Installing Python dependencies"
  local wheel_dir="${OFFLINE_WHEEL_DIR:-${TARGET_DIR}/deploy/offline-wheels}"
  if [[ -d "${wheel_dir}" ]] && compgen -G "${wheel_dir}/*.whl" >/dev/null 2>&1; then
    info "Using offline wheelhouse: ${wheel_dir}"
    if "${PYTHON_BIN}" -m pip install --no-index --find-links "${wheel_dir}" -r "${APP_REQUIREMENTS}"; then
      return 0
    fi
    warn "Offline install failed. Retrying with --break-system-packages."
    "${PYTHON_BIN}" -m pip install --break-system-packages --no-index --find-links "${wheel_dir}" -r "${APP_REQUIREMENTS}"
    return 0
  fi

  if "${PYTHON_BIN}" -m pip install -r "${APP_REQUIREMENTS}"; then
    return 0
  fi
  warn "Default pip install failed. Retrying with --break-system-packages (Ubuntu PEP 668)."
  "${PYTHON_BIN}" -m pip install --break-system-packages -r "${APP_REQUIREMENTS}"
}

verify_required_python_modules() {
  info "Verifying Python modules: netfilterqueue, scapy"
  "${PYTHON_BIN}" - <<'PY'
import importlib

checks = ("netfilterqueue", "scapy.all")
missing = []

for mod in checks:
    try:
        importlib.import_module(mod)
    except Exception as exc:
        missing.append((mod, repr(exc)))

if missing:
    print("python-modules-fail")
    for mod, err in missing:
        print(f"{mod}: {err}")
    raise SystemExit(1)

print("python-modules-ok")
PY
}

install_service_file() {
  info "Installing systemd service: ${SERVICE_NAME}.service"
  sed \
    -e "s|__WORKDIR__|${TARGET_DIR}|g" \
    -e "s|__PYTHON__|${PYTHON_BIN}|g" \
    "${APP_SERVICE_TEMPLATE}" > "${SERVICE_FILE}"
}

install_logrotate_file() {
  info "Installing logrotate policy"
  cp "${TARGET_DIR}/deploy/logrotate-sni-spoofing.conf" "${LOGROTATE_FILE}"
}

install_manager_link() {
  chmod +x "${TARGET_DIR}/deploy/sni-manager.sh" || true
  ln -sf "${TARGET_DIR}/deploy/sni-manager.sh" "${MANAGER_LINK}"
}

prepare_runtime_dirs() {
  mkdir -p "${APP_LOG_DIR}" "${BACKUP_DIR}"
  chown root:root "${APP_LOG_DIR}" "${BACKUP_DIR}"
  chmod 0755 "${APP_LOG_DIR}" "${BACKUP_DIR}"
}

backup_config_file() {
  if [[ ! -f "${APP_CONFIG}" ]]; then
    warn "Config not found: ${APP_CONFIG}"
    return 1
  fi
  mkdir -p "${BACKUP_DIR}"
  local ts
  ts="$(date +%Y%m%d-%H%M%S)"
  local backup_path="${BACKUP_DIR}/config-${ts}.json"
  cp "${APP_CONFIG}" "${backup_path}"
  ok "Config backed up: ${backup_path}"
}

restore_latest_config() {
  local latest
  latest="$(ls -1t "${BACKUP_DIR}"/config-*.json 2>/dev/null | head -n 1 || true)"
  if [[ -z "${latest}" ]]; then
    warn "No config backups found in ${BACKUP_DIR}"
    return 1
  fi
  cp "${latest}" "${APP_CONFIG}"
  ok "Restored config from: ${latest}"
}

bootstrap_install() {
  local mode="$1"  # first|upgrade
  assert_safe_target

  local backup_temp=""
  if [[ "${mode}" == "upgrade" && -f "${APP_CONFIG}" ]]; then
    backup_temp="$(mktemp)"
    cp "${APP_CONFIG}" "${backup_temp}"
  fi

  install_system_packages || return 1
  sync_source_to_target || return 1
  install_python_deps || return 1
  verify_required_python_modules || return 1
  prepare_runtime_dirs || return 1
  install_service_file || return 1
  install_logrotate_file || return 1
  install_manager_link || return 1

  if [[ -n "${backup_temp}" && -f "${backup_temp}" ]]; then
    merge_config_from_backup "${backup_temp}" || true
    rm -f "${backup_temp}"
  fi

  systemctl daemon-reload || return 1
  systemctl enable "${SERVICE_NAME}.service" || return 1
  systemctl restart "${SERVICE_NAME}.service" || return 1

  ok "Installation completed."
  ok "Run manager anytime with: sudo sni-manager"
}

ensure_bootstrapped() {
  if is_installed; then
    return 0
  fi
  info "First run detected. Installing runtime stack..."
  bootstrap_install "first"
}

show_dashboard() {
  print_banner
  local installed="NO"
  local active="inactive"
  local enabled="disabled"

  if is_installed; then
    installed="YES"
  fi
  if service_active; then
    active="active"
  fi
  if service_enabled; then
    enabled="enabled"
  fi

  echo -e "${C_BOLD}Installation${C_RESET}"
  echo "  Installed: ${installed}"
  echo "  Target:    ${TARGET_DIR}"
  echo "  Service:   ${SERVICE_NAME}.service (${active}, ${enabled})"
  echo "  Python:    ${PYTHON_BIN}"
  echo "  Rule Tag:  $(nfqueue_rule_tag)"
  echo
  echo -e "${C_BOLD}Current Config${C_RESET}"
  if [[ -f "${APP_CONFIG}" ]]; then
    echo "  LISTEN:    $(config_get LISTEN_HOST):$(config_get LISTEN_PORT)"
    echo "  TARGET:    $(config_get CONNECT_IP):$(config_get CONNECT_PORT)"
    echo "  FAKE_SNI:  $(config_get FAKE_SNI)"
    echo "  PROFILE:   $(config_get BROWSER_PROFILE)"
    echo "  WORKERS:   $(config_get FAKE_SEND_WORKERS)"
    echo "  NFQUEUE:   num=$(config_get NFQUEUE_NUM) maxlen=$(config_get NFQUEUE_MAXLEN) fail_open=$(config_get NFQUEUE_FAIL_OPEN) narrow=$(config_get NARROW_NFQUEUE_FILTER)"
    echo "  LOG_FILE:  $(config_get LOG_FILE)"
  else
    echo "  Missing config: ${APP_CONFIG}"
  fi
  echo
}

start_service() {
  systemctl start "${SERVICE_NAME}.service"
  ok "Service started."
}

stop_service() {
  systemctl stop "${SERVICE_NAME}.service"
  ok "Service stopped."
}

restart_service() {
  systemctl restart "${SERVICE_NAME}.service"
  ok "Service restarted."
}

status_service() {
  systemctl --no-pager --full status "${SERVICE_NAME}.service" || true
}

show_logs_live() {
  journalctl -u "${SERVICE_NAME}.service" -f -n 100
}

show_logs_recent() {
  echo -e "${C_BOLD}Recent logs (last 200 lines)${C_RESET}"
  journalctl -u "${SERVICE_NAME}.service" -n 200 --no-pager || true
  echo
  echo -e "${C_BOLD}Warnings/Errors (last 80 lines)${C_RESET}"
  journalctl -u "${SERVICE_NAME}.service" -p warning -n 80 --no-pager || true
}

show_app_logs_recent() {
  local logfile
  logfile="$(configured_log_file)"
  if [[ -z "${logfile}" ]]; then
    warn "LOG_FILE is empty. Application logs are going to journalctl."
    return 1
  fi
  if [[ ! -f "${logfile}" ]]; then
    warn "Configured LOG_FILE does not exist yet: ${logfile}"
    return 1
  fi
  echo -e "${C_BOLD}Application log file (last 200 lines)${C_RESET}"
  tail -n 200 "${logfile}"
}

show_app_logs_live() {
  local logfile
  logfile="$(configured_log_file)"
  if [[ -z "${logfile}" ]]; then
    warn "LOG_FILE is empty. Application logs are going to journalctl."
    return 1
  fi
  if [[ ! -f "${logfile}" ]]; then
    warn "Configured LOG_FILE does not exist yet: ${logfile}"
    return 1
  fi
  tail -f "${logfile}"
}

run_healthcheck() {
  if [[ ! -f "${APP_HEALTHCHECK}" ]]; then
    err "Healthcheck not found: ${APP_HEALTHCHECK}"
    return 1
  fi
  "${PYTHON_BIN}" "${APP_HEALTHCHECK}" --config "${APP_CONFIG}" --systemd-unit "${SERVICE_NAME}.service"
}

validate_config() {
  "${PYTHON_BIN}" - "${TARGET_DIR}" <<'PY'
import sys

target = sys.argv[1]
sys.path.insert(0, target)

from core.config import load_config

cfg = load_config()
print("config-ok")
print(f"listen={cfg.listen_host}:{cfg.listen_port}")
print(f"target={cfg.connect_ip}:{cfg.connect_port}")
print(f"profile={cfg.browser_profile} workers={cfg.fake_send_workers}")
print(f"nfqueue=num={cfg.nfqueue_num} maxlen={cfg.nfqueue_maxlen} fail_open={cfg.nfqueue_fail_open} narrow={cfg.narrow_nfqueue_filter}")
PY
}

tcp_probe() {
  local ip="$1"
  local port="$2"
  "${PYTHON_BIN}" - "${ip}" "${port}" <<'PY'
import socket
import sys

ip = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((ip, port), timeout=2.5):
        print(f"tcp-ok {ip}:{port}")
except Exception as exc:
    print(f"tcp-fail {ip}:{port} err={exc!r}")
    raise SystemExit(1)
PY
}

check_target_connectivity() {
  local host ip port
  host="$(config_get FAKE_SNI "")"
  ip="$(config_get CONNECT_IP "")"
  port="$(config_get CONNECT_PORT "443")"

  local failed=0
  local host_ips=""

  echo -e "${C_BOLD}Target Connectivity Check${C_RESET}"
  echo "${SEPARATOR}"
  echo "  host=${host}"
  echo "  ip=${ip}"
  echo "  port=${port}"
  echo

  if [[ -n "${host}" ]]; then
    host_ips="$(getent ahostsv4 "${host}" 2>/dev/null | awk '{print $1}' | sort -u)"
    if [[ -n "${host_ips}" ]]; then
      ok "DNS resolve for ${host}: $(echo "${host_ips}" | tr '\n' ' ' | sed 's/[[:space:]]\+$//')"
    else
      warn "DNS resolve failed for ${host}"
      failed=1
    fi

    if command -v ping >/dev/null 2>&1; then
      if ping -c 1 -W 2 "${host}" >/dev/null 2>&1; then
        ok "Ping host succeeded: ${host}"
      else
        warn "Ping host failed: ${host}"
        failed=1
      fi
    else
      warn "ping command is missing (install iputils-ping)"
      failed=1
    fi
  else
    warn "FAKE_SNI is empty"
    failed=1
  fi

  if [[ -n "${ip}" ]]; then
    if command -v ping >/dev/null 2>&1; then
      if ping -c 1 -W 2 "${ip}" >/dev/null 2>&1; then
        ok "Ping IP succeeded: ${ip}"
      else
        warn "Ping IP failed: ${ip}"
        failed=1
      fi
    else
      warn "ping command is missing (install iputils-ping)"
      failed=1
    fi

    local tcp_msg=""
    tcp_msg="$(tcp_probe "${ip}" "${port}" 2>&1)" && {
      ok "${tcp_msg}"
    } || {
      warn "${tcp_msg}"
      failed=1
    }
  else
    warn "CONNECT_IP is empty"
    failed=1
  fi

  if [[ -n "${host_ips}" && -n "${ip}" ]]; then
    if printf '%s\n' "${host_ips}" | grep -Fxq "${ip}"; then
      ok "CONNECT_IP is one of resolved host IPs."
    else
      warn "CONNECT_IP is not in current DNS resolution of ${host}."
    fi
  fi

  if [[ "${failed}" -eq 0 ]]; then
    ok "Connectivity check passed."
    return 0
  fi

  warn "Connectivity check failed. Target may be unreachable from this server."
  return 1
}

post_config_change_checks() {
  local failed=0
  echo
  echo -e "${C_BOLD}Post-Change Validation${C_RESET}"
  echo "${SEPARATOR}"

  if validate_config; then
    ok "Config validation passed."
  else
    warn "Config validation failed."
    failed=1
  fi
  echo
  if ! check_target_connectivity; then
    failed=1
  fi

  if [[ "${failed}" -eq 0 ]]; then
    ok "All post-change checks passed."
    return 0
  fi
  warn "One or more post-change checks failed."
  return 1
}

show_nfqueue_rules() {
  local tag
  tag="$(nfqueue_rule_tag)"
  echo -e "${C_BOLD}NFQUEUE rules for tag=${tag}${C_RESET}"
  echo "${SEPARATOR}"
  echo -e "${C_BOLD}INPUT${C_RESET}"
  iptables -S INPUT | grep -F -- "${tag}" || echo "(no tagged INPUT rules)"
  echo
  echo -e "${C_BOLD}OUTPUT${C_RESET}"
  iptables -S OUTPUT | grep -F -- "${tag}" || echo "(no tagged OUTPUT rules)"
}

remove_nfqueue_rules_by_tag() {
  local tag
  tag="$(nfqueue_rule_tag)"
  local removed=0
  local chain line delete_line
  local -a args

  for chain in INPUT OUTPUT; do
    while true; do
      line="$(iptables -S "${chain}" 2>/dev/null | grep -F -- "${tag}" | head -n 1 || true)"
      if [[ -z "${line}" ]]; then
        break
      fi
      delete_line="${line/-A /-D }"
      read -r -a args <<< "${delete_line}"
      if iptables "${args[@]}" >/dev/null 2>&1; then
        removed=$((removed + 1))
      else
        break
      fi
    done
  done

  ok "Removed ${removed} iptables rules tagged ${tag}."
}

reset_pipeline() {
  info "Resetting NFQUEUE pipeline (cleanup rules + restart)"
  remove_nfqueue_rules_by_tag
  restart_service
  run_healthcheck || true
}

rotate_logs_now() {
  if [[ ! -f "${LOGROTATE_FILE}" ]]; then
    warn "Logrotate policy not found: ${LOGROTATE_FILE}"
    return 1
  fi
  logrotate -f "${LOGROTATE_FILE}"
  ok "Logrotate forced for ${SERVICE_NAME}."
}

repair_python_dependencies() {
  info "Repairing runtime Python dependencies"
  install_system_packages || return 1
  install_python_deps || return 1
  verify_required_python_modules || return 1
  ok "Python dependency repair completed."
}

ensure_scanner_targets_file() {
  local targets_file="${TARGET_DIR}/deploy/scanner_targets.txt"
  if [[ -f "${targets_file}" ]]; then
    return 0
  fi
  cat > "${targets_file}" <<EOF
# One target per line (domain or IPv4)
$(config_get FAKE_SNI "dashboard.hcaptcha.com")
$(config_get CONNECT_IP "104.19.229.21")
dashboard.hcaptcha.com
104.19.229.21
EOF
  ok "Created scanner targets file: ${targets_file}"
}

edit_scanner_targets_file() {
  ensure_scanner_targets_file || return 1
  local targets_file="${TARGET_DIR}/deploy/scanner_targets.txt"
  local editor=""
  if command -v nano >/dev/null 2>&1; then
    editor="nano"
  elif command -v vim >/dev/null 2>&1; then
    editor="vim"
  else
    editor="vi"
  fi
  "${editor}" "${targets_file}"
}

show_latest_scanner_report() {
  local report_dir="${APP_LOG_DIR}/scanner"
  local latest_txt
  latest_txt="$(ls -1t "${report_dir}"/sni-scan-*.txt 2>/dev/null | head -n 1 || true)"
  if [[ -z "${latest_txt}" ]]; then
    warn "No scanner report found in ${report_dir}"
    return 1
  fi
  echo -e "${C_BOLD}Latest Scanner Report${C_RESET}"
  echo "${latest_txt}"
  echo "${SEPARATOR}"
  cat "${latest_txt}"
}

run_sni_scanner_apply_best() {
  local scanner_py="${TARGET_DIR}/deploy/sni_target_scanner.py"
  local targets_file="${TARGET_DIR}/deploy/scanner_targets.txt"
  local report_dir="${APP_LOG_DIR}/scanner"

  if [[ ! -f "${scanner_py}" ]]; then
    err "Scanner script missing: ${scanner_py}"
    return 1
  fi
  ensure_scanner_targets_file || return 1
  mkdir -p "${report_dir}"

  echo -e "${C_BOLD}Running integrated scanner${C_RESET}"
  echo "  targets=${targets_file}"
  echo "  reports=${report_dir}"
  echo

  "${PYTHON_BIN}" "${scanner_py}" \
    --config "${APP_CONFIG}" \
    --targets-file "${targets_file}" \
    --output-dir "${report_dir}" \
    --apply-best

  local rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    warn "Scanner finished with non-zero exit code: ${rc}"
  else
    ok "Scanner finished successfully."
  fi

  echo
  show_latest_scanner_report || true
  echo
  post_config_change_checks || true

  read -r -p "Restart service now? [Y/n]: " ans
  if [[ -z "${ans}" || "${ans}" =~ ^[Yy]$ ]]; then
    restart_service
  fi
  return 0
}

edit_config_file() {
  local editor=""
  if command -v nano >/dev/null 2>&1; then
    editor="nano"
  elif command -v vim >/dev/null 2>&1; then
    editor="vim"
  else
    editor="vi"
  fi
  "${editor}" "${APP_CONFIG}"
  post_config_change_checks || true
}

prompt_with_default() {
  local label="$1"
  local default="$2"
  local input=""
  read -r -p "${label} [${default}]: " input
  if [[ -z "${input}" ]]; then
    printf "%s" "${default}"
  else
    printf "%s" "${input}"
  fi
}

quick_config_wizard() {
  print_banner
  echo -e "${C_BOLD}Quick Config Wizard${C_RESET}"
  echo "Leave a field empty to keep current value."
  echo

  local keys=(
    "LISTEN_HOST"
    "LISTEN_PORT"
    "CONNECT_IP"
    "CONNECT_PORT"
    "FAKE_SNI"
    "BYPASS_TIMEOUT"
    "CONNECT_TIMEOUT"
    "FAKE_DELAY_MS"
    "BROWSER_PROFILE"
    "TTL_SPOOF"
    "FAKE_SEND_WORKERS"
    "NFQUEUE_NUM"
    "NFQUEUE_MAXLEN"
    "NFQUEUE_FAIL_OPEN"
    "NARROW_NFQUEUE_FILTER"
    "MAX_CONNECTIONS"
    "IDLE_TIMEOUT"
    "RATE_LIMIT"
    "LOG_LEVEL"
    "LOG_FILE"
    "LOG_CLIENT_SNI"
    "STATS_INTERVAL"
  )

  local key cur val
  for key in "${keys[@]}"; do
    cur="$(config_get "${key}")"
    val="$(prompt_with_default "${key}" "${cur}")"
    if ! config_set "${key}" "${val}"; then
      err "Failed to set ${key}=${val}"
      pause
      return 1
    fi
  done

  ok "Config updated."
  post_config_change_checks || true
  read -r -p "Restart service now? [Y/n]: " ans
  if [[ -z "${ans}" || "${ans}" =~ ^[Yy]$ ]]; then
    restart_service
  fi
}

apply_nfqueue_profile() {
  print_banner
  echo -e "${C_BOLD}NFQUEUE Tuning Profiles${C_RESET}"
  echo "1) Safe Default      -> fail-open=true,  narrow=true,  maxlen=4096"
  echo "2) Strict Control    -> fail-open=false, narrow=true,  maxlen=8192"
  echo "3) Throughput Bias   -> fail-open=true,  narrow=false, maxlen=16384"
  echo "0) Cancel"
  echo
  read -r -p "Select profile: " p

  case "${p}" in
    1)
      config_set "NFQUEUE_FAIL_OPEN" "true"
      config_set "NARROW_NFQUEUE_FILTER" "true"
      config_set "NFQUEUE_MAXLEN" "4096"
      ;;
    2)
      config_set "NFQUEUE_FAIL_OPEN" "false"
      config_set "NARROW_NFQUEUE_FILTER" "true"
      config_set "NFQUEUE_MAXLEN" "8192"
      ;;
    3)
      config_set "NFQUEUE_FAIL_OPEN" "true"
      config_set "NARROW_NFQUEUE_FILTER" "false"
      config_set "NFQUEUE_MAXLEN" "16384"
      ;;
    0) return 0 ;;
    *) warn "Invalid selection"; return 1 ;;
  esac

  ok "NFQUEUE profile applied."
  restart_service
}

upgrade_from_current_source() {
  local src_real
  src_real="$(readlink -f "${SOURCE_DIR}")"
  local tgt_real
  tgt_real="$(readlink -f "${TARGET_DIR}" 2>/dev/null || true)"

  if [[ "${src_real}" == "${tgt_real}" ]]; then
    warn "Current source is already the installed target."
    warn "Only dependencies and service files will be refreshed."
  fi

  bootstrap_install "upgrade"
}

uninstall_all() {
  echo
  warn "This will stop service and remove ${TARGET_DIR} + service files."
  read -r -p "Type DELETE to confirm: " confirm
  if [[ "${confirm}" != "DELETE" ]]; then
    warn "Canceled."
    return 1
  fi

  systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
  systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
  rm -f "${SERVICE_FILE}" "${LOGROTATE_FILE}" "${MANAGER_LINK}"
  systemctl daemon-reload
  rm -rf "${TARGET_DIR}"
  ok "Uninstalled. Logs/backups were kept in ${APP_LOG_DIR} and ${BACKUP_DIR}."
}

menu_loop() {
  while true; do
    show_dashboard
    echo -e "${C_BOLD}Operations${C_RESET}"
    echo " 1) Start service"
    echo " 2) Stop service"
    echo " 3) Restart service"
    echo " 4) Reset pipeline (cleanup NFQUEUE rules + restart)"
    echo " 5) Service status (full)"
    echo " 6) Live logs (journalctl -f)"
    echo " 7) Recent logs + warnings"
    echo " 8) App log file (recent)"
    echo " 9) App log file (live tail)"
    echo "10) Healthcheck"
    echo "11) Validate config"
    echo "12) Quick config wizard"
    echo "13) Edit config file"
    echo "14) Apply NFQUEUE tuning profile"
    echo "15) Show NFQUEUE iptables rules"
    echo "16) Cleanup NFQUEUE iptables rules"
    echo "17) Backup config"
    echo "18) Restore latest config backup"
    echo "19) Force logrotate now"
    echo "20) Upgrade/Reinstall from current source"
    echo "21) Uninstall"
    echo "22) Connectivity check (DNS + ping + TCP)"
    echo "23) Repair Python deps (NetfilterQueue/Scapy)"
    echo "24) Run SNI scanner + apply best to config"
    echo "25) Edit scanner targets list"
    echo "26) Show latest scanner report"
    echo " 0) Exit"
    echo
    read -r -p "Select option: " choice
    echo
    case "${choice}" in
      1) start_service; pause ;;
      2) stop_service; pause ;;
      3) restart_service; pause ;;
      4) reset_pipeline; pause ;;
      5) status_service; pause ;;
      6) show_logs_live ;;
      7) show_logs_recent; pause ;;
      8) show_app_logs_recent; pause ;;
      9) show_app_logs_live ;;
      10) run_healthcheck; pause ;;
      11) validate_config; pause ;;
      12) quick_config_wizard; pause ;;
      13) edit_config_file; pause ;;
      14) apply_nfqueue_profile; pause ;;
      15) show_nfqueue_rules; pause ;;
      16) remove_nfqueue_rules_by_tag; pause ;;
      17) backup_config_file; pause ;;
      18) restore_latest_config; post_config_change_checks || true; restart_service; pause ;;
      19) rotate_logs_now; pause ;;
      20) upgrade_from_current_source; pause ;;
      21) uninstall_all; pause ;;
      22) check_target_connectivity; pause ;;
      23) repair_python_dependencies; restart_service; pause ;;
      24) run_sni_scanner_apply_best; pause ;;
      25) edit_scanner_targets_file; pause ;;
      26) show_latest_scanner_report; pause ;;
      0) break ;;
      *) warn "Invalid option."; pause ;;
    esac
  done
}

main() {
  require_root
  assert_safe_target
  need_cmd systemctl || exit 1
  need_cmd iptables || exit 1
  need_cmd logrotate || exit 1
  if [[ -z "${PYTHON_BIN}" ]]; then
    err "python3 not found"
    exit 1
  fi

  ensure_bootstrapped || {
    err "Bootstrap failed. Check previous error lines."
    exit 1
  }
  menu_loop
}

main "$@"
