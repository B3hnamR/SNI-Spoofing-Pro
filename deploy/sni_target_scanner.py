#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
USE_COLOR = sys.stdout.isatty()


def _paint(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _hdr(title: str) -> None:
    line = "=" * 72
    print(_paint(line, "1;36"))
    print(_paint(f" {title}", "1;36"))
    print(_paint(line, "1;36"))


def _ok(msg: str) -> None:
    print(f"{_paint('[OK ]', '1;32')} {msg}")


def _warn(msg: str) -> None:
    print(f"{_paint('[WARN]', '1;33')} {msg}")


def _fail(msg: str) -> None:
    print(f"{_paint('[FAIL]', '1;31')} {msg}")


def _info(msg: str) -> None:
    print(f"{_paint('[INFO]', '1;34')} {msg}")


@dataclass
class PortProbe:
    port: int
    open: bool
    latency_ms: float | None


@dataclass
class TargetResult:
    target: str
    ip: str
    open_ports: list[int]
    probes: list[PortProbe]
    best_port: int | None
    best_latency_ms: float | None
    e2e_checked: bool = False
    e2e_attempts: int = 0
    e2e_local_probe_ok: int = 0
    e2e_local_probe_fail: int = 0
    e2e_relay_ok: int = 0
    e2e_bypass_fail: int = 0
    e2e_success_rate: float = 0.0
    e2e_error: str = ""


def _is_ipv4(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 4
    except Exception:
        return False


def _is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except Exception:
        return False
    if ip.version != 4:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_config(path: Path, cfg: dict) -> None:
    path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _normalize_probe_host(host: str) -> str:
    h = (host or "").strip()
    if h in {"", "0.0.0.0", "::"}:
        return "127.0.0.1"
    return h


def _load_targets(path: Path) -> list[str]:
    targets: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def _resolve_target(target: str) -> list[str]:
    if _is_ipv4(target):
        return [target]

    ips: set[str] = set()
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    for info in infos:
        ip = info[4][0]
        if _is_ipv4(ip):
            ips.add(ip)

    ordered = sorted(ips)
    public_only = [ip for ip in ordered if _is_public_ipv4(ip)]
    return public_only or ordered


def _probe_tcp(ip: str, port: int, timeout_s: float) -> tuple[bool, float | None]:
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout_s):
            latency = (time.monotonic() - start) * 1000.0
            return True, round(latency, 2)
    except Exception:
        return False, None


def _scan_target_ip(target: str, ip: str, ports: list[int], timeout_s: float) -> TargetResult:
    probes: list[PortProbe] = []
    for port in ports:
        ok, latency_ms = _probe_tcp(ip, port, timeout_s)
        probes.append(PortProbe(port=port, open=ok, latency_ms=latency_ms))

    open_ports = [p.port for p in probes if p.open]
    best_port = None
    best_latency = None
    for port in ports:
        for probe in probes:
            if probe.port == port and probe.open:
                best_port = port
                best_latency = probe.latency_ms
                break
        if best_port is not None:
            break

    return TargetResult(
        target=target,
        ip=ip,
        open_ports=open_ports,
        probes=probes,
        best_port=best_port,
        best_latency_ms=best_latency,
    )


def _rank_candidates(results: list[TargetResult], port_priority: list[int]) -> list[TargetResult]:
    ok_results = [r for r in results if r.open_ports]
    if not ok_results:
        return []

    def _first_open_port_idx(result: TargetResult) -> int:
        for idx, port in enumerate(port_priority):
            if port in result.open_ports:
                return idx
        return len(port_priority) + 1

    def _lat_on_first_open(result: TargetResult) -> float:
        for port in port_priority:
            for p in result.probes:
                if p.port == port and p.open:
                    return p.latency_ms if p.latency_ms is not None else 999999.0
        return result.best_latency_ms if result.best_latency_ms is not None else 999999.0

    def _key_fn(result: TargetResult) -> tuple[int, float, int, str, str]:
        domain_bias = 0 if not _is_ipv4(result.target) else 1
        return (
            _first_open_port_idx(result),
            _lat_on_first_open(result),
            domain_bias,
            result.target,
            result.ip,
        )

    return sorted(ok_results, key=_key_fn)


def _apply_candidate_to_config(config_path: Path, cand: TargetResult, set_fake_sni: bool) -> dict[str, str]:
    cfg = _load_config(config_path)
    changes: dict[str, str] = {}

    old_ip = str(cfg.get("CONNECT_IP", ""))
    old_port = int(cfg.get("CONNECT_PORT", 443))
    old_sni = str(cfg.get("FAKE_SNI", ""))

    new_ip = cand.ip
    new_port = int(cand.best_port or 443)
    new_sni = cand.target if (set_fake_sni and not _is_ipv4(cand.target)) else old_sni

    if new_ip != old_ip:
        cfg["CONNECT_IP"] = new_ip
        changes["CONNECT_IP"] = f"{old_ip} -> {new_ip}"
    if new_port != old_port:
        cfg["CONNECT_PORT"] = new_port
        changes["CONNECT_PORT"] = f"{old_port} -> {new_port}"
    if new_sni != old_sni:
        cfg["FAKE_SNI"] = new_sni
        changes["FAKE_SNI"] = f"{old_sni} -> {new_sni}"

    _save_config(config_path, cfg)
    return changes


def _format_line(result: TargetResult) -> str:
    total_ports = len(result.probes)
    open_ports = len(result.open_ports)
    best_port = result.best_port or "-"
    if result.best_latency_ms is None:
        best_lat = "-"
    else:
        best_lat = f"{result.best_latency_ms}ms"

    bits: list[str] = [
        f"tcp_open={open_ports}/{total_ports}",
        f"best={best_port}@{best_lat}",
    ]

    if result.e2e_checked:
        bits.append(
            "E2E:"
            f"relay={result.e2e_relay_ok}/{result.e2e_attempts} "
            f"bypass_fail={result.e2e_bypass_fail} "
            f"probe_fail={result.e2e_local_probe_fail} "
            f"rate={result.e2e_success_rate:.1f}%"
        )
        if result.e2e_error:
            bits.append(f"err={result.e2e_error}")

    return f"{result.target:<28} -> {result.ip:<15} | " + " ".join(bits)


def _service_restart(unit: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["systemctl", "restart", unit],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "systemctl restart failed").strip()
        return False, err

    for _ in range(25):
        rc = subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode
        if rc == 0:
            return True, ""
        time.sleep(0.2)
    return False, "service did not become active in time"


def _local_listener_probe(host: str, port: int, timeout_s: float, hold_s: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            if hold_s > 0:
                time.sleep(hold_s)
        return True, ""
    except Exception as exc:
        return False, repr(exc)


def _journal_slice(unit: str, since_epoch: float) -> tuple[bool, str]:
    cmd = [
        "journalctl",
        "-u",
        unit,
        "--since",
        f"@{max(0, int(since_epoch) - 1)}",
        "--no-pager",
        "-o",
        "cat",
    ]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "journalctl failed").strip()
        return False, err
    return True, proc.stdout


def _count_e2e_markers(log_text: str) -> tuple[int, int]:
    relay = 0
    bypass_fail = 0
    for line in log_text.splitlines():
        if "[main] RELAY " in line or " RELAY " in line:
            relay += 1
        if "Bypass handshake failed" in line:
            bypass_fail += 1
    return relay, bypass_fail


def _pick_best_by_e2e(cands: list[TargetResult]) -> TargetResult | None:
    usable = [c for c in cands if c.e2e_checked and not c.e2e_error]
    if not usable:
        return None

    return sorted(
        usable,
        key=lambda c: (
            -c.e2e_success_rate,
            -c.e2e_relay_ok,
            c.e2e_bypass_fail,
            c.best_latency_ms if c.best_latency_ms is not None else 999999.0,
            c.target,
            c.ip,
        ),
    )[0]


def _run_e2e_validation(
    config_path: Path,
    candidates: list[TargetResult],
    service_unit: str,
    set_fake_sni: bool,
    attempts: int,
    probe_timeout: float,
    probe_hold: float,
    settle_s: float,
) -> tuple[bool, str]:
    if not shutil.which("systemctl"):
        return False, "systemctl not found"
    if not shutil.which("journalctl"):
        return False, "journalctl not found"

    base_cfg = _load_config(config_path)
    probe_host = _normalize_probe_host(str(base_cfg.get("LISTEN_HOST", "127.0.0.1")))
    probe_port = int(base_cfg.get("LISTEN_PORT", 40443))

    _hdr("E2E BYPASS VALIDATION")
    _info(f"service={service_unit} probe={probe_host}:{probe_port} attempts={attempts}")

    for idx, cand in enumerate(candidates, start=1):
        cand.e2e_checked = True
        cand.e2e_attempts = attempts
        cand.e2e_local_probe_ok = 0
        cand.e2e_local_probe_fail = 0
        cand.e2e_relay_ok = 0
        cand.e2e_bypass_fail = 0
        cand.e2e_success_rate = 0.0
        cand.e2e_error = ""

        print("")
        print(_paint(f"[E2E {idx}/{len(candidates)}] {cand.target} -> {cand.ip}:{cand.best_port or 443}", "1;37"))
        _apply_candidate_to_config(config_path, cand, set_fake_sni=set_fake_sni)

        t0 = time.time()
        ok_restart, restart_err = _service_restart(service_unit)
        if not ok_restart:
            cand.e2e_error = restart_err
            _fail(f"restart failed: {restart_err}")
            continue

        time.sleep(max(0.0, settle_s))

        first_probe_err = ""
        for _ in range(attempts):
            ok_probe, err_probe = _local_listener_probe(probe_host, probe_port, probe_timeout, probe_hold)
            if ok_probe:
                cand.e2e_local_probe_ok += 1
            else:
                cand.e2e_local_probe_fail += 1
                if not first_probe_err:
                    first_probe_err = err_probe
            time.sleep(0.15)

        time.sleep(0.5)
        ok_logs, logs_or_err = _journal_slice(service_unit, t0)
        if not ok_logs:
            cand.e2e_error = logs_or_err
            _warn(f"journal read failed: {logs_or_err}")
            continue

        relay_ok, bypass_fail = _count_e2e_markers(logs_or_err)
        cand.e2e_relay_ok = relay_ok
        cand.e2e_bypass_fail = bypass_fail
        cand.e2e_success_rate = (relay_ok * 100.0 / attempts) if attempts > 0 else 0.0

        local_part = f"probe_ok={cand.e2e_local_probe_ok}/{attempts} probe_fail={cand.e2e_local_probe_fail}"
        if first_probe_err:
            local_part += f" first_probe_err={first_probe_err}"
        if relay_ok > 0:
            _ok(
                f"E2E relay={relay_ok}/{attempts} bypass_fail={bypass_fail} "
                f"{local_part} rate={cand.e2e_success_rate:.1f}%"
            )
        else:
            _warn(
                f"E2E relay=0/{attempts} bypass_fail={bypass_fail} "
                f"{local_part} rate={cand.e2e_success_rate:.1f}%"
            )

    return True, ""


def _save_reports(
    output_dir: Path,
    scanned: list[TargetResult],
    resolve_failed: list[str],
    best: TargetResult | None,
    applied_changes: dict[str, str],
    e2e_enabled: bool,
    rollback_performed: bool,
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"sni-scan-{ts}.json"
    txt_path = output_dir / f"sni-scan-{ts}.txt"

    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_scanned_pairs": len(scanned),
            "ok_pairs": sum(1 for r in scanned if r.open_ports),
            "fail_pairs": sum(1 for r in scanned if not r.open_ports),
            "resolve_failed_targets": len(resolve_failed),
            "e2e_checked_pairs": sum(1 for r in scanned if r.e2e_checked),
            "e2e_positive_pairs": sum(1 for r in scanned if r.e2e_checked and r.e2e_relay_ok > 0),
            "rollback_performed": rollback_performed,
        },
        "e2e_enabled": e2e_enabled,
        "best": asdict(best) if best else None,
        "applied_changes": applied_changes,
        "resolve_failed": resolve_failed,
        "results": [
            {
                "target": r.target,
                "ip": r.ip,
                "open_ports": r.open_ports,
                "best_port": r.best_port,
                "best_latency_ms": r.best_latency_ms,
                "e2e_checked": r.e2e_checked,
                "e2e_attempts": r.e2e_attempts,
                "e2e_local_probe_ok": r.e2e_local_probe_ok,
                "e2e_local_probe_fail": r.e2e_local_probe_fail,
                "e2e_relay_ok": r.e2e_relay_ok,
                "e2e_bypass_fail": r.e2e_bypass_fail,
                "e2e_success_rate": r.e2e_success_rate,
                "e2e_error": r.e2e_error,
                "probes": [asdict(p) for p in r.probes],
            }
            for r in scanned
        ],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines: list[str] = []
    lines.append("=== SNI SCAN SUMMARY ===")
    lines.append(f"total_pairs: {len(scanned)}")
    lines.append(f"ok_pairs: {sum(1 for r in scanned if r.open_ports)}")
    lines.append(f"fail_pairs: {sum(1 for r in scanned if not r.open_ports)}")
    lines.append(f"resolve_failed_targets: {len(resolve_failed)}")
    lines.append(f"e2e_checked_pairs: {sum(1 for r in scanned if r.e2e_checked)}")
    lines.append(f"e2e_positive_pairs: {sum(1 for r in scanned if r.e2e_checked and r.e2e_relay_ok > 0)}")
    lines.append(f"rollback_performed: {rollback_performed}")
    lines.append("")

    ok_lines = [_format_line(r) for r in scanned if r.open_ports]
    fail_lines = [_format_line(r) for r in scanned if not r.open_ports]

    if ok_lines:
        lines.append("=== OK (at least one open port) ===")
        lines.extend(ok_lines)
        lines.append("")
    if fail_lines:
        lines.append("=== FAIL (all ports closed) ===")
        lines.extend(fail_lines)
        lines.append("")
    if resolve_failed:
        lines.append("=== RESOLVE FAILED ===")
        lines.extend(resolve_failed)
        lines.append("")

    if best:
        lines.append("=== BEST CANDIDATE ===")
        lines.append(_format_line(best))
        lines.append(f"selected CONNECT_IP={best.ip}")
        lines.append(f"selected CONNECT_PORT={best.best_port or 443}")
        if not _is_ipv4(best.target):
            lines.append(f"suggested FAKE_SNI={best.target}")
        lines.append("")

    if applied_changes:
        lines.append("=== APPLIED TO CONFIG ===")
        for key, val in applied_changes.items():
            lines.append(f"{key}: {val}")
        lines.append("")

    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, txt_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Integrated SNI target scanner for SNI-Spoofing-Pro")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--targets-file", default="deploy/scanner_targets.txt", help="Path to targets list")
    parser.add_argument("--output-dir", default="/var/log/sni-spoofing/scanner", help="Directory for reports")
    parser.add_argument("--timeout", type=float, default=1.2, help="TCP connect timeout per probe (seconds)")
    parser.add_argument(
        "--ports",
        default="443,2053,2083,2087,2096,8443",
        help="Comma-separated ports to scan in priority order",
    )
    parser.add_argument("--apply-best", action="store_true", help="Apply best candidate to config")
    parser.add_argument(
        "--set-fake-sni-from-domain",
        action="store_true",
        default=True,
        help="When best target is a domain, update FAKE_SNI with it",
    )
    parser.add_argument("--e2e-validate", action="store_true", help="Validate top candidates with real bypass checks")
    parser.add_argument("--e2e-service-unit", default="sni-spoofing.service", help="Systemd unit used for E2E")
    parser.add_argument("--e2e-top-k", type=int, default=3, help="How many top TCP candidates to validate with E2E")
    parser.add_argument("--e2e-attempts", type=int, default=3, help="Per-candidate local probe attempts")
    parser.add_argument("--e2e-probe-timeout", type=float, default=2.0, help="Timeout for local probe connect")
    parser.add_argument("--e2e-probe-hold", type=float, default=0.35, help="Seconds to hold local probe socket open")
    parser.add_argument("--e2e-settle", type=float, default=0.8, help="Seconds to wait after restart before probing")
    parser.add_argument(
        "--no-e2e-auto-rollback",
        action="store_true",
        help="Disable rollback to original config when applied E2E best has zero relay",
    )
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    targets_path = Path(args.targets_file).resolve()
    output_dir = Path(args.output_dir).resolve()
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    if not ports:
        ports = DEFAULT_PORTS

    if not config_path.exists():
        _fail(f"missing config: {config_path}")
        return 2
    if not targets_path.exists():
        _fail(f"missing targets file: {targets_path}")
        return 2

    targets = _load_targets(targets_path)
    if not targets:
        _warn(f"no targets in {targets_path}")
        return 1

    original_cfg_raw = config_path.read_text(encoding="utf-8")

    _hdr("SNI TARGET SCANNER")
    _info(f"targets={len(targets)} ports={ports} timeout={args.timeout}s")
    _info(f"config={config_path}")
    _info(f"targets_file={targets_path}")
    _info(f"output_dir={output_dir}")
    if args.e2e_validate:
        _info(
            "e2e=enabled "
            f"top_k={args.e2e_top_k} attempts={args.e2e_attempts} "
            f"service={args.e2e_service_unit}"
        )
    print("")
    scanned: list[TargetResult] = []
    resolve_failed: list[str] = []

    total_targets = len(targets)
    for idx, target in enumerate(targets, start=1):
        print(_paint(f"[{idx}/{total_targets}] target={target}", "1;37"))
        ips = _resolve_target(target)
        if not ips:
            _fail(f"resolve failed: {target}")
            resolve_failed.append(target)
            continue
        for ip in ips:
            result = _scan_target_ip(target, ip, ports, args.timeout)
            scanned.append(result)
            if result.open_ports:
                _ok(_format_line(result))
            else:
                _fail(_format_line(result))
        print("")

    ranked = _rank_candidates(scanned, ports)
    best = ranked[0] if ranked else None
    applied_changes: dict[str, str] = {}
    rollback_performed = False
    e2e_mutated_runtime = False

    if best and args.e2e_validate:
        top_k = max(1, int(args.e2e_top_k))
        shortlist = ranked[:top_k]
        ok_e2e, err_e2e = _run_e2e_validation(
            config_path=config_path,
            candidates=shortlist,
            service_unit=args.e2e_service_unit,
            set_fake_sni=args.set_fake_sni_from_domain,
            attempts=max(1, int(args.e2e_attempts)),
            probe_timeout=max(0.2, float(args.e2e_probe_timeout)),
            probe_hold=max(0.0, float(args.e2e_probe_hold)),
            settle_s=max(0.0, float(args.e2e_settle)),
        )
        if not ok_e2e:
            _warn(f"E2E validation disabled: {err_e2e}")
        else:
            e2e_mutated_runtime = True
            e2e_best = _pick_best_by_e2e(shortlist)
            if e2e_best is not None:
                best = e2e_best

    if best:
        _hdr("BEST CANDIDATE")
        print(_paint(_format_line(best), "1;32"))

        if args.apply_best:
            # Always restore original before final apply so diff is meaningful.
            config_path.write_text(original_cfg_raw, encoding="utf-8")

            auto_rollback = not args.no_e2e_auto_rollback
            if args.e2e_validate and auto_rollback and best.e2e_checked and best.e2e_relay_ok <= 0:
                rollback_performed = True
                _warn("E2E best has zero relay success. Auto-rollback kept original config.")
                if shutil.which("systemctl"):
                    _service_restart(args.e2e_service_unit)
            else:
                applied_changes = _apply_candidate_to_config(
                    config_path,
                    best,
                    set_fake_sni=args.set_fake_sni_from_domain,
                )
                if applied_changes:
                    _ok("config updated:")
                    for k, v in applied_changes.items():
                        print(f"  - {k}: {v}")
                else:
                    _ok("best candidate equals current config (no changes)")

                if args.e2e_validate and shutil.which("systemctl"):
                    ok_restart, restart_err = _service_restart(args.e2e_service_unit)
                    if not ok_restart:
                        _warn(f"final restart failed: {restart_err}")
    elif e2e_mutated_runtime:
        # E2E validation changes runtime config temporarily. Restore if scanner
        # was run without --apply-best.
        config_path.write_text(original_cfg_raw, encoding="utf-8")
        if shutil.which("systemctl"):
            ok_restart, restart_err = _service_restart(args.e2e_service_unit)
            if not ok_restart:
                _warn(f"restore restart failed: {restart_err}")
    else:
        _warn("no candidate with open port found.")

    json_path, txt_path = _save_reports(
        output_dir,
        scanned,
        resolve_failed,
        best,
        applied_changes,
        e2e_enabled=args.e2e_validate,
        rollback_performed=rollback_performed,
    )
    _hdr("SUMMARY")
    print(f"total_pairs   : {len(scanned)}")
    print(f"ok_pairs      : {sum(1 for r in scanned if r.open_ports)}")
    print(f"fail_pairs    : {sum(1 for r in scanned if not r.open_ports)}")
    print(f"resolve_failed: {len(resolve_failed)}")
    print(f"e2e_checked   : {sum(1 for r in scanned if r.e2e_checked)}")
    print(f"e2e_positive  : {sum(1 for r in scanned if r.e2e_checked and r.e2e_relay_ok > 0)}")
    print(f"rollback      : {rollback_performed}")
    print(f"report_json   : {json_path}")
    print(f"report_txt    : {txt_path}")

    if rollback_performed:
        return 1
    if not best:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
