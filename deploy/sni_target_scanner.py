#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
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


def _pick_best(results: list[TargetResult], port_priority: list[int]) -> TargetResult | None:
    ok_results = [r for r in results if r.open_ports]
    if not ok_results:
        return None

    for port in port_priority:
        candidates = [r for r in ok_results if port in r.open_ports]
        if not candidates:
            continue

        def key_fn(r: TargetResult) -> tuple[float, int, str, str]:
            latency = next((p.latency_ms for p in r.probes if p.port == port and p.open), None)
            latency_key = latency if latency is not None else 999999.0
            domain_bias = 0 if not _is_ipv4(r.target) else 1
            return (latency_key, domain_bias, r.target, r.ip)

        return sorted(candidates, key=key_fn)[0]

    return sorted(ok_results, key=lambda r: (r.best_latency_ms or 999999.0, r.target, r.ip))[0]


def _apply_best_to_config(config_path: Path, best: TargetResult, set_fake_sni: bool) -> dict[str, str]:
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    changes: dict[str, str] = {}

    old_ip = str(cfg.get("CONNECT_IP", ""))
    old_port = int(cfg.get("CONNECT_PORT", 443))
    old_sni = str(cfg.get("FAKE_SNI", ""))

    new_ip = best.ip
    new_port = int(best.best_port or 443)
    new_sni = best.target if (set_fake_sni and not _is_ipv4(best.target)) else old_sni

    if new_ip != old_ip:
        cfg["CONNECT_IP"] = new_ip
        changes["CONNECT_IP"] = f"{old_ip} -> {new_ip}"
    if new_port != old_port:
        cfg["CONNECT_PORT"] = new_port
        changes["CONNECT_PORT"] = f"{old_port} -> {new_port}"
    if new_sni != old_sni:
        cfg["FAKE_SNI"] = new_sni
        changes["FAKE_SNI"] = f"{old_sni} -> {new_sni}"

    config_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return changes


def _format_line(result: TargetResult) -> str:
    bits: list[str] = []
    for probe in result.probes:
        if probe.open:
            lat = f"@{probe.latency_ms}ms" if probe.latency_ms is not None else ""
            bits.append(f"{probe.port}:OPEN{lat}")
        else:
            bits.append(f"{probe.port}:CLOSED")
    return f"{result.target:<28} -> {result.ip:<15} | " + " ".join(bits)


def _save_reports(
    output_dir: Path,
    scanned: list[TargetResult],
    resolve_failed: list[str],
    best: TargetResult | None,
    applied_changes: dict[str, str],
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
        },
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

    _hdr("SNI TARGET SCANNER")
    _info(f"targets={len(targets)} ports={ports} timeout={args.timeout}s")
    _info(f"config={config_path}")
    _info(f"targets_file={targets_path}")
    _info(f"output_dir={output_dir}")
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

    best = _pick_best(scanned, ports)
    applied_changes: dict[str, str] = {}

    if best:
        _hdr("BEST CANDIDATE")
        print(_paint(_format_line(best), "1;32"))
        if args.apply_best:
            applied_changes = _apply_best_to_config(config_path, best, set_fake_sni=args.set_fake_sni_from_domain)
            if applied_changes:
                _ok("config updated:")
                for k, v in applied_changes.items():
                    print(f"  - {k}: {v}")
            else:
                _ok("best candidate equals current config (no changes)")
    else:
        _warn("no candidate with open port found.")

    json_path, txt_path = _save_reports(output_dir, scanned, resolve_failed, best, applied_changes)
    _hdr("SUMMARY")
    print(f"total_pairs   : {len(scanned)}")
    print(f"ok_pairs      : {sum(1 for r in scanned if r.open_ports)}")
    print(f"fail_pairs    : {sum(1 for r in scanned if not r.open_ports)}")
    print(f"resolve_failed: {len(resolve_failed)}")
    print(f"report_json   : {json_path}")
    print(f"report_txt    : {txt_path}")

    if not best:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
