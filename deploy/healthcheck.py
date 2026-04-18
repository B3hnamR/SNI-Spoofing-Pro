#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path


def _load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _normalize_host(host: str) -> str:
    h = (host or "").strip()
    if h in {"0.0.0.0", "::", ""}:
        return "127.0.0.1"
    return h


def _check_tcp(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"tcp-ok {host}:{port}"
    except Exception as exc:
        return False, f"tcp-fail {host}:{port} err={exc!r}"


def _check_systemd(unit: str) -> tuple[bool, str]:
    proc = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        check=False,
    )
    if proc.returncode == 0:
        return True, f"systemd-ok unit={unit}"
    return False, f"systemd-fail unit={unit}"


def main() -> int:
    parser = argparse.ArgumentParser(description="SNI spoofing healthcheck")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--timeout", type=float, default=1.5, help="TCP connect timeout in seconds")
    parser.add_argument("--systemd-unit", default="", help="Optional systemd unit to validate")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    if not config_path.exists():
        print(f"healthcheck-fail missing-config path={config_path}")
        return 2

    try:
        cfg = _load_config(config_path)
    except Exception as exc:
        print(f"healthcheck-fail bad-config err={exc!r}")
        return 2

    host = _normalize_host(str(cfg.get("LISTEN_HOST", "127.0.0.1")))
    port = int(cfg.get("LISTEN_PORT", 0))
    if not (1 <= port <= 65535):
        print(f"healthcheck-fail bad-port value={port}")
        return 2

    if args.systemd_unit:
        ok, msg = _check_systemd(args.systemd_unit)
        print(msg)
        if not ok:
            return 3

    ok, msg = _check_tcp(host, port, args.timeout)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

