from __future__ import annotations

import threading
import time
from collections import defaultdict


def _fmt_bytes(value: int) -> str:
    units = ((1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "KB"), (1, "B"))
    for threshold, suffix in units:
        if value >= threshold:
            return f"{value / threshold:.1f}{suffix}"
    return "0B"


def _fmt_uptime(seconds: float) -> str:
    s = int(seconds)
    h, r = divmod(s, 3600)
    m, s = divmod(r, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self._start = time.monotonic()
        self.total = 0
        self.active = 0
        self.failed = 0
        self.relayed = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.bypass_ok = 0
        self.bypass_fail = 0
        self._sni_counts: dict[str, int] = defaultdict(int)
        self._ip_counts: dict[str, int] = defaultdict(int)

    def new_connection(self) -> None:
        with self._lock:
            self.total += 1
            self.active += 1

    def relay_started(self) -> None:
        with self._lock:
            self.relayed += 1

    def connection_done(self) -> None:
        with self._lock:
            self.active = max(0, self.active - 1)

    def connection_failed(self) -> None:
        with self._lock:
            self.failed += 1
            self.active = max(0, self.active - 1)

    def add_bytes_in(self, size: int) -> None:
        with self._lock:
            self.bytes_in += size

    def add_bytes_out(self, size: int) -> None:
        with self._lock:
            self.bytes_out += size

    def record_bypass(self, ok: bool) -> None:
        with self._lock:
            if ok:
                self.bypass_ok += 1
            else:
                self.bypass_fail += 1

    def record_sni(self, sni: str) -> None:
        with self._lock:
            self._sni_counts[sni] += 1

    def record_ip(self, ip: str) -> None:
        with self._lock:
            self._ip_counts[ip] += 1

    def top_snis(self, count: int = 5) -> list[tuple[str, int]]:
        with self._lock:
            return sorted(self._sni_counts.items(), key=lambda item: item[1], reverse=True)[:count]

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "uptime": _fmt_uptime(time.monotonic() - self._start),
                "total": self.total,
                "active": self.active,
                "failed": self.failed,
                "relayed": self.relayed,
                "bytes_in": _fmt_bytes(self.bytes_in),
                "bytes_out": _fmt_bytes(self.bytes_out),
                "bypass_ok": self.bypass_ok,
                "bypass_fail": self.bypass_fail,
            }


stats = Stats()
