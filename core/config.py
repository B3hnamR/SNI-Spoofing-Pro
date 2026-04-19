from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass

from utils.network_tools import get_default_interface_ipv4


def get_runtime_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass(frozen=True)
class Config:
    listen_host: str
    listen_port: int
    connect_ip: str
    connect_port: int
    fake_sni: bytes
    nfqueue_num: int
    interface_ipv4: str

    data_mode: str = "tls"
    bypass_method: str = "wrong_seq"
    bypass_timeout: float = 2.0
    connect_timeout: float = 5.0
    fake_delay_ms: float = 1.0

    recv_buffer: int = 65536
    max_connections: int = 0
    idle_timeout: int = 0
    rate_limit: int = 0

    handle_limit: int = 256
    accept_backlog: int = 256
    resource_pressure_backoff: float = 0.5

    log_level: str = "INFO"
    log_file: str = ""
    log_client_sni: bool = True
    stats_interval: int = 60

    browser_profile: str = "random"
    ttl_spoof: bool = True
    fake_send_workers: int = 2
    nfqueue_maxlen: int = 4096
    nfqueue_fail_open: bool = True
    narrow_nfqueue_filter: bool = True

    def validate(self) -> None:
        if not self.interface_ipv4:
            raise ValueError(f"Could not resolve local interface IPv4 for CONNECT_IP={self.connect_ip}")

        if not (1 <= self.listen_port <= 65535):
            raise ValueError(f"Invalid LISTEN_PORT={self.listen_port}")
        if not (1 <= self.connect_port <= 65535):
            raise ValueError(f"Invalid CONNECT_PORT={self.connect_port}")
        if self.data_mode != "tls":
            raise ValueError(f"Unsupported DATA_MODE={self.data_mode}")
        if self.bypass_method != "wrong_seq":
            raise ValueError(f"Unsupported BYPASS_METHOD={self.bypass_method}")
        if self.bypass_timeout <= 0:
            raise ValueError("BYPASS_TIMEOUT must be > 0")
        if self.connect_timeout <= 0:
            raise ValueError("CONNECT_TIMEOUT must be > 0")
        if self.fake_delay_ms < 0:
            raise ValueError("FAKE_DELAY_MS must be >= 0")
        if self.recv_buffer < 1024:
            raise ValueError("RECV_BUFFER must be >= 1024")
        if self.max_connections < 0:
            raise ValueError("MAX_CONNECTIONS must be >= 0")
        if self.idle_timeout < 0:
            raise ValueError("IDLE_TIMEOUT must be >= 0")
        if self.rate_limit < 0:
            raise ValueError("RATE_LIMIT must be >= 0")
        if self.handle_limit <= 0:
            raise ValueError("HANDLE_LIMIT must be > 0")
        if self.accept_backlog <= 0:
            raise ValueError("ACCEPT_BACKLOG must be > 0")
        if self.resource_pressure_backoff < 0:
            raise ValueError("RESOURCE_PRESSURE_BACKOFF must be >= 0")
        if self.nfqueue_num < 0:
            raise ValueError("NFQUEUE_NUM must be >= 0")
        if self.fake_send_workers <= 0:
            raise ValueError("FAKE_SEND_WORKERS must be > 0")
        if self.nfqueue_maxlen <= 0:
            raise ValueError("NFQUEUE_MAXLEN must be > 0")
        allowed_profiles = {"legacy", "random", "chrome", "firefox", "safari", "edge"}
        if self.browser_profile.lower() not in allowed_profiles:
            raise ValueError(f"Unsupported BROWSER_PROFILE={self.browser_profile}")


def load_config() -> Config:
    config_path = os.path.join(get_runtime_dir(), "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    connect_ip = raw["CONNECT_IP"]
    cfg = Config(
        listen_host=raw.get("LISTEN_HOST", "127.0.0.1"),
        listen_port=int(raw["LISTEN_PORT"]),
        connect_ip=connect_ip,
        connect_port=int(raw["CONNECT_PORT"]),
        fake_sni=raw["FAKE_SNI"].encode(),
        nfqueue_num=int(raw.get("NFQUEUE_NUM", 1)),
        interface_ipv4=get_default_interface_ipv4(connect_ip),
        data_mode=raw.get("DATA_MODE", "tls"),
        bypass_method=raw.get("BYPASS_METHOD", "wrong_seq"),
        bypass_timeout=float(raw.get("BYPASS_TIMEOUT", 2.0)),
        connect_timeout=float(raw.get("CONNECT_TIMEOUT", 5.0)),
        fake_delay_ms=float(raw.get("FAKE_DELAY_MS", 1.0)),
        recv_buffer=int(raw.get("RECV_BUFFER", 65536)),
        max_connections=int(raw.get("MAX_CONNECTIONS", 0)),
        idle_timeout=int(raw.get("IDLE_TIMEOUT", 0)),
        rate_limit=int(raw.get("RATE_LIMIT", 0)),
        handle_limit=int(raw.get("HANDLE_LIMIT", 256)),
        accept_backlog=int(raw.get("ACCEPT_BACKLOG", 256)),
        resource_pressure_backoff=float(raw.get("RESOURCE_PRESSURE_BACKOFF", 0.5)),
        log_level=raw.get("LOG_LEVEL", "INFO"),
        log_file=raw.get("LOG_FILE", ""),
        log_client_sni=bool(raw.get("LOG_CLIENT_SNI", True)),
        stats_interval=int(raw.get("STATS_INTERVAL", 60)),
        browser_profile=raw.get("BROWSER_PROFILE", "random"),
        ttl_spoof=bool(raw.get("TTL_SPOOF", True)),
        fake_send_workers=int(raw.get("FAKE_SEND_WORKERS", 2)),
        nfqueue_maxlen=int(raw.get("NFQUEUE_MAXLEN", 4096)),
        nfqueue_fail_open=bool(raw.get("NFQUEUE_FAIL_OPEN", True)),
        narrow_nfqueue_filter=bool(raw.get("NARROW_NFQUEUE_FILTER", True)),
    )
    cfg.validate()
    return cfg
