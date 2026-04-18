from __future__ import annotations

import math
import os
import struct


def _secure_float() -> float:
    raw = struct.unpack("!Q", os.urandom(8))[0]
    return (raw & 0x000FFFFFFFFFFFFF) / (1 << 52)


def _gauss(mu: float, sigma: float) -> float:
    u1 = max(1e-10, _secure_float())
    u2 = _secure_float()
    z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
    return mu + sigma * z


def _weibull(scale: float, shape: float) -> float:
    u = max(1e-10, _secure_float())
    return scale * (-math.log(u)) ** (1.0 / shape)


def human_delay_s(base_ms: float = 1.0) -> float:
    sigma = base_ms * 0.3
    gauss_s = max(0.0, _gauss(base_ms, sigma)) / 1000.0
    if _secure_float() < 0.08:
        return gauss_s + _weibull(scale=0.008, shape=1.5)
    return gauss_s

