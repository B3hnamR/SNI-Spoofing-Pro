from __future__ import annotations

import struct

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
SNI_EXTENSION = 0x0000
SNI_HOSTNAME = 0x00


def extract_sni(data: bytes) -> str | None:
    try:
        return _parse_sni(data)
    except Exception:
        return None


def _parse_sni(data: bytes) -> str | None:
    if len(data) < 5:
        return None
    if data[0] != TLS_HANDSHAKE:
        return None

    record_length = struct.unpack_from("!H", data, 3)[0]
    if len(data) < 5 + record_length:
        return None

    pos = 5
    if data[pos] != TLS_CLIENT_HELLO:
        return None

    hello_length = int.from_bytes(data[pos + 1:pos + 4], "big")
    pos += 4
    end = pos + hello_length
    if len(data) < end:
        return None

    pos += 2 + 32
    if pos >= end:
        return None

    session_id_len = data[pos]
    pos += 1 + session_id_len
    if pos + 2 > end:
        return None

    cipher_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2 + cipher_len
    if pos + 1 > end:
        return None

    compression_len = data[pos]
    pos += 1 + compression_len
    if pos + 2 > end:
        return None

    ext_total_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    ext_end = min(pos + ext_total_len, len(data))

    while pos + 4 <= ext_end:
        ext_type = struct.unpack_from("!H", data, pos)[0]
        ext_len = struct.unpack_from("!H", data, pos + 2)[0]
        pos += 4
        if ext_type == SNI_EXTENSION:
            return _parse_sni_ext(data, pos, pos + ext_len)
        pos += ext_len

    return None


def _parse_sni_ext(data: bytes, start: int, end: int) -> str | None:
    pos = start
    if pos + 2 > end:
        return None

    list_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    list_end = min(pos + list_len, end)

    while pos + 3 <= list_end:
        name_type = data[pos]
        name_len = struct.unpack_from("!H", data, pos + 1)[0]
        pos += 3
        if name_type == SNI_HOSTNAME and pos + name_len <= list_end:
            raw = data[pos:pos + name_len]
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode("ascii", errors="replace")
        pos += name_len
    return None

