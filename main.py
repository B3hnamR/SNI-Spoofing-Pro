from __future__ import annotations

import asyncio
import collections
import errno
import logging
import os
import signal
import socket
import threading
import time

from core.config import Config, load_config
from core.stats import stats
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
from logger_setup import setup_logging
from utils.fingerprint import build_client_hello, get_profile
from utils.packet_templates import ClientHelloMaker
from utils.sni_extractor import extract_sni

log = logging.getLogger("main")

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}
fake_connections_lock = threading.Lock()

_rate_buckets: dict[str, collections.deque[float]] = {}
_resource_pressure_until = 0.0


def _apply_keepalive(sock: socket.socket) -> None:
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def _is_resource_pressure_error(exc: BaseException) -> bool:
    if isinstance(exc, OSError):
        err = getattr(exc, "errno", None)
        if err in {errno.ENOBUFS, errno.ENOMEM, errno.EMFILE, errno.ENFILE}:
            return True
    return False


def _mark_resource_pressure(seconds: float) -> None:
    global _resource_pressure_until
    until = time.monotonic() + max(0.0, seconds)
    if until > _resource_pressure_until:
        _resource_pressure_until = until


async def _maybe_backoff_for_resource_pressure() -> None:
    delay = _resource_pressure_until - time.monotonic()
    if delay > 0:
        await asyncio.sleep(delay)


def _register_fake_connection(connection: FakeInjectiveConnection) -> None:
    with fake_connections_lock:
        fake_injective_connections[connection.id] = connection


def _unregister_fake_connection(connection: FakeInjectiveConnection) -> None:
    with fake_connections_lock:
        fake_injective_connections.pop(connection.id, None)


def _check_rate_limit(client_ip: str, limit: int) -> bool:
    now = time.monotonic()
    bucket = _rate_buckets.setdefault(client_ip, collections.deque())
    cutoff = now - 1.0
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= limit:
        return False
    bucket.append(now)
    return True


def _log_stats_summary() -> None:
    snap = stats.snapshot()
    bypass_total = snap["bypass_ok"] + snap["bypass_fail"]
    bypass_rate = (snap["bypass_ok"] / bypass_total * 100.0) if bypass_total else 0.0
    log.info(
        "Stats uptime=%s total=%d active=%d relayed=%d failed=%d up=%s down=%s bypass=%.1f%%(%d/%d)",
        snap["uptime"],
        snap["total"],
        snap["active"],
        snap["relayed"],
        snap["failed"],
        snap["bytes_in"],
        snap["bytes_out"],
        bypass_rate,
        snap["bypass_ok"],
        bypass_total,
    )
    top = stats.top_snis(5)
    if top:
        top_text = "  ".join(f"{sni}({count})" for sni, count in top)
        log.info("Top SNIs: %s", top_text)


async def _stats_loop(interval: int) -> None:
    while True:
        await asyncio.sleep(interval)
        _log_stats_summary()


async def _pipe(
    src: socket.socket,
    dst: socket.socket,
    peer: asyncio.Task | None,
    label: str,
    recv_buffer: int,
    direction: str,
    idle_timeout: int,
    resource_backoff: float,
) -> None:
    loop = asyncio.get_running_loop()
    try:
        while True:
            try:
                if idle_timeout > 0:
                    data = await asyncio.wait_for(loop.sock_recv(src, recv_buffer), timeout=idle_timeout)
                else:
                    data = await loop.sock_recv(src, recv_buffer)
            except asyncio.TimeoutError:
                log.debug("[%s] idle timeout (%ds)", label, idle_timeout)
                break
            except OSError as exc:
                if _is_resource_pressure_error(exc):
                    _mark_resource_pressure(resource_backoff)
                log.debug("[%s] recv failed: %r", label, exc)
                break

            if not data:
                break

            if direction == "in":
                stats.add_bytes_in(len(data))
            else:
                stats.add_bytes_out(len(data))

            try:
                await loop.sock_sendall(dst, data)
            except OSError as exc:
                if _is_resource_pressure_error(exc):
                    _mark_resource_pressure(resource_backoff)
                log.debug("[%s] send failed: %r", label, exc)
                break
    finally:
        try:
            src.close()
        except OSError:
            pass
        try:
            dst.close()
        except OSError:
            pass
        if peer is not None and not peer.done():
            peer.cancel()
            try:
                await asyncio.shield(peer)
            except Exception:
                pass


async def _pipe_with_sni(
    src: socket.socket,
    dst: socket.socket,
    peer: asyncio.Task | None,
    label: str,
    recv_buffer: int,
    client_addr: tuple,
    idle_timeout: int,
    resource_backoff: float,
) -> None:
    loop = asyncio.get_running_loop()
    accumulated = b""
    sni_logged = False
    try:
        while not sni_logged:
            try:
                if idle_timeout > 0:
                    chunk = await asyncio.wait_for(loop.sock_recv(src, recv_buffer), timeout=idle_timeout)
                else:
                    chunk = await loop.sock_recv(src, recv_buffer)
            except asyncio.TimeoutError:
                log.debug("[%s] idle timeout before SNI", label)
                return
            except OSError as exc:
                if _is_resource_pressure_error(exc):
                    _mark_resource_pressure(resource_backoff)
                log.debug("[%s] recv failed: %r", label, exc)
                return
            if not chunk:
                return

            accumulated += chunk
            extracted = extract_sni(accumulated)
            if extracted:
                log.info("SNI %-40s from %s", extracted, client_addr[0])
                stats.record_sni(extracted)
                sni_logged = True
            elif len(accumulated) > 16384:
                sni_logged = True

        stats.add_bytes_in(len(accumulated))
        try:
            await loop.sock_sendall(dst, accumulated)
        except OSError as exc:
            if _is_resource_pressure_error(exc):
                _mark_resource_pressure(resource_backoff)
            log.debug("[%s] send failed: %r", label, exc)
            return

        await _pipe(src, dst, peer, label, recv_buffer, "in", idle_timeout, resource_backoff)
    finally:
        try:
            src.close()
        except OSError:
            pass
        try:
            dst.close()
        except OSError:
            pass
        if peer is not None and not peer.done():
            peer.cancel()
            try:
                await asyncio.shield(peer)
            except Exception:
                pass


async def _relay_bidirectional(
    incoming_sock: socket.socket,
    outgoing_sock: socket.socket,
    cfg: Config,
    client_addr: tuple,
) -> None:
    server_to_client = asyncio.create_task(
        _pipe(
            outgoing_sock,
            incoming_sock,
            None,
            "out->in",
            cfg.recv_buffer,
            "out",
            cfg.idle_timeout,
            cfg.resource_pressure_backoff,
        )
    )
    if cfg.log_client_sni:
        await _pipe_with_sni(
            incoming_sock,
            outgoing_sock,
            server_to_client,
            "in->out",
            cfg.recv_buffer,
            client_addr,
            cfg.idle_timeout,
            cfg.resource_pressure_backoff,
        )
    else:
        await _pipe(
            incoming_sock,
            outgoing_sock,
            server_to_client,
            "in->out",
            cfg.recv_buffer,
            "in",
            cfg.idle_timeout,
            cfg.resource_pressure_backoff,
        )


async def handle(incoming_sock: socket.socket, incoming_remote_addr: tuple, cfg: Config) -> None:
    tracked = False
    finalized = False
    outgoing_sock: socket.socket | None = None
    fake_conn: FakeInjectiveConnection | None = None
    client_ip = incoming_remote_addr[0]

    try:
        await _maybe_backoff_for_resource_pressure()

        if cfg.rate_limit and not _check_rate_limit(client_ip, cfg.rate_limit):
            log.warning("Rate limit hit for %s (%d/s)", client_ip, cfg.rate_limit)
            try:
                incoming_sock.close()
            except OSError:
                pass
            return

        snap = stats.snapshot()
        if cfg.max_connections and snap["active"] >= cfg.max_connections:
            log.warning("Connection limit reached (%d), rejecting %s:%d", cfg.max_connections, client_ip, incoming_remote_addr[1])
            try:
                incoming_sock.close()
            except OSError:
                pass
            return

        stats.new_connection()
        tracked = True
        stats.record_ip(client_ip)
        snap = stats.snapshot()
        log.info("CONN %s:%d [active=%d total=%d]", client_ip, incoming_remote_addr[1], snap["active"], snap["total"])

        if cfg.data_mode != "tls":
            raise RuntimeError(f"Unsupported mode: {cfg.data_mode}")

        if cfg.browser_profile.lower() == "legacy":
            fake_data = ClientHelloMaker.get_client_hello_with(
                os.urandom(32),
                os.urandom(32),
                cfg.fake_sni,
                os.urandom(32),
            )
        else:
            profile = get_profile(cfg.browser_profile)
            fake_data = build_client_hello(profile, cfg.fake_sni)
            log.debug("Using browser profile: %s", profile.name)

        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _apply_keepalive(outgoing_sock)
        outgoing_sock.bind((cfg.interface_ipv4, 0))
        src_port = outgoing_sock.getsockname()[1]

        fake_conn = FakeInjectiveConnection(
            outgoing_sock,
            cfg.interface_ipv4,
            cfg.connect_ip,
            src_port,
            cfg.connect_port,
            fake_data,
            cfg.bypass_method,
            incoming_sock,
            fake_delay_ms=cfg.fake_delay_ms,
            ttl_spoof=cfg.ttl_spoof,
            browser_profile=cfg.browser_profile,
        )
        _register_fake_connection(fake_conn)

        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(loop.sock_connect(outgoing_sock, (cfg.connect_ip, cfg.connect_port)), timeout=cfg.connect_timeout)
        except Exception as exc:
            if _is_resource_pressure_error(exc):
                _mark_resource_pressure(cfg.resource_pressure_backoff)
            log.warning("Connect failed to %s:%d (%r)", cfg.connect_ip, cfg.connect_port, exc)
            _unregister_fake_connection(fake_conn)
            fake_conn.monitor = False
            if outgoing_sock:
                outgoing_sock.close()
            incoming_sock.close()
            stats.connection_failed()
            finalized = True
            return

        try:
            await asyncio.wait_for(fake_conn.t2a_event.wait(), timeout=cfg.bypass_timeout)
            if fake_conn.t2a_msg != "fake_data_ack_recv":
                raise ValueError(fake_conn.t2a_msg or "missing handshake msg")
        except Exception as exc:
            log.warning("Bypass handshake failed for %s:%d (%r)", client_ip, incoming_remote_addr[1], exc)
            _unregister_fake_connection(fake_conn)
            fake_conn.monitor = False
            if outgoing_sock:
                outgoing_sock.close()
            incoming_sock.close()
            stats.connection_failed()
            finalized = True
            return

        _unregister_fake_connection(fake_conn)
        fake_conn.monitor = False
        stats.relay_started()
        log.info("RELAY %s:%d <-> %s:%d", client_ip, incoming_remote_addr[1], cfg.connect_ip, cfg.connect_port)

        await _relay_bidirectional(incoming_sock, outgoing_sock, cfg, incoming_remote_addr)
        log.info("CLOSE %s:%d", client_ip, incoming_remote_addr[1])
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("Unhandled error for %s", incoming_remote_addr)
        if tracked and not finalized:
            stats.connection_failed()
            finalized = True
    finally:
        if fake_conn is not None:
            fake_conn.monitor = False
            _unregister_fake_connection(fake_conn)
        if outgoing_sock is not None:
            try:
                outgoing_sock.close()
            except OSError:
                pass
        try:
            incoming_sock.close()
        except OSError:
            pass
        if tracked and not finalized:
            stats.connection_done()


async def run_server(cfg: Config) -> None:
    handle_semaphore = asyncio.Semaphore(cfg.handle_limit)
    active_tasks: set[asyncio.Task] = set()

    async def handle_wrapper(incoming_sock: socket.socket, addr: tuple) -> None:
        try:
            await handle(incoming_sock, addr, cfg)
        finally:
            handle_semaphore.release()

    def _on_task_done(task: asyncio.Task) -> None:
        active_tasks.discard(task)
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            return
        if exc is not None:
            log.error("Handle task crashed: %r", exc)

    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _apply_keepalive(mother_sock)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((cfg.listen_host, cfg.listen_port))
    mother_sock.listen(cfg.accept_backlog)

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _on_signal() -> None:
        log.info("Shutdown signal received")
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _on_signal)
        loop.add_signal_handler(signal.SIGTERM, _on_signal)
    except NotImplementedError:
        pass

    if cfg.stats_interval > 0:
        asyncio.create_task(_stats_loop(cfg.stats_interval))

    log.info(
        "Listening on %s:%d target=%s:%d interface=%s",
        cfg.listen_host,
        cfg.listen_port,
        cfg.connect_ip,
        cfg.connect_port,
        cfg.interface_ipv4,
    )

    try:
        while not stop_event.is_set():
            await _maybe_backoff_for_resource_pressure()
            await handle_semaphore.acquire()
            try:
                incoming_sock, addr = await asyncio.wait_for(loop.sock_accept(mother_sock), timeout=1.0)
            except asyncio.TimeoutError:
                handle_semaphore.release()
                continue
            except Exception:
                handle_semaphore.release()
                raise

            _apply_keepalive(incoming_sock)
            task = asyncio.create_task(handle_wrapper(incoming_sock, addr))
            active_tasks.add(task)
            task.add_done_callback(_on_task_done)
    finally:
        for task in list(active_tasks):
            task.cancel()
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)
        try:
            mother_sock.close()
        except OSError:
            pass
        _log_stats_summary()


def start_injector(cfg: Config) -> FakeTcpInjector:
    if os.name == "nt":
        packet_filter = (
            "tcp and ("
            + "(ip.SrcAddr == " + cfg.interface_ipv4 + " and ip.DstAddr == " + cfg.connect_ip + ")"
            + " or "
            + "(ip.SrcAddr == " + cfg.connect_ip + " and ip.DstAddr == " + cfg.interface_ipv4 + ")"
            + ")"
        )
    else:
        packet_filter = ""

    injector = FakeTcpInjector(
        packet_filter,
        fake_injective_connections,
        queue_num=cfg.nfqueue_num,
        fake_send_workers=cfg.fake_send_workers,
        nfqueue_maxlen=cfg.nfqueue_maxlen,
        nfqueue_fail_open=cfg.nfqueue_fail_open,
    )
    if os.name != "nt":
        injector.prepare_linux(
            cfg.interface_ipv4,
            cfg.connect_ip,
            cfg.connect_port,
            narrow_filter=cfg.narrow_nfqueue_filter,
        )
    threading.Thread(target=injector.run, daemon=True, name="injector").start()
    return injector


if __name__ == "__main__":
    cfg = load_config()
    setup_logging(cfg.log_level, cfg.log_file)
    log = logging.getLogger("main")

    log.info(
        "Starting SNI server (mode=%s bypass=%s profile=%s workers=%d ttl_spoof=%s nfq=%d maxlen=%d fail_open=%s narrow=%s)",
        cfg.data_mode,
        cfg.bypass_method,
        cfg.browser_profile,
        cfg.fake_send_workers,
        cfg.ttl_spoof,
        cfg.nfqueue_num,
        cfg.nfqueue_maxlen,
        cfg.nfqueue_fail_open,
        cfg.narrow_nfqueue_filter,
    )
    start_injector(cfg)
    asyncio.run(run_server(cfg))
