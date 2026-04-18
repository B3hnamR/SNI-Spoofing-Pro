import atexit
import logging
import subprocess
import sys
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

IS_WINDOWS = sys.platform.startswith("win")
WINDIVERT_AVAILABLE = False

if IS_WINDOWS:
    try:
        from pydivert import Packet, WinDivert
        WINDIVERT_AVAILABLE = True
    except ModuleNotFoundError:
        Packet = Any
        WinDivert = Any
else:
    import netfilterqueue
    import scapy.all as scapy

log = logging.getLogger("injecter")


@dataclass
class LinuxTcpView:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    syn: bool
    ack: bool
    rst: bool
    fin: bool
    psh: bool
    payload_len: int


class LinuxQueuedPacket:
    def __init__(self, nfpacket):
        self._nfpacket = nfpacket
        self.finalized = False
        raw = nfpacket.get_payload()
        self.pkt = scapy.IP(raw)

        if scapy.IP not in self.pkt or scapy.TCP not in self.pkt:
            raise ValueError("non tcp/ipv4 packet")

        ip_layer = self.pkt[scapy.IP]
        tcp_layer = self.pkt[scapy.TCP]
        flags = int(tcp_layer.flags)

        self.src_ip = ip_layer.src
        self.dst_ip = ip_layer.dst
        self.tcp = LinuxTcpView(
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            seq_num=tcp_layer.seq,
            ack_num=tcp_layer.ack,
            syn=bool(flags & 0x02),
            ack=bool(flags & 0x10),
            rst=bool(flags & 0x04),
            fin=bool(flags & 0x01),
            psh=bool(flags & 0x08),
            payload_len=len(bytes(tcp_layer.payload)),
        )

    def accept(self):
        if not self.finalized:
            self._nfpacket.accept()
            self.finalized = True

    def drop(self):
        if not self.finalized:
            self._nfpacket.drop()
            self.finalized = True


if not IS_WINDOWS:
    Packet = LinuxQueuedPacket
    WinDivert = Any


class TcpInjector(ABC):
    def __init__(
        self,
        w_filter: str,
        queue_num: int = 1,
        nfqueue_maxlen: int = 4096,
        nfqueue_fail_open: bool = True,
    ):
        self.w_filter = w_filter
        self.queue_num = queue_num
        self.nfqueue_maxlen = nfqueue_maxlen
        self.nfqueue_fail_open = nfqueue_fail_open
        self._cleanup_registered = False
        if IS_WINDOWS:
            self.w: WinDivert | None = WinDivert(w_filter) if WINDIVERT_AVAILABLE else None
        else:
            self.w = None
            self.nfq: netfilterqueue.NetfilterQueue | None = None
            self._linux_rules: list[tuple[str, list[str]]] = []

    @abstractmethod
    def inject(self, packet: Packet):
        sys.exit("Not implemented")

    def _run_iptables(self, args: list[str]) -> int:
        proc = subprocess.run(
            ["iptables", *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return proc.returncode

    def _register_cleanup(self):
        if self._cleanup_registered:
            return
        atexit.register(self.cleanup_linux_rules)
        self._cleanup_registered = True

    def _build_nfqueue_jump(self, fail_open: bool) -> list[str]:
        tail = ["-j", "NFQUEUE", "--queue-num", str(self.queue_num)]
        if fail_open:
            tail.append("--queue-bypass")
        return tail

    def _remove_rule_variant(self, chain: str, base_spec: list[str], fail_open: bool) -> None:
        full_spec = [*base_spec, *self._build_nfqueue_jump(fail_open)]
        while self._run_iptables(["-C", chain, *full_spec]) == 0:
            self._run_iptables(["-D", chain, *full_spec])

    def prepare_linux(self, src_ip: str, dst_ip: str, dst_port: int, narrow_filter: bool = True):
        if IS_WINDOWS:
            return

        rule_tag = f"sni-spoof-nfq-{self.queue_num}"
        if narrow_filter:
            self._linux_rules = [
                (
                    "OUTPUT",
                    [
                        "-p", "tcp",
                        "-s", src_ip,
                        "-d", dst_ip,
                        "--dport", str(dst_port),
                        "--tcp-flags", "SYN,ACK,FIN,RST", "SYN",
                        "-m", "comment", "--comment", rule_tag,
                    ],
                ),
                (
                    "OUTPUT",
                    [
                        "-p", "tcp",
                        "-s", src_ip,
                        "-d", dst_ip,
                        "--dport", str(dst_port),
                        "--tcp-flags", "SYN,ACK,FIN,RST,PSH", "ACK",
                        "-m", "comment", "--comment", rule_tag,
                    ],
                ),
                (
                    "INPUT",
                    [
                        "-p", "tcp",
                        "-s", dst_ip,
                        "-d", src_ip,
                        "--sport", str(dst_port),
                        "--tcp-flags", "SYN,ACK", "SYN,ACK",
                        "-m", "comment", "--comment", rule_tag,
                    ],
                ),
                (
                    "INPUT",
                    [
                        "-p", "tcp",
                        "-s", dst_ip,
                        "-d", src_ip,
                        "--sport", str(dst_port),
                        "--tcp-flags", "SYN,ACK,FIN,RST,PSH", "ACK",
                        "-m", "comment", "--comment", rule_tag,
                    ],
                ),
            ]
        else:
            self._linux_rules = [
                (
                    "OUTPUT",
                    [
                        "-p", "tcp",
                        "-s", src_ip,
                        "-d", dst_ip,
                        "--dport", str(dst_port),
                        "-m", "comment", "--comment", rule_tag,
                    ],
                ),
                (
                    "INPUT",
                    [
                        "-p", "tcp",
                        "-s", dst_ip,
                        "-d", src_ip,
                        "--sport", str(dst_port),
                        "-m", "comment", "--comment", rule_tag,
                    ],
                ),
            ]

        for chain, base_spec in self._linux_rules:
            self._remove_rule_variant(chain, base_spec, not self.nfqueue_fail_open)
            full_spec = [*base_spec, *self._build_nfqueue_jump(self.nfqueue_fail_open)]
            check_rc = self._run_iptables(["-C", chain, *full_spec])
            if check_rc != 0:
                self._run_iptables(["-I", chain, "1", *full_spec])

        self._register_cleanup()
        log.info(
            "Installed Linux NFQUEUE rules queue=%d maxlen=%d fail_open=%s narrow_filter=%s",
            self.queue_num,
            self.nfqueue_maxlen,
            self.nfqueue_fail_open,
            narrow_filter,
        )

    def cleanup_linux_rules(self):
        if IS_WINDOWS:
            return

        for chain, base_spec in self._linux_rules:
            self._remove_rule_variant(chain, base_spec, True)
            self._remove_rule_variant(chain, base_spec, False)

    def _linux_process_packet(self, nfpacket):
        try:
            packet = LinuxQueuedPacket(nfpacket)
        except Exception:
            nfpacket.accept()
            return

        try:
            self.inject(packet)
        except Exception:
            traceback.print_exc()
            if not packet.finalized:
                packet.accept()
            return

        if not packet.finalized:
            packet.accept()

    def run(self):
        if IS_WINDOWS:
            if self.w is None:
                raise RuntimeError("WinDivert is not available. Install pydivert on Windows.")
            with self.w:
                while True:
                    packet = self.w.recv(65575)
                    self.inject(packet)
            return

        backoff_s = 0.5
        try:
            while True:
                try:
                    self.nfq = netfilterqueue.NetfilterQueue()
                    self.nfq.bind(self.queue_num, self._linux_process_packet)
                    try:
                        self.nfq.set_mode(netfilterqueue.COPY_PACKET, 0xFFFF)
                    except Exception:
                        pass
                    try:
                        self.nfq.set_queue_maxlen(self.nfqueue_maxlen)
                    except Exception:
                        pass
                    log.info("NFQUEUE loop started queue=%d maxlen=%d", self.queue_num, self.nfqueue_maxlen)
                    self.nfq.run()
                    break
                except KeyboardInterrupt:
                    break
                except Exception as exc:
                    log.error("NFQUEUE loop crashed: %r, retrying in %.1fs", exc, backoff_s)
                    time.sleep(backoff_s)
                    backoff_s = min(backoff_s * 2.0, 10.0)
                finally:
                    try:
                        if self.nfq:
                            self.nfq.unbind()
                    except Exception:
                        pass
                    self.nfq = None
        finally:
            self.cleanup_linux_rules()
            log.info("NFQUEUE stopped and Linux rules cleaned up")
