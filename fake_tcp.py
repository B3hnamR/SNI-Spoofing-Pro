import asyncio
import queue
import random
import socket
import sys
import threading
import time

from core.stats import stats
from injecter import IS_WINDOWS, Packet, TcpInjector
from monitor_connection import MonitorConnection
from utils.humanize import human_delay_s

if not IS_WINDOWS:
    import scapy.all as scapy


class FakeInjectiveConnection(MonitorConnection):
    def __init__(self, sock: socket.socket, src_ip, dst_ip,
                 src_port, dst_port, fake_data: bytes, bypass_method: str, peer_sock: socket.socket,
                 fake_delay_ms: float = 1.0, ttl_spoof: bool = True, browser_profile: str = "random"):
        super().__init__(sock, src_ip, dst_ip, src_port, dst_port)
        self.fake_data = fake_data
        self.sch_fake_sent = False
        self.fake_sent = False
        self.t2a_event = asyncio.Event()
        self.t2a_msg = ""
        self.bypass_method = bypass_method
        self.peer_sock = peer_sock
        self.running_loop = asyncio.get_running_loop()
        self.fake_delay_ms = fake_delay_ms
        self.ttl_spoof = ttl_spoof
        self.browser_profile = browser_profile


if IS_WINDOWS:
    class FakeTcpInjector(TcpInjector):

        def __init__(
            self,
            w_filter: str,
            connections: dict[tuple, FakeInjectiveConnection],
            queue_num: int = 1,
            fake_send_workers: int = 2,
            nfqueue_maxlen: int = 4096,
            nfqueue_fail_open: bool = True,
        ):
            super().__init__(
                w_filter,
                queue_num=queue_num,
                nfqueue_maxlen=nfqueue_maxlen,
                nfqueue_fail_open=nfqueue_fail_open,
            )
            self.connections = connections

        def fake_send_thread(self, packet: Packet, connection: FakeInjectiveConnection):
            time.sleep(0.001)
            with connection.thread_lock:
                if not connection.monitor:
                    return

                packet.tcp.psh = True
                packet.ip.packet_len = packet.ip.packet_len + len(connection.fake_data)
                packet.tcp.payload = connection.fake_data
                if packet.ipv4:
                    packet.ipv4.ident = (packet.ipv4.ident + 1) & 0xffff
                if connection.bypass_method == "wrong_seq":
                    packet.tcp.seq_num = (connection.syn_seq + 1 - len(packet.tcp.payload)) & 0xffffffff
                    connection.fake_sent = True
                    self.w.send(packet, True)
                else:
                    sys.exit("not implemented method!")

        def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
            print(info_m, packet)
            connection.sock.close()
            connection.peer_sock.close()
            connection.monitor = False
            connection.t2a_msg = "unexpected_close"
            connection.running_loop.call_soon_threadsafe(connection.t2a_event.set, )
            self.w.send(packet, False)

        def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
            if connection.syn_seq == -1:
                self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
                return
            if packet.tcp.ack and packet.tcp.syn and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                    len(packet.tcp.payload) == 0):
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound syn-ack packet, seq change! " + str(seq_num) + " " + str(
                                                  connection.syn_ack_seq))
                    return
                if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound syn-ack packet, ack not matched! " + str(
                                                  ack_num) + " " + str(connection.syn_seq))
                    return
                connection.syn_ack_seq = seq_num
                self.w.send(packet, False)
                return
            if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                    not packet.tcp.fin) and (len(packet.tcp.payload) == 0) and connection.fake_sent:
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound ack packet, seq not matched! " + str(seq_num) + " " + str(
                                                  connection.syn_ack_seq))
                    return
                if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound ack packet, ack not matched! " + str(ack_num) + " " + str(
                                                  connection.syn_seq))
                    return

                connection.monitor = False
                connection.t2a_msg = "fake_data_ack_recv"
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set, )
                return
            self.on_unexpected_packet(packet, connection, "unexpected inbound packet")
            return

        def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
            if connection.sch_fake_sent:
                self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
                return
            if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                    len(packet.tcp.payload) == 0):
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if ack_num != 0:
                    self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                    return
                if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                    self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, seq not matched! " + str(
                        seq_num) + " " + str(connection.syn_seq))
                    return
                connection.syn_seq = seq_num
                self.w.send(packet, False)
                return
            if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                    len(packet.tcp.payload) == 0):
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected outbound ack packet, seq not matched! " + str(
                                                  seq_num) + " " + str(
                                                  connection.syn_seq))
                    return
                if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected outbound ack packet, ack not matched! " + str(
                                                  ack_num) + " " + str(
                                                  connection.syn_ack_seq))
                    return

                self.w.send(packet, False)
                connection.sch_fake_sent = True
                threading.Thread(target=self.fake_send_thread, args=(packet, connection), daemon=True).start()
                return
            self.on_unexpected_packet(packet, connection, "unexpected outbound packet")
            return

        def inject(self, packet: Packet):
            if packet.is_inbound:
                c_id = (packet.ip.dst_addr, packet.tcp.dst_port, packet.ip.src_addr, packet.tcp.src_port)
                try:
                    connection = self.connections[c_id]
                except KeyError:
                    self.w.send(packet, False)
                else:
                    with connection.thread_lock:
                        if not connection.monitor:
                            self.w.send(packet, False)
                            return
                        self.on_inbound_packet(packet, connection)
            elif packet.is_outbound:
                c_id = (packet.ip.src_addr, packet.tcp.src_port, packet.ip.dst_addr, packet.tcp.dst_port)
                try:
                    connection = self.connections[c_id]
                except KeyError:
                    self.w.send(packet, False)
                else:
                    with connection.thread_lock:
                        if not connection.monitor:
                            self.w.send(packet, False)
                            return
                        self.on_outbound_packet(packet, connection)
            else:
                sys.exit("impossible direction!")
else:
    class FakeTcpInjector(TcpInjector):
        def __init__(
            self,
            w_filter: str,
            connections: dict[tuple, FakeInjectiveConnection],
            queue_num: int = 1,
            fake_send_workers: int = 2,
            nfqueue_maxlen: int = 4096,
            nfqueue_fail_open: bool = True,
        ):
            super().__init__(
                w_filter,
                queue_num=queue_num,
                nfqueue_maxlen=nfqueue_maxlen,
                nfqueue_fail_open=nfqueue_fail_open,
            )
            self.connections = connections
            self.fake_send_workers = max(1, int(fake_send_workers))
            self.fake_send_queue: queue.Queue[tuple[FakeInjectiveConnection, dict, threading.Event]] = queue.Queue()
            self._start_workers()

        def _start_workers(self):
            for idx in range(self.fake_send_workers):
                threading.Thread(target=self._fake_send_worker, daemon=True, name=f"fake-send-{idx}").start()

        def _fake_send_worker(self):
            while True:
                connection, result_holder, done_event = self.fake_send_queue.get()
                try:
                    self._send_fake_packet(connection)
                    result_holder["ok"] = True
                except Exception as exc:
                    result_holder["ok"] = False
                    result_holder["error"] = repr(exc)
                finally:
                    done_event.set()
                    self.fake_send_queue.task_done()

        def _notify(self, connection: FakeInjectiveConnection, msg: str):
            if connection.t2a_msg:
                return
            connection.t2a_msg = msg
            if msg == "fake_data_ack_recv":
                stats.record_bypass(True)
            elif msg == "unexpected_close":
                stats.record_bypass(False)
            try:
                connection.running_loop.call_soon_threadsafe(connection.t2a_event.set)
            except RuntimeError:
                pass

        def _close_connection(self, connection: FakeInjectiveConnection):
            connection.monitor = False
            try:
                connection.sock.close()
            except OSError:
                pass
            try:
                connection.peer_sock.close()
            except OSError:
                pass

        def _send_fake_packet(self, connection: FakeInjectiveConnection):
            if connection.bypass_method != "wrong_seq":
                raise RuntimeError("not implemented method")

            delay_s = human_delay_s(connection.fake_delay_ms)
            if delay_s > 0:
                time.sleep(delay_s)

            ttl_value = None
            if connection.ttl_spoof:
                ttl_value = random.choice((64, 128)) - random.randint(1, 8)

            ip_kwargs = {"src": connection.src_ip, "dst": connection.dst_ip}
            if ttl_value is not None:
                ip_kwargs["ttl"] = ttl_value

            fake_packet = (
                scapy.IP(**ip_kwargs)
                / scapy.TCP(
                    sport=connection.src_port,
                    dport=connection.dst_port,
                    flags="PA",
                    seq=(connection.syn_seq + 1 - len(connection.fake_data)) & 0xffffffff,
                    ack=(connection.syn_ack_seq + 1) & 0xffffffff,
                )
                / scapy.Raw(load=connection.fake_data)
            )
            scapy.send(fake_packet, verbose=False)
            connection.fake_sent = True

        def on_unexpected_packet(self, packet: Packet, connection: FakeInjectiveConnection, info_m: str):
            print(info_m)
            self._close_connection(connection)
            self._notify(connection, "unexpected_close")
            packet.drop()

        def on_inbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
            if connection.syn_seq == -1:
                self.on_unexpected_packet(packet, connection, "unexpected inbound packet, no syn sent!")
                return

            if packet.tcp.syn and packet.tcp.ack and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                    not packet.tcp.psh) and packet.tcp.payload_len == 0:
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if connection.syn_ack_seq != -1 and connection.syn_ack_seq != seq_num:
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound syn-ack packet, seq change!")
                    return
                if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound syn-ack packet, ack not matched!")
                    return
                connection.syn_ack_seq = seq_num
                packet.accept()
                return

            if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (
                    not packet.tcp.fin) and (not packet.tcp.psh) and packet.tcp.payload_len == 0 and connection.fake_sent:
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if connection.syn_ack_seq == -1 or ((connection.syn_ack_seq + 1) & 0xffffffff) != seq_num:
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound ack packet, seq not matched!")
                    return
                if ack_num != ((connection.syn_seq + 1) & 0xffffffff):
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected inbound ack packet, ack not matched!")
                    return
                connection.monitor = False
                self._notify(connection, "fake_data_ack_recv")
                packet.accept()
                return

            self.on_unexpected_packet(packet, connection, "unexpected inbound packet")

        def on_outbound_packet(self, packet: Packet, connection: FakeInjectiveConnection):
            if connection.sch_fake_sent:
                self.on_unexpected_packet(packet, connection, "unexpected outbound packet, recv packet after fake sent!")
                return

            if packet.tcp.syn and (not packet.tcp.ack) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                    packet.tcp.payload_len == 0):
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if ack_num != 0:
                    self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, ack_num is not zero!")
                    return
                if connection.syn_seq != -1 and connection.syn_seq != seq_num:
                    self.on_unexpected_packet(packet, connection, "unexpected outbound syn packet, seq not matched!")
                    return
                connection.syn_seq = seq_num
                packet.accept()
                return

            if packet.tcp.ack and (not packet.tcp.syn) and (not packet.tcp.rst) and (not packet.tcp.fin) and (
                    not packet.tcp.psh) and packet.tcp.payload_len == 0:
                seq_num = packet.tcp.seq_num
                ack_num = packet.tcp.ack_num
                if connection.syn_seq == -1 or ((connection.syn_seq + 1) & 0xffffffff) != seq_num:
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected outbound ack packet, seq not matched!")
                    return
                if connection.syn_ack_seq == -1 or ack_num != ((connection.syn_ack_seq + 1) & 0xffffffff):
                    self.on_unexpected_packet(packet, connection,
                                              "unexpected outbound ack packet, ack not matched!")
                    return

                connection.sch_fake_sent = True
                result_holder = {"ok": False, "error": "timeout"}
                done_event = threading.Event()
                self.fake_send_queue.put((connection, result_holder, done_event))
                wait_timeout = max(2.0, (connection.fake_delay_ms / 1000.0) + 1.5)
                done = done_event.wait(wait_timeout)
                if (not done) or (not result_holder.get("ok", False)):
                    print("linux fake packet injection failed:", result_holder.get("error", "timeout"))
                    self.on_unexpected_packet(packet, connection, "failed to send fake packet")
                    return
                packet.accept()
                return

            self.on_unexpected_packet(packet, connection, "unexpected outbound packet")

        def inject(self, packet: Packet):
            c_id_out = (packet.src_ip, packet.tcp.src_port, packet.dst_ip, packet.tcp.dst_port)
            connection = self.connections.get(c_id_out)
            if connection is not None:
                with connection.thread_lock:
                    if not connection.monitor:
                        packet.accept()
                        return
                    self.on_outbound_packet(packet, connection)
                return

            c_id_in = (packet.dst_ip, packet.tcp.dst_port, packet.src_ip, packet.tcp.src_port)
            connection = self.connections.get(c_id_in)
            if connection is not None:
                with connection.thread_lock:
                    if not connection.monitor:
                        packet.accept()
                        return
                    self.on_inbound_packet(packet, connection)
                return

            packet.accept()
