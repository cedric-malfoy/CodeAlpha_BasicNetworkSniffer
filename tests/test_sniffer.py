"""Packet decoding and CLI/capture lifecycle tests; no raw sockets are opened."""

import contextlib
import io
import tempfile
import time
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import Mock, patch

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IPv6,
    IPv6ExtHdrHopByHop,
    PcapReader,
    PcapWriter,
    Raw,
)
from scapy.automaton import ObjectPipe
from scapy.error import Scapy_Exception
from scapy.supersocket import IterSocket

import sniffer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = PROJECT_ROOT / "examples" / "sample.pcap"


def frame(payload=b"Hello, internship!"):
    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=45000, dport=8000, flags="PA")
    )
    if payload:
        packet /= Raw(payload)
    packet.time = Decimal("1792497600.125000")
    return packet


def run_cli(arguments):
    output, errors = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        status = sniffer.main(arguments)
    return status, output.getvalue(), errors.getvalue()


def packet_socket(packets):
    """Use Scapy's real capture loop with an iterable instead of a NIC."""
    source = IterSocket(packets)
    source.LL = Ether
    source.close = Mock(wraps=source.close)
    return source


class PacketAnalysisTests(unittest.TestCase):
    def test_ipv4_tcp_addresses_ports_timestamp_and_payload(self):
        packet = frame()
        info = sniffer.analyze_packet(packet)
        self.assertEqual((info.source, info.destination), ("192.0.2.10", "192.0.2.20"))
        self.assertEqual((info.network, info.protocol), ("IPv4", "TCP"))
        self.assertEqual((info.source_port, info.destination_port), (45000, 8000))
        self.assertEqual(info.payload_preview, b"Hello, internship!")
        self.assertEqual(info.length, len(bytes(packet)))
        self.assertEqual(info.timestamp, "2026-10-20T12:00:00.125000Z")

    def test_udp_decoded_dns_payload_is_not_lost(self):
        dns = DNS(id=42, qd=DNSQR(qname="demo.example"))
        packet = IP(src="192.0.2.10", dst="192.0.2.20") / UDP(sport=53000, dport=53) / dns
        info = sniffer.analyze_packet(packet)
        self.assertEqual(info.protocol, "UDP")
        self.assertEqual(info.destination_port, 53)
        self.assertEqual(info.payload_preview, bytes(dns))

    def test_icmp_error_with_embedded_tcp_remains_icmp(self):
        packet = (
            IP(src="192.0.2.20", dst="192.0.2.10") / ICMP(type=3, code=3)
            / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=1000, dport=80)
        )
        info = sniffer.analyze_packet(packet)
        self.assertEqual(info.protocol, "ICMP")
        self.assertIsNone(info.source_port)
        self.assertEqual(info.source, "192.0.2.20")

    def test_ipv6_udp_formats_unambiguous_endpoints(self):
        packet = (
            IPv6(src="2001:db8::10", dst="2001:db8::20")
            / UDP(sport=45000, dport=9999) / Raw(b"IPv6")
        )
        info = sniffer.analyze_packet(packet)
        self.assertEqual((info.network, info.protocol), ("IPv6", "UDP"))
        self.assertIn("[2001:db8::10]:45000 -> [2001:db8::20]:9999", sniffer.format_packet(info, 1))

    def test_ipv6_extension_header_is_skipped(self):
        packet = (
            IPv6(src="2001:db8::10", dst="2001:db8::20")
            / IPv6ExtHdrHopByHop() / TCP(sport=45000, dport=443) / Raw(b"data")
        )
        info = sniffer.analyze_packet(packet)
        self.assertEqual(info.protocol, "TCP")
        self.assertEqual(info.payload_preview, b"data")

    def test_icmpv6_echo_field_is_displayed_as_payload(self):
        for message_type in (ICMPv6EchoRequest, ICMPv6EchoReply):
            with self.subTest(message=message_type.__name__):
                packet = (
                    IPv6(src="2001:db8::10", dst="2001:db8::20")
                    / message_type(id=1, data=b"IPv6 echo")
                )
                info = sniffer.analyze_packet(packet)
                self.assertEqual(info.protocol, "ICMPv6")
                self.assertEqual(info.payload_preview, b"IPv6 echo")

    def test_arp_addresses_and_absent_payload(self):
        packet = ARP(psrc="192.0.2.10", pdst="192.0.2.20", hwsrc="02:00:00:00:00:01")
        info = sniffer.analyze_packet(packet)
        self.assertEqual((info.network, info.protocol), ("ARP", "ARP"))
        self.assertEqual(info.source, "192.0.2.10")
        self.assertEqual(info.payload_length, 0)
        self.assertIsNone(info.destination_port)

    def test_unknown_ethernet_protocol_preserves_mac_addresses(self):
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x88B5) / Raw(b"custom")
        info = sniffer.analyze_packet(packet)
        self.assertEqual((info.network, info.protocol), ("OTHER", "OTHER"))
        self.assertEqual(info.source, "02:00:00:00:00:01")
        self.assertEqual(info.payload_preview, b"custom")

    def test_unrecognized_ipv4_protocol_does_not_crash(self):
        packet = IP(src="192.0.2.10", dst="192.0.2.20", proto=253) / Raw(b"experimental")
        info = sniffer.analyze_packet(packet)
        self.assertEqual((info.network, info.protocol), ("IPv4", "OTHER"))
        self.assertEqual(info.payload_preview, b"experimental")

    def test_ack_without_payload(self):
        info = sniffer.analyze_packet(frame(b""))
        self.assertEqual(info.payload_length, 0)
        self.assertIn("Payload: none", sniffer.format_packet(info, 1))

    def test_ethernet_padding_is_not_application_payload(self):
        packet = Ether(bytes(frame(b"")) + b"\x00" * 10)
        self.assertEqual(sniffer.analyze_packet(packet).payload_length, 0)

    def test_payload_preview_is_bounded_and_marked(self):
        info = sniffer.analyze_packet(frame(b"A" * 100))
        self.assertEqual(info.payload_length, 100)
        self.assertEqual(info.payload_preview, b"A" * 64)
        self.assertIn("showing 64 (truncated)", sniffer.format_packet(info, 1))

    def test_binary_and_control_characters_are_escaped(self):
        info = sniffer.analyze_packet(frame(b"\x1b[31mhello\r\n\x00\xff"))
        output = sniffer.format_packet(info, 1)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\r", output)
        self.assertNotIn("\x00", output)
        self.assertIn("\\x1b", output)
        self.assertIn("\\r\\n", output)
        self.assertIn("1b 5b 33 31 6d", output)

    def test_packet_without_network_header(self):
        info = sniffer.analyze_packet(Raw(b"unknown"))
        self.assertEqual((info.source, info.destination), ("-", "-"))
        self.assertEqual(info.protocol, "OTHER")
        self.assertEqual(info.payload_preview, b"unknown")


class FileAndArgumentTests(unittest.TestCase):
    def test_sample_capture_and_protocol_summary(self):
        status, output, errors = run_cli(["--read", str(SAMPLE)])
        self.assertEqual(status, 0, errors)
        self.assertIn("Packets: 10", output)
        self.assertIn("ARP=1, ICMP=2, ICMPv6=1, OTHER=1, TCP=2, UDP=3", output)
        self.assertIn("GET /internship", output)
        self.assertEqual(errors, "")

    def test_file_packet_limit(self):
        status, output, errors = run_cli(["--read", str(SAMPLE), "--count", "2"])
        self.assertEqual(status, 0, errors)
        self.assertIn("Packets: 2", output)
        self.assertNotIn("[0003]", output)

    def test_empty_but_valid_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.pcap"
            with PcapWriter(str(path), linktype=1):
                pass
            status, output, errors = run_cli(["--read", str(path)])
        self.assertEqual(status, 0, errors)
        self.assertIn("Packets: 0", output)
        self.assertIn("Protocols: none", output)

    def test_missing_file_has_readable_error(self):
        status, _, errors = run_cli(["--read", "/no-such-sniffer-file.pcap"])
        self.assertEqual(status, 1)
        self.assertIn("No such file", errors)
        self.assertNotIn("Traceback", errors)

    def test_invalid_file_has_readable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.pcap"
            path.write_bytes(b"This is not a packet capture.")
            status, _, errors = run_cli(["--read", str(path)])
        self.assertEqual(status, 1)
        self.assertIn("Error:", errors)
        self.assertNotIn("Traceback", errors)

    def test_invalid_argument_combinations(self):
        cases = [
            [],
            ["-i", "lo", "--read", str(SAMPLE)],
            ["--read", str(SAMPLE), "--filter", "tcp"],
            ["--read", str(SAMPLE), "--write", "copy.pcap"],
            ["--read", str(SAMPLE), "--timeout", "2"],
            ["--list-interfaces", "--count", "2"],
            ["-i", ""],
            ["-i", "lo", "--filter", " "],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    sniffer.parse_args(arguments)
                self.assertEqual(result.exception.code, 2)

    def test_invalid_counts_and_timeouts(self):
        for flag, values in (("--count", ["0", "-1", "1.5", "hello"]),
                             ("--timeout", ["0", "-1", "nan", "inf", "hello"])):
            for value in values:
                with self.subTest(flag=flag, value=value), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as result:
                        sniffer.parse_args(["-i", "lo", flag, value])
                    self.assertEqual(result.exception.code, 2)


class CaptureLifecycleTests(unittest.TestCase):
    def test_actual_scapy_loop_honors_count_and_saves_readable_capture(self):
        source = packet_socket([frame(b"one"), frame(b"two"), frame(b"three")])
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "capture.pcap"
            with patch("sniffer.open_capture_socket", return_value=source):
                status, output, errors = run_cli(["-i", "demo", "-c", "2", "-w", str(output_path)])
            with PcapReader(str(output_path)) as packets:
                saved = list(packets)
        self.assertEqual(status, 0, errors)
        self.assertEqual(len(saved), 2)
        self.assertEqual(sniffer.analyze_packet(saved[-1]).payload_preview, b"two")
        self.assertIn("Packets: 2", output)
        source.close.assert_called()

    def test_actual_scapy_loop_uses_twenty_packet_default(self):
        source = packet_socket([frame() for _ in range(25)])
        with patch("sniffer.open_capture_socket", return_value=source):
            status, output, errors = run_cli(["-i", "demo"])
        self.assertEqual(status, 0, errors)
        self.assertIn("Packets: 20", output)
        self.assertNotIn("[0021]", output)

    def test_idle_capture_times_out_and_writes_valid_empty_pcap(self):
        source = ObjectPipe("idle-test")
        source.LL = Ether
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.pcap"
            started = time.monotonic()
            with patch("sniffer.open_capture_socket", return_value=source):
                status, output, errors = run_cli(["-i", "demo", "-t", "0.05", "-w", str(path)])
            elapsed = time.monotonic() - started
            with PcapReader(str(path)) as packets:
                self.assertEqual(list(packets), [])
        self.assertEqual(status, 0, errors)
        self.assertLess(elapsed, 3)
        self.assertIn("Packets: 0", output)
        self.assertTrue(source.closed)

    def test_ctrl_c_finalizes_saved_packets_and_summary(self):
        source = packet_socket([])

        def interrupted_capture(**options):
            options["prn"](frame(b"saved before interrupt"))
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "interrupted.pcap"
            with patch("sniffer.open_capture_socket", return_value=source), patch("scapy.all.sniff", side_effect=interrupted_capture):
                status, output, errors = run_cli(["-i", "demo", "-w", str(path)])
            with PcapReader(str(path)) as packets:
                self.assertEqual(len(list(packets)), 1)
        self.assertEqual(status, 130, errors)
        self.assertIn("Stopped by user", output)
        self.assertIn("Packets: 1", output)
        source.close.assert_called_once()

    def test_existing_output_is_preserved(self):
        source = packet_socket([])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.pcap"
            path.write_bytes(b"keep this file")
            with patch("sniffer.open_capture_socket", return_value=source):
                status, _, errors = run_cli(["-i", "demo", "-w", str(path)])
            self.assertEqual(path.read_bytes(), b"keep this file")
        self.assertEqual(status, 1)
        self.assertIn("already exists", errors)
        source.close.assert_called_once()

    def test_permission_failure_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-created.pcap"
            with patch("sniffer.open_capture_socket", side_effect=PermissionError("raw socket blocked")):
                status, _, errors = run_cli(["-i", "demo", "-w", str(path)])
            self.assertFalse(path.exists())
        self.assertEqual(status, 1)
        self.assertIn("permission denied", errors)
        self.assertNotIn("Traceback", errors)

    def test_invalid_filter_error_is_readable(self):
        with patch("sniffer.open_capture_socket", side_effect=Scapy_Exception("Failed to compile filter expression")):
            status, _, errors = run_cli(["-i", "demo", "--filter", "not a valid filter"])
        self.assertEqual(status, 1)
        self.assertIn("compile filter", errors)
        self.assertNotIn("Traceback", errors)

    def test_missing_libpcap_has_installation_hint(self):
        with patch("scapy.all.resolve_iface", return_value=object()), patch("ctypes.util.find_library", return_value=None):
            status, _, errors = run_cli(["-i", "demo", "--filter", "tcp"])
        self.assertEqual(status, 1)
        self.assertIn("libpcap-dev", errors)

    def test_writer_failure_is_not_swallowed_by_scapy(self):
        source = packet_socket([frame(), frame()])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failed.pcap"
            with patch("sniffer.open_capture_socket", return_value=source), patch("scapy.all.PcapWriter.write", side_effect=OSError("disk full")):
                status, output, errors = run_cli(["-i", "demo", "-w", str(path)])
        self.assertEqual(status, 1)
        self.assertIn("disk full", errors)
        self.assertIn("Packets: 0", output)
        source.close.assert_called()

    def test_invalid_interface_error_is_readable(self):
        with patch("scapy.all.resolve_iface", side_effect=ValueError("Interface 'missing' not found!")):
            status, _, errors = run_cli(["-i", "missing"])
        self.assertEqual(status, 1)
        self.assertIn("not found", errors)
        self.assertNotIn("Traceback", errors)


if __name__ == "__main__":
    unittest.main()
