#!/usr/bin/env python3
"""A small, streaming network sniffer for CodeAlpha's cybersecurity Task 1."""

from __future__ import annotations

import argparse
import ctypes.util
import importlib
import math
import sys
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PAYLOAD_PREVIEW_BYTES = 64
DEFAULT_COUNT = 20
DEFAULT_TIMEOUT = 30.0


class SnifferError(Exception):
    """An expected setup or capture error suitable for displaying to the user."""


def load_scapy() -> Any:
    """Load Scapy only after parsing arguments, so --help needs no dependencies."""
    try:
        return importlib.import_module("scapy.all")
    except ImportError as exc:
        raise SnifferError(
            "Scapy is unavailable. Activate .venv and run "
            "python -m pip install -r requirements.txt."
        ) from exc
    except PermissionError as exc:
        # Scapy discovers interfaces even when it is only decoding a file.
        raise SnifferError(
            "This sandbox blocks Scapy's network interface discovery. "
            "Permit network interface discovery for this command or use a normal "
            "Linux terminal. Reading a PCAP does not require raw capture privileges."
        ) from exc


@dataclass(frozen=True)
class PacketInfo:
    timestamp: str
    source: str
    destination: str
    network: str
    protocol: str
    length: int
    source_port: int | None
    destination_port: int | None
    payload_length: int
    payload_preview: bytes


def analyze_packet(packet: Any) -> PacketInfo:
    """Extract packet details without printing, writing files, or retaining packets."""
    scapy = load_scapy()
    network = next(
        (
            layer
            for layer in packet.iterpayloads()
            if isinstance(layer, (scapy.IP, scapy.IPv6, scapy.ARP))
        ),
        None,
    )
    source_port = destination_port = None
    protocol = "OTHER"
    payload = b""

    if isinstance(network, scapy.ARP):
        source, destination = str(network.psrc), str(network.pdst)
        network_name = protocol = "ARP"
    else:
        if network is not None:
            source, destination = str(network.src), str(network.dst)
            network_name = "IPv4" if isinstance(network, scapy.IP) else "IPv6"
            transport = network.payload
            # Skip IPv6 extension headers, but never inspect an encapsulated IP
            # packet to decide the *outer* packet's transport protocol.
            extension_headers = (
                scapy.IPv6ExtHdrHopByHop,
                scapy.IPv6ExtHdrDestOpt,
                scapy.IPv6ExtHdrRouting,
                scapy.IPv6ExtHdrFragment,
                scapy.IPv6ExtHdrSegmentRouting,
            )
            while isinstance(transport, extension_headers):
                transport = transport.payload

            if isinstance(transport, scapy.TCP):
                protocol = "TCP"
            elif isinstance(transport, scapy.UDP):
                protocol = "UDP"
            elif isinstance(transport, scapy.ICMP):
                protocol = "ICMP"
            elif type(transport).__name__.startswith("ICMPv6"):
                protocol = "ICMPv6"

            if protocol in ("TCP", "UDP"):
                source_port = int(transport.sport)
                destination_port = int(transport.dport)
            payload_layer = transport.payload if protocol != "OTHER" else transport
        else:
            ethernet = packet.getlayer(scapy.Ether)
            source = str(ethernet.src) if ethernet is not None else "-"
            destination = str(ethernet.dst) if ethernet is not None else "-"
            network_name = "OTHER"
            payload_layer = ethernet.payload if ethernet is not None else packet

        if not isinstance(payload_layer, (scapy.NoPayload, scapy.Padding)):
            payload = bytes(payload_layer)
            # Ethernet padding is outside the network packet, not application data.
            padding = payload_layer.getlayer(scapy.Padding)
            if padding is not None and len(bytes(padding)):
                payload = payload[: -len(bytes(padding))]
        if network is not None and isinstance(
            transport, (scapy.ICMPv6EchoRequest, scapy.ICMPv6EchoReply)
        ):
            # Scapy stores echo data in a field, rather than in a Raw layer.
            payload = bytes(transport.data) + payload

    try:
        timestamp = datetime.fromtimestamp(float(packet.time), timezone.utc)
        timestamp_text = timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (AttributeError, ValueError, OverflowError, OSError):
        timestamp_text = "unknown"

    return PacketInfo(
        timestamp=timestamp_text,
        source=source,
        destination=destination,
        network=network_name,
        protocol=protocol,
        length=len(bytes(packet)),
        source_port=source_port,
        destination_port=destination_port,
        payload_length=len(payload),
        payload_preview=payload[:PAYLOAD_PREVIEW_BYTES],
    )


def endpoint(address: str, port: int | None) -> str:
    if port is None:
        return address
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def format_packet(info: PacketInfo, number: int) -> str:
    """Escape binary/control bytes so payloads cannot control the terminal."""
    label = info.network if info.network == info.protocol else f"{info.network}/{info.protocol}"
    lines = [
        f"[{number:04d}] {info.timestamp}  {label}  {info.length} bytes captured",
        f"  {endpoint(info.source, info.source_port)} -> "
        f"{endpoint(info.destination, info.destination_port)}",
    ]
    if not info.payload_length:
        lines.append("  Payload: none")
    else:
        suffix = " (truncated)" if info.payload_length > len(info.payload_preview) else ""
        lines.extend(
            [
                f"  Payload: {info.payload_length} bytes; "
                f"showing {len(info.payload_preview)}{suffix}",
                f"    Text: {info.payload_preview!r}",
                f"    Hex:  {info.payload_preview.hex(' ')}",
            ]
        )
    return "\n".join(lines)


@dataclass
class CaptureStats:
    total: int = 0
    protocols: Counter[str] = field(default_factory=Counter)

    def consume(self, packet: Any, writer: Any = None) -> None:
        info = analyze_packet(packet)
        if writer is not None:
            writer.write(packet)
        self.total += 1
        self.protocols[info.protocol] += 1
        print(format_packet(info, self.total), flush=True)

    def summary(self) -> str:
        counts = ", ".join(f"{name}={count}" for name, count in sorted(self.protocols.items()))
        return f"\nSummary\n  Packets: {self.total}\n  Protocols: {counts or 'none'}"


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def positive_seconds(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive, finite number of seconds") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive, finite number of seconds")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture live network packets or analyze a saved PCAP, one packet at a time.",
        epilog="Examples: python sniffer.py --read examples/sample.pcap | "
        "sudo .venv/bin/python sniffer.py -i lo -c 20 -t 30",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--list-interfaces", action="store_true", help="list available capture interfaces")
    source.add_argument("-i", "--interface", help="interface for live capture, e.g. lo or eth0")
    source.add_argument("-r", "--read", type=Path, metavar="PCAP", help="analyze a saved capture without live capture privileges")
    parser.add_argument("-c", "--count", type=positive_int, help="maximum packets (live default: 20; file default: all)")
    parser.add_argument("-t", "--timeout", type=positive_seconds, help="live capture timeout in seconds (default: 30)")
    parser.add_argument("-f", "--filter", help='live BPF capture filter, e.g. "tcp port 8000"')
    parser.add_argument("-w", "--write", type=Path, metavar="PCAP", help="save live packets to a new PCAP file")
    args = parser.parse_args(argv)
    if args.read is not None and any(value is not None for value in (args.timeout, args.filter, args.write)):
        parser.error("--timeout, --filter, and --write apply only to --interface")
    if args.list_interfaces and any(value is not None for value in (args.count, args.timeout, args.filter, args.write)):
        parser.error("capture options cannot be combined with --list-interfaces")
    if args.interface is not None and not args.interface.strip():
        parser.error("--interface cannot be empty")
    if args.filter is not None and not args.filter.strip():
        parser.error("--filter cannot be empty")
    return args


def analyze_file(path: Path, count: int | None, stats: CaptureStats) -> None:
    scapy = load_scapy()
    # PcapReader streams; rdpcap would retain the entire file in memory.
    # Own the underlying file too: a failed Scapy reader constructor must not
    # leave an invalid capture's file descriptor open.
    with path.open("rb") as capture_file:
        with scapy.PcapReader(capture_file) as packets:
            for packet in packets:
                stats.consume(packet)
                if count is not None and stats.total >= count:
                    break


def open_capture_socket(interface: str, capture_filter: str | None) -> Any:
    scapy = load_scapy()
    device = scapy.resolve_iface(interface)
    if capture_filter is not None and ctypes.util.find_library("pcap") is None:
        raise SnifferError(
            "BPF filters require libpcap. On Ubuntu/Debian, run: sudo apt install libpcap-dev"
        )
    # Capture only the selected interface, without enabling promiscuous mode.
    return scapy.conf.L2listen(iface=device, filter=capture_filter, promisc=False)


def capture_live(args: argparse.Namespace, stats: CaptureStats) -> None:
    scapy = load_scapy()
    with ExitStack() as resources:
        capture_socket = open_capture_socket(args.interface, args.filter)
        resources.callback(capture_socket.close)
        writer = None
        if args.write is not None:
            linktype = scapy.conf.l2types.layer2num.get(capture_socket.LL)
            if linktype is None:
                raise SnifferError("Saving this interface's link-layer format is not supported.")
            # Exclusive creation prevents overwriting an existing capture.
            output = resources.enter_context(args.write.open("xb"))
            writer = scapy.PcapWriter(output, linktype=linktype, sync=True)
            resources.callback(writer.close)

        callback_errors: list[Exception] = []

        def on_packet(packet: Any) -> None:
            try:
                stats.consume(packet, writer)
            except Exception as exc:
                # Scapy otherwise logs and swallows exceptions from its callback.
                # Stop immediately and propagate the failure after it closes down.
                callback_errors.append(exc)

        count = args.count if args.count is not None else DEFAULT_COUNT
        timeout = args.timeout if args.timeout is not None else DEFAULT_TIMEOUT
        print(
            f"Capturing on {args.interface}: at most {count} packets or {timeout:g} seconds. "
            "Press Ctrl+C to stop.",
            flush=True,
        )
        scapy.sniff(
            opened_socket=capture_socket,
            store=False,
            count=count,
            timeout=timeout,
            prn=on_packet,
            stop_filter=lambda packet: bool(callback_errors),
            chainCC=True,
        )
        if callback_errors:
            raise callback_errors[0]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    stats = CaptureStats()
    status = 0
    show_summary = False
    try:
        scapy = load_scapy()
        if args.list_interfaces:
            print("Available interfaces:")
            for device in sorted(scapy.conf.ifaces.values(), key=lambda item: item.name):
                print(f"  {device.name}: {device.description or device.name}")
            return 0
        show_summary = True
        if args.read is not None:
            print(f"Reading {args.read}", flush=True)
            analyze_file(args.read, args.count, stats)
        else:
            capture_live(args, stats)
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
        status = 130
    except BrokenPipeError:
        # Avoid a second broken-pipe error during interpreter shutdown.
        sys.stdout = open("/dev/null", "w")
        return 0
    except SnifferError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        status = 1
    except PermissionError as exc:
        print(
            f"Error: permission denied: {exc}. Live capture needs root or capture "
            "capabilities on your Linux VM; some sandboxes block it even with sudo. "
            "For file errors, check the file and directory permissions.",
            file=sys.stderr,
        )
        status = 1
    except FileExistsError:
        print("Error: the output capture already exists; choose a new --write filename.", file=sys.stderr)
        status = 1
    except (OSError, ValueError, EOFError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        status = 1
    except Exception as exc:
        # Keep Scapy's expected capture/filter/format failures readable, while
        # allowing unexpected programming errors to retain their traceback.
        from scapy.error import Scapy_Exception

        if not isinstance(exc, Scapy_Exception):
            raise
        print(f"Error: {exc}", file=sys.stderr)
        status = 1
    if show_summary:
        print(stats.summary(), flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
