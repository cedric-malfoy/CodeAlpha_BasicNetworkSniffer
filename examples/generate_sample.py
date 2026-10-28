#!/usr/bin/env python3
"""Generate the committed sample using invented addresses and payloads only."""

from decimal import Decimal
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    ICMPv6EchoRequest,
    IPv6,
    PcapWriter,
    Raw,
)


def sample_packets():
    """Ten deterministic Ethernet frames covering the sniffer's main protocols."""
    client_mac, server_mac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    client_ip, server_ip = "192.0.2.10", "192.0.2.20"
    http_request = (
        b"GET /internship HTTP/1.1\r\nHost: demo.example\r\n"
        b"User-Agent: CodeAlpha-Sample\r\n\r\n"
    )

    def frame():
        return Ether(src=client_mac, dst=server_mac)

    def response_frame():
        return Ether(src=server_mac, dst=client_mac)

    packets = [
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=client_mac, hwdst="00:00:00:00:00:00", psrc=client_ip, pdst=server_ip),
        frame() / IP(src=client_ip, dst=server_ip, id=1)
        / TCP(sport=45000, dport=8000, seq=1, ack=1, flags="PA")
        / Raw(http_request),
        response_frame() / IP(src=server_ip, dst=client_ip, id=2)
        / TCP(sport=8000, dport=45000, seq=1, ack=1 + len(http_request), flags="PA")
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\n\r\nHello, internship!\n"),
        frame() / IP(src=client_ip, dst=server_ip, id=3)
        / UDP(sport=53000, dport=53)
        / DNS(id=1234, rd=1, qd=DNSQR(qname="demo.example")),
        response_frame() / IP(src=server_ip, dst=client_ip, id=4)
        / UDP(sport=53, dport=53000)
        / DNS(id=1234, qr=1, aa=1, rd=1, qd=DNSQR(qname="demo.example"),
              an=DNSRR(rrname="demo.example", ttl=60, rdata="203.0.113.5")),
        frame() / IP(src=client_ip, dst=server_ip, id=5)
        / ICMP(type=8, id=7, seq=1) / Raw(b"CodeAlpha ping"),
        response_frame() / IP(src=server_ip, dst=client_ip, id=6)
        / ICMP(type=0, id=7, seq=1) / Raw(b"CodeAlpha ping"),
        frame() / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / UDP(sport=45001, dport=9999) / Raw(b"IPv6 UDP sample"),
        frame() / IPv6(src="2001:db8::10", dst="2001:db8::20")
        / ICMPv6EchoRequest(id=8, seq=1, data=b"IPv6 echo sample"),
        frame() / Raw(b"Unknown Ethernet protocol sample"),
    ]
    packets[-1].type = 0x88B5  # Local experimental EtherType, not an IP packet.
    for index, packet in enumerate(packets):
        packet.time = Decimal("1792497600") + Decimal(index) / 1000
    return packets


def main():
    output = Path(__file__).with_name("sample.pcap")
    with PcapWriter(str(output), linktype=1, sync=True) as writer:
        for packet in sample_packets():
            writer.write(packet)
    print(f"Generated {output} (10 synthetic packets; no network traffic captured).")


if __name__ == "__main__":
    main()
