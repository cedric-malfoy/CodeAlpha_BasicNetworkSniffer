# CodeAlpha Basic Network Sniffer

A Python command-line project for **CodeAlpha Cyber Security Task 1**. It captures packets on a selected network interface or reads a saved capture, then explains each packet through its addresses, protocol, ports, and payload bytes.

## Quick start in this workspace

The virtual environment and synthetic sample capture are already prepared:

```bash
cd /workspace/CodeAlpha_BasicNetworkSniffer
.venv/bin/python sniffer.py --read examples/sample.pcap
```

The sample contains **10 invented packets**, not recorded user traffic. Its expected summary is:

```text
Summary
  Packets: 10
  Protocols: ARP=1, ICMP=2, ICMPv6=1, OTHER=1, TCP=2, UDP=3
```

A complete [sample output transcript](examples/sample-output.txt) is included for review.

Live capture needs a Linux computer or VM with capture permissions. This cloud workspace does not provide raw packet capture privileges. Its command sandbox can also block Scapy's interface discovery; see troubleshooting below.

## Install on a Linux computer or VM

Use Python **3.12 or newer**. On Ubuntu/Debian, install the system dependencies:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip libpcap-dev iputils-ping curl
```

From the project directory, create a fresh environment and install the pinned Python dependency:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python sniffer.py --help
```

Scapy handles packet decoding and capture. Libpcap compiles BPF capture filters. The program uses Python's standard library for arguments, formatting, counts, and tests.

## Commands

| Option | Purpose |
| --- | --- |
| `--list-interfaces` | List available capture interfaces. |
| `-i`, `--interface NAME` | Capture live traffic on the named interface. |
| `-r`, `--read PCAP` | Analyze a saved capture without opening a live capture socket. |
| `-c`, `--count N` | Stop after N packets; live default: 20, file default: all packets. |
| `-t`, `--timeout SECONDS` | Stop live capture after this many seconds; default: 30. |
| `-f`, `--filter EXPRESSION` | Apply a BPF filter to live capture; requires libpcap. |
| `-w`, `--write PCAP` | Save live packets to a new PCAP file. |
| `-h`, `--help` | Show command help. |

Choose exactly one of `--list-interfaces`, `--interface`, or `--read`. Timeout, filter, and write options apply to live capture. Both count and timeout must be positive; live capture stops at whichever limit is reached first. Ctrl+C stops early, prints a summary, and finalizes the output file.

```bash
# List interfaces; Linux loopback is normally called lo.
.venv/bin/python sniffer.py --list-interfaces

# Inspect the first three packets in the sample.
.venv/bin/python sniffer.py --read examples/sample.pcap --count 3

# Capture packets on your own machine's loopback interface.
sudo .venv/bin/python sniffer.py --interface lo --count 20 --timeout 30

# Capture and save HTTP traffic from the local demonstration below.
mkdir -p captures
sudo .venv/bin/python sniffer.py --interface lo --count 20 --timeout 30 \
  --filter "tcp port 8000" --write captures/http-demo.pcap

# Reopen the saved packets without sudo.
.venv/bin/python sniffer.py --read captures/http-demo.pcap
```

The output directory must already exist. Existing captures are preserved: choose a new filename for each run. Capture does not enable promiscuous mode. Use traffic on your own machine or a network where you have permission to capture it.

## Understand the output

Each packet shows:

- Its capture timestamp in UTC and captured size in bytes.
- Source and destination IP addresses, or MAC addresses for other Ethernet protocols.
- IPv4/IPv6 and the transport protocol; ports appear for TCP and UDP.
- Up to 64 payload bytes as escaped text and hexadecimal, with the full payload length and a truncation marker.

ARP packets show their protocol addresses and have no application payload. TCP acknowledgments can also have no payload. DNS is decoded by Scapy, but its UDP payload bytes are still displayed. ICMPv6 echo data is included even though Scapy stores it in a field rather than a separate payload layer. Ethernet padding is excluded from application payload previews.

Control characters such as newlines, NUL, and terminal escape bytes are displayed as escapes. Encrypted HTTPS/TLS traffic appears as bytes; the sniffer does not decrypt it or reconstruct application conversations.

| Protocol | What to learn from it |
| --- | --- |
| ARP | Maps an IPv4 address to a link-layer address on a local network. |
| IPv4 / IPv6 | Carries addresses used to route packets between hosts. |
| TCP | Uses ports and sequence numbers for reliable, ordered communication. |
| UDP | Sends datagrams using ports without TCP's connection setup. |
| ICMP / ICMPv6 | Carries diagnostics and control messages, including ping. |
| OTHER | Traffic this basic sniffer does not classify further. |

HTTP is application data carried inside TCP. A request travels through application, transport, network, and link layers; the receiving host interprets those layers in reverse. The local HTTP demonstration makes the request text visible in a TCP payload.

## Live demonstration on your Linux VM

Open three terminals in the project directory.

**Terminal 1 — start a local HTTP server:**

```bash
.venv/bin/python -m http.server 8000 --bind 127.0.0.1 --directory examples
```

**Terminal 2 — start the sniffer before generating traffic:**

```bash
mkdir -p captures
sudo .venv/bin/python sniffer.py --interface lo --count 20 --timeout 30 \
  --filter "tcp port 8000" --write captures/http-demo.pcap
```

**Terminal 3 — generate one local HTTP request:**

```bash
curl --http1.1 http://127.0.0.1:8000/
```

Look for loopback addresses, port 8000, TCP, and a payload containing `GET / HTTP/1.1`. Linux loopback capture may show duplicate copies of packets; counts refer to packets observed by the capture socket.

After capture stops, reopen `captures/http-demo.pcap` with `--read`. To demonstrate ICMP separately, start this capture in Terminal 2, then run ping in Terminal 3:

```bash
# Terminal 2
sudo .venv/bin/python sniffer.py --interface lo --count 4 --timeout 15 --filter "icmp"
```

```bash
# Terminal 3
ping -4 -c 3 127.0.0.1
```

Finish by stopping the HTTP server with Ctrl+C. Additional live checks for limits, permissions, and interruption are listed in [DEMO_AND_SUBMISSION.md](DEMO_AND_SUBMISSION.md).

## Tests and sample generation

```bash
.venv/bin/python -m unittest discover -s tests -v

# Recreate the committed sample from its source; this does not sniff traffic.
.venv/bin/python examples/generate_sample.py
```

Tests cover packet fields, protocols, IPv6 extension headers, ICMPv6 echo data, padding, binary payloads, argument validation, missing/invalid files, and output preservation. They also exercise Scapy's real capture loop using iterable packet sources and an idle pipe to check count limits, timeout, and saved PCAP files. Raw network sockets are not opened by the tests. Interruption, permissions, filter errors, and disk failures are simulated where required.

The sample generator uses documentation-only IPv4/IPv6 addresses and locally administered MAC addresses. Its fixed timestamps and contents make it repeatable. Keep real live captures in `captures/`; Git ignores them and includes only `examples/sample.pcap`.

## How the code works

`sniffer.py` contains the CLI, packet analysis, output formatting, and capture lifecycle. `analyze_packet()` extracts a `PacketInfo` value; both live capture and file reading use this same function. `CaptureStats` displays packets and maintains only counters. `PcapReader` streams saved packets, and live capture uses `store=False`, so the entire capture is not retained in memory.

The live socket is opened before the output file. Files and sockets are closed on normal completion, interruption, and failure. Captures are written synchronously and existing files are never overwritten. Exit codes are `0` for success, `1` for runtime/setup failures, `2` for invalid arguments, and `130` for Ctrl+C.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| Scapy is unavailable | Activate `.venv` and run `python -m pip install -r requirements.txt`. |
| Live capture returns permission denied | On your Linux VM, use `sudo .venv/bin/python ...`. A restricted cloud container may still lack capture capabilities. |
| Scapy interface discovery is blocked during startup | In this managed workspace, run the command with network access enabled through the execution tool. Offline decoding needs no raw capture privileges, but Scapy still discovers interfaces while loading. On a normal Linux terminal this ordinarily needs no special permission. |
| BPF filters require libpcap | Install `libpcap-dev` using the command above. |
| Filter compilation fails | Check BPF syntax; try `tcp`, `udp port 53`, or `icmp`. |
| Interface not found | Run `--list-interfaces` and use the exact interface name. |
| No packets before timeout | Start capture before generating traffic; check the interface and filter. |
| Output capture already exists | Choose a new `--write` filename. |
| File or output directory not found | Check the path and create the directory with `mkdir -p captures`. |

## Submission material

Use the repository name **`CodeAlpha_BasicNetworkSniffer`**. Include the source, requirements, README, tests, synthetic sample, generator, and demonstration checklist. See [DEMO_AND_SUBMISSION.md](DEMO_AND_SUBMISSION.md) for a video outline and the GitHub/LinkedIn/submission steps.
