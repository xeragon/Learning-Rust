# Fast Network Discovery Tool

A fast, concurrent network discovery tool for internal penetration tests. Combines ICMP ping sweeps, ARP scanning, and TCP/UDP port scanning into a single binary.

## Overview

`fast-netdiscover` started as a simple ICMP host-discovery tool and has grown into a multi-mode reconnaissance utility for pentesters. It can quickly identify live hosts, map active subnets, and enumerate open ports.

### Key Features

- **Multiple scan types** — ICMP ping, ARP, TCP connect/SYN, UDP service probes, and combined/full discovery pipelines
- **Subnet discovery mode** — finds active `/24` subnets by probing common gateway IPs, avoiding full-range scans
- **Flexible targets** — single IPs, ranges, CIDR notation, comma-separated lists, and hostnames
- **High-performance concurrency** — configurable concurrent probe limits via async tokio
- **Multiple output formats** — clean IP lists for piping, subnet lists, or detailed human-readable reports
- **Cross-platform** — Windows, Linux, and macOS

## Installation

### From Source

```bash
cd fastnetdiscover

# Build in release mode for best performance
cargo build --release

# Binary is at target/release/fast-netdiscover (or fast-netdiscover.exe on Windows)
```

### Pre-built Binary

Copy the `fast-netdiscover.exe` (Windows) or `fast-netdiscover` (Unix) binary to your tools directory or PATH.

## Scan Types

Select the scan with `-s, --scan-type` (default: `ping`).

| Scan type | Alias | Description |
|-----------|-------|-------------|
| `ping` | — | ICMP echo sweep (uses the system `ping` command) |
| `arp` | — | ARP scan for local-subnet hosts (IPv4 only); resolves MAC addresses via the ARP table |
| `tcp` | — | TCP connect scan across the configured port list |
| `syn` | — | TCP SYN scan (requires raw-socket / admin privileges) |
| `udp` | — | UDP service probes (DNS, NetBIOS, SNMP, mDNS, generic) |
| `combined` | — | Ping sweep → TCP scan → UDP scan on live hosts |
| `full` | — | Ping + ARP + TCP + UDP across all targets |

## Basic Usage

```bash
# ICMP ping a single host
fast-netdiscover 192.168.1.1

# Ping a whole /24
fast-netdiscover 192.168.1.0/24

# Ping an IP range
fast-netdiscover 192.168.1.1-192.168.1.100

# Multiple comma-separated targets
fast-netdiscover 192.168.1.1,192.168.2.1,10.0.0.1

# ARP scan for local hosts
fast-netdiscover 192.168.1.0/24 --scan-type arp

# TCP port scan on a specific port list
fast-netdiscover 192.168.1.1-192.168.1.100 --scan-type tcp --tcp-ports 22,80,443

# Full discovery
fast-netdiscover 192.168.1.0/24 --scan-type full --format detailed
```

### Output Redirection

Default output is stdout-friendly for piping to other tools:

```bash
# Save live hosts to a file
fast-netdiscover 192.168.1.0/24 > live_hosts.txt

# Pipe to nmap
fast-netdiscover 192.168.1.0/24 | nmap -n -sV -iL -

# Filter and sort
fast-netdiscover 10.0.0.0/16 | grep "192.168" | sort -u
```

## Command Line Options

### Targets

| Argument | Description | Examples |
|----------|-------------|----------|
| `<TARGETS>` | Comma-separated IPs, ranges, CIDRs, or hostnames | `192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-192.168.1.100`, `dc01.corp.local` |

### General Options

| Option | Description | Default |
|--------|-------------|---------|
| `-s, --scan-type <TYPE>` | Scan type (`ping`, `arp`, `tcp`, `syn`, `udp`, `combined`, `full`) | `ping` |
| `-c, --concurrency <N>` | Number of concurrent probes | `100` |
| `-t, --timeout <MS>` | Timeout per probe, in milliseconds | `100` |
| `-r, --retries <N>` | Retry attempts per host/port | `1` |
| `-6, --ipv6` | Use IPv6 where applicable | IPv4 |
| `-v, --verbose` | Show progress and a scan summary | off |
| `-o, --output-file <PATH>` | Save results to a file | — |

### TCP / UDP Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --tcp-ports <PORTS>` | TCP ports to scan (comma-separated, supports ranges like `80-90`) | `22,80,135,139,443,445,3389,389,88` |
| `-u, --udp-ports <PORTS>` | UDP ports to probe (comma-separated, supports ranges) | `53,137,161,5353` |
| `--tcp-syn` | Force a SYN scan instead of connect scan (needs raw-socket privileges) | off |
| `--udp-service-probes` | Use service-specific UDP probes instead of generic packets | off |
| `--live-only` | Only show hosts that have open/responding ports | off |

### Subnet Discovery Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d, --discover-subnets` | Enable subnet discovery mode | off |
| `-I, --common-ips <IPS>` | Common last-octet IPs to probe per subnet (comma-separated) | `1,2,3,252,253,254` |
| `-m, --min-responses <N>` | Minimum responsive IPs required to call a subnet active | `1` |

### ARP Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface <NAME>` | Network interface to use for ARP scanning | auto |

> **Note:** `-i` is the ARP interface flag. The common-IPs list for subnet discovery moved to `-I` (capital).

## Output Formats

Select with `-f, --format` (default: `ip`).

### `-f ip` (default)

Responsive IP addresses, one per line — ideal for piping into other tools:

```
192.168.1.1
192.168.1.10
192.168.1.254
```

### `-f subnet`

Active subnets in CIDR notation (subnet discovery mode):

```
192.168.1.0/24
192.168.5.0/24
```

### `-f host`

IP addresses (hostname where available; reverse DNS is platform-dependent).

### `-f full`

Human-readable status lines grouped by scan phase:

```
[+] Ping sweep results:
    - 192.168.1.1 is up
[+] TCP scan results:
    - 192.168.1.1: [88, 389, 445]
```

### `-f detailed`

Full report with counts and per-host open TCP and UDP ports.

## Subnet Discovery Mode

Subnet discovery (`-d`) maps which `/24` subnets are in use without scanning every possible address. Instead of pinging all 65,536 IPs in `192.168.0.0/16`, it probes a handful of common gateway/host IPs per `/24` (default `1,2,3,252,253,254`), reducing the sweep to ~1,536 pings.

### Subnet Discovery Patterns

| Pattern | Description | Example |
|---------|-------------|---------|
| `A.X` | All `/24` subnets in `A.0.0.0/8` | `10.X` |
| `A.B.X` | All `/24` subnets in `A.B.0.0/16` | `192.168.X` |
| `A.B.C-D` | Subnets from `C` to `D` | `192.168.1-100` |
| `A.B.C.0/24` | A single `/24` | `192.168.1.0/24` |
| `A.B.0.0/16` | All `/24` subnets in the `/16` | `10.0.0.0/16` |
| `A.0.0.0/8` | All `/24` subnets in the `/8` | `10.0.0.0/8` |

### Subnet Discovery Examples

```bash
# Discover active subnets in 10.0.0.0/8
fast-netdiscover "10.X" -d -f subnet

# Discover active subnets in 192.168.0.0/16
fast-netdiscover "192.168.X" -d -f subnet

# Custom common IPs (gateway, DNS, DHCP, etc.)
fast-netdiscover "10.X" -d -I "1,10,50,100,200,254" -f subnet

# Require 2+ responsive IPs to reduce false positives
fast-netdiscover "192.168.X" -d -m 2 -f subnet

# Save active subnets for further scanning
fast-netdiscover "192.168.X" -d -f subnet > active_subnets.txt
```

## Practical Use Cases

### Internal Network Reconnaissance

```bash
# Map active subnets, then enumerate them
fast-netdiscover "192.168.X" -d -f subnet > network_map.txt
cat network_map.txt | while read subnet; do
    fast-netdiscover "$subnet" -s combined -f detailed >> hosts.txt
done
```

### Enumerate Open Ports Fast

```bash
fast-netdiscover 10.0.0.0/24 -s tcp -p 88,389,445,636,3268 --live-only
```

### Integration with Other Tools

```bash
# fast-netdiscover -> nmap deep scan
fast-netdiscover 192.168.1.0/24 | nmap -n -sS -p- -T4 -iL -

# Subnet discovery -> masscan
fast-netdiscover "10.X" -d -f ip | masscan -p80,443 --rate=1000 -iL -
```

## Performance Tips

```bash
# Fast networks: high concurrency, low timeout
fast-netdiscover 192.168.1.0/24 -c 200 -t 50

# Slow / VPN networks: lower concurrency, higher timeout, extra retries
fast-netdiscover 10.0.0.0/16 -c 20 -t 500 -r 2

# Balanced subnet discovery
fast-netdiscover "192.168.X" -d -c 50 -t 100 -m 2
```

## Error Handling

- **Invalid targets** — reported to stderr; scanning continues with the remaining valid targets
- **Non-responsive hosts** — silently omitted from output (unless a verbose/detailed format is used)
- **Network errors** — individual probe failures are handled gracefully and do not abort the scan

## Limitations

- ICMP scanning requires echo requests to be permitted; some hosts block ICMP yet are still alive (use `arp`, `tcp`, or `full`)
- ARP scanning is IPv4-only and works on the local subnet
- SYN scanning (`--tcp-syn` / `-s syn`) needs raw-socket privileges (root/administrator)
- Reverse DNS resolution is platform-dependent
- IPv6 support varies by operating system
- High concurrency during subnet discovery can produce false positives — raise `-m` to require multiple responses

## Testing

```bash
cargo test
```

The `tcp` module includes unit tests covering port parsing.

## License

MIT License

## Version

0.2.0 — Adds ARP, TCP/UDP scanning, and combined/full discovery pipelines.
