# Ping Sweep - Network Host Discovery Tool

A fast, concurrent ping sweep tool for host discovery and subnet mapping during internal penetration tests.

## Overview

`ping-sweep` is designed for red team operators and penetration testers who need to quickly identify live hosts and active subnets in internal networks. It provides both traditional ping sweeps and intelligent subnet discovery modes.

### Key Features

- **High-performance concurrent scanning** with configurable concurrency
- **Flexible target specification** - IP addresses, ranges, CIDR notation
- **Subnet discovery mode** - Find active subnets by testing common gateway IPs
- **Multiple output formats** for integration with other tools
- **Cross-platform** - Works on Windows, Linux, and macOS

## Installation

### From Source

```bash
# Clone or navigate to the project
git clone <repository-url>
cd ping_sweep

# Build in release mode for best performance
cargo build --release

# The binary will be in target/release/
```

### Pre-built Binary

Copy the `ping-sweep.exe` (Windows) or `ping-sweep` (Unix) binary to your tools directory or PATH.

## Basic Usage

### Simple Ping Sweep

```bash
# Ping a single IP
ping-sweep 192.168.1.1

# Ping a subnet (all 254 hosts)
ping-sweep 192.168.1.0/24

# Ping an IP range
ping-sweep 192.168.1.1-192.168.1.100

# Multiple targets (comma-separated)
ping-sweep 192.168.1.1,192.168.2.1,10.0.0.1
```

### Output Redirection

All output is stdout-friendly for piping to other tools:

```bash
# Save live hosts to file
ping-sweep 192.168.1.0/24 > live_hosts.txt

# Pipe to nmap
ping-sweep 192.168.1.0/24 | nmap -n -sn -

# Process with other tools
ping-sweep 10.0.0.0/16 | grep "192.168" | sort -u
```

## Command Line Options

### Target Specification

| Argument | Description | Examples |
|----------|-------------|----------|
| `<TARGETS>` | IP addresses, ranges, or subnets to scan | `192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-192.168.1.100` |

### Performance Options

| Option | Description | Default | Notes |
|--------|-------------|---------|-------|
| `-c, --concurrency <N>` | Number of concurrent ping requests | 100 | Higher = faster but more network load |
| `-t, --timeout <MS>` | Timeout per ping in milliseconds | 100ms | Increase for slow networks |
| `-n, --count <N>` | Number of ping attempts per host | 1 | Multiple attempts for reliability |

### Output Options

| Option | Description | Values |
|--------|-------------|--------|
| `-f, --format <FORMAT>` | Output format | `ip`, `host`, `full`, `subnet` |
| `-v, --verbose` | Show progress information | - | Useful for monitoring long scans |

### Subnet Discovery Options

| Option | Description | Default | Notes |
|--------|-------------|---------|-------|
| `-d, --discover-subnets` | Enable subnet discovery mode | - | Tests common IPs in each subnet |
| `-i, --common-ips <IPS>` | Common IPs to test | `1,2,3,252,253,254` | Comma-separated list |

### Network Options

| Option | Description | Default |
|--------|-------------|---------|
| `-6, --ipv6` | Use IPv6 instead of IPv4 | IPv4 | For IPv6 subnet discovery |

## Subnet Discovery Mode

The subnet discovery mode (`-d`) is designed for internal network reconnaissance where you need to identify which subnets are active without scanning every possible IP address.

### Why Use Subnet Discovery?

In large internal networks, you often encounter situations where:
- You know the general IP scheme (e.g., `192.168.X.Y`)
- You need to find which specific subnets are in use
- Time is limited and full scans are impractical

Instead of pinging all 65,536 IPs in `192.168.0.0/16`, you can test just 6 common IPs per /24 subnet (1, 2, 3, 252, 253, 254), reducing the scan to ~1,536 pings.

### Subnet Discovery Patterns

| Pattern | Description | Example | Scans |
|---------|-------------|---------|--------|
| `A.X` | Scan all /24 subnets in A.0.0.0/8 | `10.X` | 256 subnets |
| `A.B.X` | Scan all /24 subnets in A.B.0.0/16 | `192.168.X` | 256 subnets |
| `A.B.X.Y` | Scan all /24 subnets in A.B.0.0/16 | `10.X.Y` | 256 subnets |
| `A.B.C-D` | Scan from subnet C to D | `192.168.1-100` | 100 subnets |
| `A.B.C.0/24` | Scan this specific /24 subnet | `192.168.1.0/24` | 1 subnet |
| `A.B.0.0/16` | Scan all /24 subnets in /16 | `10.0.0.0/16` | 256 subnets |
| `A.0.0.0/8` | Scan all /24 subnets in /8 | `10.0.0.0/8` | 256 subnets |

### Subnet Discovery Examples

```bash
# Discover all active subnets in 10.0.0.0/8
ping-sweep "10.X" -d -f subnet

# Discover all active subnets in 192.168.0.0/16
ping-sweep "192.168.X" -d -f subnet

# Find active subnets in range 192.168.1-100
ping-sweep "192.168.1-100" -d -f subnet

# Use custom common IPs (gateway, DNS, etc.)
ping-sweep "10.X" -d -i "1,10,50,100,200,254" -f subnet

# Get all responsive IPs from active subnets
ping-sweep "172.16.X" -d -f ip > live_ips.txt

# Verbose output with subnet details
ping-sweep "192.168.X" -d -v -f full

# Fast subnet discovery with high concurrency
ping-sweep "10.X" -d -c 200 -t 50 -f subnet

# Save active subnets for further scanning
ping-sweep "192.168.X" -d -f subnet > active_subnets.txt
```

## Output Formats

### `-f ip` (Default)

Only outputs responsive IP addresses, one per line:

```
192.168.1.1
192.168.1.10
192.168.1.254
```

**Best for:** Piping to other tools, creating target lists

### `-f subnet`

Outputs active subnets in CIDR notation:

```
192.168.1.0/24
192.168.5.0/24
192.168.10.0/24
```

**Best for:** Subnet discovery, network mapping

### `-f full`

Detailed output with status information:

```
[+] Subnet 192.168.1.0/24 is active
    - 192.168.1.1 is up
    - 192.168.1.254 is up
[+] 192.168.2.1 is up
```

**Best for:** Manual review, verbose monitoring

### `-f host`

IP addresses with hostname (when available):

```
192.168.1.1
192.168.1.10
```

*Note: Reverse DNS is limited on some platforms*

## Practical Use Cases

### Internal Network Reconnaissance

```bash
# Quick network mapping
ping-sweep "192.168.X" -d -c 100 -t 100 -f subnet > network_map.txt

# Identify live hosts in discovered subnets
cat network_map.txt | while read subnet; do
    ping-sweep "$subnet" -c 50 -t 200 >> live_hosts.txt
done
```

### Targeted Subnet Scanning

```bash
# Scan only common server subnets
ping-sweep "192.168.10-20,192.168.100-110" -d -f subnet

# Focus on DMZ ranges
ping-sweep "192.168.254" -d -i "1,10,50,100,200" -f ip
```

### Integration with Other Tools

```bash
# Ping sweep -> Nmap
ping-sweep 192.168.1.0/24 | nmap -n -sS -p- -T4 -

# Subnet discovery -> Masscan
ping-sweep "10.X" -d -f ip | masscan -p80,443 --rate=1000 -

# Create target list for Metasploit
ping-sweep 192.168.1.0/24 > targets.txt
msfconsole -q -r scan.rc RHOSTS=$(cat targets.txt)
```

### Custom Common IPs

For networks where you know specific common IPs (DNS servers, domain controllers, etc.):

```bash
# Enterprise network with known infrastructure IPs
ping-sweep "10.X" -d -i "1,10,50,53,67,68,69,100,200,254" -f subnet

# Cloud environments with different conventions
ping-sweep "172.16.X" -d -i "1,10,20,30,100,200,254" -f ip
```

## Performance Optimization

### For Fast Networks

```bash
# High concurrency, low timeout
ping-sweep 192.168.1.0/24 -c 200 -t 50
```

### For Slow Networks

```bash
# Lower concurrency, higher timeout
ping-sweep 10.0.0.0/16 -c 20 -t 500 -n 2
```

### For Subnet Discovery

```bash
# Balance speed and reliability
ping-sweep "192.168.X" -d -c 50 -t 100 -n 2
```

## Error Handling

- **Invalid targets**: Errors are printed to stderr, scanning continues with valid targets
- **Timeout issues**: Non-responsive hosts are simply omitted from output
- **Network errors**: Individual ping failures are handled gracefully

## Examples Gallery

### Basic Network Scan
```bash
ping-sweep 192.168.1.0/24
```

### Subnet Discovery in /16 Network
```bash
ping-sweep "192.168.X" -d -f subnet
```

### Targeted Range with Custom IPs
```bash
ping-sweep "10.0.1-50" -d -i "1,5,10,50,100,254" -f ip > targets.txt
```

### Verbose Full Scan with Retries
```bash
ping-sweep 192.168.1.1-192.168.1.100 -c 20 -t 200 -n 2 -v -f full
```

### Quick CIDR Subnet Check
```bash
ping-sweep 192.168.1.0/24 -c 10 -t 100
```

## Tips for Internal Pentesting

1. **Start with subnet discovery** to map the network quickly
2. **Use `-f subnet`** to get a clean list of active subnets
3. **Redirect output** to files for documentation
4. **Chain with other tools** for automated reconnaissance
5. **Adjust concurrency** based on network performance
6. **Increase timeout** for VPN or slow networks
7. **Use custom common IPs** based on the organization's conventions

## Limitations

- Requires ICMP echo requests to be allowed (ping)
- Some hosts may block ICMP but still be active
- Reverse DNS resolution is platform-dependent
- IPv6 support may vary by operating system

## License

MIT License

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Version

0.1.0 - Initial release with subnet discovery support