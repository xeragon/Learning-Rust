use clap::{Parser, ValueEnum};
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

// Import from the library crate
use fast_netdiscover::arp::{arp_scan_with, ArpScanConfig, ArpScanResults, ArpResult};
use fast_netdiscover::tcp::{self, tcp_scan_with, TcpScanConfig, TcpScanResults, TcpScanType, TcpHostResult, get_default_ports};
use fast_netdiscover::udp::{self, udp_scan_with, UdpScanConfig, UdpScanResults, UdpHostResult, get_default_udp_ports};

/// Scan type for discovery
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ScanType {
    /// Standard ping sweep (ICMP)
    #[value(alias = "ping")]
    Ping,
    /// ARP scan using raw sockets
    #[value(alias = "arp")]
    Arp,
    /// TCP connect scan
    #[value(alias = "tcp")]
    Tcp,
    /// TCP SYN scan (requires raw socket permissions)
    #[value(alias = "syn")]
    Syn,
    /// UDP service probe scan
    #[value(alias = "udp")]
    Udp,
    /// Combined scan (ping + TCP)
    #[value(alias = "combined")]
    Combined,
    /// Full discovery (ping + ARP + TCP + UDP)
    #[value(alias = "full")]
    Full,
}

/// Output format for results
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OutputFormat {
    /// Only IP addresses (default)
    #[value(alias = "ips")]
    Ip,
    /// IP:hostname format
    #[value(alias = "host")]
    Host,
    /// Full output with status
    #[value(alias = "full")]
    Full,
    /// Subnet format (for subnet discovery mode)
    #[value(alias = "subnet")]
    Subnet,
    /// Detailed format with all scan results
    #[value(alias = "detailed")]
    Detailed,
}

#[derive(Parser, Debug)]
#[command(name = "ping-sweep")]
#[command(author = "Red Team Tool")]
#[command(version = "0.2.0")]
#[command(about = "Advanced network discovery tool with ping sweep, ARP scan, and TCP/UDP scanning")]
#[command(long_about = "A comprehensive tool for network reconnaissance during internal pentests.

Features:
- Standard ping sweeps with IP ranges, CIDR notation, or individual IPs
- ARP scanning for local-subnet hosts using raw sockets (requires root/admin)
- TCP SYN/connect scanning across configurable port lists
- UDP service probes to DNS, NetBIOS, SNMP, mDNS
- Subnet discovery mode to find active subnets
- Concurrent scanning with configurable limits

Examples:
# Basic ping sweep
ping-sweep 192.168.1.0/24

# ARP scan for local hosts
ping-sweep 192.168.1.0/24 --scan-type arp

# TCP port scan
ping-sweep 192.168.1.1-100 --scan-type tcp --tcp-ports 22,80,443

# Full discovery
ping-sweep 192.168.1.0/24 --scan-type full")]
struct Args {
    /// IP addresses, ranges, or subnets to scan
    /// Examples: 192.168.1.1, 192.168.1.0/24, 192.168.1.1-192.168.1.100
    #[arg(required = true, value_delimiter = ',')]
    targets: Vec<String>,

    /// Type of scan to perform
    #[arg(short = 's', long, value_enum, default_value = "ping")]
    scan_type: ScanType,

    /// Number of concurrent requests (default: 100)
    #[arg(short = 'c', long, default_value = "100")]
    concurrency: usize,

    /// Timeout in milliseconds for each probe (default: 100ms)
    #[arg(short = 't', long, default_value = "100")]
    timeout: u64,

    /// Number of retry attempts per host/port (default: 1)
    #[arg(short = 'r', long, default_value = "1")]
    retries: usize,

    /// Use IPv6 instead of IPv4 (when applicable)
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Network interface to use for ARP scanning
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// TCP ports to scan (comma-separated or ranges, default: 22,80,135,139,443,445,3389,389,88)
    #[arg(short = 'p', long, value_delimiter = ',')]
    tcp_ports: Option<Vec<String>>,

    /// UDP ports to scan (comma-separated or ranges, default: 53,137,161,5353)
    #[arg(short = 'u', long, value_delimiter = ',')]
    udp_ports: Option<Vec<String>>,

    /// Output format
    #[arg(short = 'f', long, value_enum, default_value = "ip")]
    format: OutputFormat,

    /// Verbose output (show progress)
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Discover active subnets by pinging common IPs (1,2,3,252,253,254) in each X.Y range
    #[arg(short = 'd', long)]
    discover_subnets: bool,

    /// Custom common IPs to test for subnet discovery (comma-separated, default: 1,2,3,252,253,254)
    #[arg(short = 'I', long, default_value = "1,2,3,252,253,254")]
    common_ips: String,

    /// Minimum number of responsive IPs to consider a subnet active (default: 1, use 2+ to reduce false positives)
    #[arg(short = 'm', long, default_value = "1")]
    min_responses: usize,

    /// Perform TCP SYN scan instead of connect scan (requires raw socket permissions)
    #[arg(long)]
    tcp_syn: bool,

    /// Use service-specific probes for UDP scanning
    #[arg(long)]
    udp_service_probes: bool,

    /// Only show hosts with open ports (for TCP/UDP scans)
    #[arg(long)]
    live_only: bool,

    /// Save results to file
    #[arg(short = 'o', long)]
    output_file: Option<String>,
}

/// Print a single live host as it is discovered (ping/ARP paths).
/// Respects `--format`; the summary count headers are printed separately at the end.
fn emit_host(ip: IpAddr, format: OutputFormat) {
    match format {
        OutputFormat::Ip | OutputFormat::Host | OutputFormat::Subnet => println!("{}", ip),
        OutputFormat::Full | OutputFormat::Detailed => println!("    - {} is up", ip),
    }
}

/// Print a single TCP host result as its scan completes.
/// Honors `--live-only` and `--format`.
fn emit_tcp_host(host: &TcpHostResult, format: OutputFormat, live_only: bool) {
    if !host.is_alive {
        return;
    }
    match format {
        OutputFormat::Ip | OutputFormat::Host | OutputFormat::Subnet => println!("{}", host.ip),
        OutputFormat::Full | OutputFormat::Detailed => {
            println!("    - {}: {:?}", host.ip, host.open_ports)
        }
    }
    let _ = live_only; // TCP only ever emits alive hosts, so live_only is always satisfied
}

/// Print a single UDP host result as its scan completes.
fn emit_udp_host(host: &UdpHostResult, format: OutputFormat, live_only: bool) {
    if !host.is_alive {
        return;
    }
    match format {
        OutputFormat::Ip | OutputFormat::Host | OutputFormat::Subnet => println!("{}", host.ip),
        OutputFormat::Full | OutputFormat::Detailed => {
            println!("    - {}: {:?}", host.ip, host.open_ports)
        }
    }
    let _ = live_only;
}

/// Print a single active subnet as it is discovered, respecting `--format`.
fn emit_subnet(subnet_info: &(String, Vec<String>), format: OutputFormat) {
    let (subnet, ips) = subnet_info;
    match format {
        OutputFormat::Ip | OutputFormat::Host => {
            for ip in ips {
                println!("{}", ip);
            }
        }
        OutputFormat::Subnet => println!("{}", subnet),
        OutputFormat::Full | OutputFormat::Detailed => {
            println!("[+] Subnet {} is active", subnet);
            for ip in ips {
                println!("    - {} is up", ip);
            }
        }
    }
}

/// Perform subnet discovery mode
async fn subnet_discovery_mode(args: &Args, common_ips: &[u8], start_time: std::time::Instant) -> anyhow::Result<()> {
    let mut active_subnets = Vec::new();
    
    // Create semaphores to limit concurrent operations
    let subnet_semaphore = Arc::new(Semaphore::new(args.concurrency));
    let ping_semaphore = Arc::new(Semaphore::new(args.concurrency * 2));
    
    for target in &args.targets {
        let target = target.trim();
        
        if let Some((base_prefix, start_octet, end_octet)) = parse_subnet_pattern(target) {
            if args.verbose {
                let subnet_count = (end_octet as usize) - (start_octet as usize) + 1;
                println!("Discovering active subnets in range {} from octet {} to {} ({} subnets, {} concurrent tasks, {}ms timeout)", 
                        base_prefix, start_octet, end_octet, subnet_count, args.concurrency, args.timeout);
            }
            
            let mut subnet_tasks = tokio::task::JoinSet::new();

            for octet in start_octet..=end_octet {
                let subnet_base = format!("{}.{}", base_prefix, octet);
                let common_ips_clone = common_ips.to_vec();
                let timeout = args.timeout;
                let count = args.retries;
                let min_responses = args.min_responses;
                let subnet_semaphore_clone = subnet_semaphore.clone();
                let ping_semaphore_clone = ping_semaphore.clone();

                subnet_tasks.spawn(async move {
                    let _subnet_permit = subnet_semaphore_clone.acquire().await.unwrap();
                    let mut responsive_ips = Vec::new();

                    for &last_octet in &common_ips_clone {
                        let test_ip = format!("{}.{}", subnet_base, last_octet);

                        if let Ok(ip) = test_ip.parse::<Ipv4Addr>() {
                            let _ping_permit = ping_semaphore_clone.acquire().await.unwrap();
                            let result = tokio::task::spawn_blocking(move || {
                                check_host_sync(IpAddr::V4(ip), timeout, count)
                            }).await.unwrap();

                            if result {
                                responsive_ips.push(test_ip);
                                if responsive_ips.len() >= min_responses {
                                    break;
                                }
                            }
                        }
                    }

                    if responsive_ips.len() >= min_responses {
                        Some((format!("{}.0/24", subnet_base), responsive_ips))
                    } else {
                        None
                    }
                });
            }

            // Emit each active subnet the moment its probes complete (completion order).
            while let Some(joined) = subnet_tasks.join_next().await {
                if let Ok(Some(subnet_info)) = joined {
                    emit_subnet(&subnet_info, args.format);
                    active_subnets.push(subnet_info);
                }
            }
        } else {
            eprintln!("Invalid subnet pattern for discovery: {}", target);
        }
    }

    if args.verbose {
        let elapsed = start_time.elapsed();
        println!("\nSubnet discovery complete. Found {} active subnets in {:.2}s.", active_subnets.len(), elapsed.as_secs_f64());
    }
    
    Ok(())
}

/// Parse subnet pattern for discovery mode
fn parse_subnet_pattern(pattern: &str) -> Option<(String, u8, u8)> {
    let pattern_lower = pattern.to_lowercase();
    
    // Try pattern with X/x placeholder
    if pattern_lower.contains('x') {
        let parts: Vec<&str> = pattern_lower.split('.').collect();
        let x_pos = parts.iter().position(|&p| p == "x");
        
        if let Some(x_pos) = x_pos {
            match (x_pos, parts.len()) {
                (1, 2) => {
                    let base_prefix = format!("{}", parts[0]);
                    return Some((base_prefix, 0, 255));
                }
                (2, 3) => {
                    let base_prefix = format!("{}.{}", parts[0], parts[1]);
                    return Some((base_prefix, 0, 255));
                }
                (2, 4) => {
                    let base_prefix = format!("{}.{}", parts[0], parts[1]);
                    return Some((base_prefix, 0, 255));
                }
                (1, 3) => {
                    let base_prefix = format!("{}", parts[0]);
                    return Some((base_prefix, 0, 255));
                }
                (3, 4) => {
                    if let Ok(octet) = parts[2].parse::<u8>() {
                        let base_prefix = format!("{}.{}.{}", parts[0], parts[1], octet);
                        return Some((base_prefix, octet, octet));
                    }
                }
                _ => {}
            }
        }
    }
    
    // Try range pattern
    if pattern.contains('-') && pattern.contains('.') && !pattern.contains('/') {
        let dash_pos = pattern.find('-').unwrap();
        let before_dash = &pattern[..dash_pos];
        let after_dash = &pattern[dash_pos + 1..];
        let before_dots = before_dash.chars().filter(|c| *c == '.').count();
        
        if let Ok(end) = after_dash.parse::<u8>() {
            let last_octet = before_dash.split('.').last().and_then(|s| s.parse::<u8>().ok());
            let start = last_octet.unwrap_or(0);
            let base_parts: Vec<&str> = before_dash.split('.').collect();
            
            let base_prefix = if before_dots == 1 {
                format!("{}", base_parts[0])
            } else if before_dots == 2 {
                format!("{}.{}", base_parts[0], base_parts[1])
            } else if before_dots == 3 {
                format!("{}.{}", base_parts[0], base_parts[1])
            } else {
                return None;
            };
            
            return Some((base_prefix, start, end));
        }
    }
    
    // Try CIDR pattern
    if pattern.contains('/') {
        if let Ok(network) = pattern.parse::<Ipv4Network>() {
            let network_ip = network.network();
            let prefix = network.prefix();
            let octets = network_ip.octets();
            
            if prefix <= 16 {
                let base_prefix = if prefix == 8 {
                    format!("{}", octets[0])
                } else {
                    format!("{}.{}", octets[0], octets[1])
                };
                return Some((base_prefix, 0, 255));
            } else if prefix <= 24 {
                let base_prefix = format!("{}.{}", octets[0], octets[1]);
                let target_octet = octets[2];
                return Some((base_prefix, target_octet, target_octet));
            }
        }
    }
    
    None
}

/// Parse a target string into a list of IP addresses
fn parse_target(target: &str, prefer_ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
    if target.contains('/') {
        if prefer_ipv6 || target.contains(':') {
            if let Ok(network) = target.parse::<Ipv6Network>() {
                return Ok(network.iter().map(IpAddr::V6).collect());
            }
        }
        if let Ok(network) = target.parse::<Ipv4Network>() {
            return Ok(network.iter().map(IpAddr::V4).collect());
        }
    }
    
    if target.contains('-') {
        return parse_ip_range(target, prefer_ipv6);
    }
    
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(vec![IpAddr::V4(ip)]);
    }
    
    if let Ok(ip) = target.parse::<Ipv6Addr>() {
        return Ok(vec![IpAddr::V6(ip)]);
    }
    
    if let Ok(ips) = resolve_hostname(target) {
        if ips.is_empty() {
            anyhow::bail!("Hostname '{}' resolved to no IP addresses", target);
        }
        return Ok(ips);
    }
    
    anyhow::bail!("Invalid target format: {}", target);
}

/// Parse an IP range (e.g., 192.168.1.1-192.168.1.100)
fn parse_ip_range(range: &str, prefer_ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
    let parts: Vec<&str> = range.split('-').map(|s| s.trim()).collect();
    
    if parts.len() != 2 {
        anyhow::bail!("Invalid range format: {}", range);
    }
    
    let start_str = parts[0];
    let end_str = parts[1];
    
    if !prefer_ipv6 {
        if let (Ok(start), Ok(end)) = (start_str.parse::<Ipv4Addr>(), end_str.parse::<Ipv4Addr>()) {
            return Ok(ipv4_range_to_ips(start, end));
        }
    }
    
    if prefer_ipv6 {
        if let (Ok(start), Ok(end)) = (start_str.parse::<Ipv6Addr>(), end_str.parse::<Ipv6Addr>()) {
            return Ok(ipv6_range_to_ips(start, end));
        }
    }
    
    anyhow::bail!("Invalid IP range: {}", range);
}

/// Convert IPv4 range to list of IPs
fn ipv4_range_to_ips(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpAddr> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    
    (start_u32..=end_u32)
        .map(|ip| IpAddr::V4(Ipv4Addr::from(ip)))
        .collect()
}

/// Convert IPv6 range to list of IPs (simplified)
fn ipv6_range_to_ips(start: Ipv6Addr, end: Ipv6Addr) -> Vec<IpAddr> {
    let start_u128 = u128::from(start);
    let end_u128 = u128::from(end);
    
    (start_u128..=end_u128)
        .map(|ip| IpAddr::V6(Ipv6Addr::from(ip)))
        .collect()
}

/// Resolve hostname to IP addresses
fn resolve_hostname(hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    
    match (hostname, 0).to_socket_addrs() {
        Ok(addrs) => {
            Ok(addrs.map(|addr| addr.ip()).collect())
        }
        Err(_) => {
            match hostname.to_socket_addrs() {
                Ok(addrs) => Ok(addrs.map(|addr| addr.ip()).collect()),
                Err(e) => Err(anyhow::anyhow!("Failed to resolve hostname: {}", e)),
            }
        }
    }
}

/// Check if a host is responsive to ping (synchronous version for spawn_blocking)
fn check_host_sync(ip: IpAddr, timeout_ms: u64, count: usize) -> bool {
    let timeout = Duration::from_millis(timeout_ms);
    
    for _ in 0..count {
        let jitter = rand::random::<u64>() % 50;
        std::thread::sleep(Duration::from_millis(jitter));
        
        if ping_ip_sync(&ip, timeout) {
            let mut success_count = 0;
            for _ in 0..3 {
                let jitter = rand::random::<u64>() % 50;
                std::thread::sleep(Duration::from_millis(jitter));
                if ping_ip_sync(&ip, timeout) {
                    success_count += 1;
                }
            }
            if success_count >= 2 {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    
    false
}

/// Ping an IP address using system ping command (sync)
fn ping_ip_sync(ip: &IpAddr, timeout: Duration) -> bool {
    let mut command = match ip {
        IpAddr::V4(_) => {
            let mut cmd = Command::new("ping");
            cmd.arg("-n");
            cmd.arg("1");
            cmd.arg("-w");
            cmd.arg(timeout.as_millis().to_string());
            cmd.arg(ip.to_string());
            cmd
        }
        IpAddr::V6(_) => {
            let mut cmd = Command::new("ping");
            cmd.arg("-6");
            cmd.arg("-n");
            cmd.arg("1");
            cmd.arg("-w");
            cmd.arg(timeout.as_millis().to_string());
            cmd.arg(ip.to_string());
            cmd
        }
    };
    
    if cfg!(unix) {
        command = match ip {
            IpAddr::V4(_) => {
                let mut cmd = Command::new("ping");
                cmd.arg("-c");
                cmd.arg("1");
                cmd.arg("-W");
                cmd.arg(format!("{}", timeout.as_secs_f32()));
                cmd.arg(ip.to_string());
                cmd
            }
            IpAddr::V6(_) => {
                let mut cmd = Command::new("ping6");
                cmd.arg("-c");
                cmd.arg("1");
                cmd.arg("-W");
                cmd.arg(format!("{}", timeout.as_secs_f32()));
                cmd.arg(ip.to_string());
                cmd
            }
        };
    }
    
    let output = command.output();
    
    match output {
        Ok(result) => {
            if cfg!(windows) {
                let output_str = String::from_utf8_lossy(&result.stdout);
                let ip_str = ip.to_string();
                
                if output_str.contains("timed out") || output_str.contains("dépassé") || output_str.contains("Timeout") {
                    return false;
                }
                
                if !result.status.success() {
                    return false;
                }
                
                if !output_str.contains(&ip_str) {
                    return false;
                }
                
                return true;
            } else {
                result.status.success()
            }
        }
        Err(_) => false,
    }
}

/// Perform ping sweep
async fn perform_ping_sweep(
    targets: &[IpAddr],
    args: &Args,
    start_time: std::time::Instant,
) -> anyhow::Result<Vec<IpAddr>> {
    if args.verbose {
        println!("Scanning {} hosts with {} concurrent pings, {}ms timeout...",
                 targets.len(), args.concurrency, args.timeout);
    }

    if matches!(args.format, OutputFormat::Full | OutputFormat::Detailed) {
        println!("[+] Ping sweep results:");
    }

    let mut tasks = tokio::task::JoinSet::new();

    for ip in targets {
        let ip_clone = *ip;
        let timeout = args.timeout;
        let count = args.retries;

        tasks.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                check_host_sync(ip_clone, timeout, count)
            }).await.unwrap();
            (ip_clone, result)
        });
    }

    // Stream each responsive host the instant its probe completes (completion order).
    let mut responsive_hosts = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok((ip, true)) = joined {
            emit_host(ip, args.format);
            responsive_hosts.push(ip);
        }
    }

    if args.verbose {
        let elapsed = start_time.elapsed();
        println!("\nPing sweep complete. Found {} responsive hosts in {:.2}s.", 
                 responsive_hosts.len(), elapsed.as_secs_f64());
    }
    
    Ok(responsive_hosts)
}

/// Perform ARP scan
async fn perform_arp_scan(
    targets: &[IpAddr],
    args: &Args,
    _start_time: std::time::Instant,
) -> anyhow::Result<ArpScanResults> {
    // Convert to IPv4 only (ARP is IPv4 only)
    let ipv4_targets: Vec<Ipv4Addr> = targets
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(addr) => Some(*addr),
            _ => None,
        })
        .collect();
    
    if ipv4_targets.is_empty() {
        anyhow::bail!("ARP scanning only supports IPv4 addresses");
    }
    
    let config = ArpScanConfig {
        interface_name: args.interface.clone(),
        timeout: Duration::from_millis(args.timeout),
        concurrency: args.concurrency,
        retries: args.retries,
        verbose: args.verbose,
    };

    let format = args.format;
    arp_scan_with(&ipv4_targets, config, |result: &ArpResult| {
        if result.is_alive {
            emit_host(IpAddr::V4(result.ip), format);
        }
    }).await
}

/// Perform TCP scan
async fn perform_tcp_scan(
    targets: &[IpAddr],
    args: &Args,
    _start_time: std::time::Instant,
) -> anyhow::Result<TcpScanResults> {
    // Parse TCP ports
    let ports = if let Some(port_args) = &args.tcp_ports {
        tcp::parse_ports_from_args(port_args)
    } else {
        get_default_ports()
    };
    
    let scan_type = if args.tcp_syn {
        TcpScanType::Syn
    } else {
        TcpScanType::Connect
    };
    
    let config = TcpScanConfig {
        ports,
        scan_type,
        timeout: Duration::from_millis(args.timeout),
        concurrency: args.concurrency,
        verbose: args.verbose,
        retries: args.retries,
    };

    if matches!(args.format, OutputFormat::Full | OutputFormat::Detailed) {
        println!("[+] TCP scan results:");
    }

    let format = args.format;
    let live_only = args.live_only;
    tcp_scan_with(targets, config, |host: &TcpHostResult| {
        emit_tcp_host(host, format, live_only);
    }).await
}

/// Perform UDP scan
async fn perform_udp_scan(
    targets: &[IpAddr],
    args: &Args,
    _start_time: std::time::Instant,
) -> anyhow::Result<UdpScanResults> {
    // Parse UDP ports
    let ports = if let Some(port_args) = &args.udp_ports {
        udp::parse_udp_ports_from_args(port_args)
    } else {
        get_default_udp_ports()
    };
    
    let config = UdpScanConfig {
        ports,
        timeout: Duration::from_millis(args.timeout),
        concurrency: args.concurrency,
        verbose: args.verbose,
        retries: args.retries,
        use_service_probes: args.udp_service_probes,
    };

    if matches!(args.format, OutputFormat::Full | OutputFormat::Detailed) {
        println!("[+] UDP scan results:");
    }

    let format = args.format;
    let live_only = args.live_only;
    udp_scan_with(targets, config, |host: &UdpHostResult| {
        emit_udp_host(host, format, live_only);
    }).await
}

/// Print end-of-run aggregate counts.
///
/// Per-host lines are streamed live as hosts are discovered (see `emit_host`,
/// `emit_tcp_host`, `emit_udp_host` and the phase headers in the `perform_*`
/// wrappers). Only counts that can be known solely at the end are printed here,
/// and only for the `Detailed` format. Other formats stream everything and have
/// no end-of-run output.
fn output_results(
    args: &Args,
    responsive_hosts: &[IpAddr],
    tcp_results: Option<&TcpScanResults>,
    udp_results: Option<&UdpScanResults>,
    _arp_results: Option<&ArpScanResults>,
) {
    if args.format != OutputFormat::Detailed {
        return;
    }

    if !responsive_hosts.is_empty() {
        println!("[+] Ping sweep found {} live hosts", responsive_hosts.len());
    }

    if let Some(tcp) = tcp_results {
        println!("[+] TCP scan found {} live hosts with {} open ports",
                 tcp.live_hosts, tcp.total_open_ports);
    }

    if let Some(udp) = udp_results {
        println!("[+] UDP scan found {} live hosts with {} responding ports",
                 udp.live_hosts, udp.total_responding_ports);
    }
}

/// Perform combined scan
async fn perform_combined_scan(
    targets: &[IpAddr],
    args: &Args,
    start_time: std::time::Instant,
) -> anyhow::Result<(Vec<IpAddr>, Option<TcpScanResults>, Option<UdpScanResults>, Option<ArpScanResults>)> {
    let mut tcp_results = None;
    let mut udp_results = None;
    let mut arp_results = None;
    
    // Always start with ping sweep
    let responsive_hosts = perform_ping_sweep(targets, args, start_time).await?;
    
    // Then perform TCP scan on live hosts
    if !responsive_hosts.is_empty() {
        tcp_results = Some(perform_tcp_scan(&responsive_hosts, args, start_time).await?);
    }
    
    // Then perform UDP scan on live hosts
    if !responsive_hosts.is_empty() {
        udp_results = Some(perform_udp_scan(&responsive_hosts, args, start_time).await?);
    }
    
    // Optionally perform ARP scan
    if args.scan_type == ScanType::Full {
        arp_results = Some(perform_arp_scan(targets, args, start_time).await?);
    }
    
    Ok((responsive_hosts, tcp_results, udp_results, arp_results))
}

/// Perform full discovery scan
async fn perform_full_scan(
    targets: &[IpAddr],
    args: &Args,
    start_time: std::time::Instant,
) -> anyhow::Result<(Vec<IpAddr>, Option<TcpScanResults>, Option<UdpScanResults>, Option<ArpScanResults>)> {
    let mut tcp_results = None;
    let mut udp_results = None;

    // Perform ping sweep
    let mut responsive_hosts = perform_ping_sweep(targets, args, start_time).await?;

    // Perform ARP scan on all targets (not just responsive ones)
    let arp_results = Some(perform_arp_scan(targets, args, start_time).await?);
    
    // Combine ping and ARP results
    if let Some(arp) = &arp_results {
        for result in &arp.results {
            if result.is_alive && !responsive_hosts.contains(&IpAddr::V4(result.ip)) {
                responsive_hosts.push(IpAddr::V4(result.ip));
            }
        }
    }
    
    // Perform TCP scan on all discovered hosts
    if !responsive_hosts.is_empty() {
        tcp_results = Some(perform_tcp_scan(&responsive_hosts, args, start_time).await?);
    }
    
    // Perform UDP scan on all discovered hosts
    if !responsive_hosts.is_empty() {
        udp_results = Some(perform_udp_scan(&responsive_hosts, args, start_time).await?);
    }
    
    Ok((responsive_hosts, tcp_results, udp_results, arp_results))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let start_time = std::time::Instant::now();
    let args = Args::parse();
    
    // Parse common IPs for subnet discovery
    let common_ips: Vec<u8> = args.common_ips.split(',')
        .filter_map(|s| s.trim().parse::<u8>().ok())
        .collect();
    
    if common_ips.is_empty() {
        eprintln!("No valid common IPs provided for subnet discovery");
        return Ok(());
    }
    
    // Handle subnet discovery mode
    if args.discover_subnets {
        return subnet_discovery_mode(&args, &common_ips, start_time).await;
    }
    
    // Parse all targets into IP addresses
    let mut all_ips = Vec::new();
    for target in &args.targets {
        match parse_target(target.trim(), args.ipv6) {
            Ok(ips) => all_ips.extend(ips),
            Err(e) => {
                eprintln!("Error parsing target '{}': {}", target, e);
                continue;
            }
        }
    }
    
    if all_ips.is_empty() {
        eprintln!("No valid IP addresses found in targets");
        return Ok(());
    }
    
    let total_targets = all_ips.len();
    
    let (responsive_hosts, tcp_results, udp_results, arp_results) = match args.scan_type {
        ScanType::Ping => {
            let hosts = perform_ping_sweep(&all_ips, &args, start_time).await?;
            (hosts, None, None, None)
        }
        ScanType::Arp => {
            let results = perform_arp_scan(&all_ips, &args, start_time).await?;
            // Convert ARP results to responsive hosts
            let hosts: Vec<IpAddr> = results.results
                .iter()
                .filter(|r| r.is_alive)
                .map(|r| IpAddr::V4(r.ip))
                .collect();
            (hosts, None, None, Some(results))
        }
        ScanType::Tcp | ScanType::Syn => {
            (vec![], Some(perform_tcp_scan(&all_ips, &args, start_time).await?), None, None)
        }
        ScanType::Udp => {
            (vec![], None, Some(perform_udp_scan(&all_ips, &args, start_time).await?), None)
        }
        ScanType::Combined => {
            perform_combined_scan(&all_ips, &args, start_time).await?
        }
        ScanType::Full => {
            perform_full_scan(&all_ips, &args, start_time).await?
        }
    };
    
    // Output results
    output_results(&args, &responsive_hosts, tcp_results.as_ref(), udp_results.as_ref(), arp_results.as_ref());

    // Verbose summary
    if args.verbose {
        let elapsed = start_time.elapsed();
        let total_found = responsive_hosts.len();
        let tcp_live = tcp_results.as_ref().map_or(0, |r| r.live_hosts);
        let udp_live = udp_results.as_ref().map_or(0, |r| r.live_hosts);
        let tcp_ports = tcp_results.as_ref().map_or(0, |r| r.total_open_ports);
        let udp_ports = udp_results.as_ref().map_or(0, |r| r.total_responding_ports);
        
        println!("\n[+] Scan Summary:");
        println!("    Total targets: {}", total_targets);
        println!("    Ping responsive: {}", total_found);
        println!("    TCP live hosts: {}", tcp_live);
        println!("    TCP open ports: {}", tcp_ports);
        println!("    UDP live hosts: {}", udp_live);
        println!("    UDP responding ports: {}", udp_ports);
        println!("    Time elapsed: {:.2}s", elapsed.as_secs_f64());
    }
    
    Ok(())
}
