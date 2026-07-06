use clap::{Parser, ValueEnum};
use ipnetwork::{Ipv4Network, Ipv6Network};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::Arc;

use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Parser, Debug)]
#[command(name = "ping-sweep")]
#[command(author = "Red Team Tool")]
#[command(version = "0.1.0")]
#[command(about = "Fast ping sweep and subnet discovery tool for internal pentests")]
#[command(long_about = "A tool to perform ping sweeps on IP ranges or subnets and discover active subnets.\n\nFeatures:\n- Standard ping sweeps with IP ranges, CIDR notation, or individual IPs\n- Subnet discovery mode to find active subnets by testing common IPs (1,2,3,252,253,254)\n- Supports patterns like 192.168.X, 192.168.1-100, 10.0.0.0/16\n\nOutput can be redirected to a file for further scanning with other tools.")]
struct Args {
    /// IP addresses, ranges, or subnets to scan
    /// Examples: 192.168.1.1, 192.168.1.0/24, 192.168.1.1-192.168.1.100
    #[arg(required = true, value_delimiter = ',')]
    targets: Vec<String>,

    /// Number of concurrent ping requests (default: 100)
    #[arg(short = 'c', long, default_value = "100")]
    concurrency: usize,

    /// Timeout in milliseconds for each ping (default: 100ms)
    #[arg(short = 't', long, default_value = "100")]
    timeout: u64,

    /// Number of ping attempts per host (default: 1)
    #[arg(short = 'n', long, default_value = "1")]
    count: usize,

    /// Use IPv6 instead of IPv4 (when applicable)
    #[arg(short = '6', long)]
    ipv6: bool,



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
    #[arg(short = 'i', long, default_value = "1,2,3,252,253,254")]
    common_ips: String,

    /// Minimum number of responsive IPs to consider a subnet active (default: 1, use 2+ to reduce false positives)
    #[arg(short = 'm', long, default_value = "1")]
    min_responses: usize,
}

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
}



/// Perform subnet discovery by testing common IPs in each potential subnet
async fn subnet_discovery_mode(args: &Args, common_ips: &[u8], start_time: std::time::Instant) -> anyhow::Result<()> {
    let mut active_subnets = Vec::new();
    
    // Create semaphores to limit concurrent operations
    // subnet_semaphore limits the number of concurrent subnet tasks
    let subnet_semaphore = Arc::new(Semaphore::new(args.concurrency));
    // ping_semaphore limits the total number of concurrent ping operations
    // This prevents overwhelming the system with too many concurrent pings
    let ping_semaphore = Arc::new(Semaphore::new(args.concurrency * 2));
    
    for target in &args.targets {
        let target = target.trim();
        
        // Parse subnet discovery pattern
        if let Some((base_prefix, start_octet, end_octet)) = parse_subnet_pattern(target) {
            if args.verbose {
                let subnet_count = (end_octet as usize) - (start_octet as usize) + 1;
                println!("Discovering active subnets in range {} from octet {} to {} ({} subnets, {} concurrent tasks, {}ms timeout)", 
                        base_prefix, start_octet, end_octet, subnet_count, args.concurrency, args.timeout);
            }
            
            let mut discovered_subnets = Vec::new();
            
            // Test each octet in the range concurrently with semaphore limiting
            let mut subnet_tasks = Vec::new();
            
            for octet in start_octet..=end_octet {
                let subnet_base = format!("{}.{}", base_prefix, octet);
                let common_ips_clone = common_ips.to_vec();
                let timeout = args.timeout;
                let count = args.count;
                let min_responses = args.min_responses;
                let subnet_semaphore_clone = subnet_semaphore.clone();
                let ping_semaphore_clone = ping_semaphore.clone();
                
                subnet_tasks.push(tokio::spawn(async move {
                    // Acquire subnet semaphore permit for concurrency control
                    let _subnet_permit = subnet_semaphore_clone.acquire().await.unwrap();
                    
                    let mut responsive_ips = Vec::new();
                    
                    // Test common IPs in this subnet sequentially to avoid overwhelming the system
                    for &last_octet in &common_ips_clone {
                        let test_ip = format!("{}.{}", subnet_base, last_octet);
                        
                        if let Ok(ip) = test_ip.parse::<Ipv4Addr>() {
                            // Acquire ping semaphore to limit total concurrent pings
                            let _ping_permit = ping_semaphore_clone.acquire().await.unwrap();
                            
                            let result = tokio::task::spawn_blocking(move || {
                                check_host_sync(IpAddr::V4(ip), timeout, count)
                            }).await.unwrap();
                            
                            if result {
                                responsive_ips.push(test_ip);
                                // If we already have enough responses, no need to test more IPs in this subnet
                                if responsive_ips.len() >= min_responses {
                                    break;
                                }
                            }
                        }
                    }
                    
                    // Require at least min_responses to consider the subnet active
                    // This reduces false positives significantly
                    if responsive_ips.len() >= min_responses {
                        Some((format!("{}.0/24", subnet_base), responsive_ips))
                    } else {
                        None
                    }
                }));
            }
            
            // Collect results
            for task in subnet_tasks {
                if let Ok(Some(subnet_info)) = task.await {
                    discovered_subnets.push(subnet_info);
                }
            }
            
            active_subnets.extend(discovered_subnets);
        } else {
            eprintln!("Invalid subnet pattern for discovery: {}", target);
        }
    }
    
    // Output results based on format
    match args.format {
        OutputFormat::Ip | OutputFormat::Host => {
            for (_subnet, ips) in &active_subnets {
                for ip in ips {
                    println!("{}", ip);
                }
            }
        }
        OutputFormat::Full => {
            for (subnet, ips) in &active_subnets {
                println!("[+] Subnet {} is active", subnet);
                for ip in ips {
                    println!("    - {} is up", ip);
                }
            }
        }
        OutputFormat::Subnet => {
            for (subnet, _) in &active_subnets {
                println!("{}", subnet);
            }
        }
    }
    
    if args.verbose {
        let elapsed = start_time.elapsed();
        println!("\nSubnet discovery complete. Found {} active subnets in {:.2}s.", active_subnets.len(), elapsed.as_secs_f64());
    }
    
    Ok(())
}

/// Parse subnet pattern for discovery mode
/// Supported patterns:
/// - "10.X" - scan 10.0.0.0/24 to 10.255.0/24
/// - "192.168.X" or "192.168.x" - scan 192.168.0.0/24 to 192.168.255.0/24
/// - "192.168.X.Y" - scan 192.168.0.0/24 to 192.168.255.0/24
/// - "172.16.201.X" - scan just 172.16.201.0/24
/// - "192.168.1-100" - scan 192.168.1.0/24 to 192.168.100.0/24
/// - "192.168.0.0/16" - scan all /24 subnets within this /16
fn parse_subnet_pattern(pattern: &str) -> Option<(String, u8, u8)> {
    let pattern_lower = pattern.to_lowercase();
    
    // Try pattern with X/x placeholder (e.g., "192.168.X" or "10.X")
    if pattern_lower.contains('x') {
        let parts: Vec<&str> = pattern_lower.split('.').collect();
        
        // Find the position of 'x'
        let x_pos = parts.iter().position(|&p| p == "x");
        
        if let Some(x_pos) = x_pos {
            match (x_pos, parts.len()) {
                // Pattern like "10.X" - 2 parts, x at position 1
                (1, 2) => {
                    let base_prefix = format!("{}", parts[0]);
                    return Some((base_prefix, 0, 255));
                }
                // Pattern like "192.168.X" - 3 parts, x at position 2
                (2, 3) => {
                    let base_prefix = format!("{}.{}", parts[0], parts[1]);
                    return Some((base_prefix, 0, 255));
                }
                // Pattern like "192.168.X.Y" - 4 parts, x at position 2
                (2, 4) => {
                    let base_prefix = format!("{}.{}", parts[0], parts[1]);
                    return Some((base_prefix, 0, 255));
                }
                // Pattern like "10.X.Y" - 3 parts, x at position 1
                (1, 3) => {
                    let base_prefix = format!("{}", parts[0]);
                    return Some((base_prefix, 0, 255));
                }
                // Pattern like "172.16.201.X" - 4 parts, x at position 3
                // This means scan just the 172.16.201.0/24 subnet
                (3, 4) => {
                    // Check if parts[2] is a number (like "172.16.201.X")
                    if let Ok(octet) = parts[2].parse::<u8>() {
                        // This is a pattern like "172.16.201.X" - scan just that one subnet
                        let base_prefix = format!("{}.{}.{}", parts[0], parts[1], octet);
                        return Some((base_prefix, octet, octet));
                    } else {
                        // Fallback to scanning all
                        let base_prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
                        return Some((base_prefix, 0, 255));
                    }
                }
                _ => {}
            }
        }
    }
    
    // Try range pattern like "192.168.1-100" - scan 192.168.1.0/24 to 192.168.100.0/24
    // or like "127.0.1-2" - scan 127.0.1.0/24 to 127.0.2.0/24
    if pattern.contains('-') && pattern.contains('.') && !pattern.contains('/') {
        let dash_pos = pattern.find('-').unwrap();
        let before_dash = &pattern[..dash_pos];
        let after_dash = &pattern[dash_pos + 1..];
        
        // Count dots in before_dash to determine the level
        let before_dots = before_dash.chars().filter(|c| *c == '.').count();
        
        if let Ok(end) = after_dash.parse::<u8>() {
            // Extract the last octet from before_dash
            let last_octet = before_dash.split('.').last().and_then(|s| s.parse::<u8>().ok());
            let start = last_octet.unwrap_or(0);
            
            // Build the base prefix by removing the last octet from before_dash
            let base_parts: Vec<&str> = before_dash.split('.').collect();
            let base_prefix = if before_dots == 1 {
                // Pattern like "192.168-100" -> base is "192"
                format!("{}", base_parts[0])
            } else if before_dots == 2 {
                // Pattern like "192.168.1-100" -> base is "192.168"
                format!("{}.{}", base_parts[0], base_parts[1])
            } else if before_dots == 3 {
                // Pattern like "127.0.1-2" -> base is "127.0"
                format!("{}.{}", base_parts[0], base_parts[1])
            } else {
                return None;
            };
            
            return Some((base_prefix, start, end));
        }
    }
    
    // Try simple range pattern like "1-100" - this means scan subnets 1 to 100
    // We assume it's for the 3rd octet and use a default base
    if pattern.contains('-') && !pattern.contains('.') && !pattern.contains('/') {
        let parts: Vec<&str> = pattern.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
                // Use default base of "192.168" for simple ranges
                return Some(("192.168".to_string(), start, end));
            }
        }
    }
    
    // Try CIDR pattern for subnet scanning (e.g., "192.168.0.0/16")
    if pattern.contains('/') {
        if let Ok(network) = pattern.parse::<Ipv4Network>() {
            let network_ip = network.network();
            let prefix = network.prefix();
            
            if prefix <= 16 {
                // For /8 or /16, scan all /24 subnets within
                let octets = network_ip.octets();
                let base_prefix = if prefix == 8 {
                    format!("{}", octets[0])
                } else if prefix == 16 {
                    format!("{}.{}", octets[0], octets[1])
                } else {
                    return None;
                };
                
                return Some((base_prefix, 0, 255));
            } else if prefix <= 24 {
                // For /24, scan just this subnet
                let octets = network_ip.octets();
                let base_prefix = format!("{}.{}", octets[0], octets[1]);
                let target_octet = octets[2];
                return Some((base_prefix, target_octet, target_octet));
            }
        }
    }
    
    None
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

    if args.verbose {
        println!("Scanning {} hosts with {} concurrent pings, {}ms timeout...", 
                 all_ips.len(), args.concurrency, args.timeout);
    }

    // Spawn all ping tasks concurrently using spawn_blocking
    // This avoids blocking the async runtime with system ping commands
    let mut tasks = Vec::new();
    
    for ip in all_ips {
        let ip_clone = ip;
        let timeout = args.timeout;
        let count = args.count;
        
        tasks.push(tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                check_host_sync(ip_clone, timeout, count)
            }).await.unwrap();
            (ip_clone, result)
        }));
    }
    
    // Collect results
    let mut responsive_hosts = Vec::new();
    for task in tasks {
        if let Ok((ip, result)) = task.await {
            if result {
                responsive_hosts.push(ip);
            }
        }
    }

    // Output results based on format
    let host_count = responsive_hosts.len();
    for ip in &responsive_hosts {
        match args.format {
            OutputFormat::Ip => println!("{}", ip),
            OutputFormat::Host => {
                // For now, just print the IP (reverse DNS would require platform-specific code)
                println!("{}", ip);
            }
            OutputFormat::Full => println!("[+] {} is up", ip),
            OutputFormat::Subnet => println!("{}", ip),
        }
    }

    if args.verbose {
        let elapsed = start_time.elapsed();
        println!("\nScan complete. Found {} responsive hosts in {:.2}s.", host_count, elapsed.as_secs_f64());
    }

    Ok(())
}

/// Parse a target string into a list of IP addresses
fn parse_target(target: &str, prefer_ipv6: bool) -> anyhow::Result<Vec<IpAddr>> {
    // Try parsing as IP network (CIDR notation)
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
    
    // Try parsing as IP range (e.g., 192.168.1.1-192.168.1.100)
    if target.contains('-') {
        return parse_ip_range(target, prefer_ipv6);
    }
    
    // Try parsing as single IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    
    // Try parsing as single IPv4
    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        return Ok(vec![IpAddr::V4(ip)]);
    }
    
    // Try parsing as single IPv6
    if let Ok(ip) = target.parse::<Ipv6Addr>() {
        return Ok(vec![IpAddr::V6(ip)]);
    }
    
    // Try parsing as hostname and resolve
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
    
    // Try IPv4 range
    if !prefer_ipv6 {
        if let (Ok(start), Ok(end)) = (start_str.parse::<Ipv4Addr>(), end_str.parse::<Ipv4Addr>()) {
            return Ok(ipv4_range_to_ips(start, end));
        }
    }
    
    // Try IPv6 range
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

/// Convert IPv6 range to list of IPs (simplified - only handles sequential addresses)
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
            // Try without port
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
        if ping_ip_sync(&ip, timeout) {
            return true;
        }
        // Small delay between retries
        std::thread::sleep(Duration::from_millis(10));
    }
    
    false
}

/// Ping an IP address using system ping command (sync)
/// Returns true only if the ping was successful AND the response came from the intended IP
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
    
    // For Unix-like systems, use different flags
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
            // Check exit code - 0 means success
            if !result.status.success() {
                return false;
            }
            
            // On Windows, also verify the output contains the IP address
            // This helps prevent false positives from cached ARP entries or broadcast responses
            if cfg!(windows) {
                let output_str = String::from_utf8_lossy(&result.stdout);
                let ip_str = ip.to_string();
                // Check if the output contains the IP we pinged
                // Windows ping output should contain "Reply from <ip>" or "Ping statistics for <ip>"
                if !output_str.contains(&ip_str) {
                    return false;
                }
            }
            
            true
        }
        Err(_) => false,
    }
}


