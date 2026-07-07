//! ARP Scan Module
//!
//! Implements ARP scanning using system commands (ping + arp table check).
//! This avoids pnet linking issues on Windows while still providing ARP functionality.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// MAC address type for ARP results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self([a, b, c, d, e, f])
    }
    
    pub fn zero() -> Self {
        Self([0u8; 6])
    }
    
    pub fn broadcast() -> Self {
        Self([0xff; 6])
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        // Parse MAC addresses like "00-11-22-33-44-55", "00:11:22:33:44:55", or "0011.2233.4455"
        let cleaned = s.replace(['-', ':', '.'], "");
        if cleaned.len() != 12 {
            return None;
        }
        
        let mut bytes = [0u8; 6];
        for (i, byte_str) in cleaned.as_bytes().chunks(2).enumerate() {
            if i >= 6 {
                break;
            }
            let byte_str = std::str::from_utf8(byte_str).ok()?;
            bytes[i] = u8::from_str_radix(byte_str, 16).ok()?;
        }
        Some(Self(bytes))
    }
    
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }
}

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
               self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5])
    }
}

/// ARP scan configuration
#[derive(Debug, Clone)]
pub struct ArpScanConfig {
    /// Network interface to use for scanning
    pub interface_name: Option<String>,
    /// Timeout for ARP responses
    pub timeout: Duration,
    /// Number of concurrent ARP requests
    pub concurrency: usize,
    /// Number of retries per host
    pub retries: usize,
    /// Verbose output
    pub verbose: bool,
}

/// ARP scan result for a single host
#[derive(Debug, Clone)]
pub struct ArpResult {
    /// Target IP address
    pub ip: Ipv4Addr,
    /// MAC address if discovered
    pub mac: Option<MacAddr>,
    /// Whether the host responded
    pub is_alive: bool,
    /// Response time
    pub response_time: Option<Duration>,
}

/// Complete ARP scan results
#[derive(Debug, Clone)]
pub struct ArpScanResults {
    /// List of all results
    pub results: Vec<ArpResult>,
    /// Number of live hosts found
    pub live_count: usize,
    /// Total hosts scanned
    pub total_count: usize,
    /// Scan duration
    pub duration: Duration,
}

/// Perform ARP scan on a single IP using ping + arp table check
pub fn scan_single_arp(
    target_ip: Ipv4Addr,
    _config: &ArpScanConfig,
) -> ArpResult {
    let start = Instant::now();
    
    // Try to ping the host first to populate ARP table
    let ping_result = if cfg!(windows) {
        std::process::Command::new("ping")
            .arg("-n")
            .arg("1")
            .arg("-w")
            .arg("50")
            .arg(target_ip.to_string())
            .output()
    } else {
        std::process::Command::new("ping")
            .arg("-c")
            .arg("1")
            .arg("-W")
            .arg("0.05")
            .arg(target_ip.to_string())
            .output()
    };
    
    if let Ok(output) = ping_result {
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Check if ping was successful
        if cfg!(windows) {
            if output_str.contains("timed out") || output_str.contains("dépassé") || output_str.contains("Timeout") {
                return ArpResult {
                    ip: target_ip,
                    mac: None,
                    is_alive: false,
                    response_time: Some(start.elapsed()),
                };
            }
        } else {
            // Unix: check exit code
            if !output.status.success() {
                return ArpResult {
                    ip: target_ip,
                    mac: None,
                    is_alive: false,
                    response_time: Some(start.elapsed()),
                };
            }
        }
        
        // Small delay to allow ARP table update
        std::thread::sleep(Duration::from_millis(100));
        
        // Try to read ARP table
        let arp_output = if cfg!(windows) {
            std::process::Command::new("arp")
                .arg("-a")
                .arg(target_ip.to_string())
                .output()
        } else {
            std::process::Command::new("arp")
                .arg("-n")
                .arg(target_ip.to_string())
                .output()
        };
        
        if let Ok(output) = arp_output {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let ip_str = target_ip.to_string();
            
            // Look for the IP in ARP table output
            if output_str.contains(&ip_str) {
                // Try to extract MAC address from the line containing the IP
                for line in output_str.lines() {
                    if line.contains(&ip_str) && (line.contains("-") || line.contains(":")) {
                        // Windows ARP output format: "IP Address      MAC Address"
                        // Unix ARP output format: "IP Address               HWtype  HWaddress           Flags Mask    Iface"
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            // Try to parse MAC from the line
                            let mac_str = parts.iter().find(|&&p| p.contains("-") || p.contains(":"));
                            if let Some(mac_str) = mac_str {
                                if let Some(mac) = MacAddr::from_str(mac_str) {
                                    return ArpResult {
                                        ip: target_ip,
                                        mac: Some(mac),
                                        is_alive: true,
                                        response_time: Some(start.elapsed()),
                                    };
                                }
                            }
                        }
                    }
                }
                
                // If we found the IP in ARP table but couldn't parse MAC, still consider it alive
                return ArpResult {
                    ip: target_ip,
                    mac: None,
                    is_alive: true,
                    response_time: Some(start.elapsed()),
                };
            }
        }
    }
    
    ArpResult {
        ip: target_ip,
        mac: None,
        is_alive: false,
        response_time: None,
    }
}

/// Perform ARP scan on a list of IPv4 addresses
pub async fn arp_scan(
    targets: &[Ipv4Addr],
    config: ArpScanConfig,
) -> anyhow::Result<ArpScanResults> {
    if config.verbose {
        println!("ARP scanning {} hosts...", targets.len());
    }
    
    let start_time = Instant::now();
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut results = Vec::with_capacity(targets.len());
    
    let mut tasks = Vec::new();
    
    for target_ip in targets {
        let permit = semaphore.clone().acquire_owned().await?;
        let config_clone = config.clone();
        let target_ip_clone = *target_ip;
        
        tasks.push(tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let result = scan_single_arp(target_ip_clone, &config_clone);
                drop(permit);
                result
            }).await.unwrap();
            result
        }));
    }
    
    for task in tasks {
        results.push(task.await?);
    }
    
    let live_count = results.iter().filter(|r| r.is_alive).count();
    
    let scan_results = ArpScanResults {
        results,
        live_count,
        total_count: targets.len(),
        duration: start_time.elapsed(),
    };
    
    if config.verbose {
        println!("ARP scan complete: {} live hosts found in {:.2}s", 
                 live_count, scan_results.duration.as_secs_f64());
    }
    
    Ok(scan_results)
}

/// Parse ARP scan targets from a CIDR range or IP list
pub fn parse_arp_targets(target: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    if target.contains('/') {
        if let Ok(network) = target.parse::<ipnetwork::Ipv4Network>() {
            return Ok(network.iter().map(|ip| ip).collect());
        }
    }
    
    if target.contains('-') {
        let parts: Vec<&str> = target.split('-').collect();
        if parts.len() == 2 {
            let start = parts[0].parse::<Ipv4Addr>()?;
            let end = parts[1].parse::<Ipv4Addr>()?;
            return Ok(ipv4_range_to_ips(start, end));
        }
    }
    
    let ip = target.parse::<Ipv4Addr>()?;
    Ok(vec![ip])
}

/// Convert IPv4 range to list of IPs
fn ipv4_range_to_ips(start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Addr> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    
    (start_u32..=end_u32)
        .map(Ipv4Addr::from)
        .collect()
}

/// Get list of all IPs in a CIDR range
pub fn cidr_to_ips(cidr: &str) -> anyhow::Result<Vec<Ipv4Addr>> {
    if let Ok(network) = cidr.parse::<ipnetwork::Ipv4Network>() {
        Ok(network.iter().map(|ip| ip).collect())
    } else {
        anyhow::bail!("Invalid CIDR notation: {}", cidr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_arp_targets_single_ip() {
        let targets = parse_arp_targets("192.168.1.1").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], Ipv4Addr::new(192, 168, 1, 1));
    }
    
    #[test]
    fn test_parse_arp_targets_cidr() {
        let targets = parse_arp_targets("192.168.1.0/24").unwrap();
        assert_eq!(targets.len(), 256);
    }
    
    #[test]
    fn test_parse_arp_targets_range() {
        let targets = parse_arp_targets("192.168.1.1-192.168.1.10").unwrap();
        assert_eq!(targets.len(), 10);
    }
    
    #[test]
    fn test_mac_addr_from_str() {
        let mac = MacAddr::from_str("00-11-22-33-44-55").unwrap();
        assert_eq!(mac.octets(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        
        let mac = MacAddr::from_str("00:11:22:33:44:55").unwrap();
        assert_eq!(mac.octets(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }
    
    #[test]
    fn test_mac_addr_invalid() {
        assert!(MacAddr::from_str("invalid").is_none());
        assert!(MacAddr::from_str("00:11:22").is_none());
    }
}
