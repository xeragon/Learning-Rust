//! UDP Scan Module
//!
//! Implements UDP service probes to common services:
//! - DNS (53)
//! - NetBIOS (137)
//! - SNMP (161)
//! - mDNS (5353)

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time;

/// Default UDP ports for service probing
pub const DEFAULT_UDP_PORTS: &[u16] = &[53, 137, 161, 5353];

/// UDP service probe types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdpProbeType {
    /// DNS query probe
    Dns,
    /// NetBIOS query probe
    NetBios,
    /// SNMP query probe
    Snmp,
    /// mDNS query probe
    Mdns,
    /// Generic UDP ping (empty packet)
    Ping,
}

/// UDP scan configuration
#[derive(Debug, Clone)]
pub struct UdpScanConfig {
    /// List of UDP ports to probe
    pub ports: Vec<u16>,
    /// Timeout for each probe
    pub timeout: Duration,
    /// Number of concurrent probes
    pub concurrency: usize,
    /// Verbose output
    pub verbose: bool,
    /// Number of retries per port
    pub retries: usize,
    /// Whether to use service-specific probes
    pub use_service_probes: bool,
}

/// Result for a single UDP port probe
#[derive(Debug, Clone)]
pub struct UdpPortResult {
    /// Target IP address
    pub ip: IpAddr,
    /// Port number
    pub port: u16,
    /// Whether the port responded
    pub is_open: bool,
    /// Whether the port is filtered (no response)
    pub is_filtered: bool,
    /// Service type detected (if any)
    pub service: Option<String>,
    /// Response data (if any)
    pub response: Option<Vec<u8>>,
    /// Response time
    pub response_time: Option<Duration>,
    /// Error if any
    pub error: Option<String>,
}

/// Result for a single host scan
#[derive(Debug, Clone)]
pub struct UdpHostResult {
    /// Target IP address
    pub ip: IpAddr,
    /// List of port results
    pub ports: Vec<UdpPortResult>,
    /// Whether the host has any open ports
    pub is_alive: bool,
    /// Open ports with services
    pub open_ports: Vec<(u16, Option<String>)>,
}

/// Complete UDP scan results
#[derive(Debug, Clone)]
pub struct UdpScanResults {
    /// List of host results
    pub hosts: Vec<UdpHostResult>,
    /// Total number of hosts scanned
    pub total_hosts: usize,
    /// Number of live hosts (with at least one responding port)
    pub live_hosts: usize,
    /// Total number of responding ports found
    pub total_responding_ports: usize,
    /// Scan duration
    pub duration: Duration,
}

/// DNS query packet (simplified)
fn create_dns_query() -> Vec<u8> {
    // Simple DNS query for A record of "test.example.com"
    // This is a minimal DNS query that should elicit a response from DNS servers
    vec![
        0x00, 0x01, // Transaction ID
        0x01, 0x00, // Flags: Standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Question section
        0x04, b't', b'e', b's', b't', // QNAME: "test"
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // Null terminator
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    ]
}

/// NetBIOS query packet (simplified)
fn create_netbios_query() -> Vec<u8> {
    // NetBIOS Name Service query
    // This is a minimal query that should work with most NetBIOS implementations
    vec![
        0x00, // Message type
        0x00, // Flags
        0x00, 0x01, // Question count
        0x00, 0x00, // Answer count
        0x00, 0x00, // Authority count
        0x00, 0x00, // Additional count
        // Question section
        0x20, // Name length
        // 32-byte name (padded with spaces)
        b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
        b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
        b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
        b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
        0x00, 0x00, // Type: NB (Name Query)
        0x00, 0x01, // Class: IN
    ]
}

/// SNMP query packet (simplified)
fn create_snmp_query() -> Vec<u8> {
    // SNMP v2c GET request
    vec![
        0x30, 0x26, // SEQUENCE length
        0x02, 0x01, 0x00, // Integer: version 2
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // String: community "public"
        0xA0, 0x19, // GET PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01, // Request ID
        0x02, 0x01, 0x00, // Error status
        0x02, 0x01, 0x00, // Error index
        0x30, 0x0E, // SEQUENCE for variable bindings
        0x30, 0x0C, // SEQUENCE for variable binding
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr
        0x05, 0x00, // NULL value
    ]
}

/// mDNS query packet (simplified)
fn create_mdns_query() -> Vec<u8> {
    // mDNS query for local services
    vec![
        0x00, 0x00, // Transaction ID
        0x00, 0x00, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Question section
        0x0C, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', b'_', b't', b'c', b'p',
        0x05, b'_', b't', b'c', b'p', 0x00, // QNAME: "_services._tcp.local"
        0x00, 0x0C, // QTYPE: PTR
        0x00, 0x01, // QCLASS: IN
    ]
}

/// Create a probe packet based on port number
fn create_probe_packet(port: u16, use_service_probes: bool) -> Vec<u8> {
    if !use_service_probes {
        // Empty packet for basic UDP ping
        return vec![];
    }
    
    match port {
        53 => create_dns_query(),
        137 => create_netbios_query(),
        161 => create_snmp_query(),
        5353 => create_mdns_query(),
        _ => vec![], // Empty packet for other ports
    }
}

/// Get service name for port
fn get_service_name(port: u16) -> Option<String> {
    match port {
        53 => Some("DNS".to_string()),
        137 => Some("NetBIOS".to_string()),
        161 => Some("SNMP".to_string()),
        5353 => Some("mDNS".to_string()),
        67 => Some("DHCP".to_string()),
        68 => Some("DHCP".to_string()),
        69 => Some("TFTP".to_string()),
        123 => Some("NTP".to_string()),
        162 => Some("SNMP Trap".to_string()),
        _ => None,
    }
}

/// Scan a single UDP port
async fn scan_port_udp(
    target: SocketAddr,
    timeout: Duration,
    use_service_probes: bool,
) -> UdpPortResult {
    let start = Instant::now();
    let probe_packet = create_probe_packet(target.port(), use_service_probes);
    
    match UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            // Send probe
            let send_result = time::timeout(timeout, socket.send_to(&probe_packet, target)).await;
            
            // Try to receive response with timeout
            let mut buf = vec![0u8; 1024];
            let recv_result = time::timeout(timeout, socket.recv_from(&mut buf)).await;
            
            match (send_result, recv_result) {
                (Ok(Ok(_)), Ok(Ok((size, _)))) => {
                    buf.truncate(size);
                    UdpPortResult {
                        ip: target.ip(),
                        port: target.port(),
                        is_open: true,
                        is_filtered: false,
                        service: get_service_name(target.port()),
                        response: Some(buf),
                        response_time: Some(start.elapsed()),
                        error: None,
                    }
                }
                (Ok(Ok(_)), Ok(Err(_))) => {
                    // Sent successfully but no response - might be filtered
                    UdpPortResult {
                        ip: target.ip(),
                        port: target.port(),
                        is_open: false,
                        is_filtered: true,
                        service: get_service_name(target.port()),
                        response: None,
                        response_time: Some(start.elapsed()),
                        error: Some("No response".to_string()),
                    }
                }
                (Ok(Err(e)), _) => UdpPortResult {
                    ip: target.ip(),
                    port: target.port(),
                    is_open: false,
                    is_filtered: true,
                    service: get_service_name(target.port()),
                    response: None,
                    response_time: Some(start.elapsed()),
                    error: Some(e.to_string()),
                },
                (Err(_), _) => UdpPortResult {
                    ip: target.ip(),
                    port: target.port(),
                    is_open: false,
                    is_filtered: true,
                    service: get_service_name(target.port()),
                    response: None,
                    response_time: Some(start.elapsed()),
                    error: Some("Socket error".to_string()),
                },
                (Ok(Ok(_)), Err(_)) => {
                    // Timeout on receive
                    UdpPortResult {
                        ip: target.ip(),
                        port: target.port(),
                        is_open: false,
                        is_filtered: true,
                        service: get_service_name(target.port()),
                        response: None,
                        response_time: Some(start.elapsed()),
                        error: Some("Timeout".to_string()),
                    }
                }
            }
        }
        Err(e) => UdpPortResult {
            ip: target.ip(),
            port: target.port(),
            is_open: false,
            is_filtered: true,
            service: get_service_name(target.port()),
            response: None,
            response_time: Some(start.elapsed()),
            error: Some(e.to_string()),
        },
    }
}

/// Scan all UDP ports on a single host
async fn scan_host_udp(
    ip: IpAddr,
    ports: &[u16],
    config: &UdpScanConfig,
) -> UdpHostResult {
    let mut port_results = Vec::with_capacity(ports.len());
    let mut open_ports = Vec::new();
    
    for &port in ports {
        let target = SocketAddr::new(ip, port);
        let result = scan_port_udp(target, config.timeout, config.use_service_probes).await;
        
        if result.is_open {
            open_ports.push((port, result.service.clone()));
        }
        
        port_results.push(result);
    }
    
    UdpHostResult {
        ip,
        ports: port_results,
        is_alive: !open_ports.is_empty(),
        open_ports,
    }
}

/// Perform UDP scan on multiple hosts
pub async fn udp_scan(
    targets: &[IpAddr],
    config: UdpScanConfig,
) -> anyhow::Result<UdpScanResults> {
    let start_time = Instant::now();
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    
    if config.verbose {
        println!("UDP scanning {} hosts, {} ports each, concurrency: {}", 
                 targets.len(), config.ports.len(), config.concurrency);
    }
    
    let mut host_tasks = Vec::new();
    
    for ip in targets {
        let ip_clone = *ip;
        let ports_clone = config.ports.clone();
        let config_clone = config.clone();
        let semaphore_clone = semaphore.clone();
        
        host_tasks.push(tokio::spawn(async move {
            let _permit = semaphore_clone.acquire().await.unwrap();
            scan_host_udp(ip_clone, &ports_clone, &config_clone).await
        }));
    }
    
    let mut hosts = Vec::with_capacity(targets.len());
    let mut total_responding_ports = 0;
    
    for task in host_tasks {
        let host_result = task.await?;
        total_responding_ports += host_result.open_ports.len();
        hosts.push(host_result);
    }
    
    let live_hosts = hosts.iter().filter(|h| h.is_alive).count();
    
    let results = UdpScanResults {
        hosts,
        total_hosts: targets.len(),
        live_hosts,
        total_responding_ports,
        duration: start_time.elapsed(),
    };
    
    if config.verbose {
        println!("UDP scan complete: {} live hosts, {} responding ports found in {:.2}s", 
                 live_hosts, total_responding_ports, results.duration.as_secs_f64());
    }
    
    Ok(results)
}

/// Parse UDP ports from string (comma-separated or range)
pub fn parse_udp_ports(ports_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    
    for part in ports_str.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (
                    range_parts[0].parse::<u16>(),
                    range_parts[1].parse::<u16>(),
                ) {
                    for port in start..=end {
                        ports.push(port);
                    }
                }
            }
        } else {
            if let Ok(port) = part.parse::<u16>() {
                ports.push(port);
            }
        }
    }
    
    ports
}

/// Parse UDP ports from multiple strings (CLI args)
pub fn parse_udp_ports_from_args(ports_args: &[String]) -> Vec<u16> {
    let mut ports = Vec::new();
    
    for arg in ports_args {
        ports.extend(parse_udp_ports(arg));
    }
    
    ports.sort();
    ports.dedup();
    ports
}

/// Get default UDP ports
pub fn get_default_udp_ports() -> Vec<u16> {
    DEFAULT_UDP_PORTS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_service_name() {
        assert_eq!(get_service_name(53), Some("DNS".to_string()));
        assert_eq!(get_service_name(137), Some("NetBIOS".to_string()));
        assert_eq!(get_service_name(161), Some("SNMP".to_string()));
        assert_eq!(get_service_name(5353), Some("mDNS".to_string()));
        assert_eq!(get_service_name(123), Some("NTP".to_string()));
        assert_eq!(get_service_name(9999), None);
    }
    
    #[test]
    fn test_parse_udp_ports_single() {
        let ports = parse_udp_ports("53");
        assert_eq!(ports, vec![53]);
    }
    
    #[test]
    fn test_parse_udp_ports_range() {
        let ports = parse_udp_ports("50-55");
        assert_eq!(ports, vec![50, 51, 52, 53, 54, 55]);
    }
    
    #[test]
    fn test_parse_udp_ports_multiple() {
        let ports = parse_udp_ports("53,137,161,5353");
        assert_eq!(ports, vec![53, 137, 161, 5353]);
    }
    
    #[test]
    fn test_probe_packet_creation() {
        let dns_packet = create_probe_packet(53, true);
        assert!(!dns_packet.is_empty());
        
        let netbios_packet = create_probe_packet(137, true);
        assert!(!netbios_packet.is_empty());
        
        let empty_packet = create_probe_packet(12345, true);
        assert!(empty_packet.is_empty());
    }
}
