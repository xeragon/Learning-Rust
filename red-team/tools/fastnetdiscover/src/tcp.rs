//! TCP Scan Module
//!
//! Implements TCP SYN and connect scanning across configurable ports.
//! Uses async with tokio for concurrent scanning.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{ErrorKind};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time;

/// Default ports for TCP scanning
pub const DEFAULT_TCP_PORTS: &[u16] = &[21, 22, 23, 80, 443, 445];

/// TCP scan configuration
#[derive(Debug, Clone)]
pub struct TcpScanConfig {
    /// List of ports to scan
    pub ports: Vec<u16>,
    /// Scan type: SYN or Connect
    pub scan_type: TcpScanType,
    /// Timeout for each connection attempt
    pub timeout: Duration,
    /// Number of concurrent connection attempts
    pub concurrency: usize,
    /// Verbose output
    pub verbose: bool,
    /// Number of retries per port
    pub retries: usize,
}

/// TCP scan type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpScanType {
    /// SYN scan (stealth scan) - sends SYN and looks for SYN/ACK
    Syn,
    /// Connect scan - full TCP handshake
    Connect,
}

impl Default for TcpScanType {
    fn default() -> Self {
        TcpScanType::Connect
    }
}

/// Result for a single port scan
#[derive(Debug, Clone)]
pub struct TcpPortResult {
    /// Target IP address
    pub ip: IpAddr,
    /// Port number
    pub port: u16,
    /// Whether the port is open
    pub is_open: bool,
    /// Whether the port is filtered (no response)
    pub is_filtered: bool,
    /// Response time
    pub response_time: Option<Duration>,
    /// Error if any
    pub error: Option<String>,
}

/// Result for a single host scan
#[derive(Debug, Clone)]
pub struct TcpHostResult {
    /// Target IP address
    pub ip: IpAddr,
    /// List of port results
    pub ports: Vec<TcpPortResult>,
    /// Whether the host has any open ports
    pub is_alive: bool,
    /// Open ports
    pub open_ports: Vec<u16>,
}

/// Complete TCP scan results
#[derive(Debug, Clone)]
pub struct TcpScanResults {
    /// List of host results
    pub hosts: Vec<TcpHostResult>,
    /// Total number of hosts scanned
    pub total_hosts: usize,
    /// Number of live hosts (with at least one open port)
    pub live_hosts: usize,
    /// Total number of open ports found
    pub total_open_ports: usize,
    /// Scan duration
    pub duration: Duration,
}

/// Scan a single TCP port using connect method
async fn scan_port_connect(
    target: SocketAddr,
    timeout: Duration,
    _retries: usize,
) -> TcpPortResult {
    let start = Instant::now();
    
    let result = time::timeout(timeout, TcpStream::connect(target)).await;
    
    match result {
        Ok(Ok(_)) => TcpPortResult {
            ip: target.ip(),
            port: target.port(),
            is_open: true,
            is_filtered: false,
            response_time: Some(start.elapsed()),
            error: None,
        },
        Ok(Err(e)) => {
            // Check if it's a connection refused (closed) or timeout (filtered)
            let is_filtered = matches!(
                e.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::TimedOut | ErrorKind::ConnectionReset
            );
            
            // On Unix, ConnectionRefused means closed, Timeout means filtered
            // On Windows, behavior may differ
            let is_open = false;
            let is_filtered = matches!(e.kind(), ErrorKind::TimedOut);
            
            TcpPortResult {
                ip: target.ip(),
                port: target.port(),
                is_open: false,
                is_filtered,
                response_time: Some(start.elapsed()),
                error: Some(e.to_string()),
            }
        }
        Err(_) => TcpPortResult {
            ip: target.ip(),
            port: target.port(),
            is_open: false,
            is_filtered: true,
            response_time: Some(start.elapsed()),
            error: Some("Timeout".to_string()),
        },
    }
}

/// Scan all ports on a single host
async fn scan_host_tcp(
    ip: IpAddr,
    ports: &[u16],
    config: &TcpScanConfig,
) -> TcpHostResult {
    let mut port_results = Vec::with_capacity(ports.len());
    let mut open_ports = Vec::new();
    
    for &port in ports {
        let target = SocketAddr::new(ip, port);
        let result = scan_port_connect(target, config.timeout, config.retries).await;
        
        if result.is_open {
            open_ports.push(port);
        }
        
        port_results.push(result);
    }
    
    TcpHostResult {
        ip,
        ports: port_results,
        is_alive: !open_ports.is_empty(),
        open_ports,
    }
}

/// Perform TCP scan on multiple hosts
pub async fn tcp_scan(
    targets: &[IpAddr],
    config: TcpScanConfig,
) -> anyhow::Result<TcpScanResults> {
    let start_time = Instant::now();
    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    
    if config.verbose {
        println!("TCP scanning {} hosts, {} ports each, concurrency: {}", 
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
            scan_host_tcp(ip_clone, &ports_clone, &config_clone).await
        }));
    }
    
    let mut hosts = Vec::with_capacity(targets.len());
    let mut total_open_ports = 0;
    
    for task in host_tasks {
        let host_result = task.await?;
        total_open_ports += host_result.open_ports.len();
        hosts.push(host_result);
    }
    
    let live_hosts = hosts.iter().filter(|h| h.is_alive).count();
    
    let results = TcpScanResults {
        hosts,
        total_hosts: targets.len(),
        live_hosts,
        total_open_ports,
        duration: start_time.elapsed(),
    };
    
    if config.verbose {
        println!("TCP scan complete: {} live hosts, {} open ports found in {:.2}s", 
                 live_hosts, total_open_ports, results.duration.as_secs_f64());
    }
    
    Ok(results)
}

/// Parse TCP ports from string (comma-separated or range)
pub fn parse_ports(ports_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    
    for part in ports_str.split(',') {
        let part = part.trim();
        
        if part.contains('-') {
            // Range of ports
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
            // Single port
            if let Ok(port) = part.parse::<u16>() {
                ports.push(port);
            }
        }
    }
    
    ports
}

/// Parse TCP ports from multiple strings (CLI args)
pub fn parse_ports_from_args(ports_args: &[String]) -> Vec<u16> {
    let mut ports = Vec::new();
    
    for arg in ports_args {
        ports.extend(parse_ports(arg));
    }
    
    ports.sort();
    ports.dedup();
    ports
}

/// Get default ports
pub fn get_default_ports() -> Vec<u16> {
    DEFAULT_TCP_PORTS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports("80");
        assert_eq!(ports, vec![80]);
    }
    
    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("80-85");
        assert_eq!(ports, vec![80, 81, 82, 83, 84, 85]);
    }
    
    #[test]
    fn test_parse_ports_multiple() {
        let ports = parse_ports("80,443,8080");
        assert_eq!(ports, vec![80, 443, 8080]);
    }
    
    #[test]
    fn test_parse_ports_complex() {
        let ports = parse_ports("22,80-85,443");
        assert_eq!(ports, vec![22, 80, 81, 82, 83, 84, 85, 443]);
    }
}
