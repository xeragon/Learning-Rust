//! Network Discovery Library
//!
//! A comprehensive network discovery library with:
//! - Ping sweep functionality
//! - ARP scanning using raw sockets
//! - TCP SYN/connect scanning
//! - UDP service probing

pub mod arp;
pub mod tcp;
pub mod udp;

// Re-export the most commonly used types and functions
pub use arp::{arp_scan, arp_scan_with, ArpScanConfig, ArpScanResults, ArpResult};
pub use tcp::{tcp_scan, tcp_scan_with, TcpScanConfig, TcpScanResults, TcpScanType, TcpHostResult, get_default_ports};
pub use udp::{udp_scan, udp_scan_with, UdpScanConfig, UdpScanResults, UdpHostResult, get_default_udp_ports};
