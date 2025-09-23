//! Input validation utilities

use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Validate if a string is a valid domain name
pub fn is_valid_domain(domain: &str) -> bool {
    // Basic domain validation regex
    let re = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
    re.is_match(domain) && domain.len() <= 253
}

/// Validate if a string is a valid IP address
pub fn is_valid_ip(ip: &str) -> bool {
    IpAddr::from_str(ip).is_ok()
}

/// Validate if a string is a valid IPv4 address
pub fn is_valid_ipv4(ip: &str) -> bool {
    Ipv4Addr::from_str(ip).is_ok()
}

/// Validate if a string is a valid IPv6 address
pub fn is_valid_ipv6(ip: &str) -> bool {
    Ipv6Addr::from_str(ip).is_ok()
}

/// Validate CIDR notation
pub fn is_valid_cidr(cidr: &str) -> bool {
    cidr.parse::<ipnetwork::IpNetwork>().is_ok()
}