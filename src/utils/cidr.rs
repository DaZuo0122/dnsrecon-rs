//! CIDR range processing utilities

use ipnetwork::IpNetwork;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Expand a CIDR range to individual IP addresses
pub fn expand_cidr(cidr: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let network = IpNetwork::from_str(cidr)?;
    Ok(network.iter().collect())
}

/// Process an IP range string (either CIDR or start-end format)
pub fn process_range(range_str: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    if range_str.contains('/') {
        // CIDR format
        expand_cidr(range_str)
    } else if range_str.contains('-') {
        // Range format (e.g., 192.168.1.1-192.168.1.10)
        expand_range(range_str)
    } else {
        // Single IP
        let ip = IpAddr::from_str(range_str)?;
        Ok(vec![ip])
    }
}

/// Expand an IP range in start-end format
fn expand_range(range_str: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return Err("Invalid range format".into());
    }
    
    let start = IpAddr::from_str(parts[0])?;
    let end = IpAddr::from_str(parts[1])?;
    
    // For IPv4 ranges
    if let (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) = (start, end) {
        let mut ips = Vec::new();
        let mut current = u32::from(start_v4);
        let end_num = u32::from(end_v4);
        
        while current <= end_num {
            ips.push(IpAddr::V4(Ipv4Addr::from(current)));
            current += 1;
        }
        
        return Ok(ips);
    }
    
    // For IPv6 ranges (simplified - just the start and end)
    Ok(vec![start, end])
}