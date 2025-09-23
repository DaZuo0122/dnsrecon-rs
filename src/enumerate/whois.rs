//! WHOIS lookup functionality

use crate::enumerate::EnumerationError;
use std::net::{IpAddr, TcpStream};
use std::io::{Read, Write, BufReader, BufRead};
use std::time::Duration;
use regex::Regex;

/// Perform WHOIS lookup for an IP address
pub fn whois_lookup(ip: IpAddr) -> Result<String, EnumerationError> {
    // Determine the appropriate WHOIS server
    let server = get_whois_server(ip);
    
    // Connect to the WHOIS server with timeout
    let stream = TcpStream::connect((server, 43))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    
    let mut stream = stream;
    
    // Send the query
    let query = format!("{}\r\n", ip);
    stream.write_all(query.as_bytes())?;
    
    // Read the response
    let mut response = String::new();
    let mut reader = BufReader::new(&mut stream);
    
    // Read line by line to handle large responses
    for line in reader.lines() {
        let line = line?;
        response.push_str(&line);
        response.push('\n');
    }
    
    Ok(response)
}

/// Perform WHOIS lookup with referral handling
pub fn whois_lookup_with_referral(ip: IpAddr) -> Result<String, EnumerationError> {
    // First, query ARIN (default for most IPs)
    let mut response = whois_lookup(ip)?;
    
    // Check if we need to follow a referral
    if let Some(referral_server) = extract_referral_server(&response) {
        // Query the referral server
        let referral_response = whois_lookup_to_server(ip, &referral_server)?;
        response.push_str("\n--- Referral Server Response ---\n");
        response.push_str(&referral_response);
    }
    
    Ok(response)
}

/// Perform WHOIS lookup to a specific server
fn whois_lookup_to_server(ip: IpAddr, server: &str) -> Result<String, EnumerationError> {
    // Connect to the WHOIS server with timeout
    let stream = TcpStream::connect((server, 43))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    
    let mut stream = stream;
    
    // Send the query
    let query = format!("{}\r\n", ip);
    stream.write_all(query.as_bytes())?;
    
    // Read the response
    let mut response = String::new();
    let mut reader = BufReader::new(&mut stream);
    
    // Read line by line to handle large responses
    for line in reader.lines() {
        let line = line?;
        response.push_str(&line);
        response.push('\n');
    }
    
    Ok(response)
}

/// Determine the appropriate WHOIS server for an IP address
fn get_whois_server(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(ipv4) => {
            // Check which RIR the IP belongs to
            if ipv4.octets()[0] == 127 {
                // localhost
                "whois.arin.net"
            } else if ipv4.is_private() {
                // Private addresses
                "whois.arin.net"
            } else if ipv4.octets()[0] >= 1 && ipv4.octets()[0] <= 126 {
                // Class A - mostly ARIN
                "whois.arin.net"
            } else if ipv4.octets()[0] >= 128 && ipv4.octets()[0] <= 191 {
                // Class B - mostly ARIN
                "whois.arin.net"
            } else if ipv4.octets()[0] >= 192 && ipv4.octets()[0] <= 223 {
                // Class C - check specific ranges
                if ipv4.octets()[1] == 168 {
                    // 192.168.x.x - private
                    "whois.arin.net"
                } else {
                    "whois.arin.net"
                }
            } else {
                "whois.arin.net"
            }
        },
        IpAddr::V6(_) => {
            // For IPv6, use ARIN as default
            "whois.arin.net"
        }
    }
}

/// Extract referral server from WHOIS response
fn extract_referral_server(data: &str) -> Option<String> {
    // Look for referral patterns
    let patterns = vec![
        r#"ReferralServer:\s*whois://([^\s]+)"#,
        r#"WhoisServer:\s*([^\s]+)"#,
        r#"refer:\s*([^\s]+)"#,
    ];
    
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(captures) = re.captures(data) {
                if let Some(server) = captures.get(1) {
                    return Some(server.as_str().to_string());
                }
            }
        }
    }
    
    None
}

/// Parse network ranges from WHOIS data
pub fn parse_whois_nets(data: &str) -> Vec<(String, String)> {
    let mut nets = Vec::new();
    
    // Match patterns like "NetRange: 192.0.2.0 - 192.0.2.255"
    let re = Regex::new(r#"NetRange:\s*([^\s]+)\s*-\s*([^\s]+)"#).unwrap();
    
    for captures in re.captures_iter(data) {
        if captures.len() >= 3 {
            let start = captures.get(1).unwrap().as_str().to_string();
            let end = captures.get(2).unwrap().as_str().to_string();
            nets.push((start, end));
        }
    }
    
    // Also match CIDR patterns like "CIDR: 192.0.2.0/24"
    let cidr_re = Regex::new(r#"CIDR:\s*([^\s]+)"#).unwrap();
    
    for captures in cidr_re.captures_iter(data) {
        if captures.len() >= 2 {
            let cidr = captures.get(1).unwrap().as_str();
            // For CIDR, we'd need to convert to start/end, but for now just store as is
            nets.push((cidr.to_string(), cidr.to_string()));
        }
    }
    
    nets
}

/// Extract organization name from WHOIS data
pub fn get_whois_orgname(data: &str) -> String {
    // Look for organization name patterns
    let patterns = vec![
        r#"OrgName:\s*(.+)"#,
        r#"Organization:\s*(.+)"#,
        r#"owner:\s*(.+)"#,
        r#"organisation:\s*(.+)"#,
        r#"org-name:\s*(.+)"#,
    ];
    
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(captures) = re.captures(data) {
                if let Some(org) = captures.get(1) {
                    return org.as_str().trim().to_string();
                }
            }
        }
    }
    
    "Not Found".to_string()
}

/// Extract organization handle from WHOIS data
pub fn get_whois_org_handle(data: &str) -> String {
    // Look for organization handle patterns
    let patterns = vec![
        r#"OrgId:\s*(.+)"#,
        r#"handle:\s*(.+)"#,
        r#"org-handle:\s*(.+)"#,
    ];
    
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(captures) = re.captures(data) {
                if let Some(handle) = captures.get(1) {
                    return handle.as_str().trim().to_string();
                }
            }
        }
    }
    
    "Not Found".to_string()
}