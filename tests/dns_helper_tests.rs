//! Unit tests for DNS helper functionality that mirror the original DNSRecon Python tests

// These tests would normally test DNS resolution functionality,
// but since they would require network access and actual DNS queries,
// we'll focus on testing the structure and API instead.

use dnsrecon_rs::dns::resolver::DnsHelper;
use dnsrecon_rs::dns::record::{DnsRecord, RecordType, RecordData};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_dns_helper_creation() {
    // Test creating a DNS helper with default configuration
    let result = DnsHelper::new("example.com".to_string());
    assert!(result.is_ok());
}

#[test]
fn test_dns_helper_with_nameservers() {
    // Test creating a DNS helper with custom nameservers
    let nameservers = vec![
        "8.8.8.8".parse().unwrap(),
        "8.8.4.4".parse().unwrap(),
    ];
    
    let result = DnsHelper::with_nameservers("example.com".to_string(), nameservers);
    assert!(result.is_ok());
}

#[test]
fn test_dns_helper_with_ports() {
    // Test creating a DNS helper with custom ports
    let nameservers = vec![
        "8.8.8.8".parse().unwrap(),
    ];
    
    let result = DnsHelper::with_nameservers_and_ports(
        "example.com".to_string(),
        nameservers,
        53, // TCP port
        53, // UDP port
    );
    
    assert!(result.is_ok());
}

// Note: Actual DNS resolution tests that require network access
// should be integration tests or mocked tests, not unit tests.
// The original Python tests that make actual DNS requests
// would be better suited as integration tests.