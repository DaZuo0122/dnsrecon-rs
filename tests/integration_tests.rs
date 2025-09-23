//! Integration tests for the DNSRecon-rs application

use dnsrecon_rs::dns::resolver::DnsHelper;

#[tokio::test]
async fn test_dns_helper_creation() {
    // Test creating a DNS helper with default configuration
    let result = DnsHelper::new("example.com".to_string());
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_basic_dns_resolution() {
    // Test basic DNS resolution capabilities
    let dns_helper = DnsHelper::new("example.com".to_string()).unwrap();
    
    // Try to resolve a known domain
    let result = dns_helper.get_ip("example.com");
    assert!(result.is_ok());
    
    // Note: We don't assert specific results because DNS records can change
    // but we verify the function doesn't error out
}

#[tokio::test]
async fn test_cli_parsing() {
    use dnsrecon_rs::cli::{Args, EnumType};
    use clap::Parser;

    // Test basic argument parsing
    let args = vec!["dnsrecon-rs", "-d", "example.com"];
    let result = Args::try_parse_from(args);
    assert!(result.is_ok());
    
    let args = result.unwrap();
    assert_eq!(args.domain, Some("example.com".to_string()));
    assert_eq!(args.r#type, EnumType::Standard);
}

#[tokio::test]
async fn test_output_formatting() {
    use dnsrecon_rs::dns::record::{DnsRecord, RecordType, RecordData};
    use dnsrecon_rs::output;
    use std::net::Ipv4Addr;
    
    // Create a simple DNS record
    let record = DnsRecord::new_a(
        "example.com".to_string(),
        Ipv4Addr::new(192, 168, 1, 1)
    );
    
    let records = vec![record];
    
    // Test JSON output
    let json_result = output::json::to_json_string(&records);
    assert!(json_result.is_ok());
    
    // Test XML output
    let xml_result = output::xml::to_xml_string(&records);
    assert!(xml_result.is_ok());
}