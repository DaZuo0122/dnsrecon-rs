//! Unit tests for CLI functionality including proxy support

use dnsrecon_rs::cli::{Args, EnumType};
use clap::Parser;

#[test]
fn test_cli_parsing_without_proxy() {
    // Test basic argument parsing without proxy
    let args = vec!["dnsrecon-rs", "-d", "example.com"];
    let result = Args::try_parse_from(args);
    assert!(result.is_ok());
    
    let args = result.unwrap();
    assert_eq!(args.domain, Some("example.com".to_string()));
    assert_eq!(args.r#type, EnumType::Standard);
    assert_eq!(args.proxy, None);
}

#[test]
fn test_cli_parsing_with_http_proxy() {
    // Test argument parsing with HTTP proxy
    let args = vec!["dnsrecon-rs", "-d", "example.com", "--proxy", "http://proxy.example.com:8080"];
    let result = Args::try_parse_from(args);
    assert!(result.is_ok());
    
    let args = result.unwrap();
    assert_eq!(args.domain, Some("example.com".to_string()));
    assert_eq!(args.proxy, Some("http://proxy.example.com:8080".to_string()));
}

#[test]
fn test_cli_parsing_with_socks5_proxy() {
    // Test argument parsing with SOCKS5 proxy
    let args = vec!["dnsrecon-rs", "-d", "example.com", "--proxy", "socks5://proxy.example.com:1080"];
    let result = Args::try_parse_from(args);
    assert!(result.is_ok());
    
    let args = result.unwrap();
    assert_eq!(args.domain, Some("example.com".to_string()));
    assert_eq!(args.proxy, Some("socks5://proxy.example.com:1080".to_string()));
}

#[test]
fn test_cli_parsing_with_brute_force_type() {
    // Test argument parsing with brute force type
    let args = vec!["dnsrecon-rs", "-d", "example.com", "-t", "bruteforce"];
    let result = Args::try_parse_from(args);
    assert!(result.is_ok());
    
    let args = result.unwrap();
    assert_eq!(args.domain, Some("example.com".to_string()));
    assert_eq!(args.r#type, EnumType::BruteForce);
}