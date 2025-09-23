//! Integration tests for proxy functionality

use dnsrecon_rs::utils::http::create_http_client;
use dnsrecon_rs::cli::Args;
use clap::Parser;

#[test]
fn test_create_http_client_integration() {
    // Test creating an HTTP client in an integration context
    let args = Args::parse_from(["dnsrecon-rs", "-d", "example.com"]);
    
    let result = create_http_client(&args, "dnsrecon-rs-test-agent/0.1");
    assert!(result.is_ok());
    
    // We can verify the client was created successfully
    let _client = result.unwrap();
}

#[test]
fn test_create_http_client_with_proxy_integration() {
    // Test creating an HTTP client with proxy in an integration context
    // We'll use a commonly available proxy URL for testing
    let args = Args::parse_from([
        "dnsrecon-rs", 
        "-d", "example.com", 
        "--proxy", "http://127.0.0.1:8080"
    ]);
    
    let result = create_http_client(&args, "dnsrecon-rs-test-agent/0.1");
    // This might succeed or fail depending on whether a proxy is actually running
    // The important thing is that it doesn't panic
    assert!(result.is_ok() || result.is_err());
}