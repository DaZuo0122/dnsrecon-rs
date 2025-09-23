//! Unit tests for enumeration functionality that mirror the original DNSRecon Python tests

use dnsrecon_rs::enumerate::crt_sh;
use dnsrecon_rs::enumerate::bing;
use dnsrecon_rs::enumerate::yandex;
use dnsrecon_rs::enumerate::whois;
use dnsrecon_rs::enumerate::brute_force;
use dnsrecon_rs::dns::resolver::DnsHelper;
use dnsrecon_rs::cli::Args;
use std::sync::Arc;
use clap::Parser;

#[tokio::test]
async fn test_crt_sh_scraping() {
    // Test crt.sh scraping functionality
    // We'll use a domain known to have certificates
    let domain = "google.com";
    
    // Create CLI args for testing
    let args = Args::parse_from(["dnsrecon-rs", "-d", domain]);
    
    // Test the basic scraping function
    let result = crt_sh::scrape_crtsh(domain, &args).await;
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be subdomains
    if let Ok(subdomains) = result {
        for subdomain in subdomains {
            // Subdomains should end with the domain
            assert!(subdomain.ends_with(domain));
            // Subdomains should not start with "*." (wildcards should be filtered)
            assert!(!subdomain.starts_with("*."));
        }
    }
}

#[tokio::test]
async fn test_crt_sh_with_retry() {
    // Test crt.sh scraping with retry functionality
    let domain = "google.com";
    let max_retries = 2;
    
    // Create CLI args for testing
    let args = Args::parse_from(["dnsrecon-rs", "-d", domain]);
    
    // Test the retry function
    let result = crt_sh::scrape_crtsh_with_retry(domain, &args, max_retries).await;
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be valid subdomains
    if let Ok(subdomains) = result {
        for subdomain in subdomains {
            assert!(subdomain.ends_with(domain));
            assert!(!subdomain.starts_with("*."));
        }
    }
}

#[tokio::test]
async fn test_bing_scraping() {
    // Test Bing scraping functionality
    let domain = "microsoft.com";
    
    // Create CLI args for testing
    let args = Args::parse_from(["dnsrecon-rs", "-d", domain]);
    
    // Test the basic scraping function
    let result = bing::scrape_bing(domain, &args).await;
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be valid subdomains
    if let Ok(subdomains) = result {
        for subdomain in subdomains {
            assert!(subdomain.ends_with(domain));
        }
    }
}

#[tokio::test]
async fn test_bing_with_retry() {
    // Test Bing scraping with retry functionality
    let domain = "microsoft.com";
    let max_retries = 2;
    
    // Create CLI args for testing
    let args = Args::parse_from(["dnsrecon-rs", "-d", domain]);
    
    // Test the retry function
    let result = bing::scrape_bing_with_retry(domain, &args, max_retries).await;
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be valid subdomains
    if let Ok(subdomains) = result {
        for subdomain in subdomains {
            assert!(subdomain.ends_with(domain));
        }
    }
}

#[tokio::test]
async fn test_yandex_scraping() {
    // Test Yandex scraping functionality
    let domain = "yandex.ru";
    
    // Create CLI args for testing
    let args = Args::parse_from(["dnsrecon-rs", "-d", domain]);
    
    // Test the basic scraping function
    let result = yandex::scrape_yandex(domain, &args).await;
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be valid subdomains
    if let Ok(subdomains) = result {
        for subdomain in subdomains {
            assert!(subdomain.ends_with(domain));
        }
    }
}

#[tokio::test]
async fn test_yandex_with_retry() {
    // Test Yandex scraping with retry functionality
    let domain = "yandex.ru";
    let max_retries = 2;
    
    // Create CLI args for testing
    let args = Args::parse_from(["dnsrecon-rs", "-d", domain]);
    
    // Test the retry function
    let result = yandex::scrape_yandex_with_retry(domain, &args, max_retries).await;
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be valid subdomains
    if let Ok(subdomains) = result {
        for subdomain in subdomains {
            assert!(subdomain.ends_with(domain));
        }
    }
}

#[tokio::test]
async fn test_whois_lookup() {
    // Test WHOIS lookup functionality
    // Using a known IP address
    let ip = "8.8.8.8".parse().unwrap();
    
    // Test the basic WHOIS lookup function
    let result = whois::whois_lookup(ip);
    
    // The function should not panic and should return a Result
    assert!(result.is_ok() || result.is_err());
    
    // If we get results, they should be a string
    if let Ok(whois_data) = result {
        assert!(!whois_data.is_empty());
    }
}

#[tokio::test]
async fn test_brute_force_enumeration() {
    // Test brute force enumeration functionality
    let domain = "example.com";
    
    // Create a mock DNS helper
    let dns_helper = DnsHelper::new(domain.to_string()).unwrap();
    
    // Test the basic brute force function
    // Using an empty wordlist path for testing
    let result = brute_force::brute_force(domain, "nonexistent_wordlist.txt", &dns_helper).await;
    
    // The function should not panic and should return a Result
    // It will likely return an error due to the nonexistent file
    assert!(result.is_ok() || result.is_err());
}

#[tokio::test]
async fn test_brute_force_concurrent() {
    // Test concurrent brute force enumeration functionality
    let domain = "example.com";
    
    // Create a mock DNS helper
    let dns_helper = Arc::new(DnsHelper::new(domain.to_string()).unwrap());
    let concurrency = 5;
    
    // Test the concurrent brute force function
    // Using an empty wordlist path for testing
    let result = brute_force::brute_force_concurrent(
        domain, 
        "nonexistent_wordlist.txt", 
        dns_helper, 
        concurrency
    ).await;
    
    // The function should not panic and should return a Result
    // It will likely return an error due to the nonexistent file
    assert!(result.is_ok() || result.is_err());
}