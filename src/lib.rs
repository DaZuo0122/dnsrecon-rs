//! DNSRecon-rs - A high-performance DNS enumeration tool written in Rust
//!
//! This crate provides DNS enumeration capabilities similar to the original
//! DNSRecon Python tool, with improved performance through Rust's async/await
//! and concurrent operations.

pub mod cli;
pub mod dns;
pub mod enumerate;
pub mod output;
pub mod utils;

use std::path::PathBuf;

use thiserror::Error;
use std::sync::Arc;
use std::net::IpAddr;
use std::collections::HashSet;
use crate::cli::progress::ProgressReporter;

/// Main error type for the application
#[derive(Error, Debug)]
pub enum DnsReconError {
    #[error("DNS error: {0}")]
    Dns(#[from] dns::DnsError),
    
    #[error("Enumeration error: {0}")]
    Enumeration(#[from] enumerate::EnumerationError),
    
    #[error("Output error: {0}")]
    Output(#[from] output::OutputError),
    
    #[error("CLI error: {0}")]
    Cli(#[from] cli::CliError),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Other error: {0}")]
    Other(String),
}

/// Main application entry point
///
/// This function orchestrates the DNS enumeration process based on the provided arguments.
pub async fn run(args: cli::Args) -> Result<(), DnsReconError> {
    // Validate arguments
    cli::validate_args(&args)?;
    
    // Initialize progress reporter
    let progress = cli::progress::TimedProgressReporter::new();
    progress.update("Starting DNS enumeration");
    
    // Initialize results vector
    let mut all_results = Vec::new();
    
    // Set up DNS resolver
    progress.update("Setting up DNS resolver");
    let dns_helper = if let Some(ref nameservers) = args.nameservers {
        let ns_ips: Result<Vec<IpAddr>, _> = nameservers
            .split(',')
            .map(|ns| ns.trim().parse())
            .collect();
        let ns_ips = ns_ips.map_err(|e| DnsReconError::Other(format!("Invalid nameserver: {}", e)))?;
        dns::resolver::DnsHelper::with_nameservers(
            args.domain.clone().unwrap_or_default(),
            ns_ips
        )?
    } else {
        dns::resolver::DnsHelper::new(args.domain.clone().unwrap_or_default())?
    };
    
    let dns_helper = Arc::new(dns_helper);
    
    // Execute requested enumeration techniques based on type
    match args.r#type {
        cli::EnumType::Standard => {
            if let Some(ref domain) = args.domain {
                progress.update(&format!("Performing standard enumeration for domain: {}", domain));
                all_results.extend(perform_standard_enumeration(dns_helper.clone(), domain, &progress).await?);
            }
        },
        cli::EnumType::BruteForce => {
            if let Some(ref domain) = args.domain {
                let wordlist = args.dict.as_ref().map(|s| s.as_str()).unwrap_or("data/subdomains-top1mil-5000.txt");
                // Resolve the wordlist path correctly
                let resolved_wordlist = resolve_wordlist_path(wordlist)?;
                progress.update(&format!("Performing brute force enumeration for domain: {} with wordlist: {}", domain, resolved_wordlist));
                all_results.extend(
                    enumerate::brute_force::brute_force_concurrent(
                        domain,
                        &resolved_wordlist,
                        dns_helper.clone(),
                        args.concurrency
                    ).await?
                );
            }
        },
        cli::EnumType::ZoneWalk => {
            if let Some(ref domain) = args.domain {
                progress.update(&format!("Performing zone walk for domain: {}", domain));
                all_results.extend(perform_zone_walk(dns_helper.clone(), domain, &progress).await?);
            }
        },
        cli::EnumType::Reverse => {
            if let Some(ref range) = args.range {
                progress.update(&format!("Performing reverse lookup for range: {}", range));
                all_results.extend(perform_reverse_lookup(range, &progress).await?);
            }
        },
    }
    
    progress.update(&format!("Enumeration completed. Found {} records", all_results.len()));
    
    // Deduplicate results by name (case-insensitive)
    let all_results = deduplicate_records(all_results);
    
    // Output results
    if let Some(ref json_file) = args.json_file {
        progress.update(&format!("Writing results to JSON file: {}", json_file));
        output::format_json(&all_results, json_file)?;
    }
    
    if let Some(ref xml_file) = args.xml_file {
        progress.update(&format!("Writing results to XML file: {}", xml_file));
        output::format_xml(&all_results, xml_file)?;
    }
    
    if let Some(ref sqlite_file) = args.sqlite_file {
        progress.update(&format!("Writing results to SQLite database: {}", sqlite_file));
        output::export_sqlite(&all_results, sqlite_file)?;
    }
    
    // If no output files specified, print to stdout
    if args.json_file.is_none() && args.xml_file.is_none() && args.sqlite_file.is_none() {
        progress.update("Writing results to stdout");
        let json_output = output::json::to_json_string(&all_results)?;
        println!("{}", json_output);
    }
    
    progress.finish(&format!("DNS enumeration completed successfully in {:.2}s", progress.elapsed().as_secs_f32()));
    
    Ok(())
}

/// Deduplicate DNS records by name (case-insensitive)
fn deduplicate_records(records: Vec<dns::record::DnsRecord>) -> Vec<dns::record::DnsRecord> {
    let mut seen_names = HashSet::new();
    let mut deduplicated = Vec::new();
    
    for record in records {
        // Convert name to lowercase for case-insensitive comparison
        let name_lower = record.name.to_lowercase();
        
        // Only add if we haven't seen this name before
        if seen_names.insert(name_lower) {
            deduplicated.push(record);
        }
    }
    
    deduplicated
}

/// Resolve the wordlist path, handling both absolute paths and paths relative to the executable
fn resolve_wordlist_path(wordlist_path: &str) -> Result<String, DnsReconError> {
    // If it's already an absolute path, return as is
    let path = PathBuf::from(wordlist_path);
    if path.is_absolute() {
        return Ok(wordlist_path.to_string());
    }
    
    // Try to get the executable path
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            // Construct path relative to executable directory
            let data_path = parent.join(wordlist_path);
            if data_path.exists() {
                return Ok(data_path.to_string_lossy().to_string());
            }
            
            // Try one level up (in case executable is in a bin directory)
            let data_path = parent.parent().unwrap_or(parent).join(wordlist_path);
            if data_path.exists() {
                return Ok(data_path.to_string_lossy().to_string());
            }
        }
    }
    
    // Fall back to current behavior (relative to current working directory)
    Ok(wordlist_path.to_string())
}

/// Perform standard enumeration techniques
async fn perform_standard_enumeration(
    dns_helper: Arc<dns::resolver::DnsHelper>,
    domain: &str,
    progress: &cli::progress::TimedProgressReporter,
) -> Result<Vec<dns::record::DnsRecord>, DnsReconError> {
    let mut results = Vec::new();
    
    progress.update("Getting A/AAAA records");
    results.extend(dns_helper.get_ip(domain)?);
    
    progress.update("Getting MX records");
    results.extend(dns_helper.get_mx(domain)?);
    
    progress.update("Getting NS records");
    results.extend(dns_helper.get_ns(domain)?);
    
    progress.update("Getting SOA records");
    results.extend(dns_helper.get_soa(domain)?);
    
    progress.update("Getting TXT records");
    results.extend(dns_helper.get_txt(domain)?);
    
    progress.update("Getting SPF records");
    results.extend(dns_helper.get_spf(domain)?);
    
    progress.update("Getting CAA records");
    match dns_helper.get_caa(domain) {
        Ok(caa_records) => results.extend(caa_records),
        Err(e) => {
            // Log error but continue - CAA records might not exist
            progress.error(&format!("Failed to get CAA records: {}", e));
        }
    }
    
    progress.update("Performing crt.sh enumeration");
    // Perform crt.sh enumeration
    match enumerate::crt_sh::scrape_crtsh_with_retry(domain, 3).await {
        Ok(subdomains) => {
            progress.update(&format!("Found {} subdomains from crt.sh, resolving...", subdomains.len()));
            for subdomain in subdomains {
                results.extend(dns_helper.get_ip(&subdomain)?);
            }
        },
        Err(e) => {
            progress.error(&format!("Failed to scrape crt.sh: {}", e));
        }
    }
    
    progress.update("Performing Bing enumeration");
    // Perform Bing enumeration
    match enumerate::bing::scrape_bing_with_retry(domain, 3).await {
        Ok(subdomains) => {
            progress.update(&format!("Found {} subdomains from Bing, resolving...", subdomains.len()));
            for subdomain in subdomains {
                results.extend(dns_helper.get_ip(&subdomain)?);
            }
        },
        Err(e) => {
            progress.error(&format!("Failed to scrape Bing: {}", e));
        }
    }
    
    progress.update("Performing Yandex enumeration");
    // Perform Yandex enumeration
    match enumerate::yandex::scrape_yandex_with_retry(domain, 3).await {
        Ok(subdomains) => {
            progress.update(&format!("Found {} subdomains from Yandex, resolving...", subdomains.len()));
            for subdomain in subdomains {
                results.extend(dns_helper.get_ip(&subdomain)?);
            }
        },
        Err(e) => {
            progress.error(&format!("Failed to scrape Yandex: {}", e));
        }
    }
    
    Ok(results)
}

/// Perform zone walk enumeration
async fn perform_zone_walk(
    dns_helper: Arc<dns::resolver::DnsHelper>,
    domain: &str,
    progress: &cli::progress::TimedProgressReporter,
) -> Result<Vec<dns::record::DnsRecord>, DnsReconError> {
    progress.update("Getting NS records for zone walk");
    // First get NS records to know which servers to query
    let ns_records = dns_helper.get_ns(domain)?;
    
    let mut results = Vec::new();
    results.extend(ns_records);
    
    // Collect nameservers to avoid borrowing issues
    let nameservers: Vec<String> = results.iter()
        .filter_map(|record| {
            if let dns::record::RecordData::Ns(ref nameserver) = record.data {
                Some(nameserver.clone())
            } else {
                None
            }
        })
        .collect();
    
    // For each nameserver, attempt zone transfer
    for nameserver in nameservers {
        progress.update(&format!("Attempting zone transfer from {}", nameserver));
        match dns::zone_transfer::zone_transfer(domain, &nameserver) {
            Ok(zone_records) => {
                progress.update(&format!("Zone transfer from {} successful, found {} records", nameserver, zone_records.len()));
                results.extend(zone_records);
            },
            Err(e) => {
                progress.error(&format!("Zone transfer failed for {}: {}", nameserver, e));
            }
        }
    }
    
    Ok(results)
}

/// Perform reverse lookup enumeration
async fn perform_reverse_lookup(
    range: &str,
    progress: &cli::progress::TimedProgressReporter,
) -> Result<Vec<dns::record::DnsRecord>, DnsReconError> {
    progress.update(&format!("Processing IP range: {}", range));
    
    // Parse the range and perform reverse lookups
    let ips = utils::cidr::process_range(range)
        .map_err(|e| DnsReconError::Other(format!("Failed to process range: {}", e)))?;
    
    progress.update(&format!("Performing reverse lookups for {} IP addresses", ips.len()));
    
    let mut results = Vec::new();
    let mut resolved_count = 0;
    
    for (i, ip) in ips.iter().enumerate() {
        // Show progress every 100 IPs
        if i % 100 == 0 {
            progress.update(&format!("Processed {}/{} IP addresses, found {} PTR records", i, ips.len(), resolved_count));
        }
        
        // Create a temporary DNS helper for reverse lookups
        let dns_helper = dns::resolver::DnsHelper::new("".to_string())?;
        
        match dns_helper.get_ptr(&ip.to_string()) {
            Ok(ptr_records) => {
                resolved_count += ptr_records.len();
                results.extend(ptr_records);
            },
            Err(e) => {
                tracing::debug!("Failed to get PTR record for {}: {}", ip, e);
            }
        }
    }
    
    progress.update(&format!("Completed reverse lookup for {} IP addresses, found {} PTR records", ips.len(), resolved_count));
    
    Ok(results)
}