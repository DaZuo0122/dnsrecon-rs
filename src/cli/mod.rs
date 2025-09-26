//! Command Line Interface module
//!
//! This module handles command line argument parsing and validation.

use clap::Parser;
use thiserror::Error;

pub mod progress;

/// CLI-related errors
#[derive(Error, Debug)]
pub enum CliError {
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    
    #[error("Argument parsing error: {0}")]
    ParseError(String),
    
    #[error(transparent)]
    Clap(#[from] clap::Error),
}

/// Parse command line arguments
pub fn parse_args() -> Result<Args, CliError> {
    match Args::try_parse() {
        Ok(args) => Ok(args),
        Err(e) => {
            // Handle help and version requests by letting Clap display them and exit
            match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    let _ = e.print();  // Print help/version, ignore potential error
                    std::process::exit(0);
                }
                _ => Err(CliError::Clap(e)),
            }
        }
    }
}

/// Main arguments structure
#[derive(Parser, Debug)]
#[command(
    version = "0.1.0",
    about = "DNS Enumeration Tool - Rust Implementation",
)]
pub struct Args {
    /// Domain to enumerate
    #[arg(short, long)]
    pub domain: Option<String>,
    
    /// Type of enumeration to perform
	/// Available types: std, brt, zonewalk, reverse
    #[arg(short, long, value_parser = parse_enum_type, default_value = "std")]
    pub r#type: EnumType,
    
    /// Output results to JSON file
    #[arg(short = 'j', long)]
    pub json_file: Option<String>,
    
    /// Output results to XML file
    #[arg(short = 'x', long)]
    pub xml_file: Option<String>,
    
    /// Output results to SQLite database
    #[arg(short = 's', long)]
    pub sqlite_file: Option<String>,
    
    /// Wordlist for brute force enumeration (default: data/subdomains-top1mil-5000.txt)
    #[arg(short = 'D', long)]
    pub dict: Option<String>,
    
    /// Be verbose
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    
    /// Number of concurrent threads
    #[arg(short = 'c', long, default_value = "10")]
    pub concurrency: usize,
    
    /// Nameservers to use for DNS queries
    #[arg(short = 'n', long)]
    pub nameservers: Option<String>,
    
    /// TCP port to use for DNS queries
    #[arg(long, default_value = "53")]
    pub tcp_port: u16,
    
    /// UDP port to use for DNS queries
    #[arg(long, default_value = "53")]
    pub udp_port: u16,
    
    /// Perform a reverse lookup of a given CIDR or IP range
    #[arg(short = 'r', long)]
    pub range: Option<String>,
    
    /// Perform a reverse lookup of a given CIDR or IP range from a file
    #[arg(short = 'R', long)]
    pub range_file: Option<String>,
    
    /// HTTP proxy to use for requests (format: http://proxy:port or socks5://proxy:port)
    #[arg(long)]
    pub proxy: Option<String>,
}

/// Types of enumeration that can be performed
#[derive(Debug, Clone, PartialEq)]
pub enum EnumType {
    /// Standard enumeration
    Standard,
    /// Brute force enumeration
    BruteForce,
    /// Zone walk enumeration
    ZoneWalk,
    /// Reverse DNS lookup
    Reverse,
}

/// Parse enumeration type from string
fn parse_enum_type(s: &str) -> Result<EnumType, String> {
    match s.to_lowercase().as_str() {
        "std" | "standard" => Ok(EnumType::Standard),
        "brt" | "bruteforce" => Ok(EnumType::BruteForce),
        "zonewalk" => Ok(EnumType::ZoneWalk),
        "reverse" => Ok(EnumType::Reverse),
        _ => Err(format!("Invalid enumeration type: {}", s)),
    }
}

/// Validate command line arguments
pub fn validate_args(args: &Args) -> Result<(), CliError> {
    // Validate domain is provided for most enumeration types
    match args.r#type {
        EnumType::Standard | EnumType::BruteForce | EnumType::ZoneWalk => {
            if args.domain.is_none() && args.range.is_none() && args.range_file.is_none() {
                return Err(CliError::InvalidArgument(
                    "Domain, range, or range file must be specified for this enumeration type".to_string()
                ));
            }
        },
        EnumType::Reverse => {
            if args.range.is_none() && args.range_file.is_none() {
                return Err(CliError::InvalidArgument(
                    "Range or range file must be specified for reverse enumeration".to_string()
                ));
            }
        }
    }
    
    // Validate wordlist is provided for brute force
    if let EnumType::BruteForce = args.r#type {
        if args.dict.is_none() {
            // Use default wordlist if none provided
            // Default to subdomains-top1mil-5000.txt for a balance of speed and coverage
            eprintln!("No wordlist specified, using default: data/subdomains-top1mil-5000.txt");
        }
    }
    
    // Validate port numbers
    if args.tcp_port == 0 || args.udp_port == 0 {
        return Err(CliError::InvalidArgument(
            "Port numbers must be between 1 and 65535".to_string()
        ));
    }
    
    // Validate nameservers if provided
    if let Some(ref nameservers) = args.nameservers {
        for ns in nameservers.split(',') {
            if ns.trim().parse::<std::net::IpAddr>().is_err() {
                return Err(CliError::InvalidArgument(
                    format!("Invalid nameserver IP address: {}", ns)
                ));
            }
        }
    }
    
    Ok(())
}