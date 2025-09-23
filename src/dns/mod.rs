//! DNS functionality module
//!
//! This module provides DNS enumeration capabilities using the trust-dns crates.

use thiserror::Error;
use trust_dns_resolver::error::ResolveError;
use std::io;
use std::net::AddrParseError;

pub mod resolver;
pub mod record;
pub mod zone_transfer;
pub mod error;

/// DNS-related errors
#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS resolution error: {0}")]
    Resolution(#[from] ResolveError),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Address parsing error: {0}")]
    AddrParse(#[from] AddrParseError),
    
    #[error("Invalid DNS record: {0}")]
    InvalidRecord(String),
    
    #[error("Zone transfer failed: {0}")]
    ZoneTransferFailed(String),
    
    #[error("DNS query timeout")]
    Timeout,
    
    #[error("Other DNS error: {0}")]
    Other(String),
}