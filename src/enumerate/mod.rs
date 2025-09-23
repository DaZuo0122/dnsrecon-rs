//! Enumeration techniques module
//!
//! This module provides various enumeration techniques such as
//! certificate transparency log scraping, search engine enumeration, etc.

use thiserror::Error;
use std::io;

pub mod crt_sh;
pub mod bing;
pub mod yandex;
pub mod whois;
pub mod brute_force;

/// Enumeration-related errors
#[derive(Error, Debug)]
pub enum EnumerationError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    
    #[error("Parse error: {0}")]
    Parse(String),
    
    #[error("Timeout error")]
    Timeout,
    
    #[error("Other enumeration error: {0}")]
    Other(String),
}