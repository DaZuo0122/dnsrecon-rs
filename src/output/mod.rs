//! Output formatting and export module
//!
//! This module provides functionality for formatting and exporting
//! DNS enumeration results in various formats.

use thiserror::Error;
use crate::dns::record::DnsRecord;
use quick_xml::Error as XmlError;
use std::string::FromUtf8Error;

pub mod json;
pub mod xml;
pub mod sqlite;

/// Output-related errors
#[derive(Error, Debug)]
pub enum OutputError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("XML error: {0}")]
    Xml(#[from] XmlError),
    
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] FromUtf8Error),
    
    #[error("Other output error: {0}")]
    Other(String),
}

/// Format results as JSON and write to file
pub fn format_json(results: &[DnsRecord], filename: &str) -> Result<(), OutputError> {
    json::write_json(results, filename)
}

/// Format results as XML and write to file
pub fn format_xml(results: &[DnsRecord], filename: &str) -> Result<(), OutputError> {
    xml::write_xml(results, filename)
}

/// Export results to SQLite database
pub fn export_sqlite(results: &[DnsRecord], filename: &str) -> Result<(), OutputError> {
    sqlite::write_sqlite(results, filename)
}