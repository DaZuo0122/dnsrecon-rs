//! JSON output formatting

use crate::dns::record::DnsRecord;
use crate::output::OutputError;
use serde::Serialize;
use std::fs::File;
use std::io::BufWriter;

/// Serialize DNS records to JSON and write to file
pub fn write_json(results: &[DnsRecord], filename: &str) -> Result<(), OutputError> {
    let file = File::create(filename)?;
    let writer = BufWriter::new(file);
    
    serde_json::to_writer_pretty(writer, results)?;
    
    Ok(())
}

/// Write DNS records to JSON string
pub fn to_json_string(results: &[DnsRecord]) -> Result<String, OutputError> {
    let json = serde_json::to_string_pretty(results)?;
    Ok(json)
}