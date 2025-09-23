//! Zone transfer functionality

use crate::dns::{record::DnsRecord, DnsError};
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::tcp::TcpClientConnection;
use trust_dns_client::rr::{Name, RecordType, RData};
use std::net::SocketAddr;

/// Attempt zone transfer from a nameserver
pub fn zone_transfer(domain: &str, nameserver: &str) -> Result<Vec<DnsRecord>, DnsError> {
    // Parse the domain name
    let name = Name::from_ascii(domain)
        .map_err(|e| DnsError::InvalidRecord(format!("Invalid domain name: {}", e)))?;
    
    // Parse the nameserver address
    let ns_addr: SocketAddr = format!("{}:53", nameserver)
        .parse()
        .map_err(|e| DnsError::InvalidRecord(format!("Invalid nameserver address: {}", e)))?;
    
    // Create a TCP connection to the nameserver
    let conn = TcpClientConnection::new(ns_addr)
        .map_err(|e| DnsError::ZoneTransferFailed(format!("Failed to connect to nameserver: {}", e)))?;
    
    // Create a client
    let client = SyncClient::new(conn);
    
    // Perform the AXFR query
    let response = client.query(&name, trust_dns_client::rr::DNSClass::IN, RecordType::AXFR)
        .map_err(|e| DnsError::ZoneTransferFailed(format!("AXFR query failed: {}", e)))?;
    
    // Parse the response and convert to our format
    let mut records = Vec::new();
    
    for record in response.answers() {
        // Convert each record to our internal format
        if let Ok(dns_record) = convert_record(record, domain) {
            records.push(dns_record);
        }
    }
    
    Ok(records)
}

/// Convert a trust-dns record to our internal format
fn convert_record(record: &trust_dns_client::rr::Record, domain: &str) -> Result<DnsRecord, DnsError> {
    let name = record.name().to_string();
    let name = name.trim_end_matches('.').to_string();
    
    match record.record_type() {
        RecordType::A => {
            if let Some(RData::A(ref ipv4)) = record.data() {
                return Ok(DnsRecord::new_a(name, **ipv4));
            }
            Err(DnsError::InvalidRecord("Invalid A record".to_string()))
        },
        RecordType::AAAA => {
            if let Some(RData::AAAA(ref ipv6)) = record.data() {
                return Ok(DnsRecord::new_aaaa(name, **ipv6));
            }
            Err(DnsError::InvalidRecord("Invalid AAAA record".to_string()))
        },
        RecordType::MX => {
            if let Some(RData::MX(ref mx_data)) = record.data() {
                let exchange = mx_data.exchange().to_string();
                let exchange = exchange.trim_end_matches('.').to_string();
                return Ok(DnsRecord::new_mx(name, mx_data.preference(), exchange));
            }
            Err(DnsError::InvalidRecord("Invalid MX record".to_string()))
        },
        RecordType::NS => {
            if let Some(RData::NS(ref ns_data)) = record.data() {
                let nameserver = ns_data.to_string();
                let nameserver = nameserver.trim_end_matches('.').to_string();
                return Ok(DnsRecord::new_ns(name, nameserver));
            }
            Err(DnsError::InvalidRecord("Invalid NS record".to_string()))
        },
        RecordType::TXT => {
            if let Some(RData::TXT(ref txt_data)) = record.data() {
                let data = txt_data.txt_data()
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect::<Vec<_>>()
                    .join("");
                return Ok(DnsRecord::new_txt(name, data));
            }
            Err(DnsError::InvalidRecord("Invalid TXT record".to_string()))
        },
        RecordType::PTR => {
            if let Some(RData::PTR(ref ptr_data)) = record.data() {
                let target = ptr_data.to_string();
                let target = target.trim_end_matches('.').to_string();
                return Ok(DnsRecord::new_ptr(name, target));
            }
            Err(DnsError::InvalidRecord("Invalid PTR record".to_string()))
        },
        RecordType::CNAME => {
            if let Some(RData::CNAME(ref cname_data)) = record.data() {
                let target = cname_data.to_string();
                let target = target.trim_end_matches('.').to_string();
                return Ok(DnsRecord::new_cname(name, target));
            }
            Err(DnsError::InvalidRecord("Invalid CNAME record".to_string()))
        },
        RecordType::SOA => {
            if let Some(RData::SOA(ref soa_data)) = record.data() {
                let mname = soa_data.mname().to_string();
                let mname = mname.trim_end_matches('.').to_string();
                let rname = soa_data.rname().to_string();
                let rname = rname.trim_end_matches('.').to_string();
                
                return Ok(DnsRecord::new_soa(
                    name,
                    mname,
                    rname,
                    soa_data.serial(),
                    soa_data.refresh().try_into().unwrap_or(0),
                    soa_data.retry().try_into().unwrap_or(0),
                    soa_data.expire().try_into().unwrap_or(0),
                    soa_data.minimum().try_into().unwrap_or(0),
                ));
            }
            Err(DnsError::InvalidRecord("Invalid SOA record".to_string()))
        },
        _ => {
            // For other record types, we'll create a generic record with string data
            if let Some(ref rdata) = record.data() {
                let data = format!("{:?}", rdata);
                // This is a simplified approach - in a real implementation, we'd handle each type specifically
                Ok(DnsRecord::new_txt(name, data))
            } else {
                Err(DnsError::InvalidRecord("Record has no data".to_string()))
            }
        }
    }
}