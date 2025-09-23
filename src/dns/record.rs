//! DNS record types and structures

use std::net::{Ipv4Addr, Ipv6Addr};
use serde::Serialize;

/// DNS record types supported by DNSRecon
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RecordType {
    A,
    Aaaa,
    Mx,
    Ns,
    Soa,
    Spf,
    Txt,
    Ptr,
    Srv,
    Caa,
    Cname,
    // Add more record types as needed
}

/// Generic DNS record structure
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub name: String,
    pub data: RecordData,
    pub ttl: Option<u32>,
}

/// Data contained in different types of DNS records
#[derive(Debug, Clone, Serialize)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Mx { preference: u16, exchange: String },
    Ns(String),
    Soa { 
        mname: String, 
        rname: String, 
        serial: u32, 
        refresh: u32, 
        retry: u32, 
        expire: u32, 
        minimum: u32 
    },
    Spf(String),
    Txt(String),
    Ptr(String),
    Srv { 
        priority: u16, 
        weight: u16, 
        port: u16, 
        target: String 
    },
    Caa { 
        flags: u8, 
        tag: String, 
        value: String 
    },
    Cname(String),
    // Add more record data types as needed
}

impl DnsRecord {
    /// Create a new A record
    pub fn new_a(name: String, address: Ipv4Addr) -> Self {
        Self {
            record_type: RecordType::A,
            name,
            data: RecordData::A(address),
            ttl: None,
        }
    }
    
    /// Create a new AAAA record
    pub fn new_aaaa(name: String, address: Ipv6Addr) -> Self {
        Self {
            record_type: RecordType::Aaaa,
            name,
            data: RecordData::Aaaa(address),
            ttl: None,
        }
    }
    
    /// Create a new MX record
    pub fn new_mx(name: String, preference: u16, exchange: String) -> Self {
        Self {
            record_type: RecordType::Mx,
            name,
            data: RecordData::Mx { preference, exchange },
            ttl: None,
        }
    }
    
    /// Create a new NS record
    pub fn new_ns(name: String, nameserver: String) -> Self {
        Self {
            record_type: RecordType::Ns,
            name,
            data: RecordData::Ns(nameserver),
            ttl: None,
        }
    }
    
    /// Create a new SOA record
    pub fn new_soa(
        name: String,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self {
            record_type: RecordType::Soa,
            name,
            data: RecordData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
            ttl: None,
        }
    }
    
    /// Create a new TXT record
    pub fn new_txt(name: String, data: String) -> Self {
        Self {
            record_type: RecordType::Txt,
            name,
            data: RecordData::Txt(data),
            ttl: None,
        }
    }
    
    /// Create a new SPF record
    pub fn new_spf(name: String, data: String) -> Self {
        Self {
            record_type: RecordType::Spf,
            name,
            data: RecordData::Spf(data),
            ttl: None,
        }
    }
    
    /// Create a new PTR record
    pub fn new_ptr(name: String, target: String) -> Self {
        Self {
            record_type: RecordType::Ptr,
            name,
            data: RecordData::Ptr(target),
            ttl: None,
        }
    }
    
    /// Create a new SRV record
    pub fn new_srv(name: String, priority: u16, weight: u16, port: u16, target: String) -> Self {
        Self {
            record_type: RecordType::Srv,
            name,
            data: RecordData::Srv {
                priority,
                weight,
                port,
                target,
            },
            ttl: None,
        }
    }
    
    /// Create a new CAA record
    pub fn new_caa(name: String, flags: u8, tag: String, value: String) -> Self {
        Self {
            record_type: RecordType::Caa,
            name,
            data: RecordData::Caa { flags, tag, value },
            ttl: None,
        }
    }
    
    /// Create a new CNAME record
    pub fn new_cname(name: String, target: String) -> Self {
        Self {
            record_type: RecordType::Cname,
            name,
            data: RecordData::Cname(target),
            ttl: None,
        }
    }
}