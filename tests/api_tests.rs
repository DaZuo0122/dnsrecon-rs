//! Unit tests for API functionality

use dnsrecon_rs::dns::record::{DnsRecord, RecordType, RecordData};
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_dns_record_creation() {
    // Test A record creation
    let a_record = DnsRecord::new_a(
        "example.com".to_string(),
        Ipv4Addr::new(192, 168, 1, 1)
    );
    
    assert_eq!(a_record.record_type, RecordType::A);
    assert_eq!(a_record.name, "example.com");
    
    match a_record.data {
        RecordData::A(ip) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1)),
        _ => panic!("Expected A record data"),
    }
    
    // Test AAAA record creation
    let aaaa_record = DnsRecord::new_aaaa(
        "example.com".to_string(),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
    );
    
    assert_eq!(aaaa_record.record_type, RecordType::Aaaa);
    assert_eq!(aaaa_record.name, "example.com");
    
    match aaaa_record.data {
        RecordData::Aaaa(ip) => assert_eq!(ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        _ => panic!("Expected AAAA record data"),
    }
    
    // Test MX record creation
    let mx_record = DnsRecord::new_mx(
        "example.com".to_string(),
        10,
        "mail.example.com".to_string()
    );
    
    assert_eq!(mx_record.record_type, RecordType::Mx);
    assert_eq!(mx_record.name, "example.com");
    
    match mx_record.data {
        RecordData::Mx { preference, exchange } => {
            assert_eq!(preference, 10);
            assert_eq!(exchange, "mail.example.com");
        },
        _ => panic!("Expected MX record data"),
    }
    
    // Test NS record creation
    let ns_record = DnsRecord::new_ns(
        "example.com".to_string(),
        "ns1.example.com".to_string()
    );
    
    assert_eq!(ns_record.record_type, RecordType::Ns);
    assert_eq!(ns_record.name, "example.com");
    
    match ns_record.data {
        RecordData::Ns(nameserver) => {
            assert_eq!(nameserver, "ns1.example.com");
        },
        _ => panic!("Expected NS record data"),
    }
    
    // Test SOA record creation
    let soa_record = DnsRecord::new_soa(
        "example.com".to_string(),
        "ns1.example.com".to_string(),
        "admin.example.com".to_string(),
        2023010101,
        3600,
        1800,
        604800,
        86400,
    );
    
    assert_eq!(soa_record.record_type, RecordType::Soa);
    assert_eq!(soa_record.name, "example.com");
    
    match soa_record.data {
        RecordData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            assert_eq!(mname, "ns1.example.com");
            assert_eq!(rname, "admin.example.com");
            assert_eq!(serial, 2023010101);
            assert_eq!(refresh, 3600);
            assert_eq!(retry, 1800);
            assert_eq!(expire, 604800);
            assert_eq!(minimum, 86400);
        },
        _ => panic!("Expected SOA record data"),
    }
    
    // Test TXT record creation
    let txt_record = DnsRecord::new_txt(
        "example.com".to_string(),
        "v=spf1 include:_spf.example.com ~all".to_string()
    );
    
    assert_eq!(txt_record.record_type, RecordType::Txt);
    assert_eq!(txt_record.name, "example.com");
    
    match txt_record.data {
        RecordData::Txt(data) => {
            assert_eq!(data, "v=spf1 include:_spf.example.com ~all");
        },
        _ => panic!("Expected TXT record data"),
    }
    
    // Test PTR record creation
    let ptr_record = DnsRecord::new_ptr(
        "192.168.1.1".to_string(),
        "host.example.com".to_string()
    );
    
    assert_eq!(ptr_record.record_type, RecordType::Ptr);
    assert_eq!(ptr_record.name, "192.168.1.1");
    
    match ptr_record.data {
        RecordData::Ptr(target) => {
            assert_eq!(target, "host.example.com");
        },
        _ => panic!("Expected PTR record data"),
    }
    
    // Test SRV record creation
    let srv_record = DnsRecord::new_srv(
        "_sip._tcp.example.com".to_string(),
        10,
        60,
        5060,
        "sipserver.example.com".to_string()
    );
    
    assert_eq!(srv_record.record_type, RecordType::Srv);
    assert_eq!(srv_record.name, "_sip._tcp.example.com");
    
    match srv_record.data {
        RecordData::Srv { priority, weight, port, target } => {
            assert_eq!(priority, 10);
            assert_eq!(weight, 60);
            assert_eq!(port, 5060);
            assert_eq!(target, "sipserver.example.com");
        },
        _ => panic!("Expected SRV record data"),
    }
    
    // Test CNAME record creation
    let cname_record = DnsRecord::new_cname(
        "www.example.com".to_string(),
        "example.com".to_string()
    );
    
    assert_eq!(cname_record.record_type, RecordType::Cname);
    assert_eq!(cname_record.name, "www.example.com");
    
    match cname_record.data {
        RecordData::Cname(target) => {
            assert_eq!(target, "example.com");
        },
        _ => panic!("Expected CNAME record data"),
    }
}

#[test]
fn test_json_serialization() {
    // Test that DNS records can be serialized to JSON
    let a_record = DnsRecord::new_a(
        "example.com".to_string(),
        Ipv4Addr::new(192, 168, 1, 1)
    );
    
    let records = vec![a_record];
    let json = serde_json::to_string(&records);
    assert!(json.is_ok());
    
    let json = json.unwrap();
    println!("JSON output: {}", json); // For debugging
    assert!(json.contains("\"type\":\"A\""));
    assert!(json.contains("\"name\":\"example.com\""));
    // For A records, the IP address is nested in the "data" field
    assert!(json.contains("\"data\":{\"A\":\"192.168.1.1\"}"));
}

#[test]
fn test_unique_function() {
    // Test the unique function for removing duplicates
    let vec = vec![1, 2, 2, 3, 3, 3, 4];
    let unique_vec = dnsrecon_rs::utils::unique(vec);
    assert_eq!(unique_vec, vec![1, 2, 3, 4]);
}