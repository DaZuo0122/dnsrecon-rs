#[cfg(test)]
mod tests {
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
    }
}