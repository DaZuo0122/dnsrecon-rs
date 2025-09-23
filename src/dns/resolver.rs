//! DNS resolver functionality

use crate::dns::{record::DnsRecord, DnsError};
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::proto::rr::{RData, RecordType as TrustDnsRecordType};
use tokio::task;

/// DNS helper struct for performing DNS queries
pub struct DnsHelper {
    config: ResolverConfig,
    options: ResolverOpts,
}

impl DnsHelper {
    /// Create a new DNS helper
    pub fn new(_domain: String) -> Result<Self, DnsError> {
        let config = ResolverConfig::default();
        let options = ResolverOpts::default();
        Ok(Self { config, options })
    }
    
    /// Create a new DNS helper with custom nameservers
    pub fn with_nameservers(_domain: String, nameservers: Vec<IpAddr>) -> Result<Self, DnsError> {
        let mut config = ResolverConfig::new();
        for ns in nameservers {
            config.add_name_server(NameServerConfig {
                socket_addr: (ns, 53).into(),
                protocol: trust_dns_resolver::config::Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }
        
        let options = ResolverOpts::default();
        Ok(Self { config, options })
    }
    
    /// Create a new DNS helper with custom nameservers and ports
    pub fn with_nameservers_and_ports(
        _domain: String,
        nameservers: Vec<IpAddr>,
        _tcp_port: u16,
        _udp_port: u16,
    ) -> Result<Self, DnsError> {
        let mut config = ResolverConfig::new();
        for ns in nameservers {
            config.add_name_server(NameServerConfig {
                socket_addr: SocketAddr::new(ns, 53),
                protocol: trust_dns_resolver::config::Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
            
            config.add_name_server(NameServerConfig {
                socket_addr: SocketAddr::new(ns, 53),
                protocol: trust_dns_resolver::config::Protocol::Tcp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }
        
        let options = ResolverOpts::default();
        Ok(Self { config, options })
    }
    
    /// Resolve A records for a host
    pub fn get_a(&self, host: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let host = host.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.ipv4_lookup(&host)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                records.push(DnsRecord::new_a(host.clone(), **record));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve AAAA records for a host
    pub fn get_aaaa(&self, host: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let host = host.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.ipv6_lookup(&host)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                records.push(DnsRecord::new_aaaa(host.clone(), **record));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve both A and AAAA records
    pub fn get_ip(&self, hostname: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let mut records = Vec::new();
        
        // Try A records
        match self.get_a(hostname) {
            Ok(a_records) => records.extend(a_records),
            Err(e) => {
                // Log error but continue
                tracing::debug!("Failed to get A records for {}: {}", hostname, e);
            }
        }
        
        // Try AAAA records
        match self.get_aaaa(hostname) {
            Ok(aaaa_records) => records.extend(aaaa_records),
            Err(e) => {
                // Log error but continue
                tracing::debug!("Failed to get AAAA records for {}: {}", hostname, e);
            }
        }
        
        Ok(records)
    }
    
    /// Resolve MX records for the domain
    pub fn get_mx(&self, domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let domain = domain.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.mx_lookup(&domain)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                let exchange = record.exchange().to_string();
                // Remove the trailing dot if present
                let exchange = exchange.trim_end_matches('.').to_string();
                records.push(DnsRecord::new_mx(
                    domain.clone(),
                    record.preference(),
                    exchange,
                ));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve NS records for the domain
    pub fn get_ns(&self, domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let domain = domain.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.ns_lookup(&domain)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                let nameserver = record.to_string();
                // Remove the trailing dot if present
                let nameserver = nameserver.trim_end_matches('.').to_string();
                records.push(DnsRecord::new_ns(domain.clone(), nameserver));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve SOA records for the domain
    pub fn get_soa(&self, domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let domain = domain.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.soa_lookup(&domain)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                let mname = record.mname().to_string();
                let mname = mname.trim_end_matches('.').to_string();
                let rname = record.rname().to_string();
                let rname = rname.trim_end_matches('.').to_string();
                
                records.push(DnsRecord::new_soa(
                    domain.clone(),
                    mname,
                    rname,
                    record.serial().try_into().unwrap_or(0),
                    record.refresh().try_into().unwrap_or(0),
                    record.retry().try_into().unwrap_or(0),
                    record.expire().try_into().unwrap_or(0),
                    record.minimum().try_into().unwrap_or(0),
                ));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve TXT records for the domain
    pub fn get_txt(&self, domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let domain = domain.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.txt_lookup(&domain)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                let txt_data = record.txt_data();
                // Join all TXT data parts into a single string
                let data = txt_data
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect::<Vec<_>>()
                    .join("");
                
                records.push(DnsRecord::new_txt(domain.clone(), data));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve SPF records for the domain
    pub fn get_spf(&self, domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
        // SPF records are stored as TXT records with a specific format
        let txt_records = self.get_txt(domain)?;
        let mut spf_records = Vec::new();
        
        for record in txt_records {
            if let DnsRecord {
                record_type: crate::dns::record::RecordType::Txt,
                name,
                data: crate::dns::record::RecordData::Txt(data),
                ..
            } = record {
                if data.starts_with("v=spf1") {
                    spf_records.push(DnsRecord::new_spf(name, data));
                }
            }
        }
        
        Ok(spf_records)
    }
    
    /// Resolve PTR records for an IP address
    pub fn get_ptr(&self, ip: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let ip = ip.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.reverse_lookup(ip.parse()?)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                let target = record.to_string();
                // Remove the trailing dot if present
                let target = target.trim_end_matches('.').to_string();
                records.push(DnsRecord::new_ptr(ip.clone(), target));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve SRV records for a service
    pub fn get_srv(&self, service: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let service = service.to_string();
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.srv_lookup(&service)?;
            let mut records = Vec::new();
            
            for record in response.iter() {
                let target = record.target().to_string();
                // Remove the trailing dot if present
                let target = target.trim_end_matches('.').to_string();
                
                records.push(DnsRecord::new_srv(
                    service.clone(),
                    record.priority(),
                    record.weight(),
                    record.port(),
                    target,
                ));
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
    
    /// Resolve CAA records for the domain
    pub fn get_caa(&self, domain: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let domain = domain.to_string();
        let record_type = TrustDnsRecordType::CAA;
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            // For CAA records, we need to do a raw query since trust-dns doesn't have a direct method
            match resolver.lookup(&domain, record_type) {
                Ok(response) => {
                    let mut records = Vec::new();
                    
                    for record in response.record_iter() {
                        if let Some(RData::CAA(ref caa)) = record.data() {
                            // For now, let's create a simple representation using debug formatting
                            let caa_str = format!("{:?}", caa);
                            
                            records.push(DnsRecord::new_txt(
                                domain.clone(),
                                caa_str,
                            ));
                        }
                    }
                    
                    Ok::<Vec<DnsRecord>, DnsError>(records)
                },
                Err(e) => {
                    // If no CAA records are found, that's not an error - just return empty vec
                    if e.to_string().contains("no record found") {
                        Ok(Vec::new())
                    } else {
                        Err(e.into())
                    }
                }
            }
        })
    }
    
    /// Resolve CNAME records for a host
    pub fn get_cname(&self, host: &str) -> Result<Vec<DnsRecord>, DnsError> {
        let config = self.config.clone();
        let options = self.options.clone();
        let host = host.to_string();
        let record_type = TrustDnsRecordType::CNAME;
        
        task::block_in_place(|| {
            let resolver = Resolver::new(config, options)?;
            let response = resolver.lookup(&host, record_type)?;
            let mut records = Vec::new();
            
            for record in response.record_iter() {
                if let Some(RData::CNAME(ref cname)) = record.data() {
                    let target = cname.to_string();
                    // Remove the trailing dot if present
                    let target = target.trim_end_matches('.').to_string();
                    
                    records.push(DnsRecord::new_cname(host.clone(), target));
                }
            }
            
            Ok::<Vec<DnsRecord>, DnsError>(records)
        })
    }
}