//! Benchmarks for DNS functionality

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dnsrecon_rs::dns::resolver::DnsHelper;

fn benchmark_dns_resolution(c: &mut Criterion) {
    let dns_helper = DnsHelper::new("example.com".to_string()).unwrap();
    
    c.bench_function("dns_a_record_lookup", |b| {
        b.iter(|| {
            let result = dns_helper.get_ip(black_box("example.com"));
            // We don't assert the result to avoid panics in benchmarks
            let _ = result;
        })
    });
}

fn benchmark_json_output(c: &mut Criterion) {
    use dnsrecon_rs::dns::record::{DnsRecord, RecordType, RecordData};
    use dnsrecon_rs::output::json;
    use std::net::Ipv4Addr;
    
    let record = DnsRecord::new_a(
        "example.com".to_string(),
        Ipv4Addr::new(192, 168, 1, 1)
    );
    
    let records = vec![record; 100]; // Create 100 records for more realistic benchmark
    
    c.bench_function("json_output_formatting", |b| {
        b.iter(|| {
            let result = json::to_json_string(black_box(&records));
            // We don't assert the result to avoid panics in benchmarks
            let _ = result;
        })
    });
}

criterion_group!(benches, benchmark_dns_resolution, benchmark_json_output);
criterion_main!(benches);