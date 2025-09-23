//! XML output formatting

use crate::dns::record::{DnsRecord, RecordData};
use crate::output::OutputError;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::fs::File;
use std::io::BufWriter;

/// Write DNS records to XML file
pub fn write_xml(results: &[DnsRecord], filename: &str) -> Result<(), OutputError> {
    let file = File::create(filename)?;
    let writer = BufWriter::new(file);
    let mut xml_writer = Writer::new(writer);
    
    // Write XML declaration
    let decl = quick_xml::events::BytesDecl::new("1.0", Some("UTF-8"), None);
    xml_writer.write_event(Event::Decl(decl))?;
    
    // Write root element
    xml_writer.write_event(Event::Start(BytesStart::new("dnsrecon")))?;
    
    // Write each record
    for record in results {
        write_record(&mut xml_writer, record)?;
    }
    
    // Close root element
    xml_writer.write_event(Event::End(BytesEnd::new("dnsrecon")))?;
    
    Ok(())
}

/// Write DNS records to XML string
pub fn to_xml_string(results: &[DnsRecord]) -> Result<String, OutputError> {
    use std::io::Cursor;
    
    let buffer = Vec::new();
    let cursor = Cursor::new(buffer);
    let mut xml_writer = Writer::new(cursor);
    
    // Write XML declaration
    let decl = quick_xml::events::BytesDecl::new("1.0", Some("UTF-8"), None);
    xml_writer.write_event(Event::Decl(decl))?;
    
    // Write root element
    xml_writer.write_event(Event::Start(BytesStart::new("dnsrecon")))?;
    
    // Write each record
    for record in results {
        write_record(&mut xml_writer, record)?;
    }
    
    // Close root element
    xml_writer.write_event(Event::End(BytesEnd::new("dnsrecon")))?;
    
    let result = xml_writer.into_inner().into_inner();
    let xml_string = String::from_utf8(result)?;
    Ok(xml_string)
}

/// Write a single DNS record to XML
fn write_record<W: std::io::Write>(writer: &mut Writer<W>, record: &DnsRecord) -> Result<(), OutputError> {
    let element_name = format!("{:?}", record.record_type).to_lowercase();
    let element = BytesStart::new(&element_name);
    
    writer.write_event(Event::Start(element.clone()))?;
    
    // Write name
    writer.write_event(Event::Start(BytesStart::new("name")))?;
    writer.write_event(Event::Text(BytesText::new(&record.name)))?;
    writer.write_event(Event::End(BytesEnd::new("name")))?;
    
    // Write data based on record type
    match &record.data {
        RecordData::A(ip) => {
            writer.write_event(Event::Start(BytesStart::new("address")))?;
            writer.write_event(Event::Text(BytesText::new(&ip.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("address")))?;
        },
        RecordData::Aaaa(ip) => {
            writer.write_event(Event::Start(BytesStart::new("address")))?;
            writer.write_event(Event::Text(BytesText::new(&ip.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("address")))?;
        },
        RecordData::Mx { preference, exchange } => {
            writer.write_event(Event::Start(BytesStart::new("preference")))?;
            writer.write_event(Event::Text(BytesText::new(&preference.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("preference")))?;
            
            writer.write_event(Event::Start(BytesStart::new("exchange")))?;
            writer.write_event(Event::Text(BytesText::new(exchange)))?;
            writer.write_event(Event::End(BytesEnd::new("exchange")))?;
        },
        RecordData::Ns(nameserver) => {
            writer.write_event(Event::Start(BytesStart::new("nameserver")))?;
            writer.write_event(Event::Text(BytesText::new(nameserver)))?;
            writer.write_event(Event::End(BytesEnd::new("nameserver")))?;
        },
        RecordData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            writer.write_event(Event::Start(BytesStart::new("mname")))?;
            writer.write_event(Event::Text(BytesText::new(mname)))?;
            writer.write_event(Event::End(BytesEnd::new("mname")))?;
            
            writer.write_event(Event::Start(BytesStart::new("rname")))?;
            writer.write_event(Event::Text(BytesText::new(rname)))?;
            writer.write_event(Event::End(BytesEnd::new("rname")))?;
            
            writer.write_event(Event::Start(BytesStart::new("serial")))?;
            writer.write_event(Event::Text(BytesText::new(&serial.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("serial")))?;
            
            writer.write_event(Event::Start(BytesStart::new("refresh")))?;
            writer.write_event(Event::Text(BytesText::new(&refresh.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("refresh")))?;
            
            writer.write_event(Event::Start(BytesStart::new("retry")))?;
            writer.write_event(Event::Text(BytesText::new(&retry.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("retry")))?;
            
            writer.write_event(Event::Start(BytesStart::new("expire")))?;
            writer.write_event(Event::Text(BytesText::new(&expire.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("expire")))?;
            
            writer.write_event(Event::Start(BytesStart::new("minimum")))?;
            writer.write_event(Event::Text(BytesText::new(&minimum.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("minimum")))?;
        },
        RecordData::Txt(data) | RecordData::Spf(data) => {
            writer.write_event(Event::Start(BytesStart::new("data")))?;
            writer.write_event(Event::Text(BytesText::new(data)))?;
            writer.write_event(Event::End(BytesEnd::new("data")))?;
        },
        RecordData::Ptr(target) => {
            writer.write_event(Event::Start(BytesStart::new("target")))?;
            writer.write_event(Event::Text(BytesText::new(target)))?;
            writer.write_event(Event::End(BytesEnd::new("target")))?;
        },
        RecordData::Srv { priority, weight, port, target } => {
            writer.write_event(Event::Start(BytesStart::new("priority")))?;
            writer.write_event(Event::Text(BytesText::new(&priority.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("priority")))?;
            
            writer.write_event(Event::Start(BytesStart::new("weight")))?;
            writer.write_event(Event::Text(BytesText::new(&weight.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("weight")))?;
            
            writer.write_event(Event::Start(BytesStart::new("port")))?;
            writer.write_event(Event::Text(BytesText::new(&port.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("port")))?;
            
            writer.write_event(Event::Start(BytesStart::new("target")))?;
            writer.write_event(Event::Text(BytesText::new(target)))?;
            writer.write_event(Event::End(BytesEnd::new("target")))?;
        },
        RecordData::Caa { flags, tag, value } => {
            writer.write_event(Event::Start(BytesStart::new("flags")))?;
            writer.write_event(Event::Text(BytesText::new(&flags.to_string())))?;
            writer.write_event(Event::End(BytesEnd::new("flags")))?;
            
            writer.write_event(Event::Start(BytesStart::new("tag")))?;
            writer.write_event(Event::Text(BytesText::new(tag)))?;
            writer.write_event(Event::End(BytesEnd::new("tag")))?;
            
            writer.write_event(Event::Start(BytesStart::new("value")))?;
            writer.write_event(Event::Text(BytesText::new(value)))?;
            writer.write_event(Event::End(BytesEnd::new("value")))?;
        },
        RecordData::Cname(target) => {
            writer.write_event(Event::Start(BytesStart::new("target")))?;
            writer.write_event(Event::Text(BytesText::new(target)))?;
            writer.write_event(Event::End(BytesEnd::new("target")))?;
        },
    }
    
    // Write TTL if present
    if let Some(ttl) = record.ttl {
        writer.write_event(Event::Start(BytesStart::new("ttl")))?;
        writer.write_event(Event::Text(BytesText::new(&ttl.to_string())))?;
        writer.write_event(Event::End(BytesEnd::new("ttl")))?;
    }
    
    writer.write_event(Event::End(BytesEnd::new(&element_name)))?;
    
    Ok(())
}