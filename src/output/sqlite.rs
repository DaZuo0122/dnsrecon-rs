//! SQLite output formatting

use crate::dns::record::{DnsRecord, RecordData};
use crate::output::OutputError;
use rusqlite::Connection;
use serde_json::Value;

/// Write DNS records to SQLite database
pub fn write_sqlite(results: &[DnsRecord], filename: &str) -> Result<(), OutputError> {
    let conn = Connection::open(filename)?;
    
    // Create tables if they don't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dns_records (
            id INTEGER PRIMARY KEY,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            ttl INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS record_data (
            id INTEGER PRIMARY KEY,
            record_id INTEGER,
            key TEXT NOT NULL,
            value TEXT,
            FOREIGN KEY(record_id) REFERENCES dns_records(id)
        )",
        [],
    )?;
    
    // Insert records
    let mut record_stmt = conn.prepare(
        "INSERT INTO dns_records (type, name, ttl) VALUES (?1, ?2, ?3)",
    )?;
    
    let mut data_stmt = conn.prepare(
        "INSERT INTO record_data (record_id, key, value) VALUES (?1, ?2, ?3)",
    )?;
    
    for record in results {
        let record_type = format!("{:?}", record.record_type);
        
        // Insert the main record
        let record_id = record_stmt.insert([
            &record_type as &dyn rusqlite::ToSql,
            &record.name,
            &record.ttl.unwrap_or(0) as &dyn rusqlite::ToSql,
        ])?;
        
        // Insert record-specific data
        insert_record_data(&mut data_stmt, record_id, &record.data)?;
    }
    
    Ok(())
}

/// Insert record-specific data into the database
fn insert_record_data(stmt: &mut rusqlite::Statement, record_id: i64, data: &RecordData) -> Result<(), OutputError> {
    match data {
        RecordData::A(ip) => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"address" as &dyn rusqlite::ToSql,
                &ip.to_string() as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Aaaa(ip) => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"address" as &dyn rusqlite::ToSql,
                &ip.to_string() as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Mx { preference, exchange } => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"preference" as &dyn rusqlite::ToSql,
                &preference.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"exchange" as &dyn rusqlite::ToSql,
                exchange as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Ns(nameserver) => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"nameserver" as &dyn rusqlite::ToSql,
                nameserver as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Soa { mname, rname, serial, refresh, retry, expire, minimum } => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"mname" as &dyn rusqlite::ToSql,
                mname as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"rname" as &dyn rusqlite::ToSql,
                rname as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"serial" as &dyn rusqlite::ToSql,
                &serial.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"refresh" as &dyn rusqlite::ToSql,
                &refresh.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"retry" as &dyn rusqlite::ToSql,
                &retry.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"expire" as &dyn rusqlite::ToSql,
                &expire.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"minimum" as &dyn rusqlite::ToSql,
                &minimum.to_string() as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Txt(data) | RecordData::Spf(data) => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"data" as &dyn rusqlite::ToSql,
                data as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Ptr(target) => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"target" as &dyn rusqlite::ToSql,
                target as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Srv { priority, weight, port, target } => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"priority" as &dyn rusqlite::ToSql,
                &priority.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"weight" as &dyn rusqlite::ToSql,
                &weight.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"port" as &dyn rusqlite::ToSql,
                &port.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"target" as &dyn rusqlite::ToSql,
                target as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Caa { flags, tag, value } => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"flags" as &dyn rusqlite::ToSql,
                &flags.to_string() as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"tag" as &dyn rusqlite::ToSql,
                tag as &dyn rusqlite::ToSql,
            ])?;
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"value" as &dyn rusqlite::ToSql,
                value as &dyn rusqlite::ToSql,
            ])?;
        },
        RecordData::Cname(target) => {
            stmt.execute([
                &record_id as &dyn rusqlite::ToSql,
                &"target" as &dyn rusqlite::ToSql,
                target as &dyn rusqlite::ToSql,
            ])?;
        },
    }
    
    Ok(())
}

/// Export DNS records to SQLite and return the database path
pub fn export_to_sqlite(results: &[DnsRecord], filename: &str) -> Result<String, OutputError> {
    write_sqlite(results, filename)?;
    Ok(filename.to_string())
}