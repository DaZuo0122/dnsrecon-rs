//! Brute force enumeration using wordlists

use crate::dns::resolver::DnsHelper;
use crate::dns::record::DnsRecord;
use crate::enumerate::EnumerationError;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::sync::Semaphore;
use tokio::task;
use std::sync::Arc;

/// Perform brute force enumeration using a wordlist
pub async fn brute_force(
    domain: &str,
    wordlist_path: &str,
    dns_helper: &DnsHelper,
) -> Result<Vec<DnsRecord>, EnumerationError> {
    let mut found_records = Vec::new();
    
    // Open the wordlist file
    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);
    
    // Iterate through each word in the wordlist
    for line in reader.lines() {
        let word = line?;
        // Skip empty lines and comments
        if word.is_empty() || word.starts_with('#') {
            continue;
        }
        
        let subdomain = format!("{}.{}", word, domain);
        
        // Try to resolve the subdomain
        match dns_helper.get_ip(&subdomain) {
            Ok(records) => {
                if !records.is_empty() {
                    found_records.extend(records);
                }
            }
            Err(e) => {
                // Log the error but continue
                tracing::debug!("Failed to resolve {}: {}", subdomain, e);
            }
        }
    }
    
    Ok(found_records)
}

/// Perform brute force enumeration with concurrency
pub async fn brute_force_concurrent(
    domain: &str,
    wordlist_path: &str,
    dns_helper: Arc<DnsHelper>,
    concurrency: usize,
) -> Result<Vec<DnsRecord>, EnumerationError> {
    // Read all words from the wordlist
    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);
    
    let mut words = Vec::new();
    for line in reader.lines() {
        let word = line?;
        // Skip empty lines and comments
        if word.is_empty() || word.starts_with('#') {
            continue;
        }
        words.push(word);
    }
    
    // Create a semaphore to limit concurrency
    let semaphore = Arc::new(Semaphore::new(concurrency));
    
    // Create tasks for each word
    let mut tasks = Vec::new();
    let domain = domain.to_string();
    
    for word in words {
        let dns_helper = dns_helper.clone();
        let domain = domain.clone();
        let semaphore = semaphore.clone();
        
        let task = task::spawn(async move {
            // Acquire a permit from the semaphore
            let _permit = semaphore.acquire().await.unwrap();
            
            let subdomain = format!("{}.{}", word, domain);
            
            // Try to resolve the subdomain
            match dns_helper.get_ip(&subdomain) {
                Ok(records) => {
                    if !records.is_empty() {
                        Some(records)
                    } else {
                        None
                    }
                }
                Err(e) => {
                    // Log the error but continue
                    tracing::debug!("Failed to resolve {}: {}", subdomain, e);
                    None
                }
            }
        });
        
        tasks.push(task);
    }
    
    // Collect results
    let mut found_records = Vec::new();
    for task in tasks {
        if let Ok(Some(records)) = task.await {
            found_records.extend(records);
        }
    }
    
    Ok(found_records)
}

/// Perform brute force enumeration with concurrency (streaming version)
pub async fn brute_force_streaming(
    domain: &str,
    wordlist_path: &str,
    dns_helper: Arc<DnsHelper>,
    concurrency: usize,
) -> Result<Vec<DnsRecord>, EnumerationError> {
    // For now, just call the concurrent version since the streaming version is complex
    brute_force_concurrent(domain, wordlist_path, dns_helper, concurrency).await
}