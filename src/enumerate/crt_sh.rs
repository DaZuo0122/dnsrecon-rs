//! Certificate Transparency log scraping from crt.sh

use crate::enumerate::EnumerationError;
use crate::utils::http::create_http_client;
use crate::cli::Args;
use scraper::{Html, Selector};
use tokio::time::{sleep, Duration};

/// Scrape crt.sh for subdomains of a domain
pub async fn scrape_crtsh(domain: &str, args: &Args) -> Result<Vec<String>, EnumerationError> {
    let url = format!("https://crt.sh/?q=%.{}", domain);
    
    // Create HTTP client with appropriate settings
    let client = create_http_client(
        args,
        "Mozilla/5.0 (compatible; DNSRecon-rs/0.1; +https://github.com/example/dnsrecon-rs)"
    )?;
    
    // Send request
    let response = client.get(&url).send().await?;
    let body = response.text().await?;
    
    // Parse HTML
    let document = Html::parse_document(&body);
    let selector = Selector::parse("table tr td table tr td:nth-child(5)").map_err(|_| 
        EnumerationError::Parse("Failed to parse CSS selector".to_string())
    )?;
    
    let mut subdomains = Vec::new();
    
    for element in document.select(&selector) {
        if let Some(text) = element.text().next() {
            let subdomain = text.trim();
            // Filter for valid subdomains
            if subdomain.ends_with(domain) && !subdomain.starts_with("*.") {
                subdomains.push(subdomain.to_string());
            }
        }
    }
    
    // Remove duplicates
    subdomains.sort();
    subdomains.dedup();
    
    Ok(subdomains)
}

/// Scrape crt.sh with retry logic for subdomains of a domain
pub async fn scrape_crtsh_with_retry(domain: &str, args: &Args, max_retries: u32) -> Result<Vec<String>, EnumerationError> {
    let mut retries = 0;
    
    loop {
        match scrape_crtsh(domain, args).await {
            Ok(subdomains) => return Ok(subdomains),
            Err(e) => {
                if retries >= max_retries {
                    return Err(e);
                }
                
                retries += 1;
                tracing::warn!("crt.sh request failed (attempt {}/{}): {}", retries, max_retries + 1, e);
                
                // Exponential backoff
                let delay = Duration::from_secs(2u64.pow(retries));
                sleep(delay).await;
            }
        }
    }
}