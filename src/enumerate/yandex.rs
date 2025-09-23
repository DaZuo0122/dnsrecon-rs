//! Yandex search enumeration

use crate::enumerate::EnumerationError;
use reqwest;
use scraper::{Html, Selector};
use tokio::time::{sleep, Duration};
use url::Url;

/// Scrape Yandex for subdomains of a domain
pub async fn scrape_yandex(domain: &str) -> Result<Vec<String>, EnumerationError> {
    let mut subdomains = Vec::new();
    
    // Create HTTP client with reasonable settings
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)")
        .build()?;
    
    // Perform multiple searches with pagination
    for i in 0..10 {
        let url = format!(
            "https://yandex.com/search/?text=site:{}&p={}",
            domain, i
        );
        
        // Send request
        let response = client.get(&url).send().await?;
        
        // Check if we got a successful response
        if !response.status().is_success() {
            tracing::warn!("Yandex returned status {}: {}", response.status(), url);
            // Continue with next iteration instead of failing completely
            sleep(Duration::from_secs(1)).await;
            continue;
        }
            
        let body = response.text().await?;
        
        // Parse HTML
        let document = Html::parse_document(&body);
        // Try multiple selectors to be more robust
        let selectors = vec![
            "a[href^='http']",
            ".Link",
            ".link",
            ".serp-item__link",
        ];
        
        let mut found_elements = false;
        for selector_str in selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for element in document.select(&selector) {
                    found_elements = true;
                    if let Some(href) = element.value().attr("href") {
                        // Extract subdomain from URL
                        if let Some(subdomain) = extract_subdomain_from_url(href, domain) {
                            subdomains.push(subdomain);
                        }
                    }
                }
                // If we found elements with this selector, break
                if found_elements {
                    break;
                }
            }
        }
        
        // Be respectful with rate limiting
        sleep(Duration::from_secs(1)).await;
    }
    
    // Remove duplicates
    subdomains.sort();
    subdomains.dedup();
    
    Ok(subdomains)
}

/// Scrape Yandex with retry logic
pub async fn scrape_yandex_with_retry(domain: &str, max_retries: u32) -> Result<Vec<String>, EnumerationError> {
    let mut retries = 0;
    
    loop {
        match scrape_yandex(domain).await {
            Ok(subdomains) => return Ok(subdomains),
            Err(e) => {
                if retries >= max_retries {
                    return Err(e);
                }
                
                retries += 1;
                tracing::warn!("Yandex request failed (attempt {}/{}): {}", retries, max_retries + 1, e);
                
                // Exponential backoff
                let delay = Duration::from_secs(2u64.pow(retries));
                sleep(delay).await;
            }
        }
    }
}

/// Extract subdomain from a URL
fn extract_subdomain_from_url(url: &str, domain: &str) -> Option<String> {
    // Skip non-http URLs
    if !url.starts_with("http") {
        return None;
    }
    
    // Try to parse the URL
    if let Ok(parsed_url) = Url::parse(url) {
        if let Some(host) = parsed_url.host_str() {
            // Check if it's a subdomain of our target domain
            if host.ends_with(domain) && host.len() > domain.len() {
                // Make sure it's actually a subdomain (not the domain itself)
                if host.len() > domain.len() && host.as_bytes()[host.len() - domain.len() - 1] == b'.' {
                    return Some(host.to_string());
                }
            }
        }
    }
    
    // Fallback: try to extract hostname manually
    // Try to extract hostname from URL
    let hostname = if url.starts_with("http://") {
        url.get(7..)?.split('/').next()?
    } else if url.starts_with("https://") {
        url.get(8..)?.split('/').next()?
    } else {
        url.split('/').next()?
    };
    
    // Check if it's a subdomain of our target domain
    if hostname.ends_with(domain) && hostname.len() > domain.len() {
        // Make sure it's actually a subdomain (not the domain itself)
        if hostname.len() > domain.len() && hostname.as_bytes()[hostname.len() - domain.len() - 1] == b'.' {
            return Some(hostname.to_string());
        }
    }
    
    None
}