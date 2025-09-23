//! Bing search enumeration

use crate::enumerate::EnumerationError;
use reqwest;
use scraper::{Html, Selector};
use tokio::time::{sleep, Duration};
use url::Url;

/// Scrape Bing for subdomains of a domain
pub async fn scrape_bing(domain: &str) -> Result<Vec<String>, EnumerationError> {
    let mut subdomains = Vec::new();
    
    // Create HTTP client with reasonable timeouts
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)")
        .build()?;
    
    // Perform multiple searches with pagination
    for i in (1..=150).step_by(10) {
        let url = format!(
            "https://www.bing.com/search?q=domain%3A{}&qs=n&first={}",
            domain, i
        );
        
        // Send request
        let response = client.get(&url).send().await?;
        
        // Check if we got a successful response
        if !response.status().is_success() {
            tracing::warn!("Bing returned status {}: {}", response.status(), url);
            // Continue with next iteration instead of failing completely
            sleep(Duration::from_secs(1)).await;
            continue;
        }
            
        let body = response.text().await?;
        
        // Parse HTML
        let document = Html::parse_document(&body);
        // Try multiple selectors to be more robust
        let selectors = vec![
            "li.b_algo h2 a",
            "ol#b_results li.b_algo h2 a",
            "ol#b_results li.b_algo div.b_title a",
            "ol#b_results li.b_algo h3 a",
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
        
        // If we didn't find any elements, try a more general approach
        if !found_elements {
            // Look for any links that might contain our domain
            if let Ok(selector) = Selector::parse("a[href*='http']") {
                for element in document.select(&selector) {
                    if let Some(href) = element.value().attr("href") {
                        if let Some(subdomain) = extract_subdomain_from_url(href, domain) {
                            subdomains.push(subdomain);
                        }
                    }
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

/// Scrape Bing with retry logic for subdomains of a domain
pub async fn scrape_bing_with_retry(domain: &str, max_retries: u32) -> Result<Vec<String>, EnumerationError> {
    let mut retries = 0;
    
    loop {
        match scrape_bing(domain).await {
            Ok(subdomains) => return Ok(subdomains),
            Err(e) => {
                if retries >= max_retries {
                    return Err(e);
                }
                
                retries += 1;
                tracing::warn!("Bing request failed (attempt {}/{}): {}", retries, max_retries + 1, e);
                
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