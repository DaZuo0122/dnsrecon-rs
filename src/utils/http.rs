//! HTTP client utilities with proxy and user-agent support

use reqwest;
use tokio::time::Duration;
use crate::cli::Args;
use crate::enumerate::EnumerationError;

/// Create an HTTP client with appropriate settings based on CLI arguments
pub fn create_http_client(args: &Args, user_agent: &str) -> Result<reqwest::Client, EnumerationError> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(user_agent);
    
    // Add proxy if specified
    if let Some(ref proxy_url) = args.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            client_builder = client_builder.proxy(proxy);
        } else {
            return Err(EnumerationError::Network(format!("Invalid proxy URL: {}", proxy_url)));
        }
    }
    
    client_builder.build().map_err(|e| EnumerationError::Network(format!("Failed to build HTTP client: {}", e)))
}