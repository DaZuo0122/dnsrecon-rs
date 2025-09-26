//! DNSRecon-rs - A high-performance DNS enumeration tool written in Rust
//!
//! This tool provides DNS enumeration capabilities similar to the original
//! DNSRecon Python tool, with improved performance through Rust's async/await
//! and concurrent operations.

use std::process;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = match dnsrecon_rs::cli::parse_args() {
        Ok(args) => args,
        Err(e) => {
            // Clap errors (like real parsing errors) will be handled by the function
            // If we reach here, it means it was a non-Clap error
            eprintln!("Error parsing arguments: {}", e);
            process::exit(1);
        }
    };
    
    // Execute the main application logic
    if let Err(e) = dnsrecon_rs::run(args).await {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}