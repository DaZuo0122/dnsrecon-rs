//! Utility functions module
//!
//! This module provides various utility functions used throughout the application.

pub mod cidr;
pub mod http;
pub mod validation;

/// Remove duplicates from a vector while preserving order
pub fn unique<T: Clone + Eq + std::hash::Hash>(vec: Vec<T>) -> Vec<T> {
    use std::collections::HashSet;
    
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    
    for item in vec {
        if seen.insert(item.clone()) {
            result.push(item);
        }
    }
    
    result
}

/// Generate a random test name for wildcard detection
pub fn generate_testname(length: usize, suffix: &str) -> String {
    use rand::{distributions::Alphanumeric, Rng};
    
    let name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    
    format!("{}.{}", name, suffix)
}