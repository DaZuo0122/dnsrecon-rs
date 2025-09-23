//! Progress reporting functionality

use std::time::Instant;

/// Progress reporter trait
pub trait ProgressReporter {
    /// Report progress update
    fn update(&self, message: &str);
    
    /// Report completion
    fn finish(&self, message: &str);
    
    /// Report an error
    fn error(&self, message: &str);
}

/// Simple progress reporter that prints to stdout
pub struct SimpleProgressReporter {
    start_time: Instant,
}

impl SimpleProgressReporter {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }
    
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

impl Default for SimpleProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressReporter for SimpleProgressReporter {
    fn update(&self, message: &str) {
        println!("[*] {}", message);
    }
    
    fn finish(&self, message: &str) {
        println!("[+] {}", message);
    }
    
    fn error(&self, message: &str) {
        eprintln!("[!] {}", message);
    }
}

/// Progress reporter with timing information
pub struct TimedProgressReporter {
    start_time: Instant,
}

impl TimedProgressReporter {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
        }
    }
    
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

impl Default for TimedProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgressReporter for TimedProgressReporter {
    fn update(&self, message: &str) {
        let elapsed = self.elapsed().as_secs_f32();
        println!("[*] [{:.2}s] {}", elapsed, message);
    }
    
    fn finish(&self, message: &str) {
        let elapsed = self.elapsed().as_secs_f32();
        println!("[+] [{:.2}s] {}", elapsed, message);
    }
    
    fn error(&self, message: &str) {
        let elapsed = self.elapsed().as_secs_f32();
        eprintln!("[!] [{:.2}s] {}", elapsed, message);
    }
}