use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

lazy_static::lazy_static! {
    static ref PROFILER: Mutex<Profiler> = Mutex::new(Profiler::new());
}

pub struct Profiler {
    timers: HashMap<String, Vec<Duration>>,
    active_timers: HashMap<String, Instant>,
}

impl Profiler {
    fn new() -> Self {
        Self {
            timers: HashMap::new(),
            active_timers: HashMap::new(),
        }
    }

    pub fn start(&mut self, name: &str) {
        self.active_timers.insert(name.to_string(), Instant::now());
    }

    pub fn stop(&mut self, name: &str) {
        if let Some(start) = self.active_timers.remove(name) {
            let duration = start.elapsed();
            self.timers
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(duration);
        }
    }

    pub fn report(&self) {
        if self.timers.is_empty() {
            return;
        }

        eprintln!("\n=== Performance Profile ===");
        let mut entries: Vec<_> = self.timers.iter().collect();
        entries.sort_by_key(|(_, durations)| durations.iter().sum::<Duration>());
        entries.reverse();

        for (name, durations) in entries {
            let total: Duration = durations.iter().sum();
            let count = durations.len();
            let avg = total / count as u32;
            eprintln!(
                "{:30} {:>10.3}s ({:>5} calls, avg {:>8.3}ms)",
                name,
                total.as_secs_f64(),
                count,
                avg.as_secs_f64() * 1000.0
            );
        }
        eprintln!();
    }
}

pub fn start_timer(name: &str) {
    if std::env::var("ASTDIFF_PROFILE").is_ok() {
        if let Ok(mut profiler) = PROFILER.lock() {
            profiler.start(name);
        }
    }
}

pub fn stop_timer(name: &str) {
    if std::env::var("ASTDIFF_PROFILE").is_ok() {
        if let Ok(mut profiler) = PROFILER.lock() {
            profiler.stop(name);
        }
    }
}

pub fn report_profile() {
    if std::env::var("ASTDIFF_PROFILE").is_ok() {
        if let Ok(profiler) = PROFILER.lock() {
            profiler.report();
        }
    }
}

pub struct Timer<'a> {
    name: &'a str,
    enabled: bool,
}

impl<'a> Timer<'a> {
    pub fn new(name: &'a str) -> Self {
        let enabled = std::env::var("ASTDIFF_PROFILE").is_ok();
        if enabled {
            start_timer(name);
        }
        Self { name, enabled }
    }
}

impl<'a> Drop for Timer<'a> {
    fn drop(&mut self) {
        if self.enabled {
            stop_timer(self.name);
        }
    }
}
