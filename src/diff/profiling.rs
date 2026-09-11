use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

static PROFILER: LazyLock<Mutex<HashMap<&'static str, (Duration, u32)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ASTDIFF_PROFILE").is_some())
}

pub fn report_profile() {
    if !enabled() {
        return;
    }
    let Ok(profiler) = PROFILER.lock() else {
        return;
    };
    let mut entries = profiler.iter().collect::<Vec<_>>();
    entries.sort_by_key(|(name, (total, _))| (std::cmp::Reverse(*total), **name));
    eprintln!("\n=== Performance Profile ===");
    for (name, (total, count)) in entries {
        eprintln!(
            "{:30} {:>10.3}s ({:>5} calls, avg {:>8.3}ms)",
            name,
            total.as_secs_f64(),
            count,
            (*total / *count).as_secs_f64() * 1000.0
        );
    }
}

/// Each timer owns its start instant, including overlapping timers with one name.
pub struct Timer {
    name: &'static str,
    start: Option<Instant>,
}

impl Timer {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            start: enabled().then(Instant::now),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            if let Ok(mut profiler) = PROFILER.lock() {
                let (total, count) = profiler.entry(self.name).or_default();
                *total += start.elapsed();
                *count += 1;
            }
        }
    }
}
