use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

pub struct KsymCache {
    refresh_interval: Duration,
    symbols: HashSet<u64>,
    last_refresh: Option<Instant>,
}

impl KsymCache {
    pub fn new(refresh_interval: Duration) -> Self {
        Self {
            refresh_interval,
            symbols: HashSet::with_capacity(1 << 15),
            last_refresh: None,
        }
    }

    pub fn contains_addr(&mut self, addr: u64) -> bool {
        self.refresh_if_needed();
        self.symbols.contains(&addr)
    }

    fn refresh_if_needed(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_refresh {
            if now.duration_since(last) < self.refresh_interval {
                return;
            }
        }
        self.last_refresh = Some(now);
        self.symbols.clear();

        let file = match File::open("/proc/kallsyms") {
            Ok(f) => f,
            Err(_) => return,
        };
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let mut parts = line.split_whitespace();
            let addr = match parts.next() {
                Some(v) => v,
                None => continue,
            };
            if let Ok(v) = u64::from_str_radix(addr, 16) {
                if v != 0 {
                    self.symbols.insert(v);
                }
            }
        }
    }
}
