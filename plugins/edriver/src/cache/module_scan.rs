use std::collections::HashSet;
use std::fs;

pub struct ModuleScanSummary {
    pub iter_count: u64,
    pub kernel_count: usize,
    pub user_count: usize,
    pub hidden_modules: String,
}

pub struct ModuleScanCache {
    active: bool,
    max_iter_index: u64,
    kernel_modules: HashSet<String>,
}

impl ModuleScanCache {
    pub fn new(cap: usize) -> Self {
        Self {
            active: false,
            max_iter_index: 0,
            kernel_modules: HashSet::with_capacity(cap),
        }
    }

    pub fn observe(&mut self, index: u64, name: &str) -> Option<ModuleScanSummary> {
        // Index reset indicates a new scan cycle. Finalize previous cycle first.
        let summary = if self.active && index == 0 && !self.kernel_modules.is_empty() {
            self.finalize_cycle()
        } else {
            None
        };

        self.active = true;
        if index > self.max_iter_index {
            self.max_iter_index = index;
        }
        if !name.is_empty() && name != "-1" {
            self.kernel_modules.insert(name.to_string());
        }

        summary
    }

    fn finalize_cycle(&mut self) -> Option<ModuleScanSummary> {
        let user_modules = read_proc_modules_set();
        let hidden: Vec<&str> = self
            .kernel_modules
            .difference(&user_modules)
            .map(String::as_str)
            .collect();

        let summary = ModuleScanSummary {
            iter_count: self.max_iter_index,
            kernel_count: self.kernel_modules.len(),
            user_count: user_modules.len(),
            hidden_modules: if hidden.is_empty() {
                crate::events::EDEFAULT.to_string()
            } else {
                hidden.join(",")
            },
        };

        self.max_iter_index = 0;
        self.kernel_modules.clear();
        Some(summary)
    }
}

fn read_proc_modules_set() -> HashSet<String> {
    let mut set = HashSet::new();
    let content = match fs::read_to_string("/proc/modules") {
        Ok(v) => v,
        Err(_) => return set,
    };
    for line in content.lines() {
        if let Some(name) = line.split_whitespace().next() {
            if !name.is_empty() {
                set.insert(name.to_string());
            }
        }
    }
    set
}
