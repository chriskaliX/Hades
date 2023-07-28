use crate::{event::{BpfProgram, egress::EVENT_EGRESS}, config::config::Config};
use anyhow::{anyhow, bail, Ok, Result};
use std::collections::HashMap;

pub struct Bpfmanager {
    events: HashMap<String, Box<dyn BpfProgram + Send>>,
}

impl Bpfmanager {
    /// bump memlock rlimit
    pub fn bump_memlock_rlimit() -> Result<()> {
        let rlimit = libc::rlimit {
            rlim_cur: 128 << 20,
            rlim_max: 128 << 20,
        };

        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
            bail!("failed to increase rlimit");
        }

        Ok(())
    }

    pub fn new() -> Self {
        Bpfmanager {
            events: HashMap::new(),
        }
    }

    // Load the bpfprogram into the hashmap
    // @param - key - the id of the program
    //        - program - the BPF program implement BpfTrait
    pub fn load_program(&mut self, key: &str, prog: Box<dyn BpfProgram + Send>) {
        self.events.insert(key.to_owned(), prog);
    }

    pub fn start_program(&mut self, key: &str) -> Result<()> {
        let program = self.events.get_mut(key).ok_or_else(|| anyhow!("invalid"))?;
        if program.status() {
            bail!("{} is running", key)
        }
        program.init()?;
        program.attach()?;
        Ok(())
    }

    /// use drop to make this happen
    pub fn stop_program(&mut self, key: &str) {
        self.events.remove(key);
    }

    pub fn flush_config(&mut self, key: Config) -> Result<()> {
        // flush egress
        if let Some(v) = self.events.get(EVENT_EGRESS) {
            v.flush_config(key)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::egress::TcEvent;
    use crate::config::config::Config;

    #[test]
    fn test_bpfmanager() -> Result<()> {
        // Create a new Bpfmanager instance
        let mut bpfmanager = Bpfmanager::new();

        // Load a BPF program into the Bpfmanager
        let key = "egress";
        let egress_program = TcEvent::new();
        bpfmanager.load_program(key, Box::new(egress_program));

        // Start a loaded BPF program
        assert!(bpfmanager.start_program(key).is_ok());

        // Try to start the same program again (should fail)
        assert!(bpfmanager.start_program(key).is_err());

        // Flush the config
        let config = Config { tc: vec![] };
        assert!(bpfmanager.flush_config(config).is_ok());

        // Stop the BPF program
        bpfmanager.stop_program(key);

        Ok(())
    }
}
