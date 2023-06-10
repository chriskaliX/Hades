use anyhow::{bail, Result, Ok, anyhow};
use std::collections::HashMap;
use crate::event::BpfProgram;

pub struct Bpfmanager {
    events: HashMap<String, Box<dyn BpfProgram>>,
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
    pub fn load_program(&mut self, key: &str, prog: Box<dyn BpfProgram>) {
        self.events.insert(key.to_owned(),  prog);
    }

    pub fn start_program(&mut self, key: &str) -> Result<()>{
        let program = self.events.get_mut(key).ok_or_else(|| anyhow!("invalid"))?;
        if program.status() {
            bail!("{} is running", key)
        }
        program.init()?;
        program.attach()?;
        Ok(())
    }

    pub fn stop_program(&mut self, key: &str) -> Result<()> {
        let program = self.events.get_mut(key).ok_or_else(|| anyhow!("invalid"))?;
        if !program.status() {
            return Ok(())
        }
        program.detech()?;
        Ok(())
    }
}