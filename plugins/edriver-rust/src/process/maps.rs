use anyhow::{bail, Result};
use bitflags::bitflags;
use std::fs::read_to_string;

type PermFlag = u8;

/// Information about the process memory mapping
#[derive(Default, Debug)]
pub struct Mapping {
    /// Start address for virtual memory
    pub vaddr_start: u64,
    /// End address for virual memory
    vaddr_end: u64,
    /// Permissions of the page. 'p' flag means private
    perm: PermFlag,
    /// Offset for the mapping begins.
    offset: u64,
    /// Device is the major and minor device number (in hex) where the file lives.
    device_id: String,
    /// Inode of the file
    inode: u64,
    // Path contains the file name for file backed mappings
    path: Option<String>,
}

bitflags! {
    #[derive(Default)]
    pub struct MPermissions: PermFlag {
        /// No permissions
        const NONE = 0;
        /// Read permission
        const READ = 1 << 0;
        /// Write permission
        const WRITE = 1 << 1;
        /// Execute permission
        const EXECUTE = 1 << 2;
        /// Memory is shared with another process.
        /// Mutually exclusive with PRIVATE.
        const SHARED = 1 << 3;
        /// Memory is private (and copy-on-write)
        /// Mutually exclusive with SHARED.
        const PRIVATE = 1 << 4;
    }
}

impl MPermissions {
    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 4 {
            bail!("Permission length {}", s.len());
        }
        let mut permissions = MPermissions::NONE;
        for (_, c) in s.chars().enumerate() {
            match c {
                'r' => permissions |= MPermissions::READ,
                'w' => permissions |= MPermissions::WRITE,
                'x' => permissions |= MPermissions::EXECUTE,
                'p' => permissions |= MPermissions::PRIVATE,
                's' => permissions |= MPermissions::SHARED,
                _ => continue,
            }
        }
        Ok(permissions)
    }
}

/// Parse mapping
pub fn parse_mapping(pid: u32) -> Result<Vec<Mapping>> {
    // Read the maps from file
    let maps = read_to_string(format!("/proc/{}/maps", pid))?;
    let mut ret: Vec<Mapping> = Vec::with_capacity(maps.len());
    for line in maps.lines() {
        if let Ok(m) = parse_mapping_line(line) {
            ret.push(m)
        }
    }
    Ok(ret)
}

fn parse_mapping_line(line: &str) -> Result<Mapping> {
    let mut m = Mapping::default();
    // Split fields with blanks
    let fields = line.split_whitespace().collect::<Vec<&str>>();
    // Extract vaddr
    let vaddr: Vec<&str> = fields[0].split('-').collect();
    m.vaddr_start = u64::from_str_radix(vaddr[0], 16)?;
    m.vaddr_end = u64::from_str_radix(vaddr[1], 16)?;
    m.perm = MPermissions::from_str(fields[1])?.bits();
    m.offset = u64::from_str_radix(fields[2], 16)?;
    m.device_id = fields[3].to_string();
    m.inode = fields[4].parse()?;
    m.path = fields.get(5).map(|s| s.to_string());
    Ok(m)
}
