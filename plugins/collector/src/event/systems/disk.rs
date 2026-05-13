/// Disk collector — data_type 3010.
/// Reads /proc/mounts and calls statvfs(2).  Mirrors Go's event/systems/disk.go.
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::manager::{EventMode, IEvent};
use crate::event::make_record;

const DATA_TYPE: i32 = 3010;

pub struct Disk;

#[async_trait]
impl IEvent for Disk {
    fn name(&self)        -> &'static str { "disk" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let f = match File::open("/proc/mounts") { Ok(f) => f, Err(_) => return Ok(()) };
        for line in BufReader::new(f).lines().flatten() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 { continue; }
            let (device, mountpoint, fstype) = (cols[0], cols[1], cols[2]);
            if is_pseudo(device, fstype) { continue; }

            let (total, used, free, pct) = match statvfs(mountpoint) {
                Some(v) => v,
                None    => continue,
            };
            let mut fields = HashMap::new();
            fields.insert("device".into(),     device.to_owned());
            fields.insert("mountpoint".into(), mountpoint.to_owned());
            fields.insert("fs_type".into(),    fstype.to_owned());
            fields.insert("total".into(),      total.to_string());
            fields.insert("used".into(),       used.to_string());
            fields.insert("free".into(),       free.to_string());
            fields.insert("usage".into(),      format!("{pct:.8}"));
            // serial and label are Linux-specific ioctl calls; leave empty (matches gopsutil fallback on containers)
            fields.insert("serial".into(),     String::new());
            fields.insert("label".into(),      String::new());
            let _ = client.send_record(&make_record(DATA_TYPE, fields));
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }
}

fn is_pseudo(device: &str, fstype: &str) -> bool {
    matches!(fstype,
        "proc"|"sysfs"|"devtmpfs"|"devpts"|"tmpfs"|"cgroup"|"cgroup2"|"pstore"|
        "securityfs"|"debugfs"|"tracefs"|"hugetlbfs"|"mqueue"|"fusectl"|"binfmt_misc"|
        "overlay"|"aufs"|"nsfs"|"configfs"|"efivarfs"|"fuse")
    || device == "none" || device == "rootfs" || device.starts_with("sunrpc")
}

/// Returns (total_bytes, used_bytes, free_bytes, used_pct)
fn statvfs(path: &str) -> Option<(u64, u64, u64, f64)> {
    let cpath = CString::new(path).ok()?;
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(cpath.as_ptr(), &mut st) != 0 { return None; }
        let bs = st.f_bsize as u64;
        let total = st.f_blocks * bs;
        let free  = st.f_bavail * bs;
        let used  = total.saturating_sub(st.f_bfree * bs);
        let pct   = if total > 0 { used as f64 / total as f64 * 100.0 } else { 0.0 };
        Some((total, used, free, pct))
    }
}
