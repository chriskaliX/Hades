/// Process collector — data_type 1001.
use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use procfs::process::all_processes;
use sdk::Client;

use crate::cache::{self, boot_time_secs, num_cpus, pid_ns, sys_time_jiffies, ticks_per_second};
use crate::cache::user::group_name;
use crate::event::{hash, make_record};
use crate::manager::{EventMode, IEvent};

const DATA_TYPE:   i32   = 1001;
const MAX_PROCESS: usize = 1500;
const MAX_ARGV:    usize = 8 * 1024;

pub struct Process;

#[async_trait]
impl IEvent for Process {
    fn name(&self)        -> &'static str { "process" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { false }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        let seq       = hash();
        let root_pns  = pid_ns(1);
        let boot_time = boot_time_secs();
        let ticks     = ticks_per_second();
        let sys_time  = sys_time_jiffies();
        let ncpus     = num_cpus() as f64;

        // Reuse one HashMap; iterate lazily (no .collect()) to keep peak RSS low.
        let mut fields: HashMap<String, String> = HashMap::with_capacity(40);

        for p in all_processes()?.filter_map(|r| r.ok()).take(MAX_PROCESS) {
            let pid = p.pid();
            let pns = pid_ns(pid);

            fields.insert("pid".into(),      pid.to_string());
            fields.insert("root_pns".into(), root_pns.to_string());
            fields.insert("pns".into(),      pns.clone());
            // tid = 0: /proc scan sees only the main thread.
            // Remaining placeholders are filled by edriver's eBPF execve hook.
            fields.insert("tid".into(),         "0".into());
            fields.insert("pid_tree".into(),    String::new());
            fields.insert("ttyname".into(),     String::new());
            fields.insert("remote_addr".into(), String::new());
            fields.insert("remote_port".into(), String::new());
            fields.insert("local_addr".into(),  String::new());
            fields.insert("local_port".into(),  String::new());

            if let Ok(s) = p.stat() {
                let cpu = if sys_time > 0 {
                    (s.utime + s.stime) as f64 / sys_time as f64 * ncpus
                } else { 0.0 };
                fields.insert("ppid".into(),       s.ppid.to_string());
                fields.insert("pgid".into(),       s.pgrp.to_string());
                fields.insert("session_id".into(), s.session.to_string());
                fields.insert("name".into(),       s.comm.clone());
                fields.insert("tty".into(),        s.tty_nr.to_string());
                fields.insert("utime".into(),      s.utime.to_string());
                fields.insert("stime".into(),      s.stime.to_string());
                fields.insert("vsize".into(),      s.vsize.to_string());
                fields.insert("rss".into(),        s.rss.to_string());
                fields.insert("start_time".into(), (boot_time + s.starttime / ticks).to_string());
                fields.insert("cpu".into(),        format!("{cpu:.6}"));
                fields.insert("pgid_argv".into(),  if s.pgrp > 0 { cache::process::get_argv(s.pgrp) } else { String::new() });
                fields.insert("ppid_argv".into(),  if s.ppid > 0 { cache::process::get_argv(s.ppid) } else { String::new() });
            }

            if let Ok(st) = p.status() {
                let (pod_name, node_name) = cache::namespace::get(pid as u32, pns.parse().unwrap_or(0));
                fields.insert("uid".into(),        st.ruid.to_string());
                fields.insert("gid".into(),        st.rgid.to_string());
                fields.insert("username".into(),   cache::user::get_username(st.ruid));
                fields.insert("group_name".into(), group_name(st.rgid));
                fields.insert("pod_name".into(),   pod_name);
                fields.insert("nodename".into(),   node_name);
            }

            if let Ok(cmdline) = p.cmdline() {
                let mut argv = cmdline.join(" ");
                argv.truncate(MAX_ARGV);
                cache::process::put_argv(pid, argv.clone());
                fields.insert("argv".to_owned(), argv);
            }

            if let Ok(exe) = p.exe() {
                let exe_str = exe.to_string_lossy().into_owned();
                fields.insert("exe_hash".into(), cache::process::exe_hash(&exe_str));
                fields.insert("exe".into(), exe_str);
            }

            if let Ok(cwd) = p.cwd() {
                fields.insert("cwd".into(), cwd.to_string_lossy().into_owned());
            }

            fields.insert("stdin".into(),       read_fd_link(pid, 0));
            fields.insert("stdout".into(),      read_fd_link(pid, 1));
            fields.insert("package_seq".into(), seq.clone());

            let _ = client.send_record(&make_record(DATA_TYPE, fields.drain().collect()));
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
}

fn read_fd_link(pid: i32, fd: u32) -> String {
    fs::read_link(format!("/proc/{pid}/fd/{fd}"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

