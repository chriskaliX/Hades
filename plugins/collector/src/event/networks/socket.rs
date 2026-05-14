/// Socket collector — data_type 5001.
/// Reads /proc/net/{tcp,tcp6,udp,udp6} and maps inodes to PIDs.
/// Mirrors Go's event/networks/socket.go (proc fallback path).
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use sdk::Client;

use crate::cache;
use crate::manager::{EventMode, IEvent};
use crate::event::{hash, make_record};

const DATA_TYPE: i32 = 5001;

pub struct Socket;

#[async_trait]
impl IEvent for Socket {
    fn name(&self)        -> &'static str { "socket" }
    fn data_type(&self)   -> i32          { DATA_TYPE }
    fn flag(&self)        -> EventMode    { EventMode::Periodic }
    fn immediately(&self) -> bool         { true }

    async fn run(&mut self, client: &mut Client) -> Result<()> {
        // Build inode → (pid, comm, cmdline) map
        let inode_map = tokio::task::spawn_blocking(build_inode_map).await?;
        let seq       = hash();

        for proto in ["tcp", "tcp6", "udp", "udp6"] {
            let Ok(f) = File::open(format!("/proc/net/{proto}")) else { continue };
            for (i, line) in BufReader::new(f).lines().flatten().enumerate() {
                if i == 0 { continue; }  // header
                let mut fields = HashMap::new();
                if !parse_net_line(&line, proto, &inode_map, &mut fields) { continue; }
                fields.insert("package_seq".into(), seq.clone());
                let _ = client.send_record(&make_record(DATA_TYPE, fields));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        Ok(())
    }
}

// ── /proc/net line parser ────────────────────────────────────────────────────

fn parse_net_line(
    line:      &str,
    proto:     &str,
    inode_map: &HashMap<u64, ProcInfo>,
    out:       &mut HashMap<String, String>,
) -> bool {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 { return false; }
    let ipv6   = proto.ends_with('6');
    let (saddr, sport) = decode_addr(cols[1], ipv6);
    let (daddr, dport) = decode_addr(cols[2], ipv6);
    let state_raw = u8::from_str_radix(cols[3], 16).unwrap_or(0);
    let uid    = cols[7].to_owned();
    let inode: u64 = cols[9].parse().unwrap_or(0);

    let info = inode_map.get(&inode);
    let state_str = tcp_state(state_raw);

    // Write into socket cache so proc_listen_addrs() can read it without
    // re-scanning /proc/net — mirrors Go's scache.Put(inode, socket).
    if inode > 0 && inode <= u32::MAX as u64 {
        if let Some(info) = info {
            cache::socket::put(inode as u32, cache::socket::Socket {
                local_addr:  saddr.clone(),
                local_port:  sport.parse().unwrap_or(0),
                remote_addr: daddr.clone(),
                remote_port: dport.parse().unwrap_or(0),
                state:       state_str.clone(),
                protocol:    proto.trim_end_matches('6').to_owned(),
                pid:         info.pid,
            });
        }
    }

    out.insert("sip".into(),    saddr);
    out.insert("sport".into(),  sport);
    out.insert("dip".into(),    daddr);
    out.insert("dport".into(),  dport);
    // Frontend expects numeric type: 6=TCP, 17=UDP
    let type_num = if proto.starts_with("tcp") { "6" } else { "17" };
    out.insert("type".into(),   type_num.to_owned());
    out.insert("state".into(),  state_str);
    out.insert("uid".into(),    uid);
    out.insert("inode".into(),  inode.to_string());
    out.insert("pid".into(),    info.map(|i| i.pid.to_string()).unwrap_or_default());
    out.insert("comm".into(),   info.map(|i| i.comm.clone()).unwrap_or_default());
    out.insert("cmdline".into(), info.map(|i| i.cmdline.clone()).unwrap_or_default());
    true
}

fn decode_addr(hex: &str, ipv6: bool) -> (String, String) {
    let (addr_hex, port_hex) = match hex.split_once(':') {
        Some(p) => p,
        None    => return (String::new(), "0".into()),
    };
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    let addr = if ipv6 {
        if addr_hex.len() == 32 {
            let bytes: Vec<u8> = (0..4).flat_map(|i| {
                let chunk = &addr_hex[i*8..(i+1)*8];
                u32::from_str_radix(chunk, 16).unwrap_or(0).to_le_bytes()
            }).collect();
            let arr: [u8; 16] = bytes.try_into().unwrap_or([0u8; 16]);
            Ipv6Addr::from(arr).to_string()
        } else { String::new() }
    } else {
        let v = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
        Ipv4Addr::from(v.to_be()).to_string()
    };
    (addr, port.to_string())
}

fn tcp_state(code: u8) -> String {
    match code {
        1  => "ESTABLISHED", 2  => "SYN_SENT",  3  => "SYN_RECV",
        4  => "FIN_WAIT1",   5  => "FIN_WAIT2",  6  => "TIME_WAIT",
        7  => "CLOSE",       8  => "CLOSE_WAIT", 9  => "LAST_ACK",
        10 => "LISTEN",      11 => "CLOSING",    _  => "UNKNOWN",
    }.to_owned()
}

// ── inode → process mapping ──────────────────────────────────────────────────

struct ProcInfo {
    pid:     i32,
    comm:    String,
    cmdline: String,
}

fn build_inode_map() -> HashMap<u64, ProcInfo> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else { return map };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Ok(pid): std::result::Result<i32, _> = name.to_string_lossy().parse() else { continue };
        // Resolve socket inodes from /proc/<pid>/fd
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else { continue };
        let mut found_any = false;
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                let s = link.to_string_lossy();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(inner) = rest.strip_suffix(']') {
                        if let Ok(inode) = inner.parse::<u64>() {
                            if !found_any {
                                found_any = true;
                            }
                            map.entry(inode).or_insert_with(|| build_proc_info(pid));
                        }
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    map
}

fn build_proc_info(pid: i32) -> ProcInfo {
    let comm = cache::process::get_comm(pid);
    if !comm.is_empty() {
        let cmdline = cache::process::get_argv(pid);
        return ProcInfo { pid, comm, cmdline };
    }
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_owned();
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    ProcInfo { pid, comm, cmdline }
}
