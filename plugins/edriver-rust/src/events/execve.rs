use std::{collections::HashMap, net::Ipv4Addr};

use super::{parse_path, parse_sinfo, parse_str, parse_u32, Event};
use anyhow::Result;

pub struct Execve {}

impl Event for Execve {
    fn parse(data: &[u8]) -> Result<HashMap<String, String>> {
        let mut m: HashMap<_, _> = HashMap::new();
        let mut idx: usize = 0;
        m.insert("pid".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("tgid".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("pgid".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("ppid".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("sid".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("pns".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("uid".to_string(), parse_u32(data, &mut idx)?.to_string());
        m.insert("gid".to_string(), parse_u32(data, &mut idx)?.to_string());
        let s = "socket_pid".to_string();
        m.insert(s, parse_u32(data, &mut idx)?.to_string());
        m.insert("comm".to_string(), parse_str(data, &mut idx)?);
        m.insert("node".to_string(), parse_str(data, &mut idx)?);
        m.insert("args".to_string(), parse_str(data, &mut idx)?);
        m.insert("ssh_conn".to_string(), parse_str(data, &mut idx)?);
        m.insert("ld_pre".to_string(), parse_str(data, &mut idx)?);
        m.insert("ld_lib".to_string(), parse_str(data, &mut idx)?);
        m.insert("tty".to_string(), parse_str(data, &mut idx)?);
        m.insert("pwd".to_string(), parse_path(data, &mut idx)?);
        m.insert("stdin".to_string(), parse_path(data, &mut idx)?);
        m.insert("stdout".to_string(), parse_path(data, &mut idx)?);
        m.insert("exe".to_string(), parse_path(data, &mut idx)?);
        let sinfo = parse_sinfo(data, &mut idx)?;
        m.insert("sa_family".to_string(), sinfo.family.to_string());
        let local_addr = Ipv4Addr::from(sinfo.local_address).to_string();
        m.insert("sip".to_string(), local_addr);
        m.insert("sport".to_string(), sinfo.local_port.to_string());
        let remote_addr = Ipv4Addr::from(sinfo.remote_address).to_string();
        m.insert("dip".to_string(), remote_addr);
        m.insert("dport".to_string(), sinfo.remote_port.to_string());
        m.insert("pidtree".to_string(), parse_str(data, &mut idx)?);
        /* extra information */
        // m.insert("pod_name".to_string(), );
        // container
        // exe md5
        // pid argv

        Ok(m)
    }
}
