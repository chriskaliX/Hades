use std::collections::HashMap;

use crate::cache::Transformer;

use super::{parse_sinfo, parse_str, parse_u16, parse_u32, Event};
use anyhow::Result;

pub struct Execve {}

impl Event for Execve {
    fn parse(data: &[u8], trans: &mut Transformer) -> Result<HashMap<String, String>> {
        let mut m: HashMap<_, _> = HashMap::new();
        let mut idx: usize = 0;
        let pid = parse_u32(data, &mut idx)?;
        m.insert("pid".to_string(), pid.to_string());
        m.insert("tgid".to_string(), parse_u32(data, &mut idx)?.to_string());
        let pgid = parse_u32(data, &mut idx)?;
        m.insert("pgid".to_string(), pgid.to_string());
        let ppid = parse_u32(data, &mut idx)?;
        m.insert("ppid".to_string(), ppid.to_string());
        m.insert("sid".to_string(), parse_u32(data, &mut idx)?.to_string());
        let pns = parse_u32(data, &mut idx)?;
        m.insert("pns".to_string(), pns.to_string());
        let uid = parse_u32(data, &mut idx)?;
        m.insert("uid".to_string(), uid.to_string());
        m.insert("gid".to_string(), parse_u32(data, &mut idx)?.to_string());
        let socket_pid = parse_u32(data, &mut idx)?;
        m.insert("socket_pid".to_string(), socket_pid.to_string());
        m.insert("comm".to_string(), parse_str(data, &mut idx)?);
        m.insert("node".to_string(), parse_str(data, &mut idx)?);
        let argv = parse_str(data, &mut idx)?;
        m.insert("argv".to_string(), argv.clone());
        m.insert("ssh_conn".to_string(), parse_str(data, &mut idx)?);
        m.insert("ld_pre".to_string(), parse_str(data, &mut idx)?);
        m.insert("ld_lib".to_string(), parse_str(data, &mut idx)?);
        m.insert("tty".to_string(), parse_str(data, &mut idx)?);
        m.insert("pwd".to_string(), parse_str(data, &mut idx)?);
        m.insert("stdin".to_string(), parse_str(data, &mut idx)?);
        m.insert("stdout".to_string(), parse_str(data, &mut idx)?);
        let exe = parse_str(data, &mut idx)?;
        m.insert("exe".to_string(), exe.clone());
        let family = parse_u16(data, &mut idx)?;
        m.insert("sa_family".to_string(), family.to_string());
        let sinfo = parse_sinfo(data, &mut idx, family)?;
        m.insert("sip".to_string(), sinfo.local_addr);
        m.insert("sport".to_string(), sinfo.local_port);
        m.insert("dip".to_string(), sinfo.remote_addr);
        m.insert("dport".to_string(), sinfo.remote_port);
        m.insert("pidtree".to_string(), parse_str(data, &mut idx)?);
        /* extra information */
        m.insert("pod_name".to_string(), trans.ns_cache.get(pns, pid));
        m.insert("username".to_string(), trans.user_cache.get(uid));
        m.insert("pgid_argv".to_string(), trans.argv_cache.get(pgid));
        m.insert("ppid_argv".to_string(), trans.argv_cache.get(ppid));
        if socket_pid == 0 || socket_pid == pid {
            m.insert("socket_argv".to_string(), "-1".to_string());
        } else {
            m.insert("socket_argv".to_string(), trans.argv_cache.get(socket_pid));
        }
        m.insert("exe_hash".to_string(), trans.hash_cache.get(exe));
        /* cache fresh */
        trans.argv_cache.put(pid, argv);

        Ok(m)
    }
}
