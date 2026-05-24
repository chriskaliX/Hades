use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields};

// Corresponds to BPF probe: process_uprobe.h
// Events: 2000 (BASH_READLINE)

pub fn parse_bash_readline(data: &[u8], trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::with_capacity(8);

    // EVT_SUBMIT field order: pid, tgid, comm, exe, line, tty_path, stdin_path,
    // stdout_path, family(u16), sinfo(hds_socket_info=16 bytes raw), pidtree, pwd_path.
    //
    // Note: the BPF probe unconditionally emits &sinfo (hds_socket_info*, 16 bytes) even
    // for IPv6 sockets.  It does NOT emit sinfo_v6, so we always consume exactly 16 bytes
    // after family rather than calling sock_pair() which would read 56 bytes.
    let pid = dec.u32()?;
    let tgid = dec.u32()?;
    let comm = dec.string()?;
    let exe = dec.string()?;
    let line = dec.string()?;
    let tty = dec.string()?;
    let stdin = dec.string()?;
    let stdout = dec.string()?;
    // family and sinfo are typed pointers (u16* and hds_socket_info*) so they are
    // serialised as raw bytes: 2 bytes for family, 16 bytes for sinfo struct.
    let family = dec.u16()?;
    let sinfo = dec.socket_info(2)?; // always 16 bytes (v4 struct), regardless of family
    let pidtree = dec.string()?;
    let cwd = dec.string()?;

    m.insert("pid".into(), pid.to_string());
    m.insert("tgid".into(), tgid.to_string());
    m.insert("comm".into(), comm);
    m.insert("exe".into(), exe);
    m.insert("argv".into(), line.clone());
    m.insert("tty_name".into(), tty);
    m.insert("stdin".into(), stdin);
    m.insert("stdout".into(), stdout);
    m.insert("family".into(), family.to_string());
    m.insert("sport".into(), sinfo.local_port);
    m.insert("dport".into(), sinfo.remote_port);
    m.insert("sip".into(), sinfo.local_addr);
    m.insert("dip".into(), sinfo.remote_addr);
    m.insert("pid_tree".into(), pidtree.clone());
    m.insert("pidtree".into(), pidtree);
    m.insert("cwd".into(), cwd);

    trans.argv_cache.put(pid, line);
    Ok(Some(m))
}
