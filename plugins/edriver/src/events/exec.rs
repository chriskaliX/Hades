use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields, EDEFAULT};

// Corresponds to BPF probe: process_exec.h  (event 700 SYS_ENTER_EXECVE)
//
// EVT_SUBMIT field order (after data_type, which is consumed by the dispatcher):
//   pid(u32), tgid(u32), pgid(u32), ppid(u32), sid(u32), pns(u32),
//   uid(u32), gid(u32), socket_pid(u32),
//   comm(str), node(str), args(str), ssh_conn(str), ld_pre(str), ld_lib(str),
//   tty_path(str), pwd_path(str), stdin_path(str), stdout_path(str), exe_path(str),
//   EVT_SOCK → family(u16) + sinfo_v4 OR sinfo_v6 depending on family,
//   pidtree(str)
//
// socket_argv is not a BPF field; it is resolved from argv_cache[socket_pid]
// in userspace after the event is parsed.
pub fn parse_execve(data: &[u8], trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut fields = Fields::new();

    let pid        = dec.u32()?;
    let tgid       = dec.u32()?;
    let pgid       = dec.u32()?;
    let ppid       = dec.u32()?;
    let sid        = dec.u32()?;
    let pns        = dec.u32()?;
    let uid        = dec.u32()?;
    let gid        = dec.u32()?;
    let socket_pid = dec.u32()?;

    let comm     = dec.string()?;
    let nodename = dec.string()?;
    let argv     = dec.string()?;
    let ssh_conn = dec.string()?;
    let ld_pre   = dec.string()?;
    let ld_lib   = dec.string()?;
    let tty      = dec.string()?;
    let cwd      = dec.string()?;
    let stdin    = dec.string()?;
    let stdout   = dec.string()?;
    let exe      = dec.string()?;

    // EVT_SOCK: family(u16) + sinfo_v4(16 bytes) if AF_INET,
    //           or sinfo_v6(40 bytes) if AF_INET6, or nothing otherwise.
    let family = dec.u16()?;
    let sinfo  = dec.socket_info(family)?;

    let pidtree = dec.string()?;

    // socket_argv: userspace lookup of the argv belonging to the process
    // that owns the socket fd (identified by socket_pid from BPF).
    let socket_argv = if socket_pid != 0 {
        trans.argv_cache.get(socket_pid)
    } else {
        EDEFAULT.to_owned()
    };

    // Cache this process's argv so child processes can look it up as socket_argv.
    trans.argv_cache.put(pid, argv.clone());

    fields.insert("pid".into(),          pid.to_string());
    fields.insert("tgid".into(),         tgid.to_string());
    fields.insert("pgid".into(),         pgid.to_string());
    fields.insert("ppid".into(),         ppid.to_string());
    fields.insert("sid".into(),          sid.to_string());
    fields.insert("pns".into(),          pns.to_string());
    fields.insert("uid".into(),          uid.to_string());
    fields.insert("gid".into(),          gid.to_string());
    fields.insert("socket_pid".into(),   socket_pid.to_string());
    fields.insert("comm".into(),         comm);
    fields.insert("nodename".into(),     nodename.clone());
    fields.insert("hostname".into(),     nodename);
    fields.insert("argv".into(),         argv);
    fields.insert("ssh_connection".into(), ssh_conn.clone());
    fields.insert("ssh_conn".into(),     ssh_conn);
    fields.insert("ld_preload".into(),   ld_pre.clone());
    fields.insert("ld_pre".into(),       ld_pre);
    fields.insert("ld_lib".into(),       ld_lib);
    fields.insert("tty_name".into(),     tty.clone());
    fields.insert("tty".into(),          tty);
    fields.insert("cwd".into(),          cwd.clone());
    fields.insert("pwd".into(),          cwd);
    fields.insert("stdin".into(),        stdin);
    fields.insert("stdout".into(),       stdout);
    fields.insert("exe".into(),          exe);
    fields.insert("sa_family".into(),    family.to_string());
    fields.insert("family".into(),       family.to_string());
    fields.insert("sip".into(),          sinfo.local_addr);
    fields.insert("sport".into(),        sinfo.local_port);
    fields.insert("dip".into(),          sinfo.remote_addr);
    fields.insert("dport".into(),        sinfo.remote_port);
    fields.insert("pid_tree".into(),     pidtree.clone());
    fields.insert("pidtree".into(),      pidtree);
    fields.insert("socket_argv".into(),  socket_argv);

    Ok(Some(fields))
}
