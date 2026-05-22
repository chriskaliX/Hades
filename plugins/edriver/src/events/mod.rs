use anyhow::Result;

use crate::cache::Transformer;

pub mod common;
// probe: process_exec.h
mod exec;
// probe: process_exploit.h
mod exploit;
// probe: process_file.h
mod file;
// probe: process_honeypot.h
mod honeypot;
// probe: process_net.h
mod net;
// probe: process_privilege.h
mod privilege;
// probe: process_rootkit.h
mod rootkit;
// probe: process_uprobe.h
mod uprobe;

pub use common::{Fields, EDEFAULT, ENOTFOUND, ERATELIMIT};

type ParserFn = fn(&[u8], &mut Transformer) -> Result<Option<Fields>>;

const EVENT_PARSERS: &[(u32, ParserFn)] = &[
    // process_exploit.h
    (614, exploit::parse_exploit_basic),
    (1020, exploit::parse_exploit_basic),
    (1021, exploit::parse_exploit_basic),
    // process_exec.h
    (700, exec::parse_execve),
    // process_privilege.h
    (1011, privilege::parse_commit_creds),
    // process_net.h
    (1022, net::parse_sys_connect),
    (1024, net::parse_socket_bind),
    (1025, net::parse_udp_recvmsg),
    // process_rootkit.h
    (1026, rootkit::parse_do_init_module),
    (1027, rootkit::parse_kernel_read_file),
    (1030, rootkit::parse_call_usermodehelper),
    (1200, rootkit::parse_anti_rkt_sct),
    (1202, rootkit::parse_anti_rkt_fops),
    (1203, rootkit::parse_anti_rkt_module),
    // process_file.h
    (1028, file::parse_inode_create),
    (1029, file::parse_sb_mount),
    (1031, file::parse_inode_rename),
    (1032, file::parse_inode_link),
    // process_uprobe.h
    (2000, uprobe::parse_bash_readline),
    // process_honeypot.h
    (3000, honeypot::parse_honeypot_portscan),
];

pub fn parse_event(data_type: u32, data: &[u8], trans: &mut Transformer) -> Result<Option<Fields>> {
    match EVENT_PARSERS.iter().find(|(t, _)| *t == data_type) {
        Some((_, parser)) => parser(data, trans),
        None => Ok(None),
    }
}
