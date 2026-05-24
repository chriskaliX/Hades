use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields, EDEFAULT};

// Corresponds to BPF probe: process_net.h
// Events: 1022 (SYSCONNECT), 1024 (SOCKET_BIND), 1025 (UDP_RECVMSG)

pub fn parse_sys_connect(data: &[u8], trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::with_capacity(8);

    let fd = dec.i32()?;
    let family = dec.u16()?;
    let ret = dec.i64()?;
    let (sinfo_v4, sinfo_v6) = dec.sock_pair()?;
    let exe = dec.string()?;
    let sinfo = if family == 10 { sinfo_v6 } else { sinfo_v4 };

    let key = format!(
        "{}:{}->{}:{}",
        sinfo.local_addr, sinfo.local_port, sinfo.remote_addr, sinfo.remote_port
    );
    if trans.connect_ttl_cache.contains_key(&key) {
        return Ok(None);
    }
    trans.connect_ttl_cache.insert(key, ());

    m.insert("fd".into(), fd.to_string());
    m.insert("family".into(), family.to_string());
    m.insert("ret".into(), ret.to_string());
    m.insert("sport".into(), sinfo.local_port);
    m.insert("dport".into(), sinfo.remote_port);
    m.insert("sip".into(), sinfo.local_addr);
    m.insert("dip".into(), sinfo.remote_addr);
    m.insert("exe".into(), exe);
    Ok(Some(m))
}

pub fn parse_socket_bind(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::with_capacity(8);

    let family = dec.u16()?;
    m.insert("family".into(), family.to_string());

    if family == 2 {
        let port = dec.u16_be()?;
        let addr = dec.addr_v4()?.to_string();
        dec.skip(8)?;
        m.insert("local_port".into(), port.to_string());
        m.insert("local_addr".into(), addr);
    } else if family == 10 {
        let port = dec.u16_be()?;
        dec.skip(4)?;
        let addr = dec.addr_v6()?.to_string();
        dec.skip(4)?;
        m.insert("local_port".into(), port.to_string());
        m.insert("local_addr".into(), addr);
    }

    m.insert("exe".into(), dec.string()?);
    m.insert("protocol".into(), dec.u16()?.to_string());
    Ok(Some(m))
}

pub fn parse_udp_recvmsg(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::with_capacity(8);

    let family = dec.u16()?;
    let ret = dec.i64()?;
    let (sinfo_v4, sinfo_v6) = dec.sock_pair()?;
    let sinfo = if family == 10 { sinfo_v6 } else { sinfo_v4 };

    m.insert("family".into(), family.to_string());
    m.insert("ret".into(), ret.to_string());
    m.insert("opcode".into(), EDEFAULT.into());
    m.insert("rcode".into(), EDEFAULT.into());
    m.insert("qtype".into(), EDEFAULT.into());
    m.insert("atype".into(), EDEFAULT.into());
    m.insert("dns_data".into(), EDEFAULT.into());
    m.insert("sport".into(), sinfo.local_port);
    m.insert("dport".into(), sinfo.remote_port);
    m.insert("sip".into(), sinfo.local_addr);
    m.insert("dip".into(), sinfo.remote_addr);
    Ok(Some(m))
}
