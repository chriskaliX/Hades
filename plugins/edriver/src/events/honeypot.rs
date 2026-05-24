use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields};

// Corresponds to BPF probe: process_honeypot.h
// Events: 3000 (HONEYPOT_PORTSCAN_DETECT)

pub fn parse_honeypot_portscan(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::with_capacity(8);

    let family = dec.u16()?;
    let proto = dec.u8()?;
    let (sinfo_v4, sinfo_v6) = dec.sock_pair()?;
    let sinfo = if family == 10 { sinfo_v6 } else { sinfo_v4 };

    m.insert("family".into(), family.to_string());
    m.insert("protocol".into(), proto.to_string());
    m.insert("sport".into(), sinfo.local_port);
    m.insert("dport".into(), sinfo.remote_port);
    m.insert("sip".into(), sinfo.local_addr);
    m.insert("dip".into(), sinfo.remote_addr);
    Ok(Some(m))
}
