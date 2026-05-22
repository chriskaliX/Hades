use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields};

// Corresponds to BPF probe: process_privilege.h
// Events: 1011 (COMMIT_CREDS)

pub fn parse_commit_creds(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("pid".into(), dec.u32()?.to_string());
    m.insert("tgid".into(), dec.u32()?.to_string());
    m.insert("comm".into(), dec.string()?);
    let old_uid = dec.u32()?;
    let new_uid = dec.u32()?;
    m.insert("olduid".into(), old_uid.to_string());
    m.insert("newuid".into(), new_uid.to_string());
    m.insert("exe".into(), dec.string()?);
    let pidtree = dec.string()?;
    m.insert("pid_tree".into(), pidtree.clone());
    m.insert("pidtree".into(), pidtree);
    Ok(Some(m))
}
