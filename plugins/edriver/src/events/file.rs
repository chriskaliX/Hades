use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields};

// Corresponds to BPF probe: process_file.h
// Events: 1028 (INODE_CREATE), 1029 (SB_MOUNT), 1031 (INODE_RENAME), 1032 (INODE_LINK)

pub fn parse_inode_create(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    // file_emit_common: pid(u32), tgid(u32), comm(str), exe(str), then p0/p1/p2 as void*.
    // For SECURITY_INODE_CREATE: p0=filename, p1=&family (u16*→void*), p2=&sinfo (struct*→void*).
    // Because p1 and p2 are passed as void* through file_emit_common, EVT_WRITE_AUTO serialises
    // them via _EVT_WRITE_STR (length-prefixed string), not as raw integers/structs.
    // The resulting bytes are not usable as structured socket info; consume them as strings.
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("pid".into(), dec.u32()?.to_string());
    m.insert("tgid".into(), dec.u32()?.to_string());
    m.insert("comm".into(), dec.string()?);
    m.insert("exe".into(), dec.string()?);
    m.insert("filename".into(), dec.string()?);
    let _family_raw = dec.string()?; // void*-encoded u16, not usable as integer
    let _sinfo_raw  = dec.string()?; // void*-encoded struct, not usable as socket info
    Ok(Some(m))
}

pub fn parse_sb_mount(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("dev_name".into(), dec.string()?);
    m.insert("path".into(), dec.string()?);
    m.insert("type".into(), dec.string()?);
    m.insert("flags".into(), dec.u64()?.to_string());
    m.insert("exe".into(), dec.string()?);
    let pidtree = dec.string()?;
    m.insert("pid_tree".into(), pidtree.clone());
    m.insert("pidtree".into(), pidtree);
    Ok(Some(m))
}

pub fn parse_inode_rename(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("pid".into(), dec.u32()?.to_string());
    m.insert("tgid".into(), dec.u32()?.to_string());
    m.insert("comm".into(), dec.string()?);
    m.insert("exe".into(), dec.string()?);
    m.insert("old".into(), dec.string()?);
    m.insert("new".into(), dec.string()?);
    Ok(Some(m))
}

pub fn parse_inode_link(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("pid".into(), dec.u32()?.to_string());
    m.insert("tgid".into(), dec.u32()?.to_string());
    m.insert("comm".into(), dec.string()?);
    m.insert("exe".into(), dec.string()?);
    m.insert("old".into(), dec.string()?);
    m.insert("new".into(), dec.string()?);
    Ok(Some(m))
}
