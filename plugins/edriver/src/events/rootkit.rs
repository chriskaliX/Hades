use anyhow::Result;

use crate::cache::Transformer;

use super::common::{Decoder, Fields, EDEFAULT};

// Corresponds to BPF probe: process_rootkit.h
// Events: 1026 (DO_INIT_MODULE), 1027 (KERNEL_READ_FILE), 1030 (CALL_USERMODEHELPER),
//         1200 (ANTI_RKT_SCT), 1202 (ANTI_RKT_FOPS), 1203 (ANTI_RKT_MODULE)

pub fn parse_do_init_module(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("modname".into(), dec.string()?);
    m.insert("exe".into(), dec.string()?);
    Ok(Some(m))
}

pub fn parse_kernel_read_file(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("typeid".into(), dec.i32()?.to_string());
    m.insert("filename".into(), dec.string()?);
    Ok(Some(m))
}

pub fn parse_call_usermodehelper(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("path".into(), dec.string()?);
    m.insert("argv".into(), dec.string()?);
    m.insert("wait".into(), dec.i32()?.to_string());
    Ok(Some(m))
}

pub fn parse_anti_rkt_sct(data: &[u8], trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let index = dec.u64()?;
    let addr = dec.u64()?;

    if trans.ksym_cache.contains_addr(addr) {
        return Ok(None);
    }

    let mut m = Fields::new();
    m.insert("index".into(), index.to_string());
    m.insert("addr".into(), addr.to_string());
    Ok(Some(m))
}

pub fn parse_anti_rkt_fops(data: &[u8], _trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let mut m = Fields::new();
    m.insert("mask".into(), dec.i32()?.to_string());
    m.insert("path".into(), dec.string()?);
    Ok(Some(m))
}

pub fn parse_anti_rkt_module(data: &[u8], trans: &mut Transformer) -> Result<Option<Fields>> {
    let mut dec = Decoder::new(data);
    let iter_count = dec.u64()?;
    let name = dec.string()?;

    let summary = match trans.module_scan_cache.observe(iter_count, &name) {
        Some(v) => v,
        None => return Ok(None),
    };

    if summary.kernel_count == summary.user_count && summary.hidden_modules == EDEFAULT {
        return Ok(None);
    }

    let mut m = Fields::new();
    m.insert("iter_count".into(), summary.iter_count.to_string());
    m.insert("kernel_count".into(), summary.kernel_count.to_string());
    m.insert("user_count".into(), summary.user_count.to_string());
    m.insert("hidden_modules".into(), summary.hidden_modules);
    Ok(Some(m))
}
