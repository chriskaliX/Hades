mod hades_skel {
    include!("../bpf/hades.skel.rs");
}

use self::hades_skel::hades_rodata_types::hds_socket_info;
use anyhow::Result;
use std::collections::HashMap;

pub mod execve;
pub trait Event {
    fn parse(data: &[u8]) -> Result<HashMap<String, String>>;
}

/* parse functions */
fn parse_str(data: &[u8], offset: &mut usize) -> Result<String> {
    let size = u32::from_ne_bytes(data[*offset..(*offset + 4)].try_into()?) as usize;
    let mut v = String::from_utf8_lossy(&data[(*offset + 4)..(*offset + 4 + size)])
        .to_string()
        .trim_end_matches('\0')
        .to_owned();
    *offset += 4 + size;
    if v.is_empty() {
        v = "-1".to_string();
    }
    Ok(v)
}

fn parse_path(data: &[u8], offset: &mut usize) -> Result<String> {
    let pre_path = parse_str(data, offset)?;
    match pre_path.as_str() {
        "pipe:" | "socket:" => {
            let node = parse_u64(data, offset)?;
            Ok(format!("{}:[{}]", pre_path, node.to_string()))
        }
        "" => Ok("-1".to_string()),
        _ => Ok(pre_path),
    }
}

fn parse_sinfo(data: &[u8], offset: &mut usize) -> Result<hds_socket_info> {
    let mut sinfo = hds_socket_info::default();
    sinfo.family = parse_u32(data, offset)? as u16;
    sinfo.local_address = parse_u32_be(data, offset)?;
    sinfo.local_port = parse_u16_be(data, offset)?;
    parse_u16(data, offset)?;
    sinfo.remote_address = parse_u32_be(data, offset)?;
    sinfo.remote_port = parse_u16_be(data, offset)? as u16;
    parse_u16(data, offset)?;
    Ok(sinfo)
}

fn parse_u16(data: &[u8], offset: &mut usize) -> Result<u16> {
    let v = u16::from_ne_bytes(data[*offset..(*offset + 2)].try_into()?) as usize;
    *offset += 2;
    Ok(v as u16)
}

fn parse_u16_be(data: &[u8], offset: &mut usize) -> Result<u16> {
    let v = u16::from_be_bytes(data[*offset..(*offset + 2)].try_into()?) as usize;
    *offset += 2;
    Ok(v as u16)
}

fn parse_u32(data: &[u8], offset: &mut usize) -> Result<u32> {
    let v = u32::from_ne_bytes(data[*offset..(*offset + 4)].try_into()?) as usize;
    *offset += 4;
    Ok(v as u32)
}

fn parse_u32_be(data: &[u8], offset: &mut usize) -> Result<u32> {
    let v = u32::from_be_bytes(data[*offset..(*offset + 4)].try_into()?) as usize;
    *offset += 4;
    Ok(v as u32)
}

fn parse_u64(data: &[u8], offset: &mut usize) -> Result<u64> {
    let v = u32::from_ne_bytes(data[*offset..(*offset + 8)].try_into()?) as usize;
    *offset += 8;
    Ok(v as u64)
}
