mod hades_skel {
    include!("../bpf/hades.skel.rs");
}

use crate::cache::Transformer;

use anyhow::Result;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub mod execve;
pub trait Event {
    fn parse(data: &[u8], trans: &mut Transformer) -> Result<HashMap<String, String>>;
}

pub struct SocketInfo {
    pub local_addr: String,
    pub local_port: String,
    pub remote_addr: String,
    pub remote_port: String,
}

impl Default for SocketInfo {
    fn default() -> Self {
        SocketInfo {
            local_addr: "-1".to_string(),
            local_port: "-1".to_string(),
            remote_addr: "-1".to_string(),
            remote_port: "-1".to_string(),
        }
    }
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

fn parse_sinfo(data: &[u8], offset: &mut usize, family: u16) -> Result<SocketInfo> {
    let mut sinfo = SocketInfo::default();

    match family {
        2 => {
            sinfo.local_addr = parse_addr_v4(data, offset)?.to_string();
            sinfo.local_port = parse_u16_be(data, offset)?.to_string();
            *offset += 2;
            sinfo.remote_addr = parse_addr_v4(data, offset)?.to_string();
            sinfo.remote_port = parse_u16_be(data, offset)?.to_string();
            *offset += 2;
            Ok(sinfo)
        }
        10 => {
            sinfo.local_addr = parse_addr_v6(data, offset)?.to_string();
            sinfo.local_port = parse_u16_be(data, offset)?.to_string();
            *offset += 2;
            sinfo.remote_addr = parse_addr_v6(data, offset)?.to_string();
            sinfo.remote_port = parse_u16_be(data, offset)?.to_string();
            *offset += 2;
            Ok(sinfo)
        }
        _ => Ok(sinfo),
    }
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

fn parse_addr_v6(data: &[u8], offset: &mut usize) -> Result<Ipv6Addr> {
    let mut addr = [0; 16];
    for i in 0..16 {
        addr[i] = data[*offset + i];
    }
    *offset += 16;
    Ok(Ipv6Addr::from(addr))
}

fn parse_addr_v4(data: &[u8], offset: &mut usize) -> Result<Ipv4Addr> {
    Ok(Ipv4Addr::from(parse_u32_be(data, offset)?))
}
