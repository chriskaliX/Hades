use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Field value that indicates "empty / not applicable"
pub const EDEFAULT: &str = "-1";
/// Field value that indicates an I/O or resource-not-found error
pub const ENOTFOUND: &str = "-3";
/// Field value that indicates the read was dropped due to rate-limiting
pub const ERATELIMIT: &str = "-4";

pub type Fields = HashMap<String, String>;

#[derive(Default)]
pub struct SocketInfo {
    pub local_addr: String,
    pub local_port: String,
    pub remote_addr: String,
    pub remote_port: String,
}

/// Cursor-based binary decoder, analogous to Go's `EbpfDecoder`.
pub struct Decoder<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Decoder { data, cursor: 0 }
    }

    #[inline]
    fn check(&self, n: usize) -> Result<()> {
        if self.cursor + n > self.data.len() {
            Err(anyhow!(
                "buffer too short: need {} bytes at offset {}, have {}",
                n,
                self.cursor,
                self.data.len()
            ))
        } else {
            Ok(())
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.check(1)?;
        let v = self.data[self.cursor];
        self.cursor += 1;
        Ok(v)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.check(2)?;
        let v = u16::from_ne_bytes(self.data[self.cursor..self.cursor + 2].try_into()?);
        self.cursor += 2;
        Ok(v)
    }

    pub fn u16_be(&mut self) -> Result<u16> {
        self.check(2)?;
        let v = u16::from_be_bytes(self.data[self.cursor..self.cursor + 2].try_into()?);
        self.cursor += 2;
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.check(4)?;
        let v = u32::from_ne_bytes(self.data[self.cursor..self.cursor + 4].try_into()?);
        self.cursor += 4;
        Ok(v)
    }

    pub fn u32_be(&mut self) -> Result<u32> {
        self.check(4)?;
        let v = u32::from_be_bytes(self.data[self.cursor..self.cursor + 4].try_into()?);
        self.cursor += 4;
        Ok(v)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.check(8)?;
        let v = u64::from_ne_bytes(self.data[self.cursor..self.cursor + 8].try_into()?);
        self.cursor += 8;
        Ok(v)
    }

    pub fn i32(&mut self) -> Result<i32> {
        self.check(4)?;
        let v = i32::from_ne_bytes(self.data[self.cursor..self.cursor + 4].try_into()?);
        self.cursor += 4;
        Ok(v)
    }

    pub fn i64(&mut self) -> Result<i64> {
        self.check(8)?;
        let v = i64::from_ne_bytes(self.data[self.cursor..self.cursor + 8].try_into()?);
        self.cursor += 8;
        Ok(v)
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.check(n)?;
        self.cursor += n;
        Ok(())
    }

    /// Decode a length-prefixed string (4-byte LE length header).
    pub fn string(&mut self) -> Result<String> {
        self.check(4)?;
        let size = u32::from_ne_bytes(self.data[self.cursor..self.cursor + 4].try_into()?) as usize;
        self.cursor += 4;
        self.check(size)?;
        let s = String::from_utf8_lossy(&self.data[self.cursor..self.cursor + size])
            .trim_end_matches('\0')
            .to_owned();
        self.cursor += size;
        if s.is_empty() {
            Ok(EDEFAULT.to_owned())
        } else {
            Ok(s)
        }
    }

    pub fn addr_v4(&mut self) -> Result<Ipv4Addr> {
        Ok(Ipv4Addr::from(self.u32_be()?))
    }

    pub fn addr_v6(&mut self) -> Result<Ipv6Addr> {
        self.check(16)?;
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[self.cursor..self.cursor + 16]);
        self.cursor += 16;
        Ok(Ipv6Addr::from(addr))
    }

    /// Decode a socket address pair (local + remote) for the given `family` (2=IPv4, 10=IPv6).
    pub fn socket_info(&mut self, family: u16) -> Result<SocketInfo> {
        let mut sinfo = SocketInfo::default();
        match family {
            2 => {
                sinfo.local_addr = self.addr_v4()?.to_string();
                sinfo.local_port = self.u16_be()?.to_string();
                self.skip(2)?;
                sinfo.remote_addr = self.addr_v4()?.to_string();
                sinfo.remote_port = self.u16_be()?.to_string();
                self.skip(2)?;
            }
            10 => {
                sinfo.local_addr = self.addr_v6()?.to_string();
                sinfo.local_port = self.u16_be()?.to_string();
                self.skip(2)?;
                sinfo.remote_addr = self.addr_v6()?.to_string();
                sinfo.remote_port = self.u16_be()?.to_string();
                self.skip(2)?;
            }
            _ => {}
        }
        Ok(sinfo)
    }

    /// Decode both IPv4 and IPv6 socket info consecutively.
    pub fn sock_pair(&mut self) -> Result<(SocketInfo, SocketInfo)> {
        let v4 = self.socket_info(2)?;
        let v6 = self.socket_info(10)?;
        Ok((v4, v6))
    }
}
