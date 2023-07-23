use anyhow::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct IpConfig {
    pub subnet: IpAddr,
    pub prefixlen: u32,
}

impl IpConfig {
    pub fn new(address: &str) -> Result<Self> {
        let address_p;
        let mut mask = 128;
        if address.contains('/') {
            let parts: Vec<&str> = address.split('/').collect();
            address_p = parts[0].to_string();
            mask = parts[1].replace('/', "").parse()?;
        } else {
            address_p = address.to_string();
        }

        let subnet: IpAddr = if address_p.contains(':') {
            let ipv6 = address_p.parse::<Ipv6Addr>()?;
            IpAddr::V6(ipv6)
        } else {
            if mask != 128 {
                mask += 96;
            }
            let ipv4 = address_p.parse::<Ipv4Addr>()?;
            IpAddr::V4(ipv4)
        };

        if mask > 128 {
            return Err(Error::msg("Invalid mask"));
        }

        Ok(Self {
            subnet,
            prefixlen: mask,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ip_config() {
        let ip_config = IpConfig::new("192.168.1.1/24").unwrap();
        let ip = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
        assert_eq!(ip_config.subnet, ip);
        assert_eq!(ip_config.prefixlen, 24 + 96);

        let ip_config = IpConfig::new("192.168.1.1/36");
        assert_eq!(ip_config.is_err(), true);

        let ip_config = IpConfig::new("::ffff:c0a8:101/120").unwrap();
        let ip = "::ffff:c0a8:101".parse::<Ipv6Addr>().unwrap();
        assert_eq!(ip_config.subnet, ip);
        assert_eq!(ip_config.prefixlen, 120);
    }
}
