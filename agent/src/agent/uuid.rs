const HARDWARE_PLACEHOLDERS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000",
    "03000200-0400-0500-0006-000700080009",
    "03020100-0504-0706-0809-0a0b0c0d0e0f",
    "10000000-0000-8000-0040-000000000000",
];

#[cfg(not(windows))]
pub fn gen_uuid() -> uuid::Uuid {
    let mut source: Vec<u8> = Vec::new();
    if let Some(id) = read_id_bytes("/var/lib/cloud/data/instance-id") {
        source.extend_from_slice(&id);
    }
    if let Some(id) = read_id_bytes("/sys/class/dmi/id/product_uuid") {
        let s = String::from_utf8_lossy(&id);
        if !HARDWARE_PLACEHOLDERS.contains(&s.as_ref()) {
            source.extend_from_slice(&id);
        }
    }
    if let Some(mac) = read_id_bytes("/sys/class/net/eth0/address") {
        source.extend_from_slice(&mac);
    }
    if source.len() > 8 {
        return uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, &source);
    }
    if let Some(id) = read_uuid_file("/etc/machine-id") { return id; }
    if let Some(id) = read_uuid_file(super::MACHINE_ID) { return id; }
    uuid::Uuid::new_v4()
}

#[cfg(windows)]
pub fn gen_uuid() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

fn read_uuid_file(path: &str) -> Option<uuid::Uuid> {
    let content = std::fs::read(path).ok()?;
    let trimmed = std::str::from_utf8(&content).ok()?.trim();
    uuid::Uuid::parse_str(trimmed).ok()
}

fn read_id_bytes(path: &str) -> Option<Vec<u8>> {
    let content = std::fs::read(path).ok()?;
    let start = content.iter().position(|b| !b.is_ascii_whitespace())?;
    let end   = content.iter().rposition(|b| !b.is_ascii_whitespace())?;
    let trimmed = &content[start..=end];
    if trimmed.len() < 6 { return None; }
    Some(trimmed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_id_bytes_trims_whitespace() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"  abcdefgh  \n").unwrap();
        assert_eq!(read_id_bytes(f.path().to_str().unwrap()).unwrap(), b"abcdefgh");
    }

    #[test]
    fn read_id_bytes_too_short_returns_none() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap(); // < 6 bytes
        assert!(read_id_bytes(f.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn read_id_bytes_missing_file_returns_none() {
        assert!(read_id_bytes("/nonexistent/path/abc123").is_none());
    }

    #[test]
    fn read_uuid_file_valid() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let s = "550e8400-e29b-41d4-a716-446655440000";
        f.write_all(s.as_bytes()).unwrap();
        assert_eq!(read_uuid_file(f.path().to_str().unwrap()).unwrap().to_string(), s);
    }

    #[test]
    fn read_uuid_file_strips_whitespace() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"  550e8400-e29b-41d4-a716-446655440000\n").unwrap();
        assert!(read_uuid_file(f.path().to_str().unwrap()).is_some());
    }

    #[test]
    fn read_uuid_file_invalid_returns_none() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"not-a-valid-uuid").unwrap();
        assert!(read_uuid_file(f.path().to_str().unwrap()).is_none());
    }

    #[test]
    fn gen_uuid_is_not_nil() {
        assert_ne!(gen_uuid(), uuid::Uuid::nil());
    }
}
