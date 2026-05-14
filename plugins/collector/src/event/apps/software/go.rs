use crate::event::apps::{AppProc, IApp};
use std::collections::HashMap;
use std::io::Read;

pub struct Golang {
    version: String,
}

impl Golang {
    pub fn new() -> Self { Golang { version: String::new() } }
}

impl IApp for Golang {
    fn name(&self)     -> &'static str { "golang" }
    fn app_type(&self) -> &'static str { "software" }
    fn version(&self)  -> &str         { &self.version }

    /// Detect a Go-compiled binary by scanning for the build-info magic bytes
    /// and extracting the embedded Go toolchain version (e.g. "1.21.3").
    /// Reads only the first 16 KB — the go.buildinfo section always appears
    /// near the start of the binary.
    fn matches(&mut self, p: &AppProc) -> bool {
        if p.exe.is_empty() { return false; }
        match std::fs::File::open(&p.exe) {
            Ok(f) => {
                let mut buf = vec![0u8; 16384];
                let n = std::io::BufReader::new(f).read(&mut buf).unwrap_or(0);
                if let Some(ver) = extract_go_version(&buf[..n]) {
                    self.version = ver;
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    fn run(&mut self, _p: &AppProc) -> anyhow::Result<HashMap<String, String>> {
        // Version populated in matches(); nothing extra to collect.
        Ok(HashMap::new())
    }
}

/// Scan `buf` for `\xff Go buildinf:`, then look for `go1.` immediately after
/// to extract the embedded Go toolchain version string.
/// Returns `Some(version)` on detection (version may be empty if not parseable),
/// `None` if the binary is not a Go binary.
fn extract_go_version(buf: &[u8]) -> Option<String> {
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    let pos = buf.windows(MAGIC.len()).position(|w| w == MAGIC)?;
    // After the 14-byte magic there is a 2-byte flags word and two pointer-sized
    // words.  The Go version string "go1.X.Y" follows shortly after as a
    // length-prefixed (varint) inline string.  Rather than parsing the full
    // binary format, scan forward for the literal "go1." which is reliable.
    let after = &buf[pos + MAGIC.len()..];
    if let Some(v_pos) = after.windows(4).position(|w| w == b"go1.") {
        let slice = &after[v_pos..];
        let end = slice.iter()
            .position(|&b| !(0x20..=0x7e).contains(&b))
            .unwrap_or(slice.len())
            .min(32); // version strings are never this long
        let ver = std::str::from_utf8(&slice[..end]).unwrap_or("");
        // Strip leading "go" to get "1.X.Y"
        return Some(ver.trim_start_matches("go").to_owned());
    }
    // Magic found but version string not in first 16 KB — still a Go binary.
    Some(String::new())
}
