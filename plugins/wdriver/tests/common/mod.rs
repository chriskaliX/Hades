use std::{
    io::{self, BufReader, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    sync::OnceLock,
    thread,
    time::Duration,
};

use prost::Message;
use wdriver::protocol::{Record, Task};

pub struct TaskResult {
    pub records: Vec<Record>,
    pub ack: Record,
}

pub struct PluginHarness {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Record>,
}

impl PluginHarness {
    pub fn new() -> Self {
        let mut child = Command::new(binary_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn wdriver");
        let stdin = child.stdin.take().expect("missing stdin");
        let stdout = child.stdout.take().expect("missing stdout");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            while let Ok(record) = read_record(&mut reader) {
                if tx.send(record).is_err() {
                    break;
                }
            }
        });
        Self { child, stdin, rx }
    }

    pub fn send_task(&mut self, task: &Task) {
        let payload = task.encode_to_vec();
        self.stdin
            .write_all(&(payload.len() as u32).to_le_bytes())
            .expect("write task length");
        self.stdin.write_all(&payload).expect("write task payload");
        self.stdin.flush().expect("flush task payload");
    }

    pub fn collect_until_ack(&self, token: &str, timeout: Duration) -> TaskResult {
        let mut records = Vec::new();
        loop {
            let record = self
                .rx
                .recv_timeout(timeout)
                .expect("timed out waiting for plugin record");
            if is_ack_for(&record, token) {
                return TaskResult { records, ack: record };
            }
            records.push(record);
        }
    }

    pub fn collect_until_data_type(&self, data_type: i32, timeout: Duration) -> Record {
        loop {
            let record = self
                .rx
                .recv_timeout(timeout)
                .expect("timed out waiting for plugin data record");
            if record.data_type == data_type {
                return record;
            }
        }
    }

    pub fn shutdown(mut self) {
        let task = Task {
            data_type: 0,
            object_name: String::new(),
            data: String::new(),
            token: "shutdown".to_string(),
        };
        self.send_task(&task);
        let _ = self.collect_until_ack("shutdown", Duration::from_secs(5));
        let _ = self.child.wait();
    }
}

fn binary_path() -> PathBuf {
    static BIN_PATH: OnceLock<PathBuf> = OnceLock::new();
    BIN_PATH
        .get_or_init(|| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let exe = manifest_dir.join("target").join("debug").join(if cfg!(windows) {
                "wdriver.exe"
            } else {
                "wdriver"
            });
            if !exe.exists() {
                let status = Command::new("cargo")
                    .args(["build", "--bin", "wdriver"])
                    .current_dir(&manifest_dir)
                    .status()
                    .expect("build wdriver binary");
                assert!(status.success(), "failed to build wdriver binary for tests");
            }
            exe
        })
        .clone()
}

fn is_ack_for(record: &Record, token: &str) -> bool {
    if record.data_type != 5100 {
        return false;
    }
    record
        .data
        .as_ref()
        .and_then(|payload| payload.fields.get("token"))
        .map(|value| value == token)
        .unwrap_or(false)
}

fn read_record(reader: &mut BufReader<impl Read>) -> io::Result<Record> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Record::decode(payload.as_slice()).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub fn ack_status(record: &Record) -> String {
    record
        .data
        .as_ref()
        .and_then(|payload| payload.fields.get("status"))
        .cloned()
        .unwrap_or_default()
}
