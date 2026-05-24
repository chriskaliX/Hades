use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use prost::Message;

use crate::protocol::{Record, Task};

const MAX_FRAME_SIZE: usize = 1024 * 1024;

pub struct Client {
    reader: BufReader<io::Stdin>,
    writer: RecordWriter,
}

#[derive(Clone)]
pub struct RecordWriter {
    writer: Arc<Mutex<BufWriter<io::Stdout>>>,
}

impl Client {
    pub fn new() -> Self {
        Self {
            reader: BufReader::with_capacity(1024 * 1024, io::stdin()),
            writer: RecordWriter {
                writer: Arc::new(Mutex::new(BufWriter::with_capacity(
                    512 * 1024,
                    io::stdout(),
                ))),
            },
        }
    }

    pub fn send_record(&mut self, rec: &Record) -> io::Result<()> {
        self.writer.send_record(rec)
    }

    pub fn record_writer(&self) -> RecordWriter {
        self.writer.clone()
    }

    pub fn receive_task(&mut self) -> io::Result<Task> {
        let mut len = [0u8; 4];
        self.reader.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len == 0 || len > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid task frame size",
            ));
        }
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Task::decode(buf.as_slice()).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
}

impl RecordWriter {
    pub fn send_record(&self, rec: &Record) -> io::Result<()> {
        let payload = rec.encode_to_vec();
        if payload.len() > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record frame too large",
            ));
        }
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "record writer lock poisoned"))?;
        writer.write_all(&(payload.len() as u32).to_le_bytes())?;
        writer.write_all(&payload)?;
        writer.flush()
    }
}

pub fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
