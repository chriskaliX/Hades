//! Plugin-side transport client (fd 3 / 4 pipe, length-prefixed protobuf).
//!
//! Mirrors Go's `SDK/go/transport/client/`.

use crossbeam::channel::{select, tick};
use log::{debug, info};
use parking_lot::Mutex;
use prost::Message;
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Error, ErrorKind, Read, Write},
    os::unix::prelude::FromRawFd,
    sync::Arc,
    thread,
    time::Duration,
};
use coarsetime::Updater;

use super::protocol::{Record, Task};

#[cfg(feature = "debug")]
use std::collections::BTreeMap;

#[cfg(feature = "debug")]
const READ_PIPE_FD: i32 = 0;
#[cfg(not(feature = "debug"))]
const READ_PIPE_FD: i32 = 3;
#[cfg(feature = "debug")]
const WRITE_PIPE_FD: i32 = 1;
#[cfg(not(feature = "debug"))]
const WRITE_PIPE_FD: i32 = 4;

#[derive(Clone)]
pub struct Client {
    writer: Arc<Mutex<BufWriter<File>>>,
    reader: Arc<Mutex<BufReader<File>>>,
}

impl Client {
    pub fn new(ignore_terminate: bool) -> Self {
        let writer = Arc::new(Mutex::new(BufWriter::with_capacity(512 * 1024, unsafe {
            File::from_raw_fd(WRITE_PIPE_FD)
        })));
        let reader = Arc::new(Mutex::new(BufReader::new(unsafe {
            File::from_raw_fd(READ_PIPE_FD)
        })));
        let writer_c = writer.clone();
        thread::spawn(move || {
            let ticker = tick(Duration::from_millis(200));
            loop {
                select! {
                    recv(ticker) -> _ => {
                        if writer_c.lock().flush().is_err() {
                            break;
                        }
                    }
                }
            }
        });
        if ignore_terminate {
            let mut signals = Signals::new(&[SIGTERM, SIGINT]).unwrap();
            thread::spawn(move || {
                for sig in signals.forever() {
                    if sig == SIGTERM || sig == SIGINT {
                        info!("received signal: {:?}, wait 3 secs to exit", sig);
                        thread::sleep(Duration::from_secs(3));
                        unsafe {
                            libc::close(WRITE_PIPE_FD);
                            libc::close(READ_PIPE_FD);
                        }
                        break;
                    }
                }
            });
        }
        Self { writer, reader }
    }

    pub fn send_record(&mut self, rec: &Record) -> Result<(), Error> {
        let mut w = self.writer.lock();
        #[cfg(not(feature = "debug"))]
        {
            let payload = rec.encode_to_vec();
            w.write_all(&(payload.len() as u32).to_le_bytes())?;
            w.write_all(&payload)
        }
        #[cfg(feature = "debug")]
        {
            w.write_all(b"{\"data_type\":")?;
            w.write_all(rec.data_type.to_string().as_bytes())?;
            w.write_all(b",\"timestamp\":")?;
            w.write_all(rec.timestamp.to_string().as_bytes())?;
            let fields: BTreeMap<_, _> = rec
                .data
                .as_ref()
                .map(|p| p.fields.iter().collect())
                .unwrap_or_default();
            w.write_all(b",\"data\":")?;
            serde_json::to_writer(w.by_ref(), &fields)?;
            w.write_all(b"}\n")
        }
    }

    pub fn send_records(&mut self, recs: &[Record]) -> Result<(), Error> {
        let mut w = self.writer.lock();
        #[cfg(not(feature = "debug"))]
        {
            for rec in recs {
                let payload = rec.encode_to_vec();
                w.write_all(&(payload.len() as u32).to_le_bytes())?;
                w.write_all(&payload)?;
            }
            Ok(())
        }
        #[cfg(feature = "debug")]
        {
            for rec in recs {
                w.write_all(b"{\"data_type\":")?;
                w.write_all(rec.data_type.to_string().as_bytes())?;
                w.write_all(b",\"timestamp\":")?;
                w.write_all(rec.timestamp.to_string().as_bytes())?;
                w.write_all(b",\"data\":")?;
                let fields: BTreeMap<_, _> = rec
                    .data
                    .as_ref()
                    .map(|p| p.fields.iter().collect())
                    .unwrap_or_default();
                serde_json::to_writer(w.by_ref(), &fields)?;
                w.write_all(b"}\n")?;
            }
            Ok(())
        }
    }

    pub fn receive(&mut self) -> Result<Task, Error> {
        let mut r = self.reader.lock();
        let mut bytes = [0u8; 4];
        r.read_exact(&mut bytes)?;
        let length = u32::from_le_bytes(bytes);
        let mut buf = vec![0u8; length as usize];
        r.read_exact(&mut buf)?;
        Task::decode(buf.as_slice())
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))
    }

    pub async fn receive_async(&mut self) -> Result<Task, Error> {
        let reader = self.reader.clone();
        tokio::task::spawn_blocking(move || {
            let mut r = reader.lock();
            let mut bytes = [0u8; 4];
            r.read_exact(&mut bytes)?;
            let length = u32::from_le_bytes(bytes);
            let mut buf = vec![0u8; length as usize];
            r.read_exact(&mut buf)?;
            Task::decode(buf.as_slice())
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))
        })
        .await?
    }

    pub fn raw_write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.writer.lock().write_all(buf)
    }

    pub fn raw_flush(&mut self) -> Result<(), Error> {
        self.writer.lock().flush()
    }

    pub fn enable_updater(&mut self, mills: u64) -> Result<Updater, Error> {
        Updater::new(mills).start()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.raw_flush();
        let trd = thread::current();
        debug!(
            "has dropped client from thread, id: {:?}, name: {:?}",
            trd.id(),
            trd.name()
        );
    }
}
