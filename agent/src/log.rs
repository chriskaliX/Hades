/// Two-sink logger, mirrors Go's setup in agent/main.go + agent/log/log.go:
///
///   file sink   (Info+)  → SDK Logger, rolling file under log/hades.log
///   remote sink (Error+) → trans().transmission(Record{ data_type: 1010 })
///                          same as Go's GrpcWriter → transport.Trans.Transmission
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use log::{LevelFilter, Log, Metadata, Record, SetLoggerError};
use sdk::logger::{Config, Logger as SdkLogger};

use crate::{
    proto::{Payload, Record as ProtoRecord},
    transport::transfer::trans,
};

pub struct Logger {
    file:         SdkLogger,
    remote_level: LevelFilter,
}

impl Logger {
    fn new() -> Self {
        Self {
            file: SdkLogger::new(Config {
                max_size:     1024 * 1024, // 1 MiB, same as Go
                path:         format!("{}hades.log", crate::agent::LOGHOME).into(),
                file_level:   LevelFilter::Info,
                remote_level: LevelFilter::Off, // SDK remote disabled; we handle it below
                max_backups:  10,
                compress:     true,
                client:       None,
            }),
            remote_level: LevelFilter::Error,
        }
    }
}

impl Log for Logger {
    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        meta.level() <= LevelFilter::Info || meta.level() <= self.remote_level
    }

    fn log(&self, record: &Record<'_>) {
        // ── file sink ────────────────────────────────────────────────────────
        self.file.log(record);

        // ── remote sink (Go: GrpcWriter → transport.Trans.Transmission) ──────
        if record.level() <= self.remote_level {
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let rec = ProtoRecord {
                data_type: 1010,
                timestamp: ts,
                data: Some(Payload {
                    fields: HashMap::from([
                        ("level".into(),  record.level().as_str().to_owned()),
                        ("target".into(), record.target().to_owned()),
                        ("file".into(),   record.file().unwrap_or("").to_owned()),
                        ("line".into(),   record.line().unwrap_or(0).to_string()),
                        ("msg".into(),    record.args().to_string()),
                    ]),
                }),
            };
            let _ = trans().transmission(rec, false);
        }
    }

    fn flush(&self) {
        self.file.flush();
    }
}

pub fn init() -> Result<(), SetLoggerError> {
    log::set_max_level(LevelFilter::Info);
    log::set_boxed_logger(Box::new(Logger::new()))
}
