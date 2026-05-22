use anyhow::Result;
use async_trait::async_trait;
use log::{error, info};
use sdk::{Client, Payload, Record, Task, TaskCmd};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::time;

const TASK_ACK_DATA_TYPE: i32 = 5100;
/// Maximum number of queued on-demand triggers per event before rejecting new ones.
const TRIGGER_CAPACITY: usize = 3;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventMode { Realtime, Periodic, Trigger }

#[async_trait]
pub trait IEvent: Send + Sync + 'static {
    fn name(&self)        -> &'static str;
    fn data_type(&self)   -> i32;
    fn flag(&self)        -> EventMode;
    fn immediately(&self) -> bool;
    async fn run(&mut self, client: &mut Client) -> Result<()>;
}

// ── EventManager ──────────────────────────────────────────────────────────────

pub struct EventManager { entries: Vec<(Box<dyn IEvent>, Duration)> }

impl EventManager {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn add_event<E: IEvent + 'static>(&mut self, event: E, interval: Duration) {
        info!("{} added, interval: {}m, mode: {}", event.name(), interval.as_secs() / 60,
            match event.flag() {
                EventMode::Realtime => "realtime",
                EventMode::Periodic => "periodic",
                EventMode::Trigger  => "trigger",
            });
        self.entries.push((Box::new(event), interval));
    }

    /// Schedule all events and start the task-resolve loop.
    pub async fn schedule(self, client: Client) {
        let mut handles: HashMap<i32, Handle> = HashMap::new();
        let mut joins = Vec::new();

        for (mut ev, ivl) in self.entries {
            let dt  = ev.data_type();
            let imm = ev.immediately();
            let mut c = client.clone();

            let handle = match ev.flag() {
                // ── Trigger ────────────────────────────────────────────────
                // Up to TRIGGER_CAPACITY tokens can be queued; try_send rejects
                // when full so callers get an immediate "busy" error.
                EventMode::Trigger => {
                    let (tx, mut rx) = mpsc::channel::<String>(TRIGGER_CAPACITY);
                    joins.push(tokio::spawn(async move {
                        while let Some(token) = rx.recv().await {
                            let (status, msg) = match ev.run(&mut c).await {
                                Ok(())  => ("success".to_owned(), String::new()),
                                Err(e)  => { error!("[{}] triggered: {e:#}", ev.name()); ("failed".to_owned(), e.to_string()) }
                            };
                            let _ = c.send_record(&ack_record(token, status, msg));
                        }
                    }));
                    Handle::Trigger(tx)
                }

                // ── Periodic ───────────────────────────────────────────────
                // Tick-based loop. An incoming task with empty data queues an
                // immediate run (token carried for completion ACK); a numeric
                // data payload changes the interval.
                EventMode::Periodic => {
                    let (trigger_tx, mut trigger_rx) = mpsc::channel::<String>(TRIGGER_CAPACITY);
                    let (ivl_tx, mut ivl_rx) = watch::channel(ivl);
                    joins.push(tokio::spawn(async move {
                        let name = ev.name();
                        if imm {
                            info!("{name} first run");
                            if let Err(e) = ev.run(&mut c).await { error!("[{name}] first run: {e:#}"); }
                        }
                        if ivl.is_zero() { return; }
                        let mut ticker = time::interval(ivl);
                        if imm { ticker.tick().await; } // consume the instant-fire tick
                        loop {
                            tokio::select! {
                                _ = ticker.tick() => {
                                    if let Err(e) = ev.run(&mut c).await { error!("[{name}] periodic: {e:#}"); }
                                }
                                Some(token) = trigger_rx.recv() => {
                                    info!("[{name}] triggered");
                                    let (status, msg) = match ev.run(&mut c).await {
                                        Ok(())  => ("success".to_owned(), String::new()),
                                        Err(e)  => { error!("[{name}] triggered: {e:#}"); ("failed".to_owned(), e.to_string()) }
                                    };
                                    let _ = c.send_record(&ack_record(token, status, msg));
                                }
                                Ok(()) = ivl_rx.changed() => {
                                    let d = *ivl_rx.borrow_and_update();
                                    if d.is_zero() { info!("[{name}] stopped"); return; }
                                    ticker = time::interval(d);
                                    info!("[{name}] interval → {}m", d.as_secs() / 60);
                                }
                            }
                        }
                    }));
                    Handle::Periodic(trigger_tx, ivl_tx)
                }

                // ── Realtime ───────────────────────────────────────────────
                // Runs until natural exit; watch channel delivers interval > 0
                // to restart or Duration::ZERO to stop.
                EventMode::Realtime => {
                    let (tx, mut rx) = watch::channel(Duration::from_secs(1));
                    joins.push(tokio::spawn(async move {
                        let name = ev.name();
                        loop {
                            if let Err(e) = ev.run(&mut c).await { error!("[{name}] realtime: {e:#}"); }
                            if rx.changed().await.is_err() { return; }
                            if rx.borrow_and_update().is_zero() { info!("[{name}] stopped"); return; }
                        }
                    }));
                    Handle::Interval(tx)
                }
            };
            handles.insert(dt, handle);
        }

        joins.push(tokio::spawn(task_resolve(client, handles)));
        for j in joins { let _ = j.await; }
    }
}

// ── Handle ────────────────────────────────────────────────────────────────────

enum Handle {
    /// On-demand only. Channel carries the task token for completion ACK.
    Trigger(mpsc::Sender<String>),
    /// Periodic tick + on-demand trigger. Empty task data = trigger now (token
    /// forwarded); numeric data = new interval in minutes.
    Periodic(mpsc::Sender<String>, watch::Sender<Duration>),
    /// Realtime loop. Send Duration::ZERO to stop, any positive value to restart.
    Interval(watch::Sender<Duration>),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ack_record(token: String, status: String, msg: String) -> Record {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    Record {
        data_type: TASK_ACK_DATA_TYPE,
        timestamp: ts,
        data: Some(Payload {
            fields: [("token", token), ("status", status), ("msg", msg)]
                .into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }),
    }
}

// ── task_resolve ──────────────────────────────────────────────────────────────

async fn task_resolve(mut client: Client, handles: HashMap<i32, Handle>) {
    loop {
        let task = match client.receive_async().await {
            Ok(t)  => t,
            Err(e) => { error!("task_resolve: {e:#}"); return; }
        };
        if matches!(TaskCmd::try_from(task.data_type), Ok(TaskCmd::TaskShutdown)) {
            info!("task_resolve: shutdown"); return;
        }
        let token = task.token.clone();
        match dispatch(&handles, task) {
            // ACK deferred: event task sends it after run() completes.
            Ok(true)  => {}
            // ACK now: interval change, no async work pending.
            Ok(false) => { let _ = client.send_record(&ack_record(token, "success".to_owned(), String::new())); }
            Err(msg)  => { let _ = client.send_record(&ack_record(token, "failed".to_owned(), msg)); }
        }
    }
}

/// Route the task to the appropriate handle.
///
/// Returns `Ok(true)`  — ACK deferred to the event task.
/// Returns `Ok(false)` — ACK from task_resolve (interval change).
/// Returns `Err(msg)`  — Failed; task_resolve sends a failed ACK.
fn dispatch(handles: &HashMap<i32, Handle>, task: Task) -> Result<bool, String> {
    match handles.get(&task.data_type) {
        None => Err(format!("data_type {} has no handler", task.data_type)),
        Some(Handle::Trigger(tx)) => {
            tx.try_send(task.token)
                .map(|_| true)
                .map_err(|e| format!("trigger busy: {e}"))
        }
        Some(Handle::Periodic(trigger_tx, ivl_tx)) => {
            if task.data.is_empty() {
                trigger_tx.try_send(task.token)
                    .map(|_| true)
                    .map_err(|e| format!("trigger busy: {e}"))
            } else {
                parse_mins(&task.data)
                    .and_then(|d| ivl_tx.send(d).map_err(|_| "event stopped".to_owned()))
                    .map(|_| false)
            }
        }
        Some(Handle::Interval(tx)) => {
            parse_mins(&task.data)
                .and_then(|d| tx.send(d).map_err(|_| "event stopped".to_owned()))
                .map(|_| false)
        }
    }
}

#[inline]
fn parse_mins(s: &str) -> Result<Duration, String> {
    s.parse::<u64>()
        .map(|m| Duration::from_secs(m * 60))
        .map_err(|_| format!("invalid interval: '{s}'"))
}
