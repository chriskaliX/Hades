use anyhow::Result;
use async_trait::async_trait;
use log::{error, info};
use sdk::{Client, Payload, Record, Task, TaskCmd};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::time;

const TASK_ACK_DATA_TYPE: i32 = 5100;

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
    /// Mirrors Go's EventManager.Schedule() + taskResolve().
    pub async fn schedule(self, client: Client) {
        let mut handles: HashMap<i32, Handle> = HashMap::new();
        let mut joins = Vec::new();

        for (mut ev, ivl) in self.entries {
            let dt  = ev.data_type();
            let imm = ev.immediately();
            let mut c = client.clone();

            let handle = match ev.flag() {
                // ── Trigger ────────────────────────────────────────────────
                // capacity-1 channel: try_send() succeeds if idle (or one already queued),
                // fails if busy — mirrors Go's done-channel semaphore + 3 s timeout.
                EventMode::Trigger => {
                    let (tx, mut rx) = mpsc::channel::<()>(1);
                    joins.push(tokio::spawn(async move {
                        while rx.recv().await.is_some() {
                            if let Err(e) = ev.run(&mut c).await {
                                error!("[{}] triggered: {e:#}", ev.name());
                            }
                        }
                    }));
                    Handle::Trigger(tx)
                }

                // ── Periodic ───────────────────────────────────────────────
                // Tick loop; interval hot-updatable via watch channel (0 = stop).
                EventMode::Periodic => {
                    let (tx, mut rx) = watch::channel(ivl);
                    joins.push(tokio::spawn(async move {
                        let name = ev.name();
                        if imm {
                            info!("{name} first run");
                            if let Err(e) = ev.run(&mut c).await { error!("[{name}] first run: {e:#}"); }
                        }
                        if ivl.is_zero() { return; }
                        let mut ticker = time::interval(ivl);
                        if imm { ticker.tick().await; } // skip the immediate-fire tick
                        loop {
                            tokio::select! {
                                _ = ticker.tick() => {
                                    if let Err(e) = ev.run(&mut c).await { error!("[{name}] periodic: {e:#}"); }
                                }
                                Ok(()) = rx.changed() => {
                                    let d = *rx.borrow_and_update();
                                    if d.is_zero() { info!("[{name}] stopped"); return; }
                                    ticker = time::interval(d);
                                    info!("[{name}] interval → {}m", d.as_secs() / 60);
                                }
                            }
                        }
                    }));
                    Handle::Interval(tx)
                }

                // ── Realtime ───────────────────────────────────────────────
                // Runs until natural exit; watch channel delivers restart (>0) or stop (0).
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
    /// Trigger: capacity-1 channel; try_send = fire-or-busy.
    Trigger(mpsc::Sender<()>),
    /// Periodic / Realtime: watch sender; ZERO duration = stop.
    Interval(watch::Sender<Duration>),
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
        let (status, msg) = match handle_task(&handles, task) {
            Ok(())   => ("success".to_owned(), String::new()),
            Err(msg) => ("failed".to_owned(),  msg),
        };
        let _ = client.send_record(&ack_record(token, status, msg));
    }
}

fn handle_task(handles: &HashMap<i32, Handle>, task: Task) -> Result<(), String> {
    match handles.get(&task.data_type) {
        None => Err(format!("{} is invalid", task.data_type)),
        Some(Handle::Trigger(tx)) => tx.try_send(())
            .map_err(|e| format!("trigger failed: {e}")),
        Some(Handle::Interval(tx)) => {
            let mins: u64 = task.data.parse()
                .map_err(|_| format!("invalid interval: '{}'", task.data))?;
            tx.send(Duration::from_secs(mins * 60))
                .map_err(|_| "event stopped".to_owned())
        }
    }
}

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
