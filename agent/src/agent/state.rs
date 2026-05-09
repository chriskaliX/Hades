use parking_lot::Mutex;
use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::LazyLock;

const MAX_ERRORS: usize = 10;
const MAX_ERROR_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(u8)]
pub enum State { #[default] Running = 0, Abnormal = 1 }

impl State {
    fn from_u8(v: u8) -> Self {
        if v == 0 { State::Running } else { State::Abnormal }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            State::Running  => "running",
            State::Abnormal => "abnormal",
        })
    }
}

// current is written on every gRPC command received – use atomics to avoid lock contention.
static CURRENT: AtomicU8 = AtomicU8::new(0);
// errors is written only on abnormal paths; separate lock avoids blocking CURRENT reads.
static ERRORS: LazyLock<Mutex<VecDeque<String>>> = LazyLock::new(Default::default);

pub fn set_running() {
    CURRENT.store(State::Running as u8, Ordering::Relaxed);
    ERRORS.lock().clear();
}

pub fn set_abnormal(err: impl Into<String>) {
    CURRENT.store(State::Abnormal as u8, Ordering::Relaxed);
    let mut err = err.into();
    if err.len() > MAX_ERROR_SIZE { err.truncate(MAX_ERROR_SIZE); }
    let mut errors = ERRORS.lock();
    if errors.len() == MAX_ERRORS { errors.pop_front(); }
    errors.push_back(err);
}

pub fn get() -> (String, String) {
    let current = State::from_u8(CURRENT.load(Ordering::Relaxed));
    let errors = ERRORS.lock().iter().cloned().collect::<Vec<_>>();
    let errs = serde_json::to_string(&errors).unwrap_or_default();
    (current.to_string(), errs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Global statics are shared across parallel tests — serialize with a lock.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn state_from_u8() {
        assert_eq!(State::from_u8(0), State::Running);
        assert_eq!(State::from_u8(1), State::Abnormal);
        assert_eq!(State::from_u8(255), State::Abnormal); // any non-zero → Abnormal
    }

    #[test]
    fn set_running_clears_errors() {
        let _g = TEST_LOCK.lock().unwrap();
        set_abnormal("boom");
        set_running();
        let (state, errs) = get();
        assert_eq!(state, "running");
        assert_eq!(errs, "[]");
    }

    #[test]
    fn set_abnormal_accumulates() {
        let _g = TEST_LOCK.lock().unwrap();
        set_running();
        set_abnormal("err1");
        set_abnormal("err2");
        let (state, errs) = get();
        assert_eq!(state, "abnormal");
        let parsed: Vec<String> = serde_json::from_str(&errs).unwrap();
        assert_eq!(parsed, ["err1", "err2"]);
    }

    #[test]
    fn bounded_error_queue() {
        let _g = TEST_LOCK.lock().unwrap();
        set_running();
        for i in 0..=MAX_ERRORS {
            set_abnormal(format!("err{i}"));
        }
        let (_, errs) = get();
        let parsed: Vec<String> = serde_json::from_str(&errs).unwrap();
        assert_eq!(parsed.len(), MAX_ERRORS);
        assert_eq!(parsed[0], "err1"); // err0 evicted (oldest)
    }

    #[test]
    fn error_size_truncation() {
        let _g = TEST_LOCK.lock().unwrap();
        set_running();
        set_abnormal("x".repeat(MAX_ERROR_SIZE + 100));
        let (_, errs) = get();
        let parsed: Vec<String> = serde_json::from_str(&errs).unwrap();
        assert_eq!(parsed[0].len(), MAX_ERROR_SIZE);
    }
}
