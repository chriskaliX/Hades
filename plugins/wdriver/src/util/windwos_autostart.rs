use std::{error::Error, process::Command};

use serde::Deserialize;
use serde_json::Value;
use winreg::enums::*;
use winreg::reg_key::RegKey;
use winreg::reg_value::RegValue;
use winreg::HKEY;

thread_local! {
    static UNINSTALLS: Option<RegKey> = None;
}

pub struct App {
    name: String,
    reg: RegValue,
}

pub struct ScheduledTaskApp {
    name: String,
    state: u32,
    last_time: u64,
    next_time: u64,
    command: String,
}

#[derive(Deserialize)]
struct ScheduledTaskRow {
    #[serde(rename = "TaskName")]
    task_name: String,
    #[serde(rename = "State")]
    state: u32,
    #[serde(rename = "LastTime")]
    last_time: String,
    #[serde(rename = "NextTime")]
    next_time: String,
    #[serde(rename = "TaskCommand")]
    task_command: String,
}

struct AppList {
    autostart: RegKey,
    index: usize,
}
impl Iterator for AppList {
    type Item = App;
    fn next(&mut self) -> Option<Self::Item> {
        let value_ = self.autostart.enum_values().nth(self.index)?.ok()?;
        self.index += 1;
        Some(App {
            name: value_.0,
            reg: value_.1,
        })
    }
}
impl AppList {
    fn new(hive: HKEY, path: &str) -> Result<Self, Box<dyn Error>> {
        let hive = RegKey::predef(hive);
        let autostart = hive.open_subkey(path)?;

        Ok(AppList {
            autostart,
            index: 0,
        })
    }
}
impl App {
    pub fn get_key(&self) -> String {
        self.name.to_string()
    }
    pub fn get_value(&self) -> String {
        self.reg.to_string()
    }
    pub fn list() -> Result<impl Iterator<Item = App>, Box<dyn Error>> {
        let system_apps = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        let system_apps_32 = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        let user_apps = AppList::new(
            HKEY_CURRENT_USER,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        // this one may not exist
        let user_apps_32 = AppList::new(
            HKEY_CURRENT_USER,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        )
        .ok()
        .into_iter()
        .flatten();
        let system_apps_runonce = AppList::new(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Runonce",
        )
        .ok()
        .into_iter()
        .flatten();

        let chain = system_apps
            .chain(system_apps_32)
            .chain(user_apps)
            .chain(user_apps_32)
            .chain(system_apps_runonce);

        Ok(chain)
    }
}

impl ScheduledTaskApp {
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_state(&self) -> u32 {
        self.state
    }

    pub fn get_last_time(&self) -> u64 {
        self.last_time
    }

    pub fn get_next_time(&self) -> u64 {
        self.next_time
    }

    pub fn get_command(&self) -> String {
        self.command.clone()
    }
}

pub fn list_task_scheduler() -> Result<Vec<ScheduledTaskApp>, Box<dyn Error>> {
    let script = r#"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object {
    $state = switch ($_.State.ToString()) {
        'Disabled' { 1 }
        'Queued' { 2 }
        'Ready' { 3 }
        'Running' { 4 }
        default { 0 }
    }

    $last = '0'
    if ($_.LastRunTime -and $_.LastRunTime -gt [datetime]::MinValue) {
        $last = ([uint32][Math]::Truncate($_.LastRunTime.ToOADate())).ToString()
    }

    $next = '0'
    if ($_.NextRunTime -and $_.NextRunTime -gt [datetime]::MinValue) {
        $next = ([uint32][Math]::Truncate($_.NextRunTime.ToOADate())).ToString()
    }

    $action = $_.Actions | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Execute) } | Select-Object -First 1
    $command = ''
    if ($action) {
        if ([string]::IsNullOrWhiteSpace($action.Arguments)) {
            $command = $action.Execute
        }
        else {
            $command = "$($action.Execute)&$($action.Arguments)"
        }
    }

    [PSCustomObject]@{
        TaskName = $_.TaskName
        State = $state
        LastTime = $last
        NextTime = $next
        TaskCommand = $command
    }
}

if ($null -eq $tasks) {
    '[]'
}
else {
    @($tasks) | ConvertTo-Json -Compress
}
"#;

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("query scheduled tasks failed: {}", stderr),
        )
        .into());
    }

    parse_scheduled_tasks_json(&String::from_utf8_lossy(&output.stdout))
}

fn parse_scheduled_tasks_json(raw: &str) -> Result<Vec<ScheduledTaskApp>, Box<dyn Error>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }

    let value: Value = serde_json::from_str(raw)?;
    let rows: Vec<ScheduledTaskRow> = match value {
        Value::Array(_) => serde_json::from_value(value)?,
        Value::Object(_) => vec![serde_json::from_value(value)?],
        _ => Vec::new(),
    };

    Ok(rows
        .into_iter()
        .filter(|row| !row.task_name.trim().is_empty())
        .map(|row| ScheduledTaskApp {
            name: row.task_name,
            state: row.state,
            last_time: row.last_time.parse::<u64>().unwrap_or(0),
            next_time: row.next_time.parse::<u64>().unwrap_or(0),
            command: row.task_command,
        })
        .collect())
}
