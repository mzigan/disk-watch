use crate::{
    alert::{Event, Severity, now},
    devices::{Device, nonzero_wwn},
    smart::{SelfTestStatus, Snapshot},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    #[default]
    Never,
    Checked,
    Partial,
    Sleeping,
    Failed,
    StaleRace,
    Disabled,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiskState {
    pub device: Device,
    pub present: bool,
    pub snapshot: Option<Snapshot>,
    pub checked_at: Option<u64>,
    pub hot: bool,
    pub smart_error: Option<String>,
    #[serde(default)]
    pub check_status: CheckStatus,
    pub kernel_severity: Option<Severity>,
    pub kernel_last_message: Option<String>,
    pub kernel_last_seen: Option<u64>,
}
impl DiskState {
    pub fn new(device: Device) -> Self {
        Self {
            device,
            present: true,
            snapshot: None,
            checked_at: None,
            hot: false,
            smart_error: None,
            check_status: CheckStatus::Never,
            kernel_severity: None,
            kernel_last_message: None,
            kernel_last_seen: None,
        }
    }
    pub fn severity(&self) -> Severity {
        let mut severity = self.kernel_severity.unwrap_or(Severity::Info);
        if self.hot || self.smart_error.is_some() {
            severity = severity.max(Severity::Warning);
        }
        if let Some(s) = &self.snapshot {
            if s.passed == Some(false)
                || s.critical_warning.is_some_and(|n| n != 0)
                || s.prefailure == Some(true)
            {
                severity = Severity::Critical;
            }
            for (key, n) in &s.counters {
                if *n > 0 {
                    severity = severity.max(crate::alert::counter_severity(key));
                }
            }
            if s.self_test_status == Some(SelfTestStatus::Failed)
                || s.exit.past_threshold
                || s.exit.error_log
                || s.exit.self_test_log
                || s.percentage_used.is_some_and(|n| n >= 100)
                || s.remaining_life.is_some_and(|n| n <= 10)
                || s.available_spare
                    .zip(s.spare_threshold)
                    .is_some_and(|(a, b)| a < b)
            {
                severity = severity.max(Severity::Warning);
            }
        }
        severity
    }
    pub fn health(&self) -> &'static str {
        if self.kernel_severity == Some(Severity::Critical) {
            return "Critical";
        }
        let fresh_critical = matches!(
            self.check_status,
            CheckStatus::Checked | CheckStatus::Partial
        ) && self.snapshot.as_ref().is_some_and(|s| {
            (s.passed == Some(false) && !s.stale_fields.contains("passed"))
                || (s.prefailure == Some(true) && !s.stale_fields.contains("prefailure"))
                || (s.critical_warning.is_some_and(|n| n != 0)
                    && !s.stale_fields.contains("critical_warning"))
                || s.counters.iter().any(|(k, n)| {
                    *n > 0
                        && !s.stale_fields.contains(k)
                        && crate::alert::counter_severity(k) == Severity::Critical
                })
        });
        if fresh_critical {
            return "Critical";
        }
        if self.check_status != CheckStatus::Checked
            || self.snapshot.as_ref().is_none_or(Snapshot::unknown)
        {
            return "Unknown";
        }
        match self.severity() {
            Severity::Critical => "Critical",
            Severity::Warning => "Warning",
            Severity::Info => "OK",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    pub disks: BTreeMap<String, DiskState>,
    pub recent_alerts: Vec<Event>,
    pub kernel_cursor: Option<String>,
    #[serde(default)]
    pub kernel_boot_id: Option<String>,
    #[serde(default)]
    pub kernel_seen_cursors: VecDeque<String>,
    #[serde(default)]
    pub kernel_watermark: Option<u64>,
    pub notification_times: BTreeMap<String, u64>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            version: 2,
            disks: BTreeMap::new(),
            recent_alerts: vec![],
            kernel_cursor: None,
            kernel_boot_id: None,
            kernel_seen_cursors: VecDeque::new(),
            kernel_watermark: None,
            notification_times: BTreeMap::new(),
        }
    }
}
impl State {
    pub fn prepare_boot(&mut self, boot: Option<String>) {
        if self.kernel_boot_id != boot {
            self.kernel_cursor = None;
            self.kernel_watermark = None;
            self.kernel_seen_cursors.clear();
            self.kernel_boot_id = boot;
        }
    }
    pub fn accept_kernel(&mut self, record: &crate::kernel::Record) -> bool {
        if record.boot_id.is_some()
            && self.kernel_boot_id.is_some()
            && record.boot_id != self.kernel_boot_id
        {
            return false;
        }
        if record.cursor.as_ref().is_some_and(|c| {
            Some(c) == self.kernel_cursor.as_ref() || self.kernel_seen_cursors.contains(c)
        }) {
            return false;
        }
        if record
            .monotonic_usec
            .zip(self.kernel_watermark)
            .is_some_and(|(t, mark)| t < mark)
        {
            return false;
        }
        if let Some(c) = &record.cursor {
            self.kernel_cursor = Some(c.clone());
            self.kernel_seen_cursors.push_back(c.clone());
            if self.kernel_seen_cursors.len() > 2048 {
                self.kernel_seen_cursors.pop_front();
            }
        }
        if let Some(t) = record.monotonic_usec {
            self.kernel_watermark = Some(self.kernel_watermark.unwrap_or(0).max(t));
        }
        true
    }
    pub fn load(path: &Path) -> Self {
        match read(path) {
            Ok(state) => state,
            Err(e) => {
                tracing::warn!(error=%e, "cannot load state; starting empty");
                Self::default()
            }
        }
    }
    pub fn remember(&mut self, event: Event) {
        self.recent_alerts.push(event);
        if self.recent_alerts.len() > 100 {
            self.recent_alerts.remove(0);
        }
    }
    pub fn should_notify(&mut self, event: &Event, cooldown: u64) -> bool {
        let identity = event
            .disk
            .as_ref()
            .map(Device::key)
            .unwrap_or_else(|| "uncorrelated".into());
        let key = format!("{}:{identity}:{:?}", event.category, event.severity);
        let time = now();
        self.notification_times
            .retain(|_, t| time.saturating_sub(*t) < cooldown);
        if self.notification_times.contains_key(&key) {
            return false;
        }
        self.notification_times.insert(key, time);
        true
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = parent(path);
        fs::create_dir_all(parent)?;
        let temp = suffix(path, ".tmp");
        let result = (|| {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            serde_json::to_writer_pretty(&mut f, self)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
            fs::rename(&temp, path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn suffix(path: &Path, value: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(value);
    s.into()
}
pub fn lock(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::create_dir_all(parent(path))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(suffix(path, ".lock"))?;
    file.try_lock()
        .context("another disk-watch writer is running; use status instead")?;
    // Only the lock holder may remove a temp file left by a crashed process.
    match fs::remove_file(suffix(path, ".tmp")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(file)
}
pub fn read(path: &Path) -> Result<State> {
    let mut content = String::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_string(&mut content)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    }
    let mut value: serde_json::Value =
        serde_json::from_str(&content).context("corrupt state JSON")?;
    let version = value["version"].as_u64().unwrap_or(0);
    ensure!(
        version == 1 || version == 2,
        "unsupported state version {version}"
    );
    if version == 1 {
        // Preserve previous snapshots on upgrade, but do not claim old measurements are fresh.
        if let Some(disks) = value["disks"].as_object_mut() {
            for disk in disks.values_mut() {
                if let Some(snap) = disk["snapshot"].as_object_mut()
                    && let Some(failed) = snap.remove("self_test_failed").and_then(|v| v.as_bool())
                {
                    snap.insert(
                        "self_test_status".into(),
                        serde_json::json!(if failed { "Failed" } else { "Unknown" }),
                    );
                }
            }
        }
        value["version"] = serde_json::json!(2);
    }
    let mut state: State = serde_json::from_value(value).context("invalid state structure")?;
    state.disks.retain(|key, disk| {
        // Old versions could merge several disks under an all-zero WWN. Ownership
        // of that history cannot be recovered from the last device stored there.
        if key
            .strip_prefix("wwn:")
            .is_some_and(|wwn| nonzero_wwn(wwn).is_none())
        {
            tracing::warn!(disk = %key, "discarding shared history with unavailable WWN");
            return false;
        }
        disk.device.wwn = nonzero_wwn(&disk.device.wwn).unwrap_or_default().to_owned();
        if let Some(snapshot) = &mut disk.snapshot {
            snapshot.wwn = nonzero_wwn(&snapshot.wwn).unwrap_or_default().to_owned();
        }
        true
    });
    Ok(state)
}

/// One coalescing writer: at most one fsync in flight and one latest snapshot waiting.
/// Retrying failed writes never blocks kernel/SMART event handling.
pub async fn writer(path: PathBuf, rx: tokio::sync::watch::Receiver<State>) -> Result<()> {
    write_loop(rx, move |state| state.save(&path)).await
}
async fn write_loop<F>(mut rx: tokio::sync::watch::Receiver<State>, save: F) -> Result<()>
where
    F: Fn(State) -> Result<()> + Send + Sync + 'static,
{
    let save = std::sync::Arc::new(save);
    while rx.changed().await.is_ok() {
        loop {
            let snapshot = rx.borrow_and_update().clone();
            let save = save.clone();
            match tokio::task::spawn_blocking(move || save(snapshot))
                .await
                .context("state writer task panicked")?
            {
                Ok(()) => break,
                Err(e) => {
                    tracing::error!(error=%e, "state persistence failed");
                    if rx.has_changed().is_err() {
                        return Err(e);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod writer_tests {
    use super::*;
    #[tokio::test]
    async fn slow_writer_does_not_block_events_and_flushes_latest_on_close() {
        let (tx, rx) = tokio::sync::watch::channel(State::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started = std::sync::Mutex::new(Some(started_tx));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release = std::sync::Mutex::new(release_rx);
        let saved = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = saved.clone();
        let task = tokio::spawn(write_loop(rx, move |s| {
            if let Some(tx) = started.lock().unwrap().take() {
                tx.send(()).unwrap();
                release
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }
            observed.lock().unwrap().push(s.recent_alerts.len());
            Ok(())
        }));
        tx.send_replace(State::default());
        started_rx.await.unwrap();
        let mut latest = State::default();
        let (notifications, _) = tokio::sync::mpsc::channel(8);
        // Same event handler used by daemon, while its writer is blocked in a syscall.
        for _ in 0..3 {
            crate::apply_kernel(
                &mut latest,
                crate::kernel::parse(r#"{"MESSAGE":"I/O error, dev sdb"}"#).unwrap(),
                None,
                &crate::Config::default(),
                &notifications,
            );
            tx.send_replace(latest.clone());
        }
        assert_eq!(latest.recent_alerts.len(), 3);
        assert!(saved.lock().unwrap().is_empty());
        drop(tx);
        release_tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(*saved.lock().unwrap(), vec![0, 3]);
    }
}
