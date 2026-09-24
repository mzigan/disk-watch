use crate::{
    config::Temperature,
    devices::{Device, Kind},
    smart::{SelfTestStatus, Snapshot},
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: u64,
    pub severity: Severity,
    pub disk: Option<Device>,
    pub category: String,
    pub message: String,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl Event {
    pub fn new(
        severity: Severity,
        disk: Option<&Device>,
        category: &str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: now(),
            severity,
            disk: disk.cloned(),
            category: category.into(),
            message: message.into(),
        }
    }
    pub fn log(&self) {
        let disk = self.disk.as_ref();
        let model = disk.map(|d| d.model.as_str()).unwrap_or("unknown");
        let serial = disk.map(|d| d.serial.as_str()).unwrap_or("");
        let device = disk.map(|d| d.path.as_str()).unwrap_or("uncorrelated");
        // Debug-format external text so control characters cannot forge journal lines.
        match self.severity {
            Severity::Info => {
                tracing::info!(severity="INFO", disk=?model, serial=?serial, device=?device, category=%self.category, message=?self.message)
            }
            Severity::Warning => {
                tracing::warn!(severity="WARNING", disk=?model, serial=?serial, device=?device, category=%self.category, message=?self.message)
            }
            Severity::Critical => {
                tracing::error!(severity="CRITICAL", disk=?model, serial=?serial, device=?device, category=%self.category, message=?self.message)
            }
        }
    }
}
pub fn counter_severity(key: &str) -> Severity {
    match key {
        "Current_Pending_Sector"
        | "Offline_Uncorrectable"
        | "Reported_Uncorrect"
        | "media_errors" => Severity::Critical,
        _ => Severity::Warning,
    }
}
pub fn diff(
    device: &Device,
    old: Option<&Snapshot>,
    new: &Snapshot,
    hot: &mut bool,
    cfg: &Temperature,
) -> Vec<Event> {
    let mut events = Vec::new();
    let mut emit = |s, key: &str, msg| events.push(Event::new(s, Some(device), key, msg));
    for (key, value) in &new.counters {
        if new.stale_fields.contains(key) {
            continue;
        }
        let before = old.and_then(|o| o.counters.get(key)).copied().unwrap_or(0);
        if *value > before {
            emit(
                counter_severity(key),
                key,
                format!("{key} changed {before} -> {value}"),
            );
        } else if *value < before {
            emit(
                Severity::Info,
                key,
                format!("{key} decreased {before} -> {value}; counter reset or recovery"),
            );
        }
    }
    let checks = [
        (
            "overall_health",
            new.passed.map(|p| !p),
            old.and_then(|s| s.passed).map(|p| !p),
            Severity::Critical,
        ),
        (
            "critical_warning",
            new.critical_warning.map(|n| n != 0),
            old.and_then(|s| s.critical_warning).map(|n| n != 0),
            Severity::Critical,
        ),
        (
            "prefailure",
            new.prefailure,
            old.and_then(|s| s.prefailure),
            Severity::Critical,
        ),
        (
            "self_test",
            new.self_test_status.and_then(test_failed),
            old.and_then(|s| s.self_test_status).and_then(test_failed),
            Severity::Warning,
        ),
        (
            "available_spare",
            new.available_spare
                .zip(new.spare_threshold)
                .map(|(a, b)| a < b),
            old.and_then(|s| s.available_spare.zip(s.spare_threshold).map(|(a, b)| a < b)),
            Severity::Warning,
        ),
        (
            "percentage_used",
            new.percentage_used.map(|n| n >= 100),
            old.and_then(|s| s.percentage_used.map(|n| n >= 100)),
            Severity::Warning,
        ),
        (
            "remaining_life",
            new.remaining_life.map(|n| n <= 10),
            old.and_then(|s| s.remaining_life.map(|n| n <= 10)),
            Severity::Warning,
        ),
    ];
    for (key, current, previous, severity) in checks {
        if new.stale_fields.contains(key)
            || (key == "overall_health" && new.stale_fields.contains("passed"))
            || (key == "self_test" && new.stale_fields.contains("self_test_status"))
        {
            continue;
        }
        if current == Some(true) && previous != Some(true) {
            emit(
                severity,
                key,
                format!(
                    "{key}: unhealthy; self-test={:?}, NVMe warning={:?}",
                    new.self_test, new.critical_warning
                ),
            );
        } else if current == Some(false) && previous == Some(true) {
            emit(Severity::Info, key, format!("{key}: returned to normal"));
        }
    }
    if new.critical_warning.is_some_and(|n| n != 0)
        && old.is_some_and(|s| {
            s.critical_warning.is_some_and(|n| n != 0) && s.critical_warning != new.critical_warning
        })
    {
        emit(
            Severity::Critical,
            "critical_warning",
            format!(
                "NVMe critical warning changed to {:?}",
                new.critical_warning
            ),
        );
    }
    if new.self_test_status == Some(SelfTestStatus::Passed)
        && old.is_some_and(|s| {
            s.self_test != new.self_test || s.self_test_hours != new.self_test_hours
        })
        && old.and_then(|s| s.self_test_status) != Some(SelfTestStatus::Failed)
    {
        emit(
            Severity::Info,
            "self_test",
            "self-test completed successfully".into(),
        );
    }
    for (key, value, before) in [
        (
            "past_threshold",
            new.exit.past_threshold,
            old.is_some_and(|s| s.exit.past_threshold),
        ),
        (
            "error_log",
            new.exit.error_log,
            old.is_some_and(|s| s.exit.error_log),
        ),
        (
            "self_test_log",
            new.exit.self_test_log,
            old.is_some_and(|s| s.exit.self_test_log),
        ),
    ] {
        if value && !before {
            emit(
                Severity::Warning,
                key,
                format!("SMART historical indication: {key}"),
            );
        }
    }
    let threshold = match device.kind {
        Kind::Hdd => cfg.hdd_warning,
        Kind::Ssd => cfg.ssd_warning,
        Kind::Nvme => cfg.nvme_warning,
    };
    if let Some(t) = new
        .temperature
        .filter(|_| !new.stale_fields.contains("temperature"))
    {
        if !*hot && t >= threshold {
            *hot = true;
            emit(
                Severity::Warning,
                "temperature",
                format!("temperature {t} C >= {threshold} C"),
            );
        } else if *hot && t <= threshold - cfg.hysteresis {
            *hot = false;
            emit(
                Severity::Info,
                "temperature",
                format!("temperature recovered: {t} C"),
            );
        }
    }
    events
}

fn test_failed(status: SelfTestStatus) -> Option<bool> {
    match status {
        SelfTestStatus::Passed => Some(false),
        SelfTestStatus::Failed => Some(true),
        _ => None,
    }
}
