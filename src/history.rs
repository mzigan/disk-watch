//! Small, independent time series. Only the state writer/check may write it.
use crate::{alert::now, state::State};
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::{
    fs::OpenOptions as FileOptions,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Sample {
    pub timestamp: u64,
    pub temperature: Option<i64>,
    pub measured_at: Option<u64>,
    pub health: String,
    pub present: bool,
}
pub fn path(state_path: &Path) -> PathBuf {
    state_path.with_file_name("history.db")
}

/// Called after a successful state save, outside the monitoring event loop.
/// No duplicate samples on cursor-only writes, restart, or unchanged sleeping checks.
pub fn record(path: &Path, state: &State, timestamp: u64) -> Result<()> {
    let _file = FileOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let mut db = Connection::open(path).context("open history database")?;
    db.busy_timeout(Duration::from_millis(250))?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS samples (
        seq INTEGER PRIMARY KEY, identity TEXT NOT NULL, timestamp INTEGER NOT NULL,
        checked_at INTEGER, temperature INTEGER, health TEXT NOT NULL, present INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS samples_disk_time ON samples(identity, timestamp, seq);",
    )?;
    let tx = db.transaction()?;
    for (identity, disk) in &state.disks {
        let health = disk.health();
        let previous: Option<(Option<u64>, String, bool)> = tx.query_row(
            "SELECT checked_at, health, present FROM samples WHERE identity=?1 ORDER BY timestamp DESC, seq DESC LIMIT 1",
            [identity], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        if previous.as_ref().is_some_and(|(checked, h, present)| {
            *checked == disk.checked_at && h == health && *present == disk.present
        }) {
            continue;
        }
        // Do not invent old measurements when first encountering absent disks.
        if previous.is_none() && !disk.present {
            continue;
        }
        let temperature = disk
            .snapshot
            .as_ref()
            .filter(|s| {
                disk.checked_at.is_some()
                    && previous
                        .as_ref()
                        .is_none_or(|(checked, _, _)| *checked != disk.checked_at)
                    && disk.present
                    && disk.check_status == crate::state::CheckStatus::Checked
                    && !s.stale_fields.contains("temperature")
            })
            .and_then(|s| s.temperature);
        tx.execute("INSERT INTO samples(identity,timestamp,checked_at,temperature,health,present) VALUES (?1,?2,?3,?4,?5,?6)",
            params![identity, timestamp, disk.checked_at, temperature, health, disk.present])?;
    }
    tx.commit()?;
    Ok(())
}

/// Read-only open: never creates a DB, schema, WAL, or state lock.
/// Includes one sample before the range for health continuity, with its real time.
pub fn query(path: &Path, identity: &str, since: u64, until: u64) -> Result<Vec<Sample>> {
    if !path.try_exists()? {
        return Ok(vec![]);
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_millis(250))?;
    let mut stmt = db.prepare("SELECT timestamp,temperature,health,present,checked_at FROM samples
        WHERE identity=?1 AND timestamp<=?3 AND (timestamp>=?2 OR seq=(
            SELECT seq FROM samples WHERE identity=?1 AND timestamp<?2 ORDER BY timestamp DESC,seq DESC LIMIT 1))
        ORDER BY timestamp,seq")?;
    let rows = stmt.query_map(params![identity, since, until], |r| {
        Ok(Sample {
            timestamp: r.get(0)?,
            temperature: r.get(1)?,
            health: r.get(2)?,
            present: r.get(3)?,
            measured_at: r.get(4)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("read history samples")
}
pub fn record_after_save(state_path: &Path, state: &State) {
    if let Err(e) = record(&path(state_path), state, now()) {
        tracing::warn!(error=%e, "history persistence failed; state remains saved");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        devices::{Device, Kind},
        smart::Snapshot,
        state::{CheckStatus, DiskState},
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!(
                "disk-watch-history-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn state() -> State {
        let device = Device {
            path: "/dev/sdb".into(),
            model: "Test".into(),
            serial: "A".into(),
            wwn: String::new(),
            kind: Kind::Hdd,
            aliases: vec![],
            diskseq: None,
            discovered_at: 0,
            wd_usb: false,
        };
        let mut disk = DiskState::new(device);
        disk.snapshot = Some(Snapshot {
            passed: Some(true),
            temperature: Some(30),
            ..Snapshot::default()
        });
        disk.check_status = CheckStatus::Checked;
        disk.checked_at = Some(100);
        State {
            disks: std::collections::BTreeMap::from([(disk.device.key(), disk)]),
            ..State::default()
        }
    }
    #[test]
    fn temperature_query_is_identity_and_time_bounded_and_deduplicated() {
        let tmp = Temp::new();
        let p = tmp.0.join("history.db");
        let mut state = state();
        let id = state.disks.keys().next().unwrap().clone();
        record(&p, &state, 100).unwrap();
        record(&p, &state, 101).unwrap();
        let disk = state.disks.get_mut(&id).unwrap();
        disk.checked_at = Some(200);
        disk.snapshot.as_mut().unwrap().temperature = Some(35);
        record(&p, &state, 200).unwrap();
        let rows = query(&p, &id, 150, 250).unwrap();
        assert_eq!(rows.len(), 2); // lead-in + range
        assert_eq!(rows[0].temperature, Some(30));
        assert_eq!(rows[1].temperature, Some(35));
        assert_eq!(rows[1].measured_at, Some(200));
        assert!(query(&p, "other identity", 0, 999).unwrap().is_empty());
        assert_eq!(query(&p, &id, 0, 150).unwrap().len(), 1);
    }
    #[test]
    fn timeline_records_kernel_recovery_without_erasing_critical() {
        let tmp = Temp::new();
        let p = tmp.0.join("history.db");
        let mut state = state();
        let id = state.disks.keys().next().unwrap().clone();
        state.disks.get_mut(&id).unwrap().kernel_current_severity = Some(crate::Severity::Critical);
        record(&p, &state, 100).unwrap();
        state.disks.get_mut(&id).unwrap().kernel_recovery_successes = 3;
        record(&p, &state, 200).unwrap();
        let rows = query(&p, &id, 0, 300).unwrap();
        assert_eq!(
            rows.iter().map(|s| s.health.as_str()).collect::<Vec<_>>(),
            ["Critical", "OK"]
        );
        assert_eq!(rows[1].temperature, None); // recovery is not a new temperature measurement
        state.disks.get_mut(&id).unwrap().present = false;
        record(&p, &state, 300).unwrap();
        assert!(!query(&p, &id, 0, 400).unwrap().last().unwrap().present);
    }
    #[test]
    fn reading_model_and_history_never_mutates_files_or_creates_missing_db() {
        let tmp = Temp::new();
        let state = state();
        let state_path = tmp.0.join("state.json");
        state.save(&state_path).unwrap();
        let before = std::fs::read(&state_path).unwrap();
        let p = path(&state_path);
        assert!(query(&p, "id", 0, 500).unwrap().is_empty());
        assert!(!p.exists());
        record(&p, &state, 100).unwrap();
        let db_before = std::fs::read(&p).unwrap();
        let id = state.disks.keys().next().unwrap();
        let _ = query(&p, id, 0, 500).unwrap();
        let _ = crate::state::read(&state_path).unwrap();
        assert_eq!(std::fs::read(&state_path).unwrap(), before);
        assert_eq!(std::fs::read(&p).unwrap(), db_before);
        let mut names: Vec<_> = std::fs::read_dir(&tmp.0)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2);
    }
}
