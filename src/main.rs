mod alert;
mod config;
mod devices;
mod kernel;
mod notifier;
mod smart;
mod state;

use alert::{Event, Severity, now};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use devices::{Device, nonzero_wwn};
use state::{DiskState, State};
use std::{collections::BTreeSet, path::PathBuf, time::Duration};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(version, about = "Linux SMART and kernel I/O health monitor")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true, default_value = "/var/lib/disk-watch/state.json")]
    state: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    Daemon,
    Check,
    Devices,
    Status {
        /// Include detailed disk status and recent events after the summary.
        #[arg(long)]
        verbose: bool,
        /// Compatibility with the previous explicit summary mode.
        #[arg(long, hide = true, conflicts_with = "verbose")]
        summary: bool,
    },
}
enum Scan {
    Inventory(Vec<Device>),
    Disk(Device, Result<smart::Reading>),
    DiscoveryFailed(String),
}
async fn scan(cfg: &Config, tx: &mpsc::Sender<Scan>) -> Result<()> {
    let devices = devices::discover(cfg.command_timeout_seconds).await?;
    tx.send(Scan::Inventory(devices.clone()))
        .await
        .context("scan receiver closed")?;
    if !cfg.smart.enabled {
        return Ok(());
    }
    let mut pending = devices
        .into_iter()
        .filter(|d| d.serial.is_empty() || !cfg.devices.ignore_serials.contains(&d.serial));
    let mut checks = tokio::task::JoinSet::new();
    loop {
        while checks.len() < 3 {
            let Some(d) = pending.next() else {
                break;
            };
            let timeout = cfg.command_timeout_seconds;
            let skip = cfg.smart.skip_sleeping;
            checks.spawn(async move {
                let result = smart::read(&d, timeout, skip).await;
                (d, result)
            });
        }
        let Some(result) = checks.join_next().await else {
            break;
        };
        let (device, snapshot) = result.context("SMART task panicked")?;
        tx.send(Scan::Disk(device, snapshot))
            .await
            .context("scan receiver closed")?;
    }
    Ok(())
}
fn publish(state: &mut State, tx: &mpsc::Sender<Event>, event: Event, notify: bool) {
    event.log();
    if notify && event.severity != Severity::Info && tx.try_send(event.clone()).is_err() {
        tracing::warn!("notification queue full or unavailable; event remains in journal");
    }
    state.remember(event);
}
fn apply_inventory(state: &mut State, devices: &[Device], cfg: &Config, tx: &mpsc::Sender<Event>) {
    let mut events = vec![];
    let mut present = BTreeSet::new();
    for device in devices
        .iter()
        .filter(|d| d.serial.is_empty() || !cfg.devices.ignore_serials.contains(&d.serial))
    {
        present.insert(device.key());
        let entry = state.disks.entry(device.key()).or_insert_with(|| {
            events.push(Event::new(
                Severity::Info,
                Some(device),
                "discovery",
                "new disk discovered",
            ));
            if device.serial.is_empty() && nonzero_wwn(&device.wwn).is_none() {
                events.push(Event::new(
                    Severity::Warning,
                    Some(device),
                    "identity",
                    "no serial or WWN: identity depends on device path",
                ));
            }
            DiskState::new(device.clone())
        });
        if !entry.present {
            events.push(Event::new(
                Severity::Info,
                Some(device),
                "discovery",
                "disk reappeared",
            ));
        }
        entry.present = true;
        entry.device = device.clone();
        if !cfg.smart.enabled {
            entry.check_status = state::CheckStatus::Disabled;
        }
    }
    for (key, entry) in &mut state.disks {
        if entry.present && !present.contains(key) {
            entry.present = false;
            events.push(Event::new(
                Severity::Info,
                Some(&entry.device),
                "discovery",
                "disk disappeared",
            ));
        }
    }
    for event in events {
        publish(state, tx, event, true);
    }
}
fn apply_result(
    state: &mut State,
    device: Device,
    result: Result<smart::Reading>,
    cfg: &Config,
    tx: &mpsc::Sender<Event>,
) -> bool {
    use state::CheckStatus;
    let entry = state
        .disks
        .entry(device.key())
        .or_insert_with(|| DiskState::new(device.clone()));
    entry.device = device.clone();
    entry.present = true;
    let mut events = vec![];
    let mut race = false;
    match result {
        Ok(smart::Reading::Checked(mut snapshot)) => {
            let changed = smart::identity_mismatch(&device, &snapshot).or_else(|| {
                (device.diskseq.is_some() && devices::diskseq(&device) != device.diskseq)
                    .then(|| "device disappeared or diskseq changed during SMART check".into())
            });
            if let Some(error) = changed {
                entry.check_status = CheckStatus::StaleRace;
                if entry.smart_error.as_ref() != Some(&error) {
                    events.push(Event::new(
                        Severity::Warning,
                        Some(&device),
                        "identity_race",
                        error.clone(),
                    ));
                }
                entry.smart_error = Some(error);
                race = true;
            } else {
                // A persisted snapshot may predate the identity-merge fix. Do not use
                // another disk's measurements as either stale values or a diff baseline.
                if entry
                    .snapshot
                    .as_ref()
                    .is_some_and(|old| smart::identity_mismatch(&device, old).is_some())
                {
                    tracing::warn!(disk = %device.key(), "discarding SMART history with conflicting identity");
                    entry.snapshot = None;
                    entry.checked_at = None;
                    entry.hot = false;
                    entry.smart_error = None;
                }
                if let Some(old) = &entry.snapshot {
                    snapshot.retain_missing(old);
                }
                events.extend(alert::diff(
                    &device,
                    entry.snapshot.as_ref(),
                    &snapshot,
                    &mut entry.hot,
                    &cfg.temperature,
                ));
                if let Some(issue) = &snapshot.issue {
                    if entry.smart_error.as_ref() != Some(issue) {
                        events.push(Event::new(
                            Severity::Warning,
                            Some(&device),
                            "smart_read",
                            issue.clone(),
                        ));
                    }
                    entry.smart_error = Some(issue.clone());
                    entry.check_status = CheckStatus::Partial;
                } else {
                    if entry.smart_error.take().is_some() {
                        events.push(Event::new(
                            Severity::Info,
                            Some(&device),
                            "smart_read",
                            "SMART reading recovered",
                        ));
                    }
                    entry.check_status = CheckStatus::Checked;
                    entry.checked_at = Some(now());
                }
                entry.snapshot = Some(*snapshot);
            }
        }
        Ok(smart::Reading::Sleeping) => {
            entry.check_status = CheckStatus::Sleeping;
            entry.smart_error = None;
            // Old measurements and last successful check remain unchanged.
        }
        Err(e) => {
            let error = format!("{e:#}");
            if entry.smart_error.as_ref() != Some(&error) {
                events.push(Event::new(
                    Severity::Warning,
                    Some(&device),
                    "smart_read",
                    error.clone(),
                ));
            }
            entry.smart_error = Some(error);
            entry.check_status = CheckStatus::Failed;
            // A failed open/read cannot justify using this cached identity for kernel logs.
            race = true;
        }
    }
    for event in events {
        publish(state, tx, event, true);
    }
    race
}
fn fill_identity(d: &mut Device, model: &str, serial: &str, wwn: &str) {
    if d.model.is_empty() {
        d.model = model.to_owned();
    }
    if d.serial.is_empty() {
        d.serial = serial.to_owned();
    }
    if nonzero_wwn(&d.wwn).is_none() {
        d.wwn = if d.kind == devices::Kind::Nvme {
            String::new()
        } else {
            nonzero_wwn(wwn).unwrap_or_default().to_owned()
        };
    }
}
fn apply_scan(
    state: &mut State,
    event: Scan,
    devices: &mut Vec<Device>,
    cfg: &Config,
    tx: &mpsc::Sender<Event>,
) {
    match event {
        Scan::Inventory(mut found) => {
            for d in &mut found {
                if let Some(previous) = state
                    .disks
                    .values()
                    .find(|old| d.same_identity(&old.device))
                {
                    fill_identity(
                        d,
                        &previous.device.model,
                        &previous.device.serial,
                        &previous.device.wwn,
                    );
                }
            }
            apply_inventory(state, &found, cfg, tx);
            *devices = found;
        }
        Scan::Disk(mut device, result) => {
            if let Some(cached) = devices.iter().find(|d| d.same_identity(&device)) {
                fill_identity(&mut device, &cached.model, &cached.serial, &cached.wwn);
            }
            // Enrich only a verified result; migrate the existing entry when a stronger key appears.
            if let Ok(smart::Reading::Checked(snapshot)) = &result
                && smart::identity_mismatch(&device, snapshot).is_none()
                && (device.diskseq.is_none() || devices::diskseq(&device) == device.diskseq)
            {
                let original = device.clone();
                let old_key = original.key();
                fill_identity(
                    &mut device,
                    &snapshot.model,
                    &snapshot.serial,
                    &snapshot.wwn,
                );
                if old_key != device.key()
                    && let Some(mut old) = state.disks.remove(&old_key)
                {
                    // Path-only history cannot establish ownership of a stable identity.
                    if old.device.same_identity(&device) {
                        old.device = device.clone();
                        state.disks.entry(device.key()).or_insert(old);
                    }
                }
                for d in devices.iter_mut().filter(|d| {
                    d.same_identity(&original)
                        || (d.serial.is_empty()
                            && nonzero_wwn(&d.wwn).is_none()
                            && d.key() == old_key
                            && d.diskseq == original.diskseq)
                }) {
                    *d = device.clone();
                }
            }
            if !device.serial.is_empty() && cfg.devices.ignore_serials.contains(&device.serial) {
                if let Some(entry) = state.disks.get_mut(&device.key()) {
                    entry.check_status = state::CheckStatus::Disabled;
                }
                return;
            }
            if apply_result(state, device.clone(), result, cfg, tx) {
                for d in devices.iter_mut().filter(|d| d.same_identity(&device)) {
                    d.diskseq = None;
                }
            }
        }
        Scan::DiscoveryFailed(error) => {
            devices.clear();
            tracing::warn!(%error, "discovery failed; topology is unknown");
        }
    }
}
fn apply_kernel(
    state: &mut State,
    record: kernel::Record,
    disk: Option<&Device>,
    cfg: &Config,
    tx: &mpsc::Sender<Event>,
) {
    if !state.accept_kernel(&record) {
        return;
    }
    let Some((severity, category)) = kernel::classify(&record.message) else {
        return;
    };
    let mut event = Event::new(
        severity,
        disk,
        &format!("kernel_{category}"),
        record.message,
    );
    if let Some(timestamp) = record.timestamp {
        event.timestamp = timestamp;
    }
    if let Some(d) = disk {
        let entry = state
            .disks
            .entry(d.key())
            .or_insert_with(|| DiskState::new(d.clone()));
        entry.kernel_severity = Some(
            entry
                .kernel_severity
                .unwrap_or(Severity::Info)
                .max(severity),
        );
        entry.kernel_last_message = Some(event.message.clone());
        entry.kernel_last_seen = Some(event.timestamp);
    }
    let notify = state.should_notify(&event, cfg.alerts.kernel_cooldown_seconds);
    publish(state, tx, event, notify);
}
// Resolve once, then store the evidence under exactly that disk identity.
fn handle_kernel(
    state: &mut State,
    record: kernel::Record,
    devices: &[Device],
    cfg: &Config,
    tx: &mpsc::Sender<Event>,
) {
    let disk = kernel::fresh_match(&record, devices, state.kernel_boot_id.as_deref())
        .filter(|d| d.serial.is_empty() || !cfg.devices.ignore_serials.contains(&d.serial));
    apply_kernel(state, record, disk, cfg, tx);
}
fn status_summary(state: &State) -> String {
    // Group by the existing health result; presentation never classifies disks.
    let disks: Vec<_> = state
        .disks
        .values()
        .filter(|d| d.present)
        .map(|d| (d, d.health()))
        .collect();
    let mut out = format!("DISKS: {}\n", disks.len());
    for health in ["OK", "Warning", "Critical", "Unknown"] {
        let count = disks.iter().filter(|(_, h)| *h == health).count();
        out.push_str(&format!("{}: {count}\n", health.to_uppercase()));
    }
    if !disks.is_empty() && disks.iter().all(|(_, h)| *h == "OK") {
        out.push_str("\nAll disks OK\n");
    }
    for health in ["Critical", "Warning", "Unknown"] {
        let mut group = disks.iter().filter(|(_, h)| *h == health).peekable();
        if group.peek().is_none() {
            continue;
        }
        out.push_str(&format!("\n{}:\n", health.to_uppercase()));
        for (d, _) in group {
            out.push_str(&format!(
                "  {} {}",
                escaped(&d.device.model),
                escaped(&d.device.path)
            ));
            if !d.device.serial.is_empty()
                && disks
                    .iter()
                    .filter(|(other, _)| other.device.model == d.device.model)
                    .count()
                    > 1
            {
                out.push_str(&format!(" serial={}", escaped(&d.device.serial)));
            }
            out.push('\n');
            let mut reason = |key: &str, value: String, stale: bool| {
                out.push_str(&format!(
                    "    {key}={value}{}\n",
                    if stale { " (stale)" } else { "" }
                ));
            };
            let check = match d.check_status {
                state::CheckStatus::Checked => None,
                state::CheckStatus::Never => Some("not_checked"),
                state::CheckStatus::Partial => Some("partial"),
                state::CheckStatus::Sleeping => Some("skipped_sleeping"),
                state::CheckStatus::Failed => Some("failed"),
                state::CheckStatus::StaleRace => Some("stale_identity_race"),
                state::CheckStatus::Disabled => Some("disabled"),
            };
            if let Some(check) = check {
                reason("smart_check", check.into(), false);
            }
            if let Some(s) = &d.snapshot {
                for (key, value) in &s.counters {
                    if *value == 0 {
                        continue;
                    }
                    let label = match key.as_str() {
                        "Current_Pending_Sector" => "pending",
                        "Offline_Uncorrectable" => "offline_uncorrectable",
                        "Reallocated_Event_Count" => "reallocated_events",
                        "Reallocated_Sector_Ct" => "reallocated",
                        "Reported_Uncorrect" => "reported_uncorrect",
                        "UDMA_CRC_Error_Count" => "crc_errors",
                        "Command_Timeout" => "command_timeouts",
                        _ => key,
                    };
                    reason(
                        &escaped(label),
                        value.to_string(),
                        s.stale_fields.contains(key),
                    );
                }
                if d.hot {
                    reason(
                        "temperature",
                        s.temperature
                            .map(|t| format!("{t}C"))
                            .unwrap_or_else(|| "unknown".into()),
                        s.stale_fields.contains("temperature"),
                    );
                }
                for (key, value, show) in [
                    ("smart_passed", "no".into(), s.passed == Some(false)),
                    ("prefailure", "yes".into(), s.prefailure == Some(true)),
                    (
                        "critical_warning",
                        s.critical_warning.unwrap_or_default().to_string(),
                        s.critical_warning.is_some_and(|n| n != 0),
                    ),
                    (
                        "self_test",
                        "failed".into(),
                        s.self_test_status == Some(smart::SelfTestStatus::Failed),
                    ),
                    (
                        "available_spare",
                        s.available_spare.unwrap_or_default().to_string(),
                        s.available_spare
                            .zip(s.spare_threshold)
                            .is_some_and(|(a, b)| a < b),
                    ),
                    (
                        "percentage_used",
                        s.percentage_used.unwrap_or_default().to_string(),
                        s.percentage_used.is_some_and(|n| n >= 100),
                    ),
                    (
                        "remaining_life",
                        s.remaining_life.unwrap_or_default().to_string(),
                        s.remaining_life.is_some_and(|n| n <= 10),
                    ),
                    ("past_threshold", "yes".into(), s.exit.past_threshold),
                    ("error_log", "yes".into(), s.exit.error_log),
                    ("self_test_log", "yes".into(), s.exit.self_test_log),
                ] {
                    if show {
                        let field = match key {
                            "smart_passed" => "passed",
                            "self_test" => "self_test_status",
                            _ => key,
                        };
                        reason(key, value, s.stale_fields.contains(field));
                    }
                }
                if s.passed.is_none() {
                    reason("smart_health", "unknown".into(), false);
                }
                if !s.stale_fields.is_empty() {
                    reason("stale_fields", "yes".into(), false);
                }
                if s.issue.is_some() {
                    reason("smart_data", "incomplete".into(), false);
                }
            } else {
                reason("smart_data", "unavailable".into(), false);
            }
            if d.smart_error.is_some() && check.is_none() {
                reason("smart_error", "yes".into(), false);
            }
            if d.kernel_severity.is_some_and(|s| s != Severity::Info) {
                reason("kernel_io_errors", "yes".into(), false);
            }
        }
    }
    out
}
fn display(state: &State) {
    if state.disks.is_empty() {
        println!("No known physical disks.");
    }
    for d in state.disks.values() {
        println!(
            "{}\n  serial: {}\n  device: {}\n  present: {}\n  {}: {}\n  last SMART check (Unix seconds): {:?}",
            escaped(&d.device.model),
            escaped(&d.device.serial),
            escaped(&d.device.path),
            d.present,
            if d.present {
                "health"
            } else {
                "last known health"
            },
            d.health(),
            d.checked_at
        );
        println!(
            "  SMART check: {:?}; last known severity: {:?}",
            d.check_status,
            d.severity()
        );
        if let Some(s) = &d.snapshot {
            if !s.stale_fields.is_empty() {
                println!("  stale/unknown fields: {:?}", s.stale_fields);
            }
            if !s.unknown_attributes.is_empty() {
                println!(
                    "  uninterpreted vendor attributes: {:?}",
                    s.unknown_attributes.keys().collect::<Vec<_>>()
                );
            }
            println!(
                "  SMART overall passed: {:?}\n  firmware: {}\n  temperature: {:?} C\n  power-on hours: {:?}",
                s.passed,
                escaped(&s.firmware),
                s.temperature,
                s.power_on_hours
            );
            for (key, value) in &s.counters {
                println!("  {key}: {value}");
            }
            if d.device.kind == devices::Kind::Nvme {
                println!(
                    "  critical_warning: {:?}\n  available_spare: {:?}\n  percentage_used: {:?}",
                    s.critical_warning, s.available_spare, s.percentage_used
                );
            }
            if let Some(life) = s.remaining_life {
                println!("  remaining life: {life}%");
            }
            if let Some(test) = &s.self_test {
                println!("  self-test: {:?}: {}", s.self_test_status, escaped(test));
            }
        } else {
            println!("  SMART: unavailable / not checked");
        }
        if let Some(e) = &d.smart_error {
            println!(
                "  SMART error (previous snapshot may be stale): {}",
                escaped(e)
            );
        }
        if let Some(m) = &d.kernel_last_message {
            println!(
                "  kernel I/O errors observed (historical, {:?}): {}",
                d.kernel_last_seen,
                escaped(m)
            );
        }
    }
    if !state.recent_alerts.is_empty() {
        println!("Recent events:");
    }
    for event in state.recent_alerts.iter().rev().take(20) {
        println!(
            "  {} {:?} {} {}",
            event.timestamp,
            event.severity,
            event
                .disk
                .as_ref()
                .map(|d| escaped(&d.path))
                .unwrap_or_else(|| "uncorrelated".into()),
            escaped(&event.message)
        );
    }
}
fn escaped(s: &str) -> String {
    s.chars().flat_map(char::escape_default).collect()
}
async fn recent_kernel(
    state: &mut State,
    devices: &[Device],
    cfg: &Config,
    tx: &mpsc::Sender<Event>,
) -> Result<()> {
    let args = kernel::arguments(state.kernel_cursor.as_deref(), false);
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let mut out = devices::command("journalctl", &refs, cfg.command_timeout_seconds).await?;
    if !out.status.success() && state.kernel_cursor.is_some() {
        tracing::warn!("journal cursor unavailable; replaying last 200 records with deduplication");
        out = devices::command(
            "journalctl",
            &["-k", "-n", "200", "-o", "json", "--no-pager"],
            cfg.command_timeout_seconds,
        )
        .await?;
    }
    anyhow::ensure!(
        out.status.success(),
        "journalctl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        match kernel::parse(line) {
            Ok(record) => handle_kernel(state, record, devices, cfg, tx),
            Err(e) => tracing::warn!(error=%e, "invalid kernel record"),
        }
    }
    Ok(())
}
fn background_exit(
    name: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    let detail = match result {
        Ok(Ok(())) => "unexpected normal exit".into(),
        Ok(Err(e)) => format!("{e:#}"),
        Err(e) => e.to_string(),
    };
    tracing::error!(task=name, error=%detail, "background task stopped; daemon will exit");
    anyhow::anyhow!("{name} task stopped: {detail}")
}
async fn daemon(
    mut state: State,
    cfg: Config,
    path: PathBuf,
    tx: mpsc::Sender<Event>,
) -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut devices = devices::discover(cfg.command_timeout_seconds)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(error=%e, "initial discovery failed");
            vec![]
        });
    apply_inventory(&mut state, &devices, &cfg, &tx);
    let (scan_tx, mut scan_rx) = mpsc::channel(16);
    let polling_cfg = cfg.clone();
    let mut polling = tokio::spawn(async move {
        loop {
            if let Err(e) = scan(&polling_cfg, &scan_tx).await {
                // A panicked per-disk task is a scheduler failure, not a failed discovery.
                if e.chain().any(|e| e.is::<tokio::task::JoinError>()) {
                    return Err(e);
                }
                scan_tx
                    .send(Scan::DiscoveryFailed(format!("{e:#}")))
                    .await
                    .context("scan receiver closed")?;
            }
            tokio::time::sleep(Duration::from_secs(polling_cfg.check_interval_seconds)).await;
        }
    });
    let (kernel_tx, mut kernel_rx) = mpsc::channel(1024);
    let enabled = cfg.kernel.enabled;
    let cursor = state.kernel_cursor.clone();
    let mut journal = tokio::spawn(async move {
        if enabled {
            kernel::follow(cursor, kernel_tx).await
        } else {
            std::future::pending::<Result<()>>().await
        }
    });
    let (writer_tx, writer_rx) = tokio::sync::watch::channel(state.clone());
    let mut writer = tokio::spawn(state::writer(path, writer_rx));
    let mut flush = tokio::time::interval(Duration::from_secs(2));
    let mut dirty = true;
    let mut writer_finished = false;
    tracing::info!("disk-watch started");
    let outcome = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = term.recv() => break Ok(()),
            result = &mut polling => break Err(background_exit("SMART scheduler", result)),
            result = &mut journal => break Err(background_exit("journal reader", result)),
            result = &mut writer => { writer_finished = true; break Err(background_exit("state writer", result)); },
            Some(event) = scan_rx.recv() => { apply_scan(&mut state, event, &mut devices, &cfg, &tx); dirty = true; },
            Some(record) = kernel_rx.recv(), if enabled => { handle_kernel(&mut state, record, &devices, &cfg, &tx); dirty = true; },
            _ = flush.tick(), if dirty => { writer_tx.send_replace(state.clone()); dirty = false; },
        }
    };
    polling.abort();
    journal.abort();
    // Last snapshot supersedes intermediate queued writes. Exactly one writer remains.
    writer_tx.send_replace(state);
    drop(writer_tx);
    if !writer_finished {
        match tokio::time::timeout(Duration::from_secs(10), &mut writer).await {
            Ok(result) => result.context("state writer panicked during shutdown")??,
            Err(_) => anyhow::bail!("state writer did not finish within shutdown deadline"),
        }
    }
    outcome?;
    tracing::info!("disk-watch stopped");
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "disk_watch=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();
    let cli = Cli::parse();
    let cfg = Config::load(
        cli.config
            .as_deref()
            .unwrap_or(std::path::Path::new("/etc/disk-watch/config.toml")),
        cli.config.is_some(),
    )?;
    if let Action::Status { verbose, .. } = cli.command {
        let state = State::load(&cli.state);
        print!("{}", status_summary(&state));
        if verbose {
            println!();
            display(&state);
        }
        return Ok(());
    }
    if matches!(cli.command, Action::Devices) {
        for d in devices::discover(cfg.command_timeout_seconds).await? {
            if !cfg.devices.ignore_serials.contains(&d.serial) {
                println!(
                    "{} {:?} model={} serial={} wwn={}",
                    escaped(&d.path),
                    d.kind,
                    escaped(&d.model),
                    escaped(&d.serial),
                    escaped(&d.wwn)
                );
            }
        }
        return Ok(());
    }
    let _lock = state::lock(&cli.state)?;
    let mut state = State::load(&cli.state);
    state.prepare_boot(kernel::current_boot());
    let (tx, notifications) = notifier::start(cfg.alerts.desktop);
    let result = match cli.command {
        Action::Daemon => daemon(state, cfg, cli.state, tx).await,
        Action::Check => {
            let (scan_tx, mut scan_rx) = mpsc::channel(16);
            let scan_cfg = cfg.clone();
            let task = tokio::spawn(async move { scan(&scan_cfg, &scan_tx).await });
            let mut devices = vec![];
            while let Some(event) = scan_rx.recv().await {
                apply_scan(&mut state, event, &mut devices, &cfg, &tx);
            }
            task.await.context("SMART scan task stopped")??;
            let journal_error = if cfg.kernel.enabled {
                recent_kernel(&mut state, &devices, &cfg, &tx).await.err()
            } else {
                None
            };
            if let Some(e) = &journal_error {
                tracing::warn!(error=%e, "kernel journal check failed");
            }
            state.save(&cli.state).context("save state")?;
            display(&state);
            drop(tx);
            anyhow::ensure!(
                journal_error.is_none()
                    && !state.disks.values().any(|d| d.present
                        && matches!(
                            d.check_status,
                            state::CheckStatus::Failed
                                | state::CheckStatus::Partial
                                | state::CheckStatus::StaleRace
                        )),
                "check incomplete; see errors above"
            );
            Ok(())
        }
        _ => unreachable!(),
    };
    // Drain pending notifications on normal exit, with a bounded shutdown delay.
    let _ = tokio::time::timeout(Duration::from_secs(10), notifications).await;
    result
}

#[cfg(test)]
mod tests;
