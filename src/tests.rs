use super::*;
use crate::devices::Kind;
use std::sync::atomic::{AtomicU64, Ordering};
const HDD_OK: &[u8] = include_bytes!("../tests/fixtures/smart_hdd_ok.json");
const HDD_BAD: &[u8] = include_bytes!("../tests/fixtures/smart_hdd_bad_named.json");
const SSD: &[u8] = include_bytes!("../tests/fixtures/smart_ssd.json");
const NVME: &[u8] = include_bytes!("../tests/fixtures/smart_nvme.json");
fn device() -> Device {
    Device {
        path: "/dev/sdb".into(),
        model: "Test".into(),
        serial: "SERIAL".into(),
        wwn: "".into(),
        kind: Kind::Hdd,
        aliases: vec!["sdb".into(), "sdb1".into(), "ata2".into()],
        diskseq: None,
        discovered_at: 0,
    }
}
fn temp() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "disk-watch-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}
#[test]
fn parse_all_smart_fixtures() {
    let good = smart::parse(HDD_OK, 0).unwrap();
    assert_eq!(good.temperature, Some(34));
    assert_eq!(good.power_on_hours, Some(1234));
    assert_eq!(good.serial, "WD-TEST1");
    assert_eq!(good.self_test_status, Some(smart::SelfTestStatus::Passed));
    let bad = smart::parse(HDD_BAD, 200).unwrap();
    assert_eq!(bad.counters["Current_Pending_Sector"], 58);
    assert_eq!(bad.passed, Some(false));
    assert_eq!(bad.self_test_status, Some(smart::SelfTestStatus::Failed));
    let ssd = smart::parse(SSD, 0).unwrap();
    assert_eq!(ssd.remaining_life, Some(91));
    assert!(ssd.counters.is_empty());
    assert_eq!(ssd.unknown_attributes.len(), 4);
    let nvme = smart::parse(NVME, 0).unwrap();
    assert_eq!(nvme.counters["media_errors"], 2);
    assert_eq!(nvme.percentage_used, Some(7));
    assert_eq!(nvme.available_spare, Some(100));
    assert_eq!(nvme.temperature, Some(42));
}
#[test]
fn smart_exit_bits_are_not_normal_exit_codes() {
    assert!(smart::parse(HDD_BAD, 200).is_ok());
    for bit in [1, 2, 4] {
        let partial = smart::parse(HDD_OK, bit).unwrap();
        assert!(partial.issue.is_some());
        assert!(partial.passed.is_none());
    }
    assert!(smart::parse(b"{}", 0).is_err());
    assert!(smart::parse(b"garbage", 0).is_err());
}
#[test]
fn changes_suppress_duplicates_and_report_recovery() {
    let a = smart::parse(HDD_OK, 0).unwrap();
    let b = smart::parse(HDD_BAD, 200).unwrap();
    let cfg = Config::default();
    let mut hot = false;
    let events = alert::diff(&device(), Some(&a), &b, &mut hot, &cfg.temperature);
    let pending: Vec<_> = events
        .iter()
        .filter(|e| e.category == "Current_Pending_Sector")
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].severity, Severity::Critical);
    assert!(pending[0].message.contains("0 -> 58"));
    assert!(alert::diff(&device(), Some(&b), &b, &mut hot, &cfg.temperature).is_empty());
    let events = alert::diff(&device(), Some(&b), &a, &mut hot, &cfg.temperature);
    assert!(
        events
            .iter()
            .any(|e| e.category == "overall_health" && e.severity == Severity::Info)
    );
    let first = alert::diff(&device(), None, &b, &mut hot, &cfg.temperature);
    assert!(first.iter().any(|e| e.category == "Current_Pending_Sector"));
}
#[test]
fn rising_nonzero_counter_and_nvme_media_errors() {
    let a = smart::parse(HDD_BAD, 200).unwrap();
    let mut b = a.clone();
    b.counters.insert("Reallocated_Sector_Ct".into(), 7);
    let e = alert::diff(
        &device(),
        Some(&a),
        &b,
        &mut false,
        &Config::default().temperature,
    );
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].severity, Severity::Warning);
    let a = smart::parse(NVME, 0).unwrap();
    let mut b = a.clone();
    b.counters.insert("media_errors".into(), 3);
    let e = alert::diff(
        &device(),
        Some(&a),
        &b,
        &mut false,
        &Config::default().temperature,
    );
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].severity, Severity::Critical);
}
#[test]
fn temperature_hysteresis() {
    let mut d = device();
    d.kind = Kind::Ssd;
    let mut snap = smart::parse(SSD, 0).unwrap();
    let mut hot = false;
    for (temperature, count, expected_hot) in [
        (39, 0, false),
        (40, 0, false),
        (60, 1, true),
        (61, 0, true),
        (56, 0, true),
        (55, 1, false),
        (59, 0, false),
        (60, 1, true),
    ] {
        let old = snap.clone();
        snap.temperature = Some(temperature);
        let e = alert::diff(
            &d,
            Some(&old),
            &snap,
            &mut hot,
            &Config::default().temperature,
        );
        assert_eq!(e.len(), count);
        assert_eq!(hot, expected_hot);
    }
}
#[test]
fn kernel_classification_and_correlation() {
    let devices = vec![device()];
    for line in include_str!("../tests/fixtures/kernel.log").lines() {
        let r = kernel::parse(line).unwrap();
        assert!(kernel::classify(&r.message).is_some(), "{}", r.message);
        if !r.message.contains("nvme") {
            assert_eq!(
                kernel::correlate(&r.message, &devices).unwrap().serial,
                "SERIAL"
            );
        }
    }
    for m in [
        "usb 1-2: timeout",
        "network connection timeout",
        "function loaded",
        "sdb: device ready",
    ] {
        assert!(kernel::classify(m).is_none(), "{m}");
    }
    for m in [
        "ata2: COMRESET failed",
        "EXT4-fs error (device sdb1)",
        "blk_update_request: I/O error",
        "nvme nvme0: resetting controller",
    ] {
        assert_eq!(kernel::classify(m).unwrap().0, Severity::Critical);
    }
    assert!(kernel::correlate("I/O error, dev sdbb", &devices).is_none());
    assert!(kernel::correlate("ata2: timeout", &[device(), device()]).is_none());
}
#[test]
fn kernel_passed_smart_is_still_critical_and_suppressed() {
    let mut state = State::default();
    let mut d = device();
    d.serial = "SSD-TEST1".into();
    let cfg = Config::default();
    let (tx, mut rx) = mpsc::channel(64);
    apply_result(
        &mut state,
        d.clone(),
        Ok(smart::Reading::Checked(Box::new(
            smart::parse(SSD, 0).unwrap(),
        ))),
        &cfg,
        &tx,
    );
    for line in include_str!("../tests/fixtures/kernel.log").lines() {
        let record = kernel::parse(line).unwrap();
        let devices = std::slice::from_ref(&d);
        let matched = kernel::correlate(&record.message, devices);
        apply_kernel(&mut state, record, matched, &cfg, &tx);
    }
    assert_eq!(state.disks[&d.key()].severity(), Severity::Critical);
    apply_result(
        &mut state,
        d.clone(),
        Ok(smart::Reading::Checked(Box::new(
            smart::parse(SSD, 0).unwrap(),
        ))),
        &cfg,
        &tx,
    );
    assert_eq!(state.disks[&d.key()].severity(), Severity::Critical);
    while rx.try_recv().is_ok() {}
    apply_kernel(
        &mut state,
        kernel::parse(r#"{"MESSAGE":"I/O error, dev sdb"}"#).unwrap(),
        Some(&d),
        &cfg,
        &tx,
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(
        state.recent_alerts.last().unwrap().message,
        "I/O error, dev sdb"
    );
}
#[test]
fn state_atomic_roundtrip_lock_corruption_and_renaming() {
    let dir = temp();
    let path = dir.join("state.json");
    let lock = state::lock(&path).unwrap();
    assert!(state::lock(&path).is_err());
    let mut state = State::default();
    let d = device();
    state.disks.insert(d.key(), DiskState::new(d.clone()));
    let e = Event::new(Severity::Critical, Some(&d), "kernel_io_error", "I/O error");
    assert!(state.should_notify(&e, 300));
    state.save(&path).unwrap();
    let mut loaded = state::read(&path).unwrap();
    assert!(!loaded.should_notify(&e, 300));
    let mut renamed = d.clone();
    renamed.path = "/dev/sdz".into();
    assert_eq!(d.key(), renamed.key());
    loaded.save(&path).unwrap();
    assert!(!dir.join("state.json.tmp").exists());
    std::fs::write(&path, "broken").unwrap();
    assert!(State::load(&path).disks.is_empty());
    drop(lock);
    assert!(state::lock(&path).is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn disk_failure_does_not_prevent_other_checks() {
    let mut state = State::default();
    let (tx, _) = mpsc::channel(8);
    let d = device();
    let mut other = d.clone();
    other.serial = "OTHER".into();
    other.path = "/dev/sdc".into();
    apply_result(
        &mut state,
        d.clone(),
        Err(anyhow::anyhow!("read failed")),
        &Config::default(),
        &tx,
    );
    let mut snap = smart::parse(HDD_OK, 0).unwrap();
    snap.serial = other.serial.clone();
    apply_result(
        &mut state,
        other.clone(),
        Ok(smart::Reading::Checked(Box::new(snap))),
        &Config::default(),
        &tx,
    );
    assert!(state.disks[&d.key()].smart_error.is_some());
    assert!(state.disks[&other.key()].snapshot.is_some());
}
#[test]
fn config_defaults_and_validation() {
    let dir = temp();
    let path = dir.join("config.toml");
    assert_eq!(
        Config::load(&path, false).unwrap().check_interval_seconds,
        1800
    );
    assert!(Config::load(&path, true).is_err());
    for content in [
        "check_interval_seconds=0",
        "[alerts]\ntelegram=true",
        "typo=true",
        "[temperature]\nhysteresis=-1",
    ] {
        std::fs::write(&path, content).unwrap();
        assert!(Config::load(&path, true).is_err());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn later_successful_self_test_is_reported() {
    let mut before = smart::parse(HDD_OK, 0).unwrap();
    before.self_test_hours = Some(100);
    let mut after = before.clone();
    after.self_test_hours = Some(200);
    let events = alert::diff(
        &device(),
        Some(&before),
        &after,
        &mut false,
        &Config::default().temperature,
    );
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].severity, Severity::Info);
    assert_eq!(events[0].category, "self_test");
}

#[test]
fn partial_smart_failure_keeps_critical_exit_evidence() {
    let snapshot = smart::parse(
        br#"{"smartctl":{"exit_status":12},"smart_status":{"passed":false}}"#,
        12,
    )
    .unwrap();
    assert!(snapshot.exit.incomplete);
    assert!(snapshot.issue.is_some());
    assert_eq!(snapshot.passed, Some(false));
    let events = alert::diff(
        &device(),
        None,
        &snapshot,
        &mut false,
        &Config::default().temperature,
    );
    assert!(
        events
            .iter()
            .any(|e| e.category == "overall_health" && e.severity == Severity::Critical)
    );
    // Even a truncated JSON document must not erase a reliable process health bit.
    assert_eq!(smart::parse(b"{", 12).unwrap().passed, Some(false));
    let history = smart::parse(br#"{"smart_status":{"passed":true}}"#, 224).unwrap();
    assert!(history.exit.past_threshold && history.exit.error_log && history.exit.self_test_log);
    assert_eq!(history.passed, Some(true));
}
#[test]
fn failed_command_requires_storage_context() {
    assert!(kernel::classify("wifi: failed command: SET_CHANNEL").is_none());
    assert_eq!(
        kernel::classify("ata2.00: failed command: WRITE FPDMA QUEUED"),
        Some((Severity::Warning, "failed_command"))
    );
}
#[test]
fn smart_identity_race_preserves_old_data() {
    let d = device();
    let mut state = State::default();
    let (tx, _) = mpsc::channel(32);
    let mut old = smart::parse(HDD_OK, 0).unwrap();
    old.serial = d.serial.clone();
    apply_result(
        &mut state,
        d.clone(),
        Ok(smart::Reading::Checked(Box::new(old))),
        &Config::default(),
        &tx,
    );
    let checked = state.disks[&d.key()].checked_at;
    let mut replacement = smart::parse(HDD_BAD, 200).unwrap();
    replacement.serial = "NEW".into();
    assert!(apply_result(
        &mut state,
        d.clone(),
        Ok(smart::Reading::Checked(Box::new(replacement))),
        &Config::default(),
        &tx
    ));
    let disk = &state.disks[&d.key()];
    assert_eq!(disk.snapshot.as_ref().unwrap().serial, d.serial);
    assert_eq!(disk.checked_at, checked);
    assert_eq!(disk.check_status, state::CheckStatus::StaleRace);
    assert_eq!(disk.health(), "Unknown");
    assert!(
        !state
            .recent_alerts
            .iter()
            .any(|e| e.category == "Current_Pending_Sector")
    );
    assert_eq!(
        state.recent_alerts.last().unwrap().category,
        "identity_race"
    );
}
#[test]
fn missing_field_is_stale_not_recovery_or_duplicate() {
    let mut before = smart::parse(NVME, 0).unwrap();
    before.critical_warning = Some(1);
    let mut absent = smart::parse(br#"{"smart_status":{"passed":true}}"#, 0).unwrap();
    absent.retain_missing(&before);
    assert_eq!(absent.critical_warning, Some(1));
    assert!(absent.stale_fields.contains("critical_warning"));
    assert!(absent.stale_fields.contains("media_errors"));
    assert!(
        alert::diff(
            &device(),
            Some(&before),
            &absent,
            &mut false,
            &Config::default().temperature
        )
        .is_empty()
    );
    let mut disk = DiskState::new(device());
    disk.snapshot = Some(absent.clone());
    disk.check_status = state::CheckStatus::Checked;
    assert_eq!(disk.health(), "Unknown");
    // The stale value remains the comparison baseline when data returns.
    assert!(
        alert::diff(
            &device(),
            Some(&absent),
            &before,
            &mut false,
            &Config::default().temperature
        )
        .is_empty()
    );
}
#[test]
fn vendor_names_and_packed_raw_are_not_invented_health_signals() {
    let s = smart::parse(br#"{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":197,"name":"Not_In_Use","raw":{"value":1}},{"id":188,"name":"Command_Timeout","raw":{"value":4295032833,"string":"1 1 1"}}]}}"#, 0).unwrap();
    assert!(s.counters.is_empty());
    assert_eq!(s.unknown_attributes.len(), 2);
    assert!(
        alert::diff(
            &device(),
            None,
            &s,
            &mut false,
            &Config::default().temperature
        )
        .is_empty()
    );
    let original =
        smart::parse(include_bytes!("../tests/fixtures/smart_hdd_bad.json"), 200).unwrap();
    assert!(original.counters.is_empty());
    assert_eq!(original.unknown_attributes.len(), 5);
    let scalar = smart::parse(br#"{"smart_status":{"passed":true},"ata_smart_attributes":{"table":[{"id":188,"name":"Command_Timeout","raw":{"value":5,"string":"5"}}]}}"#, 0).unwrap();
    assert_eq!(scalar.counters["Command_Timeout"], 5);
}
#[test]
fn journal_replay_is_idempotent_across_state_reload() {
    let dir = temp();
    let path = dir.join("state.json");
    let mut state = State::default();
    let (tx, _) = mpsc::channel(32);
    for _ in 0..2 {
        for line in include_str!("../tests/fixtures/kernel.log").lines() {
            apply_kernel(
                &mut state,
                kernel::parse(line).unwrap(),
                None,
                &Config::default(),
                &tx,
            );
        }
        state.save(&path).unwrap();
        state = state::read(&path).unwrap();
    }
    assert_eq!(state.recent_alerts.len(), 12);
    std::fs::remove_dir_all(dir).unwrap();
}
#[test]
fn sleeping_preserves_measurements_and_success_time() {
    let d = device();
    let mut snapshot = smart::parse(HDD_OK, 0).unwrap();
    snapshot.serial = d.serial.clone();
    let (tx, _) = mpsc::channel(32);
    let mut state = State::default();
    apply_result(
        &mut state,
        d.clone(),
        Ok(smart::Reading::Checked(Box::new(snapshot))),
        &Config::default(),
        &tx,
    );
    let time = state.disks[&d.key()].checked_at;
    let alerts = state.recent_alerts.len();
    apply_result(
        &mut state,
        d.clone(),
        Ok(smart::Reading::Sleeping),
        &Config::default(),
        &tx,
    );
    let disk = &state.disks[&d.key()];
    assert_eq!(disk.check_status, state::CheckStatus::Sleeping);
    assert_eq!(disk.checked_at, time);
    assert_eq!(disk.snapshot.as_ref().unwrap().temperature, Some(34));
    assert_eq!(disk.health(), "Unknown");
    assert_eq!(disk.severity(), Severity::Info);
    assert_eq!(state.recent_alerts.len(), alerts);
}
#[test]
fn aborted_and_in_progress_tests_are_not_passed() {
    let good = smart::parse(HDD_OK, 0).unwrap();
    for (value, expected) in [
        (16, smart::SelfTestStatus::Aborted),
        (32, smart::SelfTestStatus::Aborted),
        (240, smart::SelfTestStatus::InProgress),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(HDD_OK).unwrap();
        v["ata_smart_self_test_log"]["standard"]["table"][0]["status"] =
            serde_json::json!({"value":value,"string":"Not completed"});
        let s = smart::parse(&serde_json::to_vec(&v).unwrap(), 0).unwrap();
        assert_eq!(s.self_test_status, Some(expected));
        assert!(
            alert::diff(
                &device(),
                Some(&good),
                &s,
                &mut false,
                &Config::default().temperature
            )
            .iter()
            .all(|e| !e.message.contains("successfully")
                && !e.message.contains("returned to normal"))
        );
    }
}
#[test]
fn exact_device_beats_ambiguous_ata_port() {
    let first = device();
    let mut second = first.clone();
    second.serial = "SECOND".into();
    second.aliases = vec!["sdc".into(), "ata2".into()];
    let devices = [first, second];
    assert!(kernel::correlate("ata2.00: timeout", &devices).is_none());
    assert_eq!(
        kernel::correlate("ata2: I/O error, dev sdb", &devices)
            .unwrap()
            .serial,
        "SERIAL"
    );
    assert!(kernel::correlate("ata2: I/O error, dev sdz", &devices).is_none());
    let record = kernel::parse(
        r#"{"_BOOT_ID":"boot","__REALTIME_TIMESTAMP":"1000000","MESSAGE":"ata2.00: timeout"}"#,
    )
    .unwrap();
    assert!(kernel::fresh_match(&record, &devices, Some("boot")).is_none());
}
#[tokio::test]
async fn background_panic_is_detected() {
    let task = tokio::spawn(async {
        panic!("reader panic");
        #[allow(unreachable_code)]
        Ok(())
    });
    let error = background_exit("journal reader", task.await);
    assert!(error.to_string().contains("journal reader task stopped"));
}
#[test]
fn old_state_is_upgraded_without_losing_history() {
    let dir = temp();
    let path = dir.join("state.json");
    let mut old = State::default();
    let mut disk = DiskState::new(device());
    disk.snapshot = Some(smart::parse(HDD_BAD, 200).unwrap());
    old.disks.insert(device().key(), disk);
    let mut v = serde_json::to_value(old).unwrap();
    v["version"] = serde_json::json!(1);
    let d = &mut v["disks"][device().key()];
    d.as_object_mut().unwrap().remove("check_status");
    let snap = &mut d["snapshot"];
    snap.as_object_mut().unwrap().remove("self_test_status");
    snap["self_test_failed"] = serde_json::json!(true);
    snap["critical_warning"] = serde_json::json!(0);
    snap["prefailure"] = serde_json::json!(false);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let loaded = state::read(&path).unwrap();
    assert_eq!(loaded.version, 2);
    assert_eq!(
        loaded.disks[&device().key()]
            .snapshot
            .as_ref()
            .unwrap()
            .self_test_status,
        Some(smart::SelfTestStatus::Failed)
    );
    assert_eq!(loaded.disks[&device().key()].health(), "Unknown");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn smart_identity_enrichment_migrates_instead_of_forking_state() {
    let mut d = device();
    d.serial.clear();
    d.model.clear();
    let mut state = State::default();
    let (tx, _) = mpsc::channel(32);
    let mut topology = vec![];
    apply_scan(
        &mut state,
        Scan::Inventory(vec![d.clone()]),
        &mut topology,
        &Config::default(),
        &tx,
    );
    apply_scan(
        &mut state,
        Scan::Disk(
            d.clone(),
            Ok(smart::Reading::Checked(Box::new(
                smart::parse(HDD_OK, 0).unwrap(),
            ))),
        ),
        &mut topology,
        &Config::default(),
        &tx,
    );
    assert_eq!(state.disks.len(), 1);
    assert_eq!(topology[0].serial, "WD-TEST1");
    let disk = state.disks.values().next().unwrap();
    assert!(disk.present);
    assert!(disk.snapshot.is_some());
    assert!(!state.disks.contains_key(&d.key()));
    // A later check with the verified identity rejects a replacement's result.
    let verified = topology[0].clone();
    let mut different = smart::parse(HDD_OK, 0).unwrap();
    different.serial = "REPLACED".into();
    apply_scan(
        &mut state,
        Scan::Disk(verified, Ok(smart::Reading::Checked(Box::new(different)))),
        &mut topology,
        &Config::default(),
        &tx,
    );
    assert_eq!(state.disks.len(), 1);
    assert_eq!(
        state.disks.values().next().unwrap().check_status,
        state::CheckStatus::StaleRace
    );
}
#[test]
fn journal_boot_and_monotonic_order_survive_realtime_rollback() {
    let mut state = State::default();
    state.prepare_boot(Some("boot".into()));
    let a = kernel::parse(r#"{"__CURSOR":"a","_BOOT_ID":"boot","__MONOTONIC_TIMESTAMP":"100","__REALTIME_TIMESTAMP":"9000000","MESSAGE":"I/O error"}"#).unwrap();
    let b = kernel::parse(r#"{"__CURSOR":"b","_BOOT_ID":"boot","__MONOTONIC_TIMESTAMP":"101","__REALTIME_TIMESTAMP":"1000000","MESSAGE":"I/O error"}"#).unwrap();
    assert!(state.accept_kernel(&a));
    assert!(state.accept_kernel(&b));
    assert!(!state.accept_kernel(&a));
    state.prepare_boot(Some("newboot".into()));
    assert!(state.kernel_cursor.is_none());
    assert!(state.kernel_watermark.is_none());
    assert!(!state.accept_kernel(&a));
}

#[test]
fn explicit_dev_uses_current_discovery_before_ata_freshness() {
    let mut d = device();
    d.discovered_at = 200; // Replay is older than discovery; diskseq is unavailable.
    let mut other = d.clone();
    other.serial = "OTHER".into();
    other.path = "/dev/sdc".into();
    other.aliases = vec!["sdc".into(), "ata2".into()];
    let devices = [d, other];
    let mut state = State::default();
    state.prepare_boot(Some("boot".into()));
    let (tx, _) = mpsc::channel(8);
    for (index, message) in [
        "I/O error, dev sdb, sector 1",
        "ata2: I/O error, dev /dev/sdb",
        "Buffer I/O error on dev sdb1",
    ]
    .into_iter()
    .enumerate()
    {
        let record = kernel::parse(&serde_json::json!({"__CURSOR":format!("direct-{index}"), "_BOOT_ID":"boot", "__REALTIME_TIMESTAMP":"1000000", "MESSAGE":message}).to_string()).unwrap();
        assert_eq!(
            kernel::fresh_match(&record, &devices, Some("boot"))
                .unwrap()
                .serial,
            "SERIAL"
        );
        handle_kernel(&mut state, record, &devices, &Config::default(), &tx);
        assert_eq!(
            state
                .recent_alerts
                .last()
                .unwrap()
                .disk
                .as_ref()
                .unwrap()
                .serial,
            "SERIAL"
        );
    }
    assert_eq!(
        state.disks[&devices[0].key()].kernel_severity,
        Some(Severity::Critical)
    );
    for message in [
        "ata2: I/O error, dev sdz",
        "I/O error, dev sdbb",
        "I/O error, dev sdb and dev sdc",
        "ata2.00: timeout",
    ] {
        let record = kernel::parse(&serde_json::json!({"MESSAGE":message}).to_string()).unwrap();
        assert!(
            kernel::fresh_match(&record, &devices, Some("boot")).is_none(),
            "{message}"
        );
    }
    let record = kernel::parse(r#"{"MESSAGE":"I/O error, dev sdb"}"#).unwrap();
    assert!(kernel::fresh_match(&record, &[], Some("boot")).is_none());
}

fn merge_test_disks() -> (Device, smart::Snapshot, Device, smart::Snapshot) {
    let a = Device {
        path: "/dev/sde".into(),
        model: "WDC WD30PURX".into(),
        serial: "WC3K2013DDMM".into(),
        wwn: "50014ee200000001".into(),
        ..device()
    };
    let b = Device {
        path: "/dev/sdf".into(),
        model: "Patriot Burst".into(),
        serial: "1B0607890D0804289031".into(),
        kind: Kind::Ssd,
        ..device()
    };
    let bad = smart::Snapshot {
        model: a.model.clone(),
        serial: a.serial.clone(),
        wwn: a.wwn.clone(),
        counters: [
            ("Current_Pending_Sector".into(), 58),
            ("Offline_Uncorrectable".into(), 10),
            ("Reallocated_Sector_Ct".into(), 15),
            ("UDMA_CRC_Error_Count".into(), 6779),
        ]
        .into(),
        temperature: Some(52),
        power_on_hours: Some(10000),
        passed: Some(false),
        ..Default::default()
    };
    let absent = smart::Snapshot {
        model: b.model.clone(),
        serial: b.serial.clone(),
        passed: Some(true),
        ..Default::default()
    };
    (a, bad, b, absent)
}

#[test]
fn state_merge_isolated_with_reordered_disks_and_reused_paths() {
    for use_wwn in [false, true] {
        let (mut a, mut bad, mut b, absent) = merge_test_disks();
        if !use_wwn {
            a.wwn.clear();
            bad.wwn.clear();
        }
        let mut state = State::default();
        let mut topology = vec![];
        let (tx, _) = mpsc::channel(64);
        let cfg = Config::default();
        for reverse in [false, true] {
            let mut found = vec![a.clone(), b.clone()];
            if reverse {
                std::mem::swap(&mut a.path, &mut b.path);
                found = vec![b.clone(), a.clone()];
            }
            apply_scan(&mut state, Scan::Inventory(found), &mut topology, &cfg, &tx);
            let mut results = vec![(a.clone(), bad.clone()), (b.clone(), absent.clone())];
            if reverse {
                results.reverse();
            }
            for (d, s) in results {
                apply_scan(
                    &mut state,
                    Scan::Disk(d, Ok(smart::Reading::Checked(Box::new(s)))),
                    &mut topology,
                    &cfg,
                    &tx,
                );
            }
            let b_state = state.disks[&b.key()].snapshot.as_ref().unwrap();
            assert!(b_state.counters.is_empty());
            assert!(b_state.stale_fields.is_empty());
            assert_eq!(b_state.temperature, None);
            assert_eq!(b_state.power_on_hours, None);
            assert_eq!(
                state.disks[&a.key()].snapshot.as_ref().unwrap().counters,
                bad.counters
            );
        }
        // Missing measurements of A still retain A's own last-known values.
        let mut missing = bad.clone();
        missing.counters.clear();
        apply_scan(
            &mut state,
            Scan::Disk(a.clone(), Ok(smart::Reading::Checked(Box::new(missing)))),
            &mut topology,
            &cfg,
            &tx,
        );
        let retained = state.disks[&a.key()].snapshot.as_ref().unwrap();
        assert_eq!(retained.counters, bad.counters);
        assert!(retained.stale_fields.contains("Current_Pending_Sector"));
    }
}

#[test]
fn inventory_never_borrows_wwn_from_path_or_serial_alone() {
    for same_serial in [false, true] {
        let (mut a, bad, mut b, _) = merge_test_disks();
        a.diskseq = Some(42);
        if same_serial {
            b.serial = a.serial.clone(); // Model differs: not the same model+serial identity.
        } else {
            b.path = a.path.clone();
            b.diskseq = a.diskseq; // diskseq can repeat across boots.
        }
        let mut state = State::default();
        let mut old = DiskState::new(a.clone());
        old.snapshot = Some(bad);
        state.disks.insert(a.key(), old);
        let mut topology = vec![];
        let (tx, _) = mpsc::channel(32);
        apply_scan(
            &mut state,
            Scan::Inventory(vec![b.clone()]),
            &mut topology,
            &Config::default(),
            &tx,
        );
        assert_eq!(topology[0].key(), b.key());
        assert!(state.disks[&b.key()].snapshot.is_none());
        assert_eq!(state.disks[&a.key()].device.serial, a.serial);
    }
}

#[test]
fn state_merge_never_uses_cached_identity_of_another_disk_at_same_path() {
    let (a, bad, mut b, absent) = merge_test_disks();
    b.path = a.path.clone();
    let mut state = State::default();
    let mut old = DiskState::new(a.clone());
    old.snapshot = Some(bad.clone());
    state.disks.insert(a.key(), old);
    let mut topology = vec![a.clone()];
    let (tx, _) = mpsc::channel(32);
    apply_scan(
        &mut state,
        Scan::Disk(b.clone(), Ok(smart::Reading::Checked(Box::new(absent)))),
        &mut topology,
        &Config::default(),
        &tx,
    );
    let current = state
        .disks
        .values()
        .find(|d| d.device.serial == b.serial)
        .unwrap();
    assert!(current.snapshot.as_ref().unwrap().counters.is_empty());
    assert!(current.snapshot.as_ref().unwrap().stale_fields.is_empty());
    assert_eq!(current.device.key(), b.key());
    assert_eq!(
        state.disks[&a.key()].snapshot.as_ref().unwrap().counters,
        bad.counters
    );
    assert_eq!(topology[0].serial, a.serial);
}

#[test]
fn state_merge_rejects_snapshot_with_another_identity() {
    let (_, bad, b, absent) = merge_test_disks();
    let mut state = State::default();
    let mut old = DiskState::new(b.clone());
    old.snapshot = Some(bad);
    old.hot = true;
    state.disks.insert(b.key(), old);
    let (tx, _) = mpsc::channel(32);
    apply_result(
        &mut state,
        b.clone(),
        Ok(smart::Reading::Checked(Box::new(absent))),
        &Config::default(),
        &tx,
    );
    let current = &state.disks[&b.key()];
    let snapshot = current.snapshot.as_ref().unwrap();
    assert!(snapshot.counters.is_empty());
    assert!(snapshot.stale_fields.is_empty());
    assert_eq!(snapshot.temperature, None);
    assert!(!current.hot);
    assert!(
        !state
            .recent_alerts
            .iter()
            .any(|e| e.category == "Current_Pending_Sector")
    );
}

#[test]
fn state_merge_does_not_migrate_path_history_into_stable_identity() {
    let (_, bad, b, absent) = merge_test_disks();
    let mut unknown = b.clone();
    unknown.model.clear();
    unknown.serial.clear();
    let mut state = State::default();
    let mut old = DiskState::new(unknown.clone());
    old.snapshot = Some(bad);
    state.disks.insert(unknown.key(), old);
    let mut topology = vec![unknown.clone()];
    let (tx, _) = mpsc::channel(32);
    apply_scan(
        &mut state,
        Scan::Disk(unknown, Ok(smart::Reading::Checked(Box::new(absent)))),
        &mut topology,
        &Config::default(),
        &tx,
    );
    let snapshot = state.disks[&b.key()].snapshot.as_ref().unwrap();
    assert!(snapshot.counters.is_empty());
    assert!(snapshot.stale_fields.is_empty());
}

#[test]
fn state_merge_preserves_own_history_when_wwn_is_learned() {
    let (mut a, bad, _, _) = merge_test_disks();
    a.wwn.clear();
    let old_key = a.key();
    let mut state = State::default();
    let mut old = DiskState::new(a.clone());
    let mut previous = bad.clone();
    previous.wwn.clear();
    old.snapshot = Some(previous);
    state.disks.insert(old_key.clone(), old);
    let mut topology = vec![a.clone()];
    let mut missing = bad.clone();
    missing.counters.clear();
    let (tx, _) = mpsc::channel(32);
    apply_scan(
        &mut state,
        Scan::Disk(a.clone(), Ok(smart::Reading::Checked(Box::new(missing)))),
        &mut topology,
        &Config::default(),
        &tx,
    );
    assert_eq!(state.disks.len(), 1);
    assert!(!state.disks.contains_key(&old_key));
    let key = topology[0].key();
    let retained = state.disks[&key].snapshot.as_ref().unwrap();
    assert_eq!(retained.counters, bad.counters);
    assert!(retained.stale_fields.contains("Current_Pending_Sector"));
    // The next inventory still has no WWN and uses a different path.
    a.path = "/dev/sdz".into();
    apply_scan(
        &mut state,
        Scan::Inventory(vec![a]),
        &mut topology,
        &Config::default(),
        &tx,
    );
    assert_eq!(topology[0].key(), key);
    assert_eq!(state.disks.len(), 1);
    assert_eq!(state.disks[&key].device.path, "/dev/sdz");
}

#[test]
fn kernel_history_stays_with_matched_disk_identity() {
    for zero_in_discovery in [false, true] {
        let (mut a, _, mut b, _) = merge_test_disks();
        a.wwn = if zero_in_discovery {
            "0000000000000000"
        } else {
            ""
        }
        .into();
        b.wwn = a.wwn.clone();
        a.aliases = vec!["sde".into(), "ata2".into()];
        b.aliases = vec!["sdf".into(), "ata2".into()];
        let mut state = State::default();
        let mut topology = vec![];
        let cfg = Config::default();
        let (tx, _) = mpsc::channel(64);
        apply_scan(
            &mut state,
            Scan::Inventory(vec![a.clone(), b.clone()]),
            &mut topology,
            &cfg,
            &tx,
        );
        // Both disks return the same unusable WWN in SMART.
        for d in [&a, &b] {
            let snapshot = smart::parse(
                &serde_json::to_vec(&serde_json::json!({
                    "model_name": d.model, "serial_number": d.serial,
                    "wwn": {"naa":0, "oui":0, "id":0},
                    "smart_status": {"passed":true}
                }))
                .unwrap(),
                0,
            )
            .unwrap();
            apply_scan(
                &mut state,
                Scan::Disk(d.clone(), Ok(smart::Reading::Checked(Box::new(snapshot)))),
                &mut topology,
                &cfg,
                &tx,
            );
        }
        handle_kernel(
            &mut state,
            kernel::parse(r#"{"MESSAGE":"I/O error, dev sde"}"#).unwrap(),
            &topology,
            &cfg,
            &tx,
        );
        let event = state.recent_alerts.last().unwrap();
        assert_eq!(event.disk.as_ref().unwrap().serial, a.serial);
        let patriot = state
            .disks
            .values()
            .find(|d| d.device.serial == b.serial)
            .unwrap();
        assert_eq!(patriot.health(), "OK");
        assert_eq!(patriot.kernel_severity, None);
        assert_eq!(patriot.kernel_last_message, None);
        assert_eq!(patriot.kernel_last_seen, None);
        assert_eq!(state.disks.len(), 2);
        assert_eq!(state.disks[&a.key()].health(), "Critical");
        assert_eq!(
            state.disks[&a.key()].kernel_last_message.as_deref(),
            Some("I/O error, dev sde")
        );
        assert!(!state.disks.keys().any(|k| k == "wwn:0000000000000000"));

        // Persistence and a later path swap must not transfer the evidence to B.
        let dir = temp();
        let path = dir.join("state.json");
        state.save(&path).unwrap();
        state = state::read(&path).unwrap();
        std::mem::swap(&mut a.path, &mut b.path);
        std::mem::swap(&mut a.aliases, &mut b.aliases);
        apply_scan(
            &mut state,
            Scan::Inventory(vec![b.clone(), a.clone()]),
            &mut topology,
            &cfg,
            &tx,
        );
        assert_eq!(state.disks[&a.key()].health(), "Critical");
        assert_eq!(state.disks[&b.key()].health(), "OK");
        assert_eq!(state.disks[&b.key()].kernel_last_message, None);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn uncorrelated_kernel_evidence_does_not_change_any_disk() {
    let (mut a, _, mut b, _) = merge_test_disks();
    a.aliases = vec!["sde".into(), "ata2".into()];
    b.aliases = vec!["sdf".into(), "ata2".into()];
    let topology = vec![a, b];
    let mut state = State::default();
    let cfg = Config::default();
    let (tx, _) = mpsc::channel(64);
    apply_inventory(&mut state, &topology, &cfg, &tx);
    let before = serde_json::to_value(&state.disks).unwrap();
    for message in [
        "I/O error",
        "I/O error, dev sdz",
        "ata2: I/O error, dev sdz",
        "I/O error, dev sde and dev sdf",
        "ata2: hard resetting link",
    ] {
        handle_kernel(
            &mut state,
            kernel::parse(&serde_json::json!({"MESSAGE":message}).to_string()).unwrap(),
            &topology,
            &cfg,
            &tx,
        );
        assert!(
            state.recent_alerts.last().unwrap().disk.is_none(),
            "{message}"
        );
        assert_eq!(
            serde_json::to_value(&state.disks).unwrap(),
            before,
            "{message}"
        );
    }
}

#[test]
fn kernel_handler_keeps_the_identity_selected_by_direct_path_match() {
    let (mut a, _, mut b, _) = merge_test_disks();
    a.aliases.clear();
    b.aliases.clear();
    let topology = [a.clone(), b.clone()];
    let mut state = State::default();
    let cfg = Config::default();
    let (tx, _) = mpsc::channel(32);
    apply_inventory(&mut state, &topology, &cfg, &tx);
    let record = kernel::parse(r#"{"MESSAGE":"I/O error, dev sde"}"#).unwrap();
    assert_eq!(
        kernel::fresh_match(&record, &topology, None)
            .unwrap()
            .serial,
        a.serial
    );
    handle_kernel(&mut state, record, &topology, &cfg, &tx);
    assert_eq!(
        state.disks[&a.key()].kernel_severity,
        Some(Severity::Critical)
    );
    assert_eq!(state.disks[&b.key()].kernel_severity, None);
    assert_eq!(
        state
            .recent_alerts
            .last()
            .unwrap()
            .disk
            .as_ref()
            .unwrap()
            .key(),
        a.key()
    );
}

#[test]
fn zero_wwn_is_absent_in_discovery_smart_and_identity() {
    for wwn in [
        "0000000000000000",
        "0x0000000000000000",
        "0X0000000000000000",
        "00:00:00:00:00:00:00:00",
        " 0000 0000 0000 0000 ",
    ] {
        let parsed = devices::parse(&serde_json::to_vec(&serde_json::json!({"blockdevices":[{
            "name":"/dev/sdf", "type":"disk", "model":"Patriot Burst", "serial":"1B0607890D0804289031", "wwn":wwn
        }]})).unwrap()).unwrap();
        assert!(parsed[0].wwn.is_empty(), "{wwn}");
        let mut d = parsed[0].clone();
        let key = d.key();
        d.wwn = wwn.into(); // Also protect keys constructed from persisted/raw values.
        assert_eq!(d.key(), key);
        assert!(d.same_identity(&parsed[0]));
        let snapshot = smart::parse(
            &serde_json::to_vec(
                &serde_json::json!({"logical_unit_id":wwn, "smart_status":{"passed":true}}),
            )
            .unwrap(),
            0,
        )
        .unwrap();
        assert!(snapshot.wwn.is_empty(), "{wwn}");
        let mut known = snapshot.clone();
        known.wwn = "50014ee200000001".into();
        assert!(smart::identity_mismatch(&d, &known).is_none());
        fill_identity(&mut d, "", "", &known.wwn);
        assert_eq!(d.wwn, known.wwn);
        let mut unknown = device();
        unknown.serial.clear();
        unknown.wwn = wwn.into();
        assert_eq!(unknown.key(), "path:/dev/sdb");
        assert!(!unknown.same_identity(&unknown));
    }
    let zero = smart::parse(
        br#"{"wwn":{"naa":0,"oui":0,"id":0},"smart_status":{"passed":true}}"#,
        0,
    )
    .unwrap();
    assert!(zero.wwn.is_empty());
    let valid = smart::parse(
        br#"{"wwn":{"naa":5,"oui":0,"id":1},"smart_status":{"passed":true}}"#,
        0,
    )
    .unwrap();
    assert_eq!(valid.wwn, "5000000000000001");
}

#[test]
fn legacy_zero_wwn_history_is_not_reassigned_to_its_last_device() {
    let (a, _, mut b, _) = merge_test_disks();
    b.wwn = "0000000000000000".into();
    let mut state = State::default();
    let mut shared = DiskState::new(b);
    shared.kernel_severity = Some(Severity::Critical);
    shared.kernel_last_message = Some("I/O error, dev sde".into());
    state.disks.insert("wwn:0000000000000000".into(), shared);
    state.disks.insert(a.key(), DiskState::new(a.clone()));
    let dir = temp();
    let path = dir.join("state.json");
    state.save(&path).unwrap();
    let loaded = state::read(&path).unwrap();
    assert!(!loaded.disks.contains_key("wwn:0000000000000000"));
    assert_eq!(loaded.disks.len(), 1);
    assert!(loaded.disks.contains_key(&a.key()));
    // Reading does not modify the original file.
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("I/O error, dev sde")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bracket_kernel_correlation_uses_only_current_discovery() {
    let (mut a, _, mut b, _) = merge_test_disks();
    a.aliases = vec!["sde".into(), "ata5".into()];
    b.aliases = vec!["sdf".into()];
    let cfg = Config::default();
    let (tx, _) = mpsc::channel(64);
    for (message, expected) in [
        ("I/O error, dev sde, sector 123", Some(&a)),
        (
            "sd 4:0:0:0: [sde] tag#10 Sense Key : Medium Error",
            Some(&a),
        ),
        (
            "sd 4:0:0:0: [sde] Add. Sense: Unrecovered read error",
            Some(&a),
        ),
        ("I/O error, dev sdf [sde]", Some(&b)),
        ("I/O error, dev sdz [sde]", None),
        ("sd 4:0:0:0: [sdz] Sense Key : Medium Error", None),
        ("ata5.00: [sdz] error: { UNC }", None),
        ("ata5.00: error: { UNC }", None),
        ("I/O error [sde] [sdf]", None),
        ("I/O error [sde] [sdz]", None),
    ] {
        let topology = vec![a.clone(), b.clone()];
        let mut state = State::default();
        apply_inventory(&mut state, &topology, &cfg, &tx);
        let before = serde_json::to_value(&state.disks).unwrap();
        let record = kernel::parse(&serde_json::json!({"MESSAGE":message}).to_string()).unwrap();
        handle_kernel(&mut state, record, &topology, &cfg, &tx);
        let event = state.recent_alerts.last().unwrap();
        assert_eq!(event.message, message);
        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(
            event.disk.as_ref().map(Device::key),
            expected.map(Device::key),
            "{message}"
        );
        if let Some(d) = expected {
            assert_eq!(event.disk.as_ref().unwrap().path, d.path);
            assert_eq!(state.disks[&d.key()].health(), "Critical");
            let other = if d.key() == a.key() { &b } else { &a };
            assert_eq!(
                serde_json::to_value(&state.disks[&other.key()]).unwrap(),
                before[other.key()]
            );
        } else {
            assert_eq!(serde_json::to_value(&state.disks).unwrap(), before);
        }
    }
    // A persisted disk at /dev/sde is not evidence that it is still present.
    let mut state = State::default();
    apply_inventory(&mut state, &[a.clone(), b.clone()], &cfg, &tx);
    apply_inventory(&mut state, std::slice::from_ref(&b), &cfg, &tx);
    let before = serde_json::to_value(&state.disks).unwrap();
    handle_kernel(
        &mut state,
        kernel::parse(r#"{"MESSAGE":"sd 4:0:0:0: [sde] Sense Key : Medium Error"}"#).unwrap(),
        &[b],
        &cfg,
        &tx,
    );
    assert!(state.recent_alerts.last().unwrap().disk.is_none());
    assert_eq!(serde_json::to_value(&state.disks).unwrap(), before);
}

#[test]
fn bracket_nvme_namespace_uses_current_discovery_alias() {
    let mut d = device();
    d.kind = Kind::Nvme;
    d.path = "/dev/nvme0".into();
    d.aliases = vec!["nvme0".into(), "nvme0n1".into()];
    let mut state = State::default();
    let (tx, _) = mpsc::channel(8);
    handle_kernel(
        &mut state,
        kernel::parse(r#"{"MESSAGE":"[nvme0n1] I/O error"}"#).unwrap(),
        std::slice::from_ref(&d),
        &Config::default(),
        &tx,
    );
    assert_eq!(
        state
            .recent_alerts
            .last()
            .unwrap()
            .disk
            .as_ref()
            .map(Device::key),
        Some(d.key())
    );
    assert_eq!(state.disks[&d.key()].health(), "Critical");
}

fn summary_ok_disks(count: usize) -> State {
    let mut state = State::default();
    for index in 0..count {
        let mut d = device();
        d.serial = format!("DISK-{index}");
        d.model = format!("Disk-{index}");
        d.path = format!("/dev/test{index}");
        let mut disk = DiskState::new(d.clone());
        disk.check_status = state::CheckStatus::Checked;
        disk.snapshot = Some(smart::Snapshot {
            passed: Some(true),
            ..Default::default()
        });
        state.disks.insert(d.key(), disk);
    }
    state
}

#[test]
fn summary_counts_seven_disks_and_only_lists_critical_reasons() {
    let mut state = summary_ok_disks(7);
    let disk = state.disks.values_mut().next().unwrap();
    disk.device.model = "WD30PURX-89G0VS1".into();
    disk.device.path = "/dev/sde".into();
    disk.kernel_severity = Some(Severity::Critical);
    disk.kernel_last_message = Some("FULL KERNEL MESSAGE".into());
    let s = disk.snapshot.as_mut().unwrap();
    s.counters.insert("Current_Pending_Sector".into(), 58);
    s.counters.insert("Reallocated_Sector_Ct".into(), 15);
    s.counters.insert("UDMA_CRC_Error_Count".into(), 0);
    s.firmware = "PRIVATE-FIRMWARE".into();
    s.power_on_hours = Some(54321);
    s.temperature = Some(35);
    s.unknown_attributes
        .insert("VENDOR-ATTRIBUTE".into(), serde_json::json!(123));
    assert_eq!(
        status_summary(&state),
        "DISKS: 7\nOK: 6\nWARNING: 0\nCRITICAL: 1\nUNKNOWN: 0\n\nCRITICAL:\n  WD30PURX-89G0VS1 /dev/sde\n    pending=58\n    reallocated=15\n    kernel_io_errors=yes\n"
    );
}

#[test]
fn summary_all_ok_and_empty_inventory() {
    assert_eq!(
        status_summary(&summary_ok_disks(7)),
        "DISKS: 7\nOK: 7\nWARNING: 0\nCRITICAL: 0\nUNKNOWN: 0\n\nAll disks OK\n"
    );
    let empty = status_summary(&State::default());
    assert!(empty.starts_with("DISKS: 0\n"));
    assert!(!empty.contains("All disks OK"));
}

#[test]
fn summary_unknown_reasons_and_stale_values_keep_existing_health() {
    for (check, label) in [
        (state::CheckStatus::Failed, "failed"),
        (state::CheckStatus::Sleeping, "skipped_sleeping"),
    ] {
        let mut state = summary_ok_disks(1);
        let disk = state.disks.values_mut().next().unwrap();
        disk.check_status = check;
        let s = disk.snapshot.as_mut().unwrap();
        s.counters.insert("Current_Pending_Sector".into(), 58);
        s.stale_fields.insert("Current_Pending_Sector".into());
        let before = serde_json::to_value(&state).unwrap();
        let summary = status_summary(&state);
        assert!(summary.starts_with("DISKS: 1\nOK: 0\nWARNING: 0\nCRITICAL: 0\nUNKNOWN: 1\n"));
        assert!(summary.contains(&format!("smart_check={label}")));
        assert!(summary.contains("pending=58 (stale)"));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}

#[test]
fn summary_groups_warning_temperature_and_duplicate_models() {
    let mut state = summary_ok_disks(3);
    for (index, disk) in state.disks.values_mut().enumerate() {
        disk.device.model = "Same Model".into();
        match index {
            0 => {
                disk.kernel_severity = Some(Severity::Critical);
            }
            1 => {
                disk.hot = true;
                let s = disk.snapshot.as_mut().unwrap();
                s.temperature = Some(52);
                s.counters.insert("UDMA_CRC_Error_Count".into(), 3);
            }
            _ => {
                disk.check_status = state::CheckStatus::Never;
            }
        }
    }
    let summary = status_summary(&state);
    assert!(summary.find("\nCRITICAL:\n").unwrap() < summary.find("\nWARNING:\n").unwrap());
    assert!(summary.find("\nWARNING:\n").unwrap() < summary.find("\nUNKNOWN:\n").unwrap());
    assert!(summary.contains("temperature=52C"));
    assert!(summary.contains("crc_errors=3"));
    for i in 0..3 {
        assert!(summary.contains(&format!("serial=DISK-{i}")));
    }
}

#[test]
fn summary_counter_names_are_short_and_zero_counters_are_omitted() {
    let mut state = summary_ok_disks(1);
    let disk = state.disks.values_mut().next().unwrap();
    disk.kernel_severity = Some(Severity::Critical);
    let names = [
        ("Current_Pending_Sector", "pending"),
        ("Offline_Uncorrectable", "offline_uncorrectable"),
        ("Reallocated_Event_Count", "reallocated_events"),
        ("Reallocated_Sector_Ct", "reallocated"),
        ("Reported_Uncorrect", "reported_uncorrect"),
        ("UDMA_CRC_Error_Count", "crc_errors"),
        ("Command_Timeout", "command_timeouts"),
    ];
    for (original, _) in names {
        disk.snapshot
            .as_mut()
            .unwrap()
            .counters
            .insert(original.into(), 3);
    }
    let summary = status_summary(&state);
    for (original, label) in names {
        assert!(summary.contains(&format!("    {label}=3\n")));
        assert!(!summary.contains(original));
    }
    for value in state
        .disks
        .values_mut()
        .next()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .counters
        .values_mut()
    {
        *value = 0;
    }
    let summary = status_summary(&state);
    for (_, label) in names {
        assert!(!summary.contains(&format!("{label}=")));
    }
    assert!(summary.contains("kernel_io_errors=yes"));
}
