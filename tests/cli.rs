use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

struct Sandbox {
    root: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "disk-watch-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        let sandbox = Self { root };
        sandbox.script("lsblk", "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[{\"name\":\"/dev/sdb\",\"type\":\"disk\",\"model\":\"Patriot P210 512GB\",\"serial\":\"SSD-TEST1\",\"rota\":false}]}'\n");
        fs::write(
            sandbox.root.join("smart.json"),
            include_bytes!("fixtures/smart_ssd.json"),
        )
        .unwrap();
        sandbox.script("smartctl", "#!/bin/sh\ncat \"$DISK_WATCH_FIXTURE\"\n");
        sandbox.script("journalctl", "#!/bin/sh\nprintf '%s\\n' '{\"__CURSOR\":\"test-cursor\",\"MESSAGE\":\"I/O error, dev sdb, sector 123\"}'\n");
        fs::write(
            sandbox.root.join("config.toml"),
            "check_interval_seconds = 60\ncommand_timeout_seconds = 10\n",
        )
        .unwrap();
        sandbox
    }
    fn script(&self, name: &str, content: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn command(&self, action: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_disk-watch"));
        cmd.args(["--config"])
            .arg(self.root.join("config.toml"))
            .arg("--state")
            .arg(self.root.join("state.json"))
            .arg(action)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .env("DISK_WATCH_FIXTURE", self.root.join("smart.json"));
        cmd
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn check_status_and_restart_preserve_critical() {
    let env = Sandbox::new();
    let first = env.command("check").output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("health: Critical"));
    assert!(String::from_utf8_lossy(&first.stdout).contains("SMART overall passed: Some(true)"));
    let second = env.command("check").output().unwrap();
    assert!(second.status.success());
    assert!(!String::from_utf8_lossy(&second.stderr).contains("new disk discovered"));
    let status = env.command("status").output().unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("CRITICAL: 1"));
}
#[test]
fn daemon_reads_kernel_while_smart_is_slow_and_stops_cleanly() {
    let env = Sandbox::new();
    env.script(
        "smartctl",
        "#!/bin/sh\nsleep 5\ncat \"$DISK_WATCH_FIXTURE\"\n",
    );
    env.script("journalctl", "#!/bin/sh\nprintf '%s\\n' '{\"__CURSOR\":\"test-cursor\",\"MESSAGE\":\"I/O error, dev sdb\"}'\nexec sleep 30\n");
    let mut child = env
        .command("daemon")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(4);
    let observed = loop {
        if let Ok(data) = fs::read(env.root.join("state.json")) {
            let state: serde_json::Value = serde_json::from_slice(&data).unwrap();
            if state["recent_alerts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["severity"] == "Critical")
            {
                break state["disks"]
                    .as_object()
                    .unwrap()
                    .values()
                    .all(|d| d["snapshot"].is_null());
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let deadline = Instant::now() + Duration::from_secs(4);
    let exited = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        observed,
        "kernel event must be persisted before SMART completes"
    );
    assert!(exited, "SIGTERM must exit cleanly");
}

#[test]
fn two_checks_do_not_duplicate_kernel_records() {
    let env = Sandbox::new();
    env.script("journalctl", "#!/bin/sh\nprintf '%s\\n' '{\"__CURSOR\":\"one\",\"MESSAGE\":\"I/O error, dev sdb\"}' '{\"__CURSOR\":\"two\",\"MESSAGE\":\"ata2: hard resetting link\"}'\n");
    for _ in 0..2 {
        let result = env.command("check").output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(env.root.join("state.json")).unwrap()).unwrap();
    assert_eq!(
        state["recent_alerts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["category"].as_str().unwrap().starts_with("kernel_"))
            .count(),
        2
    );
}
#[test]
fn reader_exit_is_fatal_and_reported() {
    let env = Sandbox::new();
    env.script("journalctl", "#!/bin/sh\nexit 0\n");
    let err = fs::File::create(env.root.join("stderr")).unwrap();
    let mut child = env
        .command("daemon")
        .stdout(Stdio::null())
        .stderr(err)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            assert!(
                fs::read_to_string(env.root.join("stderr"))
                    .unwrap()
                    .contains("journal reader task stopped")
            );
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("daemon failed to notice reader exit");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
#[test]
fn first_smart_critical_is_published_before_slow_disks_finish() {
    let env = Sandbox::new();
    env.script("lsblk", "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[{\"name\":\"/dev/sdz\",\"type\":\"disk\",\"serial\":\"FAST\",\"rota\":false},{\"name\":\"/dev/sdy\",\"type\":\"disk\",\"serial\":\"SLOW\",\"rota\":false}]}'\n");
    env.script("smartctl", "#!/bin/sh\ncase \"$3\" in\n/dev/sdz) printf '%s\\n' '{\"serial_number\":\"FAST\",\"smart_status\":{\"passed\":false}}'; exit 8;;\n*) sleep 4; printf '%s\\n' '{\"serial_number\":\"SLOW\",\"smart_status\":{\"passed\":true}}';;\nesac\n");
    env.script("journalctl", "#!/bin/sh\nexec sleep 30\n");
    let err = fs::File::create(env.root.join("stderr")).unwrap();
    let mut child = env
        .command("daemon")
        .stdout(Stdio::null())
        .stderr(err)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let early = loop {
        if fs::read_to_string(env.root.join("stderr"))
            .unwrap()
            .contains("overall_health: unhealthy")
        {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert!(
        early,
        "Critical must be published without waiting for slow SMART commands"
    );
}
#[test]
fn sleeping_hdd_is_skipped_without_losing_previous_snapshot() {
    let env = Sandbox::new();
    env.script("lsblk", "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[{\"name\":\"/dev/sdz\",\"type\":\"disk\",\"model\":\"Patriot P210 512GB\",\"serial\":\"SSD-TEST1\",\"rota\":true}]}'\n");
    env.script("journalctl", "#!/bin/sh\nexit 0\n");
    assert!(env.command("check").output().unwrap().status.success());
    let before: serde_json::Value =
        serde_json::from_slice(&fs::read(env.root.join("state.json")).unwrap()).unwrap();
    env.script("smartctl", "#!/bin/sh\ncase \"$*\" in '-j -a -n standby,3 /dev/sdz') printf '%s\\n' '{\"power_mode\":{\"ata_value\":0,\"name\":\"STANDBY\"},\"smartctl\":{\"exit_status\":3}}'; exit 3;; *) exit 1;; esac\n");
    let result = env.command("check").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("SMART check: Sleeping"));
    let after: serde_json::Value =
        serde_json::from_slice(&fs::read(env.root.join("state.json")).unwrap()).unwrap();
    let a = before["disks"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    let b = after["disks"].as_object().unwrap().values().next().unwrap();
    assert_eq!(a["snapshot"], b["snapshot"]);
    assert_eq!(a["checked_at"], b["checked_at"]);
    assert!(b["smart_error"].is_null());
}

#[test]
fn smartctl_72_standby_syntax_and_legacy_sleeping_json() {
    let env = Sandbox::new();
    env.script("lsblk", "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[{\"name\":\"/dev/sdz\",\"type\":\"disk\",\"rota\":true}]}'\n");
    env.script("journalctl", "#!/bin/sh\nexit 0\n");
    // Exact argv check rejects the unsupported third -n parameter, like 7.2 does.
    env.script("smartctl", "#!/bin/sh\ncase \"$*\" in '-j -a -n standby,3 /dev/sdz') cat \"$DISK_WATCH_FIXTURE\"; exit 3;; *) exit 1;; esac\n");
    fs::write(
        env.root.join("smart.json"),
        include_bytes!("fixtures/smart_sleeping_72.json"),
    )
    .unwrap();
    let result = env.command("check").output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("SMART check: Sleeping"));
    // The custom code alone must not misclassify an unrelated error as sleeping.
    fs::write(env.root.join("smart.json"), r#"{"smartctl":{"version":[7,2],"exit_status":3,"messages":[{"string":"Device open failed","severity":"error"}]}}"#).unwrap();
    let failed = env.command("check").output().unwrap();
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stdout).contains("SMART check: Failed"));
}

#[test]
fn status_defaults_to_summary_and_verbose_preserves_details() {
    let env = Sandbox::new();
    assert!(env.command("check").output().unwrap().status.success());
    let full = env.command("status").arg("--verbose").output().unwrap();
    assert!(full.status.success());
    let full = String::from_utf8(full.stdout).unwrap();
    let brief = env.command("status").output().unwrap();
    assert!(brief.status.success());
    let brief = String::from_utf8(brief.stdout).unwrap();
    assert!(brief.starts_with("DISKS: 1\n"));
    assert!(brief.contains("kernel_io_errors=yes"));
    assert!(full.starts_with(&brief));
    let legacy = env.command("status").arg("--summary").output().unwrap();
    assert!(legacy.status.success());
    assert_eq!(String::from_utf8(legacy.stdout).unwrap(), brief);
    assert!(full.contains("firmware:"));
    assert!(full.contains("Recent events:"));
    assert!(!brief.contains("firmware:"));
    assert!(!brief.contains("Recent events:"));
    assert!(!brief.contains("uninterpreted vendor attributes"));
    assert!(!brief.contains("I/O error, dev sdb"));
}

#[test]
fn status_all_ok_is_short() {
    let env = Sandbox::new();
    env.script("journalctl", "#!/bin/sh\nexit 0\n");
    assert!(env.command("check").output().unwrap().status.success());
    let status = env.command("status").output().unwrap();
    assert!(status.status.success());
    assert_eq!(
        String::from_utf8(status.stdout).unwrap(),
        "DISKS: 1\nOK: 1\nWARNING: 0\nCRITICAL: 0\nUNKNOWN: 0\n\nAll disks OK\n"
    );
}

#[test]
fn absent_disk_history_is_only_shown_in_verbose_status() {
    let env = Sandbox::new();
    assert!(env.command("check").output().unwrap().status.success());
    let path = env.root.join("state.json");
    let before: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let old_disk = before["disks"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    env.script(
        "lsblk",
        "#!/bin/sh\nprintf '%s\\n' '{\"blockdevices\":[]}'\n",
    );
    env.script("journalctl", "#!/bin/sh\nexit 0\n");
    assert!(env.command("check").output().unwrap().status.success());
    let saved = fs::read(&path).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    let disk = state["disks"].as_object().unwrap().values().next().unwrap();
    assert_eq!(disk["present"], false);
    for field in [
        "snapshot",
        "kernel_severity",
        "kernel_last_message",
        "kernel_last_seen",
        "checked_at",
    ] {
        assert_eq!(disk[field], old_disk[field]);
    }
    let brief = env.command("status").output().unwrap();
    assert!(brief.status.success());
    assert_eq!(
        String::from_utf8(brief.stdout).unwrap(),
        "DISKS: 0\nOK: 0\nWARNING: 0\nCRITICAL: 0\nUNKNOWN: 0\n"
    );
    let full = env.command("status").arg("--verbose").output().unwrap();
    assert!(full.status.success());
    let full = String::from_utf8(full.stdout).unwrap();
    assert!(full.contains("present: false\n  last known health: Critical"));
    assert!(full.contains("SMART overall passed: Some(true)"));
    assert!(full.contains("I/O error, dev sdb, sector 123"));
    assert_eq!(fs::read(&path).unwrap(), saved);
}
