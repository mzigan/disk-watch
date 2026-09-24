use crate::{alert::Severity, devices::Device};
use anyhow::{Context, Result};
use serde_json::Value;
use std::process::Stdio;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    sync::mpsc,
};

#[derive(Debug)]
pub struct Record {
    pub cursor: Option<String>,
    pub timestamp: Option<u64>,
    pub message: String,
    pub boot_id: Option<String>,
    pub monotonic_usec: Option<u64>,
}
pub fn parse(line: &str) -> Result<Record> {
    let v: Value = serde_json::from_str(line)?;
    let message = if let Some(s) = v["MESSAGE"].as_str() {
        s.to_owned()
    } else if let Some(a) = v["MESSAGE"].as_array() {
        let bytes = a
            .iter()
            .filter_map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect::<Vec<_>>();
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        anyhow::bail!("journal MESSAGE missing");
    };
    Ok(Record {
        message,
        boot_id: v["_BOOT_ID"].as_str().map(str::to_owned),
        monotonic_usec: v["__MONOTONIC_TIMESTAMP"]
            .as_str()
            .and_then(|s| s.parse().ok()),
        cursor: v["__CURSOR"].as_str().map(str::to_owned),
        timestamp: v["__REALTIME_TIMESTAMP"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| n / 1_000_000),
    })
}
fn tokens(message: &str) -> impl Iterator<Item = &str> {
    message
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .filter(|s| !s.is_empty())
}
pub fn classify(message: &str) -> Option<(Severity, &'static str)> {
    let lower = message.to_ascii_lowercase();
    let critical = [
        ("i/o error", "io_error"),
        ("unrecovered read error", "medium_error"),
        ("medium error", "medium_error"),
        ("hard resetting link", "link_reset"),
        ("comreset failed", "link_reset"),
        ("aborted journal", "filesystem"),
        ("ext4-fs error", "filesystem"),
        ("remounting filesystem read-only", "filesystem"),
        ("blk_update_request", "io_error"),
        ("lost async page write", "io_error"),
    ];
    for (pattern, category) in critical {
        if lower.contains(pattern) {
            return Some((Severity::Critical, category));
        }
    }
    if tokens(message).any(|s| s == "UNC") {
        return Some((Severity::Critical, "medium_error"));
    }
    let storage = tokens(&lower).any(|s| {
        ["ata", "nvme", "scsi"].iter().any(|p| {
            s.strip_prefix(p)
                .is_some_and(|tail| tail.starts_with(|c: char| c.is_ascii_digit()))
        }) || s.strip_prefix("sd").is_some_and(|tail| {
            !tail.is_empty()
                && tail
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        }) || s == "ata"
            || s == "nvme"
            || s == "scsi"
            || s == "blk"
            || s == "block"
    });
    if storage && lower.contains("failed command") {
        return Some((Severity::Warning, "failed_command"));
    }
    if lower.contains("link is slow to respond") {
        return Some((Severity::Warning, "link_slow"));
    }
    if lower.contains("nvme") && lower.contains("reset") {
        return Some((Severity::Critical, "nvme_reset"));
    }
    if storage && (lower.contains("timeout") || lower.contains("timed out")) {
        return Some((Severity::Warning, "timeout"));
    }
    None
}
pub fn correlate<'a>(message: &str, devices: &'a [Device]) -> Option<&'a Device> {
    let words = tokens(message).collect::<Vec<_>>();
    for port in [false, true] {
        let mut matches = devices.iter().filter(|d| {
            d.aliases
                .iter()
                .any(|a| a.starts_with("ata") == port && words.contains(&a.as_str()))
        });
        if let Some(first) = matches.next() {
            return matches.next().is_none().then_some(first);
        }
        // An explicit but unknown sd/NVMe name must not fall back to an unrelated port.
        if !port
            && words.iter().any(|w| {
                w.starts_with("nvme")
                    || w.strip_prefix("sd").is_some_and(|s| {
                        !s.is_empty()
                            && s.bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                    })
            })
        {
            return None;
        }
    }
    None
}
pub fn current_boot() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().replace('-', ""))
}
pub fn fresh_match<'a>(
    record: &Record,
    devices: &'a [Device],
    boot: Option<&str>,
) -> Option<&'a Device> {
    // Explicit dev sdX takes priority over [sdX]/[nvmeXnY]. Both use only
    // the current discovery map; ATA-port freshness guards apply below.
    let words = tokens(&record.message).collect::<Vec<_>>();
    let mut names = words
        .windows(2)
        .filter(|w| w[0] == "dev" && w[1].starts_with("sd"))
        .map(|w| w[1])
        .collect::<Vec<_>>();
    if names.is_empty() {
        names = record
            .message
            .split('[')
            .skip(1)
            .filter_map(|part| part.split_once(']').map(|(name, _)| name))
            .filter(|name| {
                (name.starts_with("sd") || name.starts_with("nvme"))
                    && name.bytes().all(|b| b.is_ascii_alphanumeric())
            })
            .collect();
    }
    if !names.is_empty() {
        let mut matches = devices.iter().filter(|d| {
            // Multiple explicit names must all identify the same current disk.
            names.iter().all(|name| {
                d.path.strip_prefix("/dev/") == Some(*name) || d.aliases.iter().any(|a| a == name)
            })
        });
        let first = matches.next()?;
        return matches.next().is_none().then_some(first);
    }
    let d = correlate(&record.message, devices)?;
    if record.boot_id.as_deref() != boot
        || boot.is_none()
        || record.timestamp.is_none_or(|t| t <= d.discovered_at)
        || d.diskseq.is_none()
        || crate::devices::diskseq(d) != d.diskseq
    {
        return None;
    }
    Some(d)
}
pub fn arguments(cursor: Option<&str>, follow: bool) -> Vec<String> {
    let mut args: Vec<String> = ["-k", "-o", "json", "--no-pager"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if follow {
        args.push("-f".into());
    }
    if let Some(c) = cursor {
        args.extend(["--after-cursor".into(), c.into(), "-n".into(), "all".into()]);
    } else {
        args.extend(["-n".into(), "200".into()]);
    }
    args
}
/// An unexpected reader exit is fatal to the daemon; systemd restarts it.
/// A rejected cursor gets one bounded replay attempt before failing.
pub async fn follow(mut cursor: Option<String>, tx: mpsc::Sender<Record>) -> Result<()> {
    loop {
        let mut child = Command::new("journalctl")
            .args(arguments(cursor.as_deref(), true))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("start journalctl")?;
        let stdout = child.stdout.take().context("journalctl stdout missing")?;
        let mut lines = BufReader::new(stdout).lines();
        let mut received = false;
        while let Some(line) = lines.next_line().await? {
            match parse(&line) {
                Ok(record) => {
                    received = true;
                    tx.send(record).await.context("journal receiver closed")?;
                }
                Err(e) => tracing::warn!(error=%e, "invalid journal JSON record"),
            }
        }
        // stdout EOF is itself unexpected. Do not hang waiting for a still-running child.
        if !received && cursor.take().is_some() {
            tracing::warn!("journal cursor unavailable; retrying last 200 records");
            continue;
        }
        anyhow::bail!("kernel journal reader ended unexpectedly");
    }
}
