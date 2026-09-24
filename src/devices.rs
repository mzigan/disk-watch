use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, process::Output, time::Duration};
use tokio::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Kind {
    Hdd,
    Ssd,
    Nvme,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub path: String,
    pub model: String,
    pub serial: String,
    pub wwn: String,
    pub kind: Kind,
    pub aliases: Vec<String>,
    #[serde(default)]
    pub diskseq: Option<u64>,
    #[serde(default)]
    pub discovered_at: u64,
    // Only discovery-confirmed WD USB devices may use the serial encoding exception.
    #[serde(default)]
    pub wd_usb: bool,
}
/// Treat an all-zero WWN (including common display formats) as unavailable.
/// Keep the existing string representation for valid identifiers and state keys.
pub fn nonzero_wwn(value: &str) -> Option<&str> {
    let value = value.trim();
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    digits
        .chars()
        .any(|c| c != '0' && c != ':' && c != '-' && !c.is_whitespace())
        .then_some(value)
}
impl Device {
    pub fn matches_smart_serial(&self, serial: &str) -> bool {
        if self.serial == serial {
            return true;
        }
        if !self.wd_usb {
            return false;
        }
        let raw = self.serial.as_bytes();
        let decoded = if !raw.is_empty()
            && raw.len().is_multiple_of(2)
            && raw.iter().all(u8::is_ascii_hexdigit)
        {
            let bytes: Vec<u8> = raw
                .chunks_exact(2)
                .map(|pair| {
                    let high = (pair[0] as char).to_digit(16).unwrap() as u8;
                    let low = (pair[1] as char).to_digit(16).unwrap() as u8;
                    high * 16 + low
                })
                .collect();
            if !bytes.iter().all(u8::is_ascii_graphic) {
                return false;
            }
            String::from_utf8(bytes).expect("validated ASCII serial")
        } else {
            self.serial.clone()
        };
        let discovery = decoded.strip_prefix("WD-").unwrap_or(&decoded);
        let smart = serial.strip_prefix("WD-").unwrap_or(serial);
        !discovery.is_empty() && discovery == smart
    }
    /// Match persisted ownership only by a stable identity, never by a device path.
    pub fn same_identity(&self, other: &Self) -> bool {
        if !self.serial.is_empty() && !other.serial.is_empty() && self.serial != other.serial {
            return false;
        }
        if let (Some(wwn), Some(other_wwn)) = (nonzero_wwn(&self.wwn), nonzero_wwn(&other.wwn)) {
            return wwn == other_wwn;
        }
        !self.model.is_empty()
            && !self.serial.is_empty()
            && self.model == other.model
            && self.serial == other.serial
    }
    pub fn key(&self) -> String {
        if let Some(wwn) = nonzero_wwn(&self.wwn) {
            format!("wwn:{wwn}")
        } else if !self.serial.is_empty() {
            format!("serial:{}:{}:{}", self.model.len(), self.model, self.serial)
        } else {
            format!("path:{}", self.path)
        }
    }
}
pub async fn command(program: &str, args: &[&str], timeout: u64) -> Result<Output> {
    tokio::time::timeout(
        Duration::from_secs(timeout),
        Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .with_context(|| format!("{program} timed out"))?
    .with_context(|| format!("execute {program}"))
}
fn string(v: &Value, name: &str) -> String {
    v[name].as_str().unwrap_or_default().trim().to_owned()
}
fn controller(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("nvme")?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let tail = &rest[digits..];
    (tail.starts_with('n') || tail.is_empty()).then_some(&name[..4 + digits])
}
pub fn parse(data: &[u8]) -> Result<Vec<Device>> {
    let root: Value = serde_json::from_slice(data)?;
    let rows = root["blockdevices"]
        .as_array()
        .context("lsblk missing blockdevices")?;
    let mut devices: BTreeMap<String, Device> = BTreeMap::new();
    for row in rows {
        if row["type"] != "disk" {
            continue;
        }
        let path = string(row, "name");
        let name = path.strip_prefix("/dev/").unwrap_or(&path);
        if ["loop", "ram", "zram", "dm-", "md"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        if !path.starts_with("/dev/") || name.contains('/') {
            continue;
        }
        let nvme = controller(name);
        let target = nvme.map(|c| format!("/dev/{c}")).unwrap_or(path.clone());
        let d = devices.entry(target.clone()).or_insert_with(|| Device {
            path: target,
            model: string(row, "model"),
            serial: string(row, "serial"),
            // NVMe WWNs identify namespaces, not the controller being monitored.
            wwn: if nvme.is_some() {
                String::new()
            } else {
                nonzero_wwn(&string(row, "wwn"))
                    .unwrap_or_default()
                    .to_owned()
            },
            kind: if nvme.is_some() {
                Kind::Nvme
            } else if row["rota"] == true || row["rota"] == 1 {
                Kind::Hdd
            } else {
                Kind::Ssd
            },
            aliases: vec![],
            diskseq: None,
            discovered_at: crate::alert::now(),
            wd_usb: string(row, "tran") == "usb"
                && matches!(
                    string(row, "vendor").as_str(),
                    "WD" | "WDC" | "Western Digital"
                ),
        });
        d.aliases.push(name.to_owned());
        if let Some(c) = nvme {
            d.aliases.push(c.to_owned());
        }
    }
    Ok(devices.into_values().collect())
}
pub async fn discover(timeout: u64) -> Result<Vec<Device>> {
    let out = command(
        "lsblk",
        &[
            "--json",
            "--paths",
            "--nodeps",
            "--output",
            "NAME,TYPE,MODEL,SERIAL,WWN,ROTA,TRAN,VENDOR",
        ],
        timeout,
    )
    .await?;
    ensure!(
        out.status.success(),
        "lsblk failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut devices = parse(&out.stdout)?;
    for d in &mut devices {
        d.diskseq = diskseq(d);
        for alias in d.aliases.clone() {
            let root = Path::new("/sys/class/block").join(&alias);
            if let Ok(real) = std::fs::canonicalize(&root) {
                for part in real.components() {
                    let s = part.as_os_str().to_string_lossy();
                    if s.strip_prefix("ata")
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    {
                        d.aliases.push(s.into_owned());
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(&root) {
                for entry in entries.flatten() {
                    if entry.path().join("partition").exists() {
                        d.aliases
                            .push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
            }
        }
        d.aliases.sort();
        d.aliases.dedup();
    }
    Ok(devices)
}

/// Linux diskseq distinguishes reuse of a block-device path. No guessing on old kernels.
pub fn diskseq(device: &Device) -> Option<u64> {
    let name = device
        .aliases
        .iter()
        .find(|a| !a.starts_with("ata") && (!a.starts_with("nvme") || a[4..].contains('n')))?;
    std::fs::read_to_string(Path::new("/sys/class/block").join(name).join("diskseq"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn physical_and_nvme_controller_dedup() {
        let d = parse(br#"{"blockdevices":[{"name":"/dev/sda","type":"disk","rota":true},{"name":"/dev/sda1","type":"part"},{"name":"/dev/loop0","type":"disk"},{"name":"/dev/dm-0","type":"disk"},{"name":"/dev/nvme0n1","type":"disk"},{"name":"/dev/nvme0n2","type":"disk"}]}"#).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].path, "/dev/nvme0");
        assert!(d[0].aliases.contains(&"nvme0n2".into()));
    }
}
