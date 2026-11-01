use crate::devices::{Device, Kind, command, nonzero_wwn};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ExitStatus {
    pub mask: u8,
    pub incomplete: bool,
    pub disk_failing: bool,
    pub prefailure: bool,
    pub past_threshold: bool,
    pub error_log: bool,
    pub self_test_log: bool,
}
impl ExitStatus {
    fn new(mask: u8) -> Self {
        Self {
            mask,
            incomplete: mask & 7 != 0,
            disk_failing: mask & 8 != 0,
            prefailure: mask & 16 != 0,
            past_threshold: mask & 32 != 0,
            error_log: mask & 64 != 0,
            self_test_log: mask & 128 != 0,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfTestStatus {
    Passed,
    Failed,
    Aborted,
    InProgress,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributeState {
    Available,
    Unsupported,
    Stale,
    ReadError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtaAttribute {
    pub id: u8,
    pub name: String,
    pub normalized_value: Option<u64>,
    pub raw: Value,
    pub state: AttributeState,
}
impl AtaAttribute {
    pub fn scalar_value(&self) -> Option<u64> {
        let value = self.raw["value"].as_u64()?;
        self.raw["string"]
            .as_str()
            .is_none_or(|text| text.trim().parse::<u64>().ok() == Some(value))
            .then_some(value)
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub model: String,
    pub model_family: String,
    pub serial: String,
    pub wwn: String,
    pub firmware: String,
    pub passed: Option<bool>,
    pub temperature: Option<i64>,
    pub power_on_hours: Option<u64>,
    pub counters: BTreeMap<String, u64>,
    pub attribute_states: BTreeMap<String, AttributeState>,
    // Physical ATA observations remain separate from diagnostic indicators.
    pub ata_attributes: Vec<AtaAttribute>,
    pub counter_sources: BTreeMap<String, BTreeSet<u8>>,
    // Keep uninterpreted vendor data for inspection; it never drives health alerts.
    pub unknown_attributes: BTreeMap<String, Value>,
    pub available_spare: Option<u64>,
    pub spare_threshold: Option<u64>,
    pub percentage_used: Option<u64>,
    pub remaining_life: Option<u64>,
    pub critical_warning: Option<u64>,
    pub prefailure: Option<bool>,
    pub self_test: Option<String>,
    pub self_test_hours: Option<u64>,
    pub self_test_status: Option<SelfTestStatus>,
    pub exit: ExitStatus,
    pub issue: Option<String>,
    pub stale_fields: BTreeSet<String>,
}
impl Snapshot {
    fn record_counter(&mut self, key: &str, id: u8, value: u64) {
        // CRC is a compatibility indicator, not a replacement for either raw
        // attribute. Max preserves alarms without adding unrelated raw counts.
        self.counters
            .entry(key.into())
            .and_modify(|old| *old = (*old).max(value))
            .or_insert(value);
        self.counter_sources
            .entry(key.into())
            .or_default()
            .insert(id);
        if self.attribute_states.get(key) != Some(&AttributeState::ReadError) {
            self.attribute_states
                .insert(key.into(), AttributeState::Available);
        }
    }
    pub fn attribute_state(&self, name: &str) -> AttributeState {
        if let Some(state) = self.attribute_states.get(name) {
            *state
        } else if self.issue.is_some() {
            AttributeState::ReadError
        } else if self.stale_fields.contains(name) {
            AttributeState::Stale
        } else if self.counters.contains_key(name) {
            AttributeState::Available
        } else {
            AttributeState::Unsupported
        }
    }
    /// Carry forward last-known measurements, explicitly marking them unavailable now.
    pub fn retain_missing(&mut self, old: &Self) {
        macro_rules! retain {
            ($($field:ident),+ $(,)?) => { $(
                if self.$field.is_none() && old.$field.is_some() {
                    self.$field = old.$field.clone();
                    self.stale_fields.insert(stringify!($field).into());
                }
            )+ };
        }
        retain!(
            passed,
            temperature,
            power_on_hours,
            available_spare,
            spare_threshold,
            percentage_used,
            remaining_life,
            critical_warning,
            prefailure,
            self_test,
            self_test_hours,
            self_test_status
        );
        for (key, value) in &old.counters {
            if let Some(current) = self.counters.get_mut(key) {
                let sources = self.counter_sources.get(key);
                let missing_source = old.counter_sources.get(key).is_some_and(|previous| {
                    previous
                        .iter()
                        .any(|id| !sources.is_some_and(|now| now.contains(id)))
                });
                // Legacy CRC had no source IDs and was last-writer-wins. A
                // smaller value from just one provider cannot clear old bad evidence.
                let unconfirmed_legacy_crc = key == "UDMA_CRC_Error_Count"
                    && *value > *current
                    && !old.counter_sources.contains_key(key)
                    && sources.is_some_and(|ids| !(ids.contains(&199) && ids.contains(&218)));
                if missing_source || unconfirmed_legacy_crc {
                    *current = (*current).max(*value);
                    self.stale_fields.insert(key.clone());
                    self.attribute_states.insert(
                        key.clone(),
                        if self.issue.is_some() {
                            AttributeState::ReadError
                        } else {
                            AttributeState::Stale
                        },
                    );
                    if unconfirmed_legacy_crc {
                        // Keep the legacy provenance unknown on subsequent polls.
                        self.counter_sources.remove(key);
                    } else if let Some(previous) = old.counter_sources.get(key) {
                        self.counter_sources
                            .entry(key.clone())
                            .or_default()
                            .extend(previous);
                    }
                }
            }
        }
        for (name, value) in &old.counters {
            if !self.counters.contains_key(name) {
                self.counters.insert(name.clone(), *value);
                // Explicit Not_In_Use can explain an old zero, but must never
                // erase a previous nonzero problem or mask a failed read.
                if (self.attribute_states.get(name) == Some(&AttributeState::Unsupported)
                    || old.attribute_state(name) == AttributeState::Unsupported)
                    && *value == 0
                    && self.issue.is_none()
                {
                    self.attribute_states
                        .insert(name.clone(), AttributeState::Unsupported);
                    continue;
                }
                self.stale_fields.insert(name.clone());
                self.attribute_states.insert(
                    name.clone(),
                    if self.issue.is_some() {
                        AttributeState::ReadError
                    } else {
                        AttributeState::Stale
                    },
                );
                if let Some(sources) = old.counter_sources.get(name) {
                    self.counter_sources.insert(name.clone(), sources.clone());
                }
            }
        }
        let fresh_ids: BTreeSet<_> = self
            .ata_attributes
            .iter()
            .filter(|a| a.state == AttributeState::Available)
            .map(|a| a.id)
            .collect();
        for previous in &old.ata_attributes {
            if !fresh_ids.contains(&previous.id) && previous.state != AttributeState::ReadError {
                let mut last_known = previous.clone();
                last_known.state = if self.issue.is_some() {
                    AttributeState::ReadError
                } else {
                    AttributeState::Stale
                };
                self.ata_attributes.push(last_known);
            }
        }
    }
    pub fn unknown(&self) -> bool {
        self.issue.is_some() || !self.stale_fields.is_empty() || self.passed.is_none()
    }
}
#[derive(Debug)]
pub enum Reading {
    Checked(Box<Snapshot>),
    Sleeping,
}
fn s(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().trim().into()
}
fn phison_profile(model: &str, family: &str) -> bool {
    matches!(family, "Phison Driven SSDs" | "Phison Driven OEM SSDs")
        || matches!(model, "Patriot Burst" | "KINGSTON SM2280S3G2120G")
        || model
            .strip_prefix("Patriot Burst ")
            .is_some_and(|capacity| matches!(capacity, "120GB" | "240GB" | "480GB" | "960GB"))
}
fn counter_name(id: Option<u64>, name: &str, model: &str, phison: bool) -> Option<&'static str> {
    match (id?, name) {
        (5, "Reallocated_Sector_Ct" | "Reallocated_Sector_Count") => Some("Reallocated_Sector_Ct"),
        (5, "Retired_Block_Count") if phison => Some("Reallocated_Sector_Ct"),
        (196, "Reallocated_Event_Count") => Some("Reallocated_Event_Count"),
        (197, "Current_Pending_Sector" | "Pending_Sector_Count") => Some("Current_Pending_Sector"),
        (198, "Offline_Uncorrectable") => Some("Offline_Uncorrectable"),
        (187, "Reported_Uncorrect") => Some("Reported_Uncorrect"),
        (187, "Uncorrectable_Error_Cnt") if model.starts_with("Samsung SSD 870 EVO ") => {
            Some("Reported_Uncorrect")
        }
        (199, "UDMA_CRC_Error_Count" | "CRC_Error_Count" | "SATA_CRC_Error_Count") => {
            Some("UDMA_CRC_Error_Count")
        }
        (218, "CRC_Error_Count") if phison => Some("vendor_crc_errors"),
        (188, "Command_Timeout" | "Command_Timeouts") => Some("Command_Timeout"),
        _ => None,
    }
}
fn normalize_ata(rows: &[Value]) -> Vec<AtaAttribute> {
    rows.iter()
        .filter_map(|row| {
            let id = u8::try_from(row["id"].as_u64()?)
                .ok()
                .filter(|id| *id != 0)?;
            Some(AtaAttribute {
                id,
                name: row["name"].as_str().unwrap_or("Unknown").trim().into(),
                normalized_value: row["value"].as_u64(),
                raw: row["raw"].clone(),
                state: if row["raw"]["value"].is_u64() {
                    AttributeState::Available
                } else {
                    AttributeState::ReadError
                },
            })
        })
        .collect()
}
fn interpret_ata(out: &mut Snapshot, attributes: &[AtaAttribute]) {
    let phison = phison_profile(&out.model, &out.model_family);
    let mut ids = BTreeSet::new();
    for a in attributes {
        let id = a.id;
        if !ids.insert(id) {
            out.issue
                .get_or_insert_with(|| format!("duplicate SMART attribute ID {id}"));
        }
        let name = a.name.as_str();
        let key = counter_name(Some(u64::from(id)), name, &out.model, phison);
        if phison && name == "Not_In_Use" {
            let unsupported = match id {
                196 => Some("Reallocated_Event_Count"),
                197 => Some("Current_Pending_Sector"),
                _ => None,
            };
            if let Some(key) = unsupported {
                out.attribute_states
                    .insert(key.into(), AttributeState::Unsupported);
            }
        }
        // ID 188 still requires explicit scalar formatting; packed raw is not
        // interpreted merely because its physical value was read successfully.
        let scalar = a
            .scalar_value()
            .filter(|_| key != Some("Command_Timeout") || a.raw["string"].is_string());
        if let (Some(key), Some(value)) = (key, scalar) {
            out.record_counter(key, id, value);
            if key == "vendor_crc_errors" {
                out.record_counter("UDMA_CRC_Error_Count", id, value);
            }
        } else {
            out.unknown_attributes
                .insert(format!("{id}:{name}"), a.raw.clone());
            if let Some(key) = key.filter(|key| *key != "Command_Timeout") {
                out.attribute_states
                    .insert(key.into(), AttributeState::ReadError);
                if key == "vendor_crc_errors" {
                    out.attribute_states
                        .insert("UDMA_CRC_Error_Count".into(), AttributeState::ReadError);
                }
                out.issue
                    .get_or_insert_with(|| format!("invalid scalar SMART attribute {id} {name}"));
            }
        }
        if matches!(
            name,
            "SSD_Life_Left" | "Percent_Lifetime_Remain" | "Media_Wearout_Indicator"
        ) {
            out.remaining_life = a.normalized_value.filter(|value| *value <= 100);
        }
    }
}
pub fn parse(bytes: &[u8], exit_code: i32) -> Result<Snapshot> {
    let process_mask = u8::try_from(exit_code).context("invalid smartctl exit status")?;
    let decoded = serde_json::from_slice::<Value>(bytes);
    // A process exit health bit remains useful even if JSON is truncated/invalid.
    let v = match decoded {
        Ok(v) => v,
        Err(e) if process_mask & 0x18 != 0 => {
            tracing::warn!(error=%e, "invalid SMART JSON; retaining exit health bits");
            Value::Null
        }
        Err(e) => return Err(e).context("invalid smartctl JSON"),
    };
    let json_mask = v["smartctl"]["exit_status"]
        .as_u64()
        .and_then(|n| u8::try_from(n).ok())
        .unwrap_or(0);
    let mut exit = ExitStatus::new(process_mask | json_mask);
    // Some USB bridges return attributes but cannot return ATA status registers.
    // Ignore only this specific command failure, not open/checksum/other errors.
    let unsupported_status = |message: &Value| {
        message["string"].as_str().is_some_and(|text| {
            text.trim()
                == "SMART Status not supported: Incomplete response, ATA output registers missing"
        })
    };
    // smartctl 7.2 may put only the attribute-check warning in JSON.
    let attribute_status = |message: &Value| {
        v["smart_status"]["passed"].is_boolean()
            && message["severity"] == "warning"
            && message["string"].as_str().is_some_and(|text| {
                text.trim() == "Warning: This result is based on an Attribute check."
            })
    };
    let status_limitation =
        |message: &Value| unsupported_status(message) || attribute_status(message);
    if exit.mask & 7 == 4
        && v["ata_smart_attributes"]["table"]
            .as_array()
            .is_some_and(|rows| {
                rows.iter()
                    .any(|row| row["name"].is_string() && row["raw"]["value"].is_u64())
            })
        && v["smartctl"]["messages"]
            .as_array()
            .is_some_and(|messages| {
                messages.iter().any(status_limitation)
                    && messages
                        .iter()
                        .all(|m| status_limitation(m) || m["severity"] == "info")
            })
    {
        exit.incomplete = false;
    }
    let usable = [
        "smart_status",
        "ata_smart_attributes",
        "nvme_smart_health_information_log",
        "scsi_error_counter_log",
    ]
    .iter()
    .any(|key| v[*key].is_object());
    ensure!(
        usable || exit.mask & 0xf8 != 0,
        "no usable SMART data (exit mask {}): {}",
        exit.mask,
        v["smartctl"]["messages"]
    );
    let incomplete = exit.incomplete || !usable;
    let mut out = Snapshot {
        model: s(&v, "model_name"),
        model_family: s(&v, "model_family"),
        serial: s(&v, "serial_number"),
        firmware: s(&v, "firmware_version"),
        exit,
        issue: incomplete.then(|| {
            format!(
                "incomplete SMART data (exit mask {}): {}",
                exit.mask, v["smartctl"]["messages"]
            )
        }),
        ..Snapshot::default()
    };
    if out.model.is_empty() {
        out.model = s(&v, "product");
    }
    if let (Some(naa), Some(oui), Some(id)) = (
        v["wwn"]["naa"].as_u64(),
        v["wwn"]["oui"].as_u64(),
        v["wwn"]["id"].as_u64(),
    ) && naa < 16
        && oui < (1 << 24)
        && id < (1 << 36)
    {
        out.wwn = format!("{:016x}", (naa << 60) | (oui << 36) | id);
    } else {
        out.wwn = s(&v, "logical_unit_id");
    }
    out.wwn = nonzero_wwn(&out.wwn).unwrap_or_default().to_owned();
    out.ata_attributes = v["ata_smart_attributes"]["table"]
        .as_array()
        .map(|rows| normalize_ata(rows))
        .unwrap_or_default();
    // On read/checksum failure the measurements may be unreliable. Preserve explicit
    // exit-status health evidence, but do not infer recovery from incomplete data.
    if exit.disk_failing {
        out.passed = Some(false);
    }
    if exit.prefailure {
        out.prefailure = Some(true);
    }
    if incomplete {
        for attribute in &mut out.ata_attributes {
            attribute.state = AttributeState::ReadError;
        }
        return Ok(out);
    }
    out.passed = out.passed.or_else(|| v["smart_status"]["passed"].as_bool());
    out.prefailure = Some(exit.prefailure);
    out.temperature = v["temperature"]["current"].as_i64();
    out.power_on_hours = v["power_on_time"]["hours"].as_u64();
    let attributes = std::mem::take(&mut out.ata_attributes);
    interpret_ata(&mut out, &attributes);
    out.ata_attributes = attributes;
    let nv = &v["nvme_smart_health_information_log"];
    out.critical_warning = nv["critical_warning"].as_u64();
    out.temperature = out.temperature.or_else(|| nv["temperature"].as_i64());
    out.power_on_hours = out.power_on_hours.or_else(|| nv["power_on_hours"].as_u64());
    out.available_spare = nv["available_spare"].as_u64();
    out.spare_threshold = nv["available_spare_threshold"].as_u64();
    out.percentage_used = nv["percentage_used"].as_u64();
    for key in ["media_errors", "num_err_log_entries"] {
        if let Some(n) = nv[key].as_u64() {
            out.counters.insert(key.into(), n);
        }
    }
    let ata = v
        .pointer("/ata_smart_self_test_log/extended/table/0")
        .or_else(|| v.pointer("/ata_smart_self_test_log/standard/table/0"));
    if let Some(test) = ata {
        out.self_test_hours = test["lifetime_hours"].as_u64();
        out.self_test = test["status"]["string"].as_str().map(str::to_owned);
        out.self_test_status = Some(match test["status"]["value"].as_u64().map(|n| n >> 4) {
            Some(0) => SelfTestStatus::Passed,
            Some(1 | 2) => SelfTestStatus::Aborted,
            Some(3..=8) => SelfTestStatus::Failed,
            Some(15) => SelfTestStatus::InProgress,
            _ => SelfTestStatus::Unknown,
        });
    }
    if let Some(test) = v.pointer("/nvme_self_test_log/table/0") {
        out.self_test_hours = test["power_on_hours"].as_u64();
        let result = &test["self_test_result"];
        out.self_test = result["string"].as_str().map(str::to_owned);
        out.self_test_status = Some(match result["value"].as_u64() {
            Some(0) => SelfTestStatus::Passed,
            Some(1 | 2 | 3 | 4 | 8 | 9) => SelfTestStatus::Aborted,
            Some(5..=7) => SelfTestStatus::Failed,
            _ => SelfTestStatus::Unknown,
        });
    }
    Ok(out)
}
pub fn identity_mismatch(d: &Device, s: &Snapshot) -> Option<String> {
    let serial_known = !d.serial.is_empty() && !s.serial.is_empty();
    let wwn_known = nonzero_wwn(&d.wwn).is_some() && nonzero_wwn(&s.wwn).is_some();
    let norm = |v: &str| {
        v.trim()
            .trim_start_matches("0x")
            .replace([':', ' '], "")
            .to_ascii_lowercase()
    };
    if serial_known && !d.matches_smart_serial(&s.serial) {
        Some(format!(
            "serial changed during check: {:?} -> {:?}",
            d.serial, s.serial
        ))
    } else if wwn_known && norm(&d.wwn) != norm(&s.wwn) {
        Some(format!(
            "WWN changed during check: {:?} -> {:?}",
            d.wwn, s.wwn
        ))
    // Model is a last resort only when neither source provides a stable ID.
    // A first SMART read may identify the drive inside an unnamed USB enclosure.
    } else if d.serial.is_empty()
        && s.serial.is_empty()
        && nonzero_wwn(&d.wwn).is_none()
        && nonzero_wwn(&s.wwn).is_none()
        && !d.model.is_empty()
        && !s.model.is_empty()
        && d.model != s.model
    {
        Some(format!(
            "model changed during check: {:?} -> {:?}",
            d.model, s.model
        ))
    } else {
        None
    }
}
pub async fn read(device: &Device, timeout: u64, skip_sleeping: bool) -> Result<Reading> {
    let skip = skip_sleeping && device.kind == Kind::Hdd;
    let mut args = vec!["-j", "-a"];
    if skip {
        args.extend(["-n", "standby,3"]);
    }
    args.push(&device.path);
    let out = command("smartctl", &args, timeout).await?;
    let code = out.status.code().context("smartctl terminated by signal")?;
    if skip && code == 3 {
        let v: Value =
            serde_json::from_slice(&out.stdout).context("invalid sleeping SMART JSON")?;
        let mode = v["power_mode"]["name"]
            .as_str()
            .or_else(|| v["power_mode"].as_str())
            .unwrap_or_default();
        let sleeping = |mode: &str| {
            matches!(
                mode.to_ascii_uppercase().as_str(),
                "STANDBY" | "STANDBY_Y" | "STANDBY_Z" | "SLEEP"
            )
        };
        // smartctl 7.2 reports the skip in messages, without a power_mode field.
        let legacy_sleeping = mode.is_empty()
            && v["smartctl"]["messages"]
                .as_array()
                .is_some_and(|messages| {
                    messages.iter().any(|m| {
                        m["string"]
                            .as_str()
                            .and_then(|s| s.trim().strip_prefix("Device is in "))
                            .and_then(|s| s.strip_suffix(" mode, exit(3)"))
                            .is_some_and(sleeping)
                    })
                });
        // Do not confuse arbitrary exit code 3 with the explicitly requested skip.
        ensure!(
            sleeping(mode) || legacy_sleeping,
            "SMART failed with exit 3 without a sleeping indication"
        );
        return Ok(Reading::Sleeping);
    }
    Ok(Reading::Checked(Box::new(parse(&out.stdout, code)?)))
}
