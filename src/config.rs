use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{fs, path::Path};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub check_interval_seconds: u64,
    pub command_timeout_seconds: u64,
    pub temperature: Temperature,
    pub alerts: Alerts,
    pub kernel: Enabled,
    pub smart: Smart,
    pub devices: Devices,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Temperature {
    pub hdd_warning: i64,
    pub ssd_warning: i64,
    pub nvme_warning: i64,
    pub hysteresis: i64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Alerts {
    pub desktop: bool,
    pub telegram: bool,
    pub kernel_cooldown_seconds: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Enabled {
    pub enabled: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Smart {
    pub enabled: bool,
    pub skip_sleeping: bool,
}
impl Default for Smart {
    fn default() -> Self {
        Self {
            enabled: true,
            skip_sleeping: true,
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Devices {
    pub ignore_serials: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            check_interval_seconds: 1800,
            command_timeout_seconds: 60,
            temperature: Temperature::default(),
            alerts: Alerts::default(),
            kernel: Enabled::default(),
            smart: Smart::default(),
            devices: Devices::default(),
        }
    }
}
impl Default for Enabled {
    fn default() -> Self {
        Self { enabled: true }
    }
}
impl Default for Temperature {
    fn default() -> Self {
        Self {
            hdd_warning: 50,
            ssd_warning: 60,
            nvme_warning: 70,
            hysteresis: 5,
        }
    }
}
impl Default for Alerts {
    fn default() -> Self {
        Self {
            desktop: false,
            telegram: false,
            kernel_cooldown_seconds: 300,
        }
    }
}
impl Config {
    pub fn load(path: &Path, explicit: bool) -> Result<Self> {
        let value = match fs::read_to_string(path) {
            Ok(s) => toml::from_str::<Self>(&s).context("invalid configuration")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => Self::default(),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        ensure!(
            value.check_interval_seconds > 0 && value.command_timeout_seconds > 0,
            "intervals must be positive"
        );
        let t = &value.temperature;
        ensure!(
            (0..=100).contains(&t.hysteresis),
            "invalid temperature hysteresis"
        );
        ensure!(
            [t.hdd_warning, t.ssd_warning, t.nvme_warning]
                .iter()
                .all(|n| (1..=200).contains(n) && *n > t.hysteresis),
            "invalid temperature thresholds"
        );
        ensure!(
            !value.alerts.telegram,
            "Telegram is not implemented in this MVP"
        );
        Ok(value)
    }
}
