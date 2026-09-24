use crate::{
    alert::{Event, Severity},
    devices::command,
};
use anyhow::Result;

pub trait Notifier {
    async fn notify(&self, event: &Event) -> Result<()>;
}
pub struct Desktop;
impl Notifier for Desktop {
    async fn notify(&self, event: &Event) -> Result<()> {
        if event.severity == Severity::Info {
            return Ok(());
        }
        let title = format!("disk-watch: {:?}", event.severity);
        let identity = event
            .disk
            .as_ref()
            .map(|d| format!("{} serial={} {}", d.model, d.serial, d.path))
            .unwrap_or_else(|| "Unknown disk".into());
        // Escape notification markup supplied by device/kernel strings.
        let body = format!("{identity}\n{}", event.message)
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let out = command(
            "notify-send",
            &[
                "--app-name=disk-watch",
                "--urgency",
                if event.severity == Severity::Critical {
                    "critical"
                } else {
                    "normal"
                },
                "--",
                &title,
                &body,
            ],
            5,
        )
        .await?;
        anyhow::ensure!(
            out.status.success(),
            "notify-send failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }
}
pub fn start(
    enabled: bool,
) -> (
    tokio::sync::mpsc::Sender<Event>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(128);
    let accessible = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
    if enabled && !accessible {
        tracing::warn!(
            "desktop notifications disabled: DBUS_SESSION_BUS_ADDRESS is absent; see README"
        );
    }
    let task = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            if enabled
                && accessible
                && let Err(e) = Desktop.notify(&event).await
            {
                tracing::warn!(error=%e, "desktop notification failed");
            }
        }
    });
    (tx, task)
}
