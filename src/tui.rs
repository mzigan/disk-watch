//! Read-only presentation. No discovery, SMART commands, journal reads, or state writes.
use crate::{
    alert::{Event, Severity, now},
    history::{self, Sample},
    state::{self, DiskState, State},
};
use anyhow::{Context, Result, ensure};
use crossterm::{
    event::{self, Event as Input, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Table, TableState,
        Wrap,
    },
};
use std::{
    io::{self, IsTerminal},
    path::Path,
    time::{Duration, SystemTime},
};

const RECENT: u64 = 24 * 3600;
fn clean(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn time(t: u64) -> String {
    i64::try_from(t)
        .ok()
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| format!("{t} (Unix)"))
}
fn color(health: &str) -> Color {
    match health {
        "Critical" => Color::Red,
        "Warning" => Color::Yellow,
        "OK" => Color::Green,
        _ => Color::Gray,
    }
}
fn same_event(a: &Event, b: &Event) -> bool {
    a.timestamp == b.timestamp
        && a.category == b.category
        && a.message == b.message
        && a.disk.as_ref().map(|d| d.key()) == b.disk.as_ref().map(|d| d.key())
}

#[derive(Clone, Debug)]
struct DiskView {
    identity: String,
    disk: DiskState,
    events: Vec<Event>,
    warning: usize,
    critical: usize,
    historical: bool,
    last_problem: Option<Event>,
    recent_critical: bool,
}
impl DiskView {
    fn new(identity: &str, disk: &DiskState, state: &State, timestamp: u64) -> Self {
        // Exact persisted ownership. Never reassign an event by its old /dev path.
        let mut events: Vec<_> = state
            .recent_alerts
            .iter()
            .filter(|e| e.disk.as_ref().is_some_and(|d| d.key() == identity))
            .cloned()
            .collect();
        if let Some(e) = &disk.kernel_last_critical
            && e.disk.as_ref().is_some_and(|d| d.key() == identity)
            && !events.iter().any(|existing| same_event(existing, e))
        {
            events.push(e.clone());
        }
        events.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
        let warning = events
            .iter()
            .filter(|e| e.severity == Severity::Warning)
            .count();
        let critical = events
            .iter()
            .filter(|e| e.severity == Severity::Critical)
            .count();
        let last_problem = events
            .iter()
            .find(|e| e.severity != Severity::Info)
            .cloned();
        let historical =
            warning + critical > 0 || disk.kernel_severity.is_some_and(|s| s != Severity::Info);
        let recent_critical = events.iter().any(|e| {
            e.severity == Severity::Critical
                && e.timestamp <= timestamp
                && timestamp - e.timestamp <= RECENT
        });
        Self {
            identity: identity.into(),
            disk: disk.clone(),
            events,
            warning,
            critical,
            historical,
            last_problem,
            recent_critical,
        }
    }
    fn rank(&self) -> u8 {
        if !self.disk.present {
            return 5;
        }
        match self.disk.health() {
            "Critical" => 0,
            "Warning" => 1,
            "Unknown" => 2,
            _ if self.recent_critical => 3,
            _ => 4,
        }
    }
    fn marker(&self, timestamp: u64) -> String {
        if !self.historical {
            return "-".into();
        }
        let recent = self
            .last_problem
            .as_ref()
            .is_some_and(|e| e.timestamp <= timestamp && timestamp - e.timestamp <= RECENT);
        format!(
            "HIST! {} C:{} W:{}",
            if recent { "RECENT" } else { "OLD" },
            self.critical,
            self.warning
        )
    }
    fn stale(&self, timestamp: u64, age: u64) -> bool {
        self.disk
            .checked_at
            .is_none_or(|t| timestamp.saturating_sub(t) > age)
            || self
                .disk
                .snapshot
                .as_ref()
                .is_some_and(|s| !s.stale_fields.is_empty())
            || self.disk.check_status != state::CheckStatus::Checked
    }
    fn details(&self, timestamp: u64, age: u64) -> String {
        let d = &self.disk;
        let s = d.snapshot.as_ref();
        let field = |key: &str| -> String {
            match s {
                Some(s) => format!(
                    "{} [{:?}]",
                    s.counters
                        .get(key)
                        .map(u64::to_string)
                        .unwrap_or_else(|| "-".into()),
                    s.attribute_state(key)
                ),
                None => "unavailable".into(),
            }
        };
        let last = self.last_problem.as_ref();
        let last_kernel = self
            .events
            .iter()
            .find(|e| e.category.starts_with("kernel"));
        format!(
            "Model: {}\nSerial: {}\nWWN: {}\nCurrent path: {}\nPresent: {}\n{}: {}{}\nHistorical problems: {}\nRecorded problems: C:{} W:{} (retained history)\nLast problem: {}\nLast severity: {}\nRecovery checks: {} / 3\nSMART check: {:?}\nSMART overall: {}\nTemperature: {}\nPending: {}\nReallocated: {}\nOffline uncorrectable: {}\nCRC errors: {}\nHistorical kernel errors: {}\nLast kernel problem: {}\n{}",
            clean(&d.device.model),
            clean(&d.device.serial),
            clean(&d.device.wwn),
            if d.present {
                clean(&d.device.path)
            } else {
                format!("ABSENT (last path {})", clean(&d.device.path))
            },
            d.present,
            if d.present {
                "Current health"
            } else {
                "Last known health"
            },
            d.health(),
            if self.stale(timestamp, age) {
                " [STALE SMART]"
            } else {
                ""
            },
            if self.historical {
                "YES"
            } else {
                "NO (no retained problems)"
            },
            self.critical,
            self.warning,
            last.map(|e| time(e.timestamp))
                .unwrap_or_else(|| "not retained".into()),
            last.map(|e| format!("{:?}", e.severity).to_uppercase())
                .unwrap_or_else(|| "not retained".into()),
            d.kernel_recovery_successes,
            d.check_status,
            s.and_then(|s| s.passed)
                .map(|p| if p { "PASSED" } else { "FAILED" })
                .unwrap_or("unknown"),
            s.and_then(|s| s.temperature)
                .map(|t| format!("{t} C"))
                .unwrap_or_else(|| "unavailable".into()),
            field("Current_Pending_Sector"),
            field("Reallocated_Sector_Ct"),
            field("Offline_Uncorrectable"),
            field("UDMA_CRC_Error_Count"),
            if d.kernel_severity.is_some_and(|s| s != Severity::Info) {
                "YES"
            } else {
                "NO"
            },
            d.kernel_last_seen
                .map(time)
                .unwrap_or_else(|| "none".into()),
            last_kernel
                .map(|e| clean(&e.message))
                .or_else(|| d.kernel_last_message.as_deref().map(clean))
                .unwrap_or_default()
        )
    }
    fn event_lines(&self) -> Vec<String> {
        self.events
            .iter()
            .map(|e| {
                format!(
                    "{} {:?} {}\n  current={} at_event={}\n  {}",
                    time(e.timestamp),
                    e.severity,
                    clean(&e.category),
                    if self.disk.present {
                        clean(&self.disk.device.path)
                    } else {
                        "ABSENT".into()
                    },
                    e.disk
                        .as_ref()
                        .map(|d| clean(&d.path))
                        .unwrap_or_else(|| "uncorrelated".into()),
                    clean(&e.message)
                )
            })
            .collect()
    }
}
struct Model {
    disks: Vec<DiskView>,
    state_stale: bool,
    error: Option<String>,
    uncorrelated: Vec<Event>,
}
impl Model {
    fn from_state(state: &State, timestamp: u64, modified: u64, max_age: u64) -> Self {
        let mut disks: Vec<_> = state
            .disks
            .iter()
            .map(|(id, d)| DiskView::new(id, d, state, timestamp))
            .collect();
        disks.sort_by(|a, b| {
            a.rank()
                .cmp(&b.rank())
                .then_with(|| a.disk.device.model.cmp(&b.disk.device.model))
                .then_with(|| a.identity.cmp(&b.identity))
        });
        Self {
            disks,
            state_stale: timestamp.saturating_sub(modified) > max_age,
            error: None,
            uncorrelated: state
                .recent_alerts
                .iter()
                .rev()
                .filter(|e| e.disk.is_none())
                .cloned()
                .collect(),
        }
    }
    fn load(path: &Path, max_age: u64) -> Result<Self> {
        let modified = path
            .metadata()
            .context("saved state unavailable")?
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs();
        Ok(Self::from_state(
            &state::read(path)?,
            now(),
            modified,
            max_age,
        ))
    }
    fn visible(&self, absent: bool) -> Vec<&DiskView> {
        self.disks
            .iter()
            .filter(|d| absent || d.disk.present)
            .collect()
    }
    fn banner(&self) -> String {
        let active: Vec<_> = self.disks.iter().filter(|d| d.disk.present).collect();
        let count = |health| active.iter().filter(|d| d.disk.health() == health).count();
        let hist = active.iter().filter(|d| d.historical).count();
        let current = if active.is_empty() {
            "NO ACTIVE DISKS".into()
        } else if count("OK") == active.len() {
            "CURRENT: ALL OK".into()
        } else {
            format!(
                "CURRENT PROBLEMS: {} | UNKNOWN: {}",
                count("Critical") + count("Warning"),
                count("Unknown")
            )
        };
        format!(
            "{}{} | DISKS: {} OK:{} W:{} C:{} U:{}\nHISTORY: {} ACTIVE DISK(S) WITH RECORDED PROBLEMS | ABSENT: {} | UNCORRELATED: {}",
            if self.state_stale || self.error.is_some() {
                "STALE / SAVED DATA | "
            } else {
                ""
            },
            current,
            active.len(),
            count("OK"),
            count("Warning"),
            count("Critical"),
            count("Unknown"),
            hist,
            self.disks.len() - active.len(),
            self.uncorrelated.len()
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Disks,
    Details,
    Events,
    Charts,
}
struct App {
    model: Model,
    selected: Option<String>,
    table: TableState,
    focus: Focus,
    show_absent: bool,
    uncorrelated: bool,
    range: u64,
    detail_scroll: u16,
    event_scroll: u16,
    samples: Vec<Sample>,
    history_error: Option<String>,
}
impl App {
    fn new(model: Model) -> Self {
        let mut app = Self {
            model,
            selected: None,
            table: TableState::default(),
            focus: Focus::Disks,
            show_absent: false,
            uncorrelated: false,
            range: RECENT,
            detail_scroll: 0,
            event_scroll: 0,
            samples: vec![],
            history_error: None,
        };
        app.reselect();
        app
    }
    fn reselect(&mut self) {
        let visible = self.model.visible(self.show_absent);
        let index = self
            .selected
            .as_ref()
            .and_then(|key| visible.iter().position(|d| &d.identity == key))
            .or(if visible.is_empty() { None } else { Some(0) });
        self.selected = index.map(|i| visible[i].identity.clone());
        self.table.select(index);
    }
    fn disk(&self) -> Option<&DiskView> {
        self.selected
            .as_ref()
            .and_then(|id| self.model.disks.iter().find(|d| &d.identity == id))
    }
    fn history(&mut self, path: &Path) {
        self.samples.clear();
        self.history_error = None;
        if let Some(id) = &self.selected {
            let t = now();
            match history::query(&history::path(path), id, t.saturating_sub(self.range), t) {
                Ok(samples) => self.samples = samples,
                Err(e) => self.history_error = Some(format!("History unavailable: {e:#}")),
            }
        }
    }
    fn reload(&mut self, path: &Path, max_age: u64) {
        match Model::load(path, max_age) {
            Ok(model) => self.model = model,
            Err(e) => {
                self.model.state_stale = true;
                self.model.error = Some(format!("State reload failed: {e:#}"));
            }
        }
        self.reselect();
        self.history(path);
    }
    fn step(&mut self, delta: i32) {
        if self.focus == Focus::Charts {
            return;
        }
        if self.focus != Focus::Disks {
            let scroll = if self.focus == Focus::Details {
                &mut self.detail_scroll
            } else {
                &mut self.event_scroll
            };
            *scroll = (*scroll as i32 + delta).clamp(0, u16::MAX as i32) as u16;
            return;
        }
        let visible = self.model.visible(self.show_absent);
        if !visible.is_empty() {
            let index = (self.table.selected().unwrap_or(0) as i32 + delta)
                .clamp(0, visible.len() as i32 - 1) as usize;
            self.selected = Some(visible[index].identity.clone());
            self.table.select(Some(index));
            self.detail_scroll = 0;
            self.event_scroll = 0;
        }
    }
    fn block(&self, title: &str, focus: Focus) -> Block<'static> {
        Block::default()
            .title(title.to_owned())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if self.focus == focus {
                Color::Cyan
            } else {
                Color::DarkGray
            }))
    }
    fn draw(&mut self, f: &mut Frame, max_age: u64) {
        let areas = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(f.area());
        f.render_widget(
            Paragraph::new(self.model.banner())
                .block(Block::bordered().title("disk-watch | saved state, read-only")),
            areas[0],
        );
        let foot=self.model.error.as_ref().or(self.history_error.as_ref()).cloned().unwrap_or_else(||
            "Up/Down select/scroll | Tab panel | e events | u uncorrelated | a absent | 1 1h  2 24h  3 7d  4 30d | r reload | q quit".into());
        f.render_widget(
            Paragraph::new(clean(&foot)).wrap(Wrap { trim: false }),
            areas[2],
        );
        let narrow = f.area().width < 130;
        let (table_area, detail_area, event_area, temp_area, health_area) = if narrow {
            let split = Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)])
                .split(areas[1]);
            let charts = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(split[1]);
            (split[0], split[1], split[1], charts[0], charts[1])
        } else {
            let panes =
                Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(areas[1]);
            let left = Layout::vertical([Constraint::Percentage(48), Constraint::Percentage(52)])
                .split(panes[0]);
            let right = Layout::vertical([
                Constraint::Percentage(44),
                Constraint::Percentage(28),
                Constraint::Percentage(28),
            ])
            .split(panes[1]);
            (left[0], right[0], left[1], right[1], right[2])
        };
        let rows: Vec<_> = self
            .model
            .visible(self.show_absent)
            .iter()
            .map(|d| {
                let health = d.disk.health();
                Row::new(vec![
                    Cell::from(format!(
                        "{} {}",
                        clean(&d.disk.device.model),
                        clean(&d.disk.device.path)
                    )),
                    Cell::from(if d.disk.present {
                        format!(
                            "{health}{}",
                            if d.stale(now(), max_age) {
                                " STALE"
                            } else {
                                ""
                            }
                        )
                    } else {
                        format!("ABSENT ({health})")
                    })
                    .style(Style::default().fg(color(health))),
                    Cell::from(
                        d.disk
                            .snapshot
                            .as_ref()
                            .and_then(|s| s.temperature)
                            .map(|t| format!("{t}C"))
                            .unwrap_or_else(|| "-".into()),
                    ),
                    Cell::from(d.marker(now())).style(Style::default().fg(if d.historical {
                        Color::Magenta
                    } else {
                        Color::Gray
                    })),
                ])
            })
            .collect();
        let table = Table::new(
            rows,
            [
                Constraint::Min(12),
                Constraint::Length(15),
                Constraint::Length(5),
                Constraint::Length(24),
            ],
        )
        .header(
            Row::new(["DISK / PATH", "STATE", "TEMP", "HISTORY"]).style(Style::default().bold()),
        )
        .block(self.block(
            if self.show_absent {
                "DISKS + ABSENT HISTORY"
            } else {
                "ACTIVE DISKS"
            },
            Focus::Disks,
        ))
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol("> ");
        f.render_stateful_widget(table, table_area, &mut self.table);
        let details = self
            .disk()
            .map(|d| d.details(now(), max_age))
            .unwrap_or_else(|| "No disk selected".into());
        if !narrow || matches!(self.focus, Focus::Disks | Focus::Details) {
            f.render_widget(
                Paragraph::new(details)
                    .wrap(Wrap { trim: false })
                    .scroll((self.detail_scroll, 0))
                    .block(self.block("DETAILS (scroll Up/Down)", Focus::Details)),
                detail_area,
            );
        }
        let event_text = if self.uncorrelated {
            self.model
                .uncorrelated
                .iter()
                .map(|e| {
                    format!(
                        "{} {:?} uncorrelated\n{}",
                        time(e.timestamp),
                        e.severity,
                        clean(&e.message)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        } else {
            self.disk()
                .map(|d| d.event_lines().join("\n\n"))
                .unwrap_or_default()
        };
        if !narrow || self.focus == Focus::Events {
            f.render_widget(
                Paragraph::new(if event_text.is_empty() {
                    "No retained events".into()
                } else {
                    event_text
                })
                .wrap(Wrap { trim: false })
                .scroll((self.event_scroll, 0))
                .block(self.block(
                    if self.uncorrelated {
                        "UNCORRELATED EVENTS (no disk health impact)"
                    } else {
                        "EVENTS (newest first, scroll Up/Down)"
                    },
                    Focus::Events,
                )),
                event_area,
            );
        }
        if !narrow || self.focus == Focus::Charts {
            self.charts(f, temp_area, health_area);
        }
    }
    fn charts(&self, f: &mut Frame, temp_area: Rect, health_area: Rect) {
        let t = now();
        let start = t.saturating_sub(self.range);
        let temp: Vec<_> = self
            .samples
            .iter()
            .filter(|s| s.present)
            .filter_map(|s| s.measured_at.zip(s.temperature))
            .filter(|(at, _)| *at >= start && *at <= t)
            .map(|(at, v)| ((at - start) as f64 / 3600.0, v as f64))
            .collect();
        let bounds = [0.0, self.range as f64 / 3600.0];
        let x_axis = || {
            Axis::default()
                .title("hours from range start")
                .bounds(bounds)
                .labels([format!("-{}h", self.range / 3600), "now".into()])
        };
        if temp.is_empty() {
            f.render_widget(Paragraph::new("No temperature samples in range.\nHistory starts when the updated daemon/check runs.").wrap(Wrap{trim:false}).block(Block::bordered().title("TEMPERATURE")),temp_area);
        } else {
            let min = temp
                .iter()
                .map(|p| p.1)
                .fold(f64::INFINITY, f64::min)
                .floor()
                - 2.0;
            let max = temp
                .iter()
                .map(|p| p.1)
                .fold(f64::NEG_INFINITY, f64::max)
                .ceil()
                + 2.0;
            let set = Dataset::default()
                .name("C")
                .marker(symbols::Marker::Braille)
                .graph_type(GraphType::Scatter)
                .style(Style::default().fg(Color::Cyan))
                .data(&temp);
            f.render_widget(
                Chart::new(vec![set])
                    .block(Block::bordered().title("TEMPERATURE (measured samples)"))
                    .x_axis(x_axis())
                    .y_axis(
                        Axis::default()
                            .bounds([min, max])
                            .labels([format!("{min:.0}C"), format!("{max:.0}C")]),
                    ),
                temp_area,
            );
        }
        let mut health = vec![];
        let mut previous = None;
        for s in &self.samples {
            let y = if !s.present {
                0.0
            } else {
                match s.health.as_str() {
                    "OK" => 1.0,
                    "Warning" => 2.0,
                    "Critical" => 3.0,
                    _ => 0.0,
                }
            };
            let x = s.timestamp.saturating_sub(start) as f64 / 3600.0;
            if let Some(old) = previous {
                health.push((x, old));
            }
            health.push((x, y));
            previous = Some(y);
        }
        // Do not extend an old observation to now: an outage is not a clean interval.
        let set = Dataset::default()
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Yellow))
            .data(&health);
        if health.is_empty() {
            f.render_widget(Paragraph::new("No recorded health samples in range.\nRetained problems are still available in EVENTS.").wrap(Wrap{trim:false}).block(Block::bordered().title("HEALTH TIMELINE")),health_area);
        } else {
            f.render_widget(
                Chart::new(vec![set])
                    .block(Block::bordered().title("HEALTH TIMELINE (saved observations)"))
                    .x_axis(x_axis())
                    .y_axis(
                        Axis::default()
                            .bounds([0.0, 3.0])
                            .labels(["U/ABS", "OK", "WARN", "CRIT"]),
                    ),
                health_area,
            );
        }
    }
}

struct Screen;
impl Drop for Screen {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
    }
}
pub async fn run(path: &Path, interval: u64) -> Result<()> {
    ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "tui requires an interactive terminal"
    );
    let max_age = interval.saturating_mul(2).saturating_add(120);
    let mut app = App::new(Model::load(path, max_age)?);
    app.history(path);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    enable_raw_mode()?;
    let _screen = Screen;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let mut refresh = tokio::time::interval(Duration::from_secs(2));
    loop {
        terminal.draw(|f| app.draw(f, max_age))?;
        tokio::select! {
            _=tokio::signal::ctrl_c()=>break,
            _=term.recv()=>break,
            _=refresh.tick()=>app.reload(path,max_age),
            _=tokio::time::sleep(Duration::from_millis(100))=>{},
        }
        while event::poll(Duration::ZERO)? {
            match event::read()? {
                Input::Key(key) if key.kind != KeyEventKind::Release => {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            return Ok(());
                        }
                        KeyCode::Up => app.step(-1),
                        KeyCode::Down => app.step(1),
                        KeyCode::PageUp => app.step(-10),
                        KeyCode::PageDown => app.step(10),
                        KeyCode::Tab => {
                            app.focus = match app.focus {
                                Focus::Disks => Focus::Details,
                                Focus::Details => Focus::Events,
                                Focus::Events => Focus::Charts,
                                Focus::Charts => Focus::Disks,
                            }
                        }
                        KeyCode::Char('e') => app.focus = Focus::Events,
                        KeyCode::Char('u') => {
                            app.uncorrelated = !app.uncorrelated;
                            app.focus = Focus::Events;
                            app.event_scroll = 0;
                        }
                        KeyCode::Char('a') => {
                            app.show_absent = !app.show_absent;
                            app.reselect();
                        }
                        KeyCode::Char('1') => app.range = 3600,
                        KeyCode::Char('2') => app.range = RECENT,
                        KeyCode::Char('3') => app.range = 7 * RECENT,
                        KeyCode::Char('4') => app.range = 30 * RECENT,
                        KeyCode::Char('r') => app.reload(path, max_age),
                        _ => {}
                    }
                    app.history(path);
                }
                Input::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        devices::{Device, Kind},
        smart::Snapshot,
        state::CheckStatus,
    };
    fn disk(serial: &str) -> DiskState {
        DiskState {
            snapshot: Some(Snapshot {
                passed: Some(true),
                temperature: Some(32),
                ..Snapshot::default()
            }),
            check_status: CheckStatus::Checked,
            checked_at: Some(100),
            ..DiskState::new(Device {
                model: "Test disk".into(),
                serial: serial.into(),
                wwn: String::new(),
                path: "/dev/sdb".into(),
                kind: Kind::Hdd,
                aliases: vec![],
                diskseq: None,
                discovered_at: 0,
                wd_usb: false,
            })
        }
    }
    fn problem(d: &mut DiskState) -> Event {
        let mut at_event = d.device.clone();
        at_event.path = "/dev/sdd".into();
        let event = Event {
            timestamp: 90,
            severity: Severity::Critical,
            disk: Some(at_event),
            category: "io_error".into(),
            message: "I/O error, dev sdd".into(),
        };
        d.kernel_severity = Some(Severity::Critical);
        d.kernel_current_severity = Some(Severity::Critical);
        d.kernel_last_seen = Some(90);
        d.kernel_last_message = Some(event.message.clone());
        d.kernel_last_critical = Some(event.clone());
        event
    }
    fn saved(d: DiskState, events: Vec<Event>) -> State {
        State {
            disks: std::collections::BTreeMap::from([(d.device.key(), d)]),
            recent_alerts: events,
            ..State::default()
        }
    }
    fn screen(app: &mut App, width: u16, height: u16) -> String {
        let mut term = Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        term.draw(|f| app.draw(f, 3600)).unwrap();
        term.backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>()
    }
    #[test]
    fn recovery_keeps_marker_events_and_distinct_current_health() {
        let mut d = disk("A");
        let event = problem(&mut d);
        let before = saved(d.clone(), vec![event.clone()]);
        let model = Model::from_state(&before, 100, 100, 60);
        assert_eq!(model.disks[0].disk.health(), "Critical");
        assert!(model.banner().contains("CURRENT PROBLEMS: 1"));
        for n in 1..=3 {
            d.recover_kernel();
            assert_eq!(d.kernel_recovery_successes, n);
        }
        assert_eq!(d.health(), "OK");
        let model = Model::from_state(&saved(d, vec![event]), 100, 100, 60);
        let view = &model.disks[0];
        assert!(view.marker(100).contains("HIST! RECENT C:1"));
        assert_eq!(view.events.len(), 1); // retained critical is deduplicated
        assert!(view.details(100, 60).contains("Current health: OK"));
        assert!(view.details(100, 60).contains("Historical problems: YES"));
        assert!(view.details(100, 60).contains("Recovery checks: 3 / 3"));
        assert!(model.banner().contains("CURRENT: ALL OK"));
        assert!(model.banner().contains("HISTORY: 1 ACTIVE"));
    }
    #[test]
    fn recovered_critical_is_above_clean_ok_and_event_paths_stay_distinct() {
        let mut d = disk("A");
        let event = problem(&mut d);
        d.kernel_recovery_successes = 3;
        let mut state = saved(d, vec![event]);
        let mut clean_disk = disk("B");
        clean_disk.device.model = "AAA clean".into();
        state.disks.insert(clean_disk.device.key(), clean_disk);
        let model = Model::from_state(&state, 100, 100, 60);
        assert_eq!(model.disks[0].disk.device.serial, "A");
        assert_eq!(model.disks[1].marker(100), "-");
        let lines = model.disks[0].event_lines().join("\n");
        assert!(lines.contains("current=/dev/sdb at_event=/dev/sdd"));
        assert!(lines.contains("I/O error, dev sdd"));
    }
    #[test]
    fn absent_does_not_affect_current_counts_or_default_list() {
        let mut d = disk("A");
        let event = problem(&mut d);
        d.present = false;
        let mut state = saved(d, vec![event]);
        let ok = disk("B");
        state.disks.insert(ok.device.key(), ok);
        let model = Model::from_state(&state, 100, 100, 60);
        assert_eq!(model.visible(false).len(), 1);
        assert_eq!(model.visible(true).len(), 2);
        assert!(model.banner().contains("DISKS: 1 OK:1 W:0 C:0 U:0"));
        assert!(model.banner().contains("ABSENT: 1"));
        let absent = model.disks.iter().find(|d| !d.disk.present).unwrap();
        assert!(
            absent
                .details(100, 60)
                .contains("Last known health: Critical")
        );
    }
    #[test]
    fn stale_state_and_reload_failure_are_visible() {
        let state = saved(disk("A"), vec![]);
        let model = Model::from_state(&state, 1000, 100, 60);
        assert!(model.banner().contains("STALE / SAVED DATA"));
        let mut app = App::new(model);
        app.reload(Path::new("/no/such/disk-watch/state.json"), 60);
        assert_eq!(app.model.disks.len(), 1);
        assert!(app.model.error.is_some());
        assert!(screen(&mut app, 160, 40).contains("STALE"));
    }
    #[test]
    fn missing_smart_and_tiny_terminal_render_without_panic() {
        let mut d = disk("A");
        d.snapshot = None;
        d.checked_at = None;
        d.check_status = CheckStatus::Never;
        let mut app = App::new(Model::from_state(&saved(d, vec![]), 100, 100, 60));
        assert!(app.disk().unwrap().details(100, 60).contains("unavailable"));
        for (w, h) in [(1, 1), (25, 8), (80, 24), (180, 50)] {
            let _ = screen(&mut app, w, h);
        }
    }
    #[test]
    fn uncorrelated_and_foreign_identity_events_never_attach_by_path() {
        let d = disk("A");
        let mut other = disk("B");
        let mut foreign = problem(&mut other);
        foreign.disk.as_mut().unwrap().path = "/dev/sdb".into();
        let mut unc = foreign.clone();
        unc.disk = None;
        let model = Model::from_state(&saved(d, vec![foreign, unc]), 100, 100, 60);
        assert!(!model.disks[0].historical);
        assert!(model.disks[0].events.is_empty());
        assert_eq!(model.uncorrelated.len(), 1);
    }
    #[test]
    fn retained_kernel_critical_survives_event_ring_rotation() {
        let mut d = disk("A");
        problem(&mut d);
        d.kernel_recovery_successes = 3;
        let model = Model::from_state(&saved(d, vec![]), 100, 100, 60);
        assert!(model.disks[0].historical);
        assert_eq!(model.disks[0].events.len(), 1);
    }
    #[test]
    fn old_history_is_distinguished_from_recent_history() {
        let mut d = disk("A");
        let event = problem(&mut d);
        d.kernel_recovery_successes = 3;
        let model = Model::from_state(&saved(d, vec![event]), RECENT + 200, RECENT + 200, 60);
        assert!(model.disks[0].marker(RECENT + 200).contains("OLD"));
        assert!(!model.disks[0].recent_critical);
    }
    #[test]
    fn refresh_keeps_selection_by_identity_after_sort_order_changes() {
        let d = disk("A");
        let b = disk("B");
        let mut state = saved(d, vec![]);
        state.disks.insert(b.device.key(), b);
        let mut app = App::new(Model::from_state(&state, 100, 100, 60));
        app.step(1);
        let selected = app.selected.clone();
        let first = state
            .disks
            .values_mut()
            .find(|d| d.device.serial == "A")
            .unwrap();
        problem(first);
        app.model = Model::from_state(&state, 100, 100, 60);
        app.reselect();
        assert_eq!(app.selected, selected);
    }
    #[test]
    fn tui_reload_render_and_navigation_are_read_only() {
        let dir =
            std::env::temp_dir().join(format!("disk-watch-tui-readonly-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut d = disk("A");
        let event = problem(&mut d);
        d.kernel_recovery_successes = 3;
        let state = saved(d, vec![event]);
        state.save(&path).unwrap();
        let db = history::path(&path);
        history::record(&db, &state, 100).unwrap();
        let before = std::fs::read(&path).unwrap();
        let db_before = std::fs::read(&db).unwrap();
        let mut app = App::new(Model::load(&path, 3600).unwrap());
        app.reload(&path, 3600);
        app.show_absent = true;
        app.reselect();
        app.range = 7 * RECENT;
        app.history(&path);
        let text = screen(&mut app, 80, 24);
        assert!(text.contains("HIST!"));
        app.focus = Focus::Events;
        let text = screen(&mut app, 80, 24);
        assert!(text.contains("I/O error"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(std::fs::read(&db).unwrap(), db_before);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn terminal_control_characters_are_escaped() {
        assert_eq!(clean("disk\x1b[2J\n"), "disk\\u{1b}[2J\\n");
    }
}
