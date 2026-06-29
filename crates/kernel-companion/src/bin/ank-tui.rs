//!
//! โมดูลนี้รวบรวมฟังก์ชันการทำงานที่จำเป็นทั้งหมด
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use intent_bus::{Intent, IntentPriority, IntentType};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
};
use serde_json::Value;
use std::io::stdout;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const SOCKET_PATH: &str = "/tmp/ank-companion.sock";

struct DashboardData {
    status: String,
    running_agents: u64,
    quarantined_pids: Vec<u64>,
    blocked_syscalls: Vec<String>,
    hardware: Vec<HardwareDevice>,
}

#[derive(Default)]
struct HardwareDevice {
    target: String,
    latency_ms: f64,
    power_watts: f64,
    cost_units: f64,
}

impl DashboardData {
    fn from_json(v: &Value) -> Self {
        let hardware = v["hardware_targets"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|hw| HardwareDevice {
                        target: hw["target"].as_str().unwrap_or("?").to_string(),
                        latency_ms: hw["latency_ms"].as_f64().unwrap_or(0.0),
                        power_watts: hw["power_watts"].as_f64().unwrap_or(0.0),
                        cost_units: hw["cost_units"].as_f64().unwrap_or(0.0),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            status: v["status"].as_str().unwrap_or("unknown").to_string(),
            running_agents: v["running_agents"].as_u64().unwrap_or(0),
            quarantined_pids: v["quarantined_pids"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_u64()).collect())
                .unwrap_or_default(),
            blocked_syscalls: v["blocked_syscalls"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            hardware,
        }
    }
}

async fn fetch_status() -> Result<DashboardData, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;

    let intent = Intent::new(
        "tui-status",
        IntentType::Command,
        "status",
        IntentPriority::High,
        "ank-tui",
    );

    let json_str = serde_json::to_string(&intent).map_err(|e| e.to_string())?;
    stream
        .write_all(json_str.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;

    let (reader, _) = stream.split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader
        .read_line(&mut line)
        .await
        .map_err(|e| e.to_string())?;

    let v: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    Ok(DashboardData::from_json(&v))
}

fn ui(frame: &mut Frame, data: &DashboardData) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // ── Header ──
    let header = Paragraph::new(Line::from(Span::styled(
        " AI-Native Kernel Dashboard ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    )
    .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(header, chunks[0]);

    let main = chunks[1];
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main);

    // ── Left column ──
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(0),
        ])
        .split(cols[0]);

    // Status block
    let status_color = if data.status == "online" {
        Color::Green
    } else {
        Color::Red
    };
    let status_text = Text::from(Line::from(vec![
        Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(&data.status, Style::default().fg(status_color)),
    ]));
    let status_block =
        Paragraph::new(status_text).block(Block::default().title("System").borders(Borders::ALL));
    frame.render_widget(status_block, left_chunks[0]);

    // Agent gauge
    let agent_pct = (data.running_agents as f64 / 100.0).min(1.0);
    let gauge = Gauge::default()
        .block(Block::default().title("Agents").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
        .label(format!("{} running", data.running_agents))
        .ratio(agent_pct);
    frame.render_widget(gauge, left_chunks[1]);

    // Quarantine list
    let quarantine_items: Vec<ListItem> = if data.quarantined_pids.is_empty() {
        vec![ListItem::new("  (none)")]
    } else {
        data.quarantined_pids
            .iter()
            .map(|pid| {
                ListItem::new(format!("  PID {}", pid)).style(Style::default().fg(Color::Red))
            })
            .collect()
    };
    let quarantine_list = List::new(quarantine_items)
        .block(Block::default().title("Quarantined").borders(Borders::ALL));
    frame.render_widget(quarantine_list, left_chunks[2]);

    // ── Right column ──
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(cols[1]);

    // Blocked syscalls
    let blocked_items: Vec<ListItem> = if data.blocked_syscalls.is_empty() {
        vec![ListItem::new("  (none)")]
    } else {
        data.blocked_syscalls
            .iter()
            .map(|s| ListItem::new(format!("  {}", s)).style(Style::default().fg(Color::Yellow)))
            .collect()
    };
    let blocked_list = List::new(blocked_items).block(
        Block::default()
            .title("Blocked Syscalls")
            .borders(Borders::ALL),
    );
    frame.render_widget(blocked_list, right_chunks[0]);

    // Hardware devices
    let hw_lines: Vec<ListItem> = if data.hardware.is_empty() {
        vec![ListItem::new("  (no devices)")]
    } else {
        data.hardware
            .iter()
            .map(|hw| {
                ListItem::new(format!(
                    "  {:<6}  Lat {:>5.1}ms  Pwr {:>5.1}W  Cost {:>5.1}",
                    hw.target, hw.latency_ms, hw.power_watts, hw.cost_units
                ))
            })
            .collect()
    };
    let hw_list = List::new(hw_lines).block(
        Block::default()
            .title("Hardware Devices")
            .borders(Borders::ALL),
    );
    frame.render_widget(hw_list, right_chunks[1]);

    // Footer hint
    let footer = Paragraph::new(Line::from(Span::styled(
        " [q] quit  |  auto-refresh every 2s ",
        Style::default().fg(Color::DarkGray),
    )))
    .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(footer, right_chunks[2]);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let mut terminal = Terminal::new(ratatui::backend::CrosstermBackend::new(stdout))?;
    let tick_rate = Duration::from_secs(2);

    let mut data = DashboardData {
        status: "connecting...".to_string(),
        running_agents: 0,
        quarantined_pids: vec![],
        blocked_syscalls: vec![],
        hardware: vec![],
    };

    // Draw initial frame immediately so user sees "connecting..." right away
    terminal.draw(|f| ui(f, &data))?;

    loop {
        // Fetch latest status
        match fetch_status().await {
            Ok(d) => data = d,
            Err(e) => {
                data.status = format!("error: {}", e);
            }
        }

        terminal.draw(|f| ui(f, &data))?;

        // Wait for keypress or timeout
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    println!("ANK TUI closed.");
    Ok(())
}
