// sentinel-ui — rendering.
//
// Four regions: a header with the live clock, then the three panels from the
// spec — agents, signals, audit — and a footer of key hints. The audit panel
// is display-only; nothing here ever mutates the trail.

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, Clear, Paragraph, Row, Table},
    Frame,
};

use crate::app::{hms, now_clock, short_hash, title_case, App, Mode};

pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    let chunks = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(6),    // agents
        Constraint::Length(9), // signals
        Constraint::Length(8), // audit
        Constraint::Length(1), // footer
    ])
    .split(area);

    render_header(f, chunks[0]);
    render_agents(f, chunks[1], app);
    render_signals(f, chunks[2], app);
    render_audit(f, chunks[3], app);
    render_footer(f, chunks[4], app);

    if let Mode::Override { agent_id, input } = &app.mode {
        render_override(f, area, app, agent_id, input);
    }
}

fn render_header(f: &mut Frame, area: Rect) {
    let cols = Layout::horizontal([Constraint::Min(10), Constraint::Length(21)]).split(area);
    let title = Paragraph::new(Span::styled(
        " SENTINEL — Agentic Process Oversight",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    let clock = Paragraph::new(format!("{} ", now_clock())).alignment(Alignment::Right);
    f.render_widget(title, cols[0]);
    f.render_widget(clock, cols[1]);
}

fn render_agents(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" AGENTS ");
    if app.order.is_empty() {
        let msg = if app.connected {
            "No agents registered. Waiting for connections…"
        } else {
            "Not connected to sentinel-core."
        };
        f.render_widget(Paragraph::new(msg).block(block), area);
        return;
    }

    let header = Row::new(["Agent", "Tier", "Score", "State", "Last Heartbeat"])
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .order
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let a = &app.agents[id];
            let (label, color) = state_style(&a.state);
            let cells = vec![
                Cell::from(id.clone()),
                Cell::from(title_case(&a.tier)),
                Cell::from(format!("{:.2}", a.score)),
                Cell::from(Span::styled(label, Style::default().fg(color))),
                Cell::from(format!("{}s ago", a.heartbeat_age_secs)),
            ];
            let row = Row::new(cells);
            if i == app.selected {
                row.style(Style::default().add_modifier(Modifier::REVERSED))
            } else {
                row
            }
        })
        .collect();

    let widths = [
        Constraint::Percentage(34),
        Constraint::Length(14),
        Constraint::Length(8),
        Constraint::Length(14),
        Constraint::Min(12),
    ];
    f.render_widget(Table::new(rows, widths).header(header).block(block), area);
}

fn render_signals(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" SIGNALS (last 10) ");
    let lines: Vec<Line> = app
        .signals
        .iter()
        .take(10)
        .map(|s| {
            let (_, color) = action_style(&s.action);
            Line::from(vec![
                Span::styled(format!("[{}] ", hms(&s.timestamp)), Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{:<18}", truncate(&s.agent_id, 18))),
                Span::raw(format!("{:<16}", truncate(&s.signal, 16))),
                Span::raw(format!("{:>5.2}  ", s.score)),
                Span::styled(action_label(&s.action), Style::default().fg(color)),
            ])
        })
        .collect();

    let body = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "No degradation signals.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
    };
    f.render_widget(Paragraph::new(body).block(block), area);
}

fn render_audit(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::bordered().title(" AUDIT (append-only) ");
    let lines: Vec<Line> = app
        .audit
        .iter()
        .take(6)
        .map(|e| {
            Line::from(vec![
                Span::styled(format!("[{}] ", hms(&e.timestamp)), Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{:<18}", truncate(&e.target, 18))),
                Span::styled(
                    format!("{:<18}", e.action.to_uppercase()),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("hash: {}", short_hash(&e.hash)),
                    Style::default().fg(Color::Blue),
                ),
            ])
        })
        .collect();

    let body = if lines.is_empty() {
        vec![Line::from(Span::styled(
            "No audited actions yet.",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        lines
    };
    f.render_widget(Paragraph::new(body).block(block), area);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let (conn_label, conn_color) = if app.connected {
        ("● live", Color::Green)
    } else {
        ("● offline", Color::Red)
    };
    let line = Line::from(vec![
        Span::raw(" [Q] Quit  [O] Override  [R] Refresh  [↑↓] Select agent    "),
        Span::styled(conn_label, Style::default().fg(conn_color)),
        Span::styled(
            format!("  │  {}", app.status_line),
            Style::default().fg(Color::Gray),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn render_override(f: &mut Frame, area: Rect, app: &App, agent_id: &str, input: &str) {
    let popup = centered(64, 10, area);
    f.render_widget(Clear, popup);

    let block = Block::bordered()
        .title(" Operator Override ")
        .border_style(Style::default().fg(Color::Yellow));
    let body = vec![
        Line::from(vec![
            Span::styled("Agent:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(agent_id.to_string(), Style::default().add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Operator: ", Style::default().fg(Color::DarkGray)),
            Span::raw(app.operator.clone()),
        ]),
        Line::from(vec![
            Span::styled("Reason:   ", Style::default().fg(Color::DarkGray)),
            Span::raw(input.to_string()),
            Span::styled("▏", Style::default().fg(Color::Yellow)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "This override is sent to sentinel-core, where it is logged and",
            Style::default().fg(Color::Gray),
        )),
        Line::from(Span::styled(
            "SHA256-hashed onto the audit trail before it is applied.",
            Style::default().fg(Color::Gray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  [Enter] confirm      [Esc] cancel",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];
    f.render_widget(Paragraph::new(body).block(block), popup);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn state_style(state: &str) -> (&'static str, Color) {
    match state {
        "clean" => ("✓ Clean", Color::Green),
        "watch" => ("⚠ Watch", Color::Yellow),
        "degraded" => ("✗ Degraded", Color::Red),
        _ => ("? Unknown", Color::Gray),
    }
}

fn action_style(action: &str) -> (&'static str, Color) {
    match action {
        "no_action" => ("no action", Color::DarkGray),
        "soft_pause" => ("soft", Color::Yellow),
        "write_suspended" => ("medium", Color::Rgb(255, 165, 0)),
        "terminated" => ("hard", Color::Red),
        _ => ("unknown", Color::Gray),
    }
}

fn action_label(action: &str) -> String {
    match action {
        "no_action" => "no action".to_string(),
        "soft_pause" => "soft — paused".to_string(),
        "write_suspended" => "medium — write suspended".to_string(),
        "terminated" => "hard — terminated".to_string(),
        other => other.to_string(),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}
