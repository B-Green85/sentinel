// sentinel-ui — real-time terminal dashboard for Sentinel agent oversight.
//
// Usage:
//   sentinel-ui [--host 127.0.0.1] [--port 7777]
//
// Connects to sentinel-core over the WebSocket interface — the same ws://
// endpoint any external client uses. Three panels: agents, signals, audit.
// The dashboard is read-only; the single operator action is the [O] override,
// which sentinel-core hashes and audits before it takes effect.

mod app;
mod net;
mod ui;

use std::io;

use crossterm::{
    event::{Event, EventStream},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

use app::{App, AppEvent};

fn parse_arg(args: &[String], flag: &str, default: &str) -> String {
    for i in 0..args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                return val.clone();
            }
        }
    }
    default.to_string()
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let host = parse_arg(&args, "--host", "127.0.0.1");
    let port = parse_arg(&args, "--port", "7777");
    let url = format!("ws://{host}:{port}");
    let operator = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "operator".to_string());

    // WebSocket client runs as a background task.
    let (tx_evt, mut rx_evt) = mpsc::unbounded_channel::<AppEvent>();
    let (tx_out, rx_out) = mpsc::unbounded_channel::<String>();
    tokio::spawn(net::run(url, tx_evt, rx_out));

    // Terminal setup.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = App::new(operator);
    let result = run_loop(&mut terminal, &mut app, &mut rx_evt, &tx_out).await;

    // Terminal teardown — always restored, even on error.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx_evt: &mut mpsc::UnboundedReceiver<AppEvent>,
    tx_out: &mpsc::UnboundedSender<String>,
) -> io::Result<()> {
    let mut input = EventStream::new();
    // Redraw at least twice a second so the clock and heartbeat ages stay live.
    let mut tick = interval(Duration::from_millis(500));

    loop {
        terminal.draw(|f| ui::render(f, app))?;
        if app.should_quit {
            return Ok(());
        }

        tokio::select! {
            _ = tick.tick() => {}
            event = rx_evt.recv() => {
                match event {
                    Some(e) => app.apply(e),
                    None => return Ok(()), // WebSocket task ended
                }
            }
            key = input.next() => {
                if let Some(Ok(Event::Key(key))) = key {
                    app.handle_key(key, tx_out);
                }
            }
        }
    }
}
