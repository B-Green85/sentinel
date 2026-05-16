// sentinel-ui — WebSocket client task.
//
// Connects to sentinel-core over the same ws:// interface any external client
// uses — no privileged channel. Inbound messages are parsed and forwarded to
// the dashboard; outbound client messages (refresh, operator override) are
// relayed to the socket. Reconnects automatically if the daemon restarts.

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::{sleep, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::app::{AppEvent, ServerMsg};

/// Run the WebSocket client until the dashboard exits.
pub async fn run(
    url: String,
    to_app: UnboundedSender<AppEvent>,
    mut from_app: UnboundedReceiver<String>,
) {
    loop {
        match connect_async(&url).await {
            Ok((ws, _resp)) => {
                if to_app.send(AppEvent::Connected).is_err() {
                    return;
                }
                let (mut write, mut read) = ws.split();

                // Request an initial snapshot so panels populate immediately.
                if write
                    .send(Message::Text(r#"{"type":"status"}"#.to_string()))
                    .await
                    .is_err()
                {
                    let _ = to_app.send(AppEvent::Disconnected);
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }

                loop {
                    tokio::select! {
                        inbound = read.next() => match inbound {
                            Some(Ok(Message::Text(text))) => {
                                if let Ok(msg) = serde_json::from_str::<ServerMsg>(&text) {
                                    if to_app.send(AppEvent::Server(msg)).is_err() {
                                        return;
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Ok(_)) => {}
                            Some(Err(_)) => break,
                        },
                        outbound = from_app.recv() => match outbound {
                            Some(text) => {
                                if write.send(Message::Text(text)).await.is_err() {
                                    break;
                                }
                            }
                            None => return, // dashboard has exited
                        },
                    }
                }
                let _ = to_app.send(AppEvent::Disconnected);
            }
            Err(_) => {
                if to_app.send(AppEvent::Disconnected).is_err() {
                    return;
                }
            }
        }
        // Backoff before retrying — the daemon may be restarting.
        sleep(Duration::from_secs(2)).await;
    }
}
