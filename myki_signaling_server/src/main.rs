use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};

type Peers = Arc<Mutex<HashMap<String, PeerState>>>;

struct PeerState {
    sender: tokio::sync::mpsc::UnboundedSender<Message>,
    name: String,
}

#[derive(Serialize)]
struct PeerList {
    #[serde(rename = "type")]
    msg_type: String,
    peers: Vec<PeerInfo>,
}

#[derive(Serialize)]
struct PeerInfo {
    id: String,
    name: String,
    last_seen: u64,
    is_online: bool,
}

#[derive(Deserialize)]
struct IncomingMsg {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    device_name: String,
    #[serde(default)]
    target_id: String,
    #[serde(default)]
    sender_id: String,
    #[serde(default)]
    sender_name: String,
    #[serde(default)]
    sdp: String,
    #[serde(default)]
    candidate: serde_json::Value,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    session_key: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    data: serde_json::Value,
}

async fn register_peer(peers: &Peers, id: &str, name: &str, sender: tokio::sync::mpsc::UnboundedSender<Message>) {
    let mut map = peers.lock().await;
    map.insert(id.to_string(), PeerState { sender, name: name.to_string() });
    broadcast_peer_list(&peers, &map).await;
}

async fn unregister_peer(peers: &Peers, id: &str) {
    let mut map = peers.lock().await;
    map.remove(id);
    broadcast_peer_list(&peers, &map).await;
}

async fn broadcast_peer_list(_peers: &Peers, map: &HashMap<String, PeerState>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let list: Vec<PeerInfo> = map.iter().map(|(id, state)| PeerInfo {
        id: id.clone(),
        name: state.name.clone(),
        last_seen: now,
        is_online: true,
    }).collect();
    let msg = serde_json::to_string(&PeerList { msg_type: "peer_list".into(), peers: list }).unwrap();
    for (_, state) in map {
        let _ = state.sender.send(Message::Text(msg.clone().into()));
    }
}

async fn relay(peers: &Peers, target_id: &str, msg: &str) {
    let map = peers.lock().await;
    if let Some(state) = map.get(target_id) {
        let _ = state.sender.send(Message::Text(msg.to_string().into()));
    }
}

async fn handle_connection(stream: TcpStream, peers: Peers) {
    let ws = match accept_async(stream).await {
        Ok(w) => w,
        Err(_) => return,
    };
    let (mut write, mut read) = ws.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let mut device_id = String::new();

    // Forward outgoing messages from channel to websocket
    let write_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Process incoming messages
    while let Some(Ok(msg)) = read.next().await {
        let txt = match msg.to_text() {
            Ok(t) => t.to_string(),
            Err(_) => continue,
        };
        let incoming: IncomingMsg = match serde_json::from_str(&txt) {
            Ok(m) => m,
            Err(_) => continue,
        };

        match incoming.msg_type.as_str() {
            "register" => {
                device_id = incoming.device_id.clone();
                register_peer(&peers, &device_id, &incoming.device_name, tx.clone()).await;
            }
            "discover" => {
                let map = peers.lock().await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let list: Vec<PeerInfo> = map.iter()
                    .filter(|(id, _)| *id != &incoming.device_id)
                    .map(|(id, state)| PeerInfo {
                        id: id.clone(), name: state.name.clone(),
                        last_seen: now, is_online: true,
                    }).collect();
                let response = serde_json::to_string(&PeerList {
                    msg_type: "peer_list".into(), peers: list,
                }).unwrap();
                let _ = tx.send(Message::Text(response.into()));
            }
            "offer" | "answer" | "candidate" | "pairing_request" | "pairing_response" => {
                relay(&peers, &incoming.target_id, &txt).await;
            }
            _ => {}
        }
    }

    // Cleanup on disconnect
    if !device_id.is_empty() {
        unregister_peer(&peers, &device_id).await;
    }
    write_task.abort();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:9737".to_string());
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    let peers: Peers = Arc::new(Mutex::new(HashMap::new()));

    tracing::info!("Myki Signaling Server listening on {}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        tracing::debug!("New connection from {}", addr);
        tokio::spawn(handle_connection(stream, peers.clone()));
    }
}
