use anyhow::Result;
use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use dmr_config::import_hblink_cfg;
use dmr_protocol_hbp::{HbpMaster, MasterEvent};
use serde::Serialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, time::interval};
use tracing::{debug, info, warn};

#[derive(Clone)]
struct AppState {
    version: &'static str,
    systems: usize,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    imported_systems: usize,
}

async fn health(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(Health {
        status: "ok",
        version: s.version,
        imported_systems: s.systems,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("dmr_master=info".parse()?),
        )
        .init();

    let cfg =
        std::env::var("DMR_HBLINK_CONFIG").unwrap_or_else(|_| "fixtures/hblink.cfg".into());
    let imported = import_hblink_cfg(PathBuf::from(cfg))?;
    info!(
        systems = imported.systems.len(),
        "legacy HBlink configuration imported"
    );

    let session_timeout_secs = std::env::var("DMR_HBP_SESSION_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);

    for s in imported.systems.iter().filter(|s| {
        s.enabled
            && matches!(
                s.mode.to_ascii_uppercase().as_str(),
                "MASTER" | "SERVER"
            )
    }) {
        if let (Some(ip), Some(port)) = (s.bind_ip.clone(), s.port) {
            let name = s.name.clone();
            let passphrase = s.passphrase.clone().unwrap_or_default();
            let max_repeaters = s.max_repeaters.unwrap_or(1) as usize;
            let timeout = Duration::from_secs(session_timeout_secs);

            tokio::spawn(async move {
                if let Err(e) = run_hbp_listener(
                    name,
                    format!("{ip}:{port}"),
                    passphrase,
                    max_repeaters,
                    timeout,
                )
                .await
                {
                    warn!(error = %e, "HBP listener stopped");
                }
            });
        }
    }

    let state = Arc::new(AppState {
        version: env!("CARGO_PKG_VERSION"),
        systems: imported.systems.len(),
    });

    let app = Router::new()
        .route("/api/public/health", get(health))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    info!(%addr, "HTTP status API listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn run_hbp_listener(
    name: String,
    addr: String,
    passphrase: String,
    max_repeaters: usize,
    session_timeout: Duration,
) -> Result<()> {
    let socket = UdpSocket::bind(&addr).await?;
    let mut master = HbpMaster::new(passphrase.into_bytes(), max_repeaters, session_timeout);
    let mut cleanup = interval(Duration::from_secs(5));
    let mut buf = [0u8; 2048];

    info!(
        system = %name,
        %addr,
        max_repeaters,
        session_timeout_secs = session_timeout.as_secs(),
        "HBP master listening"
    );

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, peer) = recv?;
                match master.handle_datagram(peer, &buf[..n], std::time::Instant::now()) {
                    Ok(events) => process_master_events(&socket, &name, events).await?,
                    Err(e) => warn!(system = %name, %peer, error = %e, bytes = n, "invalid HBP packet"),
                }
            }
            _ = cleanup.tick() => {
                let events = master.expire_sessions(std::time::Instant::now());
                process_master_events(&socket, &name, events).await?;
            }
        }
    }
}

async fn process_master_events(
    socket: &UdpSocket,
    system: &str,
    events: Vec<MasterEvent>,
) -> Result<()> {
    for event in events {
        match event {
            MasterEvent::Send {
                destination,
                payload,
            } => {
                socket.send_to(&payload, destination).await?;
                debug!(system, %destination, bytes = payload.len(), "HBP response sent");
            }
            MasterEvent::Authenticated {
                repeater_id,
                remote,
            } => {
                info!(system, repeater_id, %remote, "HBP repeater authenticated");
            }
            MasterEvent::Connected {
                repeater_id,
                remote,
            } => {
                info!(system, repeater_id, %remote, "HBP repeater connected");
            }
            MasterEvent::Frame {
                repeater_id,
                remote,
                packet,
            } => {
                let frame = packet.to_frame();
                debug!(
                    system,
                    repeater_id,
                    %remote,
                    source = frame.source.0,
                    destination = frame.destination,
                    stream_id = frame.stream_id.0,
                    "authenticated DMR frame received"
                );
                // Routing integration is the next milestone. Only authenticated frames reach here.
            }
            MasterEvent::Disconnected {
                repeater_id,
                remote,
            } => {
                info!(system, repeater_id, %remote, "HBP repeater disconnected");
            }
            MasterEvent::Rejected {
                repeater_id,
                remote,
                reason,
            } => {
                warn!(system, repeater_id, %remote, reason, "HBP packet rejected");
            }
        }
    }

    Ok(())
}
