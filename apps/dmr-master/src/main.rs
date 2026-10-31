use anyhow::{anyhow, Context, Result};
use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use dmr_config::{import_hblink_cfg, import_network_json, LegacySystem};
use dmr_core::{CallType, TalkgroupId};
use dmr_protocol_hbp::{DmrdPacket, HbpMaster, MasterEvent, SessionState};
use dmr_protocol_openbridge::OpenBridgeCodec;
use dmr_router::RouteTable;
use serde::Serialize;
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::mpsc,
    time::interval,
};
use tracing::{debug, info, warn};

#[derive(Clone)]
struct AppState {
    version: &'static str,
    systems: usize,
    routes: usize,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    imported_systems: usize,
    compiled_routes: usize,
}

#[derive(Debug, Clone)]
struct IngressFrame {
    endpoint: String,
    packet: DmrdPacket,
}

async fn health(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(Health {
        status: "ok",
        version: s.version,
        imported_systems: s.systems,
        compiled_routes: s.routes,
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

    let cfg = std::env::var("DMR_HBLINK_CONFIG").unwrap_or_else(|_| "fixtures/hblink.cfg".into());
    let imported = import_hblink_cfg(PathBuf::from(cfg))?;
    info!(
        systems = imported.systems.len(),
        server_id = ?imported.server_id,
        "legacy HBlink configuration imported"
    );

    let bridges = match std::env::var("DMR_IMPORTED_NETWORK") {
        Ok(path) => import_network_json(PathBuf::from(path))?,
        Err(_) => {
            warn!(
                "DMR_IMPORTED_NETWORK is not set; the router will start with no conference routes"
            );
            Vec::new()
        }
    };
    let route_table = Arc::new(RouteTable::compile(&bridges));
    info!(
        routes = route_table.len(),
        bridges = bridges.len(),
        "route table compiled"
    );

    let (ingress_tx, ingress_rx) = mpsc::channel::<IngressFrame>(4096);
    let mut endpoint_outputs = HashMap::<String, mpsc::Sender<DmrdPacket>>::new();
    let mut endpoint_receivers = HashMap::<String, mpsc::Receiver<DmrdPacket>>::new();

    for system in imported.systems.iter().filter(|system| system.enabled) {
        let (tx, rx) = mpsc::channel(1024);
        endpoint_outputs.insert(system.name.clone(), tx);
        endpoint_receivers.insert(system.name.clone(), rx);
    }

    tokio::spawn(run_router(
        route_table.clone(),
        ingress_rx,
        endpoint_outputs,
    ));

    let session_timeout_secs = std::env::var("DMR_HBP_SESSION_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);

    for system in imported.systems.iter().filter(|system| system.enabled) {
        let Some(outbound_rx) = endpoint_receivers.remove(&system.name) else {
            continue;
        };
        let mode = system.mode.to_ascii_uppercase();

        if matches!(mode.as_str(), "MASTER" | "SERVER") {
            if let (Some(ip), Some(port)) = (system.bind_ip.clone(), system.port) {
                let name = system.name.clone();
                let passphrase = system.passphrase.clone().unwrap_or_default();
                let max_repeaters = system.max_repeaters.unwrap_or(1) as usize;
                let timeout = Duration::from_secs(session_timeout_secs);
                let ingress = ingress_tx.clone();

                tokio::spawn(async move {
                    if let Err(e) = run_hbp_listener(
                        name,
                        format!("{ip}:{port}"),
                        passphrase,
                        max_repeaters,
                        timeout,
                        ingress,
                        outbound_rx,
                    )
                    .await
                    {
                        warn!(error = %e, "HBP listener stopped");
                    }
                });
            }
        } else if mode == "OPENBRIDGE" {
            let local_network_id = imported.server_id.unwrap_or(0);
            let system = system.clone();
            let ingress = ingress_tx.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    run_openbridge_endpoint(system, local_network_id, ingress, outbound_rx).await
                {
                    warn!(error = %e, "OpenBridge endpoint stopped");
                }
            });
        }
    }

    let state = Arc::new(AppState {
        version: env!("CARGO_PKG_VERSION"),
        systems: imported.systems.len(),
        routes: route_table.len(),
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

async fn run_router(
    routes: Arc<RouteTable>,
    mut ingress: mpsc::Receiver<IngressFrame>,
    outputs: HashMap<String, mpsc::Sender<DmrdPacket>>,
) {
    while let Some(frame) = ingress.recv().await {
        if frame.packet.call_type != CallType::Group {
            debug!(endpoint = %frame.endpoint, "private call routing is not enabled yet");
            continue;
        }

        let targets = routes.lookup(
            &frame.endpoint,
            frame.packet.slot,
            TalkgroupId(frame.packet.destination),
        );

        for target in targets {
            let Some(tx) = outputs.get(&target.endpoint) else {
                warn!(
                    source = %frame.endpoint,
                    target = %target.endpoint,
                    "route target has no active endpoint"
                );
                continue;
            };

            if target.talkgroup.0 != frame.packet.destination {
                warn!(
                    source = %frame.endpoint,
                    target = %target.endpoint,
                    source_tg = frame.packet.destination,
                    target_tg = target.talkgroup.0,
                    "TG translation deferred until DMR Link Control rewriting is implemented"
                );
                continue;
            }

            let mut packet = frame.packet.clone();
            packet.slot = target.slot;
            packet.destination = target.talkgroup.0;

            if tx.send(packet).await.is_err() {
                warn!(target = %target.endpoint, "route target channel closed");
            }
        }
    }
}

async fn run_hbp_listener(
    name: String,
    addr: String,
    passphrase: String,
    max_repeaters: usize,
    session_timeout: Duration,
    ingress: mpsc::Sender<IngressFrame>,
    mut outbound: mpsc::Receiver<DmrdPacket>,
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
                    Ok(events) => process_master_events(&socket, &name, events, &ingress).await?,
                    Err(e) => warn!(system = %name, %peer, error = %e, bytes = n, "invalid HBP packet"),
                }
            }
            Some(packet) = outbound.recv() => {
                let peers: Vec<(u32, std::net::SocketAddr)> = master
                    .peers()
                    .values()
                    .filter(|peer| peer.state == SessionState::Connected)
                    .map(|peer| (peer.repeater_id, peer.remote))
                    .collect();

                for (repeater_id, remote) in peers {
                    let mut packet = packet.clone();
                    packet.repeater = repeater_id;
                    let bytes = packet.encode();
                    socket.send_to(&bytes, remote).await?;
                    debug!(system = %name, repeater_id, %remote, bytes = bytes.len(), "routed DMRD sent to HBP peer");
                }
            }
            _ = cleanup.tick() => {
                let events = master.expire_sessions(std::time::Instant::now());
                process_master_events(&socket, &name, events, &ingress).await?;
            }
        }
    }
}

async fn process_master_events(
    socket: &UdpSocket,
    system: &str,
    events: Vec<MasterEvent>,
    ingress: &mpsc::Sender<IngressFrame>,
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
                debug!(
                    system,
                    repeater_id,
                    %remote,
                    source = packet.source,
                    destination = packet.destination,
                    stream_id = packet.stream_id,
                    "authenticated DMR frame received"
                );
                ingress
                    .send(IngressFrame {
                        endpoint: system.to_string(),
                        packet,
                    })
                    .await
                    .map_err(|_| anyhow!("router ingress channel closed"))?;
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

async fn run_openbridge_endpoint(
    system: LegacySystem,
    local_network_id: u32,
    ingress: mpsc::Sender<IngressFrame>,
    mut outbound: mpsc::Receiver<DmrdPacket>,
) -> Result<()> {
    if local_network_id == 0 {
        return Err(anyhow!(
            "{}: OpenBridge requires GLOBAL SERVER_ID or a non-zero local network id",
            system.name
        ));
    }

    let bind_ip = system.bind_ip.as_deref().unwrap_or("0.0.0.0");
    let bind_port = system
        .port
        .ok_or_else(|| anyhow!("{}: OpenBridge PORT is required", system.name))?;
    let target_ip = system
        .target_ip
        .as_deref()
        .ok_or_else(|| anyhow!("{}: OpenBridge TARGET_IP is required", system.name))?;
    let target_port = system
        .target_port
        .ok_or_else(|| anyhow!("{}: OpenBridge TARGET_PORT is required", system.name))?;
    let passphrase = system.passphrase.clone().unwrap_or_default();

    let target = lookup_host((target_ip, target_port))
        .await
        .with_context(|| format!("{}: unable to resolve OpenBridge target", system.name))?
        .next()
        .ok_or_else(|| {
            anyhow!(
                "{}: OpenBridge target resolved to no addresses",
                system.name
            )
        })?;

    let socket = UdpSocket::bind((bind_ip, bind_port)).await?;
    let codec = OpenBridgeCodec::new(
        passphrase.into_bytes(),
        local_network_id,
        system.network_id,
        system.both_slots,
    );
    let mut buf = [0u8; 2048];

    info!(
        system = %system.name,
        bind = %format!("{bind_ip}:{bind_port}"),
        %target,
        local_network_id,
        remote_network_id = ?system.network_id,
        both_slots = system.both_slots,
        "OpenBridge endpoint listening"
    );

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, remote) = recv?;
                if remote != target {
                    warn!(system = %system.name, %remote, expected = %target, "OpenBridge packet from unexpected source");
                    continue;
                }

                match codec.decode(&buf[..n]) {
                    Ok(packet) => {
                        ingress
                            .send(IngressFrame {
                                endpoint: system.name.clone(),
                                packet,
                            })
                            .await
                            .map_err(|_| anyhow!("router ingress channel closed"))?;
                    }
                    Err(e) => warn!(system = %system.name, %remote, error = %e, "invalid OpenBridge packet"),
                }
            }
            Some(packet) = outbound.recv() => {
                let bytes = codec.encode(&packet);
                socket.send_to(&bytes, target).await?;
                debug!(system = %system.name, %target, bytes = bytes.len(), "routed DMRD sent to OpenBridge");
            }
        }
    }
}
