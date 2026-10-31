use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use dmr_config::{import_hblink_cfg, import_network_topology, ImportedTopology, LegacySystem};
use dmr_core::{
    Bridge, BridgeMember, CallType, IpscRole, TalkgroupId, TimeoutPolicy, Timeslot,
};
use dmr_fec::rewrite_group_voice_payload;
use dmr_protocol_hbp::{
    challenge_digest, encode_rptc, encode_rptk, encode_rptl, encode_rptping, parse_packet as parse_hbp,
    DmrdPacket, HbpMaster, HbpPacket, MasterEvent, SessionState,
};
use dmr_protocol_ipsc::{
    encode_control, encode_peer_list, parse_packet as parse_ipsc, IpscPacket, IpscRegistry,
    IpscVoiceTranslator,
    PeerInfo, DE_REG_REQ, MASTER_ALIVE_REPLY, MASTER_ALIVE_REQ, MASTER_REG_REPLY, MASTER_REG_REQ,
    PEER_ALIVE_REPLY, PEER_ALIVE_REQ, PEER_LIST_REPLY, PEER_LIST_REQ, PEER_REG_REPLY,
    PEER_REG_REQ,
};
use dmr_protocol_openbridge::OpenBridgeCodec;
use dmr_router::{BridgeStatus, RouteEngine};
use dmr_store::{
    BridgeRecord, CallRecord, EndpointRecord, NewBridge, NewEndpoint, NewTalkgroup, Store,
    UserIdentity,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::{mpsc, Mutex, RwLock},
    time::interval,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    version: &'static str,
    systems: usize,
    route_engine: Arc<Mutex<RouteEngine>>,
    runtime: Arc<RwLock<RuntimeState>>,
    store: Option<Store>,
}

#[derive(Debug, Default)]
struct RuntimeState {
    endpoints: HashMap<String, EndpointStatus>,
    recent_calls: VecDeque<CallEvent>,
}

#[derive(Debug, Clone, Serialize)]
struct EndpointStatus {
    protocol: String,
    state: String,
    peers: usize,
}

#[derive(Debug, Clone, Serialize)]
struct CallEvent {
    timestamp: u64,
    endpoint: String,
    source: u32,
    destination: u32,
    timeslot: u8,
    call_type: &'static str,
    stream_id: u32,
    event: &'static str,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    imported_systems: usize,
    compiled_routes: usize,
    database: &'static str,
}

#[derive(Serialize)]
struct PublicStatus {
    version: &'static str,
    endpoints: HashMap<String, EndpointStatus>,
    bridges: Vec<BridgeStatus>,
    recent_calls: Vec<CallEvent>,
}

#[derive(Debug, Clone)]
struct IngressFrame {
    endpoint: String,
    packet: DmrdPacket,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Fingerprint {
    endpoint: String,
    stream: u32,
    sequence: u8,
    source: u32,
    destination: u32,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
}

async fn health(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let routes = s.route_engine.lock().await.len();
    let database = if let Some(store) = &s.store {
        if store.health().await { "connected" } else { "unavailable" }
    } else {
        "disabled"
    };
    Json(Health {
        status: "ok",
        version: s.version,
        imported_systems: s.systems,
        compiled_routes: routes,
        database,
    })
}

async fn public_status(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let runtime = s.runtime.read().await;
    let bridges = s.route_engine.lock().await.bridge_status();
    Json(PublicStatus {
        version: s.version,
        endpoints: runtime.endpoints.clone(),
        bridges,
        recent_calls: runtime.recent_calls.iter().cloned().collect(),
    })
}

async fn dashboard() -> Html<&'static str> {
    Html(PUBLIC_DASHBOARD)
}

async fn admin_page() -> Html<&'static str> {
    Html(ADMIN_PAGE)
}

async fn login(State(s): State<Arc<AppState>>, Json(req): Json<LoginRequest>) -> Response {
    let Some(store) = &s.store else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "database is not configured");
    };
    match store.login(&req.username, &req.password).await {
        Ok(token) => (StatusCode::OK, Json(LoginResponse { token })).into_response(),
        Err(_) => error_response(StatusCode::UNAUTHORIZED, "invalid credentials"),
    }
}

async fn admin_endpoints(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((store, _user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.list_endpoints().await {
        Ok(items) => Json(items).into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn admin_upsert_endpoint(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(endpoint): Json<NewEndpoint>,
) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.upsert_endpoint(&endpoint).await {
        Ok(saved) => {
            let state = serde_json::to_value(&saved).ok();
            let _ = store
                .audit(user.id, "upsert", "endpoint", Some(&saved.id.to_string()), state.as_ref())
                .await;
            Json(saved).into_response()
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn admin_delete_endpoint(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.delete_endpoint(id).await {
        Ok(()) => {
            let _ = store.audit(user.id, "delete", "endpoint", Some(&id.to_string()), None).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn admin_bridges(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((store, _user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.list_bridges().await {
        Ok(items) => Json(items).into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}


async fn admin_upsert_bridge(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(bridge): Json<NewBridge>,
) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.upsert_bridge(&bridge).await {
        Ok(saved) => {
            let state = serde_json::to_value(&saved).ok();
            let _ = store
                .audit(user.id, "upsert", "bridge", Some(&saved.id.to_string()), state.as_ref())
                .await;
            Json(saved).into_response()
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn admin_delete_bridge(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.delete_bridge(id).await {
        Ok(()) => {
            let _ = store
                .audit(user.id, "delete", "bridge", Some(&id.to_string()), None)
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn admin_talkgroups(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((store, _user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.list_talkgroups().await {
        Ok(items) => Json(items).into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn admin_upsert_talkgroup(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(item): Json<NewTalkgroup>,
) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.upsert_talkgroup(&item).await {
        Ok(saved) => {
            let state = serde_json::to_value(&saved).ok();
            let _ = store
                .audit(
                    user.id,
                    "upsert",
                    "talkgroup",
                    Some(&saved.id.to_string()),
                    state.as_ref(),
                )
                .await;
            Json(saved).into_response()
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn admin_delete_talkgroup(
    State(s): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.delete_talkgroup(id).await {
        Ok(()) => {
            let _ = store
                .audit(user.id, "delete", "talkgroup", Some(&id.to_string()), None)
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
    }
}

async fn admin_recent_calls(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((store, _user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.recent_calls(200).await {
        Ok(items) => Json(items).into_response(),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn admin_reload_routes(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some((store, user)) = authorized(&s, &headers).await else {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    };
    match store.list_bridges().await {
        Ok(records) => {
            let bridges = records
                .into_iter()
                .filter(|record| record.enabled)
                .map(bridge_record_to_bridge)
                .collect::<Result<Vec<_>>>();
            match bridges {
                Ok(bridges) => {
                    *s.route_engine.lock().await = RouteEngine::compile(&bridges);
                    let _ = store
                        .audit(user.id, "reload", "routes", None, None)
                        .await;
                    Json(json!({"status":"ok","bridges":bridges.len()})).into_response()
                }
                Err(e) => error_response(StatusCode::BAD_REQUEST, &e.to_string()),
            }
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

async fn authorized(state: &AppState, headers: &HeaderMap) -> Option<(Store, UserIdentity)> {
    let store = state.store.clone()?;
    let raw = headers.get("authorization")?.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ")?;
    let user = store.authenticate(token).await.ok()?;
    Some((store, user))
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("dmr_master=info".parse()?),
        )
        .init();

    let store = match std::env::var("DATABASE_URL") {
        Ok(url) => match Store::connect(&url).await {
            Ok(store) => {
                if let Ok(password) = std::env::var("DMR_ADMIN_PASSWORD") {
                    let username = std::env::var("DMR_ADMIN_USERNAME").unwrap_or_else(|_| "admin".into());
                    if store.ensure_admin(&username, &password).await.unwrap_or(false) {
                        info!(%username, "initial administrator created");
                    }
                }
                Some(store)
            }
            Err(e) => {
                warn!(error = %e, "PostgreSQL unavailable; continuing with file configuration and in-memory status");
                None
            }
        },
        Err(_) => None,
    };

    let use_db = env_bool("DMR_USE_DATABASE_CONFIG", false) && store.is_some();
    let (systems, server_id, topology) = if use_db {
        load_database_config(store.as_ref().unwrap()).await?
    } else {
        load_file_config()?
    };

    info!(systems = systems.len(), ?server_id, database_config = use_db, "runtime configuration loaded");

    let route_engine = Arc::new(Mutex::new(RouteEngine::compile(&topology.bridges)));
    info!(routes = route_engine.lock().await.len(), bridges = topology.bridges.len(), "route engine compiled");

    let runtime = Arc::new(RwLock::new(RuntimeState::default()));
    let (ingress_tx, ingress_rx) = mpsc::channel::<IngressFrame>(4096);
    let mut endpoint_outputs = HashMap::<String, mpsc::Sender<DmrdPacket>>::new();
    let mut endpoint_receivers = HashMap::<String, mpsc::Receiver<DmrdPacket>>::new();

    for system in systems.iter().filter(|system| system.enabled) {
        let (tx, rx) = mpsc::channel(1024);
        endpoint_outputs.insert(system.name.clone(), tx);
        endpoint_receivers.insert(system.name.clone(), rx);
    }

    tokio::spawn(run_router(
        route_engine.clone(),
        ingress_rx,
        endpoint_outputs,
        topology.unit_systems.clone(),
        runtime.clone(),
        store.clone(),
    ));

    let session_timeout_secs = std::env::var("DMR_HBP_SESSION_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(60);

    for system in systems.iter().filter(|system| system.enabled) {
        let mode = system.mode.to_ascii_uppercase();
        if matches!(mode.as_str(), "MASTER" | "SERVER") {
            let Some(outbound_rx) = endpoint_receivers.remove(&system.name) else { continue; };
            if let (Some(ip), Some(port)) = (system.bind_ip.clone(), system.port) {
                let name = system.name.clone();
                let passphrase = system.passphrase.clone().unwrap_or_default();
                let max_repeaters = system.max_repeaters.unwrap_or(1000) as usize;
                let timeout = Duration::from_secs(session_timeout_secs);
                let ingress = ingress_tx.clone();
                let runtime_state = runtime.clone();
                let allow = parse_id_list(system.raw.get("allow_ids").and_then(|v| v.as_deref()));
                let deny = parse_id_list(system.raw.get("deny_ids").and_then(|v| v.as_deref()));
                let per_id = parse_password_map(system.raw.get("per_id_passwords").and_then(|v| v.as_deref()));

                tokio::spawn(async move {
                    if let Err(e) = run_hbp_listener(
                        name,
                        format!("{ip}:{port}"),
                        passphrase,
                        max_repeaters,
                        timeout,
                        allow,
                        deny,
                        per_id,
                        ingress,
                        outbound_rx,
                        runtime_state,
                    )
                    .await
                    {
                        warn!(error = %e, "HBP listener stopped");
                    }
                });
            }
        } else if matches!(mode.as_str(), "PEER" | "CLIENT" | "OUTBOUND") {
            let Some(outbound_rx) = endpoint_receivers.remove(&system.name) else { continue; };
            let system = system.clone();
            let ingress = ingress_tx.clone();
            let runtime_state = runtime.clone();
            tokio::spawn(async move {
                if let Err(e) = run_hbp_outbound(system, ingress, outbound_rx, runtime_state).await {
                    warn!(error = %e, "HBP outbound endpoint stopped");
                }
            });
        } else if mode == "OPENBRIDGE" {
            let Some(outbound_rx) = endpoint_receivers.remove(&system.name) else { continue; };
            let local_network_id = server_id.unwrap_or(0);
            let system = system.clone();
            let ingress = ingress_tx.clone();
            let runtime_state = runtime.clone();
            tokio::spawn(async move {
                if let Err(e) = run_openbridge_endpoint(system, local_network_id, ingress, outbound_rx, runtime_state).await {
                    warn!(error = %e, "OpenBridge endpoint stopped");
                }
            });
        } else if mode == "IPSC" {
            let Some(outbound_rx) = endpoint_receivers.remove(&system.name) else { continue; };
            let system = system.clone();
            let runtime_state = runtime.clone();
            let ingress = ingress_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_ipsc_endpoint(system, ingress, outbound_rx, runtime_state).await {
                    warn!(error = %e, "IPSC endpoint stopped");
                }
            });
        }
    }

    let state = Arc::new(AppState {
        version: env!("CARGO_PKG_VERSION"),
        systems: systems.len(),
        route_engine,
        runtime,
        store,
    });

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/admin", get(admin_page))
        .route("/api/public/health", get(health))
        .route("/api/public/status", get(public_status))
        .route("/api/admin/login", post(login))
        .route("/api/admin/endpoints", get(admin_endpoints).post(admin_upsert_endpoint))
        .route("/api/admin/endpoints/{id}", delete(admin_delete_endpoint))
        .route("/api/admin/bridges", get(admin_bridges).post(admin_upsert_bridge))
        .route("/api/admin/bridges/{id}", delete(admin_delete_bridge))
        .route("/api/admin/talkgroups", get(admin_talkgroups).post(admin_upsert_talkgroup))
        .route("/api/admin/talkgroups/{id}", delete(admin_delete_talkgroup))
        .route("/api/admin/calls", get(admin_recent_calls))
        .route("/api/admin/reload-routes", post(admin_reload_routes))
        .with_state(state);

    let addr = std::env::var("DMR_HTTP_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    info!(%addr, "HTTP dashboard/API listening");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_file_config() -> Result<(Vec<LegacySystem>, Option<u32>, ImportedTopology)> {
    let cfg = std::env::var("DMR_HBLINK_CONFIG").unwrap_or_else(|_| "fixtures/hblink.example.cfg".into());
    let imported = import_hblink_cfg(PathBuf::from(cfg))?;
    let topology = match std::env::var("DMR_IMPORTED_NETWORK") {
        Ok(path) => import_network_topology(PathBuf::from(path))?,
        Err(_) => ImportedTopology { bridges: Vec::new(), unit_systems: Vec::new() },
    };
    Ok((imported.systems, imported.server_id, topology))
}

async fn load_database_config(store: &Store) -> Result<(Vec<LegacySystem>, Option<u32>, ImportedTopology)> {
    let records = store.list_endpoints().await?;
    let systems = records.iter().map(endpoint_record_to_legacy).collect::<Result<Vec<_>>>()?;
    let bridge_records = store.list_bridges().await?;
    let bridges = bridge_records.into_iter().filter(|b| b.enabled).map(bridge_record_to_bridge).collect::<Result<Vec<_>>>()?;
    let server_id = std::env::var("DMR_SERVER_ID").ok().and_then(|v| v.parse().ok());
    let unit_systems = std::env::var("DMR_UNIT_SYSTEMS").ok().map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    Ok((systems, server_id, ImportedTopology { bridges, unit_systems }))
}

fn endpoint_record_to_legacy(record: &EndpointRecord) -> Result<LegacySystem> {
    let mode = match record.protocol.to_ascii_lowercase().as_str() {
        "homebrew" => if record.role.to_ascii_lowercase().contains("outbound") { "OUTBOUND" } else { "SERVER" },
        "openbridge" => "OPENBRIDGE",
        "ipsc" => "IPSC",
        other => return Err(anyhow!("{}: unsupported database protocol {other}", record.name)),
    }.to_string();
    let cfg = record.config.as_object().cloned().unwrap_or_default();
    let get_s = |key: &str| cfg.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let get_u = |key: &str| cfg.get(key).and_then(|v| v.as_u64()).map(|v| v as u32);
    let mut raw = HashMap::new();
    for (key, value) in &cfg { raw.insert(key.clone(), Some(value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string()))); }
    Ok(LegacySystem {
        name: record.name.clone(), mode, enabled: record.enabled,
        bind_ip: get_s("bind_ip"), port: get_u("port").map(|v| v as u16),
        target_ip: get_s("target_ip"), target_port: get_u("target_port").map(|v| v as u16),
        passphrase: get_s("passphrase"), max_repeaters: get_u("max_repeaters"), group_hangtime: get_u("group_hangtime"),
        network_id: get_u("network_id"), both_slots: cfg.get("both_slots").and_then(|v| v.as_bool()).unwrap_or(false), raw,
    })
}

fn bridge_record_to_bridge(record: BridgeRecord) -> Result<Bridge> {
    let members = record.members.into_iter().map(|m| {
        let timeslot = Timeslot::from_u8(m.timeslot as u8).ok_or_else(|| anyhow!("invalid timeslot {}", m.timeslot))?;
        let timeout_policy = match m.timeout_policy.to_ascii_lowercase().as_str() { "on" => TimeoutPolicy::On, "off" => TimeoutPolicy::Off, _ => TimeoutPolicy::None };
        Ok(BridgeMember { endpoint: m.endpoint, timeslot, talkgroup: TalkgroupId(m.talkgroup as u32), initially_active: m.initially_active, timeout_secs: m.timeout_seconds.max(0) as u64, timeout_policy, on: m.on_talkgroups.into_iter().map(|v| TalkgroupId(v as u32)).collect(), off: m.off_talkgroups.into_iter().map(|v| TalkgroupId(v as u32)).collect(), reset: m.reset_talkgroups.into_iter().map(|v| TalkgroupId(v as u32)).collect() })
    }).collect::<Result<Vec<_>>>()?;
    Ok(Bridge { name: record.name, members })
}

async fn run_router(
    routes: Arc<Mutex<RouteEngine>>,
    mut ingress: mpsc::Receiver<IngressFrame>,
    outputs: HashMap<String, mpsc::Sender<DmrdPacket>>,
    unit_systems: Vec<String>,
    runtime: Arc<RwLock<RuntimeState>>,
    store: Option<Store>,
) {
    let unit: HashSet<String> = unit_systems.into_iter().collect();
    let mut fingerprints = HashMap::<Fingerprint, Instant>::new();
    let mut active_streams = HashSet::<(String, u32)>::new();
    let mut subscribers = HashMap::<u32, (String, Instant)>::new();

    while let Some(frame) = ingress.recv().await {
        let now = Instant::now();
        fingerprints.retain(|_, seen| now.saturating_duration_since(*seen) < Duration::from_secs(2));
        subscribers.retain(|_, (_, seen)| now.saturating_duration_since(*seen) < Duration::from_secs(3600));
        subscribers.insert(frame.packet.source, (frame.endpoint.clone(), now));
        let fingerprint = Fingerprint { endpoint: frame.endpoint.clone(), stream: frame.packet.stream_id, sequence: frame.packet.sequence, source: frame.packet.source, destination: frame.packet.destination };
        if fingerprints.insert(fingerprint, now).is_some() { continue; }

        let stream_key = (frame.endpoint.clone(), frame.packet.stream_id);
        if active_streams.insert(stream_key.clone()) {
            record_call_event(&runtime, store.as_ref(), &frame, "start").await;
        }

        let targets = if frame.packet.call_type == CallType::Group {
            routes.lock().await.route_group(&frame.endpoint, frame.packet.slot, TalkgroupId(frame.packet.destination), now)
        } else if unit.contains(&frame.endpoint) {
            if let Some((learned, _)) = subscribers.get(&frame.packet.destination) {
                if learned != &frame.endpoint && unit.contains(learned) {
                    vec![dmr_router::RouteTarget { endpoint: learned.clone(), slot: frame.packet.slot, talkgroup: TalkgroupId(frame.packet.destination), bridge: "UNIT-LEARNED".into() }]
                } else {
                    Vec::new()
                }
            } else {
                unit.iter().filter(|target| *target != &frame.endpoint).map(|target| dmr_router::RouteTarget { endpoint: target.clone(), slot: frame.packet.slot, talkgroup: TalkgroupId(frame.packet.destination), bridge: "UNIT-FLOOD".into() }).collect()
            }
        } else {
            Vec::new()
        };

        for target in targets {
            let Some(tx) = outputs.get(&target.endpoint) else {
                warn!(source = %frame.endpoint, target = %target.endpoint, "route target has no active DMRD transport");
                continue;
            };
            let mut packet = frame.packet.clone();
            let translation = packet.destination != target.talkgroup.0 || packet.slot != target.slot;
            packet.slot = target.slot;
            packet.destination = target.talkgroup.0;
            if translation && packet.call_type == CallType::Group {
                match rewrite_group_voice_payload(&packet.payload, packet.frame_type, packet.data_type, packet.destination, packet.source) {
                    Ok(payload) => packet.payload = payload,
                    Err(e) => { warn!(error = %e, bridge = %target.bridge, "DMR LC translation failed; frame dropped"); continue; }
                }
            }
            if tx.send(packet).await.is_err() { warn!(target = %target.endpoint, "route target channel closed"); }
        }

        if frame.packet.frame_type == 2 && frame.packet.data_type == 2 {
            active_streams.remove(&stream_key);
            record_call_event(&runtime, store.as_ref(), &frame, "end").await;
        }
    }
}

async fn record_call_event(runtime: &Arc<RwLock<RuntimeState>>, store: Option<&Store>, frame: &IngressFrame, event: &'static str) {
    let call_type = if frame.packet.call_type == CallType::Group { "group" } else { "private" };
    let item = CallEvent { timestamp: unix_now(), endpoint: frame.endpoint.clone(), source: frame.packet.source, destination: frame.packet.destination, timeslot: frame.packet.slot.as_u8(), call_type, stream_id: frame.packet.stream_id, event };
    {
        let mut state = runtime.write().await;
        state.recent_calls.push_front(item.clone());
        state.recent_calls.truncate(100);
    }
    if let Some(store) = store {
        let record = CallRecord { endpoint: item.endpoint, source_id: item.source as i32, destination_id: item.destination as i32, timeslot: item.timeslot as i16, call_type: item.call_type.into(), stream_id: item.stream_id as i64, event: item.event.into() };
        if let Err(e) = store.record_call(&record).await { debug!(error = %e, "unable to persist call event"); }
    }
}

async fn run_hbp_listener(
    name: String,
    addr: String,
    passphrase: String,
    max_repeaters: usize,
    session_timeout: Duration,
    allow: Vec<u32>,
    deny: Vec<u32>,
    per_id_passwords: HashMap<u32, String>,
    ingress: mpsc::Sender<IngressFrame>,
    mut outbound: mpsc::Receiver<DmrdPacket>,
    runtime: Arc<RwLock<RuntimeState>>,
) -> Result<()> {
    let socket = UdpSocket::bind(&addr).await?;
    let mut master = HbpMaster::new(passphrase.into_bytes(), max_repeaters, session_timeout);
    if !allow.is_empty() { master.set_allow_ids(allow); }
    if !deny.is_empty() { master.set_deny_ids(deny); }
    for (id, password) in per_id_passwords { master.set_peer_passphrase(id, password.into_bytes()); }
    let mut cleanup = interval(Duration::from_secs(5));
    let mut buf = [0u8; 2048];
    update_endpoint(&runtime, &name, "homebrew", "listening", 0).await;
    info!(system = %name, %addr, max_repeaters, "HBP master listening");

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, peer) = recv?;
                match master.handle_datagram(peer, &buf[..n], Instant::now()) {
                    Ok(events) => process_master_events(&socket, &name, events, &ingress).await?,
                    Err(e) => warn!(system = %name, %peer, error = %e, "invalid HBP packet"),
                }
                update_endpoint(&runtime, &name, "homebrew", "listening", master.peers().values().filter(|p| p.state == SessionState::Connected).count()).await;
            }
            Some(packet) = outbound.recv() => {
                let peers: Vec<(u32, SocketAddr)> = master.peers().values().filter(|peer| peer.state == SessionState::Connected).map(|peer| (peer.repeater_id, peer.remote)).collect();
                for (repeater_id, remote) in peers {
                    let mut packet = packet.clone(); packet.repeater = repeater_id;
                    socket.send_to(&packet.encode(), remote).await?;
                }
            }
            _ = cleanup.tick() => {
                let events = master.expire_sessions(Instant::now());
                process_master_events(&socket, &name, events, &ingress).await?;
                update_endpoint(&runtime, &name, "homebrew", "listening", master.peers().values().filter(|p| p.state == SessionState::Connected).count()).await;
            }
        }
    }
}

async fn process_master_events(socket: &UdpSocket, system: &str, events: Vec<MasterEvent>, ingress: &mpsc::Sender<IngressFrame>) -> Result<()> {
    for event in events {
        match event {
            MasterEvent::Send { destination, payload } => { socket.send_to(&payload, destination).await?; }
            MasterEvent::Authenticated { repeater_id, remote } => info!(system, repeater_id, %remote, "HBP repeater authenticated"),
            MasterEvent::Connected { repeater_id, remote } => info!(system, repeater_id, %remote, "HBP repeater connected"),
            MasterEvent::Frame { packet, .. } => ingress.send(IngressFrame { endpoint: system.to_string(), packet }).await.map_err(|_| anyhow!("router ingress channel closed"))?,
            MasterEvent::Disconnected { repeater_id, remote } => info!(system, repeater_id, %remote, "HBP repeater disconnected"),
            MasterEvent::Rejected { repeater_id, remote, reason } => warn!(system, repeater_id, %remote, reason, "HBP packet rejected"),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HbpOutboundState {
    Login,
    Authentication,
    Configuration,
    Connected,
}

fn fixed_field(value: Option<&str>, width: usize, pad_left_zero: bool) -> Vec<u8> {
    let raw = value.unwrap_or("").as_bytes();
    let mut out = vec![if pad_left_zero { b'0' } else { b' ' }; width];
    let take = raw.len().min(width);
    if pad_left_zero {
        out[width - take..].copy_from_slice(&raw[raw.len() - take..]);
    } else {
        out[..take].copy_from_slice(&raw[..take]);
    }
    out
}

fn hbp_config_payload(system: &LegacySystem, radio_id: u32) -> Vec<u8> {
    let raw = |key: &str| raw_string_ref(system, key);
    let mut out = Vec::with_capacity(294);
    out.extend_from_slice(&fixed_field(raw("callsign"), 8, false));
    out.extend_from_slice(&radio_id.to_be_bytes());
    out.extend_from_slice(&fixed_field(raw("rx_freq"), 9, false));
    out.extend_from_slice(&fixed_field(raw("tx_freq"), 9, false));
    out.extend_from_slice(&fixed_field(raw("tx_power"), 2, true));
    out.extend_from_slice(&fixed_field(raw("colorcode"), 2, true));
    out.extend_from_slice(&fixed_field(raw("latitude"), 8, false));
    out.extend_from_slice(&fixed_field(raw("longitude"), 9, false));
    out.extend_from_slice(&fixed_field(raw("height"), 3, true));
    out.extend_from_slice(&fixed_field(raw("location"), 20, false));
    out.extend_from_slice(&fixed_field(raw("description"), 19, false));
    out.extend_from_slice(&fixed_field(raw("slots").or(Some("3")), 1, false));
    out.extend_from_slice(&fixed_field(raw("url"), 124, false));
    out.extend_from_slice(&fixed_field(raw("software_id").or(Some("DMR-Master-System")), 40, false));
    out.extend_from_slice(&fixed_field(raw("package_id").or(Some(env!("CARGO_PKG_VERSION"))), 40, false));
    out
}

async fn run_hbp_outbound(
    system: LegacySystem,
    ingress: mpsc::Sender<IngressFrame>,
    mut outbound: mpsc::Receiver<DmrdPacket>,
    runtime: Arc<RwLock<RuntimeState>>,
) -> Result<()> {
    let bind_ip = system.bind_ip.as_deref().unwrap_or("0.0.0.0");
    let bind_port = system.port.unwrap_or(0);
    let target_ip = system
        .target_ip
        .as_deref()
        .ok_or_else(|| anyhow!("{}: HBP outbound SERVER_IP/TARGET_IP is required", system.name))?;
    let target_port = system
        .target_port
        .ok_or_else(|| anyhow!("{}: HBP outbound SERVER_PORT/TARGET_PORT is required", system.name))?;
    let remote = lookup_host((target_ip, target_port))
        .await?
        .next()
        .ok_or_else(|| anyhow!("{}: HBP target resolved to no addresses", system.name))?;
    let radio_id = raw_u32(&system, "radio_id")
        .or_else(|| raw_u32(&system, "id"))
        .ok_or_else(|| anyhow!("{}: HBP outbound RADIO_ID is required", system.name))?;
    let passphrase = system.passphrase.clone().unwrap_or_default();
    let config = hbp_config_payload(&system, radio_id);
    let ping_secs = raw_u32(&system, "ping_time").unwrap_or(5).max(1) as u64;
    let socket = UdpSocket::bind((bind_ip, bind_port)).await?;
    let mut state = HbpOutboundState::Login;
    let mut last_rx = Instant::now();
    let mut tick = interval(Duration::from_secs(ping_secs));
    let mut buf = [0u8; 2048];

    socket.send_to(&encode_rptl(radio_id), remote).await?;
    update_endpoint(&runtime, &system.name, "homebrew", "registering", 0).await;
    info!(system = %system.name, %remote, radio_id, "HBP outbound endpoint started");

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, source) = recv?;
                if source != remote { continue; }
                last_rx = Instant::now();
                match parse_hbp(&buf[..n]) {
                    Ok(HbpPacket::MasterAck(payload)) if state == HbpOutboundState::Login && payload.len() >= 4 => {
                        let challenge = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let digest = challenge_digest(challenge, passphrase.as_bytes());
                        socket.send_to(&encode_rptk(radio_id, &digest), remote).await?;
                        state = HbpOutboundState::Authentication;
                    }
                    Ok(HbpPacket::MasterAck(_)) if state == HbpOutboundState::Authentication => {
                        socket.send_to(&encode_rptc(radio_id, &config), remote).await?;
                        state = HbpOutboundState::Configuration;
                    }
                    Ok(HbpPacket::MasterAck(_)) if state == HbpOutboundState::Configuration => {
                        state = HbpOutboundState::Connected;
                        update_endpoint(&runtime, &system.name, "homebrew", "connected", 1).await;
                        info!(system = %system.name, %remote, "HBP outbound connected");
                    }
                    Ok(HbpPacket::MasterPong { .. }) => {}
                    Ok(HbpPacket::Dmrd(packet)) if state == HbpOutboundState::Connected => {
                        ingress.send(IngressFrame { endpoint: system.name.clone(), packet }).await.map_err(|_| anyhow!("router ingress channel closed"))?;
                    }
                    Ok(HbpPacket::MasterNak(_)) => {
                        state = HbpOutboundState::Login;
                        socket.send_to(&encode_rptl(radio_id), remote).await?;
                        update_endpoint(&runtime, &system.name, "homebrew", "registering", 0).await;
                    }
                    Ok(_) => {}
                    Err(e) => warn!(system = %system.name, error = %e, "invalid HBP outbound packet"),
                }
            }
            Some(mut packet) = outbound.recv(), if state == HbpOutboundState::Connected => {
                packet.repeater = radio_id;
                socket.send_to(&packet.encode(), remote).await?;
            }
            _ = tick.tick() => {
                if state == HbpOutboundState::Connected {
                    if Instant::now().saturating_duration_since(last_rx) > Duration::from_secs(ping_secs.saturating_mul(4)) {
                        state = HbpOutboundState::Login;
                        socket.send_to(&encode_rptl(radio_id), remote).await?;
                        update_endpoint(&runtime, &system.name, "homebrew", "reconnecting", 0).await;
                    } else {
                        socket.send_to(&encode_rptping(radio_id), remote).await?;
                    }
                } else {
                    socket.send_to(&encode_rptl(radio_id), remote).await?;
                }
            }
        }
    }
}

async fn run_openbridge_endpoint(system: LegacySystem, local_network_id: u32, ingress: mpsc::Sender<IngressFrame>, mut outbound: mpsc::Receiver<DmrdPacket>, runtime: Arc<RwLock<RuntimeState>>) -> Result<()> {
    if local_network_id == 0 { return Err(anyhow!("{}: OpenBridge requires a non-zero local network id", system.name)); }
    let bind_ip = system.bind_ip.as_deref().unwrap_or("0.0.0.0");
    let bind_port = system.port.ok_or_else(|| anyhow!("{}: OpenBridge PORT is required", system.name))?;
    let target_ip = system.target_ip.as_deref().ok_or_else(|| anyhow!("{}: OpenBridge TARGET_IP is required", system.name))?;
    let target_port = system.target_port.ok_or_else(|| anyhow!("{}: OpenBridge TARGET_PORT is required", system.name))?;
    let target = lookup_host((target_ip, target_port)).await.with_context(|| format!("{}: resolve OpenBridge target", system.name))?.next().ok_or_else(|| anyhow!("OpenBridge target resolved to no addresses"))?;
    let socket = UdpSocket::bind((bind_ip, bind_port)).await?;
    let codec = OpenBridgeCodec::new(system.passphrase.clone().unwrap_or_default().into_bytes(), local_network_id, system.network_id, system.both_slots);
    let mut buf = [0u8; 2048];
    update_endpoint(&runtime, &system.name, "openbridge", "connected", 1).await;
    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, remote) = recv?;
                if remote != target { warn!(system = %system.name, %remote, expected = %target, "OpenBridge packet from unexpected source"); continue; }
                match codec.decode(&buf[..n]) {
                    Ok(packet) => ingress.send(IngressFrame { endpoint: system.name.clone(), packet }).await.map_err(|_| anyhow!("router ingress channel closed"))?,
                    Err(e) => warn!(system = %system.name, error = %e, "invalid OpenBridge packet"),
                }
            }
            Some(packet) = outbound.recv() => { socket.send_to(&codec.encode(&packet), target).await?; }
        }
    }
}

async fn run_ipsc_endpoint(
    system: LegacySystem,
    ingress: mpsc::Sender<IngressFrame>,
    mut outbound: mpsc::Receiver<DmrdPacket>,
    runtime: Arc<RwLock<RuntimeState>>,
) -> Result<()> {
    let bind_ip = system.bind_ip.as_deref().unwrap_or("0.0.0.0");
    let port = system
        .port
        .ok_or_else(|| anyhow!("{}: IPSC port required", system.name))?;
    let radio_id = raw_u32(&system, "radio_id")
        .ok_or_else(|| anyhow!("{}: IPSC radio_id required", system.name))?;
    let master_mode = raw_string(&system, "ipsc_role")
        .is_some_and(|v| v.eq_ignore_ascii_case("master"));
    let role = if master_mode {
        IpscRole::Master
    } else {
        IpscRole::Peer
    };
    let auth_key = raw_string(&system, "auth_key").map(|v| v.into_bytes());
    let linking = raw_u32(&system, "linking").unwrap_or(0x6a) as u8;
    let flags = [0, 0, 0x80, 0xdc];
    let version = [4, 3, 4, 0];
    let socket = UdpSocket::bind((bind_ip, port)).await?;
    let mut registry = IpscRegistry::new(MAX_IPSC_PEERS, Duration::from_secs(20));
    let master_addr = if role == IpscRole::Peer {
        let host = system
            .target_ip
            .as_deref()
            .or_else(|| raw_string_ref(&system, "master_ip"))
            .ok_or_else(|| anyhow!("{}: IPSC master address required", system.name))?;
        let master_port = system
            .target_port
            .or_else(|| raw_u32(&system, "master_port").map(|v| v as u16))
            .ok_or_else(|| anyhow!("{}: IPSC master port required", system.name))?;
        lookup_host((host, master_port)).await?.next()
    } else {
        None
    };
    let mut tick = interval(Duration::from_secs(5));
    let mut media_tick = interval(Duration::from_millis(60));
    let mut media_queue = VecDeque::<DmrdPacket>::new();
    let mut media = IpscVoiceTranslator::new(radio_id);
    let mut buf = [0u8; 4096];
    let mut registered = role == IpscRole::Master;
    update_endpoint(
        &runtime,
        &system.name,
        "ipsc",
        if registered { "master" } else { "registering" },
        0,
    )
    .await;
    info!(system = %system.name, ?role, radio_id, bind = %format!("{bind_ip}:{port}"), "IPSC endpoint started");

    loop {
        tokio::select! {
            recv = socket.recv_from(&mut buf) => {
                let (n, remote) = recv?;
                match parse_ipsc(&buf[..n], auth_key.as_deref()) {
                    Ok(IpscPacket::Control(control)) => {
                        match control.opcode {
                            MASTER_REG_REQ if role == IpscRole::Master => {
                                let peer = PeerInfo { peer_id: control.peer_id, address: remote, linking: control.linking.unwrap_or(linking) };
                                if registry.register(peer, Instant::now()) {
                                    let reply = encode_control(MASTER_REG_REPLY, radio_id, linking, flags, version, registry.peers().len() as u16, auth_key.as_deref());
                                    socket.send_to(&reply, remote).await?;
                                }
                            }
                            MASTER_REG_REPLY if role == IpscRole::Peer => {
                                registered = true;
                                let req = encode_control(PEER_LIST_REQ, radio_id, linking, flags, version, 0, auth_key.as_deref());
                                socket.send_to(&req, remote).await?;
                            }
                            PEER_LIST_REQ if role == IpscRole::Master => {
                                let list = encode_peer_list(radio_id, &registry.peers(), auth_key.as_deref());
                                socket.send_to(&list, remote).await?;
                            }
                            MASTER_ALIVE_REQ if role == IpscRole::Master => {
                                registry.touch(control.peer_id, Instant::now());
                                let reply = encode_control(MASTER_ALIVE_REPLY, radio_id, linking, flags, version, 0, auth_key.as_deref());
                                socket.send_to(&reply, remote).await?;
                            }
                            PEER_ALIVE_REQ => {
                                registry.touch(control.peer_id, Instant::now());
                                let reply = encode_control(PEER_ALIVE_REPLY, radio_id, linking, flags, version, 0, auth_key.as_deref());
                                socket.send_to(&reply, remote).await?;
                            }
                            PEER_REG_REQ => {
                                registry.register(PeerInfo { peer_id: control.peer_id, address: remote, linking }, Instant::now());
                                let reply = encode_control(PEER_REG_REPLY, radio_id, linking, flags, version, 0, auth_key.as_deref());
                                socket.send_to(&reply, remote).await?;
                            }
                            DE_REG_REQ => { registry.remove(control.peer_id); }
                            _ => { registry.touch(control.peer_id, Instant::now()); }
                        }
                    }
                    Ok(IpscPacket::PeerList { peers, .. }) => {
                        for peer in peers {
                            if peer.peer_id != radio_id {
                                registry.register(peer.clone(), Instant::now());
                                let req = encode_control(PEER_REG_REQ, radio_id, linking, flags, version, 0, auth_key.as_deref());
                                let _ = socket.send_to(&req, peer.address).await;
                            }
                        }
                    }
                    Ok(IpscPacket::User(user)) => {
                        registry.touch(user.peer_id, Instant::now());
                        match media.ipsc_to_dmrd(&user) {
                            Ok(Some(packet)) => {
                                ingress
                                    .send(IngressFrame { endpoint: system.name.clone(), packet })
                                    .await
                                    .map_err(|_| anyhow!("router ingress channel closed"))?;
                            }
                            Ok(None) => {
                                debug!(system = %system.name, peer_id = user.peer_id, "IPSC user packet outside supported Group Voice media subset");
                            }
                            Err(e) => warn!(system = %system.name, peer_id = user.peer_id, error = %e, "IPSC media translation failed"),
                        }
                    }
                    Err(e) => warn!(system = %system.name, %remote, error = %e, "invalid IPSC packet"),
                }
                update_endpoint(&runtime, &system.name, "ipsc", if registered { "connected" } else { "registering" }, registry.peers().len()).await;
            }
            Some(packet) = outbound.recv() => {
                // Headers may go immediately. Voice/terminator frames are queued so IPSC
                // is paced at the native 60 ms burst interval.
                if packet.frame_type == 2 && packet.data_type == 1 {
                    if let Some(bytes) = media.dmrd_to_ipsc(&packet, auth_key.as_deref())? {
                        send_ipsc_media(&socket, role, master_addr, &registry, &bytes).await?;
                    }
                } else {
                    media_queue.push_back(packet);
                }
            }
            _ = media_tick.tick() => {
                if let Some(packet) = media_queue.pop_front() {
                    if let Some(bytes) = media.dmrd_to_ipsc(&packet, auth_key.as_deref())? {
                        send_ipsc_media(&socket, role, master_addr, &registry, &bytes).await?;
                    }
                }
            }
            _ = tick.tick() => {
                registry.expire(Instant::now());
                if role == IpscRole::Peer {
                    if let Some(master) = master_addr {
                        let opcode = if registered { MASTER_ALIVE_REQ } else { MASTER_REG_REQ };
                        let packet = encode_control(opcode, radio_id, linking, flags, version, 0, auth_key.as_deref());
                        let _ = socket.send_to(&packet, master).await;
                    }
                    for peer in registry.peers() {
                        let packet = encode_control(PEER_ALIVE_REQ, radio_id, linking, flags, version, 0, auth_key.as_deref());
                        let _ = socket.send_to(&packet, peer.address).await;
                    }
                }
                update_endpoint(&runtime, &system.name, "ipsc", if registered { "connected" } else { "registering" }, registry.peers().len()).await;
            }
        }
    }
}

async fn send_ipsc_media(
    socket: &UdpSocket,
    role: IpscRole,
    master_addr: Option<SocketAddr>,
    registry: &IpscRegistry,
    packet: &[u8],
) -> Result<()> {
    let mut targets = HashSet::new();
    for peer in registry.peers() {
        targets.insert(peer.address);
    }
    if role == IpscRole::Peer {
        if let Some(master) = master_addr {
            targets.insert(master);
        }
    }
    for target in targets {
        socket.send_to(packet, target).await?;
    }
    Ok(())
}

const MAX_IPSC_PEERS: usize = 14;

async fn update_endpoint(runtime: &Arc<RwLock<RuntimeState>>, name: &str, protocol: &str, state: &str, peers: usize) {
    runtime.write().await.endpoints.insert(name.to_string(), EndpointStatus { protocol: protocol.into(), state: state.into(), peers });
}

fn parse_id_list(value: Option<&str>) -> Vec<u32> {
    value.unwrap_or("").split(',').filter_map(|item| item.trim().parse().ok()).collect()
}

fn parse_password_map(value: Option<&str>) -> HashMap<u32, String> {
    value.and_then(|raw| serde_json::from_str::<HashMap<String, String>>(raw).ok()).unwrap_or_default().into_iter().filter_map(|(id, password)| id.parse().ok().map(|id| (id, password))).collect()
}

fn raw_string(system: &LegacySystem, key: &str) -> Option<String> { system.raw.get(key).and_then(|v| v.clone()) }
fn raw_string_ref<'a>(system: &'a LegacySystem, key: &str) -> Option<&'a str> { system.raw.get(key).and_then(|v| v.as_deref()) }
fn raw_u32(system: &LegacySystem, key: &str) -> Option<u32> { raw_string_ref(system, key).and_then(|v| v.parse().ok()) }
fn env_bool(key: &str, default: bool) -> bool { std::env::var(key).ok().map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")).unwrap_or(default) }
fn unix_now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }

const PUBLIC_DASHBOARD: &str = r#"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>DMR Master System</title><style>body{font-family:system-ui;background:#111827;color:#e5e7eb;margin:0}header{padding:20px;background:#0f172a}main{padding:20px;display:grid;gap:16px}.card{background:#1f2937;padding:16px;border-radius:10px}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #374151;text-align:left}.ok{color:#34d399}a{color:#93c5fd}</style></head><body><header><h1>DMR Master System</h1><a href='/admin'>Admin</a></header><main><div class='card'><h2>Endpoints</h2><table id='endpoints'></table></div><div class='card'><h2>Bridges</h2><div id='bridges'></div></div><div class='card'><h2>Recent Calls</h2><table id='calls'></table></div></main><script>async function refresh(){let r=await fetch('/api/public/status');let s=await r.json();document.getElementById('endpoints').innerHTML='<tr><th>Name</th><th>Protocol</th><th>State</th><th>Peers</th></tr>'+Object.entries(s.endpoints).map(([n,e])=>`<tr><td>${n}</td><td>${e.protocol}</td><td class=ok>${e.state}</td><td>${e.peers}</td></tr>`).join('');document.getElementById('bridges').innerHTML=s.bridges.map(b=>`<h3>${b.name}</h3><p>${b.members.map(m=>`${m.endpoint} TS${m.slot==='One'?1:2} TG${m.talkgroup} ${m.active?'ACTIVE':'inactive'}`).join(' · ')}</p>`).join('');document.getElementById('calls').innerHTML='<tr><th>Endpoint</th><th>Source</th><th>Destination</th><th>TS</th><th>Type</th><th>Event</th></tr>'+s.recent_calls.map(c=>`<tr><td>${c.endpoint}</td><td>${c.source}</td><td>${c.destination}</td><td>${c.timeslot}</td><td>${c.call_type}</td><td>${c.event}</td></tr>`).join('')}refresh();setInterval(refresh,2000)</script></body></html>"#;

const ADMIN_PAGE: &str = r#"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>DMR Master Admin</title><style>body{font-family:system-ui;background:#111827;color:#e5e7eb;margin:0}header{padding:20px;background:#0f172a;display:flex;justify-content:space-between}main{padding:20px;display:grid;gap:16px}.card{background:#1f2937;padding:16px;border-radius:10px}input,button,textarea,select{padding:9px;margin:4px;background:#111827;color:#fff;border:1px solid #4b5563;border-radius:5px}textarea{width:100%;min-height:150px;box-sizing:border-box}button{cursor:pointer}pre{background:#111827;padding:12px;overflow:auto;max-height:360px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}.hidden{display:none}.ok{color:#34d399}.bad{color:#f87171}a{color:#93c5fd}</style></head><body><header><div><h1>DMR Master Admin</h1><a href='/'>Public dashboard</a></div><div id=status></div></header><main><section id=login class=card><h2>Sign in</h2><input id=user placeholder=username value=admin><input id=pass type=password placeholder=password><button onclick=doLogin()>Login</button></section><section id=panel class=hidden><div class=grid><div class=card><h2>Configuration</h2><button onclick=load('/api/admin/endpoints')>Endpoints</button><button onclick=load('/api/admin/bridges')>Bridges</button><button onclick=load('/api/admin/talkgroups')>Talkgroups</button><button onclick=load('/api/admin/calls')>Calls</button><button onclick=reloadRoutes()>Reload routes</button><pre id=out>Ready.</pre></div><div class=card><h2>Endpoint</h2><textarea id=endpoint>{"name":"DEMO-HBP","enabled":true,"protocol":"homebrew","role":"server","kind":"repeater","config":{"bind_ip":"0.0.0.0","port":62031,"passphrase":"change-me","max_repeaters":100}}</textarea><button onclick=save('/api/admin/endpoints','endpoint')>Save endpoint</button></div><div class=card><h2>Talkgroup</h2><textarea id=talkgroup>{"talkgroup":1001,"name":"Demo","description":"Synthetic example","enabled":true}</textarea><button onclick=save('/api/admin/talkgroups','talkgroup')>Save talkgroup</button></div><div class=card><h2>Bridge</h2><textarea id=bridge>{"name":"DEMO-BRIDGE","enabled":true,"members":[{"endpoint":"DEMO-HBP","timeslot":1,"talkgroup":1001,"initially_active":true,"timeout_seconds":0,"timeout_policy":"none","on_talkgroups":[],"off_talkgroups":[],"reset_talkgroups":[]}]}</textarea><button onclick=save('/api/admin/bridges','bridge')>Save bridge</button></div><div class=card><h2>Delete by ID</h2><select id=kind><option value=endpoints>Endpoint UUID</option><option value=bridges>Bridge UUID</option><option value=talkgroups>Talkgroup numeric ID</option></select><input id=deleteId placeholder='ID'><button onclick=removeItem()>Delete</button><p>Transport endpoint additions/removals are persisted immediately but require a process restart to create or stop sockets. Bridge edits can be activated with Reload routes.</p></div></div></section></main><script>let token='';const q=id=>document.getElementById(id);function show(msg,ok=true){q('status').textContent=msg;q('status').className=ok?'ok':'bad'}async function doLogin(){let r=await fetch('/api/admin/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:q('user').value,password:q('pass').value})});let j=await r.json().catch(()=>({}));if(j.token){token=j.token;q('panel').classList.remove('hidden');q('login').classList.add('hidden');show('Authenticated');load('/api/admin/endpoints')}else show(j.error||'Login failed',false)}async function api(url,opt={}){opt.headers=Object.assign({'authorization':'Bearer '+token},opt.headers||{});let r=await fetch(url,opt);let t=await r.text();q('out').textContent=t;show(r.ok?'OK':`HTTP ${r.status}`,r.ok);return r}function load(url){api(url)}function save(url,id){let body=q(id).value;try{JSON.parse(body)}catch(e){show('Invalid JSON: '+e,false);return}api(url,{method:'POST',headers:{'content-type':'application/json'},body})}function reloadRoutes(){api('/api/admin/reload-routes',{method:'POST'})}function removeItem(){let id=q('deleteId').value.trim();if(!id)return show('Enter an ID',false);api('/api/admin/'+q('kind').value+'/'+encodeURIComponent(id),{method:'DELETE'})}</script></body></html>"#;
