use anyhow::Result;
use axum::{extract::State,response::IntoResponse,routing::get,Json,Router};
use dmr_config::import_hblink_cfg;
use serde::Serialize;
use std::{path::PathBuf,sync::Arc};
use tokio::net::UdpSocket;
use tracing::{info,warn};

#[derive(Clone)] struct AppState{version:&'static str,systems:usize}
#[derive(Serialize)] struct Health{status:&'static str,version:&'static str,imported_systems:usize}

async fn health(State(s):State<Arc<AppState>>)->impl IntoResponse{Json(Health{status:"ok",version:s.version,imported_systems:s.systems})}

#[tokio::main]
async fn main()->Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("dmr_master=info".parse()?)).init();
    let cfg=std::env::var("DMR_HBLINK_CONFIG").unwrap_or_else(|_|"fixtures/hblink.cfg".into());
    let imported=import_hblink_cfg(PathBuf::from(cfg))?;
    info!(systems=imported.systems.len(),"legacy HBlink configuration imported");
    for s in imported.systems.iter().filter(|s|s.enabled && matches!(s.mode.to_ascii_uppercase().as_str(),"MASTER"|"SERVER")) {
        if let (Some(ip),Some(port))=(s.bind_ip.clone(),s.port){
            let name=s.name.clone(); tokio::spawn(async move{ if let Err(e)=run_hbp_listener(name,format!("{}:{}",ip,port)).await{warn!(error=%e,"HBP listener stopped");} });
        }
    }
    let state=Arc::new(AppState{version:env!("CARGO_PKG_VERSION"),systems:imported.systems.len()});
    let app=Router::new().route("/api/public/health",get(health)).with_state(state);
    let addr="0.0.0.0:8080"; info!(%addr,"HTTP status API listening");
    let listener=tokio::net::TcpListener::bind(addr).await?; axum::serve(listener,app).await?; Ok(())
}

async fn run_hbp_listener(name:String,addr:String)->Result<()> {
    let socket=UdpSocket::bind(&addr).await?; info!(system=%name,%addr,"HBP server listening");
    let mut buf=[0u8;2048]; loop{let (n,peer)=socket.recv_from(&mut buf).await?; match dmr_protocol_hbp::parse_packet(&buf[..n]){Ok(packet)=>info!(system=%name,%peer,?packet,"HBP packet"),Err(e)=>warn!(system=%name,%peer,error=%e,bytes=n,"invalid HBP packet")}}
}
