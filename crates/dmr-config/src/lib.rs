use configparser::ini::Ini;
use dmr_core::{
    Bridge, BridgeMember, EndpointKind, EndpointProtocol, EndpointRole, IpscRole, TalkgroupId,
    TimeoutPolicy, Timeslot,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to load config: {0}")]
    Load(String),
    #[error("failed to parse imported network JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("system {system}: unsupported MODE {mode}")]
    UnsupportedMode { system: String, mode: String },
    #[error("bridge {bridge}: invalid timeslot {timeslot}")]
    InvalidTimeslot { bridge: String, timeslot: u8 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacySystem {
    pub name: String,
    pub mode: String,
    pub enabled: bool,
    pub bind_ip: Option<String>,
    pub port: Option<u16>,
    pub target_ip: Option<String>,
    pub target_port: Option<u16>,
    pub passphrase: Option<String>,
    pub max_repeaters: Option<u32>,
    pub group_hangtime: Option<u32>,
    pub network_id: Option<u32>,
    pub both_slots: bool,
    pub raw: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedConfig {
    pub server_id: Option<u32>,
    pub systems: Vec<LegacySystem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportedNetwork {
    #[serde(default)]
    pub bridges: Vec<ImportedBridge>,
    #[serde(default)]
    pub unit_systems: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ImportedTopology {
    pub bridges: Vec<Bridge>,
    pub unit_systems: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportedBridge {
    pub name: String,
    pub members: Vec<ImportedBridgeMember>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImportedBridgeMember {
    pub system: String,
    pub timeslot: u8,
    pub talkgroup: u32,
    pub active: bool,
    #[serde(default)]
    pub timeout_minutes: u64,
    #[serde(default)]
    pub timeout_type: String,
    #[serde(default)]
    pub on: Vec<u32>,
    #[serde(default)]
    pub off: Vec<u32>,
    #[serde(default)]
    pub reset: Vec<u32>,
}

fn parse_bool(v: Option<&str>, default: bool) -> bool {
    v.map(|x| {
        matches!(
            x.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "1" | "on"
        )
    })
    .unwrap_or(default)
}

fn parse_u16(v: Option<&str>) -> Option<u16> {
    v.and_then(|x| x.trim().parse().ok())
}

fn parse_u32(v: Option<&str>) -> Option<u32> {
    v.and_then(|x| x.trim().parse().ok())
}

pub fn normalize_mode(
    system: &str,
    mode: &str,
) -> Result<(EndpointProtocol, EndpointRole, EndpointKind), ConfigError> {
    match mode.trim().to_ascii_uppercase().as_str() {
        "MASTER" | "SERVER" => Ok((
            EndpointProtocol::Homebrew,
            EndpointRole::HomebrewServer,
            EndpointKind::Repeater,
        )),
        "PEER" | "CLIENT" | "OUTBOUND" => Ok((
            EndpointProtocol::Homebrew,
            EndpointRole::HomebrewOutbound,
            EndpointKind::Peer,
        )),
        "OPENBRIDGE" => Ok((
            EndpointProtocol::OpenBridge,
            EndpointRole::OpenBridge,
            EndpointKind::Peer,
        )),
        "IPSC" => Ok((
            EndpointProtocol::Ipsc,
            EndpointRole::Ipsc(IpscRole::Peer),
            EndpointKind::Peer,
        )),
        other => Err(ConfigError::UnsupportedMode {
            system: system.into(),
            mode: other.into(),
        }),
    }
}

pub fn import_hblink_cfg(path: impl AsRef<Path>) -> Result<ImportedConfig, ConfigError> {
    let mut ini = Ini::new();
    let path = path.as_ref().to_string_lossy().to_string();
    let map = ini.load(&path).map_err(ConfigError::Load)?;

    let server_id = map
        .get("global")
        .and_then(|props| props.get("server_id"))
        .and_then(|v| v.as_deref())
        .and_then(|v| v.trim().parse::<u32>().ok());

    let skip = ["global", "reports", "logger", "aliases"];
    let mut systems = Vec::new();

    for (section, props) in map {
        if skip.contains(&section.to_ascii_lowercase().as_str()) {
            continue;
        }

        let get = |k: &str| {
            props
                .get(&k.to_ascii_lowercase())
                .and_then(|v| v.as_deref())
        };
        let mode = get("mode").unwrap_or("").to_string();
        if mode.is_empty() {
            continue;
        }
        normalize_mode(&section, &mode)?;

        systems.push(LegacySystem {
            name: section,
            mode,
            enabled: parse_bool(get("enabled"), true),
            bind_ip: get("ip").map(str::to_string),
            port: parse_u16(get("port")),
            target_ip: get("target_ip")
                .or_else(|| get("master_ip"))
                .or_else(|| get("server_ip"))
                .map(str::to_string),
            target_port: parse_u16(
                get("target_port")
                    .or_else(|| get("master_port"))
                    .or_else(|| get("server_port")),
            ),
            passphrase: get("passphrase").map(str::to_string),
            max_repeaters: parse_u32(get("max_repeaters").or_else(|| get("max_peers"))),
            group_hangtime: parse_u32(get("group_hangtime")),
            network_id: parse_u32(get("network_id")),
            both_slots: parse_bool(get("both_slots"), false),
            raw: props,
        });
    }

    Ok(ImportedConfig { server_id, systems })
}

pub fn import_network_topology(path: impl AsRef<Path>) -> Result<ImportedTopology, ConfigError> {
    let data = fs::read_to_string(path).map_err(|e| ConfigError::Load(e.to_string()))?;
    let imported: ImportedNetwork = serde_json::from_str(&data)?;
    let mut bridges = Vec::with_capacity(imported.bridges.len());

    for bridge in imported.bridges {
        let mut members = Vec::with_capacity(bridge.members.len());
        for member in bridge.members {
            let Some(timeslot) = Timeslot::from_u8(member.timeslot) else {
                return Err(ConfigError::InvalidTimeslot {
                    bridge: bridge.name.clone(),
                    timeslot: member.timeslot,
                });
            };

            let timeout_policy = match member.timeout_type.to_ascii_uppercase().as_str() {
                "ON" => TimeoutPolicy::On,
                "OFF" => TimeoutPolicy::Off,
                _ => TimeoutPolicy::None,
            };

            members.push(BridgeMember {
                endpoint: member.system,
                timeslot,
                talkgroup: TalkgroupId(member.talkgroup),
                initially_active: member.active,
                timeout_secs: member.timeout_minutes.saturating_mul(60),
                timeout_policy,
                on: member.on.into_iter().map(TalkgroupId).collect(),
                off: member.off.into_iter().map(TalkgroupId).collect(),
                reset: member.reset.into_iter().map(TalkgroupId).collect(),
            });
        }

        bridges.push(Bridge {
            name: bridge.name,
            members,
        });
    }

    Ok(ImportedTopology {
        bridges,
        unit_systems: imported.unit_systems,
    })
}

pub fn import_network_json(path: impl AsRef<Path>) -> Result<Vec<Bridge>, ConfigError> {
    Ok(import_network_topology(path)?.bridges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_old_and_new_names() {
        assert!(normalize_mode("x", "MASTER").is_ok());
        assert!(normalize_mode("x", "SERVER").is_ok());
        assert!(normalize_mode("x", "PEER").is_ok());
        assert!(normalize_mode("x", "OUTBOUND").is_ok());
        assert!(normalize_mode("x", "OPENBRIDGE").is_ok());
        assert!(normalize_mode("x", "IPSC").is_ok());
    }

    #[test]
    fn imports_bridge_json() {
        let json = r#"{
          "bridges": [{
            "name": "demo",
            "members": [
              {"system":"A","timeslot":1,"talkgroup":1001,"active":true,"timeout_minutes":0,"timeout_type":"NONE","on":[],"off":[],"reset":[]},
              {"system":"B","timeslot":2,"talkgroup":2001,"active":true,"timeout_minutes":0,"timeout_type":"NONE","on":[],"off":[],"reset":[]}
            ]
          }]
        }"#;
        let path =
            std::env::temp_dir().join(format!("dmr-master-test-{}.json", std::process::id()));
        fs::write(&path, json).unwrap();
        let bridges = import_network_json(&path).unwrap();
        fs::remove_file(path).ok();
        assert_eq!(bridges.len(), 1);
        assert_eq!(bridges[0].members[1].talkgroup, TalkgroupId(2001));
        assert_eq!(bridges[0].members[1].timeslot, Timeslot::Two);
    }
}
