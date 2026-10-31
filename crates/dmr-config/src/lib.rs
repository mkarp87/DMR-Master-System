use configparser::ini::Ini;
use dmr_core::{EndpointKind, EndpointProtocol, EndpointRole};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to load config: {0}")]
    Load(String),
    #[error("system {system}: unsupported MODE {mode}")]
    UnsupportedMode { system: String, mode: String },
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
    pub raw: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedConfig {
    pub systems: Vec<LegacySystem>,
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
            raw: props,
        });
    }
    Ok(ImportedConfig { systems })
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
    }
}
