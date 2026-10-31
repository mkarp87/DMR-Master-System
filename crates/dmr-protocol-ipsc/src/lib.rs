use dmr_core::IpscRole;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const MAX_MASTER_PEERS: usize = 14;
pub const DMR_BURST_PERIOD: Duration = Duration::from_millis(60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpscConfig {
    pub role: IpscRole,
    pub radio_id: u32,
    pub local_port: u16,
    pub master: Option<String>,
    pub jitter_buffer_depth: u8,
}
impl IpscConfig {
    pub fn jitter_delay(&self) -> Duration {
        DMR_BURST_PERIOD * self.jitter_buffer_depth as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpscState {
    Stopped,
    Discovering,
    Registering,
    Connected,
    Degraded,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jitter_is_60ms_units() {
        let c = IpscConfig {
            role: IpscRole::Peer,
            radio_id: 1,
            local_port: 50000,
            master: Some("127.0.0.1:50000".into()),
            jitter_buffer_depth: 2,
        };
        assert_eq!(c.jitter_delay(), Duration::from_millis(120));
    }
}
