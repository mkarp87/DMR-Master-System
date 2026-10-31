//! OpenBridge shares the DMRD media envelope with HBP. This crate deliberately
//! wraps the common codec while OpenBridge-specific keepalive/authentication and
//! network policy are implemented independently.
pub use dmr_protocol_hbp::{DmrdPacket, HbpError};

pub fn parse_dmrd(data: &[u8]) -> Result<DmrdPacket, HbpError> {
    DmrdPacket::parse(data)
}
pub fn encode_dmrd(packet: &DmrdPacket) -> Vec<u8> {
    packet.encode()
}
