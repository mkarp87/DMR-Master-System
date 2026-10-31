//! OpenBridge authenticated DMRD transport.
//!
//! OpenBridge carries the same 53-byte DMRD media envelope used by Homebrew,
//! followed by a 20-byte HMAC-SHA1 authentication tag.

use dmr_protocol_hbp::{DmrdPacket, HbpError, DMRD_LEN};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

pub const OPENBRIDGE_HMAC_LEN: usize = 20;
pub const OPENBRIDGE_DMRD_LEN: usize = DMRD_LEN + OPENBRIDGE_HMAC_LEN;

#[derive(Debug, Error)]
pub enum OpenBridgeError {
    #[error("invalid OpenBridge packet length: {0}")]
    InvalidLength(usize),
    #[error("invalid OpenBridge HMAC")]
    InvalidHmac,
    #[error("unexpected OpenBridge network id: expected {expected}, got {actual}")]
    UnexpectedNetworkId { expected: u32, actual: u32 },
    #[error("OpenBridge packet is on timeslot 2 while BOTH_SLOTS is disabled")]
    InvalidTimeslot,
    #[error(transparent)]
    Hbp(#[from] HbpError),
}

#[derive(Debug, Clone)]
pub struct OpenBridgeCodec {
    passphrase: Vec<u8>,
    local_network_id: u32,
    expected_remote_network_id: Option<u32>,
    both_slots: bool,
}

impl OpenBridgeCodec {
    pub fn new(
        passphrase: impl Into<Vec<u8>>,
        local_network_id: u32,
        expected_remote_network_id: Option<u32>,
        both_slots: bool,
    ) -> Self {
        Self {
            passphrase: passphrase.into(),
            local_network_id,
            expected_remote_network_id,
            both_slots,
        }
    }

    pub fn decode(&self, data: &[u8]) -> Result<DmrdPacket, OpenBridgeError> {
        if data.len() != OPENBRIDGE_DMRD_LEN {
            return Err(OpenBridgeError::InvalidLength(data.len()));
        }

        let (dmrd, tag) = data.split_at(DMRD_LEN);
        let mut mac = HmacSha1::new_from_slice(&self.passphrase)
            .expect("HMAC accepts passphrases of any length");
        mac.update(dmrd);
        mac.verify_slice(tag)
            .map_err(|_| OpenBridgeError::InvalidHmac)?;

        let packet = DmrdPacket::parse(dmrd)?;
        if let Some(expected) = self.expected_remote_network_id {
            if packet.repeater != expected {
                return Err(OpenBridgeError::UnexpectedNetworkId {
                    expected,
                    actual: packet.repeater,
                });
            }
        }

        if !self.both_slots && packet.slot == dmr_core::Timeslot::Two {
            return Err(OpenBridgeError::InvalidTimeslot);
        }

        Ok(packet)
    }

    pub fn encode(&self, packet: &DmrdPacket) -> Vec<u8> {
        let mut packet = packet.clone();
        packet.repeater = self.local_network_id;
        if !self.both_slots {
            packet.slot = dmr_core::Timeslot::One;
        }

        let mut out = packet.encode();
        out.truncate(DMRD_LEN);

        let mut mac = HmacSha1::new_from_slice(&self.passphrase)
            .expect("HMAC accepts passphrases of any length");
        mac.update(&out);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmr_core::{CallType, Timeslot};

    fn packet() -> DmrdPacket {
        DmrdPacket {
            sequence: 7,
            source: 1_000_001,
            destination: 1001,
            repeater: 1234,
            slot: Timeslot::One,
            call_type: CallType::Group,
            frame_type: 1,
            data_type: 3,
            stream_id: 0x1234_5678,
            payload: [0x55; 33],
            trailing: vec![],
        }
    }

    #[test]
    fn authenticated_round_trip() {
        let tx = OpenBridgeCodec::new(b"secret", 4321, None, false);
        let rx = OpenBridgeCodec::new(b"secret", 9999, Some(4321), false);
        let encoded = tx.encode(&packet());
        assert_eq!(encoded.len(), OPENBRIDGE_DMRD_LEN);
        let decoded = rx.decode(&encoded).unwrap();
        assert_eq!(decoded.repeater, 4321);
        assert_eq!(decoded.destination, 1001);
    }

    #[test]
    fn rejects_wrong_password() {
        let tx = OpenBridgeCodec::new(b"secret", 4321, None, false);
        let rx = OpenBridgeCodec::new(b"wrong", 9999, Some(4321), false);
        assert!(matches!(
            rx.decode(&tx.encode(&packet())),
            Err(OpenBridgeError::InvalidHmac)
        ));
    }

    #[test]
    fn forces_slot_one_when_both_slots_is_disabled() {
        let mut p = packet();
        p.slot = Timeslot::Two;
        let tx = OpenBridgeCodec::new(b"secret", 4321, None, false);
        let rx = OpenBridgeCodec::new(b"secret", 9999, Some(4321), false);
        let decoded = rx.decode(&tx.encode(&p)).unwrap();
        assert_eq!(decoded.slot, Timeslot::One);
    }
}
