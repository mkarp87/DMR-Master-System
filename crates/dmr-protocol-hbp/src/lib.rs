use dmr_core::{CallType, DmrFrame, FrameKind, RepeaterId, StreamId, SubscriberId, Timeslot};
use rand::random;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use thiserror::Error;

pub const DMRD_LEN: usize = 53;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HbpError {
    #[error("packet too short: {0}")]
    TooShort(usize),
    #[error("unknown packet tag")]
    UnknownTag,
    #[error("invalid DMRD packet")]
    InvalidDmrd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmrdPacket {
    pub sequence: u8,
    pub source: u32,
    pub destination: u32,
    pub repeater: u32,
    pub slot: Timeslot,
    pub call_type: CallType,
    pub frame_type: u8,
    pub data_type: u8,
    pub stream_id: u32,
    pub payload: [u8; 33],
    pub trailing: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HbpPacket {
    Dmrd(DmrdPacket),
    RepeaterLogin {
        repeater_id: u32,
    },
    RepeaterKey {
        repeater_id: u32,
        digest: Vec<u8>,
    },
    RepeaterConfig {
        repeater_id: u32,
        config: Vec<u8>,
    },
    RepeaterPing {
        repeater_id: u32,
    },
    RepeaterClose {
        repeater_id: u32,
    },
    RepeaterOptions {
        repeater_id: u32,
        options: Vec<u8>,
    },
    MasterPong {
        repeater_id: u32,
    },
    MasterAck(Vec<u8>),
    MasterNak(Vec<u8>),
    Other {
        tag: [u8; 4],
        data: Vec<u8>,
    },
}

fn be_u24(v: &[u8]) -> u32 {
    ((v[0] as u32) << 16) | ((v[1] as u32) << 8) | (v[2] as u32)
}

fn put_u24(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&[
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    ]);
}

fn be_u32(v: &[u8]) -> u32 {
    u32::from_be_bytes([v[0], v[1], v[2], v[3]])
}

impl DmrdPacket {
    pub fn parse(data: &[u8]) -> Result<Self, HbpError> {
        if data.len() < DMRD_LEN || &data[..4] != b"DMRD" {
            return Err(HbpError::InvalidDmrd);
        }

        let bits = data[15];
        let slot = if bits & 0x80 != 0 {
            Timeslot::Two
        } else {
            Timeslot::One
        };
        let call_type = if bits & 0x40 != 0 {
            CallType::Private
        } else {
            CallType::Group
        };
        let frame_type = (bits >> 4) & 0x03;
        let data_type = bits & 0x0f;
        let mut payload = [0u8; 33];
        payload.copy_from_slice(&data[20..53]);

        Ok(Self {
            sequence: data[4],
            source: be_u24(&data[5..8]),
            destination: be_u24(&data[8..11]),
            repeater: be_u32(&data[11..15]),
            slot,
            call_type,
            frame_type,
            data_type,
            stream_id: be_u32(&data[16..20]),
            payload,
            trailing: data[53..].to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DMRD_LEN + self.trailing.len());
        out.extend_from_slice(b"DMRD");
        out.push(self.sequence);
        put_u24(self.source, &mut out);
        put_u24(self.destination, &mut out);
        out.extend_from_slice(&self.repeater.to_be_bytes());

        let mut bits = (self.frame_type & 0x03) << 4 | (self.data_type & 0x0f);
        if self.slot == Timeslot::Two {
            bits |= 0x80;
        }
        if self.call_type == CallType::Private {
            bits |= 0x40;
        }

        out.push(bits);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.trailing);
        out
    }

    pub fn to_frame(&self) -> DmrFrame {
        let frame_kind = match (self.frame_type, self.data_type) {
            (2, 1) => FrameKind::VoiceHeader,
            (2, 2) => FrameKind::VoiceTerminator,
            (1, b) => FrameKind::VoiceBurst { burst: b },
            (2, _) => FrameKind::DataSync,
            _ => FrameKind::Unknown,
        };

        DmrFrame {
            source: SubscriberId(self.source),
            destination: self.destination,
            repeater: RepeaterId(self.repeater),
            timeslot: self.slot,
            call_type: self.call_type,
            stream_id: StreamId(self.stream_id),
            sequence: self.sequence,
            frame_kind,
            payload: self.payload.to_vec(),
        }
    }
}

pub fn parse_packet(data: &[u8]) -> Result<HbpPacket, HbpError> {
    if data.len() < 4 {
        return Err(HbpError::TooShort(data.len()));
    }

    if data.starts_with(b"RPTPING") {
        if data.len() < 11 {
            return Err(HbpError::TooShort(data.len()));
        }
        return Ok(HbpPacket::RepeaterPing {
            repeater_id: be_u32(&data[7..11]),
        });
    }

    if data.starts_with(b"MSTPONG") {
        if data.len() < 11 {
            return Err(HbpError::TooShort(data.len()));
        }
        return Ok(HbpPacket::MasterPong {
            repeater_id: be_u32(&data[7..11]),
        });
    }

    if data.starts_with(b"RPTCL") {
        if data.len() < 9 {
            return Err(HbpError::TooShort(data.len()));
        }
        return Ok(HbpPacket::RepeaterClose {
            repeater_id: be_u32(&data[5..9]),
        });
    }

    if data.starts_with(b"RPTACK") {
        return Ok(HbpPacket::MasterAck(data[6..].to_vec()));
    }

    if data.starts_with(b"MSTNAK") {
        return Ok(HbpPacket::MasterNak(data[6..].to_vec()));
    }

    match &data[..4] {
        b"DMRD" => Ok(HbpPacket::Dmrd(DmrdPacket::parse(data)?)),
        b"RPTL" if data.len() >= 8 => Ok(HbpPacket::RepeaterLogin {
            repeater_id: be_u32(&data[4..8]),
        }),
        b"RPTK" if data.len() >= 8 => Ok(HbpPacket::RepeaterKey {
            repeater_id: be_u32(&data[4..8]),
            digest: data[8..].to_vec(),
        }),
        b"RPTC" if data.len() >= 8 => Ok(HbpPacket::RepeaterConfig {
            repeater_id: be_u32(&data[4..8]),
            config: data[8..].to_vec(),
        }),
        b"RPTO" if data.len() >= 8 => Ok(HbpPacket::RepeaterOptions {
            repeater_id: be_u32(&data[4..8]),
            options: data[8..].to_vec(),
        }),
        tag => {
            let mut t = [0u8; 4];
            t.copy_from_slice(tag);
            Ok(HbpPacket::Other {
                tag: t,
                data: data[4..].to_vec(),
            })
        }
    }
}

pub fn encode_rptack(value: u32) -> Vec<u8> {
    let mut out = b"RPTACK".to_vec();
    out.extend_from_slice(&value.to_be_bytes());
    out
}

pub fn encode_mstnak(repeater_id: u32) -> Vec<u8> {
    let mut out = b"MSTNAK".to_vec();
    out.extend_from_slice(&repeater_id.to_be_bytes());
    out
}

pub fn encode_mstpong(repeater_id: u32) -> Vec<u8> {
    let mut out = b"MSTPONG".to_vec();
    out.extend_from_slice(&repeater_id.to_be_bytes());
    out
}

pub fn challenge_digest(challenge: u32, passphrase: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(challenge.to_be_bytes());
    hasher.update(passphrase);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    ChallengeSent,
    WaitingConfig,
    Connected,
}

#[derive(Debug, Clone)]
pub struct PeerSession {
    pub repeater_id: u32,
    pub remote: SocketAddr,
    pub state: SessionState,
    pub challenge: u32,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub config: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum MasterEvent {
    Send {
        destination: SocketAddr,
        payload: Vec<u8>,
    },
    Authenticated {
        repeater_id: u32,
        remote: SocketAddr,
    },
    Connected {
        repeater_id: u32,
        remote: SocketAddr,
    },
    Frame {
        repeater_id: u32,
        remote: SocketAddr,
        packet: DmrdPacket,
    },
    Disconnected {
        repeater_id: u32,
        remote: SocketAddr,
    },
    Rejected {
        repeater_id: u32,
        remote: SocketAddr,
        reason: &'static str,
    },
}

pub struct HbpMaster {
    passphrase: Vec<u8>,
    max_repeaters: usize,
    session_timeout: Duration,
    peers: HashMap<u32, PeerSession>,
}

impl HbpMaster {
    pub fn new(passphrase: impl Into<Vec<u8>>, max_repeaters: usize, session_timeout: Duration) -> Self {
        Self {
            passphrase: passphrase.into(),
            max_repeaters: max_repeaters.max(1),
            session_timeout,
            peers: HashMap::new(),
        }
    }

    pub fn peers(&self) -> &HashMap<u32, PeerSession> {
        &self.peers
    }

    pub fn handle_datagram(
        &mut self,
        remote: SocketAddr,
        data: &[u8],
        now: Instant,
    ) -> Result<Vec<MasterEvent>, HbpError> {
        let packet = parse_packet(data)?;
        Ok(self.handle_packet(remote, packet, now))
    }

    pub fn handle_packet(
        &mut self,
        remote: SocketAddr,
        packet: HbpPacket,
        now: Instant,
    ) -> Vec<MasterEvent> {
        match packet {
            HbpPacket::RepeaterLogin { repeater_id } => {
                if !self.peers.contains_key(&repeater_id) && self.peers.len() >= self.max_repeaters {
                    return vec![
                        MasterEvent::Send {
                            destination: remote,
                            payload: encode_mstnak(repeater_id),
                        },
                        MasterEvent::Rejected {
                            repeater_id,
                            remote,
                            reason: "maximum repeaters reached",
                        },
                    ];
                }

                let challenge = random::<u32>();
                self.peers.insert(
                    repeater_id,
                    PeerSession {
                        repeater_id,
                        remote,
                        state: SessionState::ChallengeSent,
                        challenge,
                        connected_at: now,
                        last_seen: now,
                        config: Vec::new(),
                    },
                );

                vec![MasterEvent::Send {
                    destination: remote,
                    payload: encode_rptack(challenge),
                }]
            }
            HbpPacket::RepeaterKey {
                repeater_id,
                digest,
            } => {
                let Some(session) = self.peers.get_mut(&repeater_id) else {
                    return self.reject(remote, repeater_id, "authentication without login");
                };

                if session.remote != remote || session.state != SessionState::ChallengeSent {
                    return self.reject(remote, repeater_id, "invalid authentication state");
                }

                let expected = challenge_digest(session.challenge, &self.passphrase);
                if digest.as_slice() != expected.as_slice() {
                    self.peers.remove(&repeater_id);
                    return self.reject(remote, repeater_id, "invalid passphrase digest");
                }

                session.state = SessionState::WaitingConfig;
                session.last_seen = now;

                vec![
                    MasterEvent::Send {
                        destination: remote,
                        payload: encode_rptack(repeater_id),
                    },
                    MasterEvent::Authenticated {
                        repeater_id,
                        remote,
                    },
                ]
            }
            HbpPacket::RepeaterConfig {
                repeater_id,
                config,
            } => {
                let Some(session) = self.peers.get_mut(&repeater_id) else {
                    return self.reject(remote, repeater_id, "configuration without login");
                };

                if session.remote != remote || session.state != SessionState::WaitingConfig {
                    return self.reject(remote, repeater_id, "invalid configuration state");
                }

                session.state = SessionState::Connected;
                session.connected_at = now;
                session.last_seen = now;
                session.config = config;

                vec![
                    MasterEvent::Send {
                        destination: remote,
                        payload: encode_rptack(repeater_id),
                    },
                    MasterEvent::Connected {
                        repeater_id,
                        remote,
                    },
                ]
            }
            HbpPacket::RepeaterPing { repeater_id } => {
                let Some(session) = self.peers.get_mut(&repeater_id) else {
                    return self.reject(remote, repeater_id, "ping from unauthenticated repeater");
                };

                if session.remote != remote || session.state != SessionState::Connected {
                    return self.reject(remote, repeater_id, "ping from invalid session");
                }

                session.last_seen = now;
                vec![MasterEvent::Send {
                    destination: remote,
                    payload: encode_mstpong(repeater_id),
                }]
            }
            HbpPacket::RepeaterOptions { repeater_id, .. } => {
                let Some(session) = self.peers.get_mut(&repeater_id) else {
                    return self.reject(remote, repeater_id, "options from unauthenticated repeater");
                };

                if session.remote != remote || session.state != SessionState::Connected {
                    return self.reject(remote, repeater_id, "options from invalid session");
                }

                session.last_seen = now;
                vec![MasterEvent::Send {
                    destination: remote,
                    payload: encode_rptack(repeater_id),
                }]
            }
            HbpPacket::RepeaterClose { repeater_id } => {
                let valid = self
                    .peers
                    .get(&repeater_id)
                    .is_some_and(|session| session.remote == remote);

                if !valid {
                    return self.reject(remote, repeater_id, "close from invalid session");
                }

                self.peers.remove(&repeater_id);
                vec![
                    MasterEvent::Send {
                        destination: remote,
                        payload: encode_mstnak(repeater_id),
                    },
                    MasterEvent::Disconnected {
                        repeater_id,
                        remote,
                    },
                ]
            }
            HbpPacket::Dmrd(packet) => {
                let repeater_id = packet.repeater;
                let Some(session) = self.peers.get_mut(&repeater_id) else {
                    return self.reject(remote, repeater_id, "DMRD from unauthenticated repeater");
                };

                if session.remote != remote || session.state != SessionState::Connected {
                    return self.reject(remote, repeater_id, "DMRD from invalid session");
                }

                session.last_seen = now;
                vec![MasterEvent::Frame {
                    repeater_id,
                    remote,
                    packet,
                }]
            }
            _ => Vec::new(),
        }
    }

    pub fn expire_sessions(&mut self, now: Instant) -> Vec<MasterEvent> {
        let expired: Vec<(u32, SocketAddr)> = self
            .peers
            .iter()
            .filter(|(_, session)| now.duration_since(session.last_seen) >= self.session_timeout)
            .map(|(&id, session)| (id, session.remote))
            .collect();

        for (id, _) in &expired {
            self.peers.remove(id);
        }

        expired
            .into_iter()
            .map(|(repeater_id, remote)| MasterEvent::Disconnected {
                repeater_id,
                remote,
            })
            .collect()
    }

    fn reject(&self, remote: SocketAddr, repeater_id: u32, reason: &'static str) -> Vec<MasterEvent> {
        vec![
            MasterEvent::Send {
                destination: remote,
                payload: encode_mstnak(repeater_id),
            },
            MasterEvent::Rejected {
                repeater_id,
                remote,
                reason,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn dmrd_round_trip() {
        let p = DmrdPacket {
            sequence: 7,
            source: 1_000_001,
            destination: 1001,
            repeater: 1_000_002,
            slot: Timeslot::Two,
            call_type: CallType::Group,
            frame_type: 1,
            data_type: 3,
            stream_id: 0x1234_5678,
            payload: [0x55; 33],
            trailing: vec![],
        };
        let b = p.encode();
        assert_eq!(b.len(), 53);
        assert_eq!(DmrdPacket::parse(&b).unwrap(), p);
    }

    #[test]
    fn parse_login() {
        let mut b = b"RPTL".to_vec();
        b.extend_from_slice(&1234u32.to_be_bytes());
        assert_eq!(
            parse_packet(&b).unwrap(),
            HbpPacket::RepeaterLogin { repeater_id: 1234 }
        );
    }

    #[test]
    fn parse_real_ping_and_pong_tags() {
        let mut ping = b"RPTPING".to_vec();
        ping.extend_from_slice(&1234u32.to_be_bytes());
        assert_eq!(
            parse_packet(&ping).unwrap(),
            HbpPacket::RepeaterPing { repeater_id: 1234 }
        );

        let mut pong = b"MSTPONG".to_vec();
        pong.extend_from_slice(&1234u32.to_be_bytes());
        assert_eq!(
            parse_packet(&pong).unwrap(),
            HbpPacket::MasterPong { repeater_id: 1234 }
        );
    }

    #[test]
    fn challenge_digest_matches_sha256_salt_plus_password() {
        let digest = challenge_digest(0x0102_0304, b"secret");
        let mut direct = Sha256::new();
        direct.update([1, 2, 3, 4]);
        direct.update(b"secret");
        assert_eq!(digest.as_slice(), direct.finalize().as_slice());
    }

    #[test]
    fn master_login_auth_config_ping_and_dmrd_flow() {
        let now = Instant::now();
        let remote = addr(50000);
        let repeater_id = 1_234_567;
        let mut master = HbpMaster::new(b"secret".to_vec(), 10, Duration::from_secs(60));

        let login_events = master.handle_packet(
            remote,
            HbpPacket::RepeaterLogin { repeater_id },
            now,
        );
        assert_eq!(login_events.len(), 1);
        let challenge = master.peers()[&repeater_id].challenge;
        assert_eq!(master.peers()[&repeater_id].state, SessionState::ChallengeSent);

        let auth_events = master.handle_packet(
            remote,
            HbpPacket::RepeaterKey {
                repeater_id,
                digest: challenge_digest(challenge, b"secret").to_vec(),
            },
            now + Duration::from_secs(1),
        );
        assert!(auth_events
            .iter()
            .any(|e| matches!(e, MasterEvent::Authenticated { .. })));
        assert_eq!(master.peers()[&repeater_id].state, SessionState::WaitingConfig);

        let config_events = master.handle_packet(
            remote,
            HbpPacket::RepeaterConfig {
                repeater_id,
                config: b"demo-config".to_vec(),
            },
            now + Duration::from_secs(2),
        );
        assert!(config_events
            .iter()
            .any(|e| matches!(e, MasterEvent::Connected { .. })));
        assert_eq!(master.peers()[&repeater_id].state, SessionState::Connected);

        let ping_events = master.handle_packet(
            remote,
            HbpPacket::RepeaterPing { repeater_id },
            now + Duration::from_secs(3),
        );
        assert!(ping_events.iter().any(|e| matches!(
            e,
            MasterEvent::Send { payload, .. } if payload.starts_with(b"MSTPONG")
        )));

        let dmrd = DmrdPacket {
            sequence: 1,
            source: 1001,
            destination: 2001,
            repeater: repeater_id,
            slot: Timeslot::One,
            call_type: CallType::Group,
            frame_type: 1,
            data_type: 0,
            stream_id: 99,
            payload: [0; 33],
            trailing: vec![],
        };
        let frame_events = master.handle_packet(
            remote,
            HbpPacket::Dmrd(dmrd),
            now + Duration::from_secs(4),
        );
        assert!(frame_events
            .iter()
            .any(|e| matches!(e, MasterEvent::Frame { .. })));
    }

    #[test]
    fn bad_digest_is_rejected_and_session_removed() {
        let now = Instant::now();
        let remote = addr(50001);
        let repeater_id = 2_345_678;
        let mut master = HbpMaster::new(b"secret".to_vec(), 10, Duration::from_secs(60));
        master.handle_packet(
            remote,
            HbpPacket::RepeaterLogin { repeater_id },
            now,
        );

        let events = master.handle_packet(
            remote,
            HbpPacket::RepeaterKey {
                repeater_id,
                digest: vec![0; 32],
            },
            now + Duration::from_secs(1),
        );

        assert!(events
            .iter()
            .any(|e| matches!(e, MasterEvent::Rejected { .. })));
        assert!(!master.peers().contains_key(&repeater_id));
    }

    #[test]
    fn unauthenticated_dmrd_is_rejected() {
        let now = Instant::now();
        let remote = addr(50002);
        let repeater_id = 3_456_789;
        let mut master = HbpMaster::new(b"secret".to_vec(), 10, Duration::from_secs(60));
        let packet = DmrdPacket {
            sequence: 1,
            source: 1001,
            destination: 2001,
            repeater: repeater_id,
            slot: Timeslot::One,
            call_type: CallType::Group,
            frame_type: 1,
            data_type: 0,
            stream_id: 99,
            payload: [0; 33],
            trailing: vec![],
        };

        let events = master.handle_packet(remote, HbpPacket::Dmrd(packet), now);
        assert!(events
            .iter()
            .any(|e| matches!(e, MasterEvent::Rejected { .. })));
    }

    #[test]
    fn sessions_expire() {
        let now = Instant::now();
        let remote = addr(50003);
        let repeater_id = 4_567_890;
        let mut master = HbpMaster::new(b"secret".to_vec(), 10, Duration::from_secs(10));
        master.handle_packet(
            remote,
            HbpPacket::RepeaterLogin { repeater_id },
            now,
        );

        let events = master.expire_sessions(now + Duration::from_secs(11));
        assert_eq!(events.len(), 1);
        assert!(!master.peers().contains_key(&repeater_id));
    }
}
