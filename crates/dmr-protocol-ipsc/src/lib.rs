//! Motorola MOTOTRBO IPSC protocol primitives.
//!
//! IPSC is proprietary and this implementation follows the wire behavior
//! documented by DMRlink/DMRlink3. Control-plane registration, peer lists,
//! keepalives, authentication trailers, and user-packet metadata are supported.
//! The raw user payload is intentionally preserved so live captures can validate
//! the final media-normalization mapping before production use.

use dmr_core::{CallType, IpscRole, Timeslot};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

pub const MAX_MASTER_PEERS: usize = 14;
pub const DMR_BURST_PERIOD: Duration = Duration::from_millis(60);
pub const IPSC_AUTH_LEN: usize = 10;

pub const GROUP_VOICE: u8 = 0x80;
pub const PRIVATE_VOICE: u8 = 0x81;
pub const GROUP_DATA: u8 = 0x83;
pub const PRIVATE_DATA: u8 = 0x84;
pub const MASTER_REG_REQ: u8 = 0x90;
pub const MASTER_REG_REPLY: u8 = 0x91;
pub const PEER_LIST_REQ: u8 = 0x92;
pub const PEER_LIST_REPLY: u8 = 0x93;
pub const PEER_REG_REQ: u8 = 0x94;
pub const PEER_REG_REPLY: u8 = 0x95;
pub const MASTER_ALIVE_REQ: u8 = 0x96;
pub const MASTER_ALIVE_REPLY: u8 = 0x97;
pub const PEER_ALIVE_REQ: u8 = 0x98;
pub const PEER_ALIVE_REPLY: u8 = 0x99;
pub const DE_REG_REQ: u8 = 0x9a;
pub const DE_REG_REPLY: u8 = 0x9b;

const END_MASK: u8 = 0x40;
const TS_CALL_MASK: u8 = 0x20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpscConfig {
    pub role: IpscRole,
    pub radio_id: u32,
    pub local_ip: Option<String>,
    pub local_port: u16,
    pub master: Option<String>,
    pub jitter_buffer_depth: u8,
    pub alive_interval_secs: u64,
    pub auth_key: Option<String>,
}

impl IpscConfig {
    pub fn jitter_delay(&self) -> Duration {
        DMR_BURST_PERIOD * self.jitter_buffer_depth as u32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpscState {
    Stopped,
    Discovering,
    Registering,
    Connected,
    Degraded,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpscError {
    #[error("IPSC packet too short: {0}")]
    TooShort(usize),
    #[error("invalid IPSC authentication trailer")]
    InvalidAuth,
    #[error("malformed IPSC peer list")]
    InvalidPeerList,
    #[error("unsupported IPSC packet type 0x{0:02x}")]
    Unsupported(u8),
    #[error("IPSC media translation failed: {0}")]
    Media(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    pub opcode: u8,
    pub peer_id: u32,
    pub linking: Option<u8>,
    pub flags: Option<[u8; 4]>,
    pub version: Option<[u8; 4]>,
    pub peer_count: Option<u16>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: u32,
    pub address: SocketAddr,
    pub linking: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPacket {
    pub opcode: u8,
    pub peer_id: u32,
    pub sequence: u8,
    pub source: u32,
    pub destination: u32,
    pub call_type: CallType,
    pub timeslot: Timeslot,
    pub end: bool,
    pub burst_type: u8,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpscPacket {
    Control(ControlPacket),
    PeerList { peer_id: u32, peers: Vec<PeerInfo> },
    User(UserPacket),
}

fn read_u24(data: &[u8]) -> u32 {
    ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | data[2] as u32
}

fn write_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn append_auth(packet: &mut Vec<u8>, key: &[u8]) {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(packet);
    let digest = mac.finalize().into_bytes();
    packet.extend_from_slice(&digest[..IPSC_AUTH_LEN]);
}

pub fn verify_and_strip_auth(data: &[u8], key: Option<&[u8]>) -> Result<Vec<u8>, IpscError> {
    let Some(key) = key else { return Ok(data.to_vec()); };
    if data.len() < IPSC_AUTH_LEN + 5 {
        return Err(IpscError::TooShort(data.len()));
    }
    let split = data.len() - IPSC_AUTH_LEN;
    let (body, tag) = data.split_at(split);
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(body);
    let digest = mac.finalize().into_bytes();
    if &digest[..IPSC_AUTH_LEN] != tag {
        return Err(IpscError::InvalidAuth);
    }
    Ok(body.to_vec())
}

pub fn parse_packet(data: &[u8], auth_key: Option<&[u8]>) -> Result<IpscPacket, IpscError> {
    let data = verify_and_strip_auth(data, auth_key)?;
    if data.len() < 5 {
        return Err(IpscError::TooShort(data.len()));
    }
    let opcode = data[0];
    let peer_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

    if matches!(opcode, GROUP_VOICE | PRIVATE_VOICE | GROUP_DATA | PRIVATE_DATA) {
        if data.len() < 31 {
            return Err(IpscError::TooShort(data.len()));
        }
        let source = read_u24(&data[6..9]);
        let destination = read_u24(&data[9..12]);
        let call_info = data[17];
        let burst_type = data[30];
        let timeslot = if opcode == GROUP_VOICE && burst_type != 0x01 && burst_type != 0x02 {
            if burst_type & 0x80 != 0 { Timeslot::Two } else { Timeslot::One }
        } else if call_info & TS_CALL_MASK != 0 {
            Timeslot::Two
        } else {
            Timeslot::One
        };
        return Ok(IpscPacket::User(UserPacket {
            opcode,
            peer_id,
            sequence: data[5],
            source,
            destination,
            call_type: if matches!(opcode, PRIVATE_VOICE | PRIVATE_DATA) { CallType::Private } else { CallType::Group },
            timeslot,
            end: call_info & END_MASK != 0,
            burst_type,
            raw: data,
        }));
    }

    if opcode == PEER_LIST_REPLY {
        if data.len() < 7 {
            return Err(IpscError::TooShort(data.len()));
        }
        let byte_len = u16::from_be_bytes([data[5], data[6]]) as usize;
        if data.len() < 7 + byte_len || byte_len % 11 != 0 {
            return Err(IpscError::InvalidPeerList);
        }
        let mut peers = Vec::new();
        for entry in data[7..7 + byte_len].chunks_exact(11) {
            let id = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let ip = Ipv4Addr::new(entry[4], entry[5], entry[6], entry[7]);
            let port = u16::from_be_bytes([entry[8], entry[9]]);
            peers.push(PeerInfo { peer_id: id, address: SocketAddr::new(IpAddr::V4(ip), port), linking: entry[10] });
        }
        return Ok(IpscPacket::PeerList { peer_id, peers });
    }

    let (linking, flags, version, peer_count) = match opcode {
        MASTER_REG_REQ | MASTER_ALIVE_REQ | MASTER_ALIVE_REPLY => {
            if data.len() < 14 { return Err(IpscError::TooShort(data.len())); }
            (Some(data[5]), Some([data[6], data[7], data[8], data[9]]), Some([data[10], data[11], data[12], data[13]]), None)
        }
        MASTER_REG_REPLY => {
            if data.len() < 16 { return Err(IpscError::TooShort(data.len())); }
            (Some(data[5]), Some([data[6], data[7], data[8], data[9]]), Some([data[12], data[13], data[14], data[15]]), Some(u16::from_be_bytes([data[10], data[11]])))
        }
        PEER_REG_REQ | PEER_REG_REPLY => {
            if data.len() < 9 { return Err(IpscError::TooShort(data.len())); }
            (None, None, Some([data[5], data[6], data[7], data[8]]), None)
        }
        PEER_ALIVE_REQ | PEER_ALIVE_REPLY => {
            if data.len() < 10 { return Err(IpscError::TooShort(data.len())); }
            (Some(data[5]), Some([data[6], data[7], data[8], data[9]]), None, None)
        }
        PEER_LIST_REQ | DE_REG_REQ | DE_REG_REPLY => (None, None, None, None),
        other => return Err(IpscError::Unsupported(other)),
    };

    Ok(IpscPacket::Control(ControlPacket {
        opcode,
        peer_id,
        linking,
        flags,
        version,
        peer_count,
        payload: data[5..].to_vec(),
    }))
}

pub fn encode_control(opcode: u8, local_id: u32, linking: u8, flags: [u8; 4], version: [u8; 4], peer_count: u16, auth_key: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![opcode];
    write_u32(local_id, &mut out);
    match opcode {
        MASTER_REG_REQ | MASTER_ALIVE_REQ | MASTER_ALIVE_REPLY => {
            out.push(linking);
            out.extend_from_slice(&flags);
            out.extend_from_slice(&version);
        }
        MASTER_REG_REPLY => {
            out.push(linking);
            out.extend_from_slice(&flags);
            out.extend_from_slice(&peer_count.to_be_bytes());
            out.extend_from_slice(&version);
        }
        PEER_REG_REQ | PEER_REG_REPLY => out.extend_from_slice(&version),
        PEER_ALIVE_REQ | PEER_ALIVE_REPLY => {
            out.push(linking);
            out.extend_from_slice(&flags);
        }
        _ => {}
    }
    if let Some(key) = auth_key { append_auth(&mut out, key); }
    out
}

pub fn encode_peer_list(local_id: u32, peers: &[PeerInfo], auth_key: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![PEER_LIST_REPLY];
    write_u32(local_id, &mut out);
    let byte_len = (peers.len() * 11) as u16;
    out.extend_from_slice(&byte_len.to_be_bytes());
    for peer in peers {
        write_u32(peer.peer_id, &mut out);
        match peer.address.ip() {
            IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
            IpAddr::V6(_) => out.extend_from_slice(&[0, 0, 0, 0]),
        }
        out.extend_from_slice(&peer.address.port().to_be_bytes());
        out.push(peer.linking);
    }
    if let Some(key) = auth_key { append_auth(&mut out, key); }
    out
}

#[derive(Debug, Clone)]
pub struct PeerSession {
    pub info: PeerInfo,
    pub connected_at: Instant,
    pub last_seen: Instant,
}

#[derive(Debug)]
pub struct IpscRegistry {
    peers: BTreeMap<u32, PeerSession>,
    max_peers: usize,
    timeout: Duration,
}

impl IpscRegistry {
    pub fn new(max_peers: usize, timeout: Duration) -> Self {
        Self { peers: BTreeMap::new(), max_peers: max_peers.max(1), timeout }
    }

    pub fn register(&mut self, peer: PeerInfo, now: Instant) -> bool {
        if !self.peers.contains_key(&peer.peer_id) && self.peers.len() >= self.max_peers { return false; }
        self.peers.insert(peer.peer_id, PeerSession { info: peer, connected_at: now, last_seen: now });
        true
    }

    pub fn touch(&mut self, peer_id: u32, now: Instant) -> bool {
        let Some(peer) = self.peers.get_mut(&peer_id) else { return false; };
        peer.last_seen = now;
        true
    }

    pub fn remove(&mut self, peer_id: u32) -> Option<PeerSession> { self.peers.remove(&peer_id) }

    pub fn expire(&mut self, now: Instant) -> Vec<PeerInfo> {
        let expired: Vec<u32> = self.peers.iter().filter(|(_, p)| now.saturating_duration_since(p.last_seen) >= self.timeout).map(|(id, _)| *id).collect();
        expired.into_iter().filter_map(|id| self.peers.remove(&id).map(|s| s.info)).collect()
    }

    pub fn peers(&self) -> Vec<PeerInfo> { self.peers.values().map(|p| p.info.clone()).collect() }
}

#[derive(Debug)]
pub struct JitterBuffer<T> {
    depth: usize,
    queue: VecDeque<T>,
}

impl<T> JitterBuffer<T> {
    pub fn new(depth: usize) -> Self { Self { depth, queue: VecDeque::new() } }
    pub fn push(&mut self, item: T) -> Option<T> {
        self.queue.push_back(item);
        if self.queue.len() > self.depth { self.queue.pop_front() } else { None }
    }
    pub fn flush(&mut self) -> impl Iterator<Item = T> + '_ { self.queue.drain(..) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> IpscConfig {
        IpscConfig { role: IpscRole::Peer, radio_id: 1, local_ip: None, local_port: 50000, master: Some("127.0.0.1:50000".into()), jitter_buffer_depth: 2, alive_interval_secs: 5, auth_key: None }
    }

    #[test]
    fn jitter_is_60ms_units() { assert_eq!(cfg().jitter_delay(), Duration::from_millis(120)); }

    #[test]
    fn control_round_trip_with_auth() {
        let packet = encode_control(MASTER_REG_REQ, 0x0004c2c0, 0x6a, [0, 0, 0x80, 0xdc], [4, 3, 4, 0], 0, Some(b"secret"));
        let parsed = parse_packet(&packet, Some(b"secret")).unwrap();
        match parsed { IpscPacket::Control(c) => { assert_eq!(c.opcode, MASTER_REG_REQ); assert_eq!(c.peer_id, 0x0004c2c0); }, _ => panic!("unexpected packet") }
    }

    #[test]
    fn peer_list_round_trip() {
        let peers = vec![PeerInfo { peer_id: 1, address: "192.0.2.10:50001".parse().unwrap(), linking: 0x6a }];
        let bytes = encode_peer_list(99, &peers, None);
        let parsed = parse_packet(&bytes, None).unwrap();
        match parsed { IpscPacket::PeerList { peer_id, peers: got } => { assert_eq!(peer_id, 99); assert_eq!(got, peers); }, _ => panic!("unexpected packet") }
    }

    #[test]
    fn user_metadata_is_extracted() {
        let mut data = vec![0u8; 40];
        data[0] = GROUP_VOICE;
        data[1..5].copy_from_slice(&123u32.to_be_bytes());
        data[5] = 7;
        data[6..9].copy_from_slice(&[0x01, 0x02, 0x03]);
        data[9..12].copy_from_slice(&[0x00, 0x03, 0xe9]);
        data[17] = TS_CALL_MASK;
        data[30] = 0x01;
        let parsed = parse_packet(&data, None).unwrap();
        match parsed { IpscPacket::User(user) => { assert_eq!(user.source, 0x010203); assert_eq!(user.destination, 1001); assert_eq!(user.timeslot, Timeslot::Two); }, _ => panic!("unexpected packet") }
    }
}

// -----------------------------------------------------------------------------
// IPSC <-> Homebrew group-voice media translator.
// -----------------------------------------------------------------------------

use dmr_fec::{
    build_group_voice_burst, build_group_voice_lc_payload, extract_ipsc_ambe,
    group_embedded_lc, group_lc, group_lc_parity,
};
use dmr_protocol_hbp::DmrdPacket;

const VOICE_HEAD: u8 = 0x01;
const VOICE_TERM: u8 = 0x02;
const SLOT1_VOICE: u8 = 0x0a;
const SLOT2_VOICE: u8 = 0x8a;

#[derive(Debug, Clone, Copy)]
struct MediaState {
    hbp_stream: u32,
    ipsc_stream: u8,
    sequence: u8,
    position: u8,
    rtp_sequence: u16,
    rtp_timestamp: u32,
    active: bool,
}

impl Default for MediaState {
    fn default() -> Self {
        Self {
            hbp_stream: 0,
            ipsc_stream: 0,
            sequence: 0,
            position: 0,
            rtp_sequence: 0,
            rtp_timestamp: 0,
            active: false,
        }
    }
}

/// Stateful media translator for one IPSC network endpoint.
///
/// The translator intentionally supports the interoperable voice subset only.
/// Data packets remain parsed by [`parse_packet`] but are not converted into
/// Homebrew DMRD frames.
pub struct IpscVoiceTranslator {
    local_peer_id: u32,
    rx: [MediaState; 2],
    tx: [MediaState; 2],
    next_ipsc_stream: u8,
}

impl IpscVoiceTranslator {
    pub fn new(local_peer_id: u32) -> Self {
        Self {
            local_peer_id,
            rx: [MediaState::default(), MediaState::default()],
            tx: [MediaState::default(), MediaState::default()],
            next_ipsc_stream: 1,
        }
    }

    fn slot_index(slot: Timeslot) -> usize {
        if slot == Timeslot::Two { 1 } else { 0 }
    }

    fn next_stream_id(&mut self) -> u8 {
        let value = self.next_ipsc_stream;
        self.next_ipsc_stream = self.next_ipsc_stream.wrapping_add(1);
        if self.next_ipsc_stream == 0 {
            self.next_ipsc_stream = 1;
        }
        value
    }

    /// Convert one IPSC Group Voice user packet into a Homebrew DMRD frame.
    pub fn ipsc_to_dmrd(&mut self, user: &UserPacket) -> Result<Option<DmrdPacket>, IpscError> {
        if user.opcode != GROUP_VOICE || user.call_type != CallType::Group {
            return Ok(None);
        }
        let index = Self::slot_index(user.timeslot);
        let state = &mut self.rx[index];
        let (frame_type, data_type, payload) = match user.burst_type {
            VOICE_HEAD => {
                if !state.active {
                    state.hbp_stream = rand::random::<u32>();
                    state.sequence = 0;
                    state.position = 0;
                    state.active = true;
                }
                (
                    2,
                    1,
                    build_group_voice_lc_payload(user.destination, user.source, false)
                        .map_err(|e| IpscError::Media(e.to_string()))?,
                )
            }
            VOICE_TERM => {
                if !state.active {
                    return Ok(None);
                }
                let payload = build_group_voice_lc_payload(user.destination, user.source, true)
                    .map_err(|e| IpscError::Media(e.to_string()))?;
                let result = DmrdPacket {
                    sequence: state.sequence,
                    source: user.source,
                    destination: user.destination,
                    repeater: self.local_peer_id,
                    slot: user.timeslot,
                    call_type: CallType::Group,
                    frame_type: 2,
                    data_type: 2,
                    stream_id: state.hbp_stream,
                    payload,
                    trailing: Vec::new(),
                };
                *state = MediaState::default();
                return Ok(Some(result));
            }
            SLOT1_VOICE | SLOT2_VOICE => {
                if user.raw.len() < 52 {
                    return Err(IpscError::TooShort(user.raw.len()));
                }
                if !state.active {
                    state.hbp_stream = rand::random::<u32>();
                    state.sequence = 0;
                    state.position = 0;
                    state.active = true;
                }
                let mut ambe = [0u8; 19];
                ambe.copy_from_slice(&user.raw[33..52]);
                let position = state.position % 6;
                let payload = build_group_voice_burst(&ambe, position, user.destination, user.source)
                    .map_err(|e| IpscError::Media(e.to_string()))?;
                state.position = (position + 1) % 6;
                if position == 0 { (1, 0, payload) } else { (0, position, payload) }
            }
            _ => return Ok(None),
        };

        let packet = DmrdPacket {
            sequence: state.sequence,
            source: user.source,
            destination: user.destination,
            repeater: self.local_peer_id,
            slot: user.timeslot,
            call_type: CallType::Group,
            frame_type,
            data_type,
            stream_id: state.hbp_stream,
            payload,
            trailing: Vec::new(),
        };
        state.sequence = state.sequence.wrapping_add(1);
        Ok(Some(packet))
    }

    /// Convert a Homebrew Group Voice DMRD frame into a complete IPSC
    /// GROUP_VOICE packet body. Authentication, when configured, is appended.
    pub fn dmrd_to_ipsc(
        &mut self,
        packet: &DmrdPacket,
        auth_key: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, IpscError> {
        if packet.call_type != CallType::Group {
            return Ok(None);
        }
        let index = Self::slot_index(packet.slot);
        if packet.frame_type == 2 && packet.data_type == 1 {
            if !self.tx[index].active || self.tx[index].hbp_stream != packet.stream_id {
                let stream = self.next_stream_id();
                self.tx[index] = MediaState {
                    hbp_stream: packet.stream_id,
                    ipsc_stream: stream,
                    active: true,
                    ..MediaState::default()
                };
            }
            let payload = build_ipsc_lc_payload(packet.destination, packet.source, false)?;
            return Ok(Some(self.build_voice_packet(packet, 0xdd, &payload, false, auth_key)?));
        }
        if packet.frame_type == 2 && packet.data_type == 2 {
            if !self.tx[index].active {
                return Ok(None);
            }
            let payload = build_ipsc_lc_payload(packet.destination, packet.source, true)?;
            let result = self.build_voice_packet(packet, 0x5e, &payload, false, auth_key)?;
            self.tx[index] = MediaState::default();
            return Ok(Some(result));
        }

        if !self.tx[index].active || self.tx[index].hbp_stream != packet.stream_id {
            let stream = self.next_stream_id();
            self.tx[index] = MediaState {
                hbp_stream: packet.stream_id,
                ipsc_stream: stream,
                active: true,
                position: if packet.frame_type == 1 { 0 } else { packet.data_type % 6 },
                ..MediaState::default()
            };
        }
        let position = if packet.frame_type == 1 {
            0
        } else if packet.frame_type == 0 {
            packet.data_type % 6
        } else {
            return Ok(None);
        };
        let ambe = extract_ipsc_ambe(&packet.payload);
        let payload = build_ipsc_slot_voice_payload(
            packet.slot,
            position,
            &ambe,
            packet.destination,
            packet.source,
        )?;
        self.tx[index].position = (position + 1) % 6;
        Ok(Some(self.build_voice_packet(packet, 0x5d, &payload, true, auth_key)?))
    }

    fn build_voice_packet(
        &mut self,
        packet: &DmrdPacket,
        rtp_payload_type: u8,
        gv_payload: &[u8],
        advance_timestamp: bool,
        auth_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, IpscError> {
        let index = Self::slot_index(packet.slot);
        let state = &mut self.tx[index];
        if advance_timestamp {
            state.rtp_timestamp = state.rtp_timestamp.wrapping_add(480);
        }
        let mut out = Vec::with_capacity(64 + IPSC_AUTH_LEN);
        out.push(GROUP_VOICE);
        out.extend_from_slice(&self.local_peer_id.to_be_bytes());
        out.push(state.ipsc_stream);
        write_u24(packet.source, &mut out);
        write_u24(packet.destination, &mut out);
        out.push(0x02);
        out.extend_from_slice(&[0x00, 0x00, 0x43, 0xe2]);
        let mut call_info = if packet.slot == Timeslot::Two { TS_CALL_MASK } else { 0 };
        if packet.frame_type == 2 && packet.data_type == 2 {
            call_info |= END_MASK;
        }
        out.push(call_info);
        out.extend_from_slice(&[0x80, rtp_payload_type]);
        out.extend_from_slice(&state.rtp_sequence.to_be_bytes());
        out.extend_from_slice(&state.rtp_timestamp.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        state.rtp_sequence = state.rtp_sequence.wrapping_add(1);
        out.extend_from_slice(gv_payload);
        if let Some(key) = auth_key {
            append_auth(&mut out, key);
        }
        Ok(out)
    }
}

fn write_u24(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&[
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    ]);
}

fn build_ipsc_lc_payload(destination: u32, source: u32, terminator: bool) -> Result<Vec<u8>, IpscError> {
    let lc = group_lc(destination, source).map_err(|e| IpscError::Media(e.to_string()))?;
    let parity = group_lc_parity(destination, source, terminator)
        .map_err(|e| IpscError::Media(e.to_string()))?;
    let mut out = Vec::with_capacity(24);
    out.push(if terminator { VOICE_TERM } else { VOICE_HEAD });
    out.extend_from_slice(&[0x80, 0x00, 0x0a, 0x80, 0x0a, 0x00, 0x60]);
    out.extend_from_slice(&lc);
    out.extend_from_slice(&parity);
    out.extend_from_slice(&[0x00, if terminator { 0x12 } else { 0x11 }, 0x00, 0x00]);
    Ok(out)
}

fn build_ipsc_slot_voice_payload(
    slot: Timeslot,
    position: u8,
    ambe: &[u8; 19],
    destination: u32,
    source: u32,
) -> Result<Vec<u8>, IpscError> {
    let slot_burst = if slot == Timeslot::Two { SLOT2_VOICE } else { SLOT1_VOICE };
    let position = position % 6;
    let mut out = Vec::with_capacity(40);
    match position {
        0 => {
            out.extend_from_slice(&[slot_burst, 0x14, 0x40]);
            out.extend_from_slice(ambe);
        }
        4 => {
            out.extend_from_slice(&[slot_burst, 0x22, 0x16]);
            out.extend_from_slice(ambe);
            let segments = group_embedded_lc(destination, source)
                .map_err(|e| IpscError::Media(e.to_string()))?;
            out.extend_from_slice(&segments[3]);
            out.extend_from_slice(&group_lc(destination, source).map_err(|e| IpscError::Media(e.to_string()))?);
            out.push(0x14);
        }
        5 => {
            out.extend_from_slice(&[slot_burst, 0x19, 0x06]);
            out.extend_from_slice(ambe);
            out.extend_from_slice(&[0, 0, 0, 0, 0x10]);
        }
        1..=3 => {
            out.extend_from_slice(&[slot_burst, 0x19, 0x06]);
            out.extend_from_slice(ambe);
            let segments = group_embedded_lc(destination, source)
                .map_err(|e| IpscError::Media(e.to_string()))?;
            out.extend_from_slice(&segments[(position - 1) as usize]);
            out.push(match position { 1 => 0x12, 2 | 3 => 0x16, _ => 0 });
        }
        _ => unreachable!(),
    }
    Ok(out)
}

#[cfg(test)]
mod media_tests {
    use super::*;

    fn slot_voice_packet(slot: Timeslot, ambe: [u8; 19]) -> UserPacket {
        let mut raw = vec![0u8; 52];
        raw[0] = GROUP_VOICE;
        raw[5] = 1;
        raw[6..9].copy_from_slice(&[0x12, 0x34, 0x56]);
        raw[9..12].copy_from_slice(&[0, 0x03, 0xe9]);
        raw[17] = if slot == Timeslot::Two { TS_CALL_MASK } else { 0 };
        raw[30] = if slot == Timeslot::Two { SLOT2_VOICE } else { SLOT1_VOICE };
        raw[33..52].copy_from_slice(&ambe);
        UserPacket {
            opcode: GROUP_VOICE,
            peer_id: 1,
            sequence: 1,
            source: 0x123456,
            destination: 1001,
            call_type: CallType::Group,
            timeslot: slot,
            end: false,
            burst_type: raw[30],
            raw,
        }
    }

    #[test]
    fn slot_voice_translates_to_dmrd() {
        let mut translator = IpscVoiceTranslator::new(999_999);
        let packet = slot_voice_packet(Timeslot::One, dmr_fec::ipsc_ambe_silence());
        let dmrd = translator.ipsc_to_dmrd(&packet).unwrap().unwrap();
        assert_eq!(dmrd.destination, 1001);
        assert_eq!(dmrd.source, 0x123456);
        assert_eq!(dmrd.frame_type, 1);
    }

    #[test]
    fn dmrd_header_translates_to_ipsc_header() {
        let mut translator = IpscVoiceTranslator::new(999_999);
        let packet = DmrdPacket {
            sequence: 0,
            source: 1_234_567,
            destination: 1001,
            repeater: 999_999,
            slot: Timeslot::One,
            call_type: CallType::Group,
            frame_type: 2,
            data_type: 1,
            stream_id: 0x12345678,
            payload: build_group_voice_lc_payload(1001, 1_234_567, false).unwrap(),
            trailing: vec![],
        };
        let ipsc = translator.dmrd_to_ipsc(&packet, None).unwrap().unwrap();
        assert_eq!(ipsc[0], GROUP_VOICE);
        assert_eq!(ipsc[30], VOICE_HEAD);
    }
}
