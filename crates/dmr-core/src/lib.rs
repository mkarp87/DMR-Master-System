use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr, time::Instant};
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub struct $name(pub u32);
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
        }
    };
}

id_type!(SubscriberId);
id_type!(TalkgroupId);
id_type!(RepeaterId);
id_type!(NetworkId);
id_type!(StreamId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Timeslot { One, Two }
impl Timeslot {
    pub fn from_u8(v: u8) -> Option<Self> { match v { 1 => Some(Self::One), 2 => Some(Self::Two), _ => None } }
    pub fn as_u8(self) -> u8 { match self { Self::One => 1, Self::Two => 2 } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallType { Group, Private }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameKind {
    VoiceHeader,
    VoiceTerminator,
    VoiceBurst { burst: u8 },
    DataSync,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmrFrame {
    pub source: SubscriberId,
    pub destination: u32,
    pub repeater: RepeaterId,
    pub timeslot: Timeslot,
    pub call_type: CallType,
    pub stream_id: StreamId,
    pub sequence: u8,
    pub frame_kind: FrameKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointProtocol { Homebrew, OpenBridge, Ipsc }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointKind {
    Repeater,
    HotspotSimplex,
    HotspotDuplex,
    Peer,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpscRole { Master, Peer }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndpointRole {
    HomebrewServer,
    HomebrewOutbound,
    OpenBridge,
    Ipsc(IpscRole),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub protocol: EndpointProtocol,
    pub kind: EndpointKind,
    pub role: EndpointRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimeoutPolicy { None, On, Off }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMember {
    pub endpoint: String,
    pub timeslot: Timeslot,
    pub talkgroup: TalkgroupId,
    pub initially_active: bool,
    pub timeout_secs: u64,
    pub timeout_policy: TimeoutPolicy,
    pub on: Vec<TalkgroupId>,
    pub off: Vec<TalkgroupId>,
    pub reset: Vec<TalkgroupId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bridge { pub name: String, pub members: Vec<BridgeMember> }

#[derive(Debug)]
pub struct SessionRuntime {
    pub repeater_id: RepeaterId,
    pub remote_addr: SocketAddr,
    pub connected_at: Instant,
    pub last_seen: Instant,
}
