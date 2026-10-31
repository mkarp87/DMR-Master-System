use dmr_core::{CallType, DmrFrame, FrameKind, RepeaterId, StreamId, SubscriberId, Timeslot};
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
    RepeaterLogin { repeater_id: u32 },          // RPTL + 4-byte ID
    RepeaterKey { repeater_id: u32, digest: Vec<u8> }, // RPTK
    RepeaterConfig(Vec<u8>),                    // RPTC...
    RepeaterPing { repeater_id: u32 },          // RPTP
    RepeaterClose { repeater_id: u32 },         // RPTO
    MasterPing { repeater_id: u32 },            // MSTP
    MasterAck(Vec<u8>),                         // MSTN/MSTACK variants retained raw
    MasterNak(Vec<u8>),
    Other { tag: [u8; 4], data: Vec<u8> },
}

fn be_u24(v: &[u8]) -> u32 { ((v[0] as u32)<<16)|((v[1] as u32)<<8)|(v[2] as u32) }
fn put_u24(v:u32,out:&mut Vec<u8>){ out.extend_from_slice(&[((v>>16)&0xff) as u8,((v>>8)&0xff) as u8,(v&0xff) as u8]); }
fn be_u32(v:&[u8])->u32{u32::from_be_bytes([v[0],v[1],v[2],v[3]])}

impl DmrdPacket {
    pub fn parse(data: &[u8]) -> Result<Self, HbpError> {
        if data.len() < DMRD_LEN || &data[..4] != b"DMRD" { return Err(HbpError::InvalidDmrd); }
        let bits=data[15];
        let slot=if bits & 0x80 != 0 { Timeslot::Two } else { Timeslot::One };
        let call_type=if bits & 0x40 != 0 { CallType::Private } else { CallType::Group };
        let frame_type=(bits >> 4) & 0x03;
        let data_type=bits & 0x0f;
        let mut payload=[0u8;33]; payload.copy_from_slice(&data[20..53]);
        Ok(Self{sequence:data[4],source:be_u24(&data[5..8]),destination:be_u24(&data[8..11]),repeater:be_u32(&data[11..15]),slot,call_type,frame_type,data_type,stream_id:be_u32(&data[16..20]),payload,trailing:data[53..].to_vec()})
    }
    pub fn encode(&self)->Vec<u8>{
        let mut out=Vec::with_capacity(DMRD_LEN+self.trailing.len()); out.extend_from_slice(b"DMRD"); out.push(self.sequence); put_u24(self.source,&mut out); put_u24(self.destination,&mut out); out.extend_from_slice(&self.repeater.to_be_bytes());
        let mut bits=(self.frame_type&0x03)<<4 | (self.data_type&0x0f); if self.slot==Timeslot::Two{bits|=0x80;} if self.call_type==CallType::Private{bits|=0x40;} out.push(bits); out.extend_from_slice(&self.stream_id.to_be_bytes()); out.extend_from_slice(&self.payload); out.extend_from_slice(&self.trailing); out
    }
    pub fn to_frame(&self)->DmrFrame{
        let frame_kind=match (self.frame_type,self.data_type){(2,1)=>FrameKind::VoiceHeader,(2,2)=>FrameKind::VoiceTerminator,(1,b)=>FrameKind::VoiceBurst{burst:b},(2,_)=>FrameKind::DataSync,_=>FrameKind::Unknown};
        DmrFrame{source:SubscriberId(self.source),destination:self.destination,repeater:RepeaterId(self.repeater),timeslot:self.slot,call_type:self.call_type,stream_id:StreamId(self.stream_id),sequence:self.sequence,frame_kind,payload:self.payload.to_vec()}
    }
}

pub fn parse_packet(data:&[u8])->Result<HbpPacket,HbpError>{
    if data.len()<4{return Err(HbpError::TooShort(data.len()));}
    match &data[..4]{
        b"DMRD"=>Ok(HbpPacket::Dmrd(DmrdPacket::parse(data)?)),
        b"RPTL" if data.len()>=8=>Ok(HbpPacket::RepeaterLogin{repeater_id:be_u32(&data[4..8])}),
        b"RPTK" if data.len()>=8=>Ok(HbpPacket::RepeaterKey{repeater_id:be_u32(&data[4..8]),digest:data[8..].to_vec()}),
        b"RPTC"=>Ok(HbpPacket::RepeaterConfig(data[4..].to_vec())),
        b"RPTP" if data.len()>=8=>Ok(HbpPacket::RepeaterPing{repeater_id:be_u32(&data[4..8])}),
        b"RPTO" if data.len()>=8=>Ok(HbpPacket::RepeaterClose{repeater_id:be_u32(&data[4..8])}),
        b"MSTP" if data.len()>=8=>Ok(HbpPacket::MasterPing{repeater_id:be_u32(&data[4..8])}),
        b"MSTN"=>Ok(HbpPacket::MasterNak(data[4..].to_vec())),
        tag=>{let mut t=[0u8;4];t.copy_from_slice(tag);Ok(HbpPacket::Other{tag:t,data:data[4..].to_vec()})}
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn dmrd_round_trip(){
        let p=DmrdPacket{sequence:7,source:1000001,destination:1001,repeater:1000002,slot:Timeslot::Two,call_type:CallType::Group,frame_type:1,data_type:3,stream_id:0x12345678,payload:[0x55;33],trailing:vec![]};
        let b=p.encode(); assert_eq!(b.len(),53); assert_eq!(DmrdPacket::parse(&b).unwrap(),p);
    }
    #[test] fn parse_login(){ let mut b=b"RPTL".to_vec();b.extend_from_slice(&1234u32.to_be_bytes());assert_eq!(parse_packet(&b).unwrap(),HbpPacket::RepeaterLogin{repeater_id:1234}); }
}
