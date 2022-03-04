use std::fmt::Debug;
use std::fmt::Display;

use super::PacketContent;
use bytes::{Buf, BufMut, Bytes, BytesMut};

const QR_MASK: u8 = 0x80;
const OP_MASK: u8 = 0x78;
const AA_MASK: u8 = 0x04;
const TC_MASK: u8 = 0x02;
const RD_MASK: u8 = 0x01;
const RA_MASK: u8 = QR_MASK;
const Z_MASK: u8 = 0x70;
const RC_MASK: u8 = 0x0f;

/// DNS Header described in [RFC1035](https://datatracker.ietf.org/doc/html/rfc1035)
pub struct Header {
    /// transaction ID of the DNS packet
    id: u16,
    /// indicates whether this packet is for query (true) or response (false)
    is_query: bool,
    /// types of this DNS packet
    opcode: Op,
    /// is authorized answer
    is_auth: bool,
    /// is truncated packet
    is_trunc: bool,
    /// is the packet recursion desired
    is_rec_des: bool,
    /// is the server recursion available
    is_rec_avl: bool,
    /// reserved for further use.
    z: u8,
    /// response code of the packet
    response: Rcode,
    /// number of entries in question section
    questions: u16,
    /// number of Resource Records in answer section
    answers: u16,
    /// number of name server Resource Records in the authority records section
    name_servers: u16,
    /// number of resource records in additional section
    additional: u16,
}

impl PacketContent for Header {
    fn parse(packet: Bytes, _pos: usize) -> Result<Self, super::error::PacketError>
    where
        Self: Sized,
    {
        let mut buf = packet;
        let id = buf.get_u16();

        let a = buf.get_u8();
        let is_query = a & QR_MASK == QR_MASK;
        let is_auth = a & AA_MASK == AA_MASK;
        let opcode = Op::from((a & OP_MASK) >> 3);
        let is_trunc = a & TC_MASK == TC_MASK;
        let is_rec_des = a & RD_MASK == RD_MASK;

        let b = buf.get_u8();
        let is_rec_avl = b & RA_MASK == RA_MASK;
        let z = (b & Z_MASK) >> 4;
        let response = Rcode::from(b & RC_MASK);

        let questions = buf.get_u16();
        let answers = buf.get_u16();
        let name_servers = buf.get_u16();
        let additional = buf.get_u16();
        Ok(Self {
            id,
            is_query,
            opcode,
            is_trunc,
            is_auth,
            is_rec_des,
            is_rec_avl,
            z,
            response,
            questions,
            answers,
            name_servers,
            additional,
        })
    }

    fn into_bytes(self) -> bytes::BytesMut {
        let mut buf = BytesMut::with_capacity(12);
        buf.put_u16(self.id);
        let a = {
            let q: u8 = if self.is_query { 0 } else { 1 };
            let op: u8 = self.opcode.into();
            let aa = if self.is_auth { 1 } else { 0 };
            let tc = if self.is_trunc { 1 } else { 0 };
            let rd = if self.is_rec_des { 1 } else { 0 };
            (q << 7) | (op << 3) | (aa << 2) | (tc << 1) | rd
        };
        buf.put_u8(a);
        let b = {
            let ra = if self.is_rec_avl { 1 } else { 0 };
            let rc: u8 = self.response.into();
            (ra << 7) | (self.z << 4) | rc
        };
        buf.put_u8(b);
        buf.put_u16(self.questions);
        buf.put_u16(self.answers);
        buf.put_u16(self.name_servers);
        buf.put_u16(self.additional);
        buf
    }
}

// operation code in DNS Header
pub_map_enum! {
    Op<u8> {
        Query => 0,
        IQuery => 1,
        Status => 2;
        Reserved
    }
}

impl Display for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operation = match *self {
            Op::Query => String::from("Query"),
            Op::IQuery => String::from("Inverse Query"),
            Op::Status => String::from("Status"),
            Op::Reserved(x) => format!("Unknown Operation Code: {}", x),
        };
        write!(f, "{}", operation)
    }
}

pub_map_enum! {
    Rcode<u8> {
        NoError => 0,
        FormatError => 1,
        ServFail => 2,
        NameError => 3,     // NXDOMAIN
        NotImpl => 4,
        Refused => 5;
        Reserved
    }
}
