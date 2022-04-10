use std::fmt::Debug;
use std::fmt::Display;

use super::{error::PacketError, PacketContent};
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
#[derive(Debug, Clone, Copy)]
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
    authorities: u16,
    /// number of resource records in additional section
    additional: u16,
}

impl Header {
    pub fn new_query(id: u16, questions: u16) -> Self {
        Header {
            id,
            is_query: true,
            opcode: Op::Query,
            is_auth: false,
            is_trunc: false,
            is_rec_des: true,
            is_rec_avl: false,
            z: 0,
            response: Rcode::NoError,
            questions,
            answers: 0,
            authorities: 0,
            additional: 0,
        }
    }

    pub fn new_answer(id: u16, answers: u16, authorities: u16, additional: u16) -> Self {
        Header {
            id,
            is_query: false,
            opcode: Op::Query,
            is_auth: false,
            is_trunc: false,
            is_rec_des: true,
            is_rec_avl: true,
            z: 0,
            response: Rcode::NoError,
            questions: 0,
            answers,
            authorities,
            additional,
        }
    }

    pub fn new_failure(id: u16, error: PacketError) -> Self {
        let rcode = match error {
            PacketError::FormatError => Rcode::FormatError,
            PacketError::ServFail => Rcode::ServFail,
            PacketError::NameError(_) => Rcode::NameError,
            PacketError::NotImpl(_) => Rcode::NotImpl,
            PacketError::Refused(_) => Rcode::Refused,
        };
        Header {
            id,
            is_query: false,
            opcode: Op::Query,
            is_auth: false,
            is_trunc: false,
            is_rec_des: false,
            is_rec_avl: false,
            z: 0,
            response: rcode,
            questions: 0,
            answers: 0,
            authorities: 0,
            additional: 0,
        }
    }
}

impl Header {
    /// get transaction id
    pub fn get_id(&self) -> u16 {
        self.id
    }
    /// is a dns query or not
    pub fn is_query(&self) -> bool {
        self.is_query
    }

    /// opcode of the dns packet
    pub fn get_op(&self) -> Op {
        self.opcode
    }

    /// is the answer authorized answer
    pub fn is_auth(&self) -> bool {
        self.is_auth
    }

    /// is the packet truncated
    pub fn is_trunc(&self) -> bool {
        self.is_trunc
    }

    /// is the query recursion desired
    pub fn is_rec_des(&self) -> bool {
        self.is_rec_des
    }

    /// is the dns server recursion available
    pub fn is_rec_avl(&self) -> bool {
        self.is_rec_avl
    }

    /// get the z record of the dns server
    pub fn get_z(&self) -> u8 {
        self.z
    }

    /// get the rcode in header
    pub fn get_rcode(&self) -> Rcode {
        self.response
    }

    /// how many questions are there in the packet
    pub fn question_count(&self) -> u16 {
        self.questions
    }

    /// how many answers are there in the packet
    pub fn answer_count(&self) -> u16 {
        self.answers
    }

    /// how many ns records are there in the packet
    pub fn ns_count(&self) -> u16 {
        self.authorities
    }

    /// how many additional RRs are in the packet
    pub fn addition_count(&self) -> u16 {
        self.additional
    }
}

impl Header {
    pub fn set_questions(&mut self, questions: u16) {
        self.questions = questions;
    }

    pub fn set_answers(&mut self, answers: u16) {
        self.answers = answers;
    }

    pub fn set_authorities(&mut self, authorities: u16) {
        self.authorities = authorities;
    }

    pub fn set_additional(&mut self, additional: u16) {
        self.additional = additional;
    }
}

impl PacketContent for Header {
    fn parse(packet: Bytes, _pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        let mut buf = packet;
        let id = buf.get_u16();

        let a = buf.get_u8();
        let is_query = a & QR_MASK != QR_MASK;
        let is_auth = a & AA_MASK == AA_MASK;
        let opcode = Op::from((a & OP_MASK) >> 3);
        let is_trunc = a & TC_MASK == TC_MASK;
        let is_rec_des = a & RD_MASK == RD_MASK;

        let b = buf.get_u8();
        let is_rec_avl = b & RA_MASK == RA_MASK;
        let z = (b & Z_MASK) >> 5;
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
            authorities: name_servers,
            additional,
        })
    }

    fn into_bytes(self) -> Result<BytesMut, PacketError> {
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
        buf.put_u16(self.authorities);
        buf.put_u16(self.additional);
        Ok(buf)
    }

    #[inline]
    fn size(&self) -> usize {
        12
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

mod test {
    #[test]
    fn test_parse_header() {
        use super::{Op, Rcode};
        use crate::protocol::PacketContent;
        use bytes::{BufMut, Bytes, BytesMut};

        let mut packet = BytesMut::new();
        // create header
        packet.put_u16(0); // id == 0;
        packet.put_u8(1); // query = True (0); Opcode = QUERY (0); AA = FALSE (0); TC = FALSE (0); RD = TRUE (1)
        packet.put_u8(0x20); // z = 1; rcode = 0;
        packet.put_u16(1); // QDCOUNT = 1;
        packet.put_u16(0); // ANCOUNT = 0;
        packet.put_u16(0); // NSCOUNT = 0;
        packet.put_u16(0); // ARCOUNT = 0;
                           // creat question

        let h_packet = Bytes::from(packet);

        let h_result = super::Header::parse(h_packet, 0);
        assert!(h_result.is_ok());
        let h = h_result.unwrap();

        assert_eq!(h.get_id(), 0);
        assert!(h.is_query());
        assert_eq!(h.get_op(), Op::Query);
        assert!(!h.is_auth());
        assert!(!h.is_trunc());
        assert!(h.is_rec_des());

        assert!(!h.is_rec_avl());
        assert_eq!(h.get_z(), 1);
        assert_eq!(h.get_rcode(), Rcode::NoError);

        assert_eq!(h.question_count(), 1);
        assert_eq!(h.answer_count(), 0);
        assert_eq!(h.ns_count(), 0);
        assert_eq!(h.addition_count(), 0);
    }
}
