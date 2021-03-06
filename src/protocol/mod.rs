// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Display;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;

pub use self::{
    domain::Name,
    error::{PacketError, TransactionError},
    header::Header,
    question::Question,
    rr::{RRData, RR},
};
use crate::protocol::header::{Op, Rcode};

trait PacketContent {
    fn size(&self) -> usize;
    fn parse(packet: Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized;
    fn into_bytes(self) -> Result<BytesMut, PacketError>;
}

// Todo: refract Packet, it sucks
/// DNS data get from primitive packet
#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub question: Option<Question>,
    pub answers: Vec<RR>,
    pub authorities: Vec<RR>,
    pub additions: Vec<RR>,
}

impl Packet {
    // make a plain packet
    pub fn new_plain_answer(id: u16) -> Self {
        let h = Header::new_answer(id, 0, 0, 0);
        Self {
            header: h,
            question: None,
            answers: vec![],
            authorities: vec![],
            additions: vec![],
        }
    }
    // make a new query
    pub fn new_query(id: u16, query: Question) -> Self {
        let header = Header::new_query(id);
        Self {
            header,
            question: Some(query),
            answers: vec![],
            authorities: vec![],
            additions: vec![],
        }
    }

    // assuming the packet buffer contains at least 1 packet...
    pub fn parse_packet(packet: Bytes, offset: usize) -> Result<Packet, TransactionError> {
        tracing::trace!(
            "parse packet at offset {}, packet size: {}",
            offset,
            packet.len()
        );

        let h = Header::parse(packet.clone(), offset)?;
        tracing::trace!("parse header successful with header {:?}", h);

        let id = Some(h.get_id());

        let mut question = None;
        let mut answers = vec![];
        let mut offset = offset + 12;

        if h.is_query() && h.answer_count() != 0 {
            let err = TransactionError {
                id,
                error: PacketError::FormatError,
            };
            // no answer is expected in query packet.
            return Err(err);
        }
        for _ in 0..h.question_count() {
            let ques = Question::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += ques.size();
            question = Some(ques);
        }
        for _ in 0..h.answer_count() {
            let rr = RR::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += rr.size();
            answers.push(rr);
        }
        let mut authorities = Vec::new();
        for _ in 0..h.authority_count() {
            let rr = RR::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += rr.size();
            authorities.push(rr);
        }
        let mut additions = Vec::new();
        for _ in 0..h.addition_count() {
            let rr = RR::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += rr.size();
            additions.push(rr);
        }
        let pkt = Packet {
            header: h,
            question,
            answers,
            authorities,
            additions,
        };
        Ok(pkt)
    }

    pub async fn parse_stream<S>(stream: &mut S) -> Result<Self, TransactionError>
    where
        S: AsyncReadExt + Unpin,
    {
        tracing::debug!("parsing packet from stream");
        let len = stream.read_u16().await.map_err(|_| TransactionError {
            id: None,
            error: PacketError::ServFail, // treat as read an EOF, return a ServFail
        })?;
        tracing::trace!("packet length {}", len);
        let header = Header::parse_stream(stream).await?;
        tracing::debug!("parse header successfully with header: {:?}", header);
        let id = Some(header.get_id());
        if len < 12 {
            let err = TransactionError {
                id,
                error: PacketError::FormatError,
            };
            return Err(err);
        }

        let to_read = (len - 12) as usize;
        let mut pkt = Vec::from([0; 12]);
        let read = stream
            .read_buf(&mut pkt)
            .await
            .map_err(|_| TransactionError {
                id,
                error: PacketError::FormatError,
            })?;
        if read < to_read {
            let err = TransactionError {
                id,
                error: PacketError::FormatError,
            };
            return Err(err);
        }

        let mut question = None;
        let mut answers = vec![];
        let mut offset = 12;

        let packet = Bytes::from(pkt);
        if header.is_query() && header.answer_count() != 0 {
            let err = TransactionError {
                id,
                error: PacketError::FormatError,
            };
            // no answer is expected in query packet.
            return Err(err);
        }

        for _ in 0..header.question_count() {
            let ques = Question::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += ques.size();
            question = Some(ques);
        }

        for _ in 0..header.answer_count() {
            let rr = RR::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += rr.size();
            answers.push(rr);
        }
        let mut authorities = Vec::new();
        for _ in 0..header.authority_count() {
            let rr = RR::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += rr.size();
            authorities.push(rr);
        }
        let mut additions = Vec::new();
        for _ in 0..header.addition_count() {
            let rr = RR::parse(packet.clone(), offset)
                .map_err(|error| TransactionError { id, error })?;
            offset += rr.size();
            additions.push(rr);
        }
        let pkt = Packet {
            header,
            question,
            answers,
            authorities,
            additions,
        };
        Ok(pkt)
    }

    /// Generate DNS failure response
    pub fn new_failure(id: u16, rcode: PacketError) -> Packet {
        let header = Header::new_failure(id, rcode);
        Packet {
            header,
            question: None,
            answers: vec![],
            authorities: vec![],
            additions: vec![],
        }
    }

    // Todo: support domain name compressing
    /// make a binary
    pub fn into_bytes(self) -> Bytes {
        let mut buf = BytesMut::new();
        let h = self.header.try_into_bytes().unwrap();
        buf.put_slice(&h[..]);
        if let Some(question) = self.question {
            let q = question.into_bytes().unwrap();
            buf.put_slice(&q[..]);
        }
        for answer in self.answers {
            let a = answer.into_bytes().unwrap();
            buf.put_slice(&a[..]);
        }
        for authority in self.authorities {
            let a = authority.into_bytes().unwrap();
            buf.put_slice(&a[..]);
        }
        for addition in self.additions {
            let a = addition.into_bytes().unwrap();
            buf.put_slice(&a[..]);
        }

        Bytes::from(buf)
    }
}

impl Packet {
    #[inline]
    /// get transaction id
    pub fn get_id(&self) -> u16 {
        self.header.get_id()
    }

    #[inline]
    /// is a dns query or not
    pub fn is_query(&self) -> bool {
        self.header.is_query()
    }

    #[inline]
    /// opcode of the dns packet
    pub fn get_op(&self) -> Op {
        self.header.get_op()
    }

    #[inline]
    /// is the answer authorized
    pub fn is_auth(&self) -> bool {
        self.header.is_auth()
    }

    #[inline]
    /// is the packet truncated
    pub fn is_trunc(&self) -> bool {
        self.header.is_trunc()
    }

    #[inline]
    /// is the query recursion desired
    pub fn is_rec_des(&self) -> bool {
        self.header.is_rec_des()
    }

    #[inline]
    /// is the dns server recursion available
    pub fn is_rec_avl(&self) -> bool {
        self.header.is_rec_avl()
    }

    #[inline]
    /// get the z record of the dns server
    pub fn get_z(&self) -> u8 {
        self.header.get_z()
    }

    #[inline]
    /// get the rcode in header
    pub fn get_rcode(&self) -> Rcode {
        self.header.get_rcode()
    }

    #[inline]
    /// how many questions are there in the packet
    pub fn question_count(&self) -> u16 {
        self.header.question_count()
    }

    #[inline]
    /// how many answers are there in the packet
    pub fn answer_count(&self) -> u16 {
        self.header.answer_count()
    }

    #[inline]
    /// how many ns records are there in the packet
    pub fn authority_count(&self) -> u16 {
        self.header.authority_count()
    }

    #[inline]
    /// how many additional RRs are in the packet
    pub fn addition_count(&self) -> u16 {
        self.header.addition_count()
    }
}

impl Packet {
    pub fn set_question(&mut self, question: Question) {
        self.header.set_questions(1);
        self.question = Some(question);
    }

    pub fn set_answers(&mut self, answers: Vec<RR>) {
        self.header.set_answers(answers.len() as u16);
        self.answers = answers;
    }

    pub fn set_authorities(&mut self, auths: Vec<RR>) {
        self.header.set_authorities(auths.len() as u16);
        self.authorities = auths;
    }

    pub fn set_addtionals(&mut self, adds: Vec<RR>) {
        self.header.set_additional(adds.len() as u16);
        self.additions = adds;
    }
}

impl Packet {
    pub fn add_answer(&mut self, answer: RR) {
        self.answers.push(answer);
        self.header.set_answers(self.header.answer_count() + 1);
    }

    pub fn add_authority(&mut self, authority: RR) {
        self.authorities.push(authority);
        self.header
            .set_authorities(self.header.authority_count() + 1);
    }

    pub fn add_addition(&mut self, additional: RR) {
        self.additions.push(additional);
        self.header.set_additional(self.header.addition_count() + 1);
    }
}

// this (toy) macron are used for simplify definition of map-like enumerators.
//
// using:
// ```
//
// pub_map_enum!{
//     Foo<i32> {
//         Foo => 0,
//         Bar => 1;  // <- this is a ';' not a ','
//         Default    // fallback name
//     }
// }
// ```
// defines:
// ```
// pub enum Foo {
//     Foo,
//     Bar,
//     Default(i32),   // unmatched value will fallback into Unknown
// }
// ```
// and will automatically implements `From<i32>` for `Foo` and `From<Foo>` for `i32`.
macro_rules! pub_map_enum {
    ($name:ident <$t:ty> {$($key: ident => $value: expr),*; $fallback:ident}) => {
        #[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
        pub enum $name {
            $($key,)*
            $fallback($t),
        }

        impl From<$t> for $name {
            fn from(value: $t) -> Self {
                match value {
                    $($value => Self::$key,)*
                    value => Self::$fallback(value),
                }
            }
        }

        impl From<$name> for $t {
            fn from(key: $name) -> Self {
                match key {
                    $($name::$key => $value,)*
                    $name::$fallback(value) => value,
                }
            }
        }
    }
}

// Type of Resource Record
pub_map_enum! {RRType<u16> {
    A => 1,
    Ns => 2,
    Cname => 5,
    Soa => 6,
    Mb => 7,
    Mg => 8,
    Mr => 9,
    Null => 10,
    Wks => 11,
    Ptr => 12,
    HInfo => 13,
    MInfo => 14,
    Mx => 15,
    Txt => 16,
    Aaaa => 28;
    UNKNOWN
}}

impl Display for RRType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RRType::A => String::from("A"),
            RRType::Ns => String::from("NS"),
            RRType::Cname => String::from("CNAME"),
            RRType::Soa => String::from("SOA"),
            RRType::Mx => String::from("MX"),
            RRType::Mb => String::from("MB"),
            RRType::Mg => String::from("MG"),
            RRType::Mr => String::from("MR"),
            RRType::Null => String::from("NULL"),
            RRType::Wks => String::from("WKS"),
            RRType::Ptr => String::from("PTR"),
            RRType::HInfo => String::from("HINFO"),
            RRType::MInfo => String::from("MINFO"),
            RRType::Txt => String::from("TXT"),
            RRType::Aaaa => String::from("AAAA"),
            RRType::UNKNOWN(val) => format!("UNKNOWN({})", val),
        };
        write!(f, "{}", s)
    }
}

// QClass
pub_map_enum! {RRClass<u16> {
    Reserved => 0,
    Internet => 1,
    Chaos => 3,
    Hesiod => 4;
    Unknown
}}

// testing macron is enough
#[test]
fn test_pub_map_enum() {
    pub_map_enum! {Test<i32>{
        MyF => 0,
        MyB => 1;
        Unknown
    }}
    let my_foo = Test::from(0);
    assert_eq!(my_foo, Test::MyF);
    let unknown = Test::from(114514);
    assert_eq!(unknown, Test::Unknown(114514));
    assert_eq!(i32::from(my_foo), 0);
    assert_eq!(i32::from(unknown), 114514);
}

/// Domain names
mod domain;
/// Error types
mod error;
/// DNS packet header
mod header;
/// DNS packet question
mod question;
/// DNS Resource Record
mod rr;

#[cfg(test)]
mod integrated_test {
    use bytes::{BufMut, Bytes, BytesMut};

    use crate::protocol::{
        header::Header, question::Question, Packet, PacketContent, RRClass, RRType, RR,
    };

    fn example_lookup_raw() -> Bytes {
        let mut packet = BytesMut::new();
        // create header
        packet.put_u16(0); // id == 0;
        packet.put_u8(1); // query = True (0); Opcode = QUERY (0); AA = FALSE (0); TC = FALSE (0); RD = TRUE (1)
        packet.put_u8(0x20); // z = 1; rcode = 0;
        packet.put_u16(1); // QDCOUNT = 1;
        packet.put_u16(0); // ANCOUNT = 0;
        packet.put_u16(0); // NSCOUNT = 0;
        packet.put_u16(0); // ARCOUNT = 0;

        // create question
        let q_name = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let q_type = RRType::A;
        let q_class = RRClass::Internet;
        packet.put_slice(&q_name);
        packet.put_u16(u16::from(q_type));
        packet.put_u16(u16::from(q_class));

        packet.into()
    }

    #[test]
    fn test_modify() {
        let mut p = Packet::new_plain_answer(0);
        let slc = &[
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 1, 191, 82, 0,
            4, 19, 19, 81, 0,
        ][..];
        let ans_raw = Bytes::from(slc);
        let answer = RR::parse(ans_raw, 0).unwrap();
        p.add_answer(answer);
        assert!(!p.is_query());
        assert!(p.question.is_none());
        assert_eq!(p.answers.len(), 1);
    }

    fn example_answer() -> Bytes {
        let mut p = Packet::new_plain_answer(0);
        let slc = &[
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 1, 191, 82, 0,
            4, 19, 19, 81, 0,
        ][..];
        let ans_raw = Bytes::from(slc);
        let answer = RR::parse(ans_raw, 0).unwrap();
        p.add_answer(answer);
        p.into_bytes()
    }

    #[test]
    fn parse_dns_lookup() {
        let packet = example_lookup_raw();

        let header = Header::parse(packet.clone(), 0);
        assert!(header.is_ok());
        let q_result = Question::parse(packet.clone(), 12);
        assert!(q_result.is_ok());
        let q = q_result.unwrap();
        assert_eq!(q.size() + 12, packet.len());
    }

    #[test]
    fn test_parser() {
        let mut packet = BytesMut::new();
        // create header
        packet.put_u16(0); // id == 0;
        packet.put_u8(1); // query = True (0); Opcode = QUERY (0); AA = FALSE (0); TC = FALSE (0); RD = TRUE (1)
        packet.put_u8(0x20); // z = 1; rcode = 0;
        packet.put_u16(1); // QDCOUNT = 2;
        packet.put_u16(1); // ANCOUNT = 1;
        packet.put_u16(0); // NSCOUNT = 0;
        packet.put_u16(0); // ARCOUNT = 0;

        // create question 1
        // example.com A
        let q_name = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        let q_type = RRType::A;
        let q_class = RRClass::Internet;
        packet.put_slice(&q_name);
        packet.put_u16(u16::from(q_type));
        packet.put_u16(u16::from(q_class));

        let p = Bytes::from(packet.clone());

        let outcome = Packet::parse_packet(p, 0);
        assert!(outcome.is_err());

        packet[7] = 0;
        let p = Bytes::from(packet.clone());
        let outcome = Packet::parse_packet(p, 0);
        assert!(outcome.is_ok());
        let pkt = outcome.unwrap();
        assert!(pkt.question.is_some());
        assert_eq!(pkt.answers.len(), 0);
        assert_eq!(pkt.authorities.len(), 0);
        assert_eq!(pkt.additions.len(), 0);
        assert_eq!(pkt.header.get_id(), 0);
        assert_eq!(pkt.question.unwrap().get_name().to_string(), "example.com.");
    }

    #[test]
    fn test_to_bytes() {
        let p = example_answer();
        let parsed = Packet::parse_packet(p.clone(), 0).unwrap().into_bytes();
        assert_eq!(p, parsed);
    }

    #[tokio::test]
    async fn test_parse_stream() {
        let mut packet = BytesMut::new();
        let ans_pkt = &example_answer()[..];
        packet.put_u16(ans_pkt.len() as u16);
        packet.put(ans_pkt);
        let mut packet = &packet[..];
        let r = Packet::parse_stream(&mut packet).await;
        assert!(r.is_ok());
        let sr = r.unwrap();
        assert_eq!(sr.into_bytes(), example_answer());
    }
}
