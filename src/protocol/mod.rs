use std::fmt::Display;

use bytes::{BufMut, Bytes, BytesMut};

pub use self::{
    domain::Name,
    error::{PacketError, TransactionError},
    header::Header,
    question::Question,
    rr::RR,
    rr::RRData,
};

trait PacketContent {
    fn size(&self) -> usize;
    fn parse(packet: Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized;
    fn into_bytes(self) -> Result<BytesMut, PacketError>;
}

// Todo: refract Packet, it sucks
/// DNS data get from primitive packet
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
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
            questions: vec![],
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
            questions: vec![query],
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

        let (mut questions, mut answers) = (vec![], vec![]);
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
            questions.push(ques);
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
            questions,
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
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additions: vec![],
        }
    }

    // Todo: support domain name compressing
    /// make a binary
    pub fn into_bytes(self) -> Bytes {
        let mut buf = BytesMut::new();
        let h = self.header.into_bytes().unwrap();
        buf.put_slice(&h[..]);
        for question in self.questions {
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
    pub fn get_id(&self) -> u16 {
        self.header.get_id()
    }

    pub fn is_query(&self) -> bool {
        self.header.is_query()
    }
}

impl Packet {
    pub fn add_query(&mut self, query: Question) {
        self.questions.push(query);
        self.header.set_questions(self.header.question_count() + 1);
    }

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

/// this (toy) macron are used for simplify definition of map-like enumerators.
///
/// using:
/// ```
/// pub_map_enum!{
///     Foo<i32> {
///         Foo => 0,
///         Bar => 1;  // <- this is a ';' not a ','
///         Default    // fallback name
///     }
/// }
/// ```
/// defines:
/// ```
/// pub enum Foo {
///     Foo,
///     Bar,
///     Default(i32),   // unmatched value will fallback into Unknown
/// }
/// ```
/// and will automatically implements `From<i32>` for `Foo` and `From<Foo>` for `i32`.
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
    Mx => 15,
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

    use crate::protocol::{header::Header, PacketContent, question::Question, RRClass, RRType};

    #[test]
    fn parse_dns_lookup() {
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

        let packet: Bytes = packet.into();

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

        let outcome = super::Packet::parse_packet(p, 0);
        assert!(outcome.is_err());

        packet[7] = 0;
        let p = Bytes::from(packet.clone());
        let outcome = super::Packet::parse_packet(p, 0);
        assert!(outcome.is_ok());
        let pkt = outcome.unwrap();
        assert_eq!(pkt.questions.len(), 1);
        assert_eq!(pkt.answers.len(), 0);
        assert_eq!(pkt.authorities.len(), 0);
        assert_eq!(pkt.additions.len(), 0);
        assert_eq!(pkt.header.get_id(), 0);
        assert_eq!(pkt.questions[0].get_name().to_string(), "example.com.");
    }
}
