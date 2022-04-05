use bytes::{Bytes, BytesMut};

pub use self::{domain::Name, error::PacketError, header::Header, question::Question, rr::RR};

trait PacketContent {
    fn size(&self) -> usize;
    fn parse(packet: Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized;
    fn into_bytes(self) -> Result<BytesMut, PacketError>;
}

/// DNS data get from primitive packet
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<RR>,
    pub authorities: Vec<RR>,
    pub additions: Vec<RR>,
}

impl Packet {
    // assuming the packet buffer contains at least 1 packet...
    pub fn parse_packet(packet: Bytes, offset: usize) -> Result<Packet, PacketError> {
        let h = Header::parse(packet.clone(), offset)?;
        let (mut questions, mut answers) = (vec![], vec![]);
        let mut offset = offset + 12;

        if h.is_query() {
            if h.answer_count() != 0 {
                // no answer is expected in query packet.
                return Err(PacketError::FormatError);
            }
            for _ in 0..h.question_count() {
                let ques = Question::parse(packet.clone(), offset)?;
                offset += ques.size();
                questions.push(ques);
            }
        } else {
            if h.question_count() != 0 {
                // no query is expected in answer packet.
                return Err(PacketError::FormatError);
            }
            for _ in 0..h.answer_count() {
                let rr = RR::parse(packet.clone(), offset)?;
                offset += rr.size();
                answers.push(rr);
            }
        }
        let mut authorities = Vec::new();
        for _ in 0..h.ns_count() {
            let rr = RR::parse(packet.clone(), offset)?;
            offset += rr.size();
            authorities.push(rr);
        }
        let mut additions = Vec::new();
        for _ in 0..h.ns_count() {
            let rr = RR::parse(packet.clone(), offset)?;
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
        #[derive(PartialEq, Eq, Debug, Copy, Clone)]
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
    NS => 2,
    CNAME => 5,
    SOA => 6,
    MX => 15,
    AAAA => 28;
    UNKNOWN
}}

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
    pub_map_enum! {Foo<i32>{
        MyFoo => 0,
        MyBar => 1;
        Unknown
    }}
    let my_foo = Foo::from(0);
    assert_eq!(my_foo, Foo::MyFoo);
    let unknown = Foo::from(114514);
    assert_eq!(unknown, Foo::Unknown(114514));
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
    use crate::protocol::{header::Header, question::Question, PacketContent, RRClass, RRType};
    use bytes::{BufMut, Bytes, BytesMut};

    use super::domain::PTR_MASK;

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
        packet.put_u16(2); // QDCOUNT = 2;
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

        // create question 2
        // DNS domain name compressing
        // sub.example.com A
        let mut q_name = BytesMut::new();
        q_name.put_u8(3);
        q_name.put_slice(&[b's', b'u', b'b']);
        let jump_to = ((PTR_MASK as u16) << 8) | 12_u16;
        q_name.put_u16(jump_to);
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
        assert_eq!(pkt.questions.len(), 2);
        assert_eq!(pkt.answers.len(), 0);
        assert_eq!(pkt.authorities.len(), 0);
        assert_eq!(pkt.additions.len(), 0);
        assert_eq!(pkt.header.get_id(), 0);
        assert_eq!(pkt.questions[0].get_name().to_string(), "example.com.");
        assert_eq!(pkt.questions[1].get_name().to_string(), "sub.example.com.");
    }
}
