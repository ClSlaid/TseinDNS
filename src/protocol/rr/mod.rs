use bytes::Buf;

mod rdata;
use self::rdata::Rdata;

use super::{domain::Name, error::PacketError};
use crate::protocol::{PacketContent, RRType};
use rdata::{a::A, aaaa::AAAA, cname::CNAME, mx::MX, ns::NS, soa::SOA, unknown::UNKNOWN};

/// ## Resource Record
/// As is described in RFC1035,
/// `Resource Records` be like:
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
pub struct RR {
    domain: Name,
    ttl: u32,
    length: usize, // total length of RR in packet
    rdata: RDATA,
}

// TODO: replace redundant code with macron
/// ## RDATA
/// The `RDATA` section of `RR`.
/// It also implicitly points out the `TYPE` of `RR`.
pub enum RDATA {
    A(A),
    AAAA(AAAA),
    CNAME(CNAME),
    MX(MX),
    NS(NS),
    SOA(SOA),
    UNKNOWN(UNKNOWN),
}

// Parse RDATA
macro_rules! parse_rdata {
    ($rtype:expr, $packet:expr, $begin:expr, $($t:ident),*) => {
        match $rtype {
        $(
            RRType::$t => {
                let (rdata, end) = $t::parse($packet, $begin)?;
                (RDATA::$t(rdata), end)
            }
        )*
            RRType::UNKNOWN(x) => {
                let (mut unknown, end) = UNKNOWN::parse_typeless($packet, $begin)?;
                unknown.set_type(x);
                (RDATA::UNKNOWN(unknown), end)
            }
    }
    }
}

impl PacketContent for RR {
    fn parse(packet: bytes::Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        let mut p = packet.clone();
        let (name, name_end) = Name::parse(packet.clone(), pos)?;
        p.advance(name_end);
        let rtype = RRType::from(p.get_u16());
        let class = p.get_u16();
        let ttl = p.get_u16();
        let rdata_begin = name_end + 6;
        let (rdata, rdata_end) =
            parse_rdata!(rtype, packet, rdata_begin, A, AAAA, NS, CNAME, SOA, MX);
        unimplemented!()
    }

    fn into_bytes(self) -> bytes::BytesMut {
        todo!()
    }
}
