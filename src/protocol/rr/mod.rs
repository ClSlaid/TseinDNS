use bytes::{Buf, BufMut, Bytes, BytesMut};

mod rdata;
use self::rdata::Rdata;

use super::{domain::Name, error::PacketError, RRClass};
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

#[derive(Debug)]
pub struct RR {
    domain: Name,
    ttl: u32,
    ty: RRType,
    class: RRClass,
    size: usize, // total length of RR in packet
    rdata: RRData,
}

// TODO: replace redundant code with macron
/// ## RRData
/// The `RRData` section of `RR`.
/// It also implicitly points out the `TYPE` of `RR`.

#[derive(Debug)]
pub enum RRData {
    A(A),
    AAAA(AAAA),
    CNAME(CNAME),
    MX(MX),
    NS(NS),
    SOA(SOA),
    UNKNOWN(UNKNOWN),
}
impl RRData {
    pub fn get_type(&self) -> RRType {
        match self {
            Self::A(_) => RRType::A,
            Self::AAAA(_) => RRType::AAAA,
            Self::CNAME(_) => RRType::CNAME,
            Self::MX(_) => RRType::MX,
            Self::NS(_) => RRType::NS,
            Self::SOA(_) => RRType::SOA,
            Self::UNKNOWN(unknown) => unknown.get_type(),
        }
    }
    pub fn to_bytes(self) -> Result<BytesMut, PacketError> {
        match self {
            Self::A(a) => a.to_bytes(),
            Self::AAAA(aaaa) => aaaa.to_bytes(),
            Self::CNAME(cname) => cname.to_bytes(),
            Self::MX(mx) => mx.to_bytes(),
            Self::NS(ns) => ns.to_bytes(),
            Self::SOA(soa) => soa.to_bytes(),
            Self::UNKNOWN(unknown) => unknown.to_bytes(),
        }
    }
}

// Parse RDATA
macro_rules! parse_rdata {
    ($rtype:expr, $packet:expr, $begin:expr, $($t:ident),*) => {
        match $rtype {
        $(
            RRType::$t => {
                let (rdata, end) = $t::parse($packet, $begin)?;
                (RRData::$t(rdata), end)
            }
        )*
            RRType::UNKNOWN(x) => {
                let (mut unknown, end) = UNKNOWN::parse_typeless($packet, $begin)?;
                unknown.set_type(x);
                (RRData::UNKNOWN(unknown), end)
            }
    }
    }
}

fn rdata_parse(ty: RRType, packet: Bytes, offset: usize) -> Result<(RRData, usize), PacketError> {
    let (rdata, end) = parse_rdata!(ty, packet, offset, A, AAAA, NS, CNAME, SOA, MX);
    Ok((rdata, end))
}

impl PacketContent for RR {
    fn parse(packet: bytes::Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        let mut p = packet.clone();
        let (domain, name_end) = Name::parse(packet.clone(), pos)?;
        p.advance(name_end);
        let ty = RRType::from(p.get_u16());
        let class = RRClass::from(p.get_u16());
        let ttl = p.get_u32();
        let rdata_begin = name_end + 6;
        let (rdata, rdata_end) = rdata_parse(ty, packet, rdata_begin)?;
        let size = rdata_end - pos;
        Ok(Self {
            domain,
            ty,
            class,
            ttl,
            size,
            rdata,
        })
    }

    #[inline]
    fn size(&self) -> usize {
        self.size
    }

    fn into_bytes(self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::new();
        buf.put(self.domain.as_bytes_uncompressed());
        buf.put_u16(self.ty.into());
        buf.put_u16(self.class.into());
        buf.put_u32(self.ttl);
        let rdata = self.rdata.to_bytes()?;
        buf.put_slice(&rdata[..]);
        Ok(buf)
    }
}
