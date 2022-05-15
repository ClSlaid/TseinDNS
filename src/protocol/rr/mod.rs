// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rdata::{a::A, aaaa::Aaaa, cname::Cname, mx::Mx, ns::Ns, soa::Soa, unknown::Unknown, Rdata};
use tokio::time;

use super::{domain::Name, error::PacketError, RRClass};
use crate::protocol::{PacketContent, RRType};

mod rdata;

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
#[derive(Debug, Clone)]
pub struct RR {
    domain: Name,
    ttl: u32,
    ty: RRType,
    class: RRClass,
    size: usize,
    // total length of RR in packet
    r_data: RRData,
}

impl RR {
    pub fn new(domain: Name, ttl: time::Duration, class: RRClass, r_data: RRData) -> Self {
        let ty = r_data.get_type();
        let seconds = ttl.as_secs() as u32;
        RR {
            domain,
            ttl: seconds,
            ty,
            class,
            size: 0,
            r_data,
        }
    }
    pub fn get_domain(&self) -> Name {
        self.domain.clone()
    }
    pub fn get_type(&self) -> RRType {
        self.ty
    }
    pub fn into_rdata(self) -> RRData {
        self.r_data
    }
    pub fn get_ttl(&self) -> time::Duration {
        time::Duration::from_secs(self.ttl as u64)
    }
    pub fn set_ttl(&mut self, ttl: time::Duration) {
        self.ttl = ttl.as_secs() as u32;
    }
}

// TODO: replace redundant code with macron
/// ## RRData
/// The `RRData` section of `RR`.
/// It also implicitly points out the `TYPE` of `RR`.
#[derive(Debug, Clone)]
pub enum RRData {
    A(A),
    Aaaa(Aaaa),
    Cname(Cname),
    Mx(Mx),
    Ns(Ns),
    Soa(Soa),
    Unknown(Unknown),
}

impl RRData {
    pub fn get_type(&self) -> RRType {
        match self {
            Self::A(_) => RRType::A,
            Self::Aaaa(_) => RRType::Aaaa,
            Self::Cname(_) => RRType::Cname,
            Self::Mx(_) => RRType::Mx,
            Self::Ns(_) => RRType::Ns,
            Self::Soa(_) => RRType::Soa,
            Self::Unknown(unknown) => unknown.get_type(),
        }
    }
    pub fn try_into_bytes(self) -> Result<BytesMut, PacketError> {
        match self {
            Self::A(a) => a.try_into_bytes(),
            Self::Aaaa(aaaa) => aaaa.try_into_bytes(),
            Self::Cname(cname) => cname.try_into_bytes(),
            Self::Mx(mx) => mx.try_into_bytes(),
            Self::Ns(ns) => ns.try_into_bytes(),
            Self::Soa(soa) => soa.try_into_bytes(),
            Self::Unknown(unknown) => unknown.try_into_bytes(),
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
                let (mut unknown, end) = Unknown::parse_typeless($packet, $begin)?;
                unknown.set_type(x);
                (RRData::Unknown(unknown), end)
            }
    }
    }
}

fn rdata_parse(ty: RRType, packet: Bytes, offset: usize) -> Result<(RRData, usize), PacketError> {
    let (rdata, end) = parse_rdata!(ty, packet, offset, A, Aaaa, Ns, Cname, Soa, Mx);
    Ok((rdata, end))
}

impl PacketContent for RR {
    #[inline]
    fn size(&self) -> usize {
        self.size
    }

    fn parse(packet: Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        let mut p = packet.clone();
        let (domain, name_end) = Name::parse(packet.clone(), pos)?;
        p.advance(name_end);
        let ty = RRType::from(p.get_u16());
        let class = RRClass::from(p.get_u16());
        let ttl = p.get_u32();
        let rdata_begin = name_end + 8;
        let (rdata, rdata_end) = rdata_parse(ty, packet, rdata_begin)?;
        let size = rdata_end - pos;
        Ok(Self {
            domain,
            ty,
            class,
            ttl,
            size,
            r_data: rdata,
        })
    }

    fn into_bytes(self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::new();
        buf.put(self.domain.as_bytes_uncompressed());
        buf.put_u16(self.ty.into());
        buf.put_u16(self.class.into());
        buf.put_u32(self.ttl);
        let rdata = self.r_data.try_into_bytes()?;
        buf.put_slice(&rdata[..]);
        Ok(buf)
    }
}
