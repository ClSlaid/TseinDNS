// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rdata::{
    a::A, aaaa::Aaaa, cname::Cname, hinfo::HInfo, mg::Mg, minfo::MInfo, mx::Mx, nl::Null, ns::Ns,
    pt::Ptr, soa::Soa, txt::Txt, unknown::Unknown, wks::Wks, Rdata,
};
use tokio::time;

use super::{domain::Name, error::PacketError, RRClass};
use crate::protocol::{
    rr::rdata::{mb::Mb, mr::Mr},
    PacketContent, RRType,
};

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
    HInfo(HInfo),
    Ptr(Ptr),
    Mx(Mx),
    Mb(Mb),
    Mg(Mg),
    Mr(Mr),
    Wks(Wks),
    Null(Null),
    MInfo(MInfo),
    Ns(Ns),
    Soa(Soa),
    Txt(Txt),
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
            Self::Mb(_) => RRType::Mb,
            Self::Mg(_) => RRType::Mg,
            Self::Soa(_) => RRType::Soa,
            Self::Txt(_) => RRType::Txt,
            Self::Wks(_) => RRType::Wks,
            Self::Ptr(_) => RRType::Ptr,
            Self::Mr(_) => RRType::Mr,
            Self::MInfo(_) => RRType::MInfo,
            Self::HInfo(_) => RRType::HInfo,
            Self::Null(_) => RRType::Null,
            Self::Unknown(unknown) => unknown.get_type(),
        }
    }
    pub fn try_into_bytes(self) -> Result<BytesMut, PacketError> {
        match self {
            Self::A(a) => a.try_into_bytes(),
            Self::Aaaa(aaaa) => aaaa.try_into_bytes(),
            Self::Cname(cname) => cname.try_into_bytes(),
            Self::Mx(mx) => mx.try_into_bytes(),
            Self::Mb(mb) => mb.try_into_bytes(),
            Self::Mg(mg) => mg.try_into_bytes(),
            Self::Ns(ns) => ns.try_into_bytes(),
            Self::Soa(soa) => soa.try_into_bytes(),
            Self::Ptr(ptr) => ptr.try_into_bytes(),
            Self::Mr(mr) => mr.try_into_bytes(),
            Self::Wks(wks) => wks.try_into_bytes(),
            Self::MInfo(m_info) => m_info.try_into_bytes(),
            Self::HInfo(h_info) => h_info.try_into_bytes(),
            Self::Null(null) => null.try_into_bytes(),
            Self::Txt(txt) => txt.try_into_bytes(),
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
    let (rdata, end) = parse_rdata!(
        ty, packet, offset, A, Aaaa, Ns, Cname, Mb, Mg, Mr, MInfo, HInfo, Null, Ptr, Wks, Soa, Txt,
        Mx
    );
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
        tracing::trace!("parsed with type:{}", ty);
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

#[cfg(test)]
mod rr_test {
    use std::{net::Ipv4Addr, time};

    use crate::protocol::{Name, PacketContent, RRClass, RRData, RRType, RR};

    #[test]
    fn test_getters() {
        let a = super::A::from("11.4.5.14".parse::<Ipv4Addr>().unwrap());
        let name = Name::try_from("example.com").unwrap();
        let du = time::Duration::from_secs(114514);
        let rr = RR::new(name, du, RRClass::Internet, RRData::A(a));
        assert_eq!(rr.get_ttl(), du);
        assert_eq!(rr.get_domain().to_string(), "example.com.");
        assert_eq!(rr.get_type(), RRType::A);
    }

    #[test]
    fn test_setters() {
        let a = super::A::from("11.4.5.14".parse::<Ipv4Addr>().unwrap());
        let name = Name::try_from("example.com").unwrap();
        let du = time::Duration::from_secs(114514);
        let mut rr = RR::new(name, du, RRClass::Internet, RRData::A(a));

        assert_eq!(rr.get_ttl(), du);
        let new_du = time::Duration::from_secs(1919810);
        rr.set_ttl(new_du);
        assert_eq!(rr.get_ttl(), new_du);
    }

    #[test]
    fn test_to_bytes_and_parse() {
        let a = super::A::from("19.19.81.0".parse::<Ipv4Addr>().unwrap());
        let name = Name::try_from("example.com").unwrap();
        let du = time::Duration::from_secs(114514);
        let rr = RR::new(name, du, RRClass::Internet, RRData::A(a));
        let rdata = match rr.clone().into_rdata() {
            RRData::A(a) => a,
            _ => {
                unreachable!()
            }
        };
        assert_eq!(rdata, a);
        let bytes = rr.clone().into_bytes().unwrap();
        let parsed = RR::parse(bytes.into(), 0);
        assert!(parsed.is_ok());
        let parsed_rr = parsed.unwrap();
        assert_eq!(parsed_rr.get_ttl(), du);
        assert_eq!(parsed_rr.get_type(), rr.get_type());
        assert_eq!(parsed_rr.get_domain(), rr.get_domain());
    }
}
