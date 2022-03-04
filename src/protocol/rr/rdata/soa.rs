use bytes::{Buf, Bytes};

use crate::protocol::{domain::Name, error::PacketError};

use super::Rdata;

pub struct SOA {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expires: u32,
    minimum: u32,
}

impl Rdata for SOA {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        let mut pos = pos;
        let mut p = packet.clone();
        p.advance(pos);

        let length = p.get_u32() as usize;
        pos += 2;
        let (mname, m_end) = Name::parse(packet.clone(), pos)?;
        let (rname, r_end) = Name::parse(packet, m_end)?;

        p.advance(r_end - pos);
        let serial = p.get_u32();
        let refresh = p.get_u32();
        let retry = p.get_u32();
        let expires = p.get_u32();
        let minimum = p.get_u32();

        let soa = SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expires,
            minimum,
        };

        let end = r_end + 20;
        Ok((soa, end))
    }
}
