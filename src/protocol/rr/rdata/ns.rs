use bytes::Buf;

use crate::protocol::{domain::Name, error::PacketError};

use super::Rdata;

pub struct NS {
    domain: Name,
}

impl Rdata for NS {
    fn parse(packet: bytes::Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        let mut p = packet.clone();
        let length = p.get_u16() as usize;
        let pos = pos + 2;
        let end = pos + length;

        let (domain, _) = Name::parse(packet, pos)?;
        let ns = NS { domain };
        Ok((ns, end))
    }
}
