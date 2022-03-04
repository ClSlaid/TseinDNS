use crate::protocol::error::PacketError;

use super::{Name, Rdata};
use bytes::{Buf, Bytes};

pub struct MX {
    preference: u16,
    domain: Name,
}

impl Rdata for MX {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        let mut p = packet.clone();
        p.advance(pos);

        let length = p.get_u16() as usize;
        let preference = p.get_u16();

        let pos = pos + 4;
        let end = length + pos;

        let (domain, _) = Name::parse(packet.clone(), pos)?;
        let mx = MX { preference, domain };
        Ok((mx, end))
    }
}
