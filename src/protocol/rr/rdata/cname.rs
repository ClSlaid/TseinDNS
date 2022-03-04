use crate::protocol::error::PacketError;

use super::{Name, Rdata};
use bytes::{Buf, Bytes};

pub struct CNAME {
    domain: Name,
}

impl Rdata for CNAME {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        let mut pos = pos;
        let mut p = packet.clone();

        if pos + 1 >= p.len() {
            return Err(PacketError::FormatError);
        }
        p.advance(pos);
        let end = p.get_u32() as usize + pos;

        pos += 2;

        let (domain, _) = Name::parse(packet, pos)?;
        Ok((Self { domain }, end))
    }
}
