use std::net::Ipv4Addr;

use bytes::{Buf, Bytes};

use crate::protocol::error::PacketError;

use super::Rdata;
pub struct A {
    addr: u32,
}

impl Rdata for A {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        let mut data = packet;
        if pos >= data.len() {
            return Err(PacketError::FormatError);
        }
        data.advance(pos);
        let len = data.get_u16();
        if len != 4 {
            Err(PacketError::FormatError)
        } else {
            let end = pos + 8;
            Ok((
                Self {
                    addr: data.get_u32(),
                },
                end,
            ))
        }
    }
}

impl From<Ipv4Addr> for A {
    fn from(addr: Ipv4Addr) -> Self {
        Self { addr: addr.into() }
    }
}

impl Into<Ipv4Addr> for A {
    fn into(self) -> Ipv4Addr {
        Ipv4Addr::from(self.addr)
    }
}
