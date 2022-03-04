use std::net::Ipv6Addr;

use bytes::{Buf, Bytes};

use crate::protocol::error::PacketError;

use super::Rdata;

pub struct AAAA {
    addr: u128,
}

impl Rdata for AAAA {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        let mut buf = packet;
        if pos >= buf.len() {
            return Err(PacketError::FormatError);
        }
        buf.advance(pos);
        let len = buf.get_u32();
        if len != 16 {
            Err(PacketError::FormatError)
        } else {
            let end = pos + 20;
            Ok((
                Self {
                    addr: buf.get_u128(),
                },
                end,
            ))
        }
    }
}

impl From<Ipv6Addr> for AAAA {
    fn from(addr: Ipv6Addr) -> Self {
        Self { addr: addr.into() }
    }
}

impl Into<Ipv6Addr> for AAAA {
    fn into(self) -> Ipv6Addr {
        Ipv6Addr::from(self.addr)
    }
}
