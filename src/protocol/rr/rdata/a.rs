use std::{fmt::Display, net::Ipv4Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::error::PacketError;

use super::Rdata;

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct A {
    addr: u32,
}

impl Rdata for A {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        if pos + 6 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut data = packet;
        data.advance(pos);
        let len = data.get_u16();
        if len != 4 {
            Err(PacketError::FormatError)
        } else {
            let end = pos + 6;
            Ok((
                Self {
                    addr: data.get_u32(),
                },
                end,
            ))
        }
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(2 + 4);
        buf.put_u16(4); // write RDLENGTH
        buf.put_u32(self.addr);
        Ok(buf)
    }
}

impl From<Ipv4Addr> for A {
    fn from(addr: Ipv4Addr) -> Self {
        Self { addr: addr.into() }
    }
}

impl From<A> for Ipv4Addr {
    fn from(a: A) -> Self {
        Self::from(a.addr)
    }
}

impl Display for A {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = Ipv4Addr::from(self.addr);
        write!(f, "{}", addr)
    }
}

#[test]
fn test_parse() {
    // test parse invalid data
    let invalid = Bytes::from(vec![0_u8, 1_u8, 114, 5, 1, 4]);
    let parsed = A::parse(invalid, 0);
    assert!(parsed.is_err());

    let rdata = Bytes::from(vec![0, 4_u8, 114, 5, 1, 4]); // RDLENGTH and RDATA
    let pos = 0;
    let parsed = A::parse(rdata, pos);
    assert!(parsed.is_ok());
    let (a, end) = parsed.unwrap();
    assert_eq!(a, A::from("114.5.1.4".parse::<Ipv4Addr>().unwrap()));
    assert_eq!(end, 6);
}

#[test]
fn test_to_bytes() {
    let rdata = Bytes::from(vec![0_u8, 4, 191, 9, 8, 10]);
    let a = A::from("191.9.8.10".parse::<Ipv4Addr>().unwrap());
    let result = a.try_into_bytes();
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert_eq!(bytes[..], rdata[..]);
}
