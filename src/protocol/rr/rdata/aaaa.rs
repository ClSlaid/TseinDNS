use std::{fmt::Display, net::Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::error::PacketError;

use super::Rdata;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AAAA {
    addr: u128,
}

impl Rdata for AAAA {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        if pos + (16 + 128) / 8 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut buf = packet;
        buf.advance(pos);
        let len = buf.get_u16();
        if len != 16 {
            Err(PacketError::FormatError)
        } else {
            let end = pos + (16 + 128) / 8;
            Ok((
                Self {
                    addr: buf.get_u128(),
                },
                end,
            ))
        }
    }

    fn to_bytes(&self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(18);
        buf.put_u16(16); // write RDLENGTH
        buf.put_u128(self.addr);
        Ok(buf)
    }
}

impl From<Ipv6Addr> for AAAA {
    fn from(addr: Ipv6Addr) -> Self {
        Self { addr: addr.into() }
    }
}

impl From<AAAA> for Ipv6Addr {
    fn from(record: AAAA) -> Self {
        Ipv6Addr::from(record.addr)
    }
}

impl Display for AAAA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = Ipv6Addr::from(self.addr);
        write!(f, "{}", addr)
    }
}

#[test]
fn test_parse() {
    let addr = "0001:0001:0001:0001:0001:0001:0001:0001"
        .parse::<Ipv6Addr>()
        .unwrap();

    // test invalid data
    let mut invalid_buf = BytesMut::new();
    invalid_buf.put_u16(23);
    invalid_buf.put_u8(23);
    assert!(AAAA::parse(Bytes::from(invalid_buf), 0).is_err());

    let mut buf = BytesMut::new();
    buf.put_u16(16);
    buf.put_u128(addr.into());
    let rdata = Bytes::from(buf);
    let parsed = AAAA::parse(rdata, 0);
    assert!(parsed.is_ok());
    let (aaaa, end) = parsed.unwrap();
    assert_eq!(aaaa, AAAA::from(addr));
    assert_eq!(end, 18);
}

#[test]
fn test_to_bytes() {
    let addr = "0001:0001:0001:0001:0001:0001:0001:0001"
        .parse::<Ipv6Addr>()
        .unwrap();
    let aaaa = AAAA::from(addr);
    let bytes = aaaa.to_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    let rdata = [0_u8, 16, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
    assert_eq!(bytes[..], rdata[..]);
}
