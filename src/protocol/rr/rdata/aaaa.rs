// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{fmt::Display, net::Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::Rdata;
use crate::protocol::error::PacketError;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Aaaa {
    addr: u128,
}

impl Rdata for Aaaa {
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

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(18);
        buf.put_u16(16); // write RDLENGTH
        buf.put_u128(self.addr);
        Ok(buf)
    }
}

impl From<Ipv6Addr> for Aaaa {
    fn from(addr: Ipv6Addr) -> Self {
        Self { addr: addr.into() }
    }
}

impl From<Aaaa> for Ipv6Addr {
    fn from(record: Aaaa) -> Self {
        Ipv6Addr::from(record.addr)
    }
}

impl Display for Aaaa {
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
    assert!(Aaaa::parse(Bytes::from(invalid_buf), 0).is_err());

    let mut buf = BytesMut::new();
    buf.put_u16(16);
    buf.put_u128(addr.into());
    let rdata = Bytes::from(buf);
    let parsed = Aaaa::parse(rdata, 0);
    assert!(parsed.is_ok());
    let (aaaa, end) = parsed.unwrap();
    assert_eq!(aaaa, Aaaa::from(addr));
    assert_eq!(end, 18);
}

#[test]
fn test_to_bytes() {
    let addr = "0001:0001:0001:0001:0001:0001:0001:0001"
        .parse::<Ipv6Addr>()
        .unwrap();
    let aaaa = Aaaa::from(addr);
    let bytes = aaaa.try_into_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    let rdata = [0_u8, 16, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1];
    assert_eq!(bytes[..], rdata[..]);
}
