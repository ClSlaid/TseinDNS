// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Display;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{try_into_rdata_length, Name, Rdata};
use crate::protocol::error::PacketError;

#[derive(Clone, Debug, PartialEq)]
pub struct Mr {
    domain: Name,
}

impl Rdata for Mr {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        if pos + 4 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut pos = pos;
        let mut p = packet.clone();
        if pos + 1 >= p.len() {
            return Err(PacketError::FormatError);
        }
        p.advance(pos);
        pos += 2;
        let end = p.get_u16() as usize + pos;

        let (domain, domain_end) = Name::parse(packet, pos)?;
        if end == domain_end {
            Ok((Self { domain }, end))
        } else {
            Err(PacketError::FormatError)
        }
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let v = self.domain.as_bytes_uncompressed();
        let rdlength = try_into_rdata_length(v.len())?;
        let mut buf = BytesMut::with_capacity(v.len() + 2);
        buf.put_u16(rdlength); // write RDLENGTH
        buf.put_slice(&v[..]);
        Ok(buf)
    }
}

impl From<Name> for Mr {
    fn from(name: Name) -> Self {
        Self { domain: name }
    }
}

impl From<Mr> for Name {
    fn from(mr: Mr) -> Self {
        mr.domain
    }
}

impl Display for Mr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain)
    }
}

#[test]
fn test_parse() {
    // test invalid
    let invalid = Bytes::from(b"\x00\x0f\x07example\x03com\x00".to_vec());
    let parsed = Mr::parse(invalid, 0);
    assert!(parsed.is_err());

    let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
    let parsed = Mr::parse(rdata.clone(), 0);
    assert!(parsed.is_ok());
    let (mr, end) = parsed.unwrap();
    let target = Mr::from(Name::try_from("example.com").unwrap());
    assert_eq!(end, rdata.len());
    assert_eq!(mr, target);
}

#[test]
fn test_to_bytes() {
    let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
    let mr = Mr::from(Name::try_from("example.com").unwrap());
    let bytes = mr.try_into_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    assert_eq!(bytes[..], rdata[..]);
}
