// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::fmt::Display;

use bytes::{Buf, BufMut, BytesMut};

use super::{try_into_rdata_length, Rdata};
use crate::protocol::{domain::Name, error::PacketError};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Ns {
    domain: Name,
}

impl Rdata for Ns {
    fn parse(packet: bytes::Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        if pos + 4 > packet.len() {
            return Err(PacketError::FormatError);
        }
        let mut p = packet.clone();
        let length = p.get_u16() as usize;
        let pos = pos + 2;
        let end = pos + length;

        let (domain, domain_end) = Name::parse(packet, pos)?;
        let ns = Ns { domain };
        if domain_end == end {
            Ok((ns, end))
        } else {
            Err(PacketError::FormatError)
        }
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let v = self.domain.as_bytes_uncompressed();
        let mut buf = BytesMut::with_capacity(v.len() + 2);
        let rdlength = try_into_rdata_length(v.len())?;
        buf.put_u16(rdlength);
        buf.put_slice(&self.domain.as_bytes_uncompressed()[..]);
        Ok(buf)
    }
}

impl From<Name> for Ns {
    fn from(n: Name) -> Self {
        Self { domain: n }
    }
}

impl From<Ns> for Name {
    fn from(ns: Ns) -> Self {
        ns.domain
    }
}

impl Display for Ns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain)
    }
}

#[cfg(test)]
mod ns_tests {
    use bytes::Bytes;

    use super::{Name, Ns, Rdata};

    #[test]
    fn test_parse() {
        // test invalid
        let invalid = Bytes::from(b"\x00\x0f\x07example\x03com\x00".to_vec());
        let parsed = Ns::parse(invalid, 0);
        assert!(parsed.is_err());

        let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
        let parsed = Ns::parse(rdata.clone(), 0);
        assert!(parsed.is_ok());
        let (ns, end) = parsed.unwrap();
        let target = Ns::from(Name::try_from("example.com").unwrap());
        assert_eq!(end, rdata.len());
        assert_eq!(ns, target);
    }

    #[test]
    fn test_to_bytes() {
        let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
        let ns = Ns::from(Name::try_from("example.com").unwrap());
        let bytes = ns.try_into_bytes();
        assert!(bytes.is_ok());
        let bytes = bytes.unwrap();
        assert_eq!(bytes[..], rdata[..]);
    }
}
