use std::fmt::Display;

use bytes::{Buf, BufMut, BytesMut};

use crate::protocol::{domain::Name, error::PacketError};

use super::{try_into_rdata_length, Rdata};

#[derive(PartialEq, Debug, Clone)]
pub struct NS {
    domain: Name,
}

impl Rdata for NS {
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
        let ns = NS { domain };
        if domain_end == end {
            Ok((ns, end))
        } else {
            Err(PacketError::FormatError)
        }
    }

    fn to_bytes(&self) -> Result<BytesMut, PacketError> {
        let v = self.domain.as_bytes_uncompressed();
        let mut buf = BytesMut::with_capacity(v.len() + 2);
        let rdlength = try_into_rdata_length(v.len())?;
        buf.put_u16(rdlength);
        buf.put_slice(&self.domain.as_bytes_uncompressed()[..]);
        Ok(buf)
    }
}

impl From<Name> for NS {
    fn from(n: Name) -> Self {
        Self { domain: n }
    }
}

impl From<NS> for Name {
    fn from(ns: NS) -> Self {
        ns.domain
    }
}

impl Display for NS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain)
    }
}

#[cfg(test)]
mod ns_tests {
    use super::{Name, Rdata, NS};
    use bytes::Bytes;
    #[test]
    fn test_parse() {
        // test invalid
        let invalid = Bytes::from(b"\x00\x0f\x07example\x03com\x00".to_vec());
        let parsed = NS::parse(invalid, 0);
        assert!(parsed.is_err());

        let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
        let parsed = NS::parse(rdata.clone(), 0);
        assert!(parsed.is_ok());
        let (ns, end) = parsed.unwrap();
        let target = NS::from(Name::try_from("example.com").unwrap());
        assert_eq!(end, rdata.len());
        assert_eq!(ns, target);
    }

    #[test]
    fn test_to_bytes() {
        let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
        let ns = NS::from(Name::try_from("example.com").unwrap());
        let bytes = ns.to_bytes();
        assert!(bytes.is_ok());
        let bytes = bytes.unwrap();
        assert_eq!(bytes[..], rdata[..]);
    }
}
