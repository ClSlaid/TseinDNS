use std::fmt::Display;

use crate::protocol::error::PacketError;

use super::{try_into_rdata_length, Name, Rdata};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, PartialEq)]
pub struct CNAME {
    domain: Name,
}

impl Rdata for CNAME {
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

impl From<Name> for CNAME {
    fn from(name: Name) -> Self {
        Self { domain: name }
    }
}

impl From<CNAME> for Name {
    fn from(cname: CNAME) -> Self {
        cname.domain
    }
}

impl Display for CNAME {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain)
    }
}

#[test]
fn test_parse() {
    // test invalid
    let invalid = Bytes::from(b"\x00\x0f\x07example\x03com\x00".to_vec());
    let parsed = CNAME::parse(invalid, 0);
    assert!(parsed.is_err());

    let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
    let parsed = CNAME::parse(rdata.clone(), 0);
    assert!(parsed.is_ok());
    let (cname, end) = parsed.unwrap();
    let target = CNAME::from(Name::try_from("example.com").unwrap());
    assert_eq!(end, rdata.len());
    assert_eq!(cname, target);
}

#[test]
fn test_to_bytes() {
    let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
    let cname = CNAME::from(Name::try_from("example.com").unwrap());
    let bytes = cname.try_into_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    assert_eq!(bytes[..], rdata[..]);
}
