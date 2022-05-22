use std::fmt::Display;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{
    rr::rdata::{try_into_rdata_length, Rdata},
    Name, PacketError,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Ptr {
    domain: Name,
}

impl Rdata for Ptr {
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

impl From<Name> for Ptr {
    fn from(name: Name) -> Self {
        Self { domain: name }
    }
}

impl From<Ptr> for Name {
    fn from(mb: Ptr) -> Self {
        mb.domain
    }
}

impl Display for Ptr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.domain)
    }
}

#[test]
fn test_parse() {
    // test invalid
    let invalid = Bytes::from(b"\x00\x0f\x07example\x03com\x00".to_vec());
    let parsed = Ptr::parse(invalid, 0);
    assert!(parsed.is_err());

    let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
    let parsed = Ptr::parse(rdata.clone(), 0);
    assert!(parsed.is_ok());
    let (pt, end) = parsed.unwrap();
    let target = Ptr::from(Name::try_from("example.com").unwrap());
    assert_eq!(end, rdata.len());
    assert_eq!(pt, target);
}

#[test]
fn test_to_bytes() {
    let rdata = Bytes::from(b"\x00\x0d\x07example\x03com\x00".to_vec());
    let pt = Ptr::from(Name::try_from("example.com").unwrap());
    let bytes = pt.try_into_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    assert_eq!(bytes[..], rdata[..]);
}
