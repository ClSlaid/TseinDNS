use crate::protocol::error::PacketError;

use super::{try_into_rdata_length, Name, Rdata};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug)]
pub struct MX {
    preference: u16,
    domain: Name,
}

impl MX {
    pub fn get_preference(&self) -> u16 {
        self.preference
    }
    pub fn get_domain(&self) -> Name {
        self.domain.clone()
    }
}

impl Rdata for MX {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        if pos + (2 + 2 + 2) > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut p = packet.clone();
        p.advance(pos);

        let length = p.get_u16() as usize;
        let preference = p.get_u16();

        let end = length + pos + 2;

        let pos = pos + 4;

        let (domain, domain_end) = Name::parse(packet.clone(), pos)?;
        let mx = MX { preference, domain };
        if domain_end == end {
            Ok((mx, end))
        } else {
            Err(PacketError::FormatError)
        }
    }

    fn to_bytes(&self) -> Result<BytesMut, PacketError> {
        let v = self.domain.as_bytes_uncompressed();
        let mut buf = BytesMut::with_capacity(v.len() + 4);
        let rdlength = try_into_rdata_length(v.len())?;

        buf.put_u16(rdlength + 2); // write RDLENGTH

        buf.put_u16(self.preference);
        buf.put_slice(&self.domain.as_bytes_uncompressed()[..]);
        Ok(buf)
    }
}

#[test]
fn test_parse() {
    // test invalid
    let invalid = Bytes::from(b"\x00\x08\x00\x0a\x07example\x03com\x00".to_vec());
    let parsed = MX::parse(invalid, 0);
    assert!(parsed.is_err());

    let target = Bytes::from(b"\x00\x0f\x00\x0a\x07example\x03com\x00".to_vec());
    let parsed = MX::parse(target.clone(), 0);
    assert!(parsed.is_ok());
    let (mx, end) = parsed.unwrap();
    assert_eq!(end, target.len());
    assert_eq!(mx.get_preference(), 10);
    assert_eq!(mx.get_domain(), Name::try_from("example.com").unwrap());
}

#[test]
fn test_to_bytes() {
    let target = Bytes::from(b"\x00\x0f\x00\x0a\x07example\x03com\x00".to_vec());
    let mx = MX {
        preference: 10,
        domain: Name::try_from("example.com").unwrap(),
    };
    let bytes = mx.to_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    assert_eq!(bytes[..], target[..]);
}
