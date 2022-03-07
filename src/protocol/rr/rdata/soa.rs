use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{domain::Name, error::PacketError};

use super::{try_into_rdata_length, Rdata};

#[derive(Debug, Clone, PartialEq)]
pub struct SOA {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expires: u32,
    minimum: u32,
}

impl Rdata for SOA {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        let packet_len = packet.len();
        if pos + (2 + 2 * 2 + 4 * 5) > packet_len {
            return Err(PacketError::FormatError);
        }

        let mut pos = pos;
        let mut p = packet.clone();
        p.advance(pos);

        let length = p.get_u16() as usize;
        pos += 2;
        let (mname, m_end) = Name::parse(packet.clone(), pos)?;
        let (rname, r_end) = Name::parse(packet, m_end)?;

        p.advance(r_end - pos);
        if r_end + 20 > packet_len {
            return Err(PacketError::FormatError);
        }

        let serial = p.get_u32();
        let refresh = p.get_u32();
        let retry = p.get_u32();
        let expires = p.get_u32();
        let minimum = p.get_u32();

        let soa = SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expires,
            minimum,
        };

        let end = r_end + 20;

        if end - pos != length {
            Err(PacketError::FormatError)
        } else {
            Ok((soa, end))
        }
    }

    fn to_bytes(&self) -> Result<BytesMut, PacketError> {
        let mname = self.mname.as_bytes_uncompressed();
        let rname = self.rname.as_bytes_uncompressed();
        let length = mname.len() + rname.len() + 4 * 5;
        let rdlength = try_into_rdata_length(length)?;
        let mut buf = BytesMut::with_capacity(length + 2);
        buf.put_u16(rdlength);
        buf.put_slice(&self.mname.as_bytes_uncompressed()[..]);
        buf.put_slice(&self.rname.as_bytes_uncompressed()[..]);
        buf.put_u32(self.serial);
        buf.put_u32(self.refresh);
        buf.put_u32(self.retry);
        buf.put_u32(self.expires);
        buf.put_u32(self.minimum);
        Ok(buf)
    }
}
#[test]
fn test_parse_and_to_bytes() {
    let mname = Name::try_from("alpha.com").unwrap().as_bytes_uncompressed();
    let rname = Name::try_from("bravo.com").unwrap().as_bytes_uncompressed();
    let serial = 114_u32;
    let refresh = 514_u32;
    let retry = 19_u32;
    let expires = 19_u32;
    let minimum = 810_u32;
    let mut invalid = BytesMut::new();

    // test invalid
    invalid.put_u16(73);
    invalid.put_slice(&mname[..]);
    invalid.put_slice(&rname[..]);
    let invalid = Bytes::from(invalid);

    let parsed = SOA::parse(invalid, 0);
    assert!(parsed.is_err());

    let target = SOA {
        mname: Name::try_from("alpha.com").unwrap(),
        rname: Name::try_from("bravo.com").unwrap(),
        serial,
        refresh,
        retry,
        expires,
        minimum,
    };

    let mut buf = BytesMut::new();
    let length = try_into_rdata_length(mname.len() + rname.len() + 4 * 5).unwrap();
    buf.put_u16(length);
    buf.put_slice(&mname[..]);
    buf.put_slice(&rname[..]);
    buf.put_u32(serial);
    buf.put_u32(refresh);
    buf.put_u32(retry);
    buf.put_u32(expires);
    buf.put_u32(minimum);

    let buf = Bytes::from(buf);
    let len = buf.len();

    let parsed = SOA::parse(buf.clone(), 0);
    assert!(parsed.is_ok());
    let (soa, end) = parsed.unwrap();
    assert_eq!(end, len);
    assert_eq!(soa, target);

    let bytes = soa.to_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    assert_eq!(bytes[..], buf[..]);
}
