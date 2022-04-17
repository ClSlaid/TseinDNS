use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{error::PacketError, rr::RRType};

use super::Rdata;

#[derive(Debug, Clone)]
pub struct Unknown {
    rtype: RRType,
    length: usize,
    data: Bytes, // TODO: data maybe empty, fix it
}

impl Unknown {
    pub fn get_type(&self) -> RRType {
        self.rtype
    }

    pub fn set_type(&mut self, rtype: u16) {
        self.rtype = RRType::UNKNOWN(rtype);
    }

    pub fn parse_typeless(packet: bytes::Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        let mut p = packet;
        let length = p.get_u16() as usize;
        let data = Bytes::copy_from_slice(&p[..length]);
        let unknown = Self {
            length,
            rtype: RRType::UNKNOWN(255), // always set as 255
            data,
        };
        let end = pos + 2 + length;
        Ok((unknown, end))
    }
}

impl Rdata for Unknown {
    /// Warning: will look backward to other fields in RR.
    /// use only when parsing at least a whole RR.
    fn parse(packet: bytes::Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        let packet_len = packet.len();
        if pos < 8 || pos > packet_len {
            return Err(PacketError::FormatError);
        }

        // Get type of unknown
        let type_pos = pos - 8;
        let mut p = packet.clone();
        p.advance(type_pos);
        let tp = p.get_u16();

        // Parse remaining parts of the packet
        let mut p = packet;
        p.advance(pos);
        let length = p.get_u16() as usize;

        if length + pos > packet_len {
            return Err(PacketError::FormatError);
        }

        let data = Bytes::copy_from_slice(&p[..length]);
        let unknown = Self {
            length,
            rtype: RRType::UNKNOWN(tp),
            data,
        };
        let end = pos + 2 + length;
        Ok((unknown, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(self.length + 2);
        buf.put_u16(self.length as u16);
        buf.put_slice(&self.data);
        Ok(buf)
    }
}

#[test]
fn test_set_rtype() {
    let rtype = RRType::UNKNOWN(233);
    let length = 0;
    let data = Bytes::new();
    let mut u = Unknown {
        rtype,
        length,
        data,
    };
    assert_eq!(u.get_type(), rtype);

    let rtype = 114;
    u.set_type(rtype);
    assert_eq!(u.get_type(), RRType::from(rtype));
}

#[test]
fn test_parse_and_to_bytes() {
    // test invalid
    let invalid = Bytes::from([0_u8, 10, 0, 0, 2, 0].to_vec());
    let parsed = Unknown::parse(invalid, 0);
    assert!(parsed.is_err());
    // test without type
    let data = Bytes::from([0_u8, 4, 0, 0, 2, 0].to_vec());
    let parsed = Unknown::parse(data.clone(), 0);
    assert!(parsed.is_err());
    // test parse_typeless and to_bytes()
    let parsed = Unknown::parse_typeless(data.clone(), 0);
    let (unknown, end) = parsed.unwrap();
    assert_eq!(end, data.len());
    assert_eq!(unknown.try_into_bytes().unwrap()[..], data[..]);
    // test parse()
    let full_data = Bytes::from(
        [
            0, 233_u8, 0, 0, 0, 0, 0, 0, // 233 is the unknown type
            0_u8, 4, 0, 0, 2, 0, // this line is rdlength and rdata section
        ]
        .to_vec(),
    );
    let parsed = Unknown::parse(full_data.clone(), 8);
    assert!(parsed.is_ok());
    let (unknown, end) = parsed.unwrap();
    assert_eq!(end, full_data.len());
    assert_eq!(unknown.get_type(), RRType::from(233));
    assert_eq!(unknown.try_into_bytes().unwrap()[..], data[..]);
}
