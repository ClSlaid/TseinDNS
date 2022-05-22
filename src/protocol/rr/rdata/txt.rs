use std::fmt::{Debug, Display};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{rr::rdata::Rdata, PacketError};

#[derive(Clone, Debug)]
pub struct Txt {
    text: Vec<u8>,
}

impl Rdata for Txt {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError> {
        if pos + 2 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut data = packet.clone();
        data.advance(pos);
        let len = data.get_u16() as usize;
        if pos + 2 + len > packet.len() {
            return Err(PacketError::FormatError);
        }
        let v = Vec::from(&data[..len]);
        let end = pos + 2 + len;
        Ok((Self { text: v }, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(2 + self.text.len());
        buf.put_u16(self.text.len() as u16);
        buf.put(self.text.as_slice());
        Ok(buf)
    }
}

impl From<String> for Txt {
    fn from(s: String) -> Self {
        let v = s.as_bytes().to_vec();
        Self { text: v }
    }
}

impl TryFrom<Txt> for String {
    type Error = PacketError;

    fn try_from(value: Txt) -> Result<Self, Self::Error> {
        match String::from_utf8(value.text) {
            Ok(s) => Ok(s),
            Err(_) => Err(PacketError::FormatError),
        }
    }
}

impl Display for Txt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match String::from_utf8(self.text.clone()) {
            Ok(s) => s,
            Err(_) => return self.text.fmt(f),
        };

        write!(f, "{}", s)
    }
}

#[test]
fn test_parse() {
    // test parse invalid data
    let invalid = Bytes::from(vec![0_u8, 6, b'1', b'1', b'4', b'5', b'1']);
    let parsed = Txt::parse(invalid, 0);
    assert!(parsed.is_err());

    let rdata = Bytes::from(vec![0_u8, 6, b'1', b'1', b'4', b'5', b'1', b'4']);
    let parsed = Txt::parse(rdata, 0);
    assert!(parsed.is_ok());
    let (txt, end) = parsed.unwrap();
    assert_eq!(String::try_from(txt).unwrap(), "114514".to_string());
    assert_eq!(end, 8);
}

#[test]
fn test_to_bytes() {
    let s = String::from("114514");
    let rdata = Txt::from(s);
    let b = rdata.try_into_bytes().unwrap();
    let rdata = [0_u8, 6, b'1', b'1', b'4', b'5', b'1', b'4'];
    assert_eq!(&rdata, b.as_ref());
}
