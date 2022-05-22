use std::fmt::{Debug, Display};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{rr::rdata::Rdata, PacketError};

#[derive(Clone, Debug)]
pub struct Txt {
    text: Vec<Vec<u8>>,
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
        let end = pos + 2 + len;

        let mut v = vec![];
        let mut read = 0;
        while read < len {
            let m_len = data.get_u8() as usize;
            read += m_len + 1;

            let txt = Vec::from(&data[..m_len]);
            data.advance(m_len);
            v.push(txt);
        }
        Ok((Self { text: v }, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let total_len = self.text.iter().fold(0, |acc, t| acc + t.len() + 1);
        let mut buf = BytesMut::with_capacity(2 + total_len);
        let rdlen = u16::try_from(total_len).map_err(|_| PacketError::FormatError)?;
        buf.put_u16(rdlen);
        for txt in self.text.iter() {
            let mut sub_buf = BytesMut::new();
            let len = txt.len() as u8;
            sub_buf.put_u8(len);
            sub_buf.put(txt.as_slice());
            buf.put(sub_buf);
        }
        Ok(buf)
    }
}

impl From<String> for Txt {
    fn from(s: String) -> Self {
        let v = s
            .split_whitespace()
            .map(|p| p.as_bytes().to_vec())
            .collect();
        Self { text: v }
    }
}

impl TryFrom<Txt> for String {
    type Error = PacketError;

    fn try_from(value: Txt) -> Result<Self, Self::Error> {
        let mut st = String::new();
        for v in value.text {
            let s = match String::from_utf8(v) {
                Ok(s) => Ok(s),
                Err(_) => Err(PacketError::FormatError),
            }?;
            st += s.as_str();
            st += "\n";
        }
        Ok(st)
    }
}

impl Display for Txt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match String::try_from(self.clone()) {
            Ok(s) => s,
            Err(_) => return self.text.fmt(f),
        };

        write!(f, "{}", s)
    }
}

#[test]
fn test_parse() {
    // test parse invalid data
    let invalid = Bytes::from(vec![0_u8, 7, 6, b'1', b'1', b'4', b'5', b'1']);
    let parsed = Txt::parse(invalid, 0);
    assert!(parsed.is_err());

    let rdata = Bytes::from(vec![0_u8, 7, 6, b'1', b'1', b'4', b'5', b'1', b'4']);
    let parsed = Txt::parse(rdata, 0);
    assert!(parsed.is_ok());
    let (txt, end) = parsed.unwrap();
    assert_eq!(String::try_from(txt).unwrap(), "114514\n".to_string());
    assert_eq!(end, 9);
}

#[test]
fn test_to_bytes() {
    let s = String::from("114514");
    let rdata = Txt::from(s);
    let b = rdata.try_into_bytes().unwrap();
    let rdata = [0_u8, 7, 6, b'1', b'1', b'4', b'5', b'1', b'4'];
    assert_eq!(&rdata, b.as_ref());
}
