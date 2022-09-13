use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{rr::rdata::Rdata, PacketError};

#[derive(Clone, Debug)]
pub struct Wks {
    addr: u32,
    proto: u8,
    bmp: Vec<u8>,
}

impl Rdata for Wks {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        if pos + 7 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut pos = pos;
        let mut p = packet;
        if pos + 2 >= p.len() {
            return Err(PacketError::FormatError);
        }
        p.advance(pos);
        pos += 2;
        let mut rdata_length = p.get_u16() as usize;
        let end = rdata_length + pos;

        let addr = p.get_u32();
        let proto = p.get_u8();
        rdata_length -= 5;
        let bmp = Vec::from(&p[..rdata_length]);

        let wks = Wks { addr, proto, bmp };
        Ok((wks, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::new();
        buf.put_u32(self.addr);
        buf.put_u8(self.proto);
        buf.put(&self.bmp.clone()[..]);
        Ok(buf)
    }
}

#[test]
fn test_parse() {
    let invalid = Bytes::from(b"\x00\x0f\x01\x01".to_vec());
    let parsed = Wks::parse(invalid, 0);
    assert!(parsed.is_err());
}
