use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{rr::rdata::Rdata, PacketError};

#[derive(Clone, Debug)]
pub struct Null {
    data: Vec<u8>,
}

impl Rdata for Null {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        if pos + 2 >= packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut p = packet;
        p.advance(pos);
        let len = p.get_u16() as usize;
        let end = len + pos + 2;

        let data = Vec::from(&p[..len]);
        let null = Null { data };
        Ok((null, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let len = self.data.len() as u16;
        let mut buf = BytesMut::new();
        buf.put_u16(len);
        buf.put(&self.data[..]);
        Ok(buf)
    }
}
