use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{rr::rdata::Rdata, PacketError};

#[derive(Clone, Debug)]
pub struct HInfo {
    cpu: Vec<u8>,
    os: Vec<u8>,
}

impl Rdata for HInfo {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        if pos + 4 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut p = packet.clone();

        p.advance(pos);
        let rdlen = p.get_u16() as usize;
        let end = pos + 2 + rdlen;

        if end > packet.len() {
            return Err(PacketError::FormatError);
        }

        let c_len = p.get_u8();
        if (c_len + 1) as usize >= rdlen {
            return Err(PacketError::FormatError);
        }
        let cpu = Vec::from(&p[..(c_len as usize)]);
        let o_len = p.get_u8();
        if (c_len + 1 + o_len + 1) as usize > rdlen {
            return Err(PacketError::FormatError);
        }
        let os = Vec::from(&p[..(o_len as usize)]);
        Ok((Self { cpu, os }, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let total_len = self.cpu.len() + self.os.len() + 2;
        let mut buf = BytesMut::with_capacity(total_len);
        let len = u16::try_from(total_len).map_err(|_| PacketError::FormatError)?;
        buf.put_u16(len);
        buf.put_u8(self.cpu.len() as u8);
        buf.put(&self.cpu[..]);
        buf.put_u8(self.os.len() as u8);
        buf.put(&self.os[..]);
        Ok(buf)
    }
}
