use bytes::{Buf, BufMut, BytesMut};

use super::{domain::Name, error::PacketError, PacketContent, RRClass, RRType};

pub struct Question {
    name: Name,
    ty: RRType,
    class: RRClass,
    size: usize,
}

impl PacketContent for Question {
    fn size(&self) -> usize {
        self.size
    }

    fn parse(packet: bytes::Bytes, pos: usize) -> Result<Self, PacketError>
    where
        Self: Sized,
    {
        let (name, end) = Name::parse(packet.clone(), pos)?;
        let mut p = packet;
        p.advance(end);
        let ty = RRType::from(p.get_u16());
        let class = RRClass::from(p.get_u16());
        let size = end + 4 - pos;
        Ok(Self {
            name,
            ty,
            class,
            size,
        })
    }

    fn into_bytes(self) -> Result<BytesMut, PacketError> {
        let mut buf = BytesMut::with_capacity(self.name.len() + 5);
        buf.put(self.name.as_bytes_uncompressed());
        buf.put_u16(u16::from(self.ty));
        buf.put_u16(u16::from(self.class));
        Ok(buf)
    }
}
