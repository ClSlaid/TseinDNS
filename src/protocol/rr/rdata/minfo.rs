use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::protocol::{rr::rdata::Rdata, Name, PacketError};

#[derive(Clone, Debug)]
pub struct MInfo {
    r_mail_box: Name,
    e_mail_box: Name,
}

impl Rdata for MInfo {
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        if pos + 2 > packet.len() {
            return Err(PacketError::FormatError);
        }

        let mut pos = pos;
        let mut p = packet.clone();
        p.advance(pos);
        pos += 2;

        let (r_mail_box, m_end) = Name::parse(packet.clone(), pos)?;
        let (e_mail_box, end) = Name::parse(packet, m_end)?;
        let m_info = MInfo {
            r_mail_box,
            e_mail_box,
        };
        Ok((m_info, end))
    }

    fn try_into_bytes(&self) -> Result<BytesMut, PacketError> {
        let n1 = self.r_mail_box.as_bytes_uncompressed();
        let n2 = self.e_mail_box.as_bytes_uncompressed();
        let len = (n1.len() + n2.len()) as u16;
        let mut buf = BytesMut::new();
        buf.put_u16(len);
        buf.put(n1);
        buf.put(n2);
        Ok(buf)
    }
}
