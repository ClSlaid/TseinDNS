use bytes::Buf;

use crate::protocol::{error::PacketError, rr::RRType};

use super::Rdata;

pub struct UNKNOWN {
    rtype: RRType,
    length: usize,
    data: Vec<u8>,
}

impl UNKNOWN {
    pub fn set_type(&mut self, rtype: u16) {
        self.rtype = RRType::UNKNOWN(rtype);
    }

    pub fn parse_typeless(packet: bytes::Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        let mut p = packet.clone();
        let length = p.get_u16() as usize;
        let data = (0..length).fold(vec![], |mut acc, _| {
            let byte = p.get_u8();
            acc.push(byte);
            acc
        });
        let unknown = Self {
            length,
            rtype: RRType::UNKNOWN(255), // always set as 255
            data,
        };
        let end = pos + 2 + length;
        Ok((unknown, end))
    }
}

impl Rdata for UNKNOWN {
    /// Warning: will look backward to other fields in RR.
    /// use only when parsing at least a whole RR.
    fn parse(packet: bytes::Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized,
    {
        // Get type of unknown
        let type_pos = pos - 8;
        let mut p = packet.clone();
        p.advance(type_pos);
        let tp = p.get_u16();

        // Parse remaining parts of the packet
        let mut p = packet;
        let length = p.get_u16() as usize;
        let data = Vec::from(&p.chunk()[..length]);
        let unknown = Self {
            length,
            rtype: RRType::UNKNOWN(tp),
            data,
        };
        let end = pos + 2 + length;
        Ok((unknown, end))
    }
}
