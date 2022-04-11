use bytes::{Bytes, BytesMut};

use crate::protocol::{domain::Name, error::PacketError};

pub mod a;
pub mod aaaa;
pub mod cname;
pub mod mx;
pub mod ns;
pub mod soa;

pub mod unknown;

pub trait Rdata {
    /// Parse packet data, returning a valid object, and its end in packet.
    fn parse(packet: Bytes, pos: usize) -> Result<(Self, usize), PacketError>
    where
        Self: Sized;
    fn try_into_bytes(&self) -> Result<BytesMut, PacketError>;
}

pub(self) fn try_into_rdata_length<N>(rdata_length: N) -> Result<u16, PacketError>
where
    N: TryInto<u16>,
{
    rdata_length.try_into().map_err(|_| PacketError::ServFail)
}
