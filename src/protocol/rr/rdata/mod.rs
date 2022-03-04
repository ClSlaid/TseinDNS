use bytes::Bytes;

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
}
