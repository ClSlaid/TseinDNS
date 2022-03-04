use bytes::{Bytes, BytesMut};
/// DNS packet header
mod header;

/// DNS packet question
mod question;

/// DNS Resource Record
mod rr;

/// Domain names
mod domain;

/// Error types
mod error;

trait PacketContent {
    fn parse(packet: Bytes, pos: usize) -> Result<Self, error::PacketError>
    where
        Self: Sized;
    fn into_bytes(self) -> BytesMut;
}

/// Type of Resource Record
pub enum RRType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    SOA,
    UNKNOWN(u16),
}

// TODO: replace redundant code with macron
impl From<u16> for RRType {
    fn from(rtype: u16) -> Self {
        match rtype {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            15 => Self::MX,
            28 => Self::AAAA,
            x => Self::UNKNOWN(x),
        }
    }
}

// TODO: replace redundant code with macron
impl From<RRType> for u16 {
    fn from(rtype: RRType) -> Self {
        match rtype {
            RRType::A => 1,
            RRType::NS => 2,
            RRType::CNAME => 5,
            RRType::SOA => 6,
            RRType::MX => 15,
            RRType::AAAA => 28,
            RRType::UNKNOWN(x) => x,
        }
    }
}
