use std::net::IpAddr;

use thiserror::Error;

use super::{domain::Name, header::Op};

pub type Result<T> = std::result::Result<T, PacketError>;

/// Error occurred in parsing DNS packets
#[derive(Error, Debug)]
pub enum PacketError {
    #[error("Format Error in Query")]
    FormatError,
    #[error("Service Failure")]
    ServFail,
    #[error("Invalid Domain Name {0}")]
    NameError(Name),
    #[error("Unimplemented Operation: {0}")]
    NotImpl(Op),
    #[error("Refused Connection from: {0}")]
    Refused(IpAddr),
}
