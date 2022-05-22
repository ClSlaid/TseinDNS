// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use bytes::{Bytes, BytesMut};

use crate::protocol::{domain::Name, error::PacketError};

pub mod a;
pub mod aaaa;
pub mod cname;
pub mod hinfo;
pub mod mb;
pub mod mg;
pub mod minfo;
pub mod mr;
pub mod mx;
pub mod nl;
pub mod ns;
pub mod pt; // PTR
pub mod soa;
pub mod txt;
pub mod wks;

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
