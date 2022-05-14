// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{fmt::Formatter, net::IpAddr};

use thiserror::Error;

use super::{domain::Name, header::Op};

/// Error occurred in parsing DNS packets
#[derive(Error, Debug, Clone)]
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

#[derive(Error, Debug, Clone)]
pub struct TransactionError {
    pub(crate) id: Option<u16>,
    #[source]
    pub(crate) error: PacketError,
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Transaction {:?} got error: {:?}", self.id, self.error)
    }
}
