// Copyright (c) 2022 ClSlaid <cailue@bupt.edu.cn>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::net::SocketAddr;

use anyhow::Result;
use bytes::Bytes;
use quinn::{Connection, Endpoint, NewConnection, RecvStream, SendStream};
use rand::random;
use tokio::sync::mpsc;

use crate::{
    comm::{Answer, Task},
    protocol::{Packet, PacketError, TransactionError},
};

pub struct QuicForwarder {
    rec: mpsc::UnboundedReceiver<Task>,
    connection: QuicManager,
}

impl QuicForwarder {
    pub async fn try_new(
        rec: mpsc::UnboundedReceiver<Task>,
        endpoint: Endpoint,
        domain: &'static str,
        addr: SocketAddr,
    ) -> Result<Self> {
        tracing::info!(
            "establishing quic connection to quic://{}, statically configured as {}",
            domain,
            addr
        );
        let connection = QuicManager::try_build(endpoint, domain, addr).await?;

        Ok(Self { rec, connection })
    }

    pub async fn run(mut self) -> Result<()> {
        tracing::info!("forward task is running");
        let checkers = futures::stream::FuturesUnordered::new();
        let remote = self.connection.remote_address();
        while let Some(task) = self.rec.recv().await {
            let Task::Query(q, ans_to) = task;
            tracing::info!("forwarding new task from transaction layer.");
            let (mut quic_send, quic_recv) = self.connection.open_bi().await;
            let id = random::<u16>();

            let packet = Packet::new_query(id, q);
            tracing::debug!("sending packet {:?} to quic://{}", packet, remote);

            let packet_bytes = packet.into_bytes();
            if (quic_send.write_all(&packet_bytes[..]).await).is_err() {
                tracing::warn!("QUIC forward to quic://{} failed with write error!", remote);
                continue;
            }

            let checker = tokio::spawn(async move {
                let stream_id = quic_recv.id();
                let v = quic_recv
                    .read_to_end(u16::MAX as usize)
                    .await
                    .expect("failed read to end");
                let buf = Bytes::from(v);
                let r = Packet::parse_packet(buf, 0);
                tracing::debug!("received response {:?} on quic stream", r);
                if let Err(..) = r {
                    let TransactionError { id: _, error } = r.unwrap_err();
                    match error {
                        PacketError::ServFail => {
                            tracing::debug!(
                                "connection closed on stream {} against {}",
                                stream_id,
                                remote
                            );
                        }
                        e => {
                            let _ = ans_to.send(Answer::Error(e));
                        }
                    }
                    return;
                }
                let packet = r.unwrap();
                tracing::debug!("get answer from upstream: {:?}", packet);
                for ans in packet.answers {
                    let _ = ans_to.send(Answer::Answer(ans));
                }
                for ns in packet.authorities {
                    let _ = ans_to.send(Answer::NameServer(ns));
                }
                for addi in packet.additions {
                    let _ = ans_to.send(Answer::Additional(addi));
                }
            });
            let _ = quic_send.finish().await;
            tracing::debug!("packet sent to upstream");
            checkers.push(checker);
        }
        for checker in checkers {
            let _ = tokio::join!(checker);
        }
        Ok(())
    }
}

struct QuicManager {
    endpoint: Endpoint,
    addr: SocketAddr,
    domain: String,
    connection: Connection,
}

impl QuicManager {
    pub async fn try_build(
        endpoint: Endpoint,
        remote_domain: &'static str,
        remote_addr: SocketAddr,
    ) -> Result<Self> {
        let conn = endpoint
            .connect(remote_addr, remote_domain)
            .expect("cannot initiate QUIC connection")
            .await?;
        let NewConnection { connection, .. } = conn;
        Ok(Self {
            endpoint,
            addr: remote_addr,
            domain: String::from(remote_domain),
            connection,
        })
    }

    async fn reconnect(&mut self) -> Result<()> {
        let conn = self
            .endpoint
            .connect(self.addr, self.domain.as_str())
            .expect("cannot initiate QUIC connection")
            .await?;
        let NewConnection { connection, .. } = conn;
        self.connection = connection;
        Ok(())
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub async fn open_bi(&mut self) -> (SendStream, RecvStream) {
        let r = self.connection.open_bi().await;
        if r.is_err() {
            tracing::debug!("QUIC connection lost, reconnecting...");
            self.reconnect().await.unwrap();
            self.connection.open_bi().await.unwrap()
        } else {
            r.unwrap()
        }
    }
}
